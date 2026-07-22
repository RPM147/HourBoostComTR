import json
import hashlib
import inspect
import logging
import math
import os
import re
import shutil
import stat
import time
import uuid
from collections import defaultdict

import gevent
from gevent import queue
from gevent.lock import RLock
from gevent import subprocess

from log_security import protect_logger
from steam_compat import EPersonaState, EResult

logger = protect_logger(logging.getLogger(__name__))

BASE_DIR = os.path.dirname(__file__)
STATE_DIR = os.path.abspath(os.environ.get("STEAM_STATE_DIR") or BASE_DIR)
TOKEN_DIR = os.path.join(STATE_DIR, "tokens")
os.makedirs(TOKEN_DIR, exist_ok=True)
if os.name != "nt":
    try:
        os.chmod(TOKEN_DIR, 0o700)
    except Exception:
        pass

SENTRY_DIR = os.path.join(STATE_DIR, "sentry")
os.makedirs(SENTRY_DIR, exist_ok=True)
if os.name != "nt":
    try:
        os.chmod(SENTRY_DIR, 0o700)
    except Exception:
        pass

NODE_DATA_DIR = os.path.join(SENTRY_DIR, "node")
os.makedirs(NODE_DATA_DIR, exist_ok=True)
if os.name != "nt":
    try:
        os.chmod(NODE_DATA_DIR, 0o700)
    except Exception:
        pass

WORKER_SCRIPT = os.path.join(BASE_DIR, "steam_worker.js")
_FERNET = None
_QUARANTINE_SUFFIX_RE = re.compile(r"\.delete-([0-9a-f]{32})$")
MAX_PENDING_FINAL_SEGMENTS = 128
MAX_PENDING_STATE_BYTES = 262144
# Keep one slot for the terminal stop record. Checkpoints are recoverable only
# if a later hard/manual stop can still append its final boundary.
MAX_PENDING_CHECKPOINT_SEGMENTS = MAX_PENDING_FINAL_SEGMENTS - 1
FATAL_FINALIZATION_RETRY_SECONDS = 2.0


def _path_exists(path):
    """Like exists(), but also sees broken symlinks without following them."""
    return os.path.lexists(path)


def _fsync_directory(path):
    """Persist a directory entry update after an atomic replace/remove."""
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_account_id(account_id):
    value = str(account_id or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value):
        raise ValueError("Invalid Steam account id")
    return value


def _contained_path(root, *parts):
    root_path = os.path.abspath(root)
    candidate = os.path.abspath(os.path.join(root_path, *parts))
    if os.path.commonpath((root_path, candidate)) != root_path:
        raise ValueError("Path escaped its storage root")
    return candidate


def _ensure_private_directory(path, root):
    """Create a private directory and reject symlinked storage components."""
    root_path = os.path.abspath(root)
    candidate = os.path.abspath(path)
    if os.path.commonpath((root_path, candidate)) != root_path:
        raise ValueError("Directory escaped its storage root")

    os.makedirs(root_path, exist_ok=True)
    if os.path.islink(root_path):
        raise ValueError("Storage root cannot be a symlink")
    os.makedirs(candidate, exist_ok=True)
    if os.path.islink(candidate) or not os.path.isdir(candidate):
        raise ValueError("Steam data directory is not a real directory")
    if os.path.realpath(candidate) != candidate:
        raise ValueError("Steam data directory contains a symlink")
    if os.name != "nt":
        os.chmod(root_path, 0o700)
        os.chmod(candidate, 0o700)
    return candidate


def _credential_path(account_id, steam_username):
    """Return the legacy-compatible credential path, contained in TOKEN_DIR."""
    account_id = _validate_account_id(account_id)
    safe_name = str(steam_username or "").replace("/", "_").replace("\\", "_")
    candidate = os.path.realpath(
        os.path.join(TOKEN_DIR, f"{account_id}_{safe_name}.cred")
    )
    token_root = os.path.realpath(TOKEN_DIR)
    if os.path.commonpath((token_root, candidate)) != token_root:
        raise ValueError("Credential path escaped TOKEN_DIR")
    return candidate


def _node_machine_auth_path(steam_username):
    """Return the old shared machine-token path used before account isolation."""
    filename = f"machineAuthToken.{str(steam_username or '').lower()}.txt"
    candidate = os.path.realpath(os.path.join(NODE_DATA_DIR, filename))
    node_root = os.path.realpath(NODE_DATA_DIR)
    if os.path.commonpath((node_root, candidate)) != node_root:
        raise ValueError("Machine-auth path escaped NODE_DATA_DIR")
    return candidate


def _node_account_data_root():
    return _contained_path(NODE_DATA_DIR, "accounts")


def _node_account_data_dir(account_id):
    """Return a stable, non-user-controlled storage directory for one account."""
    account_id = _validate_account_id(account_id)
    storage_key = hashlib.sha256(account_id.encode("utf-8")).hexdigest()
    return _contained_path(_node_account_data_root(), storage_key)


def _pending_final_segments_path(account_id):
    return _contained_path(
        _node_account_data_dir(account_id),
        "pending-final-segments.json",
    )


def _account_node_machine_auth_path(account_id, steam_username):
    filename = f"machineAuthToken.{str(steam_username or '').lower()}.txt"
    account_dir = _node_account_data_dir(account_id)
    candidate = os.path.realpath(os.path.join(account_dir, filename))
    if os.path.commonpath((os.path.realpath(account_dir), candidate)) != os.path.realpath(account_dir):
        raise ValueError("Machine-auth path escaped account data directory")
    return candidate


def _credential_artifact_paths(
    account_id,
    steam_username,
    *,
    include_legacy_machine_auth=False,
    include_account_directory=False,
):
    paths = [
        _credential_path(account_id, steam_username),
        _account_node_machine_auth_path(account_id, steam_username),
    ]
    if include_legacy_machine_auth:
        paths.append(_node_machine_auth_path(steam_username))
    if include_account_directory:
        paths.append(_node_account_data_dir(account_id))

    # A token path is inside the account directory. If the whole directory is
    # included, moving the child first would only create an unnecessary second
    # tombstone. Keep the list deterministic and non-overlapping.
    if include_account_directory:
        account_dir = os.path.abspath(_node_account_data_dir(account_id))
        paths = [
            path for path in paths
            if os.path.abspath(path) == account_dir
            or os.path.commonpath((account_dir, os.path.abspath(path))) != account_dir
        ]
    return tuple(dict.fromkeys(paths))


def _remove_artifact(path):
    """Remove a file, symlink, or real directory without following symlinks."""
    if not _path_exists(path):
        return
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
        return
    shutil.rmtree(path)


def restore_quarantined_credentials(moved_paths):
    """Undo a pre-commit credential quarantine after a database rollback."""
    restored = True
    for original, quarantined in reversed(moved_paths or []):
        try:
            if _path_exists(quarantined):
                if _path_exists(original):
                    # A live worker may have persisted a newer token while the
                    # DB transaction was in flight. Keep the fresh artifact;
                    # never overwrite it with the quarantined older copy.
                    _remove_artifact(quarantined)
                    logger.warning(
                        "Steam credential restore kept a newer artifact"
                    )
                else:
                    os.replace(quarantined, original)
        except Exception as exc:
            restored = False
            logger.critical(
                "Steam credential quarantine restore failed: error=%s",
                type(exc).__name__,
            )
    return restored


def purge_quarantined_credentials(moved_paths):
    """Permanently remove credential artifacts after the DB commit succeeds."""
    purged = True
    for _original, quarantined in moved_paths or []:
        try:
            if _path_exists(quarantined):
                _remove_artifact(quarantined)
        except Exception as exc:
            purged = False
            logger.critical(
                "Steam credential quarantine purge failed: error=%s",
                type(exc).__name__,
            )
    return purged


def quarantine_saved_credentials(
    account_id,
    steam_username,
    *,
    include_legacy_machine_auth=False,
    include_account_directory=False,
):
    """Atomically hide all persisted Steam auth material before a DB mutation.

    Returns a reversible list on success (including an empty list when there
    were no files) and ``None`` on failure.  Renaming on the same filesystem is
    atomic, so a later DB rollback can restore the exact prior state.
    """
    moved = []
    try:
        for path in _credential_artifact_paths(
            account_id,
            steam_username,
            include_legacy_machine_auth=include_legacy_machine_auth,
            include_account_directory=include_account_directory,
        ):
            if not _path_exists(path):
                continue
            quarantined = f"{path}.delete-{uuid.uuid4().hex}"
            os.replace(path, quarantined)
            moved.append((path, quarantined))
        return moved
    except Exception as exc:
        restore_quarantined_credentials(moved)
        logger.error(
            "Steam credential quarantine failed: account_id=%s error=%s",
            account_id,
            type(exc).__name__,
        )
        return None


def delete_saved_credentials(
    account_id,
    steam_username,
    *,
    include_legacy_machine_auth=False,
):
    """Delete encrypted credentials and steam-user machine auth material."""
    quarantined = quarantine_saved_credentials(
        account_id,
        steam_username,
        include_legacy_machine_auth=include_legacy_machine_auth,
        include_account_directory=True,
    )
    if quarantined is None:
        return False
    return purge_quarantined_credentials(quarantined)


def _atomic_copy_private_file(source, destination):
    """Copy a regular credential file without exposing a partial destination."""
    source_stat = os.lstat(source)
    if not stat.S_ISREG(source_stat.st_mode):
        raise ValueError("Credential source is not a regular file")

    destination_dir = os.path.dirname(destination)
    _ensure_private_directory(destination_dir, _node_account_data_root())
    if _path_exists(destination):
        destination_stat = os.lstat(destination)
        if not stat.S_ISREG(destination_stat.st_mode):
            raise ValueError("Credential destination is not a regular file")
        return True

    temporary = f"{destination}.tmp-{uuid.uuid4().hex}"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        source_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            source_flags |= os.O_NOFOLLOW
        try:
            source_descriptor = os.open(source, source_flags)
        except Exception:
            os.close(descriptor)
            raise
        with (
            os.fdopen(descriptor, "wb") as target,
            os.fdopen(source_descriptor, "rb") as origin,
        ):
            shutil.copyfileobj(origin, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        if os.name != "nt":
            os.chmod(destination, 0o600)
        return True
    finally:
        if _path_exists(temporary):
            _remove_artifact(temporary)


def _quarantine_candidates(original):
    parent = os.path.dirname(original)
    basename = os.path.basename(original)
    if not os.path.isdir(parent) or os.path.islink(parent):
        return []
    candidates = []
    prefix = basename + ".delete-"
    for entry in os.scandir(parent):
        if entry.name.startswith(prefix) and _QUARANTINE_SUFFIX_RE.search(entry.name):
            candidates.append(entry.path)
    return candidates


def reconcile_credential_quarantines(account_pairs):
    """Recover credential tombstones using the database as the source of truth.

    A crash before DB commit leaves an account row and a tombstone that must be
    restored. A crash after commit leaves no account row, so its tombstone can
    be purged. This is deliberately DB-aware; age-only cleanup can destroy the
    only valid credential copy.
    """
    pairs = [(str(account_id), str(username or "")) for account_id, username in account_pairs]
    expected = set()
    expected_account_directories = set()
    healthy = True

    try:
        _ensure_private_directory(TOKEN_DIR, TOKEN_DIR)
        _ensure_private_directory(NODE_DATA_DIR, NODE_DATA_DIR)
        _ensure_private_directory(_node_account_data_root(), NODE_DATA_DIR)
    except Exception:
        logger.critical("Steam credential storage roots are unsafe", exc_info=True)
        return False

    for account_id, username in pairs:
        try:
            credential_path = _credential_path(account_id, username)
            account_directory = _node_account_data_dir(account_id)
            expected_account_directories.add(os.path.abspath(account_directory))
            expected.update((
                credential_path,
                _account_node_machine_auth_path(account_id, username),
                account_directory,
                _node_machine_auth_path(username),
            ))
        except Exception:
            healthy = False
            logger.critical(
                "Steam credential reconciliation skipped invalid account: account_id=%s",
                account_id,
                exc_info=True,
            )

    handled_tombstones = set()
    for original in sorted(expected):
        tombstones = _quarantine_candidates(original)
        if not tombstones:
            continue
        handled_tombstones.update(os.path.abspath(path) for path in tombstones)
        try:
            if _path_exists(original):
                for tombstone in tombstones:
                    _remove_artifact(tombstone)
                continue

            newest = max(tombstones, key=lambda path: os.lstat(path).st_mtime_ns)
            os.replace(newest, original)
            for tombstone in tombstones:
                if tombstone != newest and _path_exists(tombstone):
                    _remove_artifact(tombstone)
            logger.warning("Recovered Steam credential quarantine after interrupted deletion")
        except Exception:
            healthy = False
            logger.critical(
                "Steam credential quarantine reconciliation failed",
                exc_info=True,
            )

    scan_roots = [TOKEN_DIR, NODE_DATA_DIR, _node_account_data_root()]
    account_root = _node_account_data_root()
    if os.path.isdir(account_root) and not os.path.islink(account_root):
        for entry in os.scandir(account_root):
            if entry.is_dir(follow_symlinks=False) and not _QUARANTINE_SUFFIX_RE.search(entry.name):
                scan_roots.append(entry.path)

    orphan_account_directories = set()
    for root in scan_roots:
        if not os.path.isdir(root) or os.path.islink(root):
            continue
        for entry in os.scandir(root):
            if not _QUARANTINE_SUFFIX_RE.search(entry.name):
                continue
            tombstone = os.path.abspath(entry.path)
            if tombstone in handled_tombstones:
                continue
            try:
                suffix_match = _QUARANTINE_SUFFIX_RE.search(entry.path)
                original = entry.path[:suffix_match.start()] if suffix_match else None
                _remove_artifact(entry.path)
                if original and _path_exists(original):
                    _remove_artifact(original)
                root_path = os.path.abspath(root)
                if (
                    os.path.dirname(root_path) == os.path.abspath(account_root)
                    and re.fullmatch(r"[0-9a-f]{64}", os.path.basename(root_path))
                    and root_path not in expected_account_directories
                ):
                    orphan_account_directories.add(root_path)
                logger.warning("Purged orphaned Steam credential quarantine")
            except Exception:
                healthy = False
                logger.critical(
                    "Orphaned Steam credential quarantine purge failed",
                    exc_info=True,
                )
    for directory in orphan_account_directories:
        try:
            if _path_exists(directory):
                _remove_artifact(directory)
        except Exception:
            healthy = False
            logger.critical(
                "Orphaned Steam account data directory purge failed",
                exc_info=True,
            )
    return healthy


def migrate_legacy_node_credentials(account_pairs):
    """Copy shared steam-user machine tokens into account-isolated directories."""
    pairs = [(str(account_id), str(username or "")) for account_id, username in account_pairs]
    by_source = defaultdict(list)
    healthy = True
    for account_id, username in pairs:
        try:
            by_source[_node_machine_auth_path(username)].append(
                _account_node_machine_auth_path(account_id, username)
            )
        except Exception:
            healthy = False
            logger.critical(
                "Legacy Steam credential migration skipped invalid account: account_id=%s",
                account_id,
                exc_info=True,
            )

    referenced_sources = {os.path.abspath(path) for path in by_source}
    for source, destinations in by_source.items():
        if not _path_exists(source):
            continue
        copied_all = True
        for destination in dict.fromkeys(destinations):
            try:
                _atomic_copy_private_file(source, destination)
            except Exception:
                copied_all = False
                healthy = False
                logger.critical(
                    "Legacy Steam machine token copy failed",
                    exc_info=True,
                )
        if copied_all:
            try:
                _remove_artifact(source)
                logger.info(
                    "Legacy shared Steam machine token migrated to %d account directories",
                    len(set(destinations)),
                )
            except Exception:
                healthy = False
                logger.critical(
                    "Legacy shared Steam machine token purge failed",
                    exc_info=True,
                )

    if os.path.isdir(NODE_DATA_DIR) and not os.path.islink(NODE_DATA_DIR):
        for entry in os.scandir(NODE_DATA_DIR):
            if not re.fullmatch(r"machineAuthToken\..+\.txt", entry.name):
                continue
            if os.path.abspath(entry.path) in referenced_sources:
                continue
            try:
                _remove_artifact(entry.path)
                logger.warning("Purged orphaned legacy Steam machine token")
            except Exception:
                healthy = False
                logger.critical(
                    "Orphaned legacy Steam machine token purge failed",
                    exc_info=True,
                )
    return healthy


def _get_fernet():
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    try:
        from cryptography.fernet import Fernet
        import base64
        import hashlib

        key_str = os.environ.get("CRED_KEY")
        if key_str:
            key = key_str.encode()
            logger.info("Sifreleme anahtari env den yuklendi")
        else:
            key_path = os.path.join(BASE_DIR, ".cred_key")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key = f.read().strip()
                logger.warning(
                    "DIKKAT: Sifreleme anahtari .cred_key dosyasindan okundu. "
                    "Lutfen bunu CRED_KEY ortam degiskenine tasiyin ve dosyayi silin."
                )
            else:
                secret = os.environ.get("SECRET_KEY", "default_insecure_secret").encode()
                derived = hashlib.sha256(b"steam_cred_salt_" + secret).digest()
                key = base64.urlsafe_b64encode(derived)
                logger.info("Sifreleme anahtari SECRET_KEY uzerinden dinamik olarak uretildi")

        _FERNET = Fernet(key)
    except Exception as e:
        logger.error("Fernet baslatma hatasi: %s", e)
        _FERNET = None
    return _FERNET


def encrypt_password(password):
    f = _get_fernet()
    if not f or not password:
        return None
    try:
        return f.encrypt(password.encode()).decode()
    except Exception:
        return None


def decrypt_password(encrypted):
    f = _get_fernet()
    if not f or not encrypted:
        return None
    try:
        return f.decrypt(encrypted.encode()).decode()
    except Exception:
        return None


def _safe_eresult(value, fallback=EResult.Fail):
    try:
        return EResult(int(value))
    except Exception:
        return fallback


def _node_binary():
    configured = os.environ.get("NODE_BIN")
    if configured:
        return configured
    return shutil.which("node") or "node"


class SteamWorkerClient:
    def __init__(self, data_directory=None):
        self.connected = False
        self.logged_in = False
        self.steam_id = None
        self.refresh_token = None
        self._process = None
        self._process_generation = 0
        # A worker is detached from the request path before termination so a
        # blocked IPC call is released immediately.  Keep an identity-safe
        # reference until the OS confirms that process is dead; otherwise a
        # second force_disconnect() could incorrectly report success while a
        # stubborn old Steam session is still alive.
        self._detached_processes = {}
        self._process_lock = RLock()
        self._pending = {}
        self._handlers = defaultdict(list)
        self._reader_greenlet = None
        self._stderr_greenlet = None
        self._closed = False
        self.data_directory = data_directory or _node_account_data_dir("standalone")

    def set_credential_location(self, _path):
        return None

    def on(self, event_name):
        def decorator(callback):
            self._handlers[event_name].append(callback)
            return callback

        return decorator

    def _emit(self, event_name):
        for callback in list(self._handlers.get(event_name, [])):
            try:
                callback()
            except Exception as e:
                logger.error("Steam worker event handler hatasi (%s): %s", event_name, e)

    def _ensure_process(self):
        with self._process_lock:
            if self._closed:
                return False
            for generation, process in list(self._detached_processes.items()):
                if process.poll() is not None:
                    self._detached_processes.pop(generation, None)
            if self._detached_processes:
                logger.error(
                    "Steam worker baslatilamadi: onceki worker henuz sonlanmadi"
                )
                return False
            if self._process and self._process.poll() is None:
                return True

            if not os.path.exists(WORKER_SCRIPT):
                logger.error("Steam worker bulunamadi: %s", WORKER_SCRIPT)
                return False

            if self._process is not None:
                self._fail_pending_generation_unlocked(
                    self._process_generation,
                    EResult.NoConnection,
                )
                self._process = None
                self.connected = False
                self.logged_in = False

            try:
                data_directory = _ensure_private_directory(
                    self.data_directory,
                    _node_account_data_root(),
                )
                env = os.environ.copy()
                env["STEAM_WORKER_DATA_DIR"] = data_directory
                process = subprocess.Popen(
                    [_node_binary(), WORKER_SCRIPT],
                    cwd=BASE_DIR,
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except Exception as e:
                logger.error("Steam worker baslatilamadi: %s", e)
                self._process = None
                return False

            self._process_generation += 1
            generation = self._process_generation
            self._process = process
            self.connected = True
            self._reader_greenlet = gevent.spawn(
                self._read_stdout,
                process,
                generation,
            )
            self._stderr_greenlet = gevent.spawn(
                self._read_stderr,
                process,
                generation,
            )
            return True

    @staticmethod
    def _pending_parts(entry, default_generation):
        if isinstance(entry, tuple) and len(entry) == 2:
            return entry
        # Compatibility for an in-memory entry created by older code/tests.
        return default_generation, entry

    def _fail_pending_generation_unlocked(self, generation, result):
        response = {"ok": False, "eresult": int(result)}
        for request_id, entry in list(self._pending.items()):
            entry_generation, response_queue = self._pending_parts(
                entry,
                self._process_generation,
            )
            if entry_generation != generation:
                continue
            if self._pending.get(request_id) is entry:
                self._pending.pop(request_id, None)
            try:
                response_queue.put_nowait(dict(response))
            except Exception:
                pass

    def _read_stdout(self, process, generation):
        try:
            while process.poll() is None:
                line = process.stdout.readline()
                if not line:
                    break
                try:
                    message = json.loads(line)
                except Exception:
                    logger.warning("Steam worker gecersiz cikti: %s", line.strip())
                    continue
                self._handle_message(message, process, generation)
        except Exception as e:
            logger.error("Steam worker stdout okuma hatasi: %s", e)
        finally:
            with self._process_lock:
                self._fail_pending_generation_unlocked(
                    generation,
                    EResult.NoConnection,
                )
                if (
                    self._process is process
                    and self._process_generation == generation
                ):
                    self._process = None
                    self.connected = False
                    self.logged_in = False
                    # Serialize the process transition with event publication. A
                    # replacement worker cannot be installed between these steps.
                    self._emit("disconnected")

    def _read_stderr(self, process, generation):
        try:
            while process.poll() is None:
                line = process.stderr.readline()
                if not line:
                    break
                logger.info("Steam worker: %s", line.strip())
        except Exception:
            pass

    def _handle_message(self, message, process, generation):
        with self._process_lock:
            if (
                self._closed
                or self._process is not process
                or self._process_generation != generation
            ):
                return
            if message.get("refresh_token"):
                self.refresh_token = message.get("refresh_token")
            if message.get("steam_id"):
                self.steam_id = message.get("steam_id")

            request_id = message.get("id")
            entry = self._pending.get(request_id) if request_id else None
            if entry is not None:
                entry_generation, response_queue = self._pending_parts(
                    entry,
                    generation,
                )
                if entry_generation == generation:
                    if self._pending.get(request_id) is entry:
                        self._pending.pop(request_id, None)
                    response_queue.put_nowait(message)
                    return

            event = message.get("event")
            if event == "logged_on":
                self.logged_in = True
                self.connected = True
                self._emit("logged_on")
            elif event == "disconnected":
                self.logged_in = False
                self.connected = False
                self._emit("disconnected")
            elif event == "error":
                self.logged_in = False
                logger.warning("Steam worker event error: %s", message.get("message"))

    def _request(self, action, payload=None, timeout=60):
        if not self._ensure_process():
            if self._closed:
                return {"ok": False, "eresult": int(EResult.NoConnection)}
            return {"ok": False, "eresult": int(EResult.ServiceUnavailable)}

        request_id = uuid.uuid4().hex
        message = {"id": request_id, "action": action}
        if payload:
            message.update(payload)

        response_queue = queue.Queue(maxsize=1)
        with self._process_lock:
            if self._closed or self._process is None:
                return {"ok": False, "eresult": int(EResult.NoConnection)}
            process = self._process
            generation = self._process_generation
            if process.poll() is not None:
                return {"ok": False, "eresult": int(EResult.NoConnection)}
            entry = (generation, response_queue)
            self._pending[request_id] = entry

        try:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
        except Exception as e:
            with self._process_lock:
                if self._pending.get(request_id) is entry:
                    self._pending.pop(request_id, None)
            logger.error("Steam worker komut gonderme hatasi: %s", e)
            return {"ok": False, "eresult": int(EResult.NoConnection)}

        try:
            response = response_queue.get(timeout=timeout)
            with self._process_lock:
                if (
                    self._process is not process
                    or self._process_generation != generation
                ):
                    return {"ok": False, "eresult": int(EResult.NoConnection)}
                response = dict(response)
                response["_worker_generation"] = generation
                return response
        except queue.Empty:
            with self._process_lock:
                if self._pending.get(request_id) is entry:
                    self._pending.pop(request_id, None)
            logger.error("Steam worker timeout: %s", action)
            return {"ok": False, "eresult": int(EResult.ServiceUnavailable)}

    def login(self, username, password="", auth_code=None, two_factor_code=None, refresh_token=None):
        code = two_factor_code or auth_code
        code_type = "2fa" if two_factor_code else "email"
        response = self._request(
            "login",
            {
                "username": username,
                "password": password or "",
                "code": code,
                "code_type": code_type,
                "refresh_token": refresh_token,
            },
            timeout=90,
        )

        response_generation = response.pop("_worker_generation", None)
        result = _safe_eresult(response.get("eresult"))
        if response.get("ok") and result == EResult.OK:
            with self._process_lock:
                if (
                    response_generation is None
                    or self._process is None
                    or self._process_generation != response_generation
                ):
                    return EResult.NoConnection
                self.logged_in = True
                self.connected = True
                self.steam_id = response.get("steam_id") or self.steam_id
                self.refresh_token = (
                    response.get("refresh_token") or self.refresh_token
                )
        return result

    def games_played(self, app_ids):
        response = self._request("games_played", {"app_ids": list(app_ids or [])}, timeout=20)
        return _safe_eresult(response.get("eresult"))

    def change_status(self, persona_state=EPersonaState.Online):
        response = self._request("set_persona", {"state": int(persona_state)}, timeout=20)
        return _safe_eresult(response.get("eresult"))

    def stop_games(self):
        response = self._request("stop_boost", timeout=20)
        return _safe_eresult(response.get("eresult"))

    def reconnect(self, maxdelay=30):
        return None

    def mark_closed(self):
        """Synchronously prevent any pending or future worker resurrection."""
        with self._process_lock:
            if self._closed:
                return
            self._closed = True
            self.connected = False
            self.logged_in = False
            for request_id, entry in list(self._pending.items()):
                _generation, response_queue = self._pending_parts(
                    entry,
                    self._process_generation,
                )
                if self._pending.get(request_id) is entry:
                    self._pending.pop(request_id, None)
                try:
                    response_queue.put_nowait(
                        {"ok": False, "eresult": int(EResult.NoConnection)}
                    )
                except Exception:
                    pass

    def force_disconnect(self):
        """Terminate a bad worker without permanently closing this client.

        This is the fail-closed escape hatch used when Steam did not confirm a
        stop-games request.  Killing the CM session prevents a remotely active
        game state from surviving while still allowing an explicit later login
        to create a fresh worker process.
        """
        with self._process_lock:
            process = self._process
            generation = self._process_generation
            if process is not None:
                # Detach before blocking on process shutdown. Only requests
                # issued to this exact worker generation are failed; a fresh
                # login may safely install the next generation concurrently.
                self._process = None
                self._detached_processes[generation] = process
                self._fail_pending_generation_unlocked(
                    generation,
                    EResult.NoConnection,
                )
            self.connected = False
            self.logged_in = False
            detached = list(self._detached_processes.items())
        for _detached_generation, detached_process in detached:
            if detached_process.poll() is not None:
                continue
            try:
                detached_process.terminate()
            except Exception:
                pass
            try:
                with gevent.Timeout(5, False):
                    detached_process.wait()
            except Exception:
                pass
            try:
                if detached_process.poll() is None:
                    detached_process.kill()
                    with gevent.Timeout(2, False):
                        detached_process.wait()
            except Exception:
                pass
        with self._process_lock:
            for detached_generation, detached_process in detached:
                if (
                    self._detached_processes.get(detached_generation)
                    is detached_process
                    and detached_process.poll() is not None
                ):
                    self._detached_processes.pop(detached_generation, None)
            stopped = not self._detached_processes
        if not stopped:
            logger.critical("Steam worker could not be terminated fail-closed")
        return stopped

    def disconnect(self, permanent=False):
        if permanent:
            self.mark_closed()
            self.force_disconnect()
            return
        with self._process_lock:
            process = self._process
            generation = self._process_generation
            if process is None:
                self.connected = False
                self.logged_in = False
                return
        if not permanent:
            try:
                self._request("disconnect", timeout=5)
            except Exception:
                pass
        with self._process_lock:
            if (
                self._process is process
                and self._process_generation == generation
            ):
                self._process = None
                self._fail_pending_generation_unlocked(
                    generation,
                    EResult.NoConnection,
                )
                self.connected = False
                self.logged_in = False
        try:
            if process.poll() is None:
                process.terminate()
                with gevent.Timeout(5, False):
                    process.wait()
            if process.poll() is None:
                process.kill()
        except Exception:
            pass


def _make_client(account_id):
    client = SteamWorkerClient(_node_account_data_dir(account_id))
    client.set_credential_location(SENTRY_DIR)
    return client


class QuotaFenceActiveError(RuntimeError):
    """A hard quota cutoff crossed an in-flight Steam boost operation."""


class SteamAccountManager:
    def __init__(self, account_id, steam_username):
        self.account_id = account_id
        self.steam_username = steam_username
        self.client = _make_client(account_id)
        # All mutable runtime state for one Steam account is serialized through
        # this gevent-aware lock. It is public so route/timer/checkpoint code can
        # take one coherent snapshot instead of racing individual attributes.
        self.state_lock = RLock()
        # The hard quota fence must remain operable while state_lock is held by
        # a slow Node IPC request. Pending-segment storage therefore has its own
        # lock, and quota operation admission has a separate linearization lock.
        # Lock order is state_lock -> quota_fence_lock -> pending_lock. The
        # emergency path never acquires state_lock and never holds pending_lock
        # while terminating a worker.
        self._quota_fence_lock = RLock()
        self._pending_lock = RLock()
        self._quota_fence_serial = 0
        self._active_quota_fences = set()
        self._boost_operations_inflight = 0
        self._fenced_session_keys = set()
        self.logged_in = False
        self.boosting = False
        self.start_time = None
        self.original_start_time = None
        self._runtime_stop_deadline = None
        self.app_ids = []
        self.persona_state = 1
        self.boost_session_id = None
        self.boost_generation = 0
        self._pending_final_segments = self._load_pending_final_segments()
        self._finalized_segment_keys = []
        self._reconnect_attempts = 0
        self._reconnect_pending_generation = None
        self._reconnect_pending_token = None
        self._connection_event_generation = 0
        self._removed = False
        self._setup_events()

    def _begin_boost_operation_unlocked(self, session_key=None):
        """Admit one start/resume against the current quota-fence epoch."""
        with self._quota_fence_lock:
            if (
                self._active_quota_fences
                or (
                    session_key is not None
                    and session_key in self._fenced_session_keys
                )
            ):
                return None
            serial = self._quota_fence_serial
            self._boost_operations_inflight += 1
            return serial

    def _end_boost_operation(self):
        with self._quota_fence_lock:
            self._boost_operations_inflight = max(
                0,
                self._boost_operations_inflight - 1,
            )

    def _quota_fence_crossed(self, serial, session_key=None):
        with self._quota_fence_lock:
            return bool(
                serial != self._quota_fence_serial
                or self._active_quota_fences
                or (
                    session_key is not None
                    and session_key in self._fenced_session_keys
                )
            )

    def release_quota_fence(self, fence_token):
        """Release only the exact app-level fence; its serial stays monotonic."""
        with self._quota_fence_lock:
            if fence_token not in self._active_quota_fences:
                return False
            self._active_quota_fences.remove(fence_token)
            return True

    def _active_session_matches_unlocked(
        self,
        expected_session_id=None,
        expected_generation=None,
    ):
        if not self.boosting or self.boost_session_id is None:
            return False
        if (
            expected_session_id is not None
            and self.boost_session_id != expected_session_id
        ):
            return False
        if (
            expected_generation is not None
            and self.boost_generation != expected_generation
        ):
            return False
        return True

    def _snapshot_unlocked(self):
        with self._pending_lock:
            pending_segments = [
                self._copy_segment_unlocked(segment)
                for segment in self._pending_final_segments
            ]
        return {
            "boosting": self.boosting,
            "session_id": self.boost_session_id,
            "generation": self.boost_generation,
            "start_time": self.start_time,
            "original_start_time": self.original_start_time,
            "runtime_stop_deadline": self._runtime_stop_deadline,
            "app_ids": list(self.app_ids),
            "persona_state": self.persona_state,
            "logged_in": self.logged_in,
            "pending_final_segments": pending_segments,
        }

    def boost_snapshot(self):
        """Return one internally consistent copy of the account runtime state."""
        with self.state_lock:
            return self._snapshot_unlocked()

    def set_runtime_stop_deadline(
        self,
        deadline_epoch,
        *,
        expected_session_id=None,
        expected_generation=None,
    ):
        """Publish the current session's absolute billable stop boundary.

        The application scheduler owns the deadline calculation. Keeping the
        resulting boundary beside the live run makes fatal reconnect, manual
        stop, checkpoint and shutdown all create the same crash-durable segment
        even when the watchdog greenlet itself is scheduled late.
        """
        if deadline_epoch is not None:
            deadline_epoch = float(deadline_epoch)
            if not math.isfinite(deadline_epoch):
                raise ValueError("runtime stop deadline must be finite")
        with self.state_lock:
            if not self._active_session_matches_unlocked(
                expected_session_id=expected_session_id,
                expected_generation=expected_generation,
            ):
                return False
            with self._quota_fence_lock:
                self._runtime_stop_deadline = deadline_epoch
            return True

    @staticmethod
    def _copy_segment_unlocked(segment):
        copied = dict(segment)
        copied["app_ids"] = list(segment.get("app_ids") or [])
        return copied

    @staticmethod
    def _segment_matches(segment, *, session_id=None, generation=None):
        if session_id is not None and segment.get("session_id") != session_id:
            return False
        if generation is not None and segment.get("generation") != generation:
            return False
        return True

    def _load_pending_final_segments(self):
        path = _pending_final_segments_path(self.account_id)
        if not _path_exists(path):
            return []
        try:
            file_stat = os.lstat(path)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_size > MAX_PENDING_STATE_BYTES
            ):
                raise ValueError("Invalid pending segment state file")
            with open(path, "r", encoding="utf-8") as handle:
                raw_segments = json.load(handle)
            if (
                not isinstance(raw_segments, list)
                or len(raw_segments) > MAX_PENDING_FINAL_SEGMENTS
            ):
                raise ValueError("Invalid pending segment state payload")

            segments = []
            for raw in raw_segments:
                if not isinstance(raw, dict):
                    raise ValueError("Invalid pending segment")
                session_id = raw.get("session_id")
                generation = raw.get("generation")
                started_at = float(raw.get("started_at"))
                stopped_at = float(raw.get("stopped_at"))
                app_ids = raw.get("app_ids")
                remote_confirmed = raw.get("remote_stop_confirmed")
                checkpoint_only = raw.get("checkpoint_only", False)
                raw_remote_stopped_at = raw.get("remote_stopped_at")
                remote_stopped_at = (
                    None
                    if raw_remote_stopped_at is None
                    else float(raw_remote_stopped_at)
                )
                if (
                    raw.get("account_id") != self.account_id
                    or not isinstance(session_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session_id)
                    or type(generation) is not int
                    or generation < 0
                    or not math.isfinite(started_at)
                    or not math.isfinite(stopped_at)
                    or stopped_at < started_at
                    or not isinstance(app_ids, list)
                    or len(app_ids) > 64
                    or any(type(app_id) is not int or app_id <= 0 for app_id in app_ids)
                    or type(remote_confirmed) is not bool
                    or type(checkpoint_only) is not bool
                    or (
                        remote_stopped_at is not None
                        and not math.isfinite(remote_stopped_at)
                    )
                ):
                    raise ValueError("Invalid pending segment fields")
                segments.append({
                    "account_id": self.account_id,
                    "session_id": session_id,
                    "generation": generation,
                    "started_at": started_at,
                    "stopped_at": stopped_at,
                    "elapsed": max(0, stopped_at - started_at),
                    "app_ids": list(app_ids),
                    "remote_stop_confirmed": remote_confirmed,
                    "remote_stopped_at": remote_stopped_at,
                    "checkpoint_only": checkpoint_only,
                })
            return segments
        except Exception as exc:
            logger.critical(
                "[%s] Pending boost state could not be loaded: %s",
                self.steam_username,
                type(exc).__name__,
            )
            # Do not silently start a new run over state that could not be
            # reconciled.  Callers see a pending sentinel and fail closed.
            return [{
                "account_id": self.account_id,
                "session_id": "corrupt-pending-state",
                "generation": 0,
                "started_at": 0.0,
                "stopped_at": 0.0,
                "elapsed": 0.0,
                "app_ids": [],
                "remote_stop_confirmed": False,
                "remote_stopped_at": None,
                "checkpoint_only": False,
                "state_corrupt": True,
            }]

    def _save_pending_final_segments_unlocked(self):
        with self._pending_lock:
            path = _pending_final_segments_path(self.account_id)
            if not self._pending_final_segments:
                try:
                    if _path_exists(path):
                        _remove_artifact(path)
                        _fsync_directory(os.path.dirname(path))
                    return True
                except Exception as exc:
                    logger.critical(
                        "[%s] Pending boost state cleanup failed: %s",
                        self.steam_username,
                        type(exc).__name__,
                    )
                    return False

            try:
                account_dir = _ensure_private_directory(
                    _node_account_data_dir(self.account_id),
                    _node_account_data_root(),
                )
                temporary = _contained_path(
                    account_dir,
                    f"pending-final-segments.json.tmp-{uuid.uuid4().hex}",
                )
                try:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(temporary, flags, 0o600)
                    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                        json.dump(
                            self._pending_final_segments,
                            handle,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, path)
                    if os.name != "nt":
                        os.chmod(path, 0o600)
                    _fsync_directory(account_dir)
                finally:
                    if _path_exists(temporary):
                        _remove_artifact(temporary)
                return True
            except Exception as exc:
                logger.critical(
                    "[%s] Pending boost state persistence failed: %s",
                    self.steam_username,
                    type(exc).__name__,
                )
                return False

    def pending_final_segments(self, *, session_id=None, generation=None):
        with self._pending_lock:
            return [
                self._copy_segment_unlocked(segment)
                for segment in self._pending_final_segments
                if self._segment_matches(
                    segment,
                    session_id=session_id,
                    generation=generation,
                )
            ]

    def acknowledge_final_segment(self, segment):
        """Drop one pending final segment only after the DB commit is durable."""
        if not segment:
            return False
        session_id = segment.get("session_id")
        generation = segment.get("generation")
        started_at = segment.get("started_at")
        stopped_at = segment.get("stopped_at")
        checkpoint_only = bool(segment.get("checkpoint_only"))
        with self.state_lock, self._pending_lock:
            removed_segment = None
            removed_index = None
            for index, pending in enumerate(list(self._pending_final_segments)):
                if (
                    pending.get("session_id") == session_id
                    and pending.get("generation") == generation
                    and pending.get("started_at") == started_at
                    and pending.get("stopped_at") == stopped_at
                    and bool(pending.get("checkpoint_only")) == checkpoint_only
                ):
                    removed_segment = self._pending_final_segments.pop(index)
                    removed_index = index
                    break
            if removed_segment is not None and not self._save_pending_final_segments_unlocked():
                self._pending_final_segments.insert(removed_index, removed_segment)
                return False
            if (
                removed_segment is not None
                and not removed_segment.get("checkpoint_only")
            ):
                key = (session_id, generation)
                if key not in self._finalized_segment_keys:
                    self._finalized_segment_keys.append(key)
                    if len(self._finalized_segment_keys) > 128:
                        del self._finalized_segment_keys[:-128]
            return removed_segment is not None

    def cap_final_segment_stopped_at(self, segment, maximum_stopped_at):
        """Durably reduce a final segment to an absolute billing boundary.

        This is a defensive bridge for a stop that was prepared before the
        application could publish the session deadline. The pending identity is
        rewritten before any DB commit, so a crash between commit and ACK cannot
        later replay the uncapped interval.
        """
        if not segment:
            return None
        maximum_stopped_at = float(maximum_stopped_at)
        if not math.isfinite(maximum_stopped_at):
            raise ValueError("maximum_stopped_at must be finite")
        with self.state_lock, self._pending_lock:
            pending = self._find_pending_segment_unlocked(segment)
            target = (
                pending
                if pending is not None
                else self._copy_segment_unlocked(segment)
            )
            try:
                current_stopped_at = float(target.get("stopped_at"))
            except (TypeError, ValueError):
                return None
            capped_stopped_at = min(current_stopped_at, maximum_stopped_at)
            started_at = target.get("started_at")
            if started_at is not None:
                started_at = float(started_at)
                capped_stopped_at = max(started_at, capped_stopped_at)
            if capped_stopped_at >= current_stopped_at:
                return self._copy_segment_unlocked(target)

            previous_elapsed = target.get("elapsed")
            target["stopped_at"] = capped_stopped_at
            target["elapsed"] = (
                max(0.0, capped_stopped_at - started_at)
                if started_at is not None
                else 0.0
            )
            if pending is not None and not self._save_pending_final_segments_unlocked():
                target["stopped_at"] = current_stopped_at
                target["elapsed"] = previous_elapsed
                return None
            return self._copy_segment_unlocked(target)

    def was_final_segment_persisted(self, *, session_id=None, generation=None):
        if session_id is None and generation is None:
            return False
        with self.state_lock:
            return (session_id, generation) in self._finalized_segment_keys

    def retry_pending_final_segment_remote_stop(
        self,
        segment,
        *,
        context="pending final segment recovery",
    ):
        """Retry fail-closed remote shutdown for one durable-pending segment.

        A failed ``stop_games`` followed by a failed worker termination leaves
        the remote Steam state uncertain.  The local run must stay closed, but
        the segment cannot be committed as final until a later attempt proves
        that either Steam accepted the stop or the worker process was killed.
        """
        if not segment:
            return None
        with self.state_lock:
            with self._pending_lock:
                pending = self._find_pending_segment_unlocked(segment)
                if pending is None:
                    return None
                if pending.get("state_corrupt"):
                    return self._copy_segment_unlocked(pending)
                if pending.get("remote_stop_confirmed") is True:
                    return self._copy_segment_unlocked(pending)
            confirmed = self._stop_remote_games_unlocked(context)
            remote_stopped_at = time.time() if confirmed else None
            return self._record_pending_remote_stop_result(
                segment,
                confirmed=confirmed,
                remote_stopped_at=remote_stopped_at,
            )
        return None

    def _find_pending_segment_unlocked(self, segment):
        for pending in self._pending_final_segments:
            if (
                pending.get("session_id") == segment.get("session_id")
                and pending.get("generation") == segment.get("generation")
                and pending.get("started_at") == segment.get("started_at")
                and pending.get("stopped_at") == segment.get("stopped_at")
                and bool(pending.get("checkpoint_only"))
                == bool(segment.get("checkpoint_only"))
            ):
                return pending
        return None

    def _record_pending_remote_stop_result(
        self,
        segment,
        *,
        confirmed,
        remote_stopped_at=None,
    ):
        """Update a pending segment without exposing an undurable success."""
        with self._pending_lock:
            pending = self._find_pending_segment_unlocked(segment)
            if pending is None:
                return None
            if not confirmed:
                return self._copy_segment_unlocked(pending)

            previous_confirmed = pending.get("remote_stop_confirmed")
            previous_remote_stopped_at = pending.get("remote_stopped_at")
            pending["remote_stop_confirmed"] = True
            if previous_remote_stopped_at is None and remote_stopped_at is not None:
                pending["remote_stopped_at"] = float(remote_stopped_at)
            if not self._save_pending_final_segments_unlocked():
                pending["remote_stop_confirmed"] = previous_confirmed
                pending["remote_stopped_at"] = previous_remote_stopped_at
            return self._copy_segment_unlocked(pending)

    def _remember_final_segment_unlocked(self, segment):
        with self._pending_lock:
            if self._find_pending_segment_unlocked(segment) is not None:
                return True
            limit = (
                MAX_PENDING_CHECKPOINT_SEGMENTS
                if segment.get("checkpoint_only")
                else MAX_PENDING_FINAL_SEGMENTS
            )
            if len(self._pending_final_segments) >= limit:
                logger.critical(
                    "[%s] Pending boost state capacity reached; segment rejected",
                    self.steam_username,
                )
                return False
            self._pending_final_segments.append(self._copy_segment_unlocked(segment))
            if self._save_pending_final_segments_unlocked():
                return True
            self._pending_final_segments.pop()
            return False

    def _invalidate_boost_unlocked(self, *, force=False):
        with self._quota_fence_lock:
            session_key = (self.boost_session_id, self.boost_generation)
            had_runtime_state = bool(
                self.boosting
                or self.start_time is not None
                or self.original_start_time is not None
                or self.boost_session_id is not None
                or self._reconnect_pending_generation is not None
            )
            if force or had_runtime_state:
                self.boost_generation += 1
            self.boosting = False
            self.start_time = None
            self.original_start_time = None
            self._runtime_stop_deadline = None
            self.boost_session_id = None
            self._reconnect_pending_generation = None
            self._reconnect_pending_token = None
            self._fenced_session_keys.discard(session_key)

    def _stop_remote_games_unlocked(self, context):
        """Stop remote game state or kill the worker session fail-closed."""
        with self._quota_fence_lock:
            quota_fenced = bool(self._active_quota_fences)
        if quota_fenced:
            self._connection_event_generation += 1
            stopped = bool(self.client.force_disconnect())
            self.logged_in = False
            return stopped
        if self.client._closed:
            self.logged_in = False
            return bool(self.client.force_disconnect())
        fail_closed = False
        try:
            result = self.client.stop_games()
        except Exception as exc:
            result = EResult.Fail
            logger.warning(
                "[%s] Steam stop-games exception (%s): %s",
                self.steam_username,
                context,
                type(exc).__name__,
            )
        if result == EResult.OK:
            return True

        logger.error(
            "[%s] Steam stop-games was not confirmed (%s): %s; "
            "worker disconnected fail-closed",
            self.steam_username,
            context,
            result,
        )
        self._connection_event_generation += 1
        fail_closed = self.client.force_disconnect()
        self.logged_in = False
        return bool(fail_closed)

    def _record_all_pending_remote_stop_result(self, remote_stopped_at):
        """Mark every valid pending run stopped, atomically with its state file."""
        with self._pending_lock:
            changed = []
            for pending in self._pending_final_segments:
                if (
                    pending.get("state_corrupt")
                    or pending.get("remote_stop_confirmed") is True
                ):
                    continue
                changed.append((
                    pending,
                    pending.get("remote_stop_confirmed"),
                    pending.get("remote_stopped_at"),
                ))
                pending["remote_stop_confirmed"] = True
                if pending.get("remote_stopped_at") is None:
                    pending["remote_stopped_at"] = float(remote_stopped_at)
            if changed and not self._save_pending_final_segments_unlocked():
                for pending, previous_confirmed, previous_remote_at in changed:
                    pending["remote_stop_confirmed"] = previous_confirmed
                    pending["remote_stopped_at"] = previous_remote_at
                return False
            return True

    def emergency_quota_cutoff(self, stopped_at, fence_token, *, reason="quota"):
        """Fence boost IPC and kill remote state without waiting for state_lock.

        The billable segment is persisted before process termination. Local
        runtime invalidation deliberately remains on the normal state-locked
        prepare path; the monotonic fence serial prevents an older IPC response
        from committing in the meantime.
        """
        boundary_epoch = float(stopped_at)
        if not math.isfinite(boundary_epoch):
            raise ValueError("stopped_at must be finite")
        fence_token = str(fence_token or "")
        if not fence_token:
            raise ValueError("fence_token is required")

        with self._quota_fence_lock:
            if fence_token not in self._active_quota_fences:
                self._active_quota_fences.add(fence_token)
                self._quota_fence_serial += 1
            fence_serial = self._quota_fence_serial
            inflight = self._boost_operations_inflight > 0
            active = bool(
                self.boosting
                and self.boost_session_id is not None
                and self.start_time is not None
            )
            segment = None
            if active:
                started_at = float(self.start_time)
                billable_boundary = boundary_epoch
                if self._runtime_stop_deadline is not None:
                    billable_boundary = min(
                        billable_boundary,
                        self._runtime_stop_deadline,
                    )
                canonical_stop = max(started_at, billable_boundary)
                session_key = (self.boost_session_id, self.boost_generation)
                self._fenced_session_keys.add(session_key)
                segment = {
                    "account_id": self.account_id,
                    "session_id": self.boost_session_id,
                    "generation": self.boost_generation,
                    "started_at": started_at,
                    "stopped_at": canonical_stop,
                    "elapsed": max(0, canonical_stop - started_at),
                    "app_ids": list(self.app_ids),
                    "remote_stop_confirmed": False,
                    "remote_stopped_at": None,
                    "checkpoint_only": False,
                }

        durable = True
        if segment is not None:
            durable = self._remember_final_segment_unlocked(segment)
            if not durable:
                segment["local_stop_aborted"] = True
                logger.critical(
                    "[%s] Hard quota cutoff segment is not durable (%s)",
                    self.steam_username,
                    reason,
                )

        with self._pending_lock:
            unconfirmed_pending = any(
                pending.get("remote_stop_confirmed") is not True
                for pending in self._pending_final_segments
            )

        force_required = bool(active or inflight or unconfirmed_pending)
        remote_confirmed = True
        remote_stopped_at = None
        remote_lag_seconds = 0.0
        if force_required:
            # Invalidate a successful login/reconnect response that returned
            # just before this state-lock-free cutoff reached manager state.
            self._connection_event_generation += 1
            try:
                remote_confirmed = bool(self.client.force_disconnect())
            except Exception:
                remote_confirmed = False
                logger.exception(
                    "[%s] Hard quota worker termination failed (%s)",
                    self.steam_username,
                    reason,
                )
            remote_stopped_at = time.time()
            remote_lag_seconds = max(0.0, remote_stopped_at - boundary_epoch)
            with self._quota_fence_lock:
                self.logged_in = False
            if remote_confirmed:
                confirmations_durable = self._record_all_pending_remote_stop_result(
                    remote_stopped_at
                )
                with self._pending_lock:
                    unresolved = any(
                        pending.get("remote_stop_confirmed") is not True
                        for pending in self._pending_final_segments
                    )
                if not confirmations_durable or unresolved:
                    # Remote state is closed, but the confirmation is not
                    # durable; do not let the DB consume the pending record.
                    remote_confirmed = False

        if segment is not None:
            with self._pending_lock:
                persisted_segment = self._find_pending_segment_unlocked(segment)
                if persisted_segment is not None:
                    segment = self._copy_segment_unlocked(persisted_segment)

        return {
            "fence_token": fence_token,
            "fence_serial": fence_serial,
            "segment": segment,
            "durable": durable,
            "active": active,
            "inflight": inflight,
            "force_required": force_required,
            "remote_stop_confirmed": remote_confirmed,
            "remote_stopped_at": remote_stopped_at,
            "remote_lag_seconds": remote_lag_seconds,
        }

    @staticmethod
    def _invoke_fatal_disconnect_callback(segment):
        # A zero-duration segment still has DB/timer reconciliation work.
        if not segment:
            return
        callback = boost_service.fatal_disconnect_callback
        if callback is None:
            return

        args = (
            segment["account_id"],
            segment["elapsed"],
            segment["session_id"],
            segment["generation"],
            segment["started_at"],
            list(segment["app_ids"]),
            segment["stopped_at"],
        )
        try:
            signature = inspect.signature(callback)
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            accepts_varargs = any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL
                for parameter in signature.parameters.values()
            )
        except (TypeError, ValueError):
            # Some extension callables do not expose a Python signature. Keep
            # the established two-argument contract in that case.
            positional = []
            accepts_varargs = False

        # Resolve compatibility before invoking the handler. A TypeError raised
        # inside application callback code must not trigger a second invocation
        # and duplicate a financial/usage log.
        if accepts_varargs or len(positional) >= 7:
            callback(*args)
        elif len(positional) >= 6:
            callback(*args[:6])
        elif len(positional) >= 4:
            callback(*args[:4])
        else:
            callback(*args[:2])

    def _cred_path(self):
        return _credential_path(self.account_id, self.steam_username)

    def save_credentials(self, password=None, refresh_token=None):
        try:
            if self._removed:
                return False
            existing = {}
            path = self._cred_path()
            _ensure_private_directory(TOKEN_DIR, TOKEN_DIR)
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        existing = json.load(f)
                except Exception:
                    existing = {}

            data = {
                "password": existing.get("password"),
                "refresh_token": existing.get("refresh_token"),
                "saved_at": time.time(),
            }

            if password:
                enc = encrypt_password(password)
                if not enc:
                    logger.warning("[%s] Sifre sifrelenemedi", self.steam_username)
                    return False
                data["password"] = enc

            if refresh_token:
                enc_token = encrypt_password(refresh_token)
                if enc_token:
                    data["refresh_token"] = enc_token

            if not data.get("password") and not data.get("refresh_token"):
                return False

            temporary = f"{path}.tmp-{uuid.uuid4().hex}"
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(temporary, flags, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(data, handle, separators=(",", ":"))
                    handle.flush()
                    os.fsync(handle.fileno())
                if self._removed:
                    _remove_artifact(temporary)
                    return False
                os.replace(temporary, path)
                if os.name != "nt":
                    os.chmod(path, 0o600)
            finally:
                if _path_exists(temporary):
                    _remove_artifact(temporary)
            logger.info("[%s] Kimlik bilgileri kaydedildi", self.steam_username)
            return True
        except Exception as e:
            logger.error("[%s] Kimlik kaydetme hatasi: %s", self.steam_username, e)
            return False

    def load_credentials(self):
        path = self._cred_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                data = json.load(f)
            password = decrypt_password(data.get("password"))
            refresh_token = decrypt_password(data.get("refresh_token"))
            if not password and not refresh_token:
                return None
            return {"password": password, "refresh_token": refresh_token}
        except Exception as e:
            logger.error("[%s] Kimlik yukleme hatasi: %s", self.steam_username, e)
            return None

    def delete_credentials(self, *, include_legacy_machine_auth=False):
        return delete_saved_credentials(
            self.account_id,
            self.steam_username,
            include_legacy_machine_auth=include_legacy_machine_auth,
        )

    def has_credentials(self):
        return os.path.exists(self._cred_path())

    def has_token(self):
        return self.has_credentials()

    def _setup_events(self):
        def _process_disconnect_event(event_generation):
            logger.warning("[%s] Baglanti koptu", self.steam_username)
            with self.state_lock:
                if event_generation != self._connection_event_generation:
                    return
                self.logged_in = False
                generation = (
                    self.boost_generation
                    if self._active_session_matches_unlocked()
                    else None
                )
            if generation is not None:
                self._schedule_reconnect(generation)

        @self.client.on("disconnected")
        def _on_dc():
            # SteamWorkerClient emits from its stdout reader. Never let lock
            # contention in account state block that reader from resolving IPC.
            self._connection_event_generation += 1
            gevent.spawn(
                _process_disconnect_event,
                self._connection_event_generation,
            )

        def _process_login_event(event_generation):
            with self.state_lock:
                if event_generation != self._connection_event_generation:
                    return
                if self._removed:
                    self.logged_in = False
                    return
                logger.info("[%s] Giris basarili", self.steam_username)
                self.logged_in = True
                self._reconnect_attempts = 0
                self._reconnect_pending_generation = None
                self._reconnect_pending_token = None
                generation = (
                    self.boost_generation
                    if self._active_session_matches_unlocked()
                    else None
                )
                refresh_token = self.client.refresh_token
            if refresh_token:
                self.save_credentials(refresh_token=refresh_token)
            if generation is not None:
                gevent.spawn(self._resume_boost, generation)

        @self.client.on("logged_on")
        def _on_login():
            # Keep the worker stdout reader free to deliver responses consumed
            # by credential persistence and resume IPC.
            self._connection_event_generation += 1
            gevent.spawn(
                _process_login_event,
                self._connection_event_generation,
            )

        @self.client.on("new_login_key")
        def _on_new_key():
            logger.info("[%s] new_login_key alindi", self.steam_username)

    def _schedule_reconnect(
        self,
        expected_generation=None,
        expected_connection_generation=None,
    ):
        finalize_generation = None
        finalize_reconnect_token = None
        finalize_connection_generation = None
        with self.state_lock:
            if (
                expected_connection_generation is not None
                and self._connection_event_generation
                != expected_connection_generation
            ):
                return
            if self._removed or not self._active_session_matches_unlocked(
                expected_generation=expected_generation
            ):
                return
            generation = self.boost_generation
            if self._reconnect_pending_generation == generation:
                return
            if self._reconnect_attempts >= 5:
                finalize_generation = generation
                finalize_reconnect_token = uuid.uuid4().hex
                finalize_connection_generation = self._connection_event_generation
                self._reconnect_pending_generation = generation
                self._reconnect_pending_token = finalize_reconnect_token
            else:
                delay = min(30 * (2 ** self._reconnect_attempts), 300)
                self._reconnect_attempts += 1
                self._reconnect_pending_generation = generation
                reconnect_token = uuid.uuid4().hex
                self._reconnect_pending_token = reconnect_token

        if finalize_generation is not None:
            logger.error("[%s] Max reconnect asildi", self.steam_username)
            self._finalize_fatal_session(
                finalize_generation,
                "maximum reconnect attempts exceeded",
                expected_reconnect_token=finalize_reconnect_token,
                expected_connection_generation=finalize_connection_generation,
            )
            return

        logger.info("[%s] %dsn sonra reconnect", self.steam_username, delay)
        try:
            gevent.spawn_later(
                delay,
                self._try_reconnect,
                generation,
                reconnect_token,
            )
        except Exception:
            with self.state_lock:
                if (
                    self._reconnect_pending_generation == generation
                    and self._reconnect_pending_token == reconnect_token
                ):
                    self._reconnect_pending_generation = None
                    self._reconnect_pending_token = None
            logger.exception("[%s] Reconnect zamanlanamadi", self.steam_username)

    def _reconnect_attempt_matches_unlocked(
        self,
        generation,
        reconnect_token,
        connection_generation,
    ):
        return bool(
            not self._removed
            and self._active_session_matches_unlocked(
                expected_generation=generation
            )
            and self._reconnect_pending_generation == generation
            and self._reconnect_pending_token == reconnect_token
            and self._connection_event_generation == connection_generation
        )

    def _reschedule_after_connection_generation_change(
        self,
        generation,
        reconnect_token,
        connection_generation,
    ):
        """Atomically replace a stale transport attempt with its successor."""
        finalize_generation = None
        finalize_reconnect_token = None
        finalize_connection_generation = None
        delay = None
        successor_token = None
        with self.state_lock:
            if (
                self._removed
                or not self._active_session_matches_unlocked(
                    expected_generation=generation
                )
                or self._reconnect_pending_generation != generation
                or self._reconnect_pending_token != reconnect_token
                or self._connection_event_generation == connection_generation
            ):
                return False

            # Replace the ticket while holding state_lock. Clearing it first and
            # scheduling later leaves a small gap where a newer disconnect event
            # can observe the old ticket, decline to schedule, and strand the
            # active session without any reconnect work.
            if self._reconnect_attempts >= 5:
                finalize_generation = generation
                finalize_reconnect_token = uuid.uuid4().hex
                finalize_connection_generation = self._connection_event_generation
                self._reconnect_pending_generation = generation
                self._reconnect_pending_token = finalize_reconnect_token
            else:
                delay = min(30 * (2 ** self._reconnect_attempts), 300)
                self._reconnect_attempts += 1
                successor_token = uuid.uuid4().hex
                self._reconnect_pending_generation = generation
                self._reconnect_pending_token = successor_token

        if finalize_generation is not None:
            logger.error("[%s] Max reconnect asildi", self.steam_username)
            self._finalize_fatal_session(
                finalize_generation,
                "maximum reconnect attempts exceeded",
                expected_reconnect_token=finalize_reconnect_token,
                expected_connection_generation=finalize_connection_generation,
            )
            return True

        logger.info("[%s] %dsn sonra reconnect", self.steam_username, delay)
        try:
            gevent.spawn_later(
                delay,
                self._try_reconnect,
                generation,
                successor_token,
            )
        except Exception:
            with self.state_lock:
                if (
                    self._reconnect_pending_generation == generation
                    and self._reconnect_pending_token == successor_token
                ):
                    self._reconnect_pending_generation = None
                    self._reconnect_pending_token = None
            logger.exception("[%s] Reconnect zamanlanamadi", self.steam_username)
            return False
        return True

    def _try_reconnect(self, expected_generation=None, reconnect_token=None):
        with self.state_lock:
            if self._removed or not self._active_session_matches_unlocked(
                expected_generation=expected_generation
            ):
                return
            generation = self.boost_generation
            if reconnect_token is not None:
                if (
                    self._reconnect_pending_generation != generation
                    or self._reconnect_pending_token != reconnect_token
                ):
                    return
            elif (
                self._reconnect_pending_generation == generation
                and self._reconnect_pending_token is not None
            ):
                reconnect_token = self._reconnect_pending_token
            else:
                # Direct/internal callers still receive the same behavior, but
                # now participate in the same CAS protocol as scheduled work.
                reconnect_token = uuid.uuid4().hex
                self._reconnect_pending_generation = generation
                self._reconnect_pending_token = reconnect_token
            connection_generation = self._connection_event_generation

        try:
            creds = self.load_credentials()
            if not creds:
                with self.state_lock:
                    attempt_matches = self._reconnect_attempt_matches_unlocked(
                        generation,
                        reconnect_token,
                        connection_generation,
                    )
                if not attempt_matches:
                    self._reschedule_after_connection_generation_change(
                        generation,
                        reconnect_token,
                        connection_generation,
                    )
                    return
                logger.warning(
                    "[%s] Kayitli kimlik yok; aktif boost sonlandiriliyor",
                    self.steam_username,
                )
                self._finalize_fatal_session(
                    generation,
                    "saved credentials unavailable",
                    expected_reconnect_token=reconnect_token,
                    expected_connection_generation=connection_generation,
                )
                return

            result = self._login_with_saved_credentials(creds)
            if result == EResult.OK:
                return
            with self.state_lock:
                attempt_matches = self._reconnect_attempt_matches_unlocked(
                    generation,
                    reconnect_token,
                    connection_generation,
                )
            if not attempt_matches:
                self._reschedule_after_connection_generation_change(
                    generation,
                    reconnect_token,
                    connection_generation,
                )
                return
            if result in (
                EResult.AccountLogonDenied,
                EResult.AccountLoginDeniedNeedTwoFactor,
                EResult.InvalidLoginAuthCode,
                EResult.TwoFactorCodeMismatch,
                EResult.InvalidPassword,
            ):
                logger.warning(
                    "[%s] Terminal reconnect sonucu %s; aktif boost "
                    "sonlandiriliyor",
                    self.steam_username,
                    result,
                )
                self._finalize_fatal_session(
                    generation,
                    f"terminal reconnect result {int(result)}",
                    expected_reconnect_token=reconnect_token,
                    expected_connection_generation=connection_generation,
                )
                return

            self.client.reconnect(maxdelay=30)
            with self.state_lock:
                attempt_matches = self._reconnect_attempt_matches_unlocked(
                    generation,
                    reconnect_token,
                    connection_generation,
                )
                if attempt_matches:
                    self._reconnect_pending_generation = None
                    self._reconnect_pending_token = None
            if not attempt_matches:
                self._reschedule_after_connection_generation_change(
                    generation,
                    reconnect_token,
                    connection_generation,
                )
                return
            self._schedule_reconnect(
                generation,
                expected_connection_generation=connection_generation,
            )
        except Exception as e:
            logger.error("[%s] Reconnect hatasi: %s", self.steam_username, e)
            with self.state_lock:
                attempt_matches = self._reconnect_attempt_matches_unlocked(
                    generation,
                    reconnect_token,
                    connection_generation,
                )
                if attempt_matches:
                    self._reconnect_pending_generation = None
                    self._reconnect_pending_token = None
            if not attempt_matches:
                self._reschedule_after_connection_generation_change(
                    generation,
                    reconnect_token,
                    connection_generation,
                )
                return
            self._schedule_reconnect(
                generation,
                expected_connection_generation=connection_generation,
            )

    def _record_login_success(
        self,
        password=None,
        *,
        expected_connection_generation=None,
    ):
        with self.state_lock:
            if (
                self._removed
                or self.client._closed
                or (
                    expected_connection_generation is not None
                    and self._connection_event_generation
                    != expected_connection_generation
                )
            ):
                self.logged_in = False
                return False
            # The synchronous login response is newer than any event task that
            # was queued before it; invalidate those stale connection updates.
            self._connection_event_generation += 1
            self.logged_in = True
            self._reconnect_attempts = 0
            self._reconnect_pending_generation = None
            self._reconnect_pending_token = None
            generation = (
                self.boost_generation
                if self._active_session_matches_unlocked()
                else None
            )
        if password or self.client.refresh_token:
            self.save_credentials(password=password, refresh_token=self.client.refresh_token)
        if generation is not None:
            gevent.spawn(self._resume_boost, generation)
        return True

    def _login_with_saved_credentials(self, creds, code=None, code_type="2fa"):
        if self._removed:
            return EResult.NoConnection
        refresh_token = creds.get("refresh_token")
        password = creds.get("password")

        if refresh_token and not code:
            with self.state_lock:
                connection_generation = self._connection_event_generation
            result = self.client.login(
                username=self.steam_username,
                refresh_token=refresh_token,
            )
            if self._removed:
                return EResult.NoConnection
            if result == EResult.OK:
                if self._record_login_success(
                    expected_connection_generation=connection_generation
                ):
                    return result
                return EResult.NoConnection
            logger.warning(
                "[%s] Refresh token login basarisiz: %s, sifre fallback deneniyor",
                self.steam_username,
                result,
            )

        if password and not self._removed:
            return self._login_with_credentials(password, code=code, code_type=code_type)
        return EResult.NoConnection if self._removed else EResult.InvalidPassword

    def _login_with_credentials(self, password, code=None, code_type="2fa"):
        try:
            if self._removed:
                return EResult.NoConnection
            with self.state_lock:
                connection_generation = self._connection_event_generation
            if code:
                if code_type == "email":
                    result = self.client.login(
                        username=self.steam_username,
                        password=password,
                        auth_code=code,
                    )
                else:
                    result = self.client.login(
                        username=self.steam_username,
                        password=password,
                        two_factor_code=code,
                    )
            else:
                result = self.client.login(
                    username=self.steam_username,
                    password=password,
                )

            if self._removed:
                return EResult.NoConnection
            if result == EResult.OK:
                if not self._record_login_success(
                    password=password,
                    expected_connection_generation=connection_generation,
                ):
                    return EResult.NoConnection
                logger.info("[%s] Kimlik bilgileriyle giris basarili", self.steam_username)
            else:
                logger.warning(
                    "[%s] Kimlik bilgileriyle giris basarisiz: %s",
                    self.steam_username,
                    result,
                )
            return result
        except Exception as e:
            logger.error("[%s] Credential login hatasi: %s", self.steam_username, e)
            return EResult.Fail

    def _prepare_stop_boost_segment_unlocked(
        self,
        *,
        expected_session_id=None,
        expected_generation=None,
        stopped_at=None,
        context="explicit stop",
    ):
        with self._quota_fence_lock:
            if (
                expected_session_id is not None
                or expected_generation is not None
            ) and not self._active_session_matches_unlocked(
                expected_session_id=expected_session_id,
                expected_generation=expected_generation,
            ):
                return None
            if not self.boosting:
                return None

            started_at = self.start_time
            if stopped_at is None:
                stopped_at = time.time()
            else:
                stopped_at = float(stopped_at)
                if not math.isfinite(stopped_at):
                    raise ValueError("stopped_at must be finite")
            if self._runtime_stop_deadline is not None:
                stopped_at = min(stopped_at, self._runtime_stop_deadline)
            if started_at is not None:
                stopped_at = max(float(started_at), stopped_at)
            segment = {
                "account_id": self.account_id,
                "session_id": self.boost_session_id,
                "generation": self.boost_generation,
                "started_at": started_at,
                "stopped_at": stopped_at,
                "elapsed": max(0, stopped_at - started_at)
                if started_at is not None
                else 0,
                "app_ids": list(self.app_ids),
                "remote_stop_confirmed": False,
                "remote_stopped_at": None,
                "checkpoint_only": False,
            }

            # Write the recovery record before yielding to IPC. A process kill
            # between local invalidation and the Steam response must still leave
            # enough information for the next process to finalize this segment.
            if not self._remember_final_segment_unlocked(segment):
                segment["local_stop_aborted"] = True
                logger.critical(
                    "[%s] Boost stop aborted: pending state is not durable",
                    self.steam_username,
                )
                return self._copy_segment_unlocked(segment)
            # Local state is closed before IPC. A synchronous disconnected event
            # can therefore never observe boosting=True and schedule a new loop.
            self._invalidate_boost_unlocked(force=True)
            return self._copy_segment_unlocked(segment)

    def prepare_stop_boost_segment(
        self,
        *,
        expected_session_id=None,
        expected_generation=None,
        stopped_at=None,
        context="explicit stop",
    ):
        """Durably close one local run without waiting for Steam IPC.

        User-level quota enforcement prepares every account with the same
        canonical ``stopped_at`` before any network request.  This bounds
        aggregate usage even when one account's Node worker responds slowly.
        The returned segment must subsequently be passed to
        :meth:`confirm_prepared_stop_segment` and persisted by the caller.
        """
        with self.state_lock:
            return self._prepare_stop_boost_segment_unlocked(
                expected_session_id=expected_session_id,
                expected_generation=expected_generation,
                stopped_at=stopped_at,
                context=context,
            )

    def _confirm_prepared_stop_segment_unlocked(
        self,
        segment,
        *,
        context="explicit stop",
    ):
        if not segment or segment.get("local_stop_aborted"):
            return self._copy_segment_unlocked(segment) if segment else None

        with self._pending_lock:
            pending_match = self._find_pending_segment_unlocked(segment)
            pending_copy = (
                self._copy_segment_unlocked(pending_match)
                if pending_match is not None
                else None
            )
        if pending_match is None:
            # Another reconciliation path may have confirmed, committed, and
            # acknowledged this exact run while a user-level hard fence was
            # waiting on a different account's IPC. Treat that as idempotent
            # success instead of emitting a false durability failure.
            finalized_key = (
                segment.get("session_id"),
                segment.get("generation"),
            )
            if finalized_key in self._finalized_segment_keys:
                completed = self._copy_segment_unlocked(segment)
                completed["remote_stop_confirmed"] = True
                completed["already_persisted"] = True
                return completed
            logger.critical(
                "[%s] Prepared boost segment is not durable; remote stop skipped",
                self.steam_username,
            )
            failed = self._copy_segment_unlocked(segment)
            failed["remote_stop_confirmed"] = False
            failed["local_stop_aborted"] = True
            return failed

        if pending_copy.get("remote_stop_confirmed") is not True:
            confirmed = self._stop_remote_games_unlocked(context)
            updated = self._record_pending_remote_stop_result(
                segment,
                confirmed=confirmed,
                remote_stopped_at=time.time() if confirmed else None,
            )
            if updated is None:
                failed = self._copy_segment_unlocked(segment)
                failed["remote_stop_confirmed"] = False
                failed["local_stop_aborted"] = True
                return failed
            return updated
        return pending_copy

    def confirm_prepared_stop_segment(
        self,
        segment,
        *,
        context="explicit stop",
    ):
        """Confirm Steam shutdown for a previously prepared final segment."""
        with self.state_lock:
            return self._confirm_prepared_stop_segment_unlocked(
                segment,
                context=context,
            )

    def _stop_boost_session(
        self,
        *,
        expected_session_id=None,
        expected_generation=None,
        context="explicit stop",
        expected_reconnect_token=None,
        expected_connection_generation=None,
    ):
        with self.state_lock:
            if expected_reconnect_token is not None:
                if (
                    self._reconnect_pending_generation != expected_generation
                    or self._reconnect_pending_token
                    != expected_reconnect_token
                    or (
                        expected_connection_generation is not None
                        and self._connection_event_generation
                        != expected_connection_generation
                    )
                ):
                    return None
            segment = self._prepare_stop_boost_segment_unlocked(
                expected_session_id=expected_session_id,
                expected_generation=expected_generation,
                context=context,
            )
            if segment is None or segment.get("local_stop_aborted"):
                return segment
            return self._confirm_prepared_stop_segment_unlocked(
                segment,
                context=context,
            )

    def _schedule_fatal_finalization_retry(
        self,
        expected_generation,
        reason,
        *,
        expected_reconnect_token=None,
    ):
        """Publish one CAS-protected retry after a fatal stop could not commit."""
        with self.state_lock:
            if (
                self._removed
                or not self._active_session_matches_unlocked(
                    expected_generation=expected_generation
                )
                or (
                    expected_reconnect_token is not None
                    and (
                        self._reconnect_pending_generation != expected_generation
                        or self._reconnect_pending_token
                        != expected_reconnect_token
                    )
                )
            ):
                return False

            retry_token = uuid.uuid4().hex
            connection_generation = self._connection_event_generation
            self._reconnect_pending_generation = expected_generation
            self._reconnect_pending_token = retry_token

        try:
            gevent.spawn_later(
                FATAL_FINALIZATION_RETRY_SECONDS,
                self._finalize_fatal_session,
                expected_generation,
                reason,
                expected_reconnect_token=retry_token,
                expected_connection_generation=connection_generation,
            )
        except Exception:
            with self.state_lock:
                if (
                    self._reconnect_pending_generation == expected_generation
                    and self._reconnect_pending_token == retry_token
                ):
                    self._reconnect_pending_generation = None
                    self._reconnect_pending_token = None
            logger.critical(
                "[%s] Fatal boost finalization retry could not be scheduled",
                self.steam_username,
                exc_info=True,
            )
            return False
        return True

    def _finalize_fatal_session(
        self,
        expected_generation,
        reason,
        *,
        expected_reconnect_token=None,
        expected_connection_generation=None,
    ):
        segment = self._stop_boost_session(
            expected_generation=expected_generation,
            context=f"fatal reconnect: {reason}",
            expected_reconnect_token=expected_reconnect_token,
            expected_connection_generation=expected_connection_generation,
        )
        if segment is None:
            self._schedule_fatal_finalization_retry(
                expected_generation,
                reason,
                expected_reconnect_token=expected_reconnect_token,
            )
            return False
        if segment.get("local_stop_aborted"):
            logger.critical(
                "[%s] Fatal boost finalization postponed: pending state is not durable",
                self.steam_username,
            )
            self._schedule_fatal_finalization_retry(
                expected_generation,
                reason,
                expected_reconnect_token=expected_reconnect_token,
            )
            return False
        logger.error(
            "[%s] Boost session fail-closed sonlandirildi: %s",
            self.steam_username,
            reason,
        )
        # Never call application/DB code while state_lock is held. Application
        # routes acquire user_operation_lock before state_lock, so reversing that
        # order here would create a cross-greenlet deadlock.
        try:
            self._invoke_fatal_disconnect_callback(segment)
        except Exception:
            logger.exception(
                "[%s] Fatal disconnect callback hatasi",
                self.steam_username,
            )
        return True

    def _resume_boost(self, expected_generation=None):
        failure = None
        fenced = False
        operation_started = False
        with self.state_lock:
            if (
                self._removed
                or not self.logged_in
                or not self._active_session_matches_unlocked(
                    expected_generation=expected_generation
                )
            ):
                return False
            generation = self.boost_generation
            session_key = (self.boost_session_id, generation)
            operation_serial = self._begin_boost_operation_unlocked(session_key)
            if operation_serial is None:
                return False
            operation_started = True
            try:
                result = self.client.change_status(
                    persona_state=EPersonaState(self.persona_state)
                )
                fenced = self._quota_fence_crossed(
                    operation_serial,
                    session_key,
                )
                if fenced:
                    failure = "quota fence"
                elif result != EResult.OK:
                    failure = f"persona result {int(result)}"
                else:
                    result = self.client.games_played(list(self.app_ids))
                    fenced = self._quota_fence_crossed(
                        operation_serial,
                        session_key,
                    )
                    if fenced:
                        failure = "quota fence"
                    elif result != EResult.OK:
                        failure = f"games result {int(result)}"
            except Exception as exc:
                failure = f"{type(exc).__name__}"
                fenced = self._quota_fence_crossed(
                    operation_serial,
                    session_key,
                )
            finally:
                if operation_started:
                    self._end_boost_operation()

            if fenced:
                self.logged_in = False

        if fenced:
            if self.client.connected:
                self.client.force_disconnect()
            logger.info(
                "[%s] Boost resume hard quota fence tarafindan iptal edildi",
                self.steam_username,
            )
            return False
        if failure is not None:
            logger.error("[%s] Resume hatasi: %s", self.steam_username, failure)
            self._finalize_fatal_session(generation, f"resume failed: {failure}")
            return False
        with self.state_lock:
            if not self._active_session_matches_unlocked(
                expected_generation=generation
            ):
                return False
        logger.info("[%s] Boost devam ediyor", self.steam_username)
        return True

    def login(self, password=None, code=None, code_type="email"):
        if self._removed:
            return EResult.NoConnection
        if not password:
            creds = self.load_credentials()
            if creds:
                return self._login_with_saved_credentials(creds, code=code, code_type=code_type)
            return EResult.InvalidPassword

        return self._login_with_credentials(password, code=code, code_type=code_type)

    def start_boost(self, app_ids, persona_state=1):
        candidate_app_ids = list(app_ids or [])
        with self.state_lock:
            if self._removed or self.client._closed or not self.logged_in:
                raise Exception("Steam bagli degil")
            if self.boosting:
                raise Exception("Steam boost zaten aktif")
            operation_serial = self._begin_boost_operation_unlocked()
            if operation_serial is None:
                raise QuotaFenceActiveError("Hard quota fence is active")
            try:
                result = self.client.change_status(
                    persona_state=EPersonaState(persona_state)
                )
                if self._quota_fence_crossed(operation_serial):
                    if self.client.connected:
                        self.client.force_disconnect()
                    self.logged_in = False
                    raise QuotaFenceActiveError(
                        "Hard quota fence crossed Steam status IPC"
                    )
                if result != EResult.OK:
                    self._stop_remote_games_unlocked("start persona failure")
                    raise Exception(f"Steam status degistirilemedi: {result}")

                result = self.client.games_played(candidate_app_ids)
                if self._quota_fence_crossed(operation_serial):
                    if self.client.connected:
                        self.client.force_disconnect()
                    self.logged_in = False
                    raise QuotaFenceActiveError(
                        "Hard quota fence crossed Steam games IPC"
                    )
                if result != EResult.OK:
                    self._stop_remote_games_unlocked("start games failure")
                    raise Exception(f"Steam boost baslatilamadi: {result}")

                with self._quota_fence_lock:
                    if (
                        operation_serial != self._quota_fence_serial
                        or self._active_quota_fences
                    ):
                        fenced_before_commit = True
                    else:
                        fenced_before_commit = False
                        now = time.time()
                        self.boost_generation += 1
                        self.boost_session_id = uuid.uuid4().hex
                        self.app_ids = candidate_app_ids
                        self.persona_state = persona_state
                        self.boosting = True
                        self.start_time = now
                        self.original_start_time = now
                        self._runtime_stop_deadline = None
                        self._reconnect_attempts = 0
                        self._reconnect_pending_generation = None
                        self._reconnect_pending_token = None
                if fenced_before_commit:
                    if self.client.connected:
                        self.client.force_disconnect()
                    self.logged_in = False
                    raise QuotaFenceActiveError(
                        "Hard quota fence crossed before boost commit"
                    )
                return self._snapshot_unlocked()
            finally:
                self._end_boost_operation()

    def stop_boost(
        self,
        *,
        expected_session_id=None,
        expected_generation=None,
    ):
        """Stop one session and return elapsed seconds (legacy-compatible).

        Supplying either expectation turns this into compare-and-stop: a stale
        timer/checkpoint cannot stop a newer boost session.
        """
        segment = self._stop_boost_session(
            expected_session_id=expected_session_id,
            expected_generation=expected_generation,
            context="explicit stop",
        )
        return segment["elapsed"] if segment is not None else 0

    def stop_boost_segment(
        self,
        *,
        expected_session_id=None,
        expected_generation=None,
        context="explicit stop",
    ):
        """Stop one session and return the pending final segment metadata."""
        return self._stop_boost_session(
            expected_session_id=expected_session_id,
            expected_generation=expected_generation,
            context=context,
        )

    def prepare_boost_checkpoint(
        self,
        *,
        expected_session_id=None,
        expected_generation=None,
        min_elapsed=0,
        now=None,
    ):
        """Durably capture and advance one active usage segment.

        The pending record is written before ``start_time`` advances. A hard
        quota fence can therefore cut the new interval while the checkpoint DB
        commit is yielding without ever double-billing the old interval.
        """
        with self.state_lock:
            with self._quota_fence_lock:
                if not self._active_session_matches_unlocked(
                    expected_session_id=expected_session_id,
                    expected_generation=expected_generation,
                ):
                    return None
                session_key = (self.boost_session_id, self.boost_generation)
                if (
                    self._active_quota_fences
                    or session_key in self._fenced_session_keys
                    or self.start_time is None
                ):
                    return None
                stopped_at = time.time() if now is None else float(now)
                if not math.isfinite(stopped_at):
                    raise ValueError("checkpoint time must be finite")
                if self._runtime_stop_deadline is not None:
                    stopped_at = min(stopped_at, self._runtime_stop_deadline)
                stopped_at = max(float(self.start_time), stopped_at)
                elapsed = max(0, stopped_at - self.start_time)
                if elapsed < max(0, float(min_elapsed or 0)):
                    return None
                checkpoint = {
                    "account_id": self.account_id,
                    "session_id": self.boost_session_id,
                    "generation": self.boost_generation,
                    "started_at": self.start_time,
                    "stopped_at": stopped_at,
                    "elapsed": elapsed,
                    "app_ids": list(self.app_ids),
                    "remote_stop_confirmed": True,
                    "remote_stopped_at": None,
                    "checkpoint_only": True,
                }
                if not self._remember_final_segment_unlocked(checkpoint):
                    logger.critical(
                        "[%s] Boost checkpoint aborted: pending state is not durable",
                        self.steam_username,
                    )
                    return None
                self.start_time = stopped_at
                return self._copy_segment_unlocked(checkpoint)

    def advance_boost_checkpoint(
        self,
        *,
        expected_session_id=None,
        expected_generation=None,
        min_elapsed=0,
        now=None,
    ):
        """Backward-compatible alias for the durable checkpoint transition."""
        return self.prepare_boost_checkpoint(
            expected_session_id=expected_session_id,
            expected_generation=expected_generation,
            min_elapsed=min_elapsed,
            now=now,
        )

    def rollback_boost_checkpoint(self, checkpoint):
        """Restore an uncommitted checkpoint without rewinding newer state."""
        if not isinstance(checkpoint, dict):
            return False
        with self.state_lock, self._quota_fence_lock:
            if not self._active_session_matches_unlocked(
                expected_session_id=checkpoint.get("session_id"),
                expected_generation=checkpoint.get("generation"),
            ):
                return False
            session_key = (self.boost_session_id, self.boost_generation)
            if (
                self._active_quota_fences
                or session_key in self._fenced_session_keys
                or self.start_time != checkpoint.get("stopped_at")
            ):
                return False
            started_at = checkpoint.get("started_at")
            if started_at is None:
                return False
            with self._pending_lock:
                pending = self._find_pending_segment_unlocked(checkpoint)
                if pending is None or not pending.get("checkpoint_only"):
                    return False
                index = self._pending_final_segments.index(pending)
                removed = self._pending_final_segments.pop(index)
                if not self._save_pending_final_segments_unlocked():
                    self._pending_final_segments.insert(index, removed)
                    return False
            self.start_time = started_at
            return True

    def set_persona(self, state):
        with self.state_lock:
            self.persona_state = state
            if self.logged_in and not self._removed:
                try:
                    self.client.change_status(persona_state=EPersonaState(state))
                except Exception:
                    pass

    def disconnect(self, permanent=False):
        with self.state_lock:
            self._invalidate_boost_unlocked(force=not self._removed)
            stop_confirmed = True
            if not permanent:
                stop_confirmed = self._stop_remote_games_unlocked("disconnect")
            try:
                if permanent or stop_confirmed:
                    self.client.disconnect(permanent=permanent)
            except Exception:
                pass
            self.logged_in = False

    def remove_completely(self, *, include_legacy_machine_auth=False):
        segment = self.stop_boost_segment(context="permanent removal")
        if segment and (
            segment.get("local_stop_aborted")
            or segment.get("remote_stop_confirmed") is False
        ):
            return False
        self.mark_removed()
        self.disconnect(permanent=True)
        return self.delete_credentials(
            include_legacy_machine_auth=include_legacy_machine_auth
        )

    def mark_removed(self):
        """Synchronously make callbacks/reconnects inert before blocking IPC."""
        with self.state_lock:
            self._removed = True
            self.logged_in = False
            self._invalidate_boost_unlocked(force=True)
            self.client.mark_closed()

    def summary(self):
        with self.state_lock:
            snapshot = self._snapshot_unlocked()
            return {
                "id": self.account_id,
                "steam_username": self.steam_username,
                "logged_in": snapshot["logged_in"],
                "boosting": snapshot["boosting"],
                "start_time": snapshot["original_start_time"],
                "app_ids": snapshot["app_ids"],
                "persona_state": snapshot["persona_state"],
                "boost_session_id": snapshot["session_id"],
                "boost_generation": snapshot["generation"],
                "has_token": self.has_token(),
            }


class BoostService:
    def __init__(self):
        self._managers = {}
        self.fatal_disconnect_callback = None

    def get(self, account_id):
        return self._managers.get(account_id)

    def get_or_create(self, account_id, steam_username):
        if account_id not in self._managers:
            self._managers[account_id] = SteamAccountManager(account_id, steam_username)
        return self._managers[account_id]

    def remove(
        self,
        account_id,
        steam_username=None,
        *,
        include_legacy_machine_auth=False,
    ):
        mgr = self.detach(account_id)
        if mgr:
            return mgr.remove_completely(
                include_legacy_machine_auth=include_legacy_machine_auth
            )
        if steam_username is not None:
            return delete_saved_credentials(
                account_id,
                steam_username,
                include_legacy_machine_auth=include_legacy_machine_auth,
            )
        return True

    def detach(self, account_id):
        """Pop and deactivate a manager without yielding on Node IPC."""
        mgr = self._managers.pop(account_id, None)
        if mgr:
            mgr.mark_removed()
        return mgr

    def all_managers(self):
        return list(self._managers.items())

    def active_boosts(self):
        managers = list(self._managers.values())
        return sum(
            1 for manager in managers
            if manager.boost_snapshot()["boosting"]
        )

    def stats(self):
        snapshots = [
            manager.boost_snapshot()
            for manager in list(self._managers.values())
        ]
        return {
            "total": len(snapshots),
            "active_boosts": sum(1 for item in snapshots if item["boosting"]),
            "logged_in": sum(1 for item in snapshots if item["logged_in"]),
        }


boost_service = BoostService()
