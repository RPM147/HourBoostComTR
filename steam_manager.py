import json
import logging
import os
import shutil
import time
import uuid
from collections import defaultdict

import gevent
from gevent import queue
from gevent import subprocess

from steam_compat import EPersonaState, EResult

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(__file__)
TOKEN_DIR = os.path.join(BASE_DIR, "tokens")
os.makedirs(TOKEN_DIR, exist_ok=True)
if os.name != "nt":
    try:
        os.chmod(TOKEN_DIR, 0o700)
    except Exception:
        pass

SENTRY_DIR = os.path.join(BASE_DIR, "sentry")
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
    def __init__(self):
        self.connected = False
        self.logged_in = False
        self.steam_id = None
        self.refresh_token = None
        self._process = None
        self._pending = {}
        self._handlers = defaultdict(list)
        self._reader_greenlet = None
        self._stderr_greenlet = None

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
        if self._process and self._process.poll() is None:
            return True

        if not os.path.exists(WORKER_SCRIPT):
            logger.error("Steam worker bulunamadi: %s", WORKER_SCRIPT)
            return False

        env = os.environ.copy()
        env["STEAM_WORKER_DATA_DIR"] = NODE_DATA_DIR
        try:
            self._process = subprocess.Popen(
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

        self.connected = True
        self._reader_greenlet = gevent.spawn(self._read_stdout)
        self._stderr_greenlet = gevent.spawn(self._read_stderr)
        return True

    def _read_stdout(self):
        try:
            while self._process and self._process.poll() is None:
                line = self._process.stdout.readline()
                if not line:
                    break
                try:
                    message = json.loads(line)
                except Exception:
                    logger.warning("Steam worker gecersiz cikti: %s", line.strip())
                    continue
                self._handle_message(message)
        except Exception as e:
            logger.error("Steam worker stdout okuma hatasi: %s", e)
        finally:
            self.connected = False
            self.logged_in = False
            for response_queue in list(self._pending.values()):
                response_queue.put({"ok": False, "eresult": int(EResult.NoConnection)})
            self._pending.clear()
            self._emit("disconnected")

    def _read_stderr(self):
        try:
            while self._process and self._process.poll() is None:
                line = self._process.stderr.readline()
                if not line:
                    break
                logger.info("Steam worker: %s", line.strip())
        except Exception:
            pass

    def _handle_message(self, message):
        if message.get("refresh_token"):
            self.refresh_token = message.get("refresh_token")
        if message.get("steam_id"):
            self.steam_id = message.get("steam_id")

        request_id = message.get("id")
        if request_id and request_id in self._pending:
            response_queue = self._pending.pop(request_id)
            response_queue.put(message)
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
            return {"ok": False, "eresult": int(EResult.ServiceUnavailable)}

        request_id = uuid.uuid4().hex
        message = {"id": request_id, "action": action}
        if payload:
            message.update(payload)

        response_queue = queue.Queue(maxsize=1)
        self._pending[request_id] = response_queue

        try:
            self._process.stdin.write(json.dumps(message) + "\n")
            self._process.stdin.flush()
        except Exception as e:
            self._pending.pop(request_id, None)
            logger.error("Steam worker komut gonderme hatasi: %s", e)
            return {"ok": False, "eresult": int(EResult.NoConnection)}

        try:
            return response_queue.get(timeout=timeout)
        except queue.Empty:
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

        result = _safe_eresult(response.get("eresult"))
        if response.get("ok") and result == EResult.OK:
            self.logged_in = True
            self.connected = True
            self.steam_id = response.get("steam_id") or self.steam_id
            self.refresh_token = response.get("refresh_token") or self.refresh_token
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

    def disconnect(self):
        if not self._process:
            self.connected = False
            self.logged_in = False
            return
        try:
            self._request("disconnect", timeout=5)
        except Exception:
            pass
        try:
            if self._process.poll() is None:
                self._process.terminate()
                with gevent.Timeout(5, False):
                    self._process.wait()
            if self._process.poll() is None:
                self._process.kill()
        except Exception:
            pass
        self.connected = False
        self.logged_in = False


def _make_client():
    client = SteamWorkerClient()
    client.set_credential_location(SENTRY_DIR)
    return client


class SteamAccountManager:
    def __init__(self, account_id, steam_username):
        self.account_id = account_id
        self.steam_username = steam_username
        self.client = _make_client()
        self.logged_in = False
        self.boosting = False
        self.start_time = None
        self.original_start_time = None
        self.app_ids = []
        self.persona_state = 1
        self._reconnect_attempts = 0
        self._setup_events()

    def _cred_path(self):
        safe_name = self.steam_username.replace("/", "_").replace("\\", "_")
        return os.path.join(TOKEN_DIR, f"{self.account_id}_{safe_name}.cred")

    def save_credentials(self, password=None, refresh_token=None):
        try:
            existing = {}
            path = self._cred_path()
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

            with open(path, "w") as f:
                json.dump(data, f)
            if os.name != "nt":
                os.chmod(path, 0o600)
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

    def delete_credentials(self):
        path = self._cred_path()
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    def has_credentials(self):
        return os.path.exists(self._cred_path())

    def has_token(self):
        return self.has_credentials()

    def _setup_events(self):
        @self.client.on("disconnected")
        def _on_dc():
            logger.warning("[%s] Baglanti koptu", self.steam_username)
            self.logged_in = False
            if self.boosting:
                self._schedule_reconnect()

        @self.client.on("logged_on")
        def _on_login():
            logger.info("[%s] Giris basarili", self.steam_username)
            self.logged_in = True
            self._reconnect_attempts = 0
            if self.client.refresh_token:
                self.save_credentials(refresh_token=self.client.refresh_token)
            if self.boosting:
                self._resume_boost()

        @self.client.on("new_login_key")
        def _on_new_key():
            logger.info("[%s] new_login_key alindi", self.steam_username)

    def _schedule_reconnect(self):
        if self._reconnect_attempts >= 5:
            logger.error("[%s] Max reconnect asildi", self.steam_username)
            if self.boosting:
                elapsed = self.stop_boost()
                if elapsed > 0 and boost_service.fatal_disconnect_callback:
                    boost_service.fatal_disconnect_callback(self.account_id, elapsed)
            return
        delay = min(30 * (2 ** self._reconnect_attempts), 300)
        self._reconnect_attempts += 1
        logger.info("[%s] %dsn sonra reconnect", self.steam_username, delay)
        gevent.spawn_later(delay, self._try_reconnect)

    def _try_reconnect(self):
        try:
            creds = self.load_credentials()
            if creds:
                result = self._login_with_saved_credentials(creds)
                if result == EResult.OK:
                    return
                if result in (
                    EResult.AccountLogonDenied,
                    EResult.AccountLoginDeniedNeedTwoFactor,
                    EResult.InvalidLoginAuthCode,
                    EResult.TwoFactorCodeMismatch,
                ):
                    logger.warning(
                        "[%s] Steam Guard gerekiyor, otomatik reconnect yapilamiyor",
                        self.steam_username,
                    )
                    return
                if result == EResult.InvalidPassword:
                    logger.warning(
                        "[%s] Gecersiz sifre/token (EResult.5), reconnect durduruluyor",
                        self.steam_username,
                    )
                    return
            self.client.reconnect(maxdelay=30)
        except Exception as e:
            logger.error("[%s] Reconnect hatasi: %s", self.steam_username, e)
            self._schedule_reconnect()

    def _record_login_success(self, password=None):
        self.logged_in = True
        self._reconnect_attempts = 0
        if password or self.client.refresh_token:
            self.save_credentials(password=password, refresh_token=self.client.refresh_token)

    def _login_with_saved_credentials(self, creds, code=None, code_type="2fa"):
        refresh_token = creds.get("refresh_token")
        password = creds.get("password")

        if refresh_token and not code:
            result = self.client.login(
                username=self.steam_username,
                refresh_token=refresh_token,
            )
            if result == EResult.OK:
                self._record_login_success()
                return result
            logger.warning(
                "[%s] Refresh token login basarisiz: %s, sifre fallback deneniyor",
                self.steam_username,
                result,
            )

        if password:
            return self._login_with_credentials(password, code=code, code_type=code_type)
        return EResult.InvalidPassword

    def _login_with_credentials(self, password, code=None, code_type="2fa"):
        try:
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

            if result == EResult.OK:
                self._record_login_success(password=password)
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

    def _resume_boost(self):
        try:
            self.client.change_status(persona_state=EPersonaState(self.persona_state))
            self.client.games_played(self.app_ids)
            logger.info("[%s] Boost devam ediyor", self.steam_username)
        except Exception as e:
            logger.error("[%s] Resume hatasi: %s", self.steam_username, e)

    def login(self, password=None, code=None, code_type="email"):
        if not password:
            creds = self.load_credentials()
            if creds:
                return self._login_with_saved_credentials(creds, code=code, code_type=code_type)
            return EResult.InvalidPassword

        return self._login_with_credentials(password, code=code, code_type=code_type)

    def start_boost(self, app_ids, persona_state=1):
        if not self.logged_in:
            raise Exception("Steam bagli degil")
        self.app_ids = app_ids
        self.persona_state = persona_state
        result = self.client.change_status(persona_state=EPersonaState(persona_state))
        if result != EResult.OK:
            raise Exception(f"Steam status degistirilemedi: {result}")
        result = self.client.games_played(app_ids)
        if result != EResult.OK:
            raise Exception(f"Steam boost baslatilamadi: {result}")
        self.boosting = True
        self.start_time = time.time()
        self.original_start_time = time.time()

    def stop_boost(self):
        try:
            self.client.stop_games()
        except Exception:
            pass
        self.boosting = False
        elapsed = 0
        if self.start_time:
            elapsed = time.time() - self.start_time
        self.start_time = None
        self.original_start_time = None
        return elapsed

    def set_persona(self, state):
        self.persona_state = state
        if self.logged_in:
            try:
                self.client.change_status(persona_state=EPersonaState(state))
            except Exception:
                pass

    def disconnect(self):
        self.boosting = False
        self.start_time = None
        self.original_start_time = None
        try:
            self.client.stop_games()
        except Exception:
            pass
        try:
            self.client.disconnect()
        except Exception:
            pass
        self.logged_in = False

    def remove_completely(self):
        self.disconnect()
        self.delete_credentials()

    def summary(self):
        return {
            "id": self.account_id,
            "steam_username": self.steam_username,
            "logged_in": self.logged_in,
            "boosting": self.boosting,
            "start_time": self.original_start_time,
            "app_ids": self.app_ids,
            "persona_state": self.persona_state,
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

    def remove(self, account_id):
        mgr = self._managers.pop(account_id, None)
        if mgr:
            mgr.remove_completely()

    def all_managers(self):
        return list(self._managers.items())

    def active_boosts(self):
        return sum(1 for m in self._managers.values() if m.boosting)

    def stats(self):
        return {
            "total": len(self._managers),
            "active_boosts": self.active_boosts(),
            "logged_in": sum(1 for m in self._managers.values() if m.logged_in),
        }


boost_service = BoostService()
