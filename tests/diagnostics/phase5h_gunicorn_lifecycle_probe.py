"""Exercise real Gunicorn lifecycle guards without importing HourBoost's app.

Run on Linux with the application's installed Python environment::

    venv/bin/python tests/diagnostics/phase5h_gunicorn_lifecycle_probe.py

Every case uses a disposable WSGI app, loopback ephemeral socket, and isolated
process session. Only the repository's Gunicorn configuration is loaded. Output
contains case results, never application environment values or captured logs.
"""

from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


WORK_SECONDS = 8.0
CLEANUP_SECONDS = 2.0
POLL_SECONDS = 0.025
# Gunicorn 25.1.0 Arbiter.run catches lifecycle-hook exceptions, stops workers,
# and calls sys.exit(-1). POSIX exposes that deliberate error exit as 255.
RUNTIME_GUARD_EXIT = 255


class ProbeFailure(Exception):
    """A deliberately secret-free acceptance failure."""


class GunicornCase:
    def __init__(self, directory: Path, source_config: Path):
        self.directory = directory
        self.loads = directory / "app-loads.txt"
        self.ready = directory / "worker-ready.txt"
        self.log = directory / "gunicorn.log"
        self.proc: subprocess.Popen | None = None
        self.log_stream = None
        self.deadline = 0.0
        self._write_fixture(source_config)

    def _write_fixture(self, source_config: Path) -> None:
        # The sentinel records imports, not requests. An unsafe preload or
        # overlapping replacement worker is observable even if it then exits.
        (self.directory / "phase5h_probe_app.py").write_text(
            "import os\n"
            f"fd = os.open({str(self.loads)!r}, "
            "os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
            "try:\n"
            "    os.write(fd, (str(os.getpid()) + '\\n').encode('ascii'))\n"
            "finally:\n"
            "    os.close(fd)\n"
            "def application(environ, start_response):\n"
            "    start_response('200 OK', [('Content-Type', 'text/plain')])\n"
            "    return [b'phase5h-probe-ok']\n",
            encoding="utf-8",
        )
        (self.directory / "probe_config.py").write_text(
            "import os\n"
            "import runpy\n"
            f"_production_config = runpy.run_path({str(source_config)!r})\n"
            "globals().update({key: value for key, value in "
            "_production_config.items() if not key.startswith('__')})\n"
            "bind = '127.0.0.1:0'\n"
            f"chdir = {str(self.directory)!r}\n"
            "errorlog = '-'\n"
            "accesslog = None\n"
            "logger_class = 'gunicorn.glogging.Logger'\n"
            "daemon = False\n"
            "pidfile = None\n"
            "graceful_timeout = 1\n"
            "def post_worker_init(worker):\n"
            f"    fd = os.open({str(self.ready)!r}, "
            "os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
            "    try:\n"
            "        os.write(fd, (str(os.getpid()) + '\\n').encode('ascii'))\n"
            "    finally:\n"
            "        os.close(fd)\n",
            encoding="utf-8",
        )

    def start(self, *extra_args: str) -> None:
        env = os.environ.copy()
        # Ignore ambient Gunicorn command overrides and socket activation. The
        # USR2 test must receive GUNICORN_PID from Gunicorn itself, not our shell.
        for key in (
            "GUNICORN_CMD_ARGS", "GUNICORN_PID", "PYTHONPATH",
            "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES",
        ):
            env.pop(key, None)
        self.log_stream = self.log.open("wb")
        self.deadline = time.monotonic() + WORK_SECONDS
        self.proc = subprocess.Popen(
            [
                # USR2 reconstructs argv using sys.executable + sys.argv.
                # Running with -m loses module context during that re-exec;
                # use the same real console entrypoint as a service deployment.
                str(Path(sys.executable).with_name("gunicorn")), "--config",
                str(self.directory / "probe_config.py"),
                *extra_args, "phase5h_probe_app:application",
            ],
            cwd=self.directory,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=self.log_stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )

    def wait_for(self, predicate, failure: str) -> None:
        while time.monotonic() < self.deadline:
            if predicate():
                return
            time.sleep(POLL_SECONDS)
        raise ProbeFailure(failure)

    def load_pids(self) -> list[int]:
        if not self.loads.exists():
            return []
        return [int(line) for line in self.loads.read_text().splitlines()]

    def log_contains(self, message: str) -> bool:
        return message in self.log.read_text(encoding="utf-8", errors="replace")

    def require_live_master(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            raise ProbeFailure("master exited unexpectedly")

    def boot(self) -> None:
        self.start("--workers", "1")

        def worker_ready():
            self.require_live_master()
            return self.ready.exists() and bool(self.ready.read_text().strip())

        self.wait_for(worker_ready, "worker did not become ready within deadline")
        pids = self.load_pids()
        if len(pids) != 1 or pids[0] == self.proc.pid:
            raise ProbeFailure("expected exactly one worker-side WSGI import")

    def send(self, signum: int) -> None:
        self.require_live_master()
        self.proc.send_signal(signum)

    def assert_one_load(self) -> None:
        if len(self.load_pids()) != 1:
            raise ProbeFailure("lifecycle action caused a second WSGI import")

    def wait_exit(self, expected: int) -> None:
        self.wait_for(
            lambda: self.proc.poll() is not None,
            "master failed to exit within deadline",
        )
        if self.proc.returncode != expected:
            raise ProbeFailure(
                f"master exit status={self.proc.returncode}, expected={expected}; "
                f"WSGI imports={len(self.load_pids())}"
            )
        self.wait_for(
            lambda: not self.live_group_members(),
            "master left a running child behind",
        )

    def live_group_members(self) -> list[int]:
        """Read Linux process metadata; exited zombies are no longer running."""

        members = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            # comm can contain spaces/parentheses; fields after its final ')'
            # begin with state, ppid, pgrp, session, respectively.
            fields = stat[stat.rfind(")") + 2:].split()
            if len(fields) >= 4 and (
                int(fields[2]) == self.proc.pid
                and int(fields[3]) == self.proc.pid
                and fields[0] != "Z"
            ):
                members.append(int(entry.name))
        return members

    def observe_healthy(self) -> None:
        until = time.monotonic() + 0.2
        if until >= self.deadline:
            raise ProbeFailure("no time remained to observe signal stability")
        while time.monotonic() < until:
            self.require_live_master()
            self.assert_one_load()
            time.sleep(POLL_SECONDS)

    def cleanup(self) -> None:
        # start_new_session=True gives this child a private process group whose
        # id is its PID. Never signal a group obtained from another process.
        cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
        try:
            if self.proc is not None:
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.proc.wait(timeout=CLEANUP_SECONDS / 2)
                except subprocess.TimeoutExpired:
                    pass
                # A dead master can leave a child; always clean our group, not
                # only the master. Killing this private group cannot hit prod.
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                remaining = max(0.001, cleanup_deadline - time.monotonic())
                self.proc.wait(timeout=remaining)
        finally:
            if self.log_stream is not None:
                self.log_stream.close()


def reject_before_import(
    case: GunicornCase, expected_rejection: str, *args: str
) -> None:
    case.start(*args)
    case.wait_exit(1)
    if case.load_pids():
        raise ProbeFailure("unsafe startup imported the WSGI application")
    if not case.log_contains(expected_rejection):
        raise ProbeFailure("startup failed without the expected guard rejection")


def normal_boot(case: GunicornCase) -> None:
    case.boot()
    case.send(signal.SIGTERM)
    case.wait_exit(0)
    case.assert_one_load()


def rejecting_signal(case: GunicornCase, signum: int) -> None:
    case.boot()
    case.send(signum)
    case.wait_exit(RUNTIME_GUARD_EXIT)
    case.assert_one_load()
    expected_rejection = (
        "HourBoost requires exactly one Gunicorn worker"
        if signum == signal.SIGTTIN else "Gunicorn HUP reload is disabled"
    )
    if not case.log_contains(expected_rejection):
        raise ProbeFailure("signal failed without the expected guard rejection")


def reject_usr2(case: GunicornCase) -> None:
    case.boot()
    case.send(signal.SIGUSR2)

    def replacement_rejected():
        case.require_live_master()
        case.assert_one_load()
        return case.log_contains("Gunicorn USR2 re-exec is disabled")

    case.wait_for(replacement_rejected, "USR2 replacement rejection was not observed")
    case.observe_healthy()
    case.send(signal.SIGTERM)
    case.wait_exit(0)
    case.assert_one_load()


def support_usr1(case: GunicornCase) -> None:
    case.boot()
    case.send(signal.SIGUSR1)

    def rotation_handled():
        case.require_live_master()
        case.assert_one_load()
        return case.log_contains("Handling signal: usr1")

    case.wait_for(rotation_handled, "USR1 log-rotation handling was not observed")
    case.observe_healthy()
    case.send(signal.SIGTERM)
    case.wait_exit(0)
    case.assert_one_load()


def main() -> int:
    if sys.platform != "linux":
        print("FAIL: this lifecycle probe requires Linux")
        return 2
    try:
        version = importlib.metadata.version("gunicorn")
    except importlib.metadata.PackageNotFoundError:
        print("FAIL: Gunicorn is not installed in this Python environment")
        return 2
    entrypoint = Path(sys.executable).with_name("gunicorn")
    if not entrypoint.is_file() or not os.access(entrypoint, os.X_OK):
        print("FAIL: Gunicorn console entrypoint is missing from this Python environment")
        return 2
    source_config = Path(__file__).resolve().parents[2] / "gunicorn_config.py"
    if not source_config.is_file():
        print("FAIL: repository Gunicorn configuration was not found")
        return 2
    cases = (
        ("workers=2 rejected before WSGI import", lambda c: reject_before_import(c, "HourBoost requires exactly one Gunicorn worker", "--workers", "2")),
        ("preload rejected before WSGI import", lambda c: reject_before_import(c, "Gunicorn application preloading is disabled", "--preload")),
        ("workers=2 plus preload rejected before WSGI import", lambda c: reject_before_import(c, "HourBoost requires exactly one Gunicorn worker", "--workers", "2", "--preload")),
        ("one worker boots and shuts down", normal_boot),
        ("TTIN exits without duplicate WSGI import", lambda c: rejecting_signal(c, signal.SIGTTIN)),
        ("HUP exits without duplicate WSGI import", lambda c: rejecting_signal(c, signal.SIGHUP)),
        ("USR2 rejects replacement and preserves original master", reject_usr2),
        ("USR1 log rotation remains supported", support_usr1),
    )
    failures = 0
    print(f"Gunicorn lifecycle probe: installed version {version}")
    with tempfile.TemporaryDirectory(prefix="hourboost-phase5h-lifecycle-") as root:
        for index, (label, run) in enumerate(cases):
            directory = Path(root) / str(index)
            directory.mkdir(mode=0o700)
            case = GunicornCase(directory, source_config)
            failure = None
            try:
                run(case)
            except ProbeFailure as exc:
                failure = str(exc)
            except Exception:
                # Do not emit exception text, environment, or captured logs.
                failure = "unexpected probe execution error"
            finally:
                try:
                    case.cleanup()
                except Exception:
                    failure = "private process-group cleanup failed"
            if failure:
                failures += 1
                print(f"FAIL: {label}: {failure}")
            else:
                print(f"PASS: {label}")
    print(f"Result: {len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
