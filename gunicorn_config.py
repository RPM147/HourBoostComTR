import multiprocessing
import os

bind = "127.0.0.1:5000"
# UYARI: Boost durumu, timer'lar, JWT blacklist, brute-force sayaçları,
# game_cache ve "memory://" rate limiter PROCESS-İÇİ bellekte tutulur.
# Bu yüzden worker sayısı 1 OLMAK ZORUNDADIR. Aksi halde çift loglama ve
# limit kaçağı olur.
#
# Yatay ölçek (workers>1 veya birden fazla sunucu) için önce şu durum Redis'e
# taşınmalıdır (bkz. PHASE_ROADMAP.md, Phase 5H ve Phase 5I):
#   - JWT blacklist (_token_blacklist set)      -> Redis Set
#   - brute-force sayaçları (_failed_logins)    -> Redis (TTL'li key)
#   - game_cache                                -> Redis (TTL'li key)
#   - rate limiter storage                      -> LIMITER_STORAGE_URI=redis://...
#   - boost manager/timer durumu                -> kalıcı koordinasyon katmanı
workers = 1
worker_class = "gevent"
preload_app = False
# Gunicorn 25's optional dirty-arbiter pool is another process boundary and is
# outside HourBoost's current ownership model.
dirty_workers = 0
dirty_apps = []
worker_connections = 100
timeout = 120
keepalive = 5
# gunicorn 25.x kontrol soketi, gevent altında asyncio'yu ayrı bir thread'de
# çalıştırır; bu, worker boot sırasında aralıklı kilitlenmeye (restart hang)
# yol açabiliyor. Bu özelliği kullanmıyoruz; kapatıyoruz.
control_socket_disable = True
errorlog = "/home/ubuntu/steamboost/logs/error.log"
accesslog = "/home/ubuntu/steamboost/logs/access.log"
# Keep the access record low-PII and query-free. JSONSafeAtoms additionally
# escapes decoded control characters in PATH_INFO before interpolation.
logger_class = "gunicorn_logging.HourBoostLogger"
access_log_format = (
    '{"ts":"%(t)s","source":"gunicorn","pid":"%(p)s",'
    '"method":"%(m)s","path":"%(U)s","status":"%(s)s",'
    '"bytes":"%(B)s","duration_s":"%(L)s"}'
)
# Logrotate creates existing log files as 0640. Gunicorn applies this setting to
# worker-side files, but master log creation must also be protected by a systemd
# UMask/logger mode policy; see the recorded Phase 5H follow-up debt.
umask = 0o027
loglevel = "info"


_SINGLE_WORKER_ERROR = (
    "HourBoost requires exactly one Gunicorn worker until Phase 5I moves "
    "Steam ownership out of the web process."
)


def _assert_safe_worker_lifecycle(server, worker_count):
    """Reject every Gunicorn path that can duplicate process-local state."""

    if int(worker_count) != 1:
        raise RuntimeError(_SINGLE_WORKER_ERROR)
    # Arbiter.setup calls nworkers_changed before a CLI --preload can import the
    # application, so this guard runs before DB and background-job side effects.
    if bool(getattr(server.cfg, "preload_app", False)):
        raise RuntimeError(
            "Gunicorn application preloading is disabled for HourBoost."
        )
    if (
        int(getattr(server.cfg, "dirty_workers", 0)) != 0
        or bool(getattr(server.cfg, "dirty_apps", ()))
    ):
        raise RuntimeError(
            "Gunicorn dirty workers are disabled for HourBoost."
        )
    # USR2 starts a second master alongside the first. The replacement master
    # carries GUNICORN_PID; reject it during setup, before loading app:app.
    if os.environ.get("GUNICORN_PID"):
        raise RuntimeError(
            "Gunicorn USR2 re-exec is disabled; use a full service restart."
        )


def nworkers_changed(server, new_value, old_value):
    """Guard initial config and runtime TTIN/TTOU worker-count changes."""

    _assert_safe_worker_lifecycle(server, new_value)


def on_starting(server):
    """Recheck the effective configuration before socket/worker startup.

    The module-level ``workers = 1`` is only a default; command-line and
    environment settings can override it. Steam ownership and several security
    state stores remain process-local until Phase 5I, so the effective value is
    checked on the live Gunicorn configuration object.
    """

    _assert_safe_worker_lifecycle(server, server.cfg.workers)


def on_reload(server):
    """Reject HUP reload because Gunicorn overlaps old and new workers."""

    raise RuntimeError(
        "Gunicorn HUP reload is disabled; use a full service restart."
    )
