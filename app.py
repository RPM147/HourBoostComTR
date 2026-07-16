from gevent import monkey; monkey.patch_all()

import os
import json
import time
import math
import secrets
import hashlib
import hmac
import logging
import urllib.request
import urllib.parse
import re
import xml.etree.ElementTree as ET
import bleach
import mailer
import jwt as pyjwt
import ipaddress
from urllib.parse import urlparse
from functools import wraps
from contextlib import nullcontext

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ───────────────────── SSRF Koruması ─────────────────────

# Cloudflare ve SSRF Korumasi izin verilen domainler
ALLOWED_HOSTS = {
    'steamcommunity.com',
    'api.steampowered.com',
    'store.steampowered.com',
    'avatars.steamstatic.com',
    'cdn.cloudflare.steamstatic.com',
    'api.shopier.com',
    'www.shopier.com',
}

PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]


def is_safe_url(url):
    """SSRF saldırılarını önlemek için URL'yi doğrula."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.hostname:
            return False
        if parsed.hostname not in ALLOWED_HOSTS:
            logger.warning("URL hostname'e izin verilmiyor: %s", parsed.hostname)
            return False
        return True
    except Exception:
        return False


def is_private_ip(ip_str):
    """IP adresinin özel aralıkta olup olmadığını kontrol et."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_IP_RANGES)
    except ValueError:
        return True


def _resolves_to_private_ip(hostname):
    """Host adının özel/iç bir IP'ye çözümlenip çözümlenmediğini kontrol et."""
    if not hostname:
        return False
    try:
        import socket
        # AF_UNSPEC (0): hem IPv4 hem IPv6 kayıtlarını döndür; ikisi de kontrol edilir.
        for *_x, sockaddr in socket.getaddrinfo(
            hostname, None, 0, socket.SOCK_STREAM
        ):
            if is_private_ip(sockaddr[0]):
                return True
    except OSError:
        return False  # DNS hatası gerçek istekte başarısız olacak
    return False


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Yönlendirme (redirect) hedeflerini de SSRF kontrolünden geçirir.
    İzinli bir host açık-redirect ile iç IP'ye yönlendirse bile engellenir."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_safe_url(newurl):
            logger.warning("Güvensiz redirect engellendi: %s", newurl)
            raise ValueError(f"Güvensiz redirect engellendi: {newurl}")
        host = urlparse(newurl).hostname
        if _resolves_to_private_ip(host):
            logger.warning("Redirect özel IP'ye çözümleniyor, engellendi: %s", host)
            raise ValueError(f"Redirect özel IP'ye çözümleniyor: {host}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_safe_opener = urllib.request.build_opener(_SafeRedirectHandler)


def safe_urlopen(url, timeout=10, **kwargs):
    """
    SSRF ve DNS Rebinding korumalı urlopen.
    ALLOWED_HOSTS listesi sıkı olduğu için TOCTOU/DNS Rebinding riski taşımaz.
    """
    if isinstance(url, str):
        check_url = url
        req = urllib.request.Request(url, **kwargs)
    elif hasattr(url, 'full_url'):
        check_url = url.full_url
        req = url
    else:
        check_url = str(url)
        req = urllib.request.Request(check_url, **kwargs)

    if not is_safe_url(check_url):
        raise ValueError(f"Güvensiz URL engellendi: {check_url}")

    hostname = urlparse(check_url).hostname
    if _resolves_to_private_ip(hostname):
        logger.warning("URL özel IP'ye çözümleniyor, engellendi: %s", hostname)
        raise ValueError(f"URL özel IP'ye çözümleniyor: {hostname}")

    # Yönlendirmeler de doğrulanır (bkz. _SafeRedirectHandler).
    return _safe_opener.open(req, timeout=timeout)


# Geriye dönük uyumluluk için sınıf sarmalayıcı
class SafeURLOpener:
    @staticmethod
    def urlopen(url, timeout=10, **kwargs):
        return safe_urlopen(url, timeout=timeout, **kwargs)


from datetime import datetime, timedelta
from collections import defaultdict

from flask import Flask, request, jsonify, session, g, render_template
from flask import redirect as flask_redirect
from flask_limiter import Limiter
from steam_compat import EResult
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import and_, or_, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from config import Config
from models import (
    db, User, SteamAccount, BoostGame, Payment, PaymentAuditLog, BoostLog,
    Announcement, UserSession, RevokedToken,
)
from steam_manager import (
    boost_service,
    migrate_legacy_node_credentials,
    purge_quarantined_credentials,
    quarantine_saved_credentials,
    reconcile_credential_quarantines,
    restore_quarantined_credentials,
)
import shopier as shopier_lib
from payment_verification import (
    HB_TOKEN_RE,
    OrderValidationError,
    extract_single_token,
    token_fingerprint,
    validate_canonical_order,
)

from gevent.event import Event
from gevent.lock import RLock

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = Config.PERMANENT_SESSION_LIFETIME

# The production service deliberately uses one gevent worker.  Per-user locks
# close the cooperative-concurrency gap left by SQLite's lack of row locks:
# deleting an account now waits for any yielded Steam/login/payment request for
# that user, while unrelated users continue normally.
_user_operation_locks = {}
_user_operation_locks_guard = RLock()


def _user_operation_lock(user_id):
    user_id = int(user_id)
    with _user_operation_locks_guard:
        lock = _user_operation_locks.get(user_id)
        if lock is None:
            lock = RLock()
            _user_operation_locks[user_id] = lock
        return lock


app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

csrf = CSRFProtect(app)
# Otomatik CSRF kontrolünü kapat — JWT Bearer istekleri muaf tutulacak.
app.config["WTF_CSRF_CHECK_DEFAULT"] = False

db.init_app(app)

# Üretim ortamı kontrolü (ISSUES.md #16): SQLite tek-worker gunicorn altında
# çalışır ama ödeme alan bir uygulama için PostgreSQL önerilir. Sesli uyar.
if not app.debug and "sqlite" in app.config["SQLALCHEMY_DATABASE_URI"].lower():
    logger.warning(
        "SQLite veritabani kullaniliyor (DATABASE_URL ayarlanmamis olabilir). "
        "Uretimde PostgreSQL onerilir; bkz. .env.example"
    )

# ── SQLite eşzamanlılık sertleştirme ──────────────────────────────
# gevent altında çok sayıda greenlet eşzamanlı yazınca SQLite "database is
# locked" hatası verebilir. WAL modu + busy_timeout bunu büyük ölçüde önler.
# Listener Engine sınıfına bağlandığından sadece SQLite bağlantılarına
# uygulanır (isinstance kontrolü); PostgreSQL'de no-op'tur.
from sqlalchemy import event as _sa_event
from sqlalchemy.engine import Engine as _SAEngine
import sqlite3 as _sqlite3


@_sa_event.listens_for(_SAEngine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, _sqlite3.Connection):
        try:
            cur = dbapi_connection.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
        except Exception as _e:
            logger.error("SQLite PRAGMA ayarlanamadi: %s", _e)


# ── DB Migration (Flask-Migrate / Alembic) ────────────────────────
# Şema değişikliklerini düzgün yönetmek için. Kurulum sonrası ilk sefer:
#   flask db init
# Her şema değişikliğinde:
#   flask db migrate -m "açıklama"   &&   flask db upgrade
# Not: flask_migrate yalnızca CLI içindir, runtime için zorunlu değildir;
# kurulu değilse uygulama yine de çalışır (aşağıda savunmacı import).
try:
    from flask_migrate import Migrate
    migrate = Migrate(app, db)
except ImportError:
    logger.warning("flask_migrate kurulu degil; 'flask db' komutlari kullanilamaz.")


def _limiter_key_func():
    # Rate limiter ile brute-force kilidi AYNI istemci IP tanımını kullanmalı
    # (ISSUES.md #4); ikisi de _get_client_ip()'e dayanır. Fonksiyon aşağıda
    # tanımlıdır; isim istek anında çözüldüğü için sorun olmaz.
    return _get_client_ip()


limiter = Limiter(
    _limiter_key_func,
    app=app,
    default_limits=["200 per hour"],
    storage_uri=app.config.get("LIMITER_STORAGE_URI", "memory://"),
)

game_cache: dict = {}
game_cache_lock = RLock()
GAME_CACHE_MAX = 500

SERVER_START = time.time()

_active_timers = {}
_timer_lock = RLock()
_bg_reconnect_locks = set()

def _clear_timers(acct_id):
    # Referansları kilit altında çıkar, kill işlemini kilit dışında yap
    # (kill context-switch yapabileceği için kilidi tutmamak gerekir).
    current = gevent.getcurrent()
    with _timer_lock:
        timers = _active_timers.pop(acct_id, None)
    if not timers:
        return
    for t in timers:
        if t is current:
            continue  # Bu fonksiyonu çağıran greenlet kendini öldürmesin
        try:
            t.kill()
        except Exception:
            pass

def _add_timer(acct_id, glet):
    with _timer_lock:
        if acct_id not in _active_timers:
            _active_timers[acct_id] = []
        _active_timers[acct_id].append(glet)


def _discard_timer(acct_id, glet):
    """Remove only the completed timer, never a newer boost's timers."""
    with _timer_lock:
        timers = _active_timers.get(acct_id)
        if not timers:
            return
        try:
            timers.remove(glet)
        except ValueError:
            return
        if not timers:
            _active_timers.pop(acct_id, None)


def _same_boost_session(snapshot, session_id=None, generation=None):
    if not snapshot:
        return False
    has_expectation = session_id is not None or generation is not None
    if session_id is not None and snapshot.get("session_id") != session_id:
        return False
    if generation is not None and snapshot.get("generation") != generation:
        return False
    return has_expectation


def _add_boost_log_if_missing(
    acct_id,
    user_id,
    started_epoch,
    stopped_epoch,
    duration_seconds,
    app_ids,
):
    """Stage one deterministic segment and make an immediate retry idempotent."""
    duration_seconds = max(0, int(duration_seconds or 0))
    if duration_seconds <= 0 or started_epoch is None:
        return False

    started_at = datetime.utcfromtimestamp(float(started_epoch))
    stopped_at = datetime.utcfromtimestamp(float(stopped_epoch))
    existing = BoostLog.query.filter_by(
        account_id=acct_id,
        user_id=user_id,
        started_at=started_at,
        stopped_at=stopped_at,
        duration_seconds=duration_seconds,
    ).first()
    if existing is not None:
        return False

    normalized_app_ids = [int(app_id) for app_id in (app_ids or [])]
    db.session.add(BoostLog(
        account_id=acct_id,
        user_id=user_id,
        started_at=started_at,
        stopped_at=stopped_at,
        duration_seconds=duration_seconds,
        games_count=len(normalized_app_ids),
        app_ids_json=json.dumps(normalized_app_ids),
    ))
    return True


def _persist_stopped_boost_state(
    acct_id,
    user_id,
    *,
    started_epoch,
    stopped_epoch,
    duration_seconds,
    app_ids,
    clear_account_state=True,
    max_attempts=2,
):
    """Persist a stopped segment with a bounded retry.

    Steam and SQLite cannot participate in one transaction.  Runtime is stopped
    first (fail closed); this function then makes the local state converge.  The
    values are frozen by the caller so a retry cannot manufacture a new segment.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            acct = db.session.get(SteamAccount, acct_id)
            if acct is None:
                db.session.rollback()
                return False
            if clear_account_state:
                acct.is_boosting = False
                acct.target_stop_time = None
            _add_boost_log_if_missing(
                acct_id,
                user_id,
                started_epoch,
                stopped_epoch,
                duration_seconds,
                app_ids,
            )
            db.session.commit()
            return True
        except SQLAlchemyError as exc:
            db.session.rollback()
            if attempt == max_attempts:
                logger.error(
                    "[acct:%s] Durdurulan boost durumu %d denemede yazilamadi: %s",
                    acct_id,
                    max_attempts,
                    exc,
                )
                return False
            logger.warning(
                "[acct:%s] Boost durum commit hatasi; yeniden deneniyor: %s",
                acct_id,
                exc,
            )


def _handle_fatal_disconnect(
    acct_id,
    elapsed,
    session_id=None,
    generation=None,
    started_epoch=None,
    app_ids=None,
):
    try:
        with app.app_context():
            owner_id = db.session.query(SteamAccount.user_id).filter_by(
                id=acct_id
            ).scalar()
            if owner_id is None:
                _clear_timers(acct_id)
                return

            with _user_operation_lock(owner_id):
                db.session.expire_all()
                acct = db.session.get(SteamAccount, acct_id)
                if acct is None:
                    _clear_timers(acct_id)
                    return
                fallback_app_ids = acct.app_ids()

                manager = boost_service.get(acct_id)
                clear_account_state = True
                if manager is not None:
                    # Do not retain a DB read transaction while stop_games may
                    # yield for up to its IPC timeout.
                    db.session.rollback()
                    with manager.state_lock:
                        current = manager.boost_snapshot()
                        if current.get("boosting"):
                            # A successful manual login may already have started
                            # a newer session while this old callback was queued.
                            # Never clear that session's DB state or timer.
                            if _same_boost_session(
                                current,
                                session_id=session_id,
                                generation=generation,
                            ):
                                manager.stop_boost(
                                    expected_session_id=session_id,
                                    expected_generation=generation,
                                )
                            else:
                                clear_account_state = False

                elapsed = max(0, float(elapsed or 0))
                stopped_epoch = time.time()
                if started_epoch is None:
                    started_epoch = stopped_epoch - elapsed
                persisted = _persist_stopped_boost_state(
                    acct_id,
                    owner_id,
                    started_epoch=started_epoch,
                    stopped_epoch=stopped_epoch,
                    duration_seconds=elapsed,
                    app_ids=(
                        list(app_ids)
                        if app_ids is not None
                        else fallback_app_ids
                    ),
                    clear_account_state=clear_account_state,
                )
                if clear_account_state:
                    _clear_timers(acct_id)
                if persisted:
                    logger.info(
                        "[acct:%s] Fatal disconnect sonrasi %d saniye kaydedildi",
                        acct_id,
                        int(elapsed),
                    )
                else:
                    logger.critical(
                        "[acct:%s] Fatal disconnect runtime'i durdu fakat DB uzlasmadi",
                        acct_id,
                    )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.exception("[acct:%s] Fatal disconnect finalization hatasi", acct_id)

boost_service.fatal_disconnect_callback = _handle_fatal_disconnect

def _get_active_seconds(user_id, start_time_filter=None):
    active = 0
    now = time.time()
    accounts = SteamAccount.query.filter_by(user_id=user_id).all()
    for acct in accounts:
        mgr = boost_service.get(acct.id)
        snapshot = mgr.boost_snapshot() if mgr else None
        if snapshot and snapshot.get("boosting") and snapshot.get("start_time"):
            active_start = snapshot["start_time"]
            if start_time_filter:
                start_dt = datetime.utcfromtimestamp(active_start)
                if start_dt >= start_time_filter:
                    active += (now - active_start)
            else:
                active += (now - active_start)
    return active

# ───────────────────── JWT ─────────────────────

_token_blacklist: set = set()
_blacklist_lock = RLock()
_blacklist_cleanup_last = time.time()


def _cleanup_blacklist():
    global _blacklist_cleanup_last
    now = time.time()
    if now - _blacklist_cleanup_last < 3600:
        return
    _blacklist_cleanup_last = now
    to_remove = set()
    with _blacklist_lock:
        snapshot = set(_token_blacklist)
    for token in snapshot:
        try:
            pyjwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        except pyjwt.ExpiredSignatureError:
            to_remove.add(token)
        except Exception:
            to_remove.add(token)
    if to_remove:
        with _blacklist_lock:
            _token_blacklist.difference_update(to_remove)
        logger.info("JWT blacklist temizlendi: %d token silindi", len(to_remove))


def _cleanup_revoked_tokens():
    try:
        RevokedToken.cleanup_expired()
        logger.info("Revoked token'lar veritabanından temizlendi")
    except Exception as e:
        logger.error("Revoked token temizleme hatasi: %s", e)


def generate_api_token(user_id, expires_hours=24 * 30):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=expires_hours),
        "iat": datetime.utcnow(),
        "jti": secrets.token_hex(16),
    }
    return pyjwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")


def _verified_token_session(token):
    """Return ``(user_id, session_id, jti)`` for an active signed JWT.

    A valid signature is not sufficient: every JWT must also map to one active
    server-side UserSession row. This makes single-device revocation durable and
    prevents the Flask session cookie from bypassing a revoked JWT.
    """
    # Tek decode — önce imza + süre doğrulaması yap.
    # verify_exp=False ile yapılan önceki iki aşamalı tasarım
    # süresi dolmuş token'ların revoke kontrolünden geçip
    # ikinci decode'da reddedileceği varsayımına dayanıyordu;
    # bu aradaki pencere gereksiz bir race condition yaratıyordu.
    try:
        payload = pyjwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None

    jti = payload.get("jti")
    user_id = payload.get("user_id")
    if (
        not isinstance(user_id, int)
        or isinstance(user_id, bool)
        or user_id <= 0
        or not isinstance(jti, str)
        or not re.fullmatch(r"[0-9a-f]{32}", jti)
    ):
        return None

    # İmza ve süre geçerliyse revoke/blacklist kontrolü yap.
    revoked = RevokedToken.query.filter_by(token_jti=jti).first()
    if revoked:
        # Kayıt hâlâ geçerliyse reddet; süresi gectiyse temizle.
        if revoked.expires_at > datetime.utcnow():
            logger.info("Token iptal edilmiş (kalıcı): jti=%s", jti)
            return None
        try:
            db.session.delete(revoked)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error("Revoked token temizleme hatasi: %s", e)

    with _blacklist_lock:
        if token in _token_blacklist:
            return None

    active_session = UserSession.query.filter_by(
        user_id=user_id,
        token_jti=jti,
        is_active=True,
    ).filter(
        UserSession.expires_at.isnot(None),
        UserSession.expires_at > datetime.utcnow(),
    ).first()
    if active_session is None:
        return None

    iat = payload.get("iat")
    try:
        iat_dt = datetime.utcfromtimestamp(int(iat))
    except (TypeError, ValueError, OSError):
        return None
    user = db.session.get(User, user_id)
    if user is None:
        return None
    # Şifre değişimi / toplu oturum iptali sonrası eski token'ları reddet.
    if (
        user.tokens_valid_after
        and iat_dt < user.tokens_valid_after.replace(microsecond=0)
    ):
        return None

    return user_id, active_session.id, jti


def verify_api_token(token):
    verified = _verified_token_session(token)
    return verified[0] if verified else None


def _decode_token_for_revocation(token):
    if not token:
        return None
    try:
        payload = pyjwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=["HS256"],
            options={"verify_exp": False},
        )
        user_id = payload.get("user_id")
        jti = payload.get("jti")
        expires_at = datetime.utcfromtimestamp(int(payload.get("exp")))
    except (pyjwt.InvalidTokenError, TypeError, ValueError, OSError):
        return None
    if (
        not isinstance(user_id, int)
        or isinstance(user_id, bool)
        or user_id <= 0
        or not isinstance(jti, str)
        or not re.fullmatch(r"[0-9a-f]{32}", jti)
    ):
        return None
    return {
        "user_id": user_id,
        "jti": jti,
        "expires_at": expires_at,
    }


def _stage_session_revocations(session_records, token_identities=()):
    """Stage durable token revocations and session deactivation atomically."""
    records = {record.id: record for record in session_records if record}
    identities = {}
    for record in records.values():
        if record.token_jti and record.expires_at:
            identities[record.token_jti] = {
                "user_id": record.user_id,
                "jti": record.token_jti,
                "expires_at": record.expires_at,
            }
    for identity in token_identities:
        if identity:
            identities[identity["jti"]] = identity

    now = datetime.utcnow()
    valid_user_ids = set()
    if identities:
        valid_user_ids = {
            item[0] for item in db.session.query(User.id).filter(
                User.id.in_({
                    identity["user_id"] for identity in identities.values()
                })
            ).all()
        }
    durable = {
        jti: identity
        for jti, identity in identities.items()
        if (
            identity["expires_at"] > now
            and identity["user_id"] in valid_user_ids
        )
    }
    existing = set()
    if durable:
        existing = {
            item[0] for item in db.session.query(RevokedToken.token_jti).filter(
                RevokedToken.token_jti.in_(durable.keys())
            ).all()
        }
    for jti, identity in durable.items():
        if jti not in existing:
            db.session.add(RevokedToken(
                token_jti=jti,
                user_id=identity["user_id"],
                expires_at=identity["expires_at"],
            ))
    for record in records.values():
        record.is_active = False


def _revoke_session_records(session_records, token_identities=()):
    try:
        _stage_session_revocations(session_records, token_identities)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logger.error("Oturum iptali kalıcılaştırılamadı: %s", e)
        return False


def blacklist_token(token):
    """Backward-compatible helper; persist revocation and return success."""
    identity = _decode_token_for_revocation(token)
    if identity is None:
        return False
    record = UserSession.query.filter_by(
        user_id=identity["user_id"],
        token_jti=identity["jti"],
    ).first()
    success = _revoke_session_records([record] if record else [], [identity])
    if success:
        with _blacklist_lock:
            _token_blacklist.add(token)
        _cleanup_blacklist()
    return success


def _invalidate_all_user_tokens(user):
    """Kullanıcının tüm JWT token'larını ve aktif oturumlarını geçersiz kıl.
    tokens_valid_after güncellenir; çağıran taraf commit etmelidir."""
    user.tokens_valid_after = datetime.utcnow()
    active_sessions = UserSession.query.filter_by(
        user_id=user.id,
        is_active=True,
    ).all()
    _stage_session_revocations(active_sessions)


# ───────────────────── Brute Force Koruması ─────────────────────

_failed_logins: defaultdict = defaultdict(list)
_failed_logins_lock = RLock()
# Kilit YALNIZCA IP bazlıdır. Kullanıcı-adı bazlı kilit kaldırıldı: saldırgan
# kurbanın kullanıcı adıyla bilerek yanlış şifre göndererek hesabı sürekli
# kilitleyebiliyordu (hedefli DoS, ISSUES.md #3). Buna karşılık IP eşiği
# 5'ten 10'a çıkarıldı.
_LOCKOUT_MAX_ATTEMPTS = 10
_LOCKOUT_SECONDS = 300


def is_locked_out(identifier: str) -> bool:
    now = time.time()
    with _failed_logins_lock:
        recent = [
            t for t in _failed_logins.get(identifier, [])
            if now - t < _LOCKOUT_SECONDS
        ]
        if recent:
            _failed_logins[identifier] = recent
        else:
            # Süresi geçen kayıtlar bittiğinde key'i tamamen sil (bellek sızıntısını önle)
            _failed_logins.pop(identifier, None)
        return len(recent) >= _LOCKOUT_MAX_ATTEMPTS


def record_failed_login(identifier: str):
    with _failed_logins_lock:
        _failed_logins[identifier].append(time.time())
        count = len(_failed_logins[identifier])
    if count >= _LOCKOUT_MAX_ATTEMPTS:
        logger.warning("Hesap/IP kilitlendi: %s (%d deneme)", identifier, count)


def clear_failed_logins(identifier: str):
    with _failed_logins_lock:
        _failed_logins.pop(identifier, None)


# ───────────────────── Oturum Yardımcıları ─────────────────────

def _get_client_ip() -> str:
    """Gerçek istemci IP'sini döndür.

    Site Cloudflare arkasında olduğundan, CF'in set ettiği 'CF-Connecting-IP'
    başlığı gerçek istemciyi verir; yoksa ProxyFix ile düzeltilen
    request.remote_addr'a düşülür.

    GÜVENLİK NOTU: Bunun taklit edilemez olması için origin (port 5000)
    yalnızca Cloudflare IP aralıklarından erişime kısıtlanmalıdır (firewall).
    Aksi halde saldırgan Cloudflare'i atlayıp bu başlığı sahteleyebilir.
    """
    cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
    if cf_ip:
        try:
            ipaddress.ip_address(cf_ip)
            return cf_ip
        except ValueError:
            pass
    return request.remote_addr or "unknown"


def _get_user_agent() -> str:
    ua = request.headers.get("User-Agent", "")
    return ua[:256]


def _create_session_record(user_id: int, token: str):
    try:
        payload = pyjwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        token_user_id = payload.get("user_id")
        token_jti = payload.get("jti")
        try:
            expires_at = datetime.utcfromtimestamp(int(payload.get("exp")))
            datetime.utcfromtimestamp(int(payload.get("iat")))
        except (TypeError, ValueError, OSError):
            raise ValueError("JWT timestamps are invalid")
        if (
            not isinstance(token_user_id, int)
            or isinstance(token_user_id, bool)
            or token_user_id != user_id
            or not isinstance(token_jti, str)
            or not re.fullmatch(r"[0-9a-f]{32}", token_jti)
            or expires_at <= datetime.utcnow()
        ):
            raise ValueError("JWT session identity is invalid")

        old_sessions = (
            UserSession.query
            .filter_by(user_id=user_id, is_active=True)
            .order_by(UserSession.created_at.asc())
            .all()
        )
        if len(old_sessions) >= 10:
            _stage_session_revocations(
                old_sessions[:len(old_sessions) - 9]
            )

        ip = _get_client_ip()
        ua = (request.headers.get("User-Agent", "") or "")[:256]

        sess = UserSession(
            user_id=user_id,
            token_jti=token_jti,
            token_hint=token_jti[:12],
            expires_at=expires_at,
            ip_address=ip,
            user_agent=ua,
        )
        db.session.add(sess)
        db.session.commit()
        logger.info("Oturum kaydı oluşturuldu: user_id=%s ip=%s", user_id, ip)
        return sess
    except Exception as e:
        logger.error("Oturum kaydı oluşturulamadı: %s", e)
        db.session.rollback()
        return None


def _establish_authenticated_session(user_id: int, token: str):
    """Persist the server-side session before issuing browser credentials."""
    session_record = _create_session_record(user_id, token)
    if session_record is None:
        session.clear()
        return None
    session.permanent = True
    # Sayısal DB kimlikleri SQLite'ta silme sonrası yeniden kullanılabilir.
    # Cookie yalnız kriptografik rastgele JTI taşır; user_id yetki kaynağı olmaz.
    session["auth_jti"] = session_record.token_jti
    return session_record.id


def _active_cookie_session():
    cookie_jti = session.get("auth_jti")
    if (
        not isinstance(cookie_jti, str)
        or not re.fullmatch(r"[0-9a-f]{32}", cookie_jti)
    ):
        return None
    record = UserSession.query.filter_by(
        token_jti=cookie_jti,
        is_active=True,
    ).filter(
        UserSession.expires_at.isnot(None),
        UserSession.expires_at > datetime.utcnow(),
    ).first()
    if record is None:
        return None
    if RevokedToken.query.filter_by(token_jti=cookie_jti).first():
        return None
    return record


# ───────────────────── Dil Yardımcısı ─────────────────────

def _get_request_lang() -> str:
    if request.path.startswith("/en/") or request.path == "/en":
        return "en"
    lang = request.args.get("lang", "")
    if lang in ("en", "tr"):
        return lang
    return "tr"


# ───────────────────── Sunucu Başlangıcı ─────────────────────

HB_TOKEN_BYTES = 16


def _new_match_token() -> str:
    return "HB-" + secrets.token_hex(HB_TOKEN_BYTES).upper()


def _generate_match_token() -> str:
    for _ in range(32):
        token = _new_match_token()
        if not Payment.query.filter_by(match_token=token).first():
            return token
    raise RuntimeError("Unique payment token could not be generated.")


def _ensure_schema():
    """Idempotent runtime bridge until Alembic migrations are established.

    Auth/payment schema errors are fatal. Booting with a partially migrated
    security or financial table is more dangerous than an explicit outage.
    """
    try:
        from sqlalchemy import inspect, text

        inspector = inspect(db.engine)
        dialect = db.engine.dialect.name
        false_literal = "FALSE" if dialect == "postgresql" else "0"
        true_literal = "TRUE" if dialect == "postgresql" else "1"
        cols = {c["name"] for c in inspector.get_columns("users")}
        if "tokens_valid_after" not in cols:
            col_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
            with db.engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN tokens_valid_after {col_type}"))
            logger.info("Şema güncellendi: users.tokens_valid_after eklendi")

        session_cols = {
            c["name"] for c in inspector.get_columns("user_sessions")
        }
        with db.engine.begin() as conn:
            if "token_jti" not in session_cols:
                conn.execute(text(
                    "ALTER TABLE user_sessions ADD COLUMN token_jti VARCHAR(64)"
                ))
                logger.info("Şema güncellendi: user_sessions.token_jti eklendi")
            if "expires_at" not in session_cols:
                session_datetime_type = (
                    "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
                )
                conn.execute(text(
                    "ALTER TABLE user_sessions ADD COLUMN expires_at "
                    + session_datetime_type
                ))
                logger.info("Şema güncellendi: user_sessions.expires_at eklendi")

        session_indexes = {
            item["name"]: item
            for item in inspect(db.engine).get_indexes("user_sessions")
        }
        jti_index = session_indexes.get("ix_user_sessions_token_jti")
        if jti_index is not None and not jti_index.get("unique", False):
            raise RuntimeError(
                "ix_user_sessions_token_jti exists but is not unique"
            )
        if jti_index is None:
            with db.engine.begin() as conn:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ix_user_sessions_token_jti "
                    "ON user_sessions (token_jti)"
                ))
            logger.info(
                "Şema güncellendi: ix_user_sessions_token_jti oluşturuldu"
            )

        # Eski token_hint değerlerinden JWT jti geri üretilemez. Kullanıcı
        # cutoff'u eski kodun da bu JWT'leri reddetmesini sağlar; ardından satır
        # kapatılır. Böylece auth migration sonrası güvenli kod rollback'i
        # iptal edilmiş legacy oturumları yeniden canlandırmaz.
        legacy_cutoff = datetime.utcnow()
        with db.engine.begin() as conn:
            conn.execute(text(
                "UPDATE users SET tokens_valid_after = :cutoff "
                "WHERE id IN ("
                "SELECT DISTINCT user_id FROM user_sessions "
                "WHERE is_active = " + true_literal + " "
                "AND (token_jti IS NULL OR expires_at IS NULL)"
                ") AND (tokens_valid_after IS NULL OR tokens_valid_after < :cutoff)"
            ), {"cutoff": legacy_cutoff})
            legacy_sessions = conn.execute(text(
                "UPDATE user_sessions SET is_active = " + false_literal + " "
                "WHERE is_active = " + true_literal + " "
                "AND (token_jti IS NULL OR expires_at IS NULL)"
            ))
        if legacy_sessions.rowcount:
            logger.warning(
                "Güvenli oturum migration'ı: %d legacy oturum kapatıldı",
                legacy_sessions.rowcount,
            )

        datetime_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
        pcols = {c["name"] for c in inspector.get_columns("payments")}
        payment_columns = {
            "owner_user_id_snapshot": "INTEGER",
            "owner_username_snapshot": "VARCHAR(80)",
            "owner_detached_at": datetime_type,
            "match_token": "VARCHAR(64)",
            "admin_hidden": f"BOOLEAN NOT NULL DEFAULT {false_literal}",
            "shopier_webhook_id": "VARCHAR(100)",
            "shopier_event": "VARCHAR(50)",
            "shopier_account_id": "VARCHAR(100)",
            "shopier_timestamp": "BIGINT",
            "webhook_body_sha256": "VARCHAR(64)",
            "webhook_received_at": datetime_type,
            "verification_attempts": "INTEGER NOT NULL DEFAULT 0",
            "verification_error": "VARCHAR(255)",
            "verification_last_http_status": "INTEGER",
            "next_verification_at": datetime_type,
            "verification_lock_until": datetime_type,
            "verified_at": datetime_type,
            "verified_amount_minor": "INTEGER",
        }
        with db.engine.begin() as conn:
            for column_name, column_type in payment_columns.items():
                if column_name not in pcols:
                    conn.execute(text(
                        f"ALTER TABLE payments ADD COLUMN {column_name} {column_type}"
                    ))
                    logger.info("Şema güncellendi: payments.%s eklendi", column_name)

        # Backfill durable ownership hints before any future user deletion.
        # The live FK is intentionally cleared on deletion, while these fields
        # keep the financial row attributable without relying on a reusable
        # SQLite integer ID alone.
        with db.engine.begin() as conn:
            conn.execute(text(
                "UPDATE payments SET owner_user_id_snapshot = user_id "
                "WHERE owner_user_id_snapshot IS NULL AND user_id IS NOT NULL"
            ))
            conn.execute(text(
                "UPDATE payments SET owner_username_snapshot = ("
                "SELECT users.username FROM users WHERE users.id = payments.user_id"
                ") WHERE owner_username_snapshot IS NULL AND user_id IS NOT NULL"
            ))

        if dialect == "postgresql":
            with db.engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE payments ALTER COLUMN match_token TYPE VARCHAR(64)"
                ))
                conn.execute(text(
                    "ALTER TABLE payments ALTER COLUMN status TYPE VARCHAR(32)"
                ))

        # Eski sürümde yalnızca checkout butonuna basmak status=pending üretiyordu.
        # match_token içeren ve henüz işlem görmemiş bu kayıtlar ödeme değil,
        # checkout niyetidir; idempotent biçimde admin kuyruğundan çıkarılır.
        with db.engine.begin() as conn:
            rows = conn.execute(text(
                "SELECT id, match_token, status FROM payments "
                "WHERE match_token IS NOT NULL ORDER BY id"
            )).mappings().all()
            used_tokens = set()
            for row in rows:
                token = str(row["match_token"] or "").strip().upper()
                if not token:
                    conn.execute(
                        text("UPDATE payments SET match_token = NULL WHERE id = :id"),
                        {"id": row["id"]},
                    )
                    continue
                status = row["status"]
                is_checkout_intent = status in ("checkout_started", "pending")
                needs_new_active_token = (
                    is_checkout_intent
                    and not re.fullmatch(r"HB-[0-9A-F]{32}", token)
                )
                duplicate = token in used_tokens

                if status == "verification_pending" and (
                    not re.fullmatch(r"HB-[0-9A-F]{32}", token) or duplicate
                ):
                    raise RuntimeError(
                        "verification_pending kaydında geçersiz/duplicate HB token bulundu"
                    )

                if is_checkout_intent and (needs_new_active_token or duplicate):
                    new_token = _new_match_token()
                    while new_token in used_tokens:
                        new_token = _new_match_token()
                    conn.execute(
                        text("UPDATE payments SET match_token = :token WHERE id = :id"),
                        {"token": new_token, "id": row["id"]},
                    )
                    used_tokens.add(new_token)
                elif duplicate:
                    conn.execute(
                        text("UPDATE payments SET match_token = NULL WHERE id = :id"),
                        {"id": row["id"]},
                    )
                else:
                    if token != row["match_token"]:
                        conn.execute(
                            text("UPDATE payments SET match_token = :token WHERE id = :id"),
                            {"token": token, "id": row["id"]},
                        )
                    used_tokens.add(token)

        with db.engine.begin() as conn:
            migrated = conn.execute(text(
                "UPDATE payments SET status = 'checkout_started' "
                "WHERE status = 'pending' "
                "AND match_token IS NOT NULL "
                "AND transaction_id IS NULL"
            ))
        if migrated.rowcount:
            logger.info(
                "Şema veri düzeltmesi: %d checkout kaydı checkout_started yapıldı",
                migrated.rowcount,
            )

        # Tek kullanıcı için yalnızca bir açık checkout/payment verification
        # bulunabilir. Eski checkout duplikelerinde en yeni kayıt korunur;
        # birden fazla verification_pending varsa güvenli otomatik karar yoktur.
        with db.engine.begin() as conn:
            open_rows = conn.execute(text(
                "SELECT id, user_id, status FROM payments "
                "WHERE user_id IS NOT NULL "
                "AND status IN ('checkout_started', 'verification_pending') "
                "ORDER BY user_id, id DESC"
            )).mappings().all()
            by_user = {}
            for row in open_rows:
                by_user.setdefault(row["user_id"], []).append(row)
            for user_id, rows in by_user.items():
                pending = [r for r in rows if r["status"] == "verification_pending"]
                if len(pending) > 1:
                    raise RuntimeError(
                        f"user_id={user_id} için birden fazla verification_pending bulundu"
                    )
                keep_id = pending[0]["id"] if pending else rows[0]["id"]
                for row in rows:
                    if row["id"] != keep_id and row["status"] == "checkout_started":
                        conn.execute(text(
                            "UPDATE payments SET status = 'cancelled' WHERE id = :id"
                        ), {"id": row["id"]})

        with db.engine.begin() as conn:
            duplicates = conn.execute(text(
                "SELECT transaction_id, COUNT(*) AS n FROM payments "
                "WHERE transaction_id IS NOT NULL GROUP BY transaction_id HAVING COUNT(*) > 1"
            )).mappings().all()
            if duplicates:
                raise RuntimeError(
                    f"payments.transaction_id duplicate kayıt sayısı: {len(duplicates)}"
                )

            if dialect in ("sqlite", "postgresql"):
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_match_token "
                    "ON payments (match_token) WHERE match_token IS NOT NULL"
                ))
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_transaction_id "
                    "ON payments (transaction_id) WHERE transaction_id IS NOT NULL"
                ))
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_one_open_checkout "
                    "ON payments (user_id) WHERE user_id IS NOT NULL "
                    "AND status IN ('checkout_started', 'verification_pending')"
                ))
            else:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ux_payments_match_token ON payments (match_token)"
                ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_payments_shopier_webhook_id "
                "ON payments (shopier_webhook_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_payments_verification_due "
                "ON payments (status, next_verification_at, verification_lock_until)"
            ))
    except Exception as e:
        try:
            db.session.rollback()
        except RuntimeError:
            # _ensure_schema normalde app context içinde çağrılır. Hatalı bir
            # CLI/test çağrısı asli migration hatasını gölgelememelidir.
            pass
        logger.critical("Kritik şema güncelleme hatası; başlangıç durduruldu: %s", e)
        raise


def _reconcile_boost_state_on_startup():
    """Restart sonrası DB'deki boost durumunu gerçeklikle hizala.

    auto_reconnect bilinçli olarak devre dışıdır (kullanıcılara Steam giriş
    bildirimi gitmemesi için), bu yüzden process yeniden başladığında hiçbir
    boost gerçekte çalışmaz. is_boosting=True kalan tüm kayıtlar bayattır;
    DB'nin gerçeklikle tutarlı kalması için temizlenir.

    Not: Son checkpoint ile çökme arasındaki süre (en fazla ~15 dk)
    güvenilir biçimde bilinemediğinden uydurma BoostLog yazılmaz."""
    try:
        stale = SteamAccount.query.filter(
            db.or_(SteamAccount.is_boosting.is_(True),
                   SteamAccount.target_stop_time.isnot(None))
        ).all()
        if stale:
            for acct in stale:
                acct.is_boosting = False
                acct.target_stop_time = None
            db.session.commit()
            logger.info("Restart reconciliation: %d hesabin bayat boost durumu temizlendi", len(stale))
    except Exception as e:
        db.session.rollback()
        logger.critical(
            "Restart reconciliation hatasi; bayat boost durumu ile servis baslatilmadi: %s",
            e,
        )
        raise


def _reconcile_steam_credentials_on_startup():
    """Resolve interrupted deletions, then remove the legacy shared-token layout."""
    account_pairs = [
        (account.id, account.steam_username)
        for account in SteamAccount.query.with_entities(
            SteamAccount.id,
            SteamAccount.steam_username,
        ).all()
    ]
    if not reconcile_credential_quarantines(account_pairs):
        logger.critical(
            "Steam credential quarantine reconciliation completed with errors"
        )
    if not migrate_legacy_node_credentials(account_pairs):
        logger.critical(
            "Legacy Steam credential migration completed with errors; "
            "shared sources were retained for retry"
        )


with app.app_context():
    db.create_all()
    _ensure_schema()
    _reconcile_steam_credentials_on_startup()
    _reconcile_boost_state_on_startup()

import gevent
# Restart davranışı: auto_reconnect BİLİNÇLİ olarak yoktur (kullanıcılara Steam
# giriş bildirimi gitmemesi için; ürün kararı). Restart sonrası boostlar
# otomatik devam etmez; başlangıçta _reconcile_boost_state_on_startup() bayat
# boost durumunu temizler. Ölü auto_reconnect_saved_accounts() fonksiyonu
# kaldırıldı (ISSUES.md #19).

def _checkpoint_active_boosts_once():
    """Persist active segments without advancing memory before durability."""
    saved = 0
    for acct_id, manager in boost_service.all_managers():
        try:
            owner_id = db.session.query(SteamAccount.user_id).filter_by(
                id=acct_id
            ).scalar()
            if owner_id is None:
                logger.warning(
                    "[acct:%s] Checkpoint atlandi: manager icin DB hesabi yok",
                    acct_id,
                )
                continue

            with _user_operation_lock(owner_id):
                db.session.expire_all()
                acct = db.session.get(SteamAccount, acct_id)
                if acct is None:
                    continue
                with manager.state_lock:
                    snapshot = manager.boost_snapshot()
                    if not snapshot.get("boosting") or snapshot.get("start_time") is None:
                        continue

                    stopped_epoch = time.time()
                    elapsed = stopped_epoch - snapshot["start_time"]
                    if elapsed <= 60:
                        continue

                    _add_boost_log_if_missing(
                        acct_id,
                        owner_id,
                        snapshot["start_time"],
                        stopped_epoch,
                        elapsed,
                        snapshot.get("app_ids") or acct.app_ids(),
                    )
                    try:
                        db.session.commit()
                    except SQLAlchemyError as exc:
                        # The in-memory boundary remains untouched, so the exact
                        # duration is eligible for the next checkpoint/stop.
                        db.session.rollback()
                        logger.error(
                            "[acct:%s] Checkpoint commit hatasi: %s",
                            acct_id,
                            exc,
                        )
                        continue

                    advanced = manager.advance_boost_checkpoint(
                        expected_session_id=snapshot.get("session_id"),
                        expected_generation=snapshot.get("generation"),
                        min_elapsed=60,
                        now=stopped_epoch,
                    )
                    if advanced is None:
                        # The manager lock makes this defensive branch unlikely.
                        # The DB segment is still valid; a later stop may overlap
                        # only if an invariant outside this lock was violated.
                        logger.critical(
                            "[acct:%s] Checkpoint yazildi fakat runtime siniri ilerlemedi",
                            acct_id,
                        )
                    else:
                        saved += 1
        except Exception:
            db.session.rollback()
            logger.exception("[acct:%s] Checkpoint hesap hatasi", acct_id)
    return saved


def _checkpoint_loop():
    while True:
        gevent.sleep(900)  # 15 dakika (900 saniye)
        try:
            with app.app_context():
                logger.info(
                    "Running background boost checkpoint (saving active durations)..."
                )
                count = _checkpoint_active_boosts_once()
                if count:
                    logger.info("Checkpoint basarili: %d kayit eklendi.", count)
        except Exception:
            # One unexpected account/DB failure must not kill this permanent
            # background greenlet.
            logger.exception("Checkpoint dongusu beklenmeyen hata ile karsilasti")

gevent.spawn(_checkpoint_loop)


# ───────────────────── Shutdown ─────────────────────

import atexit


@atexit.register
def shutdown_cleanup():
    with app.app_context():
        for acct_id, mgr in boost_service.all_managers():
            try:
                with mgr.state_lock:
                    snapshot = mgr.boost_snapshot()
                    if not snapshot.get("boosting"):
                        continue
                    elapsed = mgr.stop_boost(
                        expected_session_id=snapshot.get("session_id"),
                        expected_generation=snapshot.get("generation"),
                    )
                acct_db = db.session.get(SteamAccount, acct_id)
                if acct_db:
                    _persist_stopped_boost_state(
                        acct_id,
                        acct_db.user_id,
                        started_epoch=snapshot.get("start_time"),
                        stopped_epoch=time.time(),
                        duration_seconds=elapsed,
                        app_ids=snapshot.get("app_ids") or [],
                    )
            except Exception:
                db.session.rollback()
                logger.exception("[acct:%s] Shutdown boost cleanup hatasi", acct_id)

        try:
            _cleanup_revoked_tokens()
        except Exception as e:
            logger.error("Kapatma sırasında revoked token temizleme hatasi: %s", e)


def periodic_token_cleanup():
    import gevent as _gevent
    while True:
        _gevent.sleep(3600)
        try:
            with app.app_context():
                _cleanup_revoked_tokens()
        except Exception as e:
            logger.error("Periyodik token temizleme hatasi: %s", e)


gevent.spawn(periodic_token_cleanup)


# ───────────────────── Yardımcılar ─────────────────────

def _auth_error_should_be_json():
    return (
        request.path.startswith("/admin/")
        or request.method != 'GET'
        or request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        # JWT veya Flask cookie istek başında aynı UserSession kaydına çözüldü.
        user_id = g.get("_auth_user_id")
        if not user_id:
            if _auth_error_should_be_json():
                return jsonify({"ok": False, "error": "Not logged in."}), 401
            return flask_redirect("/")
        user = db.session.get(User, user_id)
        if not user:
            session.clear()
            return jsonify({"ok": False, "error": "User not found."}), 401
        # Admin accounts cannot be deletion targets. Avoid holding the actor's
        # lock while an admin endpoint acquires a different user's lock, which
        # would otherwise create a cross-admin lock-order deadlock.
        if user.is_admin:
            g.user = user
            return f(*args, **kwargs)
        # Serialize all authenticated mutations for one user.  This is
        # especially important on SQLite, where SELECT ... FOR UPDATE is a
        # no-op: account deletion must not race a yielded Steam IPC login,
        # checkout creation, or another request from the same account.
        with _user_operation_lock(user_id):
            db.session.expire_all()
            active_session = UserSession.query.filter(
                UserSession.id == g.get("_auth_session_id"),
                UserSession.user_id == user_id,
                UserSession.token_jti == g.get("_auth_jti"),
                UserSession.is_active.is_(True),
                UserSession.expires_at.isnot(None),
                UserSession.expires_at > datetime.utcnow(),
            ).first()
            if active_session is None:
                session.clear()
                return jsonify({
                    "ok": False,
                    "error": "Session is no longer active.",
                }), 401
            user = db.session.get(User, user_id)
            if not user:
                session.clear()
                return jsonify({"ok": False, "error": "User not found."}), 401
            g.user = user
            return f(*args, **kwargs)
    return wrapped


def target_user_operation_locked(f):
    """Serialize an admin action with every request made by its target user."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        # Authorization must precede lock acquisition; otherwise any logged-in
        # user could queue on an arbitrary victim ID and create a targeted DoS.
        actor = g.get("user")
        if not actor or not actor.is_admin:
            return f(*args, **kwargs)
        data = request.get_json(silent=True)
        target_id = data.get("user_id") if isinstance(data, dict) else None
        if type(target_id) is not int or target_id <= 0:
            return f(*args, **kwargs)
        with _user_operation_lock(target_id):
            # Discard ORM rows read by middleware before the target lock was
            # acquired. The endpoint must make decisions from fresh state.
            db.session.expire_all()
            return f(*args, **kwargs)
    return wrapped


def sanitize(text, maxlen=100):
    if not text:
        return ""
    return bleach.clean(str(text).strip()[:maxlen])


# Parola politikası (ISSUES.md #13): en az 10 karakter, en az 1 küçük harf,
# 1 büyük harf ve 1 rakam. Tüm parola belirleyen endpoint'ler bunu kullanır.
_PW_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{10,}$")
PASSWORD_POLICY_MSG_EN = "Password must be at least 10 characters and include uppercase and lowercase letters and a number."
PASSWORD_POLICY_MSG_TR = "Sifre en az 10 karakter olmali; buyuk harf, kucuk harf ve rakam icermelidir."


def is_strong_password(pw) -> bool:
    return bool(pw) and bool(_PW_RE.match(str(pw)))


def _checkout_cutoff(reference_time=None):
    reference_time = reference_time or datetime.utcnow()
    return reference_time - timedelta(hours=Config.SHOPIER_CHECKOUT_TTL_HOURS)


def _find_active_checkout_by_token(token: str, reference_time=None):
    if not token:
        return None
    return Payment.query.filter(
        Payment.match_token == token,
        Payment.status == "checkout_started",
        Payment.transaction_id.is_(None),
        Payment.created_at >= _checkout_cutoff(reference_time),
    ).first()


def resolve_payment_from_note(note: str, reference_time=None):
    """Resolve exactly one unexpired HB token to an active checkout."""
    try:
        token = extract_single_token(note)
    except OrderValidationError:
        return None, None

    payment = _find_active_checkout_by_token(token, reference_time)
    if payment and payment.user_id:
        user = db.session.get(User, payment.user_id)
        if user:
            return user, payment
    return None, None


def _activate_plan(user, plan: str):
    """Kullanıcıya planı tanımla; süre Config.PLANS[plan]['duration_days']'ten
    okunur. None ise plan süresizdir (plan_expires=None). Çağıran commit eder."""
    user.plan = plan
    duration_days = Config.PLANS.get(plan, {}).get("duration_days")
    user.plan_expires = (
        datetime.utcnow() + timedelta(days=duration_days) if duration_days else None
    )
    user.plan_activated_at = datetime.utcnow()


_PLAN_RANK = {"free": 0, "basic": 1, "premium": 2}


def _activate_paid_plan(user, plan: str) -> bool:
    """Apply a paid plan without allowing out-of-order payment downgrades."""
    current_rank = _PLAN_RANK.get(user.plan, 0)
    if user.plan_expires and user.plan_expires <= datetime.utcnow():
        current_rank = 0
    if current_rank > _PLAN_RANK.get(plan, -1):
        return False
    _activate_plan(user, plan)
    return True


# ───────────────────── Shopier Kalıcı Doğrulama Kuyruğu ─────────────────────

SHOPIER_WEBHOOK_MAX_BYTES = 512 * 1024
SHOPIER_VERIFICATION_BATCH_SIZE = 10
SHOPIER_VERIFICATION_LOCK_SECONDS = 60
SHOPIER_RETRY_DELAYS = (5, 30, 120, 600, 3600)
SHOPIER_MAX_ATTEMPTS = len(SHOPIER_RETRY_DELAYS) + 1

_payment_verification_wakeup = Event()
_payment_verification_greenlet = None


def _shopier_products():
    return {
        str(Config.SHOPIER_BASIC_PRODUCT_ID): (
            "basic", Config.PLANS["basic"]["price"]
        ),
        str(Config.SHOPIER_PREMIUM_PRODUCT_ID): (
            "premium", Config.PLANS["premium"]["price"]
        ),
    }


def _safe_verification_reason(reason) -> str:
    value = re.sub(r"[^a-zA-Z0-9_.:-]", "_", str(reason or "unknown_error"))
    return value[:255]


def _verification_retry_delay(attempt: int, retry_after=None) -> int:
    if retry_after is not None:
        try:
            return max(1, min(3600, int(retry_after)))
        except (TypeError, ValueError):
            pass
    index = max(0, min(attempt - 1, len(SHOPIER_RETRY_DELAYS) - 1))
    base = SHOPIER_RETRY_DELAYS[index]
    jitter = secrets.randbelow(max(2, (base // 5) + 1))
    return base + jitter


def _claim_due_payment(now=None):
    """Atomically lease one due row. Requires an active Flask app context."""
    now = now or datetime.utcnow()
    candidate = (
        Payment.query
        .filter(
            Payment.status == "verification_pending",
            Payment.transaction_id.isnot(None),
            or_(
                Payment.next_verification_at.is_(None),
                Payment.next_verification_at <= now,
            ),
            or_(
                Payment.verification_lock_until.is_(None),
                Payment.verification_lock_until <= now,
            ),
        )
        .order_by(Payment.next_verification_at.asc(), Payment.id.asc())
        .with_entities(Payment.id)
        .first()
    )
    if not candidate:
        return None

    payment_id = candidate[0]
    lock_until = now + timedelta(seconds=SHOPIER_VERIFICATION_LOCK_SECONDS)
    result = db.session.execute(
        update(Payment)
        .where(
            Payment.id == payment_id,
            Payment.status == "verification_pending",
            or_(
                Payment.next_verification_at.is_(None),
                Payment.next_verification_at <= now,
            ),
            or_(
                Payment.verification_lock_until.is_(None),
                Payment.verification_lock_until <= now,
            ),
        )
        .values(
            verification_attempts=Payment.verification_attempts + 1,
            verification_lock_until=lock_until,
        )
    )
    if result.rowcount != 1:
        db.session.rollback()
        return None
    db.session.commit()

    payment = db.session.get(Payment, payment_id)
    if not payment:
        return None
    return {
        "payment_id": payment.id,
        "order_id": payment.transaction_id,
        "attempt": payment.verification_attempts,
    }


def _mark_verification_failed(payment_id, attempt, reason, http_status=None):
    payment = db.session.get(Payment, payment_id)
    if (
        not payment
        or payment.status != "verification_pending"
        or payment.verification_attempts != attempt
    ):
        return False
    payment.status = "verification_failed"
    payment.verification_error = _safe_verification_reason(reason)
    payment.verification_last_http_status = http_status
    payment.next_verification_at = None
    payment.verification_lock_until = None
    db.session.commit()
    logger.warning(
        "shopier.verification.failed payment_id=%s order_id=%s reason=%s attempt=%s",
        payment.id,
        payment.transaction_id,
        payment.verification_error,
        attempt,
    )
    return True


def _schedule_verification_retry(payment_id, attempt, error):
    payment = db.session.get(Payment, payment_id)
    if (
        not payment
        or payment.status != "verification_pending"
        or payment.verification_attempts != attempt
    ):
        return False

    reason = _safe_verification_reason(getattr(error, "reason", "api_error"))
    http_status = getattr(error, "status_code", None)
    retryable = bool(getattr(error, "retryable", False))
    if not retryable or attempt >= SHOPIER_MAX_ATTEMPTS:
        terminal_reason = f"retry_exhausted:{reason}" if retryable else reason
        return _mark_verification_failed(
            payment_id, attempt, terminal_reason, http_status
        )

    delay = _verification_retry_delay(
        attempt, getattr(error, "retry_after", None)
    )
    payment.verification_error = reason
    payment.verification_last_http_status = http_status
    payment.next_verification_at = datetime.utcnow() + timedelta(seconds=delay)
    payment.verification_lock_until = None
    db.session.commit()
    logger.warning(
        "shopier.verification.retry payment_id=%s order_id=%s reason=%s "
        "attempt=%s delay=%s",
        payment.id,
        payment.transaction_id,
        reason,
        attempt,
        delay,
    )
    return True


def _mark_financially_verified_unmatched(payment, canonical, reason):
    payment.user_id = None
    payment.match_token = None
    payment.plan = canonical.plan
    payment.amount = float(canonical.amount)
    payment.verified_amount_minor = canonical.amount_minor
    payment.verified_at = datetime.utcnow()
    payment.status = "unmatched"
    payment.verification_error = _safe_verification_reason(reason)
    payment.verification_last_http_status = 200
    payment.next_verification_at = None
    payment.verification_lock_until = None


def _commit_financially_verified_unmatched(payment, canonical, reason):
    """Persist a paid order without activating a plan or leaving a lease."""
    _mark_financially_verified_unmatched(payment, canonical, reason)
    db.session.commit()
    logger.warning(
        "shopier.verification.unmatched payment_id=%s order_id=%s reason=%s",
        payment.id,
        payment.transaction_id,
        payment.verification_error,
    )
    return True


def _locked_user(user_id):
    if not user_id:
        return None
    # PostgreSQL serializes account deletion/finalization on this row. SQLite
    # ignores FOR UPDATE, but production currently runs a single gunicorn
    # worker and write transactions are serialized by SQLite itself.
    return (
        db.session.query(User)
        .filter(User.id == user_id)
        .with_for_update()
        .first()
    )


def _finalize_canonical_order(
    payment_id, attempt, canonical, _owner_lock_acquired=False
):
    """Finalize payment and plan in one DB transaction."""
    payment = db.session.get(Payment, payment_id)
    if (
        not payment
        or payment.status != "verification_pending"
        or payment.verification_attempts != attempt
        or payment.transaction_id != canonical.order_id
    ):
        return False

    if not _owner_lock_acquired:
        owner_id = payment.user_id
        if owner_id is None and not payment.match_token and canonical.token:
            checkout = _find_active_checkout_by_token(
                canonical.token,
                payment.webhook_received_at or datetime.utcnow(),
            )
            owner_id = checkout.user_id if checkout else None
        if owner_id is not None:
            # Re-run every precondition after acquiring the lock.  If deletion
            # won the race, the refreshed row is finalized as unmatched; if the
            # worker won, deletion observes the completed financial record.
            db.session.expire_all()
            with _user_operation_lock(owner_id):
                return _finalize_canonical_order(
                    payment_id,
                    attempt,
                    canonical,
                    _owner_lock_acquired=True,
                )

    if canonical.token_error:
        if payment.match_token:
            return _mark_verification_failed(
                payment_id, attempt, canonical.token_error, 200
            )
        return _commit_financially_verified_unmatched(
            payment,
            canonical,
            canonical.token_error,
        )

    target = payment
    user = None
    if payment.match_token:
        if payment.match_token != canonical.token:
            return _mark_verification_failed(
                payment_id, attempt, "token_mismatch", 200
            )
        user = _locked_user(payment.user_id)
        if not user:
            payment.owner_user_id_snapshot = (
                payment.owner_user_id_snapshot or payment.user_id
            )
            if payment.user_id is not None and payment.owner_detached_at is None:
                payment.owner_detached_at = datetime.utcnow()
            return _commit_financially_verified_unmatched(
                payment, canonical, "owner_not_found"
            )
    else:
        target = _find_active_checkout_by_token(
            canonical.token,
            payment.webhook_received_at or datetime.utcnow(),
        )
        if not target or not target.user_id:
            return _commit_financially_verified_unmatched(
                payment, canonical, "active_token_not_found"
            )

        user = _locked_user(target.user_id)
        if not user:
            detached_at = target.owner_detached_at or datetime.utcnow()
            payment.owner_user_id_snapshot = (
                target.owner_user_id_snapshot or target.user_id
            )
            payment.owner_username_snapshot = target.owner_username_snapshot
            payment.owner_detached_at = detached_at
            target.user_id = None
            target.owner_detached_at = detached_at
            target.status = "cancelled"
            target.match_token = None
            target.verification_error = "owner_not_found"
            target.next_verification_at = None
            target.verification_lock_until = None
            _mark_financially_verified_unmatched(
                payment, canonical, "owner_not_found"
            )
            db.session.commit()
            logger.warning(
                "shopier.verification.unmatched payment_id=%s order_id=%s "
                "reason=owner_not_found checkout_id=%s token_fp=%s",
                payment.id,
                payment.transaction_id,
                target.id,
                token_fingerprint(canonical.token),
            )
            return True

        metadata = {
            "transaction_id": payment.transaction_id,
            "shopier_webhook_id": payment.shopier_webhook_id,
            "shopier_event": payment.shopier_event,
            "shopier_account_id": payment.shopier_account_id,
            "shopier_timestamp": payment.shopier_timestamp,
            "webhook_body_sha256": payment.webhook_body_sha256,
            "webhook_received_at": payment.webhook_received_at,
            "verification_attempts": payment.verification_attempts,
            # Hiding either side of a consolidation is append-only admin state;
            # never make a previously hidden financial row visible again.
            "admin_hidden": bool(payment.admin_hidden or target.admin_hidden),
        }
        PaymentAuditLog.query.filter_by(payment_id=payment.id).update(
            {"payment_id": target.id}, synchronize_session=False
        )
        db.session.delete(payment)
        db.session.flush()
        for field, value in metadata.items():
            setattr(target, field, value)

    if not user:
        # Defensive fallback for corrupt legacy rows. A canonically paid order
        # must end in manual review instead of being reclaimed forever.
        target.owner_user_id_snapshot = (
            target.owner_user_id_snapshot or target.user_id
        )
        if target.user_id is not None and target.owner_detached_at is None:
            target.owner_detached_at = datetime.utcnow()
        return _commit_financially_verified_unmatched(
            target, canonical, "owner_not_found"
        )

    target.status = "completed"
    target.plan = canonical.plan
    target.amount = float(canonical.amount)
    target.verified_amount_minor = canonical.amount_minor
    target.verified_at = datetime.utcnow()
    target.verification_error = None
    target.verification_last_http_status = 200
    target.next_verification_at = None
    target.verification_lock_until = None
    plan_changed = _activate_paid_plan(user, canonical.plan)
    db.session.commit()

    logger.info(
        "shopier.payment.completed payment_id=%s order_id=%s plan=%s "
        "amount_minor=%s plan_changed=%s",
        target.id,
        target.transaction_id,
        canonical.plan,
        canonical.amount_minor,
        plan_changed,
    )
    return True


def _process_payment_claim(claim):
    try:
        order = shopier_lib.get_order(Config.SHOPIER_PAT, claim["order_id"])
    except shopier_lib.ShopierAPIError as exc:
        with app.app_context():
            _schedule_verification_retry(
                claim["payment_id"], claim["attempt"], exc
            )
        return False

    try:
        canonical = validate_canonical_order(
            order,
            expected_order_id=claim["order_id"],
            products=_shopier_products(),
        )
    except OrderValidationError as exc:
        with app.app_context():
            _mark_verification_failed(
                claim["payment_id"], claim["attempt"], exc.reason, 200
            )
        return False

    try:
        with app.app_context():
            finalized = _finalize_canonical_order(
                claim["payment_id"], claim["attempt"], canonical
            )
            if not finalized:
                stalled = db.session.get(Payment, claim["payment_id"])
                if (
                    stalled
                    and stalled.status == "verification_pending"
                    and stalled.verification_attempts == claim["attempt"]
                ):
                    synthetic = shopier_lib.ShopierAPIError(
                        "finalize_without_transition", retryable=True
                    )
                    _schedule_verification_retry(
                        claim["payment_id"], claim["attempt"], synthetic
                    )
            return finalized
    except IntegrityError:
        with app.app_context():
            db.session.rollback()
            synthetic = shopier_lib.ShopierAPIError(
                "concurrent_conflict", retryable=True
            )
            _schedule_verification_retry(
                claim["payment_id"], claim["attempt"], synthetic
            )
        logger.warning(
            "shopier.verification.concurrent_conflict payment_id=%s order_id=%s",
            claim["payment_id"],
            claim["order_id"],
        )
        return False
    except Exception:
        with app.app_context():
            db.session.rollback()
            synthetic = shopier_lib.ShopierAPIError(
                "internal_finalize_error", retryable=True
            )
            _schedule_verification_retry(
                claim["payment_id"], claim["attempt"], synthetic
            )
        logger.exception(
            "shopier.verification.internal_error payment_id=%s order_id=%s",
            claim["payment_id"],
            claim["order_id"],
        )
        return False


def process_due_payment_verifications(limit=SHOPIER_VERIFICATION_BATCH_SIZE):
    """Process a bounded number of due jobs; deterministic entrypoint for tests."""
    processed = 0
    for _ in range(max(1, min(int(limit), 50))):
        with app.app_context():
            claim = _claim_due_payment()
        if not claim:
            break
        processed += 1
        _process_payment_claim(claim)
        gevent.sleep(0)
    return processed


def _payment_verification_loop():
    logger.info("shopier.verification.worker_started")
    while True:
        _payment_verification_wakeup.clear()
        try:
            processed = process_due_payment_verifications()
        except Exception:
            logger.exception("shopier.verification.worker_iteration_failed")
            processed = 0
        if processed:
            gevent.sleep(0.25)
            continue
        _payment_verification_wakeup.wait(timeout=5)


def _payment_worker_failed(greenlet):
    logger.critical(
        "shopier.verification.worker_died exception=%s",
        type(greenlet.exception).__name__ if greenlet.exception else "unknown",
    )


def _start_payment_verification_worker():
    global _payment_verification_greenlet
    if not Config.SHOPIER_API_VERIFY_ENABLED:
        logger.warning("Shopier API doğrulaması feature flag ile kapalı")
        return
    if not Config.SHOPIER_VERIFICATION_WORKER_ENABLED:
        logger.warning("Shopier verification worker feature flag ile kapalı")
        return
    if _payment_verification_greenlet and not _payment_verification_greenlet.dead:
        return
    _payment_verification_greenlet = gevent.spawn(_payment_verification_loop)
    _payment_verification_greenlet.link_exception(_payment_worker_failed)


# ───────────────────── Bakım Modu ─────────────────────
# Bakım modu bayrağı DOSYA tabanlıdır (instance/maintenance.flag). Böylece durum
# gunicorn yeniden başlasa bile KORUNUR (global değişken restart'ta sıfırlanırdı)
# ve gerekirse SSH ile elle açılıp kapatılabilir. workers=1 olduğundan dosya
# kontrolü ucuzdur; ileride çok worker'a geçilse bile dosya paylaşımı sorunsuzdur.
MAINTENANCE_FLAG_PATH = os.path.join(app.instance_path, "maintenance.flag")


def is_maintenance_mode() -> bool:
    return os.path.exists(MAINTENANCE_FLAG_PATH)


def set_maintenance_mode(enabled: bool) -> None:
    if enabled:
        os.makedirs(app.instance_path, exist_ok=True)
        with open(MAINTENANCE_FLAG_PATH, "w") as f:
            f.write(datetime.utcnow().isoformat() + "\n")
    else:
        try:
            os.remove(MAINTENANCE_FLAG_PATH)
        except FileNotFoundError:
            pass


# ───────────────────── Middleware ─────────────────────

# Nonce tabanlı KATI CSP'ye geçirilmiş endpoint'ler (FIX.md Phase 4).
# Bir sayfanın template'i inline onclick/onsubmit handler'lardan arındırılıp
# <script> etiketleri nonce="{{ csp_nonce }}" aldığında endpoint adı buraya
# eklenir. Kalan sayfalar taşınana kadar eski (unsafe-inline) politikada kalır.
# Not: nonce ile 'unsafe-inline' aynı politikada birleştirilemez — nonce varsa
# tarayıcı 'unsafe-inline'ı yok sayar; bu yüzden geçiş sayfa-bazlı yapılır.
_STRICT_CSP_ENDPOINTS = {"admin_page"}


@app.before_request
def _generate_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)


@app.context_processor
def _inject_csp_nonce():
    return {"csp_nonce": g.get("csp_nonce", "")}


@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # _STRICT_CSP_ENDPOINTS'teki sayfalarda script-src nonce tabanlıdır
    # ('unsafe-inline' yok); inline <script> blokları nonce taşımak zorundadır
    # ve inline onclick/onsubmit handler'ları ÇALIŞMAZ. Henüz taşınmamış
    # sayfalar eski (unsafe-inline) politikayla devam eder (ISSUES.md #9).
    # style-src'de 'unsafe-inline' bilinçli olarak KALIYOR: arayüz yaygın
    # biçimde inline style attribute kullanıyor; asıl XSS riski (script
    # çalıştırma / JWT çalma) script-src katılaştırmasıyla kapanır.
    if request.endpoint in _STRICT_CSP_ENDPOINTS:
        script_src = f"'self' https://cdn.jsdelivr.net 'nonce-{g.get('csp_nonce', '')}'"
    else:
        script_src = "'self' https://cdn.jsdelivr.net 'unsafe-inline'"
    csp = (
        "default-src 'self'; "
        f"script-src {script_src}; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.shopier.com https://api.steampowered.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    if app.config.get('SESSION_COOKIE_SECURE', False):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


_plan_expiry_cache: dict = {}
_PLAN_CHECK_INTERVAL = 300


@app.before_request
def _resolve_request_auth():
    """Bearer JWT veya Flask cookie'yi aktif UserSession kaydına çöz.

    Authorization başlığı varsa yalnızca o kimlik bilgisi değerlendirilir;
    geçersiz/revoked Bearer'ın cookie'ye sessizce düşmesine izin verilmez.
    """
    g._auth_user_id = None
    g._auth_session_id = None
    g._auth_jti = None
    g._jwt_user_id = None
    g._jwt_token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        verified = _verified_token_session(token)
        if verified:
            user_id, session_id, jti = verified
            g._auth_user_id = user_id
            g._auth_session_id = session_id
            g._auth_jti = jti
            g._jwt_user_id = user_id
            g._jwt_token = token
        return

    cookie_jti = session.get("auth_jti")
    has_legacy_auth = (
        "user_id" in session or "auth_session_id" in session
    )
    if cookie_jti is None and not has_legacy_auth:
        return
    if (
        not isinstance(cookie_jti, str)
        or not re.fullmatch(r"[0-9a-f]{32}", cookie_jti)
    ):
        session.clear()
        return

    active_session = _active_cookie_session()
    if active_session is None:
        session.clear()
        return

    g._auth_user_id = active_session.user_id
    g._auth_session_id = active_session.id
    g._auth_jti = active_session.token_jti


@app.before_request
def auto_csrf_protect():
    """
    CSRF korumasını manuel olarak yönet.

    Flask-WTF'in otomatik before_request kontrolü (WTF_CSRF_CHECK_DEFAULT=False)
    kapatılmıştır. Bu fonksiyon:
      - Bearer JWT ile gelen istekleri CSRF'den muaf tutar.
        (JWT localStorage'da saklandığından tarayıcı otomatik göndermez → CSRF riski yok)
      - Cookie/session tabanlı isteklerde standart CSRF doğrulamasını uygular.

    Böylece eski cache'den açılan sayfalar veya uzun süre açık kalan sekmeler
    süresi dolmuş CSRF token nedeniyle 400/403 almaz; JWT varsa istek geçer.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return  # Salt-okunur metodlarda CSRF gerekmez

    # @csrf.exempt ile işaretlenmiş endpoint'leri atla (ör. Shopier webhook).
    # WTF_CSRF_CHECK_DEFAULT=False olduğundan exempt mantığı otomatik
    # çalışmaz; csrf.protect() exempt view'ları dikkate almadığı için
    # burada elle kontrol etmemiz gerekir.
    if request.endpoint:
        view = app.view_functions.get(request.endpoint)
        if view is not None:
            dest = f"{view.__module__}.{view.__name__}"
            if view in csrf._exempt_views or dest in csrf._exempt_views:
                return

    if request.headers.get("Authorization", "").startswith("Bearer "):
        # Authorization başlığı tarayıcı tarafından cross-site isteklere
        # otomatik eklenmez. Token geçersiz/revoked olsa bile CSRF yerine ilgili
        # endpoint'in tutarlı 401/200 cevabını üretmesine izin ver.
        return

    # JWT yoksa veya geçersizse standart CSRF doğrulaması yap
    csrf.protect()


@app.before_request
def check_plan_expiry():
    uid = g.get("_auth_user_id")
    if not uid:
        return
    now = time.time()
    last = _plan_expiry_cache.get(uid, 0)
    if now - last < _PLAN_CHECK_INTERVAL:
        return
    # Sınırsız büyümeyi önle: cache şiştiğinde aralık dışı (bayat) kayıtları temizle.
    if len(_plan_expiry_cache) > 5000:
        cutoff = now - _PLAN_CHECK_INTERVAL
        for k in [k for k, v in _plan_expiry_cache.items() if v < cutoff]:
            _plan_expiry_cache.pop(k, None)
    _plan_expiry_cache[uid] = now
    user = db.session.get(User, uid)
    if not user:
        return
    if user.plan != "free" and user.plan_expires:
        if user.plan_expires < datetime.utcnow():
            user.plan = "free"
            user.plan_expires = None
            db.session.commit()

    # Oturum "son görülme" güncellemesi (Bearer ile gelen istekler için).
    # Bu blok 5 dk throttle'lı (fonksiyon başındaki _plan_expiry_cache kontrolü),
    # dolayısıyla her istekte DB yazımı yapılmaz.
    if g.get("_auth_session_id"):
        try:
            UserSession.query.filter_by(
                id=g._auth_session_id,
                user_id=uid,
                is_active=True,
            ).update(
                {"last_seen": datetime.utcnow()}, synchronize_session=False
            )
            db.session.commit()
        except Exception:
            db.session.rollback()


# Bakım modunda dahi her zaman erişilebilen yollar: oturum açma uçları (yönetici
# tekrar giriş yapıp modu kapatabilsin diye), oturum kontrolü ve ads.txt.
# Statik dosyalar ayrıca muaf tutulur; /admin* erişimi doğrulanmış admin kimliği
# üzerinden aşağıdaki ortak yetki kontrolünden geçer.
_MAINTENANCE_ALLOWED_EXACT = {
    "/site_login",
    "/site_logout",
    "/session_check",
    "/favicon.ico",
    "/ads.txt",
}
_MAINTENANCE_BLOCKED_AUTH_EXACT = {
    "/steam/login",
    "/steam/callback",
}


@app.before_request
def maintenance_gate():
    """Bakım modu açıkken yöneticiler hariç herkese bakım sayfasını göster.

    _resolve_request_auth'dan SONRA çalışır (g._auth_user_id hazır). Yöneticiler
    siteyi normal kullanmaya devam eder; statik dosyalar, admin paneli ve oturum
    açma uçları her zaman erişilebilir kalır ki kilitlenme yaşanmasın.
    """
    if not is_maintenance_mode():
        return

    path = request.path or "/"
    if path in _MAINTENANCE_BLOCKED_AUTH_EXACT:
        session.pop("steam_state", None)
        return render_template("development.html"), 503
    if path.startswith("/static/"):
        return
    if path in _MAINTENANCE_ALLOWED_EXACT:
        return

    uid = g.get("_auth_user_id")
    if uid:
        u = db.session.get(User, uid)
        if u and u.is_admin:
            return

    if request.method in ("GET", "HEAD"):
        return render_template("development.html"), 503
    return jsonify({
        "ok": False,
        "maintenance": True,
        "error": "Site şu anda bakım modunda. Lütfen daha sonra tekrar deneyin.",
    }), 503


# ───────────────────── Sayfalar (TR) ─────────────────────

@app.route("/")
def index():
    uid = g.get("_auth_user_id")
    if uid and db.session.get(User, uid):
        return render_template("index.html")
    return render_template("landing.html")


@app.route("/dashboard")
def dashboard():
    return render_template("index.html")


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/gizlilik")
def gizlilik():
    return render_template("gizlilik.html")


@app.route("/kullanim-sartlari")
def kullanim_sartlari():
    return render_template("kullanim-sartlari.html")


@app.route("/mesafeli-satis")
def mesafeli_satis():
    return render_template("mesafeli-satis.html")


@app.route("/iade-politikasi")
def iade_politikasi():
    return render_template("iade-politikasi.html")


@app.route("/hakkimizda")
def hakkimizda():
    return render_template("hakkimizda.html")


@app.route("/iletisim")
def iletisim():
    return render_template("hakkimizda.html")


@app.route("/cerez-politikasi")
def cerez_politikasi():
    return render_template("cerez-politikasi.html")


# ───────────────────── Sayfalar (EN) ─────────────────────

@app.route("/en/")
@app.route("/en")
def index_en():
    uid = g.get("_auth_user_id")
    if uid and db.session.get(User, uid):
        return render_template("en/index.html")
    return render_template("en/landing.html")


@app.route("/en/dashboard")
def dashboard_en():
    return render_template("en/index.html")


@app.route("/en/pricing")
def pricing_en():
    return render_template("en/pricing.html")


@app.route("/en/privacy")
def privacy_en():
    return render_template("en/gizlilik.html")


@app.route("/en/terms-of-service")
def terms_en():
    return render_template("en/kullanim-sartlari.html")


@app.route("/en/distance-selling")
def distance_selling_en():
    return render_template("en/mesafeli-satis.html")


@app.route("/en/refund-policy")
def refund_policy_en():
    return render_template("en/iade-politikasi.html")


@app.route("/en/about")
def about_en():
    return render_template("en/hakkimizda.html")


@app.route("/en/contact")
def contact_en():
    return render_template("en/hakkimizda.html")


@app.route("/en/cookie-policy")
def cookie_policy_en():
    return render_template("en/cerez-politikasi.html")


@app.route("/ads.txt")
def ads_txt():
    return (
        "google.com, pub-4233612570799995, DIRECT, f08c47fec0942fa0",
        200,
        {"Content-Type": "text/plain"},
    )


# ───────────────────── Auth ─────────────────────

@app.route("/session_check")
def session_check():
    user_id = g.get("_auth_user_id")
    if not user_id:
        return jsonify({"logged_in": False})
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "username": user.username,
        "is_admin": user.is_admin,
        # Steam ile kayıt olup henüz kendi şifresini belirlememiş kullanıcı
        "is_steam_only": bool(user.steam_id) and (user.email or "").endswith("@steamlogin.hourboost"),
    })


@app.route("/plan/info")
@login_required
def plan_info():
    user = g.user
    limits = user.plan_limits()
    acct_count = SteamAccount.query.filter_by(user_id=user.id).count()
    return jsonify({
        "plan": user.plan,
        "max_accounts": limits["max_accounts"],
        "max_games": limits["max_games"],
        "daily_hours": limits.get("daily_hours"),
        "total_hours": limits.get("total_hours"),
        "price": limits["price"],
        "current_accounts": acct_count,
        "plan_expires": user.plan_expires.isoformat() if user.plan_expires else None,
        "all_plans": Config.PLANS,
        "is_verified": user.is_verified,
    })


@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.json
    u = sanitize(data.get("username", ""), 40)
    e = sanitize(data.get("email", ""), 120).lower()
    p = data.get("password", "")
    lang = data.get("lang", "tr")
    if lang not in ("en", "tr"):
        lang = "tr"

    if not u or not e or not p:
        return jsonify({"ok": False, "error": "All fields are required." if lang == "en" else "Tum alanlar gerekli."})
    if not is_strong_password(p):
        return jsonify({"ok": False, "error": PASSWORD_POLICY_MSG_EN if lang == "en" else PASSWORD_POLICY_MSG_TR})
    # "Kullanıcı adı/e-posta alınmış" ön kontrolleri KALDIRILDI (enumeration,
    # ISSUES.md #5): benzersizlik DB unique kısıtlarına bırakılır ve aşağıda
    # hangi alanın çakıştığını açık etmeyen tek bir genel mesajla yanıtlanır.
    verification_token = secrets.token_urlsafe(32)
    user = User(
        username=u,
        email=e,
        is_verified=False,
        verification_token=verification_token,
        verification_sent_at=datetime.utcnow(),
        lang=lang,
    )
    from sqlalchemy.exc import IntegrityError
    _generic_reg_err = jsonify({
        "ok": False,
        "error": "Registration could not be completed. Please check your details."
        if lang == "en" else "Kayit tamamlanamadi. Lutfen bilgilerinizi kontrol edin.",
    })
    try:
        user.set_password(p)
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        # Kullanıcı adı veya e-posta zaten kayıtlı; hangisi olduğunu söyleme.
        db.session.rollback()
        return _generic_reg_err
    except Exception as exc:
        db.session.rollback()
        logger.error("Kullanici kayit sirasinda veritabani hatasi: %s", exc)
        return _generic_reg_err

    gevent.spawn(mailer.send_verification_email, e, u, verification_token, lang=lang)

    # Mail gönderimi async (gevent.spawn) olduğundan başarısını burada bilemeyiz;
    # frontend yalnızca "verify_email" bayrağını kullanıyor. Yanıltıcı
    # "mail_sent: true" alanı kaldırıldı.
    return jsonify({
        "ok": True,
        "verify_email": True,
    })


@app.route("/verify-email/<token>")
def verify_email(token):
    lang = request.args.get("lang", "tr")
    if lang not in ("en", "tr"):
        lang = "tr"

    template = "en/verify_result.html" if lang == "en" else "verify_result.html"

    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return render_template(template, success=False,
            message="Invalid or expired verification link." if lang == "en"
            else "Geçersiz veya süresi dolmuş doğrulama linki.")

    if not user.verification_sent_at:
        return render_template(template, success=False,
            message="Invalid verification link." if lang == "en"
            else "Geçersiz doğrulama linki.")

    elapsed = datetime.utcnow() - user.verification_sent_at
    if elapsed.total_seconds() > 86400:
        return render_template(template, success=False,
            message="Verification link has expired. Please request a new one." if lang == "en"
            else "Doğrulama linkinin süresi dolmuş. Lütfen yeni link isteyin.")

    if user.is_verified:
        return render_template(template, success=True,
            message="Your email address is already verified." if lang == "en"
            else "E-posta adresiniz zaten doğrulanmış.")

    user.is_verified = True
    user.verification_token = None
    db.session.commit()

    user_lang = getattr(user, "lang", "tr") or "tr"
    # SMTP'yi bloklamadan arka planda gönder (register/forgot ile tutarlı).
    gevent.spawn(mailer.send_welcome_email, user.email, user.username, lang=user_lang)

    return render_template(template, success=True,
        message="Your email has been verified! You can now add Steam accounts." if lang == "en"
        else "E-posta adresiniz başarıyla doğrulandı! Artık Steam hesabı ekleyebilirsiniz.")


@app.route("/resend-verification", methods=["POST"])
@login_required
@limiter.limit("3 per hour")
def resend_verification():
    user = g.user
    lang = getattr(user, "lang", "tr") or "tr"

    if user.is_verified:
        return jsonify({"ok": False, "error": "Your account is already verified." if lang == "en" else "Hesabiniz zaten dogrulanmis."})

    if user.verification_sent_at:
        elapsed = (datetime.utcnow() - user.verification_sent_at).total_seconds()
        if elapsed < 300:
            remaining = int(300 - elapsed)
            return jsonify({"ok": False, "error": f"Please wait {remaining} seconds." if lang == "en" else f"Lutfen {remaining} saniye bekleyin."})

    token = secrets.token_urlsafe(32)
    user.verification_token = token
    user.verification_sent_at = datetime.utcnow()
    db.session.commit()

    # Mail gönderimini bloklamadan arka planda yap (register/forgot ile tutarlı).
    gevent.spawn(mailer.send_verification_email, user.email, user.username, token, lang=lang)
    return jsonify({"ok": True, "message": "Verification email sent." if lang == "en" else "Dogrulama maili gonderildi."})


# ───────────────────── Şifre Sıfırlama ─────────────────────

@app.route("/forgot-password", methods=["POST"])
@limiter.limit("3 per hour")
def forgot_password():
    data = request.json
    email = sanitize(data.get("email", ""), 120)
    lang = data.get("lang", "tr")
    if lang not in ("en", "tr"):
        lang = "tr"

    if not email:
        return jsonify({"ok": False, "error": "Email address is required." if lang == "en" else "E-posta adresi gerekli."})

    user = User.query.filter_by(email=email).first()

    _generic_msg = {
        "ok": True,
        "message": "If this email is registered, a reset link has been sent." if lang == "en"
        else "Eğer bu e-posta kayıtlıysa sıfırlama linki gönderildi.",
    }

    if not user:
        return jsonify(_generic_msg)

    if user.reset_token_expires:
        remaining = (user.reset_token_expires - datetime.utcnow()).total_seconds()
        if remaining > (3600 - 300):
            return jsonify(_generic_msg)

    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()

    user_lang = getattr(user, "lang", "tr") or "tr"
    gevent.spawn(mailer.send_password_reset_email, user.email, user.username, token, user_lang)

    return jsonify(_generic_msg)


@app.route("/reset-password/<token>")
def reset_password_page(token):
    lang = request.args.get("lang", "tr")
    if lang not in ("en", "tr"):
        lang = "tr"
    template = "en/reset_password.html" if lang == "en" else "reset_password.html"

    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expires:
        return render_template(template, valid=False,
            message="Invalid or expired link." if lang == "en" else "Geçersiz veya süresi dolmuş link.")
    if datetime.utcnow() > user.reset_token_expires:
        return render_template(template, valid=False,
            message="This link has expired. Please create a new request." if lang == "en"
            else "Bu linkin süresi dolmuş. Lütfen yeni talep oluşturun.")
    return render_template(template, valid=True, token=token)


@app.route("/reset-password", methods=["POST"])
@limiter.limit("5 per hour")
def reset_password():
    data = request.json
    token = data.get("token", "")
    new_password = data.get("password", "")

    if not token or not new_password:
        return jsonify({"ok": False, "error": "Missing information."})
    if not is_strong_password(new_password):
        return jsonify({"ok": False, "error": PASSWORD_POLICY_MSG_EN})

    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expires:
        return jsonify({"ok": False, "error": "Invalid link."})
    if datetime.utcnow() > user.reset_token_expires:
        return jsonify({"ok": False, "error": "Link has expired."})

    user.set_password(new_password)
    user.reset_token = None
    user.reset_token_expires = None
    _invalidate_all_user_tokens(user)
    db.session.commit()
    logger.info("Sifre sifirlandi: %s", user.username)
    return jsonify({"ok": True, "message": "Your password has been updated successfully."})


@app.route("/change-password", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def change_password():
    data = request.json
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"ok": False, "error": "All fields are required."})
    if not is_strong_password(new_password):
        return jsonify({"ok": False, "error": PASSWORD_POLICY_MSG_EN})

    user = g.user
    if not user.check_password(current_password):
        return jsonify({"ok": False, "error": "Current password is incorrect."})

    user.set_password(new_password)
    _invalidate_all_user_tokens(user)
    db.session.commit()

    # Diğer tüm oturumlar iptal edildi; mevcut cihazın oturumda kalması
    # için taze bir token üret ve döndür (frontend bunu saklamalı).
    new_token = generate_api_token(user.id)
    if _establish_authenticated_session(user.id, new_token) is None:
        logger.error(
            "Sifre degisti ancak yeni oturum olusturulamadi: user_id=%s",
            user.id,
        )
        return jsonify({
            "ok": False,
            "error": "Password changed, but a secure session could not be created. Please log in again.",
            "reauth_required": True,
        }), 503

    logger.info("Sifre degistirildi: %s", user.username)
    return jsonify({
        "ok": True,
        "message": "Your password has been updated successfully.",
        "token": new_token,
    })


@app.route("/account/set-password", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def set_initial_password():
    """Steam ile giriş yapıp henüz şifresi olmayan kullanıcıların, MEVCUT şifre
    istenmeden ilk şifrelerini belirlemesini sağlar (dead-end çözümü).
    Yalnızca placeholder e-postalı Steam hesaplarında çalışır; gerçek şifre/
    e-posta belirlendikten sonra normal /change-password kullanılmalıdır."""
    user = g.user
    if not (user.steam_id and (user.email or "").endswith("@steamlogin.hourboost")):
        return jsonify({"ok": False, "error": "This option is only for Steam-login accounts without a password. Use 'Change Password'."})

    new_password = request.json.get("new_password", "")
    if not is_strong_password(new_password):
        return jsonify({"ok": False, "error": PASSWORD_POLICY_MSG_EN})

    user.set_password(new_password)
    db.session.commit()

    new_token = generate_api_token(user.id)
    if _establish_authenticated_session(user.id, new_token) is None:
        logger.error(
            "Ilk sifre kaydedildi ancak yeni oturum olusturulamadi: user_id=%s",
            user.id,
        )
        return jsonify({
            "ok": False,
            "error": "Password was saved, but a secure session could not be created. Please log in again.",
            "reauth_required": True,
        }), 503
    logger.info("Steam kullanicisi ilk sifresini belirledi: %s", user.username)
    return jsonify({
        "ok": True,
        "message": "Password set. You can now also log in with your username and password, then change your email.",
        "token": new_token,
    })


# ───────────────────── E-posta Değiştirme ─────────────────────

@app.route("/change-email", methods=["POST"])
@login_required
@limiter.limit("3 per hour")
def change_email():
    data = request.json
    new_email = sanitize(data.get("email", ""), 120)
    password = data.get("password", "")

    if not new_email or not password:
        return jsonify({"ok": False, "error": "All fields are required."})

    user = g.user
    if not user.check_password(password):
        return jsonify({"ok": False, "error": "Current password is incorrect."})
    if new_email == user.email:
        return jsonify({"ok": False, "error": "This is already your current email address."})

    if user.email_change_expires:
        remaining = (user.email_change_expires - datetime.utcnow()).total_seconds()
        if remaining > 0:
            return jsonify({"ok": False, "error": "Please wait."})

    # Enumeration önlemi (ISSUES.md #5): e-posta başka bir hesapta kayıtlıysa
    # bunu AÇIK ETME — gerçek akışla birebir aynı yanıtı döndür ama mail
    # gönderme/token üretme. Benzersizlik onay adımında (confirm_email_change)
    # zaten yeniden kontrol ediliyor.
    if User.query.filter_by(email=new_email).first():
        return jsonify({"ok": True, "message": f"A verification email has been sent to {new_email}."})

    token = secrets.token_urlsafe(32)
    user.email_change_token = token
    user.email_change_new = new_email
    user.email_change_expires = datetime.utcnow() + timedelta(hours=1)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error("E-posta degistirme sirasinda veritabani hatasi: %s", e)
        return jsonify({"ok": False, "error": "An error occurred."})

    user_lang = getattr(user, "lang", "tr") or "tr"
    gevent.spawn(mailer.send_email_change_email, new_email, user.username, token, user_lang)

    return jsonify({"ok": True, "message": f"A verification email has been sent to {new_email}."})


@app.route("/confirm-email-change/<token>")
def confirm_email_change(token):
    lang = request.args.get("lang", "tr")
    if lang not in ("en", "tr"):
        lang = "tr"
    template = "en/verify_result.html" if lang == "en" else "verify_result.html"

    user = User.query.filter_by(email_change_token=token).first()
    if not user or not user.email_change_expires:
        return render_template(template, success=False,
            message="Invalid or expired link." if lang == "en" else "Geçersiz veya süresi dolmuş link.")
    if datetime.utcnow() > user.email_change_expires:
        return render_template(template, success=False,
            message="This link has expired. Please create a new request." if lang == "en"
            else "Bu linkin süresi dolmuş. Lütfen yeni talep oluşturun.")

    # İstek ile onay arasında yeni e-posta başkası tarafından alınmış olabilir;
    # unique constraint'ten kaynaklı 500 yerine temiz hata döndür.
    taken = User.query.filter(
        User.email == user.email_change_new,
        User.id != user.id,
    ).first()
    if taken:
        user.email_change_token = None
        user.email_change_new = None
        user.email_change_expires = None
        db.session.commit()
        return render_template(template, success=False,
            message="This email address is now in use by another account. Please try again." if lang == "en"
            else "Bu e-posta adresi artık başka bir hesap tarafından kullanılıyor. Lütfen tekrar deneyin.")

    user.email = user.email_change_new
    user.email_change_token = None
    user.email_change_new = None
    user.email_change_expires = None
    db.session.commit()
    logger.info("E-posta degistirildi: %s", user.username)
    return render_template(template, success=True,
        message="Your email address has been updated successfully!" if lang == "en"
        else "E-posta adresiniz başarıyla güncellendi!")


@app.route("/site_login", methods=["POST"])
@limiter.limit("10 per minute")
def site_login():
    data = request.json
    u = sanitize(data.get("username", ""), 40)
    p = data.get("password", "")

    ip = _get_client_ip()
    ip_key = f"ip:{ip}"

    if is_locked_out(ip_key):
        return jsonify({"ok": False, "error": "Too many failed attempts. Please wait 5 minutes."}), 429

    user = User.query.filter_by(username=u).first()
    if not user or not user.check_password(p):
        record_failed_login(ip_key)
        return jsonify({"ok": False, "error": "Invalid username or password."})

    if is_maintenance_mode() and not user.is_admin:
        logger.info(
            "Bakim modunda non-admin girisi engellendi: user_id=%s ip=%s",
            user.id,
            ip,
        )
        return jsonify({
            "ok": False,
            "maintenance": True,
            "error": "The service is temporarily unavailable due to maintenance.",
        }), 503

    clear_failed_logins(ip_key)

    user.last_login = db.func.now()
    db.session.commit()

    token = generate_api_token(user.id)
    if _establish_authenticated_session(user.id, token) is None:
        logger.error("Guvenli oturum olusturulamadi: user_id=%s", user.id)
        return jsonify({
            "ok": False,
            "error": "A secure session could not be created. Please try again.",
        }), 503

    return jsonify({"ok": True, "is_admin": user.is_admin, "token": token})


@app.route("/site_logout", methods=["POST"])
def site_logout():
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    identity = _decode_token_for_revocation(token)
    records = {}
    if identity:
        token_record = UserSession.query.filter_by(
            user_id=identity["user_id"],
            token_jti=identity["jti"],
        ).first()
        if token_record:
            records[token_record.id] = token_record

    # Resolver, bozuk Bearer varken bilinçli olarak cookie'ye fallback yapmaz.
    # Logout ise tarayıcının imzalı cookie oturumunu da bağımsız kapatmalıdır.
    cookie_jti = session.get("auth_jti")
    if isinstance(cookie_jti, str) and re.fullmatch(r"[0-9a-f]{32}", cookie_jti):
        cookie_record = UserSession.query.filter_by(token_jti=cookie_jti).first()
        if cookie_record:
            records[cookie_record.id] = cookie_record

    # Not: Web'den çıkış boost'u DURDURMAZ; boost sunucu tarafında çalışmaya
    # devam eder. Boost yalnızca /boost/toggle veya hesap silme ile durdurulur.
    success = _revoke_session_records(
        list(records.values()),
        [identity] if identity else [],
    )
    if success and token and identity:
        with _blacklist_lock:
            _token_blacklist.add(token)
        _cleanup_blacklist()
    session.clear()
    if not success:
        return jsonify({
            "ok": False,
            "error": "Logout could not be persisted. Please try again.",
        }), 503
    return jsonify({"ok": True})


# ───────────────────── Oturum Yönetimi ─────────────────────

@app.route("/sessions")
@login_required
def list_sessions():
    sessions = (
        UserSession.query
        .filter_by(user_id=g.user.id, is_active=True)
        .filter(
            UserSession.token_jti.isnot(None),
            UserSession.expires_at.isnot(None),
            UserSession.expires_at > datetime.utcnow(),
        )
        .order_by(UserSession.last_seen.desc())
        .all()
    )

    current_session_id = g.get("_auth_session_id")

    result = []
    for s in sessions:
        ua = s.user_agent or ""
        if "Mobile" in ua or "Android" in ua or "iPhone" in ua:
            device = "📱 Mobile"
        elif "Windows" in ua:
            device = "🖥 Windows"
        elif "Mac" in ua:
            device = "🖥 macOS"
        elif "Linux" in ua:
            device = "🖥 Linux"
        else:
            device = "🌐 Browser"

        result.append({
            "id": s.id,
            "ip": s.ip_address or "Unknown",
            "device": device,
            "user_agent": ua[:80] + ("..." if len(ua) > 80 else ""),
            "created_at": s.created_at.isoformat(),
            "last_seen": s.last_seen.isoformat(),
            "is_current": s.id == current_session_id,
        })

    return jsonify({"sessions": result})


@app.route("/sessions/revoke", methods=["POST"])
@login_required
def revoke_session():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    if not isinstance(session_id, int) or isinstance(session_id, bool):
        return jsonify({"ok": False, "error": "session_id is required."})

    sess = db.session.get(UserSession, session_id)
    if not sess or sess.user_id != g.user.id:
        return jsonify({"ok": False, "error": "Session not found."})

    if not _revoke_session_records([sess]):
        return jsonify({
            "ok": False,
            "error": "Session termination could not be persisted.",
        }), 503
    return jsonify({"ok": True, "message": "Session terminated."})


@app.route("/sessions/revoke-all", methods=["POST"])
@login_required
def revoke_all_sessions():
    query = UserSession.query.filter_by(user_id=g.user.id, is_active=True)
    current_session_id = g.get("_auth_session_id")
    if current_session_id:
        query = query.filter(UserSession.id != current_session_id)

    sessions_to_revoke = query.all()
    count = len(sessions_to_revoke)
    if not _revoke_session_records(sessions_to_revoke):
        return jsonify({
            "ok": False,
            "error": "Sessions could not be terminated.",
        }), 503

    return jsonify({"ok": True, "message": f"{count} session(s) terminated."})


# ───────────────────── Plan ─────────────────────

@app.route("/plan/upgrade", methods=["POST"])
@login_required
def plan_upgrade():
    if not g.user.is_admin:
        return jsonify({"ok": False, "error": "You need to make a payment to upgrade your plan."}), 403

    plan = request.json.get("plan", "")
    if plan not in ("basic", "premium"):
        return jsonify({"ok": False, "error": "Invalid plan."})

    user = g.user
    if user.plan == plan:
        return jsonify({"ok": False, "error": "You are already on this plan."})

    _activate_plan(user, plan)
    db.session.commit()
    return jsonify({"ok": True, "plan": plan, "message": f"Switched to {plan.title()} plan!"})


@app.route("/plan/request", methods=["POST"])
@login_required
def plan_request():
    return jsonify({
        "ok": False,
        "error": "Manual payment requests are no longer supported. Use checkout.",
    }), 410


# ───────────────────── Shopier ─────────────────────

@app.route("/plan/checkout", methods=["POST"])
@login_required
def plan_checkout():
    data = request.get_json(silent=True) or {}
    plan = data.get("plan")
    if plan not in ("basic", "premium"):
        return jsonify({"ok": False, "error": "Invalid plan."})

    user = g.user
    if user.plan == plan:
        return jsonify({"ok": False, "error": "You are already on this plan."})
    if _PLAN_RANK.get(user.plan, 0) > _PLAN_RANK[plan]:
        return jsonify({
            "ok": False,
            "error": "A paid plan cannot be downgraded through checkout.",
        }), 409

    pending_verification = Payment.query.filter_by(
        user_id=user.id,
        status="verification_pending",
    ).first()
    if pending_verification:
        return jsonify({
            "ok": False,
            "error": "A payment is already being verified. Please wait.",
            "payment_id": pending_verification.id,
        }), 409

    # Ürün ID'leri Config'ten (SHOPIER_*_PRODUCT_ID) gelir; URL burada türetilir
    # ki ID değişikliği tek yerden yönetilsin (ISSUES.md #12).
    shopier_links = {
        "basic": f"https://www.shopier.com/hourboostcomtr/{Config.SHOPIER_BASIC_PRODUCT_ID}",
        "premium": f"https://www.shopier.com/hourboostcomtr/{Config.SHOPIER_PREMIUM_PRODUCT_ID}",
    }

    # Ödemeyi kullanıcıya güvenli eşlemek için benzersiz kodlu checkout intent'i.
    # Bu kayıt ödeme yapıldığı anlamına gelmez ve admin onay kuyruğunda gösterilmez.
    # Tek aktif checkout kurali: ayni plandaki intent'i yeniden kullan, digerlerini
    # iptal et. Iptal edilen veya tamamlanan token tekrar plan aktive edemez.
    checkout_intents = (
        Payment.query
        .filter_by(user_id=user.id, status="checkout_started")
        .order_by(Payment.created_at.desc())
        .all()
    )
    payment = None
    cutoff = _checkout_cutoff()
    for p in checkout_intents:
        is_fresh = p.created_at is not None and p.created_at >= cutoff
        if payment is None and is_fresh and p.plan == plan and p.match_token:
            payment = p          # bu plandaki en güncel checkout kodunu koru
        else:
            p.status = "cancelled"   # diğer planlar + fazlalık duplikeler
    if payment is None:
        token = _generate_match_token()
        payment = Payment(
            user_id=user.id,
            owner_user_id_snapshot=user.id,
            owner_username_snapshot=user.username,
            amount=Config.PLANS[plan]["price"],
            plan=plan,
            status="checkout_started",
            match_token=token,
        )
        db.session.add(payment)
    else:
        token = payment.match_token
        payment.owner_user_id_snapshot = user.id
        payment.owner_username_snapshot = user.username
        payment.owner_detached_at = None
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        active = Payment.query.filter_by(
            user_id=user.id,
            status="checkout_started",
        ).first()
        if active and active.plan == plan and active.match_token:
            payment = active
            token = active.match_token
        else:
            return jsonify({
                "ok": False,
                "error": "Another checkout is already active. Please retry.",
            }), 409

    logger.info(
        "Checkout baslatildi: user_id=%s payment_id=%s plan=%s token_fp=%s",
        user.id,
        payment.id,
        plan,
        token_fingerprint(token),
    )
    return jsonify({
        "ok": True,
        "payment_id": payment.id,
        "shopier_url": shopier_links[plan],
        "match_token": token,
        "note": f"Order note code: {token}",
    })


@app.route("/payment/check/<int:payment_id>")
@login_required
def payment_check(payment_id):
    payment = db.session.get(Payment, payment_id)
    if not payment or payment.user_id != g.user.id:
        return jsonify({"ok": False})
    return jsonify({"ok": True, "status": payment.status, "plan": payment.plan})


@app.route("/shopier/webhook", methods=["POST"])
@limiter.exempt
@csrf.exempt
def shopier_webhook():
    if not Config.SHOPIER_API_VERIFY_ENABLED:
        logger.error("shopier.webhook.disabled")
        return jsonify({"error": "Payment verification unavailable"}), 503
    if not Config.SHOPIER_VERIFICATION_WORKER_ENABLED:
        logger.error("shopier.webhook.worker_disabled")
        return jsonify({"error": "Payment verification unavailable"}), 503
    if not Config.SHOPIER_WEBHOOK_SECRET:
        logger.error("shopier.webhook.missing_secret")
        return jsonify({"error": "Payment verification unavailable"}), 503
    if not Config.SHOPIER_PAT:
        logger.error("shopier.webhook.missing_pat")
        return jsonify({"error": "Payment verification unavailable"}), 503
    if not Config.SHOPIER_ACCOUNT_ID or not Config.SHOPIER_WEBHOOK_ID:
        logger.error("shopier.webhook.missing_identity_config")
        return jsonify({"error": "Payment verification unavailable"}), 503

    if request.content_length and request.content_length > SHOPIER_WEBHOOK_MAX_BYTES:
        return jsonify({"error": "Payload too large"}), 413

    raw_body = request.get_data(cache=True, as_text=False)
    if len(raw_body) > SHOPIER_WEBHOOK_MAX_BYTES:
        return jsonify({"error": "Payload too large"}), 413
    signature = request.headers.get("Shopier-Signature", "")

    if not shopier_lib.verify_webhook(raw_body, signature, Config.SHOPIER_WEBHOOK_SECRET):
        logger.warning("shopier.webhook.invalid_signature")
        return jsonify({"error": "Invalid signature"}), 401

    event_type = request.headers.get("Shopier-Event", "").strip()
    webhook_id = request.headers.get("Shopier-Webhook-Id", "").strip()
    account_id = request.headers.get("Shopier-Account-Id", "").strip()
    timestamp_raw = request.headers.get("Shopier-Timestamp", "").strip()

    if not event_type or not re.fullmatch(r"[a-z][a-zA-Z0-9_.-]{0,99}", event_type):
        return jsonify({"error": "Invalid event"}), 400
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", webhook_id):
        return jsonify({"error": "Invalid webhook id"}), 400
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", account_id):
        return jsonify({"error": "Invalid account id"}), 400
    try:
        shopier_timestamp = int(timestamp_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid timestamp"}), 400
    if shopier_timestamp <= 0 or shopier_timestamp > int(time.time()) + 300:
        return jsonify({"error": "Invalid timestamp"}), 400

    if not hmac.compare_digest(account_id, str(Config.SHOPIER_ACCOUNT_ID)):
        logger.warning("shopier.webhook.account_mismatch")
        return jsonify({"error": "Account mismatch"}), 403
    if not hmac.compare_digest(webhook_id, str(Config.SHOPIER_WEBHOOK_ID)):
        logger.warning("shopier.webhook.subscription_mismatch")
        return jsonify({"error": "Webhook mismatch"}), 403

    if event_type != "order.created":
        logger.info("shopier.webhook.ignored event=%s", event_type)
        return jsonify({"ok": True, "ignored": True}), 200

    try:
        data = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return jsonify({"error": "Invalid JSON"}), 400
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid data"}), 400

    shopier_txn = str(data.get("id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", shopier_txn):
        return jsonify({"error": "Invalid transaction id"}), 400

    existing = Payment.query.filter_by(transaction_id=shopier_txn).first()
    if existing:
        logger.info(
            "shopier.webhook.duplicate order_id=%s payment_id=%s",
            shopier_txn,
            existing.id,
        )
        return jsonify({"ok": True, "duplicate": True}), 200

    received_at = datetime.utcnow()
    body_sha256 = hashlib.sha256(raw_body).hexdigest()
    _user, matched_payment = resolve_payment_from_note(
        data.get("note"), received_at
    )
    metadata = {
        "status": "verification_pending",
        "transaction_id": shopier_txn,
        "shopier_webhook_id": webhook_id,
        "shopier_event": event_type,
        "shopier_account_id": account_id,
        "shopier_timestamp": shopier_timestamp,
        "webhook_body_sha256": body_sha256,
        "webhook_received_at": received_at,
        "verification_attempts": 0,
        "verification_error": None,
        "verification_last_http_status": None,
        "next_verification_at": received_at,
        "verification_lock_until": None,
    }

    payment_id = None
    try:
        if matched_payment:
            result = db.session.execute(
                update(Payment)
                .where(
                    Payment.id == matched_payment.id,
                    Payment.status == "checkout_started",
                    Payment.transaction_id.is_(None),
                )
                .values(**metadata)
            )
            if result.rowcount == 1:
                payment_id = matched_payment.id
            else:
                db.session.rollback()

        if payment_id is None:
            placeholder = Payment(user_id=None, amount=None, plan=None, **metadata)
            db.session.add(placeholder)
            db.session.flush()
            payment_id = placeholder.id

        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        duplicate = Payment.query.filter_by(transaction_id=shopier_txn).first()
        if duplicate:
            logger.info(
                "shopier.webhook.duplicate order_id=%s payment_id=%s",
                shopier_txn,
                duplicate.id,
            )
            return jsonify({"ok": True, "duplicate": True}), 200
        logger.exception("shopier.webhook.persistence_conflict order_id=%s", shopier_txn)
        return jsonify({"error": "Persistence failure"}), 500
    except Exception:
        db.session.rollback()
        logger.exception("shopier.webhook.persistence_failed order_id=%s", shopier_txn)
        return jsonify({"error": "Persistence failure"}), 500

    _payment_verification_wakeup.set()
    logger.info(
        "shopier.verification.pending payment_id=%s order_id=%s webhook_id=%s",
        payment_id,
        shopier_txn,
        webhook_id,
    )
    return jsonify({
        "ok": True,
        "status": "verification_pending",
    }), 200


# ───────────────────── Steam Hesaplar ─────────────────────

@app.route("/accounts")
@login_required
def get_accounts():
    accounts = SteamAccount.query.filter_by(user_id=g.user.id).all()
    result = []
    for acct in accounts:
        mgr = boost_service.get_or_create(acct.id, acct.steam_username)
        s = mgr.summary()
        s["app_ids"] = acct.app_ids()
        result.append(s)
    return jsonify({"accounts": result})


@app.route("/accounts/login", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def account_login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid request body."}), 400
    username = sanitize(data.get("username", ""), 100)
    password = data.get("password", "")
    if password == "_use_saved_":
        password = ""
    code = sanitize(data.get("code", ""), 10)
    code_type = data.get("code_type", "email")
    acct_id = data.get("acct_id")
    if acct_id is not None and (
        not isinstance(acct_id, str)
        or not re.fullmatch(r"[0-9a-f]{16}", acct_id)
    ):
        return jsonify({"ok": False, "error": "Invalid account id."}), 400
    use_token = data.get("use_token", False)
    use_credentials = data.get("use_credentials", False)

    user = g.user
    limits = user.plan_limits()

    if not acct_id:
        if not username:
            return jsonify({"ok": False, "error": "Username is required."})
        if not user.is_verified:
            return jsonify({
                "ok": False,
                "error": "Please verify your email address before adding a Steam account.",
                "need_verify": True,
            })
        current = SteamAccount.query.filter_by(user_id=user.id).count()
        if current >= limits["max_accounts"]:
            return jsonify({
                "ok": False,
                "error": f"Your plan supports a maximum of {limits['max_accounts']} accounts.",
                "upgrade": True,
            })
        existing_acct = SteamAccount.query.filter_by(user_id=user.id, steam_username=username).first()
        if existing_acct:
            acct_id = existing_acct.id
        else:
            acct_id = secrets.token_hex(8)
            new_acct = SteamAccount(id=acct_id, user_id=user.id, steam_username=username)
            db.session.add(new_acct)
            db.session.commit()

    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db:
        # Account IDs are generated by the server. A caller-selected missing ID
        # must never create a DB row or choose a filesystem storage namespace.
        return jsonify({"ok": False, "error": "Account not found."}), 404

    if acct_db.user_id != user.id:
        return jsonify({"ok": False, "error": "Unauthorized."})
    if username and username.casefold() != acct_db.steam_username.casefold():
        return jsonify({
            "ok": False,
            "error": "A connected Steam account username cannot be changed.",
        }), 409

    mgr = boost_service.get_or_create(acct_id, acct_db.steam_username)

    if use_credentials and mgr.has_credentials():
        creds = mgr.load_credentials()
        if creds:
            result = mgr._login_with_credentials(creds["password"], code=code or None, code_type=code_type or "2fa")
            if result == EResult.OK:
                try:
                    acct_db.steam_id = str(mgr.client.steam_id)
                except Exception:
                    pass
                db.session.commit()
                with mgr.state_lock:
                    mgr.app_ids = acct_db.app_ids()
                    mgr.persona_state = acct_db.persona_state
                return jsonify({"ok": True, "acct_id": acct_id})
            elif result == EResult.AccountLogonDenied:
                return jsonify({"ok": False, "need_code": True, "code_type": "email", "msg": "Email Guard code required."})
            elif result in (EResult.AccountLoginDeniedNeedTwoFactor, EResult.TwoFactorCodeMismatch):
                return jsonify({"ok": False, "need_code": True, "code_type": "2fa", "msg": "Invalid or expired 2FA code."})
            elif result == EResult.InvalidLoginAuthCode:
                return jsonify({"ok": False, "need_code": True, "code_type": code_type or "email", "msg": "Invalid code, please try again."})
            else:
                return jsonify({"ok": False, "error": str(result)})

    if use_token or (not password and mgr.has_credentials()):
        result = mgr.login()
        if result == EResult.OK:
            try:
                acct_db.steam_id = str(mgr.client.steam_id)
            except Exception:
                pass
            db.session.commit()
            with mgr.state_lock:
                mgr.app_ids = acct_db.app_ids()
                mgr.persona_state = acct_db.persona_state
            return jsonify({"ok": True, "acct_id": acct_id, "method": "token"})
        elif result == EResult.AccountLogonDenied:
            return jsonify({"ok": False, "need_code": True, "code_type": "email", "acct_id": acct_id, "msg": "Email Guard code required."})
        elif result in (EResult.AccountLoginDeniedNeedTwoFactor, EResult.TwoFactorCodeMismatch):
            return jsonify({"ok": False, "need_2fa": True, "acct_id": acct_id, "msg": "2FA code required."})
        elif not password:
            return jsonify({"ok": False, "error": "Credentials invalid, please login with password.", "token_expired": True})

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password are required."})

    result = mgr.login(password, code=code or None, code_type=code_type)

    if result == EResult.AccountLogonDenied:
        return jsonify({"ok": False, "need_code": True, "code_type": "email", "msg": "Email Guard code required."})
    if result == EResult.AccountLoginDeniedNeedTwoFactor:
        return jsonify({"ok": False, "need_code": True, "code_type": "2fa", "msg": "Authenticator code required."})
    if result == EResult.InvalidLoginAuthCode:
        return jsonify({"ok": False, "need_code": True, "msg": "Invalid code, please try again."})
    if result != EResult.OK:
        return jsonify({"ok": False, "error": str(result)})

    try:
        acct_db.steam_id = str(mgr.client.steam_id)
    except Exception:
        pass
    db.session.commit()
    with mgr.state_lock:
        mgr.app_ids = acct_db.app_ids()
        mgr.persona_state = acct_db.persona_state
    return jsonify({"ok": True, "acct_id": acct_id, "has_token": mgr.has_token()})


@app.route("/accounts/remove", methods=["POST"])
@login_required
def remove_account():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid request body."}), 400
    acct_id = data.get("acct_id")
    if (
        not isinstance(acct_id, str)
        or not re.fullmatch(r"[0-9a-f]{16}", acct_id)
    ):
        return jsonify({"ok": False, "error": "Invalid account id."}), 400

    user_id = g.user.id
    # Non-admin requests already hold this RLock through login_required. Taking
    # it here also serializes an admin's own Steam mutations.
    with _user_operation_lock(user_id):
        db.session.expire_all()
        acct_db = (
            SteamAccount.query.filter_by(id=acct_id, user_id=user_id)
            .with_for_update()
            .first()
        )
        if acct_db is None:
            return jsonify({"ok": False, "error": "Account not found."}), 404

        steam_username = acct_db.steam_username
        app_ids = acct_db.app_ids()
        manager = boost_service.get(acct_id)
        manager_snapshot = manager.boost_snapshot() if manager else None
        boost_started_at = (
            manager_snapshot.get("start_time")
            if manager_snapshot and manager_snapshot.get("boosting")
            else None
        )
        remove_legacy_machine_auth = not db.session.query(SteamAccount.id).filter(
            SteamAccount.id != acct_id,
            db.func.lower(SteamAccount.steam_username)
            == steam_username.lower(),
        ).first()

        quarantined = quarantine_saved_credentials(
            acct_id,
            steam_username,
            include_legacy_machine_auth=remove_legacy_machine_auth,
        )
        if quarantined is None:
            logger.error(
                "steam_account.delete_credential_quarantine_failed "
                "user_id=%s account_id=%s",
                user_id,
                acct_id,
            )
            return jsonify({
                "ok": False,
                "error": "Stored Steam credentials could not be removed.",
            }), 503

        try:
            stopped_at = datetime.utcnow()
            if boost_started_at is not None:
                elapsed = max(0, int(time.time() - boost_started_at))
                if elapsed > 0:
                    db.session.add(BoostLog(
                        account_id=None,
                        user_id=user_id,
                        started_at=datetime.utcfromtimestamp(boost_started_at),
                        stopped_at=stopped_at,
                        duration_seconds=elapsed,
                        games_count=len(app_ids),
                        app_ids_json=json.dumps(app_ids),
                    ))

            # Keep historical usage, but sever the foreign key before deleting
            # the operational account. This prevents new BoostLog FK debt.
            BoostLog.query.filter_by(account_id=acct_id).update(
                {BoostLog.account_id: None},
                synchronize_session=False,
            )
            db.session.delete(acct_db)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            restore_quarantined_credentials(quarantined)
            logger.warning(
                "steam_account.delete_integrity_conflict user_id=%s account_id=%s",
                user_id,
                acct_id,
            )
            return jsonify({
                "ok": False,
                "error": "The account changed during deletion. Please retry.",
            }), 409
        except SQLAlchemyError:
            db.session.rollback()
            restore_quarantined_credentials(quarantined)
            logger.exception(
                "steam_account.delete_database_error user_id=%s account_id=%s",
                user_id,
                acct_id,
            )
            return jsonify({
                "ok": False,
                "error": "Deletion could not be completed. Please try again.",
            }), 503
        except Exception:
            db.session.rollback()
            restore_quarantined_credentials(quarantined)
            logger.exception(
                "steam_account.delete_internal_error user_id=%s account_id=%s",
                user_id,
                acct_id,
            )
            return jsonify({
                "ok": False,
                "error": "Deletion could not be completed. Please try again.",
            }), 503

        # The DB commit is durable. Make every runtime callback inert before
        # timer cancellation or blocking Node IPC can yield to another greenlet.
        cleanup_ok = True
        detached_manager = None
        try:
            detached_manager = boost_service.detach(acct_id)
        except Exception:
            cleanup_ok = False
            logger.exception(
                "steam_account.delete_manager_detach_failed "
                "user_id=%s account_id=%s",
                user_id,
                acct_id,
            )
            fallback_manager = boost_service.get(acct_id)
            if fallback_manager:
                try:
                    fallback_manager.mark_removed()
                except Exception:
                    logger.critical(
                        "steam_account.delete_manager_disable_failed "
                        "user_id=%s account_id=%s",
                        user_id,
                        acct_id,
                        exc_info=True,
                    )

        try:
            _clear_timers(acct_id)
        except Exception:
            cleanup_ok = False
            logger.exception(
                "steam_account.delete_timer_cleanup_failed "
                "user_id=%s account_id=%s",
                user_id,
                acct_id,
            )

        try:
            if detached_manager:
                removed = detached_manager.remove_completely(
                    include_legacy_machine_auth=remove_legacy_machine_auth
                )
            else:
                removed = boost_service.remove(
                    acct_id,
                    steam_username,
                    include_legacy_machine_auth=remove_legacy_machine_auth,
                )
            if not removed:
                cleanup_ok = False
        except Exception:
            cleanup_ok = False
            logger.exception(
                "steam_account.delete_runtime_cleanup_failed "
                "user_id=%s account_id=%s",
                user_id,
                acct_id,
            )

        if not purge_quarantined_credentials(quarantined):
            cleanup_ok = False
        if not cleanup_ok:
            logger.critical(
                "steam_account.delete_post_commit_cleanup_incomplete "
                "user_id=%s account_id=%s",
                user_id,
                acct_id,
            )
        logger.info(
            "steam_account.deleted user_id=%s account_id=%s final_segment=%s",
            user_id,
            acct_id,
            bool(boost_started_at),
        )
        return jsonify({"ok": True, "cleanup_warning": not cleanup_ok})


# ───────────────────── Oyun Listesi ─────────────────────

@app.route("/apps/add", methods=["POST"])
@login_required
def add_app():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid request body."}), 400
    acct_id = data.get("acct_id")
    if (
        not isinstance(acct_id, str)
        or not re.fullmatch(r"[0-9a-f]{16}", acct_id)
    ):
        return jsonify({"ok": False, "error": "Invalid account id."}), 400

    try:
        app_id = int(data.get("id"))
    except (ValueError, TypeError):
        return jsonify({
            "ok": False,
            "error": "Please enter a valid AppID.",
        }), 400
    if not 1 <= app_id <= 0xFFFFFFFF:
        return jsonify({
            "ok": False,
            "error": "Please enter a valid AppID.",
        }), 400

    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False, "error": "Account not found."}), 404

    manager = boost_service.get(acct_id)
    lock = manager.state_lock if manager is not None else nullcontext()
    with lock:
        db.session.expire_all()
        acct_db = db.session.get(SteamAccount, acct_id)
        if not acct_db or acct_db.user_id != g.user.id:
            return jsonify({"ok": False, "error": "Account not found."}), 404
        if acct_db.is_boosting or (
            manager is not None and manager.boost_snapshot().get("boosting")
        ):
            return jsonify({
                "ok": False,
                "error": "Stop boosting before changing the game list.",
            }), 409

        limits = g.user.plan_limits()
        if len(acct_db.games) >= limits["max_games"]:
            return jsonify({
                "ok": False,
                "error": (
                    f"Your plan supports {limits['max_games']} games per account."
                ),
                "upgrade": True,
            })

        exists = BoostGame.query.filter_by(
            account_id=acct_id,
            app_id=app_id,
        ).first()
        if not exists:
            db.session.add(BoostGame(account_id=acct_id, app_id=app_id))
            db.session.commit()

        app_ids = acct_db.app_ids()
        if manager is not None:
            manager.app_ids = list(app_ids)
        return jsonify({"app_ids": app_ids})


@app.route("/apps/remove", methods=["POST"])
@login_required
def remove_app():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid request body."}), 400
    acct_id = data.get("acct_id")
    if (
        not isinstance(acct_id, str)
        or not re.fullmatch(r"[0-9a-f]{16}", acct_id)
    ):
        return jsonify({"ok": False, "error": "Invalid account id."}), 400

    try:
        app_id = int(data.get("id"))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Invalid AppID."}), 400
    if not 1 <= app_id <= 0xFFFFFFFF:
        return jsonify({"ok": False, "error": "Invalid AppID."}), 400

    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False, "error": "Account not found."}), 404

    manager = boost_service.get(acct_id)
    lock = manager.state_lock if manager is not None else nullcontext()
    with lock:
        db.session.expire_all()
        acct_db = db.session.get(SteamAccount, acct_id)
        if not acct_db or acct_db.user_id != g.user.id:
            return jsonify({"ok": False, "error": "Account not found."}), 404
        if acct_db.is_boosting or (
            manager is not None and manager.boost_snapshot().get("boosting")
        ):
            return jsonify({
                "ok": False,
                "error": "Stop boosting before changing the game list.",
            }), 409

        game = BoostGame.query.filter_by(
            account_id=acct_id,
            app_id=app_id,
        ).first()
        if game:
            db.session.delete(game)
            db.session.commit()

        app_ids = acct_db.app_ids()
        if manager is not None:
            manager.app_ids = list(app_ids)
        return jsonify({"app_ids": app_ids})

# ───────────────────── Durum & Boost ─────────────────────

@app.route("/status/set", methods=["POST"])
@login_required
def set_status():
    acct_id = request.json.get("acct_id")
    state = request.json.get("state", 1)
    if state not in (1, 3, 7):
        return jsonify({"ok": False, "error": "Invalid status."})

    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False})

    acct_db.persona_state = state
    db.session.commit()

    mgr = boost_service.get(acct_id)
    if mgr:
        mgr.set_persona(state)
    return jsonify({"ok": True, "state": state})


def _stop_boost_session_and_persist(
    acct_id,
    user_id,
    manager,
    *,
    expected_session_id=None,
    expected_generation=None,
):
    """Stop exactly one runtime session and durably finalize its open segment."""
    snapshot = manager.boost_snapshot()
    if expected_session_id is not None or expected_generation is not None:
        if not _same_boost_session(
            snapshot,
            session_id=expected_session_id,
            generation=expected_generation,
        ):
            return {"stopped": False, "stale": True, "persisted": True}

    if not snapshot.get("boosting"):
        persisted = _persist_stopped_boost_state(
            acct_id,
            user_id,
            started_epoch=None,
            stopped_epoch=time.time(),
            duration_seconds=0,
            app_ids=snapshot.get("app_ids") or [],
        )
        return {"stopped": False, "stale": False, "persisted": persisted}

    elapsed = manager.stop_boost(
        expected_session_id=expected_session_id,
        expected_generation=expected_generation,
    )
    stopped_epoch = time.time()
    persisted = _persist_stopped_boost_state(
        acct_id,
        user_id,
        started_epoch=snapshot.get("start_time"),
        stopped_epoch=stopped_epoch,
        duration_seconds=elapsed,
        app_ids=snapshot.get("app_ids") or [],
    )
    return {
        "stopped": True,
        "stale": False,
        "persisted": persisted,
        "elapsed": elapsed,
        "session_id": snapshot.get("session_id"),
        "generation": snapshot.get("generation"),
    }


def _run_boost_stop_timer(acct_id, user_id, session_id, generation, reason):
    current = gevent.getcurrent()
    try:
        with app.app_context():
            owner_id = db.session.query(SteamAccount.user_id).filter_by(
                id=acct_id
            ).scalar()
            if owner_id != user_id:
                return
            with _user_operation_lock(user_id):
                db.session.expire_all()
                acct = db.session.get(SteamAccount, acct_id)
                if acct is None or acct.user_id != user_id:
                    return
                manager = boost_service.get(acct_id)
                if manager is None:
                    _persist_stopped_boost_state(
                        acct_id,
                        user_id,
                        started_epoch=None,
                        stopped_epoch=time.time(),
                        duration_seconds=0,
                        app_ids=acct.app_ids(),
                    )
                    return
                db.session.rollback()
                with manager.state_lock:
                    result = _stop_boost_session_and_persist(
                        acct_id,
                        user_id,
                        manager,
                        expected_session_id=session_id,
                        expected_generation=generation,
                    )
                if result.get("stale"):
                    logger.info(
                        "[acct:%s] Eski boost timer'i yeni session'a dokunmadan atlandi",
                        acct_id,
                    )
                elif not result.get("persisted"):
                    logger.critical(
                        "[acct:%s] Timer runtime'i durdurdu fakat DB uzlasmadi",
                        acct_id,
                    )
                else:
                    logger.info(
                        "[acct:%s] Boost timer tamamlandi: %s",
                        acct_id,
                        reason,
                    )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.exception("[acct:%s] Boost timer finalization hatasi", acct_id)
    finally:
        _discard_timer(acct_id, current)


def _schedule_boost_stop_timer(
    acct_id,
    user_id,
    session_id,
    generation,
    delay_seconds,
    reason,
):
    timer = gevent.spawn_later(
        max(0.0, float(delay_seconds)),
        _run_boost_stop_timer,
        acct_id,
        user_id,
        session_id,
        generation,
        reason,
    )
    try:
        _add_timer(acct_id, timer)
    except Exception:
        timer.kill()
        raise
    return timer


@app.route("/boost/toggle", methods=["POST"])
@login_required
def toggle_boost():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid request body."}), 400
    acct_id = data.get("acct_id")
    if (
        not isinstance(acct_id, str)
        or not re.fullmatch(r"[0-9a-f]{16}", acct_id)
    ):
        return jsonify({"ok": False, "error": "Invalid account id."}), 400

    timer_hours = data.get("timer_hours", 0)
    try:
        timer_hours = float(timer_hours) if timer_hours else 0.0
    except (ValueError, TypeError):
        timer_hours = 0.0
    if not math.isfinite(timer_hours) or timer_hours <= 0:
        timer_hours = 0.0
    else:
        timer_hours = max(0.5, min(24.0, timer_hours))

    user_id = g.user.id
    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != user_id:
        return jsonify({"ok": False, "error": "Account not found."}), 404

    manager = boost_service.get(acct_id)
    if not manager:
        return jsonify({"ok": False, "error": "Please connect to Steam first."})

    with manager.state_lock:
        db.session.expire_all()
        acct_db = db.session.get(SteamAccount, acct_id)
        if acct_db is None or acct_db.user_id != user_id:
            return jsonify({"ok": False, "error": "Account not found."}), 404

        current = manager.boost_snapshot()
        if current.get("boosting"):
            # Close the read transaction before yielding to Node IPC.
            db.session.rollback()
            _clear_timers(acct_id)
            result = _stop_boost_session_and_persist(
                acct_id,
                user_id,
                manager,
                expected_session_id=current.get("session_id"),
                expected_generation=current.get("generation"),
            )
            if not result.get("persisted"):
                return jsonify({
                    "ok": False,
                    "boosting": False,
                    "error": (
                        "Boost stopped, but its status could not be saved. "
                        "Please retry."
                    ),
                }), 503
            return jsonify({
                "ok": True,
                "boosting": False,
                "steam_connected": manager.logged_in,
            })

        if not current.get("logged_in"):
            return jsonify({
                "ok": False,
                "error": "Please connect to Steam first.",
            })

        ids = acct_db.app_ids()
        if not ids:
            return jsonify({"ok": False, "error": "Game list is empty."})

        limits = g.user.plan_limits()
        stop_candidates = []

        daily_hours = limits.get("daily_hours")
        if daily_hours is not None:
            from sqlalchemy import func as sqlfunc
            today_start = datetime.utcnow().replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            used_seconds = (
                db.session.query(sqlfunc.sum(BoostLog.duration_seconds))
                .filter(
                    BoostLog.user_id == user_id,
                    BoostLog.started_at >= today_start,
                )
                .scalar() or 0
            )
            used_seconds += _get_active_seconds(user_id, today_start)
            remaining_daily = daily_hours * 3600 - used_seconds
            if remaining_daily <= 0:
                return jsonify({
                    "ok": False,
                    "error": (
                        f"You have reached your daily {daily_hours}-hour limit."
                    ),
                    "upgrade": True,
                })
            stop_candidates.append((remaining_daily, "daily_limit"))

        total_hours = limits.get("total_hours")
        if total_hours is not None:
            from sqlalchemy import func as sqlfunc2
            plan_start = (
                g.user.plan_activated_at
                if g.user.plan_activated_at
                else datetime.utcnow() - timedelta(days=365)
            )
            used_total = (
                db.session.query(sqlfunc2.sum(BoostLog.duration_seconds))
                .filter(
                    BoostLog.user_id == user_id,
                    BoostLog.started_at >= plan_start,
                )
                .scalar() or 0
            )
            used_total += _get_active_seconds(user_id, plan_start)
            remaining_total = total_hours * 3600 - used_total
            if remaining_total <= 0:
                return jsonify({
                    "ok": False,
                    "error": (
                        f"You have used all {total_hours} hours in your plan."
                    ),
                    "upgrade": True,
                })
            stop_candidates.append((remaining_total, "total_limit"))

        if timer_hours > 0:
            stop_candidates.append((timer_hours * 3600, "user_timer"))

        # No timer may exist until every quota check has passed.
        persona_state = acct_db.persona_state
        # All values needed by Steam are frozen. Do not hold a DB transaction
        # across the yielding Node request.
        db.session.rollback()
        _clear_timers(acct_id)
        try:
            started = manager.start_boost(ids, persona_state)
        except Exception as exc:
            logger.error("[acct:%s] start_boost hatasi: %s", acct_id, exc)
            _persist_stopped_boost_state(
                acct_id,
                user_id,
                started_epoch=None,
                stopped_epoch=time.time(),
                duration_seconds=0,
                app_ids=ids,
            )
            return jsonify({
                "ok": False,
                "error": "Steam connection lost. Please reconnect.",
            })

        acct_db = db.session.get(SteamAccount, acct_id)
        if acct_db is None or acct_db.user_id != user_id:
            compensation = _stop_boost_session_and_persist(
                acct_id,
                user_id,
                manager,
                expected_session_id=started.get("session_id"),
                expected_generation=started.get("generation"),
            )
            _clear_timers(acct_id)
            if not compensation.get("persisted"):
                logger.critical(
                    "[acct:%s] Start sirasinda hesap kayboldu ve DB uzlasmadi",
                    acct_id,
                )
            return jsonify({
                "ok": False,
                "error": "Account changed while boost was starting.",
            }), 409

        stop_after = (
            min(stop_candidates, key=lambda item: item[0])
            if stop_candidates
            else None
        )
        deadline_epoch = time.time() + stop_after[0] if stop_after else None
        acct_db.is_boosting = True
        acct_db.target_stop_time = (
            datetime.utcfromtimestamp(deadline_epoch) if deadline_epoch else None
        )
        try:
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            logger.error(
                "[acct:%s] Start DB commit hatasi; Steam boost geri aliniyor: %s",
                acct_id,
                exc,
            )
            compensation = _stop_boost_session_and_persist(
                acct_id,
                user_id,
                manager,
                expected_session_id=started.get("session_id"),
                expected_generation=started.get("generation"),
            )
            _clear_timers(acct_id)
            if not compensation.get("persisted"):
                logger.critical(
                    "[acct:%s] Start compensation sonrasi DB uzlasmadi",
                    acct_id,
                )
            return jsonify({
                "ok": False,
                "error": "Boost could not be saved and was stopped. Please retry.",
            }), 503

        if stop_after:
            try:
                _schedule_boost_stop_timer(
                    acct_id,
                    user_id,
                    started.get("session_id"),
                    started.get("generation"),
                    max(0.0, deadline_epoch - time.time()),
                    stop_after[1],
                )
            except Exception:
                logger.exception(
                    "[acct:%s] Timer olusturulamadi; boost fail-closed durduruluyor",
                    acct_id,
                )
                compensation = _stop_boost_session_and_persist(
                    acct_id,
                    user_id,
                    manager,
                    expected_session_id=started.get("session_id"),
                    expected_generation=started.get("generation"),
                )
                _clear_timers(acct_id)
                if not compensation.get("persisted"):
                    logger.critical(
                        "[acct:%s] Timer compensation sonrasi DB uzlasmadi",
                        acct_id,
                    )
                return jsonify({
                    "ok": False,
                    "error": (
                        "Boost timer could not be created; boost was stopped."
                    ),
                }), 503

        return jsonify({
            "ok": True,
            "boosting": True,
            "start_time": started.get("start_time"),
            "timer_hours": timer_hours if timer_hours > 0 else None,
        })

# ───────────────────── İstatistikler ─────────────────────

@app.route("/stats/my")
@login_required
def my_stats():
    from sqlalchemy import func
    user = g.user
    total_seconds = (
        db.session.query(func.sum(BoostLog.duration_seconds))
        .filter_by(user_id=user.id).scalar() or 0
    )
    total_sessions = BoostLog.query.filter_by(user_id=user.id).count()
    week_ago = datetime.utcnow() - timedelta(days=7)
    daily = (
        db.session.query(
            func.date(BoostLog.started_at).label("day"),
            func.sum(BoostLog.duration_seconds).label("total"),
        )
        .filter(BoostLog.user_id == user.id, BoostLog.started_at > week_ago)
        .group_by(func.date(BoostLog.started_at))
        .all()
    )
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_seconds = (
        db.session.query(func.sum(BoostLog.duration_seconds))
        .filter(BoostLog.user_id == user.id, BoostLog.started_at >= today_start)
        .scalar() or 0
    )
    today_seconds += _get_active_seconds(user.id, today_start)
    
    plan_start = user.plan_activated_at if user.plan_activated_at else datetime.utcnow() - timedelta(days=365)
    plan_used_seconds = (
        db.session.query(func.sum(BoostLog.duration_seconds))
        .filter(BoostLog.user_id == user.id, BoostLog.started_at >= plan_start)
        .scalar() or 0
    )
    plan_used_seconds += _get_active_seconds(user.id, plan_start)
    
    # Active seconds since all time
    active_all_time = _get_active_seconds(user.id)
    total_seconds += active_all_time
    
    return jsonify({
        "total_hours": round(total_seconds / 3600, 1),
        "today_hours": round(today_seconds / 3600, 1),
        "plan_used_hours": round(plan_used_seconds / 3600, 1),
        "total_sessions": total_sessions,
        "accounts_count": SteamAccount.query.filter_by(user_id=user.id).count(),
        "plan": user.plan,
        "member_since": user.created_at.isoformat(),
        "daily": [{"day": str(d.day), "hours": round(d.total / 3600, 1)} for d in daily],
    })


@app.route("/stats/games")
@login_required
def game_stats():
    user = g.user
    logs = BoostLog.query.filter_by(user_id=user.id).all()
    game_hours: dict = {}

    for log in logs:
        if not log.app_ids_json or log.duration_seconds <= 0:
            continue
        try:
            app_ids = json.loads(log.app_ids_json)
        except Exception:
            continue
        if not app_ids:
            continue
        per_game = log.duration_seconds / len(app_ids)
        for aid in app_ids:
            aid_str = str(aid)
            game_hours[aid_str] = game_hours.get(aid_str, 0) + per_game

    sorted_games = sorted(game_hours.items(), key=lambda x: x[1], reverse=True)
    result = [
        {"app_id": int(k), "hours": round(v / 3600, 1)}
        for k, v in sorted_games[:20]
    ]
    return jsonify({"games": result, "total_tracked": len(game_hours)})


@app.route("/stats/detailed")
@login_required
def stats_detailed():
    from sqlalchemy import func
    user = g.user
    now_utc = datetime.utcnow()

    # ── Son 7 gün: günlük saat dağılımı ──
    week_ago = now_utc - timedelta(days=7)
    daily_rows = (
        db.session.query(
            func.date(BoostLog.started_at).label("day"),
            func.sum(BoostLog.duration_seconds).label("total"),
        )
        .filter(BoostLog.user_id == user.id, BoostLog.started_at > week_ago)
        .group_by(func.date(BoostLog.started_at))
        .all()
    )
    day_names_tr = ["Pzt", "Sal", "Çar", "Per", "Cum", "Cmt", "Paz"]
    day_names_en = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    weekly_hours = []
    for i in range(6, -1, -1):
        d = (now_utc - timedelta(days=i)).date()
        found = 0
        for row in daily_rows:
            rd = row.day if isinstance(row.day, type(d)) else datetime.strptime(str(row.day), "%Y-%m-%d").date()
            if rd == d:
                found = row.total or 0
                break
        wd = d.weekday()
        weekly_hours.append({
            "day_tr": day_names_tr[wd],
            "day_en": day_names_en[wd],
            "date": str(d),
            "hours": round(found / 3600, 1),
        })

    # ── Son 4 hafta: haftalık toplam ──
    four_weeks_ago = now_utc - timedelta(days=28)
    monthly_rows = (
        db.session.query(
            func.date(BoostLog.started_at).label("day"),
            func.sum(BoostLog.duration_seconds).label("total"),
        )
        .filter(BoostLog.user_id == user.id, BoostLog.started_at > four_weeks_ago)
        .group_by(func.date(BoostLog.started_at))
        .all()
    )
    monthly_hours = []
    for w in range(3, -1, -1):
        w_start = (now_utc - timedelta(days=(w + 1) * 7)).date()
        w_end = (now_utc - timedelta(days=w * 7)).date()
        total = 0
        for row in monthly_rows:
            rd = row.day if isinstance(row.day, type(w_start)) else datetime.strptime(str(row.day), "%Y-%m-%d").date()
            if w_start <= rd < w_end:
                total += (row.total or 0)
        monthly_hours.append({
            "week_tr": f"Hafta {4 - w}",
            "week_en": f"Week {4 - w}",
            "hours": round(total / 3600, 1),
        })

    # ── En çok boost edilen 10 oyun ──
    logs = BoostLog.query.filter_by(user_id=user.id).all()
    game_secs: dict = {}
    for log in logs:
        if not log.app_ids_json or log.duration_seconds <= 0:
            continue
        try:
            aids = json.loads(log.app_ids_json)
        except Exception:
            continue
        if not aids:
            continue
        per = log.duration_seconds / len(aids)
        for aid in aids:
            game_secs[str(aid)] = game_secs.get(str(aid), 0) + per

    sorted_games = sorted(game_secs.items(), key=lambda x: x[1], reverse=True)[:10]
    max_secs = sorted_games[0][1] if sorted_games else 1
    top_games = [
        {"app_id": int(k), "hours": round(v / 3600, 1), "pct": round((v / max_secs) * 100)}
        for k, v in sorted_games
    ]

    # ── Özet istatistikler ──
    total_seconds = (
        db.session.query(func.sum(BoostLog.duration_seconds))
        .filter_by(user_id=user.id).scalar() or 0
    )
    total_seconds += _get_active_seconds(user.id)

    total_sessions = BoostLog.query.filter_by(user_id=user.id).count()

    today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    today_seconds = (
        db.session.query(func.sum(BoostLog.duration_seconds))
        .filter(BoostLog.user_id == user.id, BoostLog.started_at >= today_start)
        .scalar() or 0
    )
    today_seconds += _get_active_seconds(user.id, today_start)

    active_days = (
        db.session.query(func.count(func.distinct(func.date(BoostLog.started_at))))
        .filter_by(user_id=user.id).scalar() or 0
    )

    avg_daily = (total_seconds / max(active_days, 1)) if active_days else 0

    longest_log = (
        db.session.query(func.max(BoostLog.duration_seconds))
        .filter_by(user_id=user.id).scalar() or 0
    )

    return jsonify({
        "weekly_hours": weekly_hours,
        "monthly_hours": monthly_hours,
        "top_games": top_games,
        "summary": {
            "total_hours": round(total_seconds / 3600, 1),
            "today_hours": round(today_seconds / 3600, 1),
            "total_sessions": total_sessions,
            "avg_daily_hours": round(avg_daily / 3600, 1),
            "longest_session_hours": round(longest_log / 3600, 1),
            "active_days": active_days,
        },
    })


# ───────────────────── Duyurular ─────────────────────

@app.route("/announcements")
def get_announcements():
    anns = (
        Announcement.query.filter_by(is_active=True)
        .order_by(Announcement.created_at.desc())
        .limit(5).all()
    )
    return jsonify([{
        "id": a.id, "title": a.title, "content": a.content,
        "type": a.type, "date": a.created_at.isoformat(),
    } for a in anns])


# ───────────────────── Bilgi ─────────────────────

@app.route("/server_status")
def server_status():
    uptime = int(time.time() - SERVER_START)
    stats = boost_service.stats()
    total_users = User.query.count()
    return jsonify({"uptime": uptime, "active_boosts": stats["active_boosts"], "total_users": total_users})


@app.route("/steam_profile")
@login_required
def steam_profile():
    acct_id = request.args.get("acct_id")
    acct_db = db.session.get(SteamAccount, acct_id) if acct_id else None
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False})

    mgr = boost_service.get(acct_id)
    manager_snapshot = mgr.boost_snapshot() if mgr else None
    if not manager_snapshot or not manager_snapshot.get("logged_in"):
        return jsonify({"ok": False})

    steamid = str(
        acct_db.steam_id or getattr(mgr.client, "steam_id", "") or ""
    ).strip()
    if not re.fullmatch(r"\d{17}", steamid):
        logger.warning("Steam profili için geçersiz SteamID: account=%s", acct_id)
        return jsonify({"ok": False})

    # Worker SteamID'yi biliyor fakat eski kayıtta DB alanı boşsa kalıcılaştır.
    if acct_db.steam_id != steamid:
        acct_db.steam_id = steamid
        db.session.commit()

    profile = _get_steam_profile(steamid)
    return jsonify({
        "ok": True,
        "name": profile.get("name") or acct_db.steam_username or steamid,
        "avatar": profile.get("avatar") or "",
        "profile_url": f"https://steamcommunity.com/profiles/{steamid}",
        "steamid": steamid,
    })


@app.route("/game_search")
@limiter.limit("30 per minute")
def game_search():
    term = request.args.get("q", "").strip()
    if not term:
        return jsonify([])
    try:
        url = (
            "https://store.steampowered.com/api/storesearch/"
            f"?term={urllib.parse.quote(term)}&l=english&cc=US"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with safe_urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        return jsonify([
            {"id": i["id"], "name": i["name"], "tiny_image": i.get("tiny_image", "")}
            for i in data.get("items", [])[:8]
        ])
    except Exception:
        return jsonify([])


@app.route("/game_info", methods=["POST"])
@limiter.limit("30 per minute")
def game_info():
    app_ids = request.json.get("app_ids", [])
    results = {}
    now = time.time()
    for aid in app_ids[:15]:
        with game_cache_lock:
            cached = game_cache.get(aid)
        if cached and (now - cached["ts"]) < Config.STEAM_CACHE_TTL:
            results[str(aid)] = cached["data"]
            continue
        try:
            url = f"https://store.steampowered.com/api/appdetails?appids={aid}&l=english"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with safe_urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode())
            if data.get(str(aid), {}).get("success"):
                d = data[str(aid)]["data"]
                info = {
                    "name": d.get("name", "Unknown"),
                    "header_image": d.get("header_image", ""),
                    "genres": [gg["description"] for gg in d.get("genres", [])[:2]],
                }
            else:
                info = {"name": f"AppID {aid}", "header_image": "", "genres": []}

            with game_cache_lock:
                if len(game_cache) >= GAME_CACHE_MAX:
                    oldest = sorted(game_cache.items(), key=lambda x: x[1]["ts"])[:50]
                    for k, _ in oldest:
                        game_cache.pop(k, None)
                game_cache[aid] = {"data": info, "ts": now}
            results[str(aid)] = info
        except Exception:
            results[str(aid)] = {"name": f"AppID {aid}", "header_image": "", "genres": []}

    return jsonify(results)


# ───────────────────── Admin ─────────────────────

@app.route("/admin")
@login_required
def admin_page():
    if not getattr(g.user, 'is_admin', False):
        return flask_redirect("/")
    return render_template("admin.html")


@app.route("/admin/stats")
@login_required
def admin_stats():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    return jsonify({
        "total_users": User.query.count(),
        "new_users_week": User.query.filter(User.created_at > week_ago).count(),
        "new_users_month": User.query.filter(User.created_at > month_ago).count(),
        "paying_users": User.query.filter(User.plan != "free").count(),
        "plan_breakdown": {
            "free": User.query.filter_by(plan="free").count(),
            "basic": User.query.filter_by(plan="basic").count(),
            "premium": User.query.filter_by(plan="premium").count(),
        },
        "active_boosts": boost_service.active_boosts(),
        "total_accounts": SteamAccount.query.count(),
        "revenue_month": (
            db.session.query(db.func.sum(Payment.amount))
            .filter(Payment.status == "completed", Payment.created_at > month_ago)
            .scalar() or 0
        ),
        "revenue_total": (
            db.session.query(db.func.sum(Payment.amount))
            .filter(Payment.status == "completed").scalar() or 0
        ),
        "pending_payments": Payment.query.filter(Payment.status.in_((
            "pending", "verification_pending", "verification_failed", "unmatched"
        ))).count(),
        "verifications_pending": Payment.query.filter_by(
            status="verification_pending"
        ).count(),
        "manual_review_payments": Payment.query.filter(Payment.status.in_((
            "verification_failed", "unmatched"
        ))).count(),
    })


@app.route("/admin/maintenance")
@login_required
def admin_maintenance_status():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({"enabled": is_maintenance_mode()})


@app.route("/admin/maintenance/toggle", methods=["POST"])
@login_required
def admin_maintenance_toggle():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    new_state = not is_maintenance_mode()
    set_maintenance_mode(new_state)
    logger.info(
        "Bakim modu %s (admin=%s)",
        "ACILDI" if new_state else "KAPANDI",
        g.user.username,
    )
    return jsonify({"ok": True, "enabled": new_state})


@app.route("/admin/users")
@login_required
def admin_users():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "").strip()
    query = User.query
    if search:
        # LIKE özel karakterlerini (\ % _) escape et; aksi halde "%"/"_" wildcard
        # olarak çalışıp tüm tabloyu tarayabilir.
        safe = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{safe}%"
        query = query.filter(db.or_(
            User.username.ilike(like, escape="\\"),
            User.email.ilike(like, escape="\\"),
        ))
    users = query.order_by(User.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return jsonify({
        "users": [{
            "id": u.id, "username": u.username, "email": u.email, "plan": u.plan,
            "plan_expires": u.plan_expires.isoformat() if u.plan_expires else None,
            "accounts": SteamAccount.query.filter_by(user_id=u.id).count(),
            "created_at": u.created_at.isoformat(),
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "is_admin": u.is_admin,
        } for u in users.items],
        "total": users.total, "pages": users.pages, "current_page": page,
    })


@app.route("/admin/users/update", methods=["POST"])
@login_required
def admin_update_user():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    target_id = data.get("user_id")
    user = db.session.get(User, target_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found."})

    if "plan" in data:
        if data["plan"] not in ("free", "basic", "premium"):
            return jsonify({"ok": False, "error": "Invalid plan."})
        if data["plan"] != "free":
            _activate_plan(user, data["plan"])
        else:
            user.plan = "free"
            user.plan_expires = None
            user.plan_activated_at = None

    if "is_admin" in data:
        if str(target_id) == str(g.user.id) and not data["is_admin"]:
            return jsonify({"ok": False, "error": "You cannot remove your own admin privileges."})
        user.is_admin = data["is_admin"]

    db.session.commit()
    return jsonify({"ok": True})


@app.route("/admin/payments")
@login_required
def admin_payments():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    payments = (
        Payment.query
        .filter(
            Payment.status != "cancelled",
            Payment.status != "checkout_started",
            Payment.admin_hidden.is_(False),
        )
        .order_by(
            db.case(
                (Payment.status == "verification_failed", 0),
                (Payment.status == "unmatched", 1),
                (Payment.status == "verification_pending", 2),
                else_=3,
            ),
            Payment.created_at.desc(),
        )
        .limit(50).all()
    )

    user_ids = {p.user_id for p in payments if p.user_id}
    user_map = {}
    if user_ids:
        rows = User.query.filter(User.id.in_(user_ids)).all()
        user_map = {u.id: u.username for u in rows}

    def _owner_label(payment):
        active_username = user_map.get(payment.user_id)
        if active_username:
            return active_username
        if payment.owner_detached_at:
            snapshot = payment.owner_username_snapshot
            if snapshot:
                return f"{snapshot} (deleted)"
            if payment.owner_user_id_snapshot:
                return f"deleted account #{payment.owner_user_id_snapshot}"
            return "deleted account"
        return "unmatched"

    return jsonify({"payments": [{
        "id": p.id, "user_id": p.user_id,
        "username": _owner_label(p),
        "owner_deleted": bool(p.user_id is None and p.owner_detached_at),
        "amount": p.amount, "plan": p.plan, "status": p.status,
        "transaction_id": p.transaction_id or "",
        "verification_error": p.verification_error or "",
        "verification_attempts": p.verification_attempts or 0,
        "verified_at": p.verified_at.isoformat() if p.verified_at else None,
        "can_match": bool(
            p.status == "unmatched"
            and p.verified_at
            and p.transaction_id
            and p.verified_amount_minor is not None
            and p.plan in ("basic", "premium")
        ),
        "can_retry": bool(p.status == "verification_failed" and p.transaction_id),
        "created_at": p.created_at.isoformat() if p.created_at else None,
    } for p in payments]})


@app.route("/admin/payments/approve", methods=["POST"])
@login_required
def admin_approve_payment():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    payment_id = data.get("payment_id")
    payment = db.session.get(Payment, payment_id)
    if not payment:
        return jsonify({"ok": False, "error": "Payment not found."}), 404
    if (
        payment.admin_hidden
        or payment.status != "unmatched"
        or not payment.verified_at
        or not payment.transaction_id
        or payment.verified_amount_minor is None
        or payment.plan not in ("basic", "premium")
    ):
        return jsonify({
            "ok": False,
            "error": "This order has not passed canonical payment verification.",
        }), 409

    username = str(data.get("username") or "").strip()
    reason = str(data.get("reason") or "").strip()
    if not username:
        return jsonify({"ok": False, "error": "Username is required."}), 400
    if len(reason) < 5 or len(reason) > 255:
        return jsonify({
            "ok": False,
            "error": "An audit reason between 5 and 255 characters is required.",
        }), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"ok": False, "error": f"'{username}' not found."}), 404

    user_identity = (
        user.id,
        user.username,
        user.created_at,
        user.password_hash,
    )
    user_id = user.id
    payment_id = payment.id
    with _user_operation_lock(user_id):
        # The account may have been deleted while this admin request waited for
        # its operation lock. Re-read both rows and fail closed.
        db.session.expire_all()
        user = db.session.get(User, user_id)
        payment = db.session.get(Payment, payment_id)
        if not user or (
            user.id,
            user.username,
            user.created_at,
            user.password_hash,
        ) != user_identity:
            return jsonify({
                "ok": False,
                "error": "The target user changed before matching.",
            }), 409
        if (
            not payment
            or payment.admin_hidden
            or payment.status != "unmatched"
            or not payment.verified_at
            or not payment.transaction_id
            or payment.verified_amount_minor is None
            or payment.plan not in ("basic", "premium")
        ):
            return jsonify({
                "ok": False,
                "error": "The payment changed before matching. Please reload.",
            }), 409

        old_status = payment.status
        payment.user_id = user.id
        payment.owner_user_id_snapshot = user.id
        payment.owner_username_snapshot = user.username
        payment.owner_detached_at = None
        payment.status = "completed"
        payment.verification_error = "manual_match"
        plan_changed = _activate_paid_plan(user, payment.plan)
        db.session.add(PaymentAuditLog(
            payment_id=payment.id,
            actor_user_id=g.user.id,
            actor_username=g.user.username,
            action="manual_match",
            from_status=old_status,
            to_status="completed",
            reason=reason,
        ))
        db.session.commit()
    logger.warning(
        "shopier.payment.manual_match payment_id=%s order_id=%s admin_id=%s",
        payment.id,
        payment.transaction_id,
        g.user.id,
    )
    return jsonify({
        "ok": True,
        "message": f"{user.username} matched to verified {payment.plan} order.",
        "plan_changed": plan_changed,
    })


@app.route("/admin/payments/retry", methods=["POST"])
@login_required
def admin_retry_payment():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "ok": False,
            "error": "A JSON object is required.",
        }), 400

    payment_id = data.get("payment_id")
    if type(payment_id) is not int or payment_id <= 0:
        return jsonify({
            "ok": False,
            "error": "A valid payment_id is required.",
        }), 400

    reason_value = data.get("reason")
    if not isinstance(reason_value, str):
        return jsonify({
            "ok": False,
            "error": "An audit reason between 5 and 255 characters is required.",
        }), 400
    reason = reason_value.strip()
    if len(reason) < 5 or len(reason) > 255:
        return jsonify({
            "ok": False,
            "error": "An audit reason between 5 and 255 characters is required.",
        }), 400

    payment = db.session.get(Payment, payment_id)
    if not payment:
        return jsonify({"ok": False, "error": "Payment not found."}), 404
    if (
        payment.admin_hidden
        or payment.status != "verification_failed"
        or not payment.transaction_id
    ):
        return jsonify({
            "ok": False,
            "error": "This payment cannot be retried.",
        }), 409

    if payment.user_id is not None and db.session.get(User, payment.user_id) is None:
        logger.warning(
            "shopier.verification.retry_blocked_missing_user "
            "payment_id=%s admin_id=%s",
            payment.id,
            g.user.id,
        )
        return jsonify({
            "ok": False,
            "error": "This payment no longer has a valid owner.",
        }), 409

    conflicting_payment = None
    if payment.user_id is not None:
        conflicting_payment = (
            db.session.query(Payment.id)
            .filter(
                Payment.user_id == payment.user_id,
                Payment.id != payment.id,
                Payment.status.in_(("checkout_started", "verification_pending")),
            )
            .order_by(Payment.id.desc())
            .first()
        )
    if conflicting_payment:
        logger.warning(
            "shopier.verification.retry_blocked_open_payment "
            "payment_id=%s conflicting_payment_id=%s admin_id=%s",
            payment.id,
            conflicting_payment[0],
            g.user.id,
        )
        return jsonify({
            "ok": False,
            "error": "Another checkout or payment verification is already open for this user.",
            "conflict": "open_payment_exists",
        }), 409

    old_status = payment.status
    transaction_id = payment.transaction_id
    owner_condition = (
        Payment.user_id.is_(None)
        if payment.user_id is None
        else Payment.user_id == payment.user_id
    )
    try:
        result = db.session.execute(
            update(Payment)
            .where(
                Payment.id == payment_id,
                Payment.status == "verification_failed",
                Payment.admin_hidden.is_(False),
                Payment.transaction_id == transaction_id,
                owner_condition,
            )
            .values(
                status="verification_pending",
                verification_attempts=0,
                verification_error=None,
                verification_last_http_status=None,
                next_verification_at=datetime.utcnow(),
                verification_lock_until=None,
            )
        )
        if result.rowcount != 1:
            db.session.rollback()
            logger.warning(
                "shopier.verification.retry_stale payment_id=%s admin_id=%s",
                payment_id,
                g.user.id,
            )
            return jsonify({
                "ok": False,
                "error": "The payment changed before the retry could be queued.",
                "conflict": "payment_state_changed",
            }), 409

        db.session.add(PaymentAuditLog(
            payment_id=payment_id,
            actor_user_id=g.user.id,
            actor_username=g.user.username,
            action="verification_retry",
            from_status=old_status,
            to_status="verification_pending",
            reason=reason,
        ))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        logger.warning(
            "shopier.verification.retry_integrity_conflict "
            "payment_id=%s admin_id=%s",
            payment_id,
            g.user.id,
        )
        return jsonify({
            "ok": False,
            "error": "Another checkout or payment verification became active. Retry was not queued.",
            "conflict": "open_payment_exists",
        }), 409
    except SQLAlchemyError:
        db.session.rollback()
        logger.exception(
            "shopier.verification.retry_database_error "
            "payment_id=%s admin_id=%s",
            payment_id,
            g.user.id,
        )
        return jsonify({
            "ok": False,
            "error": "Payment retry could not be queued. Please try again.",
        }), 503

    _payment_verification_wakeup.set()
    return jsonify({"ok": True, "message": "Payment verification queued."})


@app.route("/admin/payments/hide", methods=["POST"])
@login_required
def admin_hide_payment():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    payment = db.session.get(Payment, data.get("payment_id"))
    if not payment:
        return jsonify({"ok": False, "error": "Payment not found."}), 404

    payment.admin_hidden = True
    db.session.add(PaymentAuditLog(
        payment_id=payment.id,
        actor_user_id=g.user.id,
        actor_username=g.user.username,
        action="admin_hide",
        from_status=payment.status,
        to_status=payment.status,
        reason="Admin panel cleanup; payment record retained.",
    ))
    db.session.commit()
    logger.info(
        "Ödeme admin panelinden gizlendi: payment_id=%s admin=%s",
        payment.id,
        g.user.username,
    )
    return jsonify({"ok": True, "message": "Payment hidden from the admin panel."})


@app.route("/admin/users/delete", methods=["POST"])
@login_required
@target_user_operation_locked
def admin_delete_user():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "ok": False,
            "error": "A JSON object is required.",
        }), 400

    target_id = data.get("user_id")
    if type(target_id) is not int or target_id <= 0:
        return jsonify({
            "ok": False,
            "error": "A valid user_id is required.",
        }), 400

    if target_id == g.user.id:
        return jsonify({
            "ok": False,
            "error": "You cannot delete your own account.",
        }), 409

    target_user = (
        db.session.query(User)
        .filter(User.id == target_id)
        .with_for_update()
        .first()
    )
    if not target_user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if target_user.is_admin:
        return jsonify({
            "ok": False,
            "error": "Admin accounts cannot be deleted.",
        }), 409

    username = target_user.username
    payments = (
        Payment.query.filter_by(user_id=target_id)
        .with_for_update()
        .all()
    )
    known_statuses = {
        "pending",
        "checkout_started",
        "verification_pending",
        "verification_failed",
        "completed",
        "unmatched",
        "cancelled",
    }
    unsafe_payment = next((
        payment for payment in payments
        if (
            payment.status not in known_statuses
            or (
                payment.status in ("pending", "checkout_started")
                and payment.transaction_id is not None
            )
        )
    ), None)
    if unsafe_payment:
        logger.warning(
            "user.delete_blocked_payment_state target_id=%s payment_id=%s status=%s",
            target_id,
            unsafe_payment.id,
            unsafe_payment.status,
        )
        return jsonify({
            "ok": False,
            "error": "This account has a payment in an unsafe state. Resolve it before deletion.",
        }), 409

    steam_accounts = (
        SteamAccount.query.filter_by(user_id=target_id)
        .with_for_update()
        .all()
    )
    target_account_ids = [account.id for account in steam_accounts]
    remaining_steam_usernames = set()
    if target_account_ids:
        remaining_steam_usernames = {
            row[0]
            for row in db.session.query(
                db.func.lower(SteamAccount.steam_username)
            ).filter(
                ~SteamAccount.id.in_(target_account_ids)
            ).all()
        }
    remove_legacy_by_account = {
        account.id: account.steam_username.lower() not in remaining_steam_usernames
        for account in steam_accounts
    }
    credential_quarantines = []
    for account in steam_accounts:
        quarantined = quarantine_saved_credentials(
            account.id,
            account.steam_username,
            include_legacy_machine_auth=remove_legacy_by_account[account.id],
        )
        if quarantined is None:
            restore_quarantined_credentials(credential_quarantines)
            logger.error(
                "user.delete_credential_quarantine_failed target_id=%s account_id=%s",
                target_id,
                account.id,
            )
            return jsonify({
                "ok": False,
                "error": "Stored Steam credentials could not be removed.",
            }), 503
        credential_quarantines.extend(quarantined)

    deletion_committed = False
    try:
        detached_at = datetime.utcnow()
        for payment in payments:
            old_status = payment.status
            payment.owner_user_id_snapshot = target_id
            payment.owner_username_snapshot = username
            payment.owner_detached_at = detached_at
            payment.user_id = None
            if old_status in ("pending", "checkout_started"):
                payment.status = "cancelled"
                payment.match_token = None
                payment.verification_error = "owner_deleted_before_payment"
                payment.next_verification_at = None
                payment.verification_lock_until = None
            db.session.add(PaymentAuditLog(
                payment_id=payment.id,
                actor_user_id=g.user.id,
                actor_username=g.user.username,
                action="owner_detached_on_user_delete",
                from_status=old_status,
                to_status=payment.status,
                reason=(
                    f"Owner account deleted: user_id={target_id}; "
                    "financial record retained."
                ),
            ))

        BoostLog.query.filter_by(user_id=target_id).delete(synchronize_session=False)
        UserSession.query.filter_by(user_id=target_id).delete(synchronize_session=False)
        RevokedToken.query.filter_by(user_id=target_id).delete(synchronize_session=False)

        for account in steam_accounts:
            account_fresh = db.session.get(SteamAccount, account.id)
            if account_fresh:
                db.session.delete(account_fresh)

        db.session.delete(target_user)
        db.session.commit()
        deletion_committed = True
        _plan_expiry_cache.pop(target_id, None)

        # External side effects happen only after the financial/user database
        # transaction is durable. The pre-commit rename above means secrets are
        # already inactive, yet a DB rollback could still restore them exactly.
        cleanup_ok = True
        detached_managers = {}
        for account in steam_accounts:
            try:
                detached_managers[account.id] = boost_service.detach(account.id)
            except Exception:
                detached_managers[account.id] = None
                cleanup_ok = False
                logger.exception(
                    "user.delete_manager_detach_failed target_id=%s account_id=%s",
                    target_id,
                    account.id,
                )
        for account in steam_accounts:
            try:
                _clear_timers(account.id)
            except Exception:
                cleanup_ok = False
                logger.exception(
                    "user.delete_timer_cleanup_failed target_id=%s account_id=%s",
                    target_id,
                    account.id,
                )
        for account in steam_accounts:
            try:
                manager = detached_managers.get(account.id)
                if manager:
                    removed = manager.remove_completely(
                        include_legacy_machine_auth=(
                            remove_legacy_by_account[account.id]
                        )
                    )
                else:
                    removed = boost_service.remove(
                        account.id,
                        account.steam_username,
                        include_legacy_machine_auth=(
                            remove_legacy_by_account[account.id]
                        ),
                    )
                if not removed:
                    cleanup_ok = False
            except Exception:
                cleanup_ok = False
                logger.exception(
                    "user.delete_manager_cleanup_failed target_id=%s account_id=%s",
                    target_id,
                    account.id,
                )
        if not purge_quarantined_credentials(credential_quarantines):
            cleanup_ok = False
        if not cleanup_ok:
            logger.critical(
                "user.delete_post_commit_cleanup_incomplete target_id=%s",
                target_id,
            )
        logger.warning(
            "user.deleted admin_id=%s target_id=%s payments_retained=%s steam_accounts_removed=%s",
            g.user.id,
            target_id,
            len(payments),
            len(steam_accounts),
        )
        return jsonify({
            "ok": True,
            "message": f"{username} was deleted; financial records were retained.",
            "cleanup_warning": not cleanup_ok,
        })
    except IntegrityError:
        if deletion_committed:
            try:
                purge_quarantined_credentials(credential_quarantines)
            except Exception:
                logger.critical(
                    "user.delete_post_commit_quarantine_purge_failed target_id=%s",
                    target_id,
                    exc_info=True,
                )
            logger.critical(
                "user.delete_post_commit_integrity_error target_id=%s",
                target_id,
                exc_info=True,
            )
            return jsonify({
                "ok": True,
                "message": f"{username} was deleted; financial records were retained.",
                "cleanup_warning": True,
            })
        db.session.rollback()
        restore_quarantined_credentials(credential_quarantines)
        logger.warning("user.delete_integrity_conflict target_id=%s", target_id)
        return jsonify({
            "ok": False,
            "error": "The account changed during deletion. Please retry.",
        }), 409
    except SQLAlchemyError:
        if deletion_committed:
            try:
                purge_quarantined_credentials(credential_quarantines)
            except Exception:
                logger.critical(
                    "user.delete_post_commit_quarantine_purge_failed target_id=%s",
                    target_id,
                    exc_info=True,
                )
            logger.critical(
                "user.delete_post_commit_database_error target_id=%s",
                target_id,
                exc_info=True,
            )
            return jsonify({
                "ok": True,
                "message": f"{username} was deleted; financial records were retained.",
                "cleanup_warning": True,
            })
        db.session.rollback()
        restore_quarantined_credentials(credential_quarantines)
        logger.exception("user.delete_database_error target_id=%s", target_id)
        return jsonify({
            "ok": False,
            "error": "Deletion could not be completed. Please try again.",
        }), 503
    except Exception:
        if deletion_committed:
            try:
                purge_quarantined_credentials(credential_quarantines)
            except Exception:
                logger.critical(
                    "user.delete_post_commit_quarantine_purge_failed target_id=%s",
                    target_id,
                    exc_info=True,
                )
            logger.critical(
                "user.delete_post_commit_internal_error target_id=%s",
                target_id,
                exc_info=True,
            )
            return jsonify({
                "ok": True,
                "message": f"{username} was deleted; financial records were retained.",
                "cleanup_warning": True,
            })
        db.session.rollback()
        restore_quarantined_credentials(credential_quarantines)
        logger.exception("user.delete_internal_error target_id=%s", target_id)
        return jsonify({
            "ok": False,
            "error": "Deletion could not be completed. Please try again.",
        }), 503


@app.route("/admin/announcements/create", methods=["POST"])
@login_required
def create_announcement():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    ann = Announcement(
        title=sanitize(data.get("title", ""), 200),
        content=sanitize(data.get("content", ""), 1000),
        type=data.get("type", "info"),
    )
    db.session.add(ann)
    db.session.commit()
    return jsonify({"ok": True})


# ───────────────────── Steam OpenID ─────────────────────

STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"


def _build_steam_login_url(return_to: str) -> str:
    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": return_to,
        "openid.realm": Config.SITE_URL,
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }
    return STEAM_OPENID_URL + "?" + urllib.parse.urlencode(params)


def _verify_steam_callback(params: dict):
    check_params = dict(params)
    check_params["openid.mode"] = "check_authentication"
    try:
        data = urllib.parse.urlencode(check_params).encode("utf-8")
        req = urllib.request.Request(
            STEAM_OPENID_URL,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with safe_urlopen(req, timeout=10) as r:
            response = r.read().decode("utf-8")
        if "is_valid:true" not in response:
            return None
        claimed_id = params.get("openid.claimed_id", "")
        m = re.search(r"https://steamcommunity\.com/openid/id/(\d+)", claimed_id)
        if not m:
            return None
        return m.group(1)
    except Exception as e:
        logger.error("Steam OpenID dogrulama hatasi: %s", e)
        return None


def _get_steam_profile(steam_id: str) -> dict:
    steam_id = str(steam_id or "").strip()
    if not re.fullmatch(r"\d{17}", steam_id):
        return {}

    api_key = Config.STEAM_API_KEY
    if api_key:
        try:
            url = (
                "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
                f"?key={urllib.parse.quote(api_key)}&steamids={steam_id}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with safe_urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode("utf-8"))
            players = data.get("response", {}).get("players", [])
            if players:
                player = players[0]
                return {
                    "steam_id": steam_id,
                    "name": player.get("personaname", ""),
                    "avatar": player.get("avatarfull", ""),
                    "profile_url": player.get("profileurl", ""),
                }
        except Exception as e:
            logger.warning("Steam Web API profil isteği başarısız: %s", e)

    # API anahtarı yoksa veya Web API geçici olarak başarısızsa public XML
    # profili kullan. Bu fallback başarısız olsa bile caller hesap adını gösterir.
    try:
        url = f"https://steamcommunity.com/profiles/{steam_id}/?xml=1"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with safe_urlopen(req, timeout=5) as r:
            root = ET.fromstring(r.read().decode("utf-8"))
        return {
            "steam_id": steam_id,
            "name": (root.findtext("steamID") or "").strip(),
            "avatar": (root.findtext("avatarFull") or "").strip(),
            "profile_url": f"https://steamcommunity.com/profiles/{steam_id}",
        }
    except Exception as e:
        logger.warning("Steam Community profil isteği başarısız: %s", e)
        return {}


@app.route("/steam/login")
def steam_login():
    lang = request.args.get("lang", "tr")
    state = secrets.token_hex(16)
    session["steam_state"] = state
    return_to = f"{Config.SITE_URL}/steam/callback?lang={lang}&state={state}"
    redirect_url = _build_steam_login_url(return_to)
    return flask_redirect(redirect_url)


@app.route("/steam/callback")
def steam_callback():
    lang = request.args.get("lang", "tr")
    returned_state = request.args.get("state", "")
    expected_state = session.pop("steam_state", None)

    if not expected_state or returned_state != expected_state:
        logger.warning("Steam OpenID CSRF state uyumsuzlugu!")
        if lang == "en":
            return flask_redirect("/en/?error=steam_failed")
        return flask_redirect("/?error=steam_failed")

    params = dict(request.args)
    steam_id = _verify_steam_callback(params)

    if not steam_id:
        logger.warning("Steam OpenID dogrulama basarisiz")
        if lang == "en":
            return flask_redirect("/en/?error=steam_failed")
        return flask_redirect("/?error=steam_failed")

    profile = _get_steam_profile(steam_id)
    display_name = profile.get("name", "")
    avatar = profile.get("avatar", "")

    user = User.query.filter_by(steam_id=steam_id).first()

    if user:
        user.last_login = datetime.utcnow()
        user.steam_avatar = avatar
        user.steam_display_name = display_name
        db.session.commit()
    else:
        base_username = re.sub(r"[^a-zA-Z0-9_]", "", display_name)[:30] or f"steam_{steam_id[-6:]}"
        username = base_username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1

        fake_email = f"steam_{steam_id}@steamlogin.hourboost"

        user = User(
            username=username,
            email=fake_email,
            is_verified=True,
            steam_id=steam_id,
            steam_avatar=avatar,
            steam_display_name=display_name,
            lang=lang,
        )
        user.set_password(secrets.token_hex(32))
        db.session.add(user)
        db.session.commit()
        logger.info("Steam ile yeni kullanici olusturuldu: %s (steam_id=%s)", username, steam_id)

    token = generate_api_token(user.id)
    if _establish_authenticated_session(user.id, token) is None:
        logger.error(
            "Steam girisi dogrulandi ancak guvenli oturum olusturulamadi: user_id=%s",
            user.id,
        )
        if lang == "en":
            return flask_redirect("/en/?error=session_failed")
        return flask_redirect("/?error=session_failed")

    if lang == "en":
        return flask_redirect("/en/dashboard")
    return flask_redirect("/dashboard")


@app.route("/steam/unlink", methods=["POST"])
@login_required
def steam_unlink():
    user = g.user

    if user.email.endswith("@steamlogin.hourboost"):
        return jsonify({
            "ok": False,
            "error": "Steam ile kayıt oldunuz. Önce bir e-posta ve şifre belirleyin."
        })

    user.steam_id = None
    user.steam_avatar = None
    user.steam_display_name = None
    db.session.commit()
    return jsonify({"ok": True, "message": "Steam hesabı bağlantısı kaldırıldı."})


# ───────────────────── Başlat ─────────────────────

_start_payment_verification_worker()

if __name__ == "__main__":
    print("Hour Boost calisiyor -> http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
