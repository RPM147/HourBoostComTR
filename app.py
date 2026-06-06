from gevent import monkey; monkey.patch_all()

import os
import json
import time
import secrets
import logging
import urllib.request
import urllib.parse
import re
import bleach
import mailer
import jwt as pyjwt
import hmac
import hashlib
import ipaddress
from urllib.parse import urlparse
from functools import wraps

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
from flask_limiter.util import get_remote_address
from steam.enums import EResult
from flask_wtf.csrf import CSRFProtect

from config import Config
from models import db, User, SteamAccount, BoostGame, Payment, BoostLog, Announcement, UserSession, RevokedToken
from steam_manager import boost_service
import shopier as shopier_lib

from gevent.lock import RLock

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = Config.PERMANENT_SESSION_LIFETIME
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

csrf = CSRFProtect(app)
# Otomatik CSRF kontrolünü kapat — JWT Bearer istekleri muaf tutulacak.
app.config["WTF_CSRF_CHECK_DEFAULT"] = False

db.init_app(app)

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


limiter = Limiter(
    get_remote_address,
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

def _handle_fatal_disconnect(acct_id, elapsed):
    try:
        with app.app_context():
            acct = db.session.get(SteamAccount, acct_id)
            if acct:
                log = BoostLog(
                    account_id=acct_id,
                    user_id=acct.user_id,
                    started_at=datetime.utcnow() - timedelta(seconds=elapsed),
                    stopped_at=datetime.utcnow(),
                    duration_seconds=int(elapsed),
                    games_count=len(acct.app_ids()),
                    app_ids_json=json.dumps(acct.app_ids())
                )
                db.session.add(log)
                db.session.commit()
                logger.info("[%s] Fatal disconnect sonrasi %d saniye veritabanina yazildi", acct_id, int(elapsed))
    except Exception as e:
        logger.error("[%s] Fatal disconnect log yazma hatasi: %s", acct_id, e)

boost_service.fatal_disconnect_callback = _handle_fatal_disconnect

def _get_active_seconds(user_id, start_time_filter=None):
    active = 0
    now = time.time()
    accounts = SteamAccount.query.filter_by(user_id=user_id).all()
    for acct in accounts:
        mgr = boost_service.get(acct.id)
        if mgr and mgr.boosting and mgr.start_time:
            if start_time_filter:
                start_dt = datetime.utcfromtimestamp(mgr.start_time)
                if start_dt >= start_time_filter:
                    active += (now - mgr.start_time)
            else:
                active += (now - mgr.start_time)
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


def verify_api_token(token):
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

    # İmza ve süre geçerliyse revoke/blacklist kontrolü yap.
    jti = payload.get("jti")
    if jti:
        revoked = RevokedToken.query.filter_by(token_jti=jti).first()
        if revoked:
            # Kayıt hâlâ geçerliyse reddet; süresi gectiyse temizle.
            if revoked.expires_at > datetime.utcnow():
                logger.info("Token iptal edilmiş (kalıcı): jti=%s", jti)
                return None
            else:
                try:
                    db.session.delete(revoked)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    logger.error("Revoked token temizleme hatasi: %s", e)

    with _blacklist_lock:
        if token in _token_blacklist:
            return None

    user_id = payload.get("user_id")

    # Şifre değişimi / toplu oturum iptali sonrası eski token'ları reddet:
    # token'ın iat'ı kullanıcının tokens_valid_after'ından önceyse geçersizdir.
    iat = payload.get("iat")
    if user_id and iat:
        user = db.session.get(User, user_id)
        if user is not None and user.tokens_valid_after:
            try:
                iat_dt = datetime.utcfromtimestamp(int(iat))
            except (TypeError, ValueError, OSError):
                return None
            # Saniye granülaritesinde karşılaştır: değişimle aynı saniyede
            # üretilen yeni token yanlışlıkla reddedilmesin.
            if iat_dt < user.tokens_valid_after.replace(microsecond=0):
                return None

    return user_id


def blacklist_token(token):
    if token:
        try:
            payload = pyjwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})
            jti = payload.get("jti")
            exp_timestamp = payload.get("exp", time.time() + 3600)
            exp_datetime = datetime.utcfromtimestamp(exp_timestamp)

            if jti:
                revoked = RevokedToken(
                    token_jti=jti,
                    user_id=payload.get("user_id"),
                    expires_at=exp_datetime
                )
                db.session.add(revoked)
                db.session.commit()
                logger.info("Token kalıcı olarak blacklist'e eklendi: jti=%s", jti)
        except pyjwt.InvalidTokenError:
            logger.warning("Token blacklist için decode edilemedi")

        with _blacklist_lock:
            _token_blacklist.add(token)
        _cleanup_blacklist()


def _invalidate_all_user_tokens(user):
    """Kullanıcının tüm JWT token'larını ve aktif oturumlarını geçersiz kıl.
    tokens_valid_after güncellenir; çağıran taraf commit etmelidir."""
    user.tokens_valid_after = datetime.utcnow()
    try:
        UserSession.query.filter_by(user_id=user.id, is_active=True).update(
            {"is_active": False}, synchronize_session=False
        )
    except Exception as e:
        logger.error("Oturum toplu iptal hatasi: %s", e)


# ───────────────────── Brute Force Koruması ─────────────────────

_failed_logins: defaultdict = defaultdict(list)
_failed_logins_lock = RLock()
_LOCKOUT_MAX_ATTEMPTS = 5
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
        old_sessions = (
            UserSession.query
            .filter_by(user_id=user_id, is_active=True)
            .order_by(UserSession.created_at.asc())
            .all()
        )
        if len(old_sessions) >= 10:
            for s in old_sessions[:len(old_sessions) - 9]:
                s.is_active = False

        ip = _get_client_ip()
        ua = (request.headers.get("User-Agent", "") or "")[:256]

        sess = UserSession(
            user_id=user_id,
            token_hint=token[:16] if token else None,
            ip_address=ip,
            user_agent=ua,
        )
        db.session.add(sess)
        db.session.commit()
        logger.info("Oturum kaydı oluşturuldu: user_id=%s ip=%s", user_id, ip)
        return sess.id
    except Exception as e:
        logger.error("Oturum kaydı oluşturulamadı: %s", e)
        db.session.rollback()
        return None


def _deactivate_session_by_token(token: str):
    if not token:
        return
    hint = token[:16]
    try:
        sess = UserSession.query.filter_by(token_hint=hint, is_active=True).first()
        if sess:
            sess.is_active = False
            db.session.commit()
    except Exception as e:
        logger.error("Oturum kapatma hatasi: %s", e)


# ───────────────────── Dil Yardımcısı ─────────────────────

def _get_request_lang() -> str:
    if request.path.startswith("/en/") or request.path == "/en":
        return "en"
    lang = request.args.get("lang", "")
    if lang in ("en", "tr"):
        return lang
    return "tr"


# ───────────────────── Sunucu Başlangıcı ─────────────────────

def auto_reconnect_saved_accounts():
    import gevent as _gevent
    _gevent.sleep(3)
    with app.app_context():
        accounts = SteamAccount.query.all()
        logger.info("Otomatik reconnect baslatiliyor: %d hesap", len(accounts))
        
        def _bg_reconnect_single(acct):
            mgr = boost_service.get_or_create(acct.id, acct.steam_username)
            if mgr.has_credentials():
                try:
                    result = mgr.login()
                    if result == EResult.OK:
                        mgr.app_ids = acct.app_ids()
                        mgr.persona_state = acct.persona_state
                        if acct.is_boosting and mgr.app_ids:
                            mgr.start_boost(mgr.app_ids, mgr.persona_state)
                        logger.info("[%s] Otomatik reconnect basarili", acct.steam_username)
                        
                        # Eger onceden kalma bir target_stop_time varsa, timer'i canlandir
                        if acct.target_stop_time:
                            now = datetime.utcnow()
                            if acct.target_stop_time > now:
                                rem_sec = (acct.target_stop_time - now).total_seconds()
                                def _resume_timer(a_id=acct.id, u_id=acct.user_id, rem=rem_sec):
                                    _gevent.sleep(rem)
                                    m = boost_service.get(a_id)
                                    if m and m.boosting:
                                        bs = m.start_time
                                        el = m.stop_boost()
                                        if el > 0 and bs:
                                            with app.app_context():
                                                a2 = db.session.get(SteamAccount, a_id)
                                                if a2:
                                                    a2.target_stop_time = None
                                                    lg = BoostLog(
                                                        account_id=a_id, user_id=u_id,
                                                        started_at=datetime.utcfromtimestamp(bs),
                                                        stopped_at=datetime.utcnow(), duration_seconds=int(el),
                                                        games_count=len(a2.app_ids()), app_ids_json=json.dumps(a2.app_ids())
                                                    )
                                                    db.session.add(lg)
                                                    db.session.commit()
                                        logger.info("[%s] Reconnect sonrasi timer doldu", a_id)
                                _add_timer(acct.id, _gevent.spawn(_resume_timer))
                            else:
                                # Süre geçmiş, doğrudan kapat logla
                                logger.info("[%s] Reconnect sirasinda timer suresi coktan dolmus, kapatiliyor.", acct.steam_username)
                                bs = mgr.start_time or time.time()
                                mgr.stop_boost()
                                acct.target_stop_time = None
                                lg = BoostLog(
                                    account_id=acct.id, user_id=acct.user_id,
                                    started_at=datetime.utcfromtimestamp(bs),
                                    stopped_at=datetime.utcnow(), duration_seconds=1,
                                    games_count=len(acct.app_ids()), app_ids_json=json.dumps(acct.app_ids())
                                )
                                db.session.add(lg)
                                db.session.commit()
                    elif result in (
                        EResult.AccountLoginDeniedNeedTwoFactor,
                        EResult.TwoFactorCodeMismatch,
                    ):
                        logger.info("[%s] 2FA gerekiyor, manuel giris bekleniyor", acct.steam_username)
                    else:
                        logger.warning("[%s] Otomatik reconnect basarisiz: %s", acct.steam_username, result)
                except Exception as e:
                    logger.warning("[%s] Otomatik reconnect hatasi: %s", acct.steam_username, e)

        for acct in accounts:
            _gevent.spawn(_bg_reconnect_single, acct)


def _ensure_schema():
    """Hafif, idempotent şema güncellemesi (Flask-Migrate kurulana dek köprü).
    Mevcut DB'lerde eksik sütunları ekler; sütun zaten varsa no-op."""
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        cols = {c["name"] for c in inspector.get_columns("users")}
        if "tokens_valid_after" not in cols:
            col_type = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
            with db.engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN tokens_valid_after {col_type}"))
            logger.info("Şema güncellendi: users.tokens_valid_after eklendi")

        pcols = {c["name"] for c in inspector.get_columns("payments")}
        if "match_token" not in pcols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE payments ADD COLUMN match_token VARCHAR(32)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_payments_match_token ON payments (match_token)"))
            logger.info("Şema güncellendi: payments.match_token eklendi")
    except Exception as e:
        logger.error("Şema güncelleme hatası: %s", e)


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
        logger.error("Restart reconciliation hatasi: %s", e)


with app.app_context():
    db.create_all()
    _ensure_schema()
    _reconcile_boost_state_on_startup()

import gevent
# Restart davranışı (bkz. FIX.md Phase 5): auto_reconnect DEVRE DIŞI bırakıldı
# (kullanıcılara Steam giriş bildirimi gitmemesi için). Bunun yerine başlangıçta
# _reconcile_boost_state_on_startup() ile bayat boost durumu temizlenir.
# gevent.spawn(auto_reconnect_saved_accounts)

def _checkpoint_loop():
    while True:
        gevent.sleep(900)  # 15 dakika (900 saniye)
        with app.app_context():
            logger.info("Running background boost checkpoint (saving active durations)...")
            count = 0
            for acct_id, mgr in boost_service.all_managers():
                if mgr.boosting and mgr.start_time:
                    elapsed = time.time() - mgr.start_time
                    if elapsed > 60:
                        mgr.start_time = time.time()
                        acct_db = db.session.get(SteamAccount, acct_id)
                        if acct_db:
                            log = BoostLog(
                                account_id=acct_id,
                                user_id=acct_db.user_id,
                                started_at=datetime.utcfromtimestamp(time.time() - elapsed),
                                stopped_at=datetime.utcnow(),
                                duration_seconds=int(elapsed),
                                games_count=len(acct_db.app_ids()),
                                app_ids_json=json.dumps(acct_db.app_ids()),
                            )
                            db.session.add(log)
                            count += 1
            if count > 0:
                try:
                    db.session.commit()
                    logger.info("Checkpoint basarili: %d kayit eklendi.", count)
                except Exception as e:
                    db.session.rollback()
                    logger.error("Checkpoint commit hatasi: %s", e)

gevent.spawn(_checkpoint_loop)


# ───────────────────── Shutdown ─────────────────────

import atexit


@atexit.register
def shutdown_cleanup():
    with app.app_context():
        for acct_id, mgr in boost_service.all_managers():
            if mgr.boosting:
                boost_start = mgr.start_time
                if boost_start is None:
                    mgr.stop_boost()
                    continue
                elapsed = mgr.stop_boost()
                acct_db = db.session.get(SteamAccount, acct_id)
                if acct_db and elapsed > 0:
                    log = BoostLog(
                        account_id=acct_id,
                        user_id=acct_db.user_id,
                        started_at=datetime.utcfromtimestamp(boost_start),
                        stopped_at=datetime.utcnow(),
                        duration_seconds=int(elapsed),
                        games_count=len(acct_db.app_ids()),
                        app_ids_json=json.dumps(acct_db.app_ids()),
                    )
                    db.session.add(log)
        db.session.commit()

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

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        user_id = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            user_id = verify_api_token(token)
        if not user_id:
            user_id = session.get("user_id")
        if not user_id:
            if request.method != 'GET' or request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"ok": False, "error": "Not logged in."}), 401
            return flask_redirect("/")
        user = db.session.get(User, user_id)
        if not user:
            session.clear()
            return jsonify({"ok": False, "error": "User not found."}), 401
        g.user = user
        return f(*args, **kwargs)
    return wrapped


def sanitize(text, maxlen=100):
    if not text:
        return ""
    return bleach.clean(str(text).strip()[:maxlen])


def resolve_payment_from_note(note: str):
    """Webhook notundan ödeme sahibini GÜVENLİ biçimde çöz.

    Yalnızca açık eşleştirme kodları kabul edilir:
      - HB-xxxxxx  → /plan/checkout'ta üretilen benzersiz Payment.match_token
      - SB-<id>    → kullanıcı ID'si (geriye dönük uyumluluk)
    Serbest metinden kullanıcı-adı TAHMİNİ YAPILMAZ; bu, nota rastgele bir
    kelime (ör. "admin") yazıldığında yanlış hesaba plan tanımlanmasını önler.

    Dönüş: (user, payment_or_None)
    """
    if not note:
        return None, None
    note = note.strip()

    m = re.search(r"HB-([0-9A-Fa-f]{6})", note, re.IGNORECASE)
    if m:
        token = "HB-" + m.group(1).upper()
        payment = Payment.query.filter_by(match_token=token).first()
        if payment and payment.user_id:
            user = db.session.get(User, payment.user_id)
            if user:
                return user, payment

    m = re.search(r"SB-(\d+)", note, re.IGNORECASE)
    if m:
        try:
            user = db.session.get(User, int(m.group(1)))
            if user:
                return user, None
        except Exception:
            pass

    return None, None


# ───────────────────── Middleware ─────────────────────

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # NOT: script-src/style-src'de 'unsafe-inline' KALDI; mevcut arayüz baştan
    # sona inline onclick/onsubmit handler'ları ve inline style'lar üzerine kurulu.
    # Bunu nonce tabanlı CSP'ye geçirmek tüm template'lerdeki inline handler'ları
    # addEventListener'a taşımayı gerektirir (ayrı, büyük bir frontend işi).
    # Aşağıdaki ek direktifler ('unsafe-inline'ı bozmadan) güvenliği artırır:
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
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

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        if verify_api_token(token):
            # Geçerli JWT → CSRF kontrolünü atla
            return

    # JWT yoksa veya geçersizse standart CSRF doğrulaması yap
    csrf.protect()


@app.before_request
def check_plan_expiry():
    uid = session.get("user_id")
    if not uid:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            uid = verify_api_token(auth_header[7:])
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
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        hint = auth_header[7:][:16]
        try:
            UserSession.query.filter_by(token_hint=hint, is_active=True).update(
                {"last_seen": datetime.utcnow()}, synchronize_session=False
            )
            db.session.commit()
        except Exception:
            db.session.rollback()


# ───────────────────── Sayfalar (TR) ─────────────────────

@app.route("/")
def index():
    uid = session.get("user_id")
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
    uid = session.get("user_id")
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
    user_id = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        user_id = verify_api_token(auth_header[7:])
    if not user_id:
        user_id = session.get("user_id")
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
    if len(p) < 6 or not any(char.isdigit() for char in p) or not any(char.isalpha() for char in p):
        return jsonify({"ok": False, "error": "Password must be at least 6 characters and contain letters and numbers." if lang == "en" else "Sifre en az 6 karakter olmali ve hem harf hem rakam icermelidir."})
    if User.query.filter_by(username=u).first():
        return jsonify({"ok": False, "error": "This username is already taken." if lang == "en" else "Bu kullanici adi alinmis."})
    if User.query.filter_by(email=e).first():
        return jsonify({"ok": False, "error": "This email address is already in use." if lang == "en" else "Bu e-posta adresi alinmis."})

    verification_token = secrets.token_urlsafe(32)
    user = User(
        username=u,
        email=e,
        is_verified=False,
        verification_token=verification_token,
        verification_sent_at=datetime.utcnow(),
        lang=lang,
    )
    try:
        user.set_password(p)
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error("Kullanici kayit sirasinda veritabani hatasi: %s", e)
        return jsonify({"ok": False, "error": "This username or email is already taken or an error occurred." if lang == "en" else "Bu kullanici adi veya e-posta alinmis veya bir hata olustu."})

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
    mailer.send_welcome_email(user.email, user.username, lang=user_lang)

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
    if len(new_password) < 6 or not any(char.isdigit() for char in new_password) or not any(char.isalpha() for char in new_password):
        return jsonify({"ok": False, "error": "Password must be at least 6 characters and contain letters and numbers."})

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
    if len(new_password) < 6 or not any(char.isdigit() for char in new_password) or not any(char.isalpha() for char in new_password):
        return jsonify({"ok": False, "error": "New password must be at least 6 characters and contain letters and numbers."})

    user = g.user
    if not user.check_password(current_password):
        return jsonify({"ok": False, "error": "Current password is incorrect."})

    user.set_password(new_password)
    _invalidate_all_user_tokens(user)
    db.session.commit()

    # Diğer tüm oturumlar iptal edildi; mevcut cihazın oturumda kalması
    # için taze bir token üret ve döndür (frontend bunu saklamalı).
    new_token = generate_api_token(user.id)
    _create_session_record(user.id, new_token)
    session["user_id"] = user.id

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
    if len(new_password) < 6 or not any(c.isdigit() for c in new_password) or not any(c.isalpha() for c in new_password):
        return jsonify({"ok": False, "error": "Password must be at least 6 characters and contain letters and numbers."})

    user.set_password(new_password)
    db.session.commit()

    new_token = generate_api_token(user.id)
    _create_session_record(user.id, new_token)
    session["user_id"] = user.id
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
    if User.query.filter_by(email=new_email).first():
        return jsonify({"ok": False, "error": "This email address is already in use by another account."})

    if user.email_change_expires:
        remaining = (user.email_change_expires - datetime.utcnow()).total_seconds()
        if remaining > 0:
            return jsonify({"ok": False, "error": "Please wait."})

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
    user_key = f"user:{u}"

    if is_locked_out(ip_key):
        return jsonify({"ok": False, "error": "Too many failed attempts. Please wait 5 minutes."}), 429
    if is_locked_out(user_key):
        return jsonify({"ok": False, "error": "This account is temporarily locked. Please try again in 5 minutes."}), 429

    user = User.query.filter_by(username=u).first()
    if not user or not user.check_password(p):
        record_failed_login(ip_key)
        record_failed_login(user_key)
        return jsonify({"ok": False, "error": "Invalid username or password."})

    clear_failed_logins(ip_key)
    clear_failed_logins(user_key)

    user.last_login = db.func.now()
    db.session.commit()

    session.permanent = True
    session["user_id"] = user.id
    token = generate_api_token(user.id)

    _create_session_record(user.id, token)

    return jsonify({"ok": True, "is_admin": user.is_admin, "token": token})


@app.route("/site_logout", methods=["POST"])
def site_logout():
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

    # Not: Web'den çıkış boost'u DURDURMAZ; boost sunucu tarafında çalışmaya
    # devam eder. Boost yalnızca /boost/toggle veya hesap silme ile durdurulur.
    if token:
        blacklist_token(token)
        _deactivate_session_by_token(token)

    session.clear()
    return jsonify({"ok": True})


# ───────────────────── Oturum Yönetimi ─────────────────────

@app.route("/sessions")
@login_required
def list_sessions():
    sessions = (
        UserSession.query
        .filter_by(user_id=g.user.id, is_active=True)
        .order_by(UserSession.last_seen.desc())
        .all()
    )

    current_hint = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        current_hint = auth_header[7:][:16]

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
            "is_current": s.token_hint == current_hint,
        })

    return jsonify({"sessions": result})


@app.route("/sessions/revoke", methods=["POST"])
@login_required
def revoke_session():
    session_id = request.json.get("session_id")
    if not session_id:
        return jsonify({"ok": False, "error": "session_id is required."})

    sess = db.session.get(UserSession, session_id)
    if not sess or sess.user_id != g.user.id:
        return jsonify({"ok": False, "error": "Session not found."})

    sess.is_active = False
    db.session.commit()
    return jsonify({"ok": True, "message": "Session terminated."})


@app.route("/sessions/revoke-all", methods=["POST"])
@login_required
def revoke_all_sessions():
    current_hint = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        current_hint = auth_header[7:][:16]

    query = UserSession.query.filter_by(user_id=g.user.id, is_active=True)
    if current_hint:
        query = query.filter(UserSession.token_hint != current_hint)

    count = query.count()
    query.update({"is_active": False}, synchronize_session=False)
    db.session.commit()

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

    user.plan = plan
    user.plan_activated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "plan": plan, "message": f"Switched to {plan.title()} plan!"})


@app.route("/plan/request", methods=["POST"])
@login_required
def plan_request():
    plan = request.json.get("plan")
    if plan not in ("basic", "premium"):
        return jsonify({"ok": False, "error": "Invalid plan."})

    existing = Payment.query.filter_by(user_id=g.user.id, status="pending").first()
    if existing:
        return jsonify({"ok": False, "error": "You already have a pending request."})

    prices = {"basic": 29.99, "premium": 59.99}
    payment = Payment(user_id=g.user.id, amount=prices[plan], plan=plan, status="pending")
    db.session.add(payment)
    db.session.commit()
    return jsonify({
        "ok": True,
        "message": f"Your request has been received. It will be activated within 1 hour after payment of ${prices[plan]}.",
        "payment_info": {"amount": prices[plan], "note": f"SB-{g.user.id}"},
    })


# ───────────────────── Shopier ─────────────────────

@app.route("/plan/checkout", methods=["POST"])
@login_required
def plan_checkout():
    plan = request.json.get("plan")
    if plan not in ("basic", "premium"):
        return jsonify({"ok": False, "error": "Invalid plan."})

    user = g.user
    if user.plan == plan:
        return jsonify({"ok": False, "error": "You are already on this plan."})

    shopier_links = {
        "basic": "https://www.shopier.com/hourboostcomtr/45175746",
        "premium": "https://www.shopier.com/hourboostcomtr/45175760",
    }

    # Ödemeyi kullanıcıya GÜVENLİ eşlemek için benzersiz kodlu pending Payment.
    # TEK AKTİF PENDING kuralı: kullanıcının bu plandaki pending'ini yeniden kullan,
    # DİĞER tüm pending ödemelerini "cancelled" yap. Böylece admin onay kuyruğunda
    # aynı kullanıcı için birden fazla plan (örn. hem basic hem premium) görünmez.
    # Not: iptal edilen kayıtların match_token'ı durur; kullanıcı eski bir kodla
    # ödese bile webhook token ile eşleştirmeye devam eder.
    pendings = (Payment.query
                .filter_by(user_id=user.id, status="pending")
                .order_by(Payment.created_at.desc()).all())
    payment = None
    for p in pendings:
        if payment is None and p.plan == plan and p.match_token:
            payment = p          # bu plandaki en güncel kodlu pending'i koru
        else:
            p.status = "cancelled"   # diğer planlar + fazlalık duplikeler
    if payment is None:
        token = "HB-" + secrets.token_hex(3).upper()
        payment = Payment(user_id=user.id, amount=Config.PLANS[plan]["price"],
                          plan=plan, status="pending", match_token=token)
        db.session.add(payment)
    else:
        token = payment.match_token
    db.session.commit()

    logger.info("Checkout baslatildi: user=%s plan=%s token=%s", user.username, plan, token)
    return jsonify({
        "ok": True,
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
@csrf.exempt
def shopier_webhook():
    if not Config.SHOPIER_WEBHOOK_SECRET:
        logger.error("SHOPIER_WEBHOOK_SECRET ayarlanmamış! Webhook reddedildi.")
        return jsonify({"error": "Server configuration error"}), 500

    raw_body = request.get_data()
    signature = request.headers.get("Shopier-Signature", "")

    # ── GEÇİCİ TANI LOGU (webhook teşhisi — sorun çözülünce KALDIRILACAK) ──
    # Amaç: webhook app'e ulaşıyor mu, hangi imza başlığıyla geliyor, bizim
    # hesapladığımız HMAC ile eşleşiyor mu? (Gövde içeriği/PII loglanmaz.)
    try:
        _all_hdrs = list(request.headers.keys())
        _sig_like = {k: v for k, v in request.headers.items()
                     if any(s in k.lower() for s in ("sign", "hmac", "shopier"))}
        _expected = hmac.new(Config.SHOPIER_WEBHOOK_SECRET.encode("utf-8"),
                             raw_body, hashlib.sha256).hexdigest()
        logger.warning(
            "WEBHOOK-TANI ip=%s ua=%r body_len=%d gelen_imza=%r hesaplanan=%r imza_basliklari=%r tum_basliklar=%r",
            _get_client_ip(), request.headers.get("User-Agent", ""),
            len(raw_body), signature, _expected, _sig_like, _all_hdrs,
        )
    except Exception as _e:
        logger.warning("WEBHOOK-TANI log hatasi: %s", _e)
    # ── /GEÇİCİ TANI LOGU ──

    if not shopier_lib.verify_webhook(raw_body, signature, Config.SHOPIER_WEBHOOK_SECRET):
        logger.warning("Shopier webhook: IMZA HATASI!")
        return jsonify({"error": "Invalid signature"}), 401

    try:
        data = request.json or {}
    except Exception:
        return jsonify({"error": "Invalid data"}), 400

    event_type = request.headers.get("Shopier-Event", "") or data.get("event", "")
    logger.info("Shopier webhook alindi: event=%s", event_type)

    # Shopier sürümüne göre event adı değişebiliyor (order.created /
    # order.fulfilled / payment.completed). Bilinen bir event adı varsa ve
    # kabul listesinde değilse atla; event adı hiç yoksa (imza zaten
    # doğrulandığından) işleme devam et.
    ACCEPTED_EVENTS = {"order.created", "order.fulfilled", "payment.completed"}
    if event_type and event_type not in ACCEPTED_EVENTS:
        logger.info("Shopier webhook: islenmeyen event=%s, atlandi", event_type)
        return jsonify({"ok": True}), 200

    order = data
    line_items = order.get("lineItems", [])
    product_id = str(line_items[0].get("productId", "")) if line_items else ""
    buyer_note = (order.get("note") or "").strip()
    shopier_txn = str(order.get("id", ""))

    if shopier_txn:
        existing_txn = Payment.query.filter_by(transaction_id=shopier_txn).first()
        if existing_txn:
            logger.info("Shopier webhook: duplicate transaction_id=%s, atlanıyor", shopier_txn)
            return jsonify({"ok": True, "message": "Duplicate ignored"}), 200

    plan = shopier_lib.extract_plan(product_id, Config.SHOPIER_BASIC_PRODUCT_ID, Config.SHOPIER_PREMIUM_PRODUCT_ID)
    if not plan:
        logger.error("Shopier webhook: bilinmeyen urun ID=%s", product_id)
        return jsonify({"error": "Unknown product"}), 400

    user, matched_payment = resolve_payment_from_note(buyer_note)
    prices = {"basic": 29.99, "premium": 59.99}

    from sqlalchemy.exc import IntegrityError

    if not user:
        logger.error("Shopier webhook: kullanici bulunamadi note='%s'", buyer_note)
        unmatched = Payment(user_id=None, amount=prices.get(plan, 0), plan=plan,
                           status="unmatched", transaction_id=shopier_txn)
        db.session.add(unmatched)
        try:
            db.session.commit()
        except IntegrityError:
            # Eşzamanlı ikinci webhook aynı txn'i araya girip eklemiş olabilir.
            db.session.rollback()
            logger.info("Shopier webhook: eszamanli duplicate txn=%s (unmatched), atlandi", shopier_txn)
            return jsonify({"ok": True, "message": "Duplicate ignored"}), 200
        return jsonify({"ok": True, "warning": "User not found, saved as unmatched"}), 200

    # Token ile gelen pending ödemeyi tercih et; yoksa user+plan pending ara;
    # o da yoksa yeni completed kayıt oluştur. (Ürün ID'sinden gelen plan otoriter.)
    payment = matched_payment
    if payment is None:
        payment = (Payment.query
                   .filter_by(user_id=user.id, status="pending", plan=plan)
                   .order_by(Payment.created_at.desc()).first())
    if payment:
        payment.status = "completed"
        payment.plan = plan
        payment.transaction_id = shopier_txn
    else:
        payment = Payment(user_id=user.id, amount=prices[plan], plan=plan,
                         status="completed", transaction_id=shopier_txn)
        db.session.add(payment)

    user.plan = plan
    user.plan_expires = datetime.utcnow() + timedelta(days=3650)
    user.plan_activated_at = datetime.utcnow()
    try:
        db.session.commit()
    except IntegrityError:
        # transaction_id unique kisiti: ayni txn eszamanli islenmis.
        db.session.rollback()
        logger.info("Shopier webhook: eszamanli duplicate txn=%s, atlandi", shopier_txn)
        return jsonify({"ok": True, "message": "Duplicate ignored"}), 200
    logger.info("Shopier webhook: plan aktif edildi user=%s plan=%s txn=%s", user.username, plan, shopier_txn)
    return jsonify({"ok": True}), 200


# ───────────────────── Steam Hesaplar ─────────────────────

@app.route("/accounts")
@login_required
def get_accounts():
    accounts = SteamAccount.query.filter_by(user_id=g.user.id).all()
    result = []
    for acct in accounts:
        mgr = boost_service.get_or_create(acct.id, acct.steam_username)

        if mgr.logged_in:
            s = mgr.summary()
            s["app_ids"] = acct.app_ids()
        else:
            s = {
                "id": acct.id,
                "steam_username": acct.steam_username,
                "logged_in": False,
                "boosting": False,
                "start_time": None,
                "app_ids": acct.app_ids(),
                "persona_state": acct.persona_state,
                "has_token": mgr.has_token(),
            }
        result.append(s)
    return jsonify({"accounts": result})


@app.route("/accounts/login", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def account_login():
    data = request.json
    username = sanitize(data.get("username", ""), 100)
    password = data.get("password", "")
    if password == "_use_saved_":
        password = ""
    code = sanitize(data.get("code", ""), 10)
    code_type = data.get("code_type", "email")
    acct_id = data.get("acct_id")
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
        if not username:
            return jsonify({"ok": False, "error": "Username is required."})
        acct_db = SteamAccount(id=acct_id, user_id=user.id, steam_username=username)
        db.session.add(acct_db)
        db.session.commit()

    if acct_db.user_id != user.id:
        return jsonify({"ok": False, "error": "Unauthorized."})

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
                mgr.app_ids = acct_db.app_ids()
                mgr.persona_state = acct_db.persona_state
                return jsonify({"ok": True, "acct_id": acct_id})
            elif result in (EResult.AccountLoginDeniedNeedTwoFactor, EResult.TwoFactorCodeMismatch, EResult.InvalidLoginAuthCode):
                return jsonify({"ok": False, "need_code": True, "code_type": "2fa", "msg": "Invalid or expired 2FA code."})
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
            mgr.app_ids = acct_db.app_ids()
            mgr.persona_state = acct_db.persona_state
            return jsonify({"ok": True, "acct_id": acct_id, "method": "token"})
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
    acct_db.steam_username = username
    db.session.commit()
    mgr.app_ids = acct_db.app_ids()
    mgr.persona_state = acct_db.persona_state
    return jsonify({"ok": True, "acct_id": acct_id, "has_token": mgr.has_token()})


@app.route("/accounts/remove", methods=["POST"])
@login_required
def remove_account():
    acct_id = request.json.get("acct_id")
    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False})
    boost_service.remove(acct_id)
    db.session.delete(acct_db)
    db.session.commit()
    return jsonify({"ok": True})


# ───────────────────── Oyun Listesi ─────────────────────

@app.route("/apps/add", methods=["POST"])
@login_required
def add_app():
    acct_id = request.json.get("acct_id")
    aid = request.json.get("id")
    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False, "error": "Account not found."})

    limits = g.user.plan_limits()
    if len(acct_db.games) >= limits["max_games"]:
        return jsonify({"ok": False, "error": f"Your plan supports {limits['max_games']} games per account.", "upgrade": True})

    try:
        aid = int(aid)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Please enter a valid AppID."})

    exists = BoostGame.query.filter_by(account_id=acct_id, app_id=aid).first()
    if not exists:
        db.session.add(BoostGame(account_id=acct_id, app_id=aid))
        db.session.commit()

    ids = acct_db.app_ids()
    mgr = boost_service.get(acct_id)
    if mgr:
        mgr.app_ids = ids
    return jsonify({"app_ids": ids})


@app.route("/apps/remove", methods=["POST"])
@login_required
def remove_app():
    acct_id = request.json.get("acct_id")
    aid = request.json.get("id")
    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False})

    try:
        aid = int(aid)
    except (ValueError, TypeError):
        return jsonify({"ok": False})

    game = BoostGame.query.filter_by(account_id=acct_id, app_id=aid).first()
    if game:
        db.session.delete(game)
        db.session.commit()

    ids = acct_db.app_ids()
    mgr = boost_service.get(acct_id)
    if mgr:
        mgr.app_ids = ids
    return jsonify({"app_ids": ids})


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


@app.route("/boost/toggle", methods=["POST"])
@login_required
def toggle_boost():
    acct_id = request.json.get("acct_id")
    timer_hours = request.json.get("timer_hours", 0)
    try:
        timer_hours = float(timer_hours) if timer_hours else 0
    except (ValueError, TypeError):
        timer_hours = 0
    if timer_hours > 0:
        timer_hours = max(0.5, min(24.0, timer_hours))

    acct_db = db.session.get(SteamAccount, acct_id)
    if not acct_db or acct_db.user_id != g.user.id:
        return jsonify({"ok": False, "error": "Account not found."})

    mgr = boost_service.get(acct_id)
    if not mgr or not mgr.logged_in:
        return jsonify({"ok": False, "error": "Please connect to Steam first."})

    if mgr.boosting:
        acct_db.target_stop_time = None
        acct_db.is_boosting = False
        db.session.commit()
        _clear_timers(acct_id)
        boost_start = mgr.start_time
        elapsed = mgr.stop_boost()
        if elapsed > 0 and boost_start:
            log = BoostLog(
                account_id=acct_id,
                user_id=g.user.id,
                started_at=datetime.utcfromtimestamp(boost_start),
                stopped_at=datetime.utcnow(),
                duration_seconds=int(elapsed),
                games_count=len(acct_db.app_ids()),
                app_ids_json=json.dumps(acct_db.app_ids()),
            )
            db.session.add(log)
            db.session.commit()
        return jsonify({"ok": True, "boosting": False})

    ids = acct_db.app_ids()
    if not ids:
        return jsonify({"ok": False, "error": "Game list is empty."})
        
    _clear_timers(acct_id)

    limits = g.user.plan_limits()

    # ── Günlük saat limiti ──
    daily_hours = limits.get("daily_hours")
    if daily_hours is not None:
        from sqlalchemy import func as sqlfunc
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        used_seconds = (
            db.session.query(sqlfunc.sum(BoostLog.duration_seconds))
            .filter(BoostLog.user_id == g.user.id, BoostLog.started_at >= today_start)
            .scalar() or 0
        )
        used_seconds += _get_active_seconds(g.user.id, today_start)
        
        limit_seconds = daily_hours * 3600
        remaining = limit_seconds - used_seconds
        if remaining <= 0:
            return jsonify({"ok": False, "error": f"You have reached your daily {daily_hours}-hour limit.", "upgrade": True})

        if timer_hours > 0:
            remaining = min(remaining, timer_hours * 3600)

        _uid_daily = g.user.id

        def _auto_stop_on_limit():
            import gevent as _gevent
            _gevent.sleep(remaining)
            mgr2 = boost_service.get(acct_id)
            if mgr2 and mgr2.boosting:
                boost_start2 = mgr2.start_time
                elapsed2 = mgr2.stop_boost()
                with app.app_context():
                    acct2 = db.session.get(SteamAccount, acct_id)
                    if acct2:
                        acct2.is_boosting = False
                        acct2.target_stop_time = None
                    if elapsed2 > 0 and boost_start2:
                        log2 = BoostLog(
                            account_id=acct_id,
                            user_id=_uid_daily,
                            started_at=datetime.utcfromtimestamp(boost_start2),
                            stopped_at=datetime.utcnow(),
                            duration_seconds=int(elapsed2),
                            games_count=len(acct2.app_ids()) if acct2 else 0,
                            app_ids_json=json.dumps(acct2.app_ids()) if acct2 else "[]",
                        )
                        db.session.add(log2)
                    db.session.commit()
                logger.info("[acct:%s] Limit/zamanlayici doldu", acct_id)
            _clear_timers(acct_id)

        _add_timer(acct_id, gevent.spawn(_auto_stop_on_limit))

    else:
        if timer_hours > 0:
            _uid_timer = g.user.id
            timer_seconds = timer_hours * 3600

            def _auto_stop_on_timer():
                import gevent as _gevent
                _gevent.sleep(timer_seconds)
                mgr_t = boost_service.get(acct_id)
                if mgr_t and mgr_t.boosting:
                    boost_start_t = mgr_t.start_time
                    elapsed_t = mgr_t.stop_boost()
                    with app.app_context():
                        acct_t = db.session.get(SteamAccount, acct_id)
                        if acct_t:
                            acct_t.is_boosting = False
                            acct_t.target_stop_time = None
                        if elapsed_t > 0 and boost_start_t:
                            log_t = BoostLog(
                                account_id=acct_id,
                                user_id=_uid_timer,
                                started_at=datetime.utcfromtimestamp(boost_start_t),
                                stopped_at=datetime.utcnow(),
                                duration_seconds=int(elapsed_t),
                                games_count=len(acct_t.app_ids()) if acct_t else 0,
                                app_ids_json=json.dumps(acct_t.app_ids()) if acct_t else "[]",
                            )
                            db.session.add(log_t)
                        db.session.commit()
                    logger.info("[acct:%s] Timer finished (%.1f hours)", acct_id, timer_hours)
                _clear_timers(acct_id)

            _add_timer(acct_id, gevent.spawn(_auto_stop_on_timer))

    # ── Toplam saat limiti ──
    total_hours = limits.get("total_hours")
    if total_hours is not None:
        from sqlalchemy import func as sqlfunc2
        plan_start = g.user.plan_activated_at if g.user.plan_activated_at else datetime.utcnow() - timedelta(days=365)
        used_total = (
            db.session.query(sqlfunc2.sum(BoostLog.duration_seconds))
            .filter(BoostLog.user_id == g.user.id, BoostLog.started_at >= plan_start)
            .scalar() or 0
        )
        used_total += _get_active_seconds(g.user.id, plan_start)
        remaining_total = total_hours * 3600 - used_total
        if remaining_total <= 0:
            return jsonify({"ok": False, "error": f"You have used all {total_hours} hours in your plan.", "upgrade": True})

        _uid_total = g.user.id

        def _auto_stop_on_total_limit():
            import gevent as _gevent
            _gevent.sleep(remaining_total)
            mgr3 = boost_service.get(acct_id)
            if mgr3 and mgr3.boosting:
                boost_start3 = mgr3.start_time
                elapsed3 = mgr3.stop_boost()
                with app.app_context():
                    acct3 = db.session.get(SteamAccount, acct_id)
                    if acct3:
                        acct3.is_boosting = False
                        acct3.target_stop_time = None
                    if elapsed3 > 0 and boost_start3:
                        log3 = BoostLog(
                            account_id=acct_id,
                            user_id=_uid_total,
                            started_at=datetime.utcfromtimestamp(boost_start3),
                            stopped_at=datetime.utcnow(),
                            duration_seconds=int(elapsed3),
                            games_count=len(acct3.app_ids()) if acct3 else 0,
                            app_ids_json=json.dumps(acct3.app_ids()) if acct3 else "[]",
                        )
                        db.session.add(log3)
                    db.session.commit()
                logger.info("[acct:%s] Total limit reached", acct_id)
            _clear_timers(acct_id)

        _add_timer(acct_id, gevent.spawn(_auto_stop_on_total_limit))

    # Calculate and save target_stop_time
    possible_stops = []
    if 'remaining' in locals():
        possible_stops.append(remaining)
    elif 'timer_seconds' in locals():
        possible_stops.append(timer_seconds)
    if 'remaining_total' in locals():
        possible_stops.append(remaining_total)
        
    if possible_stops:
        min_sec = min(possible_stops)
        acct_db.target_stop_time = datetime.utcnow() + timedelta(seconds=min_sec)
    else:
        acct_db.target_stop_time = None
        
    acct_db.is_boosting = True
    db.session.commit()

    mgr.start_boost(ids, acct_db.persona_state)
    return jsonify({
        "boosting": True,
        "start_time": mgr.start_time,
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
    if not mgr or not mgr.logged_in:
        return jsonify({"ok": False})

    try:
        client = mgr.client
        me = client.user
        if not me:
            return jsonify({"ok": False})

        steamid = str(client.steam_id)
        name = getattr(me, "name", "") or ""
        avatar_url = ""
        if hasattr(me, "get_avatar_url"):
            avatar_url = me.get_avatar_url(2)
            if avatar_url:
                filename = avatar_url.split('/')[-1]
                avatar_url = f"https://avatars.steamstatic.com/{filename}"

        if not avatar_url:
            try:
                if Config.STEAM_API_KEY:
                    api_url = f"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key={Config.STEAM_API_KEY}&steamids={steamid}"
                    req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
                    with safe_urlopen(req, timeout=5) as r:
                        data = json.loads(r.read().decode())
                    players = data.get("response", {}).get("players", [])
                    if players:
                        avatar_url = players[0].get("avatarfull", "")
                
                if not avatar_url:
                    api_url = f"https://steamcommunity.com/profiles/{steamid}/?xml=1"
                    req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
                    with safe_urlopen(req, timeout=5) as r:
                        xml = r.read().decode()
                    m = re.search(r"<avatarFull><!\[CDATA\[(.*?)\]\]></avatarFull>", xml)
                    if m:
                        avatar_url = m.group(1)
            except Exception:
                pass

        return jsonify({
            "ok": True, "name": name, "avatar": avatar_url,
            "profile_url": f"https://steamcommunity.com/profiles/{steamid}",
            "steamid": steamid,
        })
    except Exception as e:
        logger.error("Profile error: %s", e)
        return jsonify({"ok": False})


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
        "pending_payments": Payment.query.filter_by(status="pending").count(),
    })


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
        user.plan = data["plan"]
        if data["plan"] != "free":
            user.plan_expires = datetime.utcnow() + timedelta(days=3650)
            user.plan_activated_at = datetime.utcnow()
        else:
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
        .filter(Payment.status != "cancelled")
        .order_by(db.case((Payment.status == "unmatched", 0), else_=1), Payment.created_at.desc())
        .limit(50).all()
    )

    user_ids = {p.user_id for p in payments if p.user_id}
    user_map = {}
    if user_ids:
        rows = User.query.filter(User.id.in_(user_ids)).all()
        user_map = {u.id: u.username for u in rows}

    return jsonify({"payments": [{
        "id": p.id, "user_id": p.user_id,
        "username": user_map.get(p.user_id, "unmatched"),
        "amount": p.amount, "plan": p.plan, "status": p.status,
        "transaction_id": p.transaction_id or "",
        "created_at": p.created_at.isoformat(),
    } for p in payments]})


@app.route("/admin/payments/approve", methods=["POST"])
@login_required
def admin_approve_payment():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    payment_id = request.json.get("payment_id")
    payment = db.session.get(Payment, payment_id)
    if not payment:
        return jsonify({"ok": False, "error": "Payment not found."})

    if payment.status == "unmatched":
        username = request.json.get("username", "").strip()
        if not username:
            return jsonify({"ok": False, "error": "Username is required."})
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"ok": False, "error": f"'{username}' not found."})
        payment.user_id = user.id
    else:
        user = db.session.get(User, payment.user_id)
        if not user:
            return jsonify({"ok": False, "error": "User not found."})

    payment.status = "completed"
    user.plan = payment.plan
    user.plan_expires = datetime.utcnow() + timedelta(days=3650)
    user.plan_activated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "message": f"{user.username} upgraded to {payment.plan} plan."})


@app.route("/admin/users/delete", methods=["POST"])
@login_required
def admin_delete_user():
    if not g.user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    target_id = data.get("user_id")
    
    if str(target_id) == str(g.user.id):
        return jsonify({"ok": False, "error": "You cannot delete your own account."})

    target_user = db.session.get(User, target_id)
    if not target_user:
        return jsonify({"ok": False, "error": "User not found."})
    if target_user.is_admin:
        return jsonify({"ok": False, "error": "Admin accounts cannot be deleted."})

    username = target_user.username
    try:
        steam_accounts = SteamAccount.query.filter_by(user_id=target_id).all()
        for acct in steam_accounts:
            mgr = boost_service.get(acct.id)
            if mgr:
                try:
                    mgr.disconnect()
                except Exception:
                    pass
            boost_service.remove(acct.id)

        BoostLog.query.filter_by(user_id=target_id).delete(synchronize_session=False)
        Payment.query.filter_by(user_id=target_id).delete(synchronize_session=False)
        UserSession.query.filter_by(user_id=target_id).delete(synchronize_session=False)

        for acct in steam_accounts:
            acct_fresh = db.session.get(SteamAccount, acct.id)
            if acct_fresh:
                db.session.delete(acct_fresh)

        db.session.delete(target_user)
        db.session.commit()
        logger.info("Admin %s tarafindan kullanici silindi: %s (ID:%s)", g.user.username, username, target_id)
        return jsonify({"ok": True, "message": f"{username} has been successfully deleted."})
    except Exception as e:
        db.session.rollback()
        logger.error("Kullanici silme hatasi (ID:%s): %s", target_id, e)
        return jsonify({"ok": False, "error": "Deletion failed. Check server logs."})


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
    try:
        api_key = Config.STEAM_API_KEY
        if not api_key:
            return {}
        url = (
            f"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
            f"?key={api_key}&steamids={steam_id}"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with safe_urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        players = data.get("response", {}).get("players", [])
        if not players:
            return {}
        p = players[0]
        return {
            "steam_id": steam_id,
            "name": p.get("personaname", ""),
            "avatar": p.get("avatarfull", ""),
            "profile_url": p.get("profileurl", ""),
        }
    except Exception as e:
        logger.error("Steam profil bilgisi alinamadi: %s", e)
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

    session.permanent = True
    session["user_id"] = user.id
    token = generate_api_token(user.id)
    _create_session_record(user.id, token)

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

if __name__ == "__main__":
    print("Hour Boost calisiyor -> http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
