import os
import secrets
from dotenv import load_dotenv

load_dotenv()


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return value.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # SECRET_KEY zorunlu; env'de yoksa RuntimeError fırlat
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set! "
            "Please set a secure SECRET_KEY in your environment variables."
        )

    STEAM_API_KEY = os.environ.get("STEAM_API_KEY")
    SITE_URL = os.environ.get("SITE_URL", "https://hourboost.com.tr")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///steamboost.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = 30 * 24 * 3600

    # Rate Limiting Depolama (Redis önerilir: redis://localhost:6379)
    LIMITER_STORAGE_URI = os.environ.get("LIMITER_STORAGE_URI", "memory://")

    # Güvenli oturum çerezi ayarları
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "hourboost_session"

    # CSRF Koruması
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # duration_days: ödeme/onay sonrası planın geçerlilik süresi (gün).
    # None = süresiz (plan_expires hiç set edilmez). Eskiden kod içinde
    # sabit 3650 gün (~10 yıl) kullanılıyordu; gerçek fatura dönemi burada
    # tek yerden yönetilir (bkz. FIX.md Phase 2 minor 3).
    PLANS = {
        "free": {
            "max_accounts": 1,
            "max_games": 1,
            "daily_hours": 8,
            "total_hours": None,
            "price": 0,
            "duration_days": None,
        },
        "basic": {
            "max_accounts": 3,
            "max_games": 10,
            "daily_hours": None,
            "total_hours": 1500,
            "price": 29.99,
            "duration_days": None,
        },
        "premium": {
            "max_accounts": 10,
            "max_games": 32,
            "daily_hours": None,
            "total_hours": 3500,
            "price": 59.99,
            "duration_days": None,
        },
    }

    STEAM_CACHE_TTL = 86400
    RECONNECT_MAX = 5

    # ── Shopier ───────────────────────────────────────
    SHOPIER_PAT = os.environ.get("SHOPIER_PAT")
    SHOPIER_WEBHOOK_SECRET = os.environ.get("SHOPIER_WEBHOOK_SECRET")
    SHOPIER_ACCOUNT_ID = os.environ.get("SHOPIER_ACCOUNT_ID")
    # Shopier-Webhook-Id, delivery ID değil webhook subscription ID'sidir.
    SHOPIER_WEBHOOK_ID = os.environ.get("SHOPIER_WEBHOOK_ID")
    SHOPIER_API_VERIFY_ENABLED = _env_bool("SHOPIER_API_VERIFY_ENABLED", False)
    SHOPIER_VERIFICATION_WORKER_ENABLED = _env_bool(
        "SHOPIER_VERIFICATION_WORKER_ENABLED",
        SHOPIER_API_VERIFY_ENABLED,
    )
    SHOPIER_CHECKOUT_TTL_HOURS = max(
        1, int(os.environ.get("SHOPIER_CHECKOUT_TTL_HOURS", "24"))
    )
    SHOPIER_BASIC_PRODUCT_ID = os.environ.get(
        "SHOPIER_BASIC_PRODUCT_ID", "45175746"
    )
    SHOPIER_PREMIUM_PRODUCT_ID = os.environ.get(
        "SHOPIER_PREMIUM_PRODUCT_ID", "45175760"
    )
