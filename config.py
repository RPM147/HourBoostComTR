import os
import secrets
from dotenv import load_dotenv

load_dotenv()


class Config:
    # SECRET_KEY zorunlu; env'de yoksa güvenli rastgele değer üret
    _raw_secret = os.environ.get("SECRET_KEY")
    if not _raw_secret:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "SECRET_KEY environment variable is not set! "
            "A random key is being generated — sessions will be lost on restart."
        )
        _raw_secret = secrets.token_hex(32)
    SECRET_KEY = _raw_secret
    STEAM_API_KEY = os.environ.get("STEAM_API_KEY")
    SITE_URL = os.environ.get("SITE_URL", "https://hourboost.com.tr")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///steamboost.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = 30 * 24 * 3600

    PLANS = {
        "free": {
            "max_accounts": 1,
            "max_games": 1,
            "daily_hours": 8,
            "total_hours": None,
            "price": 0,
        },
        "basic": {
            "max_accounts": 3,
            "max_games": 10,
            "daily_hours": None,
            "total_hours": 1500,
            "price": 29.99,
        },
        "premium": {
            "max_accounts": 10,
            "max_games": 32,
            "daily_hours": None,
            "total_hours": 3500,
            "price": 59.99,
        },
    }

    STEAM_CACHE_TTL = 86400
    RECONNECT_MAX = 5

    # ── Shopier ───────────────────────────────────────
    SHOPIER_PAT = os.environ.get("SHOPIER_PAT")
    SHOPIER_WEBHOOK_SECRET = os.environ.get("SHOPIER_WEBHOOK_SECRET")
    SHOPIER_BASIC_PRODUCT_ID = os.environ.get(
        "SHOPIER_BASIC_PRODUCT_ID", "45175746"
    )
    SHOPIER_PREMIUM_PRODUCT_ID = os.environ.get(
        "SHOPIER_PREMIUM_PRODUCT_ID", "45175760"
    )
