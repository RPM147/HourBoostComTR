import os
import secrets
from dotenv import load_dotenv

load_dotenv()


class Config:
    # SECRET_KEY is now REQUIRED - no fallback to random generation
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
    
    # Secure session cookie configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True  # Only send cookies over HTTPS
    SESSION_COOKIE_SAMESITE = 'Lax'  # Prevent CSRF attacks
    SESSION_COOKIE_NAME = 'hourboost_session'
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # Security: Require webhook secret for Shopier
    SHOPIER_WEBHOOK_REQUIRED = True

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
