from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    plan = db.Column(db.String(20), default="free")
    plan_expires = db.Column(db.DateTime, nullable=True)
    plan_activated_at = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    lang = db.Column(db.String(5), default="tr", nullable=True)
    steam_id = db.Column(db.String(20), nullable=True, unique=True)
    steam_avatar = db.Column(db.String(256), nullable=True)
    steam_display_name = db.Column(db.String(100), nullable=True)

    # ── E-posta doğrulama ──────────────────────────
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(64), nullable=True, unique=True)
    verification_sent_at = db.Column(db.DateTime, nullable=True)

    # ── Şifre sıfırlama ───────────────────────────
    reset_token = db.Column(db.String(64), nullable=True, unique=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    # ── E-posta değiştirme ────────────────────────
    email_change_token = db.Column(db.String(64), nullable=True, unique=True)
    email_change_new = db.Column(db.String(120), nullable=True)
    email_change_expires = db.Column(db.DateTime, nullable=True)

    steam_accounts = db.relationship(
        "SteamAccount", backref="owner", lazy=True, cascade="all, delete-orphan"
    )
    sessions = db.relationship(
        "UserSession", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw, method="pbkdf2:sha256:600000")

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def plan_limits(self):
        from config import Config
        return Config.PLANS.get(self.plan, Config.PLANS["free"])


class SteamAccount(db.Model):
    __tablename__ = "steam_accounts"

    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    steam_username = db.Column(db.String(100), nullable=False)
    steam_id = db.Column(db.String(20))
    persona_state = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    games = db.relationship(
        "BoostGame", backref="account", lazy=True, cascade="all, delete-orphan"
    )

    def app_ids(self):
        return [g.app_id for g in self.games]


class BoostGame(db.Model):
    __tablename__ = "boost_games"

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.String(32), db.ForeignKey("steam_accounts.id"))
    app_id = db.Column(db.Integer, nullable=False)


class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    amount = db.Column(db.Float)
    plan = db.Column(db.String(20))
    status = db.Column(db.String(20), default="pending")
    transaction_id = db.Column(db.String(100), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class BoostLog(db.Model):
    __tablename__ = "boost_logs"

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.String(32), db.ForeignKey("steam_accounts.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    started_at = db.Column(db.DateTime, nullable=False)
    stopped_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer, default=0)
    games_count = db.Column(db.Integer, default=0)
    # Hangi oyunların boost edildiğini sakla (JSON string: "[730, 440]")
    app_ids_json = db.Column(db.Text, nullable=True)


class Announcement(db.Model):
    __tablename__ = "announcements"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default="info")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class UserSession(db.Model):
    """Aktif kullanıcı oturumlarını takip eder."""
    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # JWT token'ın jti yerine token'ın ilk 16 karakteri (tanımlama için)
    token_hint = db.Column(db.String(32), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)