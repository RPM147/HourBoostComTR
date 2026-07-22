from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"


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
    # Bu tarihten ÖNCE üretilmiş JWT token'lar geçersiz sayılır
    # (şifre değişimi / oturum iptali sonrası set edilir).
    tokens_valid_after = db.Column(db.DateTime, nullable=True)
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
        self.password_hash = generate_password_hash(pw, method=PASSWORD_HASH_METHOD)

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
    is_boosting = db.Column(db.Boolean, default=False)
    target_stop_time = db.Column(db.DateTime, nullable=True)
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
    # Financial ownership snapshots survive account deletion. ``user_id`` is
    # deliberately nullable so the operational user can be removed without
    # destroying the payment ledger or reattaching history to a reused ID.
    owner_user_id_snapshot = db.Column(db.Integer, nullable=True)
    owner_username_snapshot = db.Column(db.String(80), nullable=True)
    owner_detached_at = db.Column(db.DateTime, nullable=True)
    amount = db.Column(db.Float)
    plan = db.Column(db.String(20))
    status = db.Column(db.String(32), default="pending")
    transaction_id = db.Column(db.String(100), unique=True, nullable=True)
    # Webhook'ta odemeyi kullaniciya guvenli eslemek icin benzersiz 128-bit HB kodu.
    match_token = db.Column(db.String(64), nullable=True, index=True)
    # Admin panelinden gizlemek içindir; ödeme/audit kaydı fiziksel olarak silinmez.
    admin_hidden = db.Column(
        db.Boolean, nullable=False, default=False, server_default=db.false()
    )
    # Shopier-Webhook-Id bir subscription ID'sidir; farklı siparişlerde aynı
    # kalabileceğinden unique OLAMAZ. Asıl idempotency transaction_id üzerindedir.
    shopier_webhook_id = db.Column(db.String(100), nullable=True)
    shopier_event = db.Column(db.String(50), nullable=True)
    shopier_account_id = db.Column(db.String(100), nullable=True)
    shopier_timestamp = db.Column(db.BigInteger, nullable=True)
    webhook_body_sha256 = db.Column(db.String(64), nullable=True)
    webhook_received_at = db.Column(db.DateTime, nullable=True)
    verification_attempts = db.Column(
        db.Integer, nullable=False, default=0, server_default="0"
    )
    verification_error = db.Column(db.String(255), nullable=True)
    verification_last_http_status = db.Column(db.Integer, nullable=True)
    next_verification_at = db.Column(db.DateTime, nullable=True)
    verification_lock_until = db.Column(db.DateTime, nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    # Finansal doğrulamanın tam sayı kuruş karşılığı; amount yalnız gösterim ve
    # eski raporlarla uyumluluk içindir.
    verified_amount_minor = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PaymentAuditLog(db.Model):
    """Append-only audit trail for exceptional admin payment actions."""

    __tablename__ = "payment_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, nullable=True)
    actor_username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    from_status = db.Column(db.String(32), nullable=True)
    to_status = db.Column(db.String(32), nullable=True)
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class BoostLog(db.Model):
    __tablename__ = "boost_logs"
    __table_args__ = (
        db.Index(
            "ix_boost_logs_user_window",
            "user_id",
            "stopped_at",
            "started_at",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.String(32), db.ForeignKey("steam_accounts.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    started_at = db.Column(db.DateTime, nullable=False)
    stopped_at = db.Column(db.DateTime)
    # Canonical quota accounting stops at ``stopped_at``.  This separate audit
    # timestamp records when the Steam worker was actually confirmed dead or
    # accepted stop-games, so enforcement latency is observable rather than
    # hidden by backdating the billable boundary.
    remote_stopped_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, default=0)
    games_count = db.Column(db.Integer, default=0)
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
    # JWT'nin rastgele, imzalı kimliği. Oturum iptali JWT ve Flask cookie için
    # aynı sunucu tarafı kaydı üzerinden uygulanır. Nullable yalnızca eski
    # veritabanlarının güvenli şekilde migrate edilebilmesi içindir.
    token_jti = db.Column(db.String(64), nullable=True, unique=True, index=True)
    # Legacy görüntüleme alanı; güvenlik kararı için kullanılmaz.
    token_hint = db.Column(db.String(32), nullable=True)
    # JWT ve Flask cookie aynı mutlak sona erme zamanını paylaşır; aksi halde
    # Flask'ın yenilenen permanent cookie'si JWT'den daha uzun yaşayabilir.
    expires_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)


class RevokedToken(db.Model):
    """Yeniden kullanımı önlemek için iptal edilmiş JWT token'ları kalıcı olarak saklar."""
    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_jti = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    @classmethod
    def cleanup_expired(cls):
        """Süresi dolmuş token'ları veritabanından temizle."""
        from sqlalchemy import delete
        now = datetime.utcnow()
        db.session.execute(delete(cls).where(cls.expires_at < now))
        db.session.commit()
