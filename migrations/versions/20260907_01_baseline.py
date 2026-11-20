"""Frozen intended HourBoost schema; empty SQLite databases only.

Revision ID: 20260907_01
Revises: None

This is the target schema, not permission to stamp a historical database.
Phase 5H.1B must audit and reconcile existing installations separately. The
revision deliberately imports no application modules: startup reconciliation,
credentials, workers and configuration must never run during migration.

SQLite timestamps remain timezone-naive UTC. PostgreSQL support, including
TIMESTAMPTZ and integer-width review, is deferred to Phase 5H.1C. Offline SQL
is rejected because it cannot prove the empty-schema precondition.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260907_01"
down_revision = None
branch_labels = None
depends_on = None


def _require_empty_sqlite_schema() -> None:
    context = op.get_context()
    if context.as_sql:
        raise RuntimeError("The baseline requires an online empty SQLite database")
    if context.dialect.name != "sqlite":
        raise RuntimeError("The baseline supports SQLite only; PostgreSQL is deferred")
    connection = op.get_bind()
    if connection is None:
        raise RuntimeError("The baseline requires an online SQLite connection")
    # Alembic creates its bookkeeping table before invoking upgrade(). Ignore
    # only that table and SQLite's own internal objects, never unknown user
    # tables, views, indexes or triggers. Temp objects can shadow real tables.
    existing = connection.execute(sa.text(
        "SELECT 1 FROM sqlite_master "
        "WHERE name NOT GLOB 'sqlite_*' "
        "AND NOT (type = 'table' AND name = 'alembic_version') "
        "UNION ALL SELECT 1 FROM sqlite_temp_master "
        "WHERE name NOT GLOB 'sqlite_*' LIMIT 1"
    )).first()
    if existing is not None:
        raise RuntimeError(
            "The baseline only bootstraps empty schemas; audit existing databases first"
        )


def upgrade() -> None:
    """Create the reviewed schema without reading or rewriting user data."""
    _require_empty_sqlite_schema()

    op.create_table(
        "announcements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("type", sa.String(length=20), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "payment_audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("payment_id", sa.Integer(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(length=80), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=True),
        sa.Column("to_status", sa.String(length=32), nullable=True),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_payment_audit_logs_payment_id", "payment_audit_logs", ["payment_id"],
        unique=False,
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("email", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("plan", sa.String(length=20), nullable=True),
        sa.Column("plan_expires", sa.DateTime(timezone=False), nullable=True),
        sa.Column("plan_activated_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("last_login", sa.DateTime(timezone=False), nullable=True),
        sa.Column("tokens_valid_after", sa.DateTime(timezone=False), nullable=True),
        sa.Column("lang", sa.String(length=5), nullable=True),
        sa.Column("steam_id", sa.String(length=20), nullable=True),
        sa.Column("steam_avatar", sa.String(length=256), nullable=True),
        sa.Column("steam_display_name", sa.String(length=100), nullable=True),
        sa.Column("is_verified", sa.Boolean(), nullable=True),
        sa.Column("verification_token", sa.String(length=64), nullable=True),
        sa.Column("verification_sent_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("reset_token", sa.String(length=64), nullable=True),
        sa.Column("reset_token_expires", sa.DateTime(timezone=False), nullable=True),
        sa.Column("email_change_token", sa.String(length=64), nullable=True),
        sa.Column("email_change_new", sa.String(length=120), nullable=True),
        sa.Column("email_change_expires", sa.DateTime(timezone=False), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("email_change_token"),
        sa.UniqueConstraint("reset_token"),
        sa.UniqueConstraint("steam_id"),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("verification_token"),
    )
    op.create_table(
        "payments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("owner_user_id_snapshot", sa.Integer(), nullable=True),
        sa.Column("owner_username_snapshot", sa.String(length=80), nullable=True),
        sa.Column("owner_detached_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("amount", sa.Float(), nullable=True),
        sa.Column("plan", sa.String(length=20), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=True),
        sa.Column("transaction_id", sa.String(length=100), nullable=True),
        sa.Column("match_token", sa.String(length=64), nullable=True),
        sa.Column("admin_hidden", sa.Boolean(), server_default=sa.text("0"), nullable=False),
        sa.Column("shopier_webhook_id", sa.String(length=100), nullable=True),
        sa.Column("shopier_event", sa.String(length=50), nullable=True),
        sa.Column("shopier_account_id", sa.String(length=100), nullable=True),
        sa.Column("shopier_timestamp", sa.BigInteger(), nullable=True),
        sa.Column("webhook_body_sha256", sa.String(length=64), nullable=True),
        sa.Column("webhook_received_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("verification_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("verification_error", sa.String(length=255), nullable=True),
        sa.Column("verification_last_http_status", sa.Integer(), nullable=True),
        sa.Column("next_verification_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("verification_lock_until", sa.DateTime(timezone=False), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("verified_amount_minor", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("transaction_id"),
    )
    op.create_index("ix_payments_match_token", "payments", ["match_token"], unique=False)
    # These five indexes used to be installed only by app._ensure_schema().
    # Preserve the redundant transaction constraint/index pair intentionally:
    # fresh metadata and historical runtime schemas both have to be audited.
    op.create_index(
        "ux_payments_match_token", "payments", ["match_token"], unique=True,
        sqlite_where=sa.text("match_token IS NOT NULL"),
    )
    op.create_index(
        "ux_payments_transaction_id", "payments", ["transaction_id"], unique=True,
        sqlite_where=sa.text("transaction_id IS NOT NULL"),
    )
    op.create_index(
        "ux_payments_one_open_checkout", "payments", ["user_id"], unique=True,
        sqlite_where=sa.text(
            "user_id IS NOT NULL AND status IN ('checkout_started', 'verification_pending')"
        ),
    )
    op.create_index(
        "ix_payments_shopier_webhook_id", "payments", ["shopier_webhook_id"], unique=False,
    )
    op.create_index(
        "ix_payments_verification_due", "payments",
        ["status", "next_verification_at", "verification_lock_until"], unique=False,
    )
    op.create_table(
        "revoked_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_jti", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=False), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=False), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_revoked_tokens_token_jti", "revoked_tokens", ["token_jti"], unique=True)
    op.create_table(
        "steam_accounts",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("steam_username", sa.String(length=100), nullable=False),
        sa.Column("steam_id", sa.String(length=20), nullable=True),
        sa.Column("persona_state", sa.Integer(), nullable=True),
        sa.Column("is_boosting", sa.Boolean(), nullable=True),
        sa.Column("target_stop_time", sa.DateTime(timezone=False), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_jti", sa.String(length=64), nullable=True),
        sa.Column("token_hint", sa.String(length=32), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=False), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_sessions_token_jti", "user_sessions", ["token_jti"], unique=True)
    op.create_table(
        "boost_games",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("account_id", sa.String(length=32), nullable=True),
        sa.Column("app_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["steam_accounts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "boost_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("account_id", sa.String(length=32), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("account_id_snapshot", sa.String(length=32), nullable=True),
        sa.Column("steam_username_snapshot", sa.String(length=100), nullable=True),
        sa.Column("owner_user_id_snapshot", sa.Integer(), nullable=True),
        sa.Column("owner_username_snapshot", sa.String(length=80), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=False), nullable=False),
        sa.Column("stopped_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("remote_stopped_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("duration_microseconds", sa.BigInteger(), nullable=True),
        sa.Column("games_count", sa.Integer(), nullable=True),
        sa.Column("app_ids_json", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "duration_seconds IS NOT NULL "
            "AND duration_seconds >= 0 "
            "AND duration_seconds <= 9223372036854 "
            "AND (duration_microseconds IS NULL OR ("
            "(duration_seconds = 0 AND duration_microseconds = 0) OR "
            "(duration_seconds > 0 "
            "AND duration_microseconds > "
            "(CAST(duration_seconds AS BIGINT) - 1) * 1000000 "
            "AND duration_microseconds <= "
            "CAST(duration_seconds AS BIGINT) * 1000000)))",
            name="ck_boost_logs_duration_ledger",
        ),
        sa.ForeignKeyConstraint(["account_id"], ["steam_accounts.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_boost_logs_user_window", "boost_logs", ["user_id", "stopped_at", "started_at"],
        unique=False,
    )

    # SQLite CHECK comparisons alone do not enforce integer storage classes.
    # Freeze both the type checks and the range/dual-write checks from 5G.2.
    invalid_ledger = (
        "typeof(NEW.duration_seconds) <> 'integer' "
        "OR (NEW.duration_microseconds IS NOT NULL AND "
        "typeof(NEW.duration_microseconds) <> 'integer') "
        "OR NEW.duration_seconds IS NULL OR NEW.duration_seconds < 0 "
        "OR NEW.duration_seconds > 9223372036854 "
        "OR (NEW.duration_microseconds IS NOT NULL AND ("
        "NEW.duration_microseconds < 0 "
        "OR NEW.duration_microseconds > 9223372036854000000 "
        "OR (NEW.duration_seconds = 0 AND NEW.duration_microseconds <> 0) "
        "OR (NEW.duration_seconds > 0 AND ("
        "NEW.duration_microseconds <= "
        "(CAST(NEW.duration_seconds AS BIGINT) - 1) * 1000000 "
        "OR NEW.duration_microseconds > "
        "CAST(NEW.duration_seconds AS BIGINT) * 1000000))))"
    )
    for name, event in (
        ("trg_boost_logs_duration_ledger_insert", "BEFORE INSERT"),
        (
            "trg_boost_logs_duration_ledger_update",
            "BEFORE UPDATE OF duration_seconds, duration_microseconds",
        ),
    ):
        op.execute(sa.text(
            f"CREATE TRIGGER {name} {event} ON boost_logs "
            f"WHEN {invalid_ledger} "
            "BEGIN SELECT RAISE(ABORT, 'invalid boost duration ledger'); END"
        ))


def downgrade() -> None:
    """Never implement rollback by deleting users or financial/usage history."""
    raise RuntimeError(
        "Baseline downgrade is disabled; use a reviewed backup/recovery procedure"
    )
