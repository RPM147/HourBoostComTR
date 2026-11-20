"""Frozen HourBoost schema for an empty PostgreSQL rehearsal target.

Revision ID: 20260913_01
Revises: None

This revision is deliberately independent from the deployed SQLite migration
lineage and imports no application modules. It may run only online, on
PostgreSQL, inside a caller-owned transaction, and against an empty target
schema. It does not activate the application PostgreSQL runtime.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260913_01"
down_revision = None
branch_labels = ("postgresql",)
depends_on = None


UTC_TIMESTAMP = sa.DateTime(timezone=True)
TEXT_COLLATION = "C"


def _varchar(length):
    return sa.String(length=length, collation=TEXT_COLLATION)


def _text():
    return sa.Text(collation=TEXT_COLLATION)


def _identity_id():
    return sa.Column(
        "id",
        sa.BigInteger(),
        sa.Identity(always=False),
        nullable=False,
    )


def _require_empty_postgresql_schema():
    migration_context = op.get_context()
    if migration_context.as_sql:
        raise RuntimeError("PostgreSQL baseline requires an online connection")
    if migration_context.dialect.name != "postgresql":
        raise RuntimeError("PostgreSQL baseline rejects non-PostgreSQL targets")
    connection = op.get_bind()
    if connection is None or not connection.in_transaction():
        raise RuntimeError("PostgreSQL baseline requires an explicit transaction")

    # Alembic may create its own version table before invoking upgrade(). Allow
    # only that table and its automatically-owned indexes. Any other relation,
    # function, enum/domain/range/multirange is unknown state and fails closed.
    unknown_object = connection.execute(sa.text(
        "SELECT 1 FROM pg_catalog.pg_class AS c "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = current_schema() "
        "AND c.relkind IN ('r','p','v','m','S','f','i') "
        "AND NOT ("
        "  (c.relkind IN ('r','p') AND c.relname = 'alembic_version') OR "
        "  (c.relkind = 'i' AND EXISTS ("
        "    SELECT 1 FROM pg_catalog.pg_index AS ix "
        "    JOIN pg_catalog.pg_class AS t ON t.oid = ix.indrelid "
        "    WHERE ix.indexrelid = c.oid "
        "    AND t.relname = 'alembic_version' "
        "    AND t.relnamespace = n.oid"
        "  ))"
        ") "
        "UNION ALL "
        "SELECT 1 FROM pg_catalog.pg_proc AS p "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace "
        "WHERE n.nspname = current_schema() "
        "UNION ALL "
        "SELECT 1 FROM pg_catalog.pg_type AS t "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace "
        "WHERE n.nspname = current_schema() "
        "AND t.typtype IN ('d','e','r','m') "
        "LIMIT 1"
    )).first()
    if unknown_object is not None:
        raise RuntimeError("PostgreSQL baseline requires an empty target schema")


def upgrade():
    _require_empty_postgresql_schema()

    op.create_table(
        "announcements",
        _identity_id(),
        sa.Column("title", _varchar(200), nullable=False),
        sa.Column("content", _text(), nullable=False),
        sa.Column("type", _varchar(20), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", UTC_TIMESTAMP, nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "users",
        _identity_id(),
        sa.Column("username", _varchar(80), nullable=False),
        sa.Column("email", _varchar(120), nullable=False),
        sa.Column("password_hash", _varchar(256), nullable=False),
        sa.Column("plan", _varchar(20), nullable=True),
        sa.Column("plan_expires", UTC_TIMESTAMP, nullable=True),
        sa.Column("plan_activated_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=True),
        sa.Column("created_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("last_login", UTC_TIMESTAMP, nullable=True),
        sa.Column("tokens_valid_after", UTC_TIMESTAMP, nullable=True),
        sa.Column(
            "lang", _varchar(5), server_default=sa.text("'tr'"), nullable=True
        ),
        sa.Column("steam_id", _varchar(20), nullable=True),
        sa.Column("steam_avatar", _varchar(256), nullable=True),
        sa.Column("steam_display_name", _varchar(100), nullable=True),
        sa.Column(
            "is_verified",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=True,
        ),
        sa.Column("verification_token", _varchar(64), nullable=True),
        sa.Column("verification_sent_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("reset_token", _varchar(64), nullable=True),
        sa.Column("reset_token_expires", UTC_TIMESTAMP, nullable=True),
        sa.Column("email_change_token", _varchar(64), nullable=True),
        sa.Column("email_change_new", _varchar(120), nullable=True),
        sa.Column("email_change_expires", UTC_TIMESTAMP, nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    for field in (
        "steam_id",
        "verification_token",
        "reset_token",
        "email_change_token",
    ):
        op.create_index("ux_users_" + field, "users", [field], unique=True)

    op.create_table(
        "payment_audit_logs",
        _identity_id(),
        sa.Column("payment_id", sa.BigInteger(), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_username", _varchar(80), nullable=False),
        sa.Column("action", _varchar(50), nullable=False),
        sa.Column("from_status", _varchar(32), nullable=True),
        sa.Column("to_status", _varchar(32), nullable=True),
        sa.Column("reason", _varchar(255), nullable=False),
        sa.Column("created_at", UTC_TIMESTAMP, nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_payment_audit_logs_payment_id",
        "payment_audit_logs",
        ["payment_id"],
        unique=False,
    )

    op.create_table(
        "payments",
        _identity_id(),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.Column("owner_user_id_snapshot", sa.BigInteger(), nullable=True),
        sa.Column("owner_username_snapshot", _varchar(80), nullable=True),
        sa.Column("owner_detached_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("amount", sa.Double(), nullable=True),
        sa.Column("plan", _varchar(20), nullable=True),
        sa.Column("status", _varchar(32), nullable=True),
        sa.Column("transaction_id", _varchar(100), nullable=True),
        sa.Column("match_token", _varchar(64), nullable=True),
        sa.Column(
            "admin_hidden",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("shopier_webhook_id", _varchar(100), nullable=True),
        sa.Column("shopier_event", _varchar(50), nullable=True),
        sa.Column("shopier_account_id", _varchar(100), nullable=True),
        sa.Column("shopier_timestamp", sa.BigInteger(), nullable=True),
        sa.Column("webhook_body_sha256", _varchar(64), nullable=True),
        sa.Column("webhook_received_at", UTC_TIMESTAMP, nullable=True),
        sa.Column(
            "verification_attempts",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("verification_error", _varchar(255), nullable=True),
        sa.Column("verification_last_http_status", sa.Integer(), nullable=True),
        sa.Column("next_verification_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("verification_lock_until", UTC_TIMESTAMP, nullable=True),
        sa.Column("verified_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("verified_amount_minor", sa.BigInteger(), nullable=True),
        sa.Column("created_at", UTC_TIMESTAMP, nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("transaction_id", name="uq_payments_transaction_id"),
    )
    op.create_index(
        "ix_payments_match_token", "payments", ["match_token"], unique=False
    )
    op.create_index(
        "ux_payments_match_token",
        "payments",
        ["match_token"],
        unique=True,
        postgresql_where=sa.text("match_token IS NOT NULL"),
    )
    op.create_index(
        "ux_payments_transaction_id",
        "payments",
        ["transaction_id"],
        unique=True,
        postgresql_where=sa.text("transaction_id IS NOT NULL"),
    )
    op.create_index(
        "ux_payments_one_open_checkout",
        "payments",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text(
            "user_id IS NOT NULL "
            "AND status IN ('checkout_started', 'verification_pending')"
        ),
    )
    op.create_index(
        "ix_payments_shopier_webhook_id",
        "payments",
        ["shopier_webhook_id"],
        unique=False,
    )
    op.create_index(
        "ix_payments_verification_due",
        "payments",
        ["status", "next_verification_at", "verification_lock_until"],
        unique=False,
    )

    op.create_table(
        "revoked_tokens",
        _identity_id(),
        sa.Column("token_jti", _varchar(128), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("revoked_at", UTC_TIMESTAMP, nullable=False),
        sa.Column("expires_at", UTC_TIMESTAMP, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_revoked_tokens_token_jti",
        "revoked_tokens",
        ["token_jti"],
        unique=True,
    )

    op.create_table(
        "steam_accounts",
        sa.Column("id", _varchar(32), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("steam_username", _varchar(100), nullable=False),
        sa.Column("steam_id", _varchar(20), nullable=True),
        sa.Column("persona_state", sa.Integer(), nullable=True),
        sa.Column(
            "is_boosting",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=True,
        ),
        sa.Column("target_stop_time", UTC_TIMESTAMP, nullable=True),
        sa.Column("created_at", UTC_TIMESTAMP, nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "user_sessions",
        _identity_id(),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("token_jti", _varchar(64), nullable=True),
        sa.Column("token_hint", _varchar(32), nullable=True),
        sa.Column("expires_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("ip_address", _varchar(64), nullable=True),
        sa.Column("user_agent", _varchar(256), nullable=True),
        sa.Column("created_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("last_seen", UTC_TIMESTAMP, nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_user_sessions_token_jti",
        "user_sessions",
        ["token_jti"],
        unique=True,
    )

    op.create_table(
        "boost_games",
        _identity_id(),
        sa.Column("account_id", _varchar(32), nullable=True),
        sa.Column("app_id", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["steam_accounts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "boost_logs",
        _identity_id(),
        sa.Column("account_id", _varchar(32), nullable=True),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.Column("account_id_snapshot", _varchar(32), nullable=True),
        sa.Column("steam_username_snapshot", _varchar(100), nullable=True),
        sa.Column("owner_user_id_snapshot", sa.BigInteger(), nullable=True),
        sa.Column("owner_username_snapshot", _varchar(80), nullable=True),
        sa.Column("started_at", UTC_TIMESTAMP, nullable=False),
        sa.Column("stopped_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("remote_stopped_at", UTC_TIMESTAMP, nullable=True),
        sa.Column("duration_seconds", sa.BigInteger(), nullable=True),
        sa.Column("duration_microseconds", sa.BigInteger(), nullable=True),
        sa.Column("games_count", sa.Integer(), nullable=True),
        sa.Column("app_ids_json", _text(), nullable=True),
        sa.CheckConstraint(
            "duration_seconds IS NOT NULL "
            "AND duration_seconds >= 0 "
            "AND duration_seconds <= 9223372036854 "
            "AND (duration_microseconds IS NULL OR ("
            "(duration_seconds = 0 AND duration_microseconds = 0) OR "
            "(duration_seconds > 0 "
            "AND duration_microseconds > (duration_seconds - 1) * 1000000 "
            "AND duration_microseconds <= duration_seconds * 1000000)))",
            name="ck_boost_logs_duration_ledger",
        ),
        sa.ForeignKeyConstraint(["account_id"], ["steam_accounts.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_boost_logs_user_window",
        "boost_logs",
        ["user_id", "stopped_at", "started_at"],
        unique=False,
    )


def downgrade():
    raise RuntimeError(
        "PostgreSQL baseline downgrade is disabled; use reviewed recovery"
    )
