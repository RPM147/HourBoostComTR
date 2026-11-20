"""Freeze safe SQLite defaults and named nullable-user uniqueness.

Revision ID: 20260908_01
Revises: 20260907_01

This revision runs only as part of a fresh disposable SQLite bootstrap. Its
table rebuilds must never be used to adopt a populated historical database.
The separate, guarded adoption entrypoint verifies the historical defaults,
adds the four exact indexes in place and stamps only after its full audit.

No mutable application/model/configuration imports are permitted here.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260908_01"
down_revision = "20260907_01"
branch_labels = None
depends_on = None


_APPLICATION_TABLES = (
    "announcements", "boost_games", "boost_logs", "payment_audit_logs",
    "payments", "revoked_tokens", "steam_accounts", "user_sessions", "users",
)
_USER_UNIQUE_FIELDS = (
    "steam_id", "verification_token", "reset_token", "email_change_token",
)


def _require_empty_bootstrap() -> None:
    context = op.get_context()
    if context.as_sql or context.dialect.name != "sqlite":
        raise RuntimeError("This revision requires an online SQLite bootstrap")
    connection = op.get_bind()
    if connection is None or not connection.in_transaction():
        raise RuntimeError("This revision requires an explicit SQLite transaction")
    # SQLAlchemy's logical autobegin alone does not guarantee transactional
    # SQLite DDL. Require the driver's actual BEGIN as well.
    if not connection.connection.driver_connection.in_transaction:
        raise RuntimeError("This revision requires an explicit SQLite transaction")
    tables = set(connection.execute(sa.text(
        "SELECT name FROM main.sqlite_master WHERE type = 'table' "
        "AND name NOT GLOB 'sqlite_*'"
    )).scalars())
    if tables != set(_APPLICATION_TABLES) | {"alembic_version"}:
        raise RuntimeError("This revision requires the complete fresh baseline")
    unexpected = connection.execute(sa.text(
        "SELECT 1 FROM main.sqlite_master WHERE type = 'view' "
        "UNION ALL SELECT 1 FROM sqlite_temp_master "
        "WHERE name NOT GLOB 'sqlite_*' LIMIT 1"
    )).first()
    if unexpected is not None:
        raise RuntimeError("This revision requires an unshadowed fresh baseline")
    versions = connection.exec_driver_sql(
        "SELECT version_num FROM main.alembic_version"
    ).scalars().all()
    if versions != [down_revision]:
        raise RuntimeError("This revision requires the exact predecessor revision")
    # Check EVERY application table before either parent table is recreated.
    # Constant internal identifiers are used, never caller-supplied SQL names.
    for table in _APPLICATION_TABLES:
        if connection.exec_driver_sql(f'SELECT 1 FROM main."{table}" LIMIT 1').first():
            raise RuntimeError("Populated databases require guarded adoption")


def upgrade() -> None:
    _require_empty_bootstrap()
    # Naming reflected constraints lets us remove only the four old unnamed
    # inline UNIQUEs. Username/email retain their uniqueness. No duplicate
    # autoindex-plus-named-index pairs are left behind for these four fields.
    with op.batch_alter_table(
        "users", recreate="always",
        naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"},
    ) as batch:
        batch.alter_column(
            "lang", existing_type=sa.String(length=5), existing_nullable=True,
            server_default="tr",
        )
        batch.alter_column(
            "is_verified", existing_type=sa.Boolean(), existing_nullable=True,
            server_default=sa.text("0"),
        )
        for field in _USER_UNIQUE_FIELDS:
            batch.drop_constraint(f"uq_users_{field}", type_="unique")

    for field in _USER_UNIQUE_FIELDS:
        # Full indexes, default ascending/BINARY order; multiple NULLs remain
        # permitted, but duplicate non-NULL identifiers cannot be inserted.
        op.create_index(f"ux_users_{field}", "users", [field], unique=True)

    with op.batch_alter_table("steam_accounts", recreate="always") as batch:
        batch.alter_column(
            "is_boosting", existing_type=sa.Boolean(), existing_nullable=True,
            server_default=sa.text("0"),
        )


def downgrade() -> None:
    raise RuntimeError(
        "SQLite adoption downgrade is disabled; use a reviewed recovery procedure"
    )
