"""Isolated Alembic environment for the HourBoost PostgreSQL baseline.

This environment is intentionally unusable through a URL in an ini file.  A
reviewed rehearsal/cutover runner must inject an already-open PostgreSQL
Connection inside an explicit transaction through ``config.attributes``.
Importing the Flask app, dotenv, or runtime configuration here is forbidden.
"""

from alembic import context


def _injected_connection():
    connection = context.config.attributes.get("connection")
    if connection is None:
        raise RuntimeError(
            "PostgreSQL migrations require an injected online connection"
        )
    if connection.dialect.name != "postgresql":
        raise RuntimeError("PostgreSQL migrations reject non-PostgreSQL targets")
    if not connection.in_transaction():
        raise RuntimeError(
            "PostgreSQL migrations require an explicit outer transaction"
        )
    return connection


def run_migrations_offline():
    raise RuntimeError("Offline PostgreSQL migration execution is disabled")


def run_migrations_online():
    connection = _injected_connection()
    context.configure(
        connection=connection,
        target_metadata=None,
        transactional_ddl=True,
        transaction_per_migration=False,
        compare_type=True,
        compare_server_default=True,
    )
    # The caller owns the outer transaction. Alembic participates in it; the
    # caller alone may publish or roll back the complete schema/data rehearsal.
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
