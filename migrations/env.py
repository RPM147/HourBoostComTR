"""Standalone, explicitly connected migration environment; never import app.py.

This environment permits only a fresh disposable SQLite bootstrap. Existing-DB
adoption uses the standalone tool's audited transaction, not this CLI. No URL fallback,
Flask CLI integration, dotenv loading or implicit engine creation is permitted.
"""

from alembic import context
from sqlalchemy import inspect


def run_migrations():
    config = context.config
    if context.is_offline_mode():
        raise RuntimeError("Offline migration is not enabled in this phase.")
    connection = config.attributes.get("connection")
    if config.attributes.get("bootstrap_disposable") is not True or connection is None:
        raise RuntimeError("Use the standalone disposable-bootstrap entrypoint.")
    if (connection.dialect.name != "sqlite" or not connection.in_transaction()
            or not connection.connection.driver_connection.in_transaction):
        raise RuntimeError("Bootstrap requires an explicit SQLite transaction.")
    inspector = inspect(connection)
    if inspector.get_table_names() or inspector.get_view_names():
        raise RuntimeError("Bootstrap requires a completely empty database.")
    context.configure(connection=connection, transactional_ddl=True)
    with context.begin_transaction():
        context.run_migrations()


run_migrations()
