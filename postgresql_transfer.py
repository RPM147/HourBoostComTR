"""Fail-closed SQLite-to-PostgreSQL transfer for Phase 5H.1C rehearsals.

The module never reads application configuration or a database URL.  Callers
must supply a canonical, read-only SQLite backup and an already-open hidden-
parameter PostgreSQL connection inside an explicit outer transaction.  The
caller owns the success commit; any failure rolls back the explicit target
transaction.  The real-server A2 acceptance suite remains mandatory.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import re
import sqlite3

import sqlalchemy as sa

from postgresql_contract import (
    BIGINT_COLUMNS,
    BOOLEAN_COLUMNS,
    CHECK_CONSTRAINTS,
    FLOAT64_COLUMNS,
    FOREIGN_KEYS,
    IDENTITY_TABLES,
    INDEX_CONTRACT,
    INTEGER_COLUMNS,
    PHYSICAL_NOT_NULL_COLUMNS,
    POSTGRESQL_BASELINE_REVISION,
    POSTGRESQL17_EXPRESSION_FORMS,
    PRIMARY_KEYS,
    SERVER_DEFAULTS,
    TABLE_COLUMNS,
    TEXT_COLLATION,
    TEXT_LIMITS,
    TRANSFER_TABLES,
    UNIQUE_CONSTRAINTS,
    UTC_DATETIME_COLUMNS,
    boost_ledger_totals,
    digest_ordered_rows,
    identity_restart_value,
    normalize_row_for_postgresql,
    payment_minor_total,
)


SQLITE_SOURCE_REVISION = "20260908_01"
DEFAULT_BATCH_SIZE = 500
MAX_BATCH_SIZE = 5_000
_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")


class PostgreSQLTransferError(RuntimeError):
    """Constant, secret-safe failure for a rejected or failed transfer."""


def _canonical_source_path(value) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute() or path != path.resolve(strict=True):
            raise ValueError
        if not path.is_file() or path.is_symlink():
            raise ValueError
        if hasattr(path, "is_junction") and path.is_junction():
            raise ValueError
        if path.stat().st_size <= 0:
            raise ValueError
        for suffix in ("-wal", "-shm", "-journal"):
            if Path(str(path) + suffix).exists():
                raise ValueError
    except (OSError, RuntimeError, TypeError, ValueError):
        raise PostgreSQLTransferError(
            "SQLite source must be a canonical standalone backup file."
        ) from None
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise PostgreSQLTransferError("SQLite source could not be read.") from None
    return digest.hexdigest()


def _sqlite_identifier(value: str) -> str:
    # Every identifier comes from the frozen contract; this assertion prevents
    # later refactors from accidentally turning the source reader into raw SQL
    # interpolation over caller input.
    if value not in TABLE_COLUMNS and not any(
        value in columns for columns in TABLE_COLUMNS.values()
    ):
        raise PostgreSQLTransferError("SQLite contract identifier is invalid.")
    return '"' + value.replace('"', '""') + '"'


def _validate_batch_size(value) -> int:
    if type(value) is not int or not 1 <= value <= MAX_BATCH_SIZE:
        raise PostgreSQLTransferError("Transfer batch size is invalid.")
    return value


@contextmanager
def open_sqlite_backup(value):
    """Open a standalone SQLite backup under one read-only snapshot."""

    connection = None
    try:
        path = _canonical_source_path(value)
        initial_stat = path.stat()
        initial_identity = (
            initial_stat.st_dev,
            initial_stat.st_ino,
            initial_stat.st_size,
            initial_stat.st_mtime_ns,
        )
        initial_sha256 = _sha256_file(path)
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN")
        _validate_sqlite_source(connection)
        yield path, connection, initial_sha256
        verified_path = _canonical_source_path(path)
        final_stat = verified_path.stat()
        final_identity = (
            final_stat.st_dev,
            final_stat.st_ino,
            final_stat.st_size,
            final_stat.st_mtime_ns,
        )
        if verified_path != path or final_identity != initial_identity:
            raise PostgreSQLTransferError(
                "SQLite backup changed during the transfer snapshot."
            )
        if _sha256_file(verified_path) != initial_sha256:
            raise PostgreSQLTransferError(
                "SQLite backup changed during the transfer snapshot."
            )
    except PostgreSQLTransferError:
        raise
    except (OSError, sqlite3.Error):
        raise PostgreSQLTransferError(
            "SQLite backup validation failed."
        ) from None
    finally:
        if connection is not None:
            try:
                connection.rollback()
            finally:
                connection.close()


def _validate_sqlite_source(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or integrity[0] != "ok":
        raise PostgreSQLTransferError("SQLite backup integrity check failed.")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise PostgreSQLTransferError("SQLite backup foreign keys are invalid.")

    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
        if row[0] != "sqlite_sequence"
    }
    expected = set(TRANSFER_TABLES) | {"alembic_version"}
    if tables != expected:
        raise PostgreSQLTransferError("SQLite backup table contract is invalid.")

    revision_rows = connection.execute(
        "SELECT version_num FROM alembic_version"
    ).fetchall()
    if [row[0] for row in revision_rows] != [SQLITE_SOURCE_REVISION]:
        raise PostgreSQLTransferError("SQLite backup revision is not accepted.")

    for table in TRANSFER_TABLES:
        pragma = connection.execute(
            "PRAGMA table_info(" + _sqlite_identifier(table) + ")"
        ).fetchall()
        if tuple(row[1] for row in pragma) != TABLE_COLUMNS[table]:
            raise PostgreSQLTransferError(
                "SQLite backup column contract is invalid."
            )


def iter_sqlite_rows(
    connection: sqlite3.Connection,
    table: str,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
):
    """Yield validated rows in strict primary-key order without mutation."""

    batch_size = _validate_batch_size(batch_size)
    if table not in TABLE_COLUMNS:
        raise PostgreSQLTransferError("SQLite source table is invalid.")
    columns = TABLE_COLUMNS[table]
    projection = ", ".join(_sqlite_identifier(column) for column in columns)
    primary_key = _sqlite_identifier(PRIMARY_KEYS[table])
    cursor = connection.execute(
        f"SELECT {projection} FROM {_sqlite_identifier(table)} "
        f"ORDER BY {primary_key} ASC"
    )
    while True:
        batch = cursor.fetchmany(batch_size)
        if not batch:
            break
        for row in batch:
            yield {column: row[column] for column in columns}


def _source_evidence(connection: sqlite3.Connection) -> dict:
    tables = {
        table: digest_ordered_rows(
            table,
            iter_sqlite_rows(connection, table),
        )
        for table in TRANSFER_TABLES
    }
    return {
        "tables": tables,
        "boost_ledger": boost_ledger_totals(
            iter_sqlite_rows(connection, "boost_logs")
        ),
        "payment_minor": payment_minor_total(
            iter_sqlite_rows(connection, "payments")
        ),
    }


def inspect_sqlite_backup(value) -> dict:
    """Return only sanitized counts/digests/totals for an accepted backup."""

    with open_sqlite_backup(value) as (_path, connection, source_sha256):
        evidence = _source_evidence(connection)
        evidence["source_sha256"] = source_sha256
        evidence["source_revision"] = SQLITE_SOURCE_REVISION
        return evidence


def _normalized_server_default(column) -> str | None:
    default = column.server_default
    if default is None:
        return None
    tokens = _sql_expression_tokens(getattr(default, "arg", default))
    while len(tokens) >= 3 and tokens[0] == "(" and tokens[-1] == ")":
        depth = 0
        wraps_entire_expression = True
        for index, token in enumerate(tokens):
            depth += (token == "(") - (token == ")")
            if depth == 0 and index != len(tokens) - 1:
                wraps_entire_expression = False
                break
        if not wraps_entire_expression or depth != 0:
            break
        tokens = tokens[1:-1]
    if not tokens:
        return "<unsupported-default>"
    literal = re.fullmatch(r"'((?:''|[^'])*)'", tokens[0])
    if literal and tokens[1:] in {(), ("::", "text"), ("::", "character", "varying")}:
        # A cast is syntax only after the closing quote, never within the value.
        return literal.group(1).replace("''", "'")
    if len(tokens) == 1 and (
        tokens[0] in {"true", "false"} or re.fullmatch(r"[0-9]+", tokens[0])
    ):
        return tokens[0]
    return "<unsupported-default>"


def _sql_expression_tokens(value) -> tuple[str, ...]:
    tokens = re.findall(
        r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|[a-zA-Z_][a-zA-Z_0-9]*|[0-9]+|::|<=|>=|<>|!=|[^\s]",
        str(value),
    )
    return tuple(token if token.startswith(("'", '"')) else token.lower() for token in tokens)


def _normalized_sql_expression(value) -> tuple[str, ...]:
    tokens = _sql_expression_tokens(value)
    for canonical, observed_forms in POSTGRESQL17_EXPRESSION_FORMS.items():
        if tokens in {_sql_expression_tokens(form) for form in observed_forms}:
            return _sql_expression_tokens(canonical)
    return tokens


def _validate_postgresql_catalog(connection, schema: str) -> None:
    """Enforce catalog flags not fully represented by SQLAlchemy reflection."""
    unexpected = connection.execute(sa.text(
        "SELECT 1 FROM pg_catalog.pg_constraint c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace "
        "WHERE n.nspname=:schema AND (c.condeferrable OR c.condeferred "
        "OR NOT c.convalidated OR (c.contype='c' AND c.connoinherit) "
        "OR c.contype NOT IN ('p','u','f','c') "
        "OR (c.contype='f' AND (c.confmatchtype <> 's' "
        "OR c.confupdtype <> 'a' OR c.confdeltype <> 'a'))) "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_trigger t "
        "JOIN pg_catalog.pg_class r ON r.oid=t.tgrelid "
        "JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace "
        "WHERE n.nspname=:schema AND NOT t.tgisinternal "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_class r "
        "JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace "
        "WHERE n.nspname=:schema AND (r.relkind NOT IN ('r','i','S') "
        "OR r.relpersistence <> 'p' OR r.relrowsecurity OR r.relforcerowsecurity OR r.relispartition) "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_index i "
        "JOIN pg_catalog.pg_class r ON r.oid=i.indexrelid "
        "JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace "
        "WHERE n.nspname=:schema AND (NOT i.indisvalid OR NOT i.indisready "
        "OR NOT i.indislive OR NOT i.indimmediate OR i.indnullsnotdistinct) "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=:schema "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_rewrite w "
        "JOIN pg_catalog.pg_class r ON r.oid=w.ev_class "
        "JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=:schema "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_type t "
        "JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace "
        "WHERE n.nspname=:schema AND t.typtype IN ('d','e','r','m') "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_inherits h "
        "JOIN pg_catalog.pg_class child ON child.oid=h.inhrelid "
        "JOIN pg_catalog.pg_class parent ON parent.oid=h.inhparent "
        "JOIN pg_catalog.pg_namespace cn ON cn.oid=child.relnamespace "
        "JOIN pg_catalog.pg_namespace pn ON pn.oid=parent.relnamespace "
        "WHERE cn.nspname=:schema OR pn.nspname=:schema LIMIT 1"
    ), {"schema": schema}).first()
    if unexpected is not None:
        raise PostgreSQLTransferError("PostgreSQL target catalog contract is invalid.")

    inspector = sa.inspect(connection)
    columns = inspector.get_columns("alembic_version", schema=schema)
    if len(columns) != 1:
        raise PostgreSQLTransferError("PostgreSQL version table contract is invalid.")
    column = columns[0]
    if (
        column["name"] != "version_num" or column["nullable"] is not False
        or not isinstance(column["type"], sa.VARCHAR) or column["type"].length != 32
        or column.get("default") is not None or column.get("identity") is not None
        or column.get("computed") is not None
        or inspector.get_pk_constraint("alembic_version", schema=schema)["constrained_columns"] != ["version_num"]
        or inspector.get_unique_constraints("alembic_version", schema=schema)
        or inspector.get_check_constraints("alembic_version", schema=schema)
        or inspector.get_foreign_keys("alembic_version", schema=schema)
        or inspector.get_indexes("alembic_version", schema=schema)
    ):
        raise PostgreSQLTransferError("PostgreSQL version table contract is invalid.")


def _validate_postgresql_column_contract(table_name: str, column) -> None:
    key = (table_name, column.name)
    expected_nullable = key not in PHYSICAL_NOT_NULL_COLUMNS
    if column.nullable is not expected_nullable:
        raise PostgreSQLTransferError("PostgreSQL target column contract is invalid.")

    column_type = column.type
    if key in UTC_DATETIME_COLUMNS:
        valid_type = isinstance(column_type, sa.DateTime) and bool(
            getattr(column_type, "timezone", False)
        )
        valid_type = valid_type and getattr(column_type, "precision", None) in (
            None,
            6,
        )
    elif key in BOOLEAN_COLUMNS:
        valid_type = isinstance(column_type, sa.Boolean)
    elif key in FLOAT64_COLUMNS:
        valid_type = isinstance(column_type, sa.Double)
    elif key in BIGINT_COLUMNS:
        valid_type = isinstance(column_type, sa.BigInteger)
    elif key in INTEGER_COLUMNS:
        valid_type = isinstance(column_type, sa.Integer) and not isinstance(
            column_type, sa.BigInteger
        )
    elif key in TEXT_LIMITS:
        limit = TEXT_LIMITS[key]
        if limit is None:
            valid_type = isinstance(column_type, sa.Text)
        else:
            valid_type = (
                isinstance(column_type, sa.String)
                and not isinstance(column_type, sa.Text)
                and column_type.length == limit
            )
        valid_type = valid_type and column_type.collation == TEXT_COLLATION
    else:
        valid_type = False
    if not valid_type:
        raise PostgreSQLTransferError("PostgreSQL target column contract is invalid.")

    expected_identity = table_name in IDENTITY_TABLES and column.name == "id"
    if (column.identity is not None) is not expected_identity:
        raise PostgreSQLTransferError("PostgreSQL target identity contract is invalid.")
    if expected_identity and column.identity.always is not False:
        raise PostgreSQLTransferError("PostgreSQL target identity contract is invalid.")
    if expected_identity:
        identity = column.identity
        identity_contract = {
            "start": (None, 1),
            "increment": (None, 1),
            "minvalue": (None, 1),
            "maxvalue": (None, 9_223_372_036_854_775_807),
            "nominvalue": (None, False),
            "nomaxvalue": (None, False),
            "cycle": (None, False),
            "cache": (None, 1),
            "order": (None, False),
            "on_null": (None, False),
        }
        if any(
            getattr(identity, field, None) not in accepted
            for field, accepted in identity_contract.items()
        ):
            raise PostgreSQLTransferError(
                "PostgreSQL target identity contract is invalid."
            )

    expected_default = SERVER_DEFAULTS.get(key)
    expected_default = (
        str(expected_default).lower() if expected_default is not None else None
    )
    actual_default = (
        None if expected_identity else _normalized_server_default(column)
    )
    if actual_default != expected_default:
        raise PostgreSQLTransferError("PostgreSQL target default contract is invalid.")


def _validate_postgresql_table_contract(tables) -> None:
    actual_foreign_keys = {}
    actual_unique = {}
    actual_checks = {}
    actual_indexes = {}

    for table_name, table in tables.items():
        if tuple(column.name for column in table.columns) != TABLE_COLUMNS[table_name]:
            raise PostgreSQLTransferError("PostgreSQL target columns are invalid.")
        if tuple(column.name for column in table.primary_key.columns) != (
            PRIMARY_KEYS[table_name],
        ):
            raise PostgreSQLTransferError("PostgreSQL target primary key is invalid.")
        if (
            table.primary_key.deferrable is not None
            or table.primary_key.initially is not None
        ):
            raise PostgreSQLTransferError("PostgreSQL target primary key is invalid.")
        for column in table.columns:
            _validate_postgresql_column_contract(table_name, column)

        for foreign_key in table.foreign_keys:
            foreign_key_key = (table_name, foreign_key.parent.name)
            if foreign_key_key in actual_foreign_keys:
                raise PostgreSQLTransferError(
                    "PostgreSQL target foreign key contract is invalid."
                )
            actual_foreign_keys[foreign_key_key] = (
                foreign_key.column.table.name,
                foreign_key.column.name,
            )
            constraint = foreign_key.constraint
            if (
                foreign_key.ondelete is not None
                or foreign_key.onupdate is not None
                or constraint.deferrable is not None
                or constraint.initially is not None
                or constraint.use_alter
            ):
                raise PostgreSQLTransferError(
                    "PostgreSQL target foreign key contract is invalid."
                )
            expected_parent = FOREIGN_KEYS.get((table_name, foreign_key.parent.name))
            if (
                expected_parent is None
                or foreign_key.column.table is not tables[expected_parent[0]]
            ):
                raise PostgreSQLTransferError(
                    "PostgreSQL target foreign key contract is invalid."
                )

        for constraint in table.constraints:
            if isinstance(constraint, sa.UniqueConstraint):
                options = constraint.dialect_options["postgresql"]
                if (
                    constraint.deferrable is not None
                    or constraint.initially is not None
                    or options.get("include") not in (None, (), [])
                    or options.get("nulls_not_distinct") not in (None, False)
                ):
                    raise PostgreSQLTransferError(
                        "PostgreSQL target unique contract is invalid."
                    )
                actual_unique[(table_name, constraint.name)] = tuple(
                    column.name for column in constraint.columns
                )
            elif isinstance(constraint, sa.CheckConstraint):
                actual_checks[(table_name, constraint.name)] = (
                    _normalized_sql_expression(constraint.sqltext)
                )

        for index in table.indexes:
            options = index.dialect_options["postgresql"]
            where = options.get("where")
            if (
                options.get("using") not in (None, False, "btree")
                or options.get("include") not in (None, (), [])
                or options.get("ops") not in (None, {})
                or options.get("with") not in (None, {})
                or options.get("tablespace") not in (None, False)
                or options.get("concurrently") not in (None, False)
                or options.get("nulls_not_distinct") not in (None, False)
            ):
                raise PostgreSQLTransferError(
                    "PostgreSQL target index contract is invalid."
                )
            actual_indexes[index.name] = (
                table_name,
                tuple(column.name for column in index.columns),
                bool(index.unique),
                None if where is None else _normalized_sql_expression(where),
            )

    if actual_foreign_keys != FOREIGN_KEYS:
        raise PostgreSQLTransferError(
            "PostgreSQL target foreign key contract is invalid."
        )
    if actual_unique != UNIQUE_CONSTRAINTS:
        raise PostgreSQLTransferError("PostgreSQL target unique contract is invalid.")

    expected_checks = {
        key: _normalized_sql_expression(expression)
        for key, expression in CHECK_CONSTRAINTS.items()
    }
    if actual_checks != expected_checks:
        raise PostgreSQLTransferError("PostgreSQL target check contract is invalid.")

    expected_indexes = {
        name: (
            table_name,
            columns,
            unique,
            None if predicate is None else _normalized_sql_expression(predicate),
        )
        for name, (table_name, columns, unique, predicate) in INDEX_CONTRACT.items()
    }
    if actual_indexes != expected_indexes:
        raise PostgreSQLTransferError("PostgreSQL target index contract is invalid.")


def _postgresql_target_revision(connection, schema: str) -> str:
    if not isinstance(schema, str) or _IDENTIFIER.fullmatch(schema) is None:
        raise PostgreSQLTransferError("PostgreSQL target schema is invalid.")
    rows = connection.execute(
        sa.text(f'SELECT version_num FROM "{schema}".alembic_version')
    ).scalars().all()
    if rows != [POSTGRESQL_BASELINE_REVISION]:
        raise PostgreSQLTransferError(
            "PostgreSQL target revision is not accepted."
        )
    return rows[0]


def _postgresql_target_tables(connection, schema: str):
    if not isinstance(schema, str) or _IDENTIFIER.fullmatch(schema) is None:
        raise PostgreSQLTransferError("PostgreSQL target schema is invalid.")
    if connection.dialect.name != "postgresql" or not connection.in_transaction():
        raise PostgreSQLTransferError(
            "PostgreSQL transfer requires an explicit target transaction."
        )
    engine = getattr(connection, "engine", None)
    if engine is None or getattr(engine, "hide_parameters", False) is not True:
        raise PostgreSQLTransferError(
            "PostgreSQL transfer requires hidden SQL parameters."
        )
    current_schema = connection.execute(
        sa.text("SELECT current_schema()")
    ).scalar_one()
    if current_schema != schema:
        raise PostgreSQLTransferError("PostgreSQL target schema is not current.")

    _postgresql_target_revision(connection, schema)

    inspector = sa.inspect(connection)
    names = set(inspector.get_table_names(schema=schema))
    if names != set(TRANSFER_TABLES) | {"alembic_version"}:
        raise PostgreSQLTransferError("PostgreSQL target tables are invalid.")

    _validate_postgresql_catalog(connection, schema)

    metadata = sa.MetaData()
    metadata.reflect(
        bind=connection,
        schema=schema,
        only=TRANSFER_TABLES,
    )
    tables = {
        table: metadata.tables[f"{schema}.{table}"]
        for table in TRANSFER_TABLES
    }
    _validate_postgresql_table_contract(tables)
    for table in tables.values():
        count = connection.execute(
            sa.select(sa.func.count()).select_from(table)
        ).scalar_one()
        if count != 0:
            raise PostgreSQLTransferError("PostgreSQL target is not empty.")
    return tables


def _load_table(
    source: sqlite3.Connection,
    target,
    table_name: str,
    table,
    *,
    batch_size: int,
) -> None:
    batch = []
    for row in iter_sqlite_rows(source, table_name, batch_size=batch_size):
        batch.append(normalize_row_for_postgresql(table_name, row))
        if len(batch) >= batch_size:
            target.execute(table.insert(), batch)
            batch.clear()
    if batch:
        target.execute(table.insert(), batch)


def _reset_identities(source, target, tables, schema: str) -> dict[str, int]:
    if not isinstance(schema, str) or _IDENTIFIER.fullmatch(schema) is None:
        raise PostgreSQLTransferError("PostgreSQL target schema is invalid.")
    planned = {}
    for table_name in sorted(IDENTITY_TABLES):
        primary_key = PRIMARY_KEYS[table_name]
        maximum = source.execute(
            "SELECT MAX(" + _sqlite_identifier(primary_key) + ") "
            "FROM " + _sqlite_identifier(table_name)
        ).fetchone()[0]
        next_value = identity_restart_value(table_name, maximum)
        qualified_table = f'"{schema}"."{table_name}"'
        if type(next_value) is not int or not 1 <= next_value <= 9_223_372_036_854_775_807:
            raise PostgreSQLTransferError(
                "PostgreSQL identity restart value is invalid."
            )
        # setval() is NOT rolled back by PostgreSQL. Identity RESTART is
        # transactional, so failed parity/commit cannot leave modified counters.
        # DDL accepts no bind parameter here: identifiers are contract-owned,
        # schema is allowlisted, and the numeric literal is a bounded integer.
        target.execute(sa.text(
            f'ALTER TABLE {qualified_table} ALTER COLUMN "{primary_key}" '
            f"RESTART WITH {next_value}"
        ))
        planned[table_name] = next_value
    return planned


def _target_rows(target, table_name: str, table):
    statement = sa.select(*table.columns).order_by(
        table.c[PRIMARY_KEYS[table_name]].asc()
    )
    yield from target.execute(statement).mappings()


def _target_evidence(target, tables) -> dict:
    evidence = {
        "tables": {
            table_name: digest_ordered_rows(
                table_name,
                _target_rows(target, table_name, tables[table_name]),
            )
            for table_name in TRANSFER_TABLES
        }
    }
    evidence["boost_ledger"] = boost_ledger_totals(
        _target_rows(target, "boost_logs", tables["boost_logs"])
    )
    evidence["payment_minor"] = payment_minor_total(
        _target_rows(target, "payments", tables["payments"])
    )
    return evidence


def transfer_sqlite_backup(
    source_path,
    target_connection,
    *,
    target_schema: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> dict:
    """Load and verify a backup without committing the caller's transaction."""

    try:
        batch_size = _validate_batch_size(batch_size)
        with open_sqlite_backup(source_path) as (_path, source, source_sha256):
            source_evidence = _source_evidence(source)
            tables = _postgresql_target_tables(target_connection, target_schema)
            for table_name in TRANSFER_TABLES:
                _load_table(
                    source,
                    target_connection,
                    table_name,
                    tables[table_name],
                    batch_size=batch_size,
                )
            identities = _reset_identities(
                source,
                target_connection,
                tables,
                target_schema,
            )
            target_evidence = _target_evidence(target_connection, tables)
            if source_evidence != target_evidence:
                raise PostgreSQLTransferError(
                    "PostgreSQL transfer parity check failed."
                )
            return {
                "source_revision": SQLITE_SOURCE_REVISION,
                "target_revision": POSTGRESQL_BASELINE_REVISION,
                "source_sha256": source_sha256,
                "tables": source_evidence["tables"],
                "boost_ledger": source_evidence["boost_ledger"],
                "payment_minor": source_evidence["payment_minor"],
                "identity_next_values": identities,
            }
    except BaseException as exc:
        # A failed transfer must never leave a committable partial target.  The
        # caller still owns the success commit, but failure invalidates and
        # rolls back the explicit outer transaction before returning control.
        try:
            target_connection.rollback()
        except Exception:
            pass
        if not isinstance(exc, Exception):
            raise
        if isinstance(exc, PostgreSQLTransferError):
            raise
        # Raw driver exceptions can contain connection details or bound values.
        # Log only this constant public error.
        raise PostgreSQLTransferError("PostgreSQL transfer failed.") from None
