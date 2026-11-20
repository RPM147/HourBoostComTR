"""Standalone SQLite audit, empty bootstrap and controlled historical adoption.

This CLI never loads app/config/dotenv. Only explicit, backed-up adoption may
add the four reviewed indexes and stamp an existing DB. Diagnostics omit row values,
SQL text, paths, URLs, tokens or driver exception text.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import time

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.pool import NullPool


ROOT = Path(__file__).resolve().parent
BASELINE_REVISION = "20260907_01"
HEAD_REVISION = "20260908_01"
ADOPTION_INDEXES = {
    "ux_users_" + name: name for name in
    ("steam_id", "verification_token", "reset_token", "email_change_token")
}
RUNTIME_INDEXES = {
    "ux_payments_match_token", "ux_payments_transaction_id",
    "ux_payments_one_open_checkout", "ix_payments_shopier_webhook_id",
    "ix_payments_verification_due",
}
LEDGER_TRIGGERS = {
    "trg_boost_logs_duration_ledger_insert", "trg_boost_logs_duration_ledger_update",
}
USER_UNIQUE_FIELDS = ("steam_id", "verification_token", "reset_token", "email_change_token")
# Only documented historical declarations are compatible, not arbitrary affinity
# equivalence (INTEGER and REAL can materially differ for the usage ledger).
LEGACY_TYPES = {
    ("payments", "status"): "VARCHAR(20)",
    ("payments", "match_token"): "VARCHAR(32)",
    ("users", "is_verified"): "INTEGER",
    ("users", "verification_token"): "TEXT",
    ("users", "reset_token"): "TEXT",
    ("users", "email_change_token"): "TEXT",
    ("users", "email_change_new"): "TEXT",
}
_TOKENS = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`[^`]*`|\[[^\]]*\]|[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]")


class SchemaToolError(RuntimeError):
    """Constant, safe error suitable for the standalone CLI."""


def sql_tokens(value):
    """Ignore whitespace/unquoted case, preserve every quoted token exactly.

    SQLite's legacy double-quoted-string behavior makes unquoting unsafe:
    NULL and "null" can have different semantics in a predicate.
    """
    result = []
    for token in _TOKENS.findall(value or ""):
        if token[0] in ("'", '"', '`', '['):
            result.append(token)
        else:
            result.append(token.lower())
    return tuple(result)


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def _canonical_path(value, *, existing):
    path = Path(value)
    if not path.is_absolute() or path != path.resolve():
        raise SchemaToolError("An absolute canonical SQLite file path is required.")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise SchemaToolError("Symlink database paths are not permitted.")
    if not path.parent.is_dir():
        raise SchemaToolError("The database parent directory must already exist.")
    if existing:
        try:
            info = path.stat(follow_symlinks=False)
        except OSError:
            raise SchemaToolError("An existing SQLite database is required.") from None
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            raise SchemaToolError("The SQLite target must be a nonempty regular file.")
    return path


def _engine(path=None, *, readonly=False, exclusive=False):
    def connect():
        if path is None:
            conn = sqlite3.connect(":memory:", isolation_level=None)
        else:
            mode = "ro" if readonly else "rw"
            conn = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True,
                                   isolation_level=None, timeout=5)
        conn.execute("PRAGMA foreign_keys=ON")
        if readonly:
            conn.execute("PRAGMA query_only=ON")
            deadline = time.monotonic() + 30
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        return conn

    engine = create_engine("sqlite://", creator=connect, poolclass=NullPool,
                           hide_parameters=True)

    @event.listens_for(engine, "begin")
    def begin(connection):
        # Explicit BEGIN also makes SQLite DDL in a disposable rehearsal atomic.
        connection.exec_driver_sql("BEGIN EXCLUSIVE" if exclusive else "BEGIN")

    return engine


def _bootstrap_connection(connection, *, revision=HEAD_REVISION):
    from alembic import command
    from alembic.config import Config
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations").replace("%", "%%"))
    config.attributes.update(connection=connection, bootstrap_disposable=True)
    command.upgrade(config, revision)


@contextmanager
def _reference_database(*, metadata=False, revision=HEAD_REVISION):
    engine = _engine()
    try:
        with engine.begin() as connection:
            if metadata:
                # Safe model definitions only. Never call Flask db.create_all().
                from models import db
                db.metadata.create_all(connection)
            else:
                _bootstrap_connection(connection, revision=revision)
            yield connection
    finally:
        engine.dispose()


def _snapshot(connection):
    tables = {}
    raw = connection.exec_driver_sql(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name"
    ).fetchall()
    definitions = {(r[0], r[1]): r[3] for r in raw}
    for kind, name, _, ddl in raw:
        if kind != "table" or name == "alembic_version":
            continue
        columns = {
            r[1]: {"type": r[2].upper(), "notnull": bool(r[3]),
                   "default": sql_tokens(r[4]), "pk": r[5], "hidden": r[6]}
            for r in connection.exec_driver_sql("PRAGMA table_xinfo(" + _quote(name) + ")")
        }
        fk_groups = {}
        for row in connection.exec_driver_sql("PRAGMA foreign_key_list(" + _quote(name) + ")"):
            fk_groups.setdefault(row[0], []).append(tuple(row[1:]))
        foreign_keys = sorted(tuple(sorted(rows)) for rows in fk_groups.values())
        indexes, uniques, primary_indexes = {}, set(), []
        for _, index, unique, origin, partial in connection.exec_driver_sql("PRAGMA index_list(" + _quote(name) + ")"):
            keys = tuple((r[2], r[3], r[4]) for r in connection.exec_driver_sql(
                "PRAGMA index_xinfo(" + _quote(index) + ")") if r[5])
            tokens = sql_tokens(definitions.get(("index", index)))
            predicate = tokens[tokens.index("where") + 1:] if "where" in tokens else ()
            if origin == "pk":
                # INTEGER PRIMARY KEY DESC is not SQLite's rowid alias even
                # though table_xinfo reports the same PK column and type.
                primary_indexes.append(keys)
            if origin == "c":
                indexes[index] = {"keys": keys, "unique": bool(unique),
                                  "partial": bool(partial), "predicate": predicate}
            if unique and origin != "pk":
                # A single-column nullable UNIQUE and WHERE col IS NOT NULL
                # have the same uniqueness semantics in SQLite.
                if not partial or (len(keys) == 1 and predicate == (keys[0][0], "is", "not", "null")):
                    uniques.add(keys)
        checks = sorted(sql_tokens(c["sqltext"]) for c in inspect(connection).get_check_constraints(name))
        # PRAGMA reflection does not expose column collations, conflict policy,
        # deferred FKs or table storage modes. None occurs in this frozen target;
        # reject them conservatively instead of declaring false schema parity.
        ddl_tokens = sql_tokens(ddl)
        ddl_features = sorted({token for token in ddl_tokens if token in {
            "collate", "conflict", "deferrable", "deferred", "autoincrement",
            "strict", "without", "virtual", "generated",
        }})
        tables[name] = {"columns": columns, "foreign_keys": foreign_keys,
                        "ddl_features": ddl_features, "primary_indexes": sorted(primary_indexes),
                        "indexes": indexes, "unique_keys": sorted(uniques), "checks": checks}
    return {"tables": tables, "triggers": {r[1]: sql_tokens(r[3]) for r in raw if r[0] == "trigger"},
            "views": {r[1]: sql_tokens(r[3]) for r in raw if r[0] == "view"}}


def _compare(expected, actual, *, legacy=False):
    differences, compatibility = [], []

    def add(obj, issue, *, compatible=False):
        (compatibility if compatible else differences).append({"object": obj, "issue": issue})

    triggers_valid = all(actual["triggers"].get(n) == expected["triggers"].get(n) for n in LEDGER_TRIGGERS) and LEDGER_TRIGGERS <= expected["triggers"].keys()
    for name, target in expected["tables"].items():
        current = actual["tables"].get(name)
        if current is None:
            add(name, "missing_table")
            continue
        for col, definition in target["columns"].items():
            live = current["columns"].get(col)
            if live is None:
                add(name + "." + col, "missing_column")
                continue
            for attribute, desired in definition.items():
                if live[attribute] != desired:
                    compatible = legacy and attribute == "type" and live[attribute] == LEGACY_TYPES.get((name, col))
                    # This legacy INTEGER column's quoted/unquoted zero default
                    # is the same SQLite stored integer, not a behavior change.
                    compatible = compatible or (
                        legacy and (name, col, attribute) == ("payments", "verification_attempts", "default")
                        and {live[attribute], desired} == {("0",), ("'0'",)}
                    )
                    add(name + "." + col, attribute + "_mismatch", compatible=compatible)
        if current["columns"].keys() - target["columns"].keys():
            add(name, "unexpected_columns")
        for attr in ("foreign_keys", "ddl_features", "primary_indexes"):
            if target[attr] != current[attr]:
                add(name, attr + "_mismatch")
        for key in target["unique_keys"]:
            if key not in current["unique_keys"]:
                add(name + "." + ",".join(part[0] for part in key), "missing_unique_key")
        if any(key not in target["unique_keys"] for key in current["unique_keys"]):
            add(name, "unexpected_unique_keys")
        for index, specification in target["indexes"].items():
            if current["indexes"].get(index) != specification:
                add(index, "index_definition_mismatch")
        if current["indexes"].keys() - target["indexes"].keys():
            add(name, "unexpected_indexes")
        if target["checks"] != current["checks"]:
            compatible = legacy and name == "boost_logs" and not current["checks"] and triggers_valid
            add(name, "check_definition_mismatch", compatible=compatible)
    if actual["tables"].keys() - expected["tables"].keys():
        add("database", "unexpected_tables")
    for kind in ("triggers", "views"):
        for name, desired in expected[kind].items():
            if actual[kind].get(name) != desired:
                add(name, kind + "_definition_mismatch")
        if actual[kind].keys() - expected[kind].keys():
            add("database", "unexpected_" + kind)
    return differences, compatibility


def _metadata_drift(expected):
    with _reference_database(metadata=True) as connection:
        actual = _snapshot(connection)
    # The five indexes/two triggers are deliberately revision-owned additions,
    # not phantom autogenerate drift in mutable ORM definitions.
    expected = {
        **expected, "tables": {n: {**t, "indexes": {k: v for k, v in t["indexes"].items() if k not in RUNTIME_INDEXES}}
                                for n, t in expected["tables"].items()}, "triggers": {},
    }
    # Runtime UNIQUE(match_token) adds a semantic key absent from bare metadata.
    expected["tables"]["payments"] = {**expected["tables"]["payments"], "unique_keys": [
        k for k in expected["tables"]["payments"]["unique_keys"] if k != (("match_token", 0, "BINARY"),)
    ]}
    return _compare(expected, actual)[0]


def _data_summary(connection, actual):
    integrity = connection.exec_driver_sql("PRAGMA integrity_check").fetchall() == [("ok",)]
    foreign_key_violations = len(connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall())
    checks = {"integrity_ok": integrity, "foreign_key_violations": foreign_key_violations}
    tables = actual["tables"]
    if "users" in tables and all(c in tables["users"]["columns"] for c in USER_UNIQUE_FIELDS):
        checks["duplicate_user_unique_groups"] = {
            column: connection.exec_driver_sql("SELECT count(*) FROM (SELECT " + _quote(column) +
                " FROM users WHERE " + _quote(column) + " IS NOT NULL GROUP BY " + _quote(column) +
                " HAVING count(*) > 1)").scalar_one() for column in USER_UNIQUE_FIELDS
        }
    if "boost_logs" in tables and {"duration_seconds", "duration_microseconds"} <= tables["boost_logs"]["columns"].keys():
        seconds_total = microseconds_total = invalid = legacy = 0
        for seconds, microseconds in connection.exec_driver_sql("SELECT duration_seconds,duration_microseconds FROM boost_logs"):
            valid = isinstance(seconds, int) and 0 <= seconds <= 9223372036854
            if microseconds is None:
                legacy += 1
            else:
                valid = valid and isinstance(microseconds, int) and (
                    (seconds == 0 and microseconds == 0) or
                    (seconds > 0 and (seconds - 1) * 1000000 < microseconds <= seconds * 1000000))
            invalid += not valid
            if valid:
                seconds_total += seconds
                microseconds_total += microseconds if microseconds is not None else seconds * 1000000
        checks.update(invalid_ledger_rows=invalid, legacy_seconds_only_rows=legacy,
                      duration_seconds_total=seconds_total, duration_microseconds_total=microseconds_total)
    return checks


def _revision_state(connection):
    exists = connection.exec_driver_sql(
        "SELECT type FROM main.sqlite_schema WHERE name='alembic_version'"
    ).fetchall()
    if not exists:
        return "unstamped"
    if exists != [("table",)]:
        return "unexpected"
    columns = connection.exec_driver_sql("PRAGMA main.table_info(alembic_version)").fetchall()
    if len(columns) != 1 or tuple(columns[0][1:]) != ("version_num", "VARCHAR(32)", 1, None, 1):
        return "unexpected"
    versions = connection.exec_driver_sql("SELECT version_num FROM main.alembic_version").fetchall()
    if versions == [(HEAD_REVISION,)]:
        return "head"
    return "baseline" if versions == [(BASELINE_REVISION,)] else "unexpected"


def _audit_connection(connection, expected, metadata_drift, *,
                      paid_plan_names=("basic", "premium"), require_idle=False):
    from schema_preconditions import check_legacy_data
    actual = _snapshot(connection)
    differences, compatibility = _compare(expected, actual, legacy=True)
    checks = _data_summary(connection, actual)
    complete_columns = all(
        name in actual["tables"] and target["columns"].keys() <= actual["tables"][name]["columns"].keys()
        for name, target in expected["tables"].items()
    )
    legacy = check_legacy_data(connection, paid_plan_names=paid_plan_names,
                               require_idle=require_idle) if complete_columns else {
        "ok": False, "checks": {}, "scope": "incomplete_schema",
    }
    state = _revision_state(connection)
    data_ok = (checks["integrity_ok"] and checks["foreign_key_violations"] == 0
               and checks.get("invalid_ledger_rows", 0) == 0
               and not any(checks.get("duplicate_user_unique_groups", {}).values())
               and legacy["ok"])
    return {"operation": "audit", "baseline_revision": BASELINE_REVISION,
            "target_revision": HEAD_REVISION, "read_only": True,
            "schema_matches": not differences, "metadata_matches": not metadata_drift,
            "data_checks_ok": bool(data_ok), "revision_state": state,
            "ok": not differences and not metadata_drift and data_ok and state in {"head", "unstamped"},
            "stamp_permitted": False, "differences": differences,
            "compatibility_notes": compatibility, "metadata_drift": metadata_drift,
            "data_checks": checks, "legacy_data": legacy,
            "table_count": len(actual["tables"]),
            "schema_fingerprint": hashlib.sha256(repr(actual).encode()).hexdigest()}


def _reference_contract():
    with _reference_database() as connection:
        expected = _snapshot(connection)
    return expected, _metadata_drift(expected)


def audit_sqlite(value, *, paid_plan_names=("basic", "premium")):
    path = _canonical_path(value, existing=True)
    identity = path.stat()
    expected, metadata_drift = _reference_contract()
    engine = _engine(path, readonly=True)
    try:
        with engine.begin() as connection:
            result = _audit_connection(connection, expected, metadata_drift,
                                       paid_plan_names=paid_plan_names)
    finally:
        engine.dispose()
    after = path.stat()
    if (identity.st_dev, identity.st_ino) != (after.st_dev, after.st_ino):
        raise SchemaToolError("Database identity changed during audit.")
    return result


def _logical_manifest(connection, snapshot):
    """Internal complete row hashes; no row contents enter diagnostic output."""
    result = {}
    for table, spec in sorted(snapshot["tables"].items()):
        columns = sorted(spec["columns"])
        primary = sorted((value["pk"], name) for name, value in spec["columns"].items() if value["pk"])
        if not primary:
            raise SchemaToolError("A stable primary key is required for adoption.")
        sql = "SELECT " + ",".join(map(_quote, columns)) + " FROM " + _quote(table)
        sql += " ORDER BY " + ",".join(_quote(name) for _, name in primary)
        digest, count = hashlib.sha256(), 0
        for row in connection.exec_driver_sql(sql):
            encoded = repr(tuple(row)).encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            count += 1
        result[table] = {"columns": columns, "rows": count, "sha256": digest.hexdigest()}
    return result


def _stamp_adopted_connection(connection):
    # Public low-level API uses the SAME already audited transaction. Keep
    # env.py closed to all generic existing-database CLI stamp/upgrade calls.
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory
    if (not connection.in_transaction()
            or not connection.connection.driver_connection.in_transaction
            or _revision_state(connection) != "unstamped"):
        raise SchemaToolError("Stamp requires the audited adoption transaction.")
    script = ScriptDirectory(str(ROOT / "migrations"))
    if script.get_heads() != [HEAD_REVISION]:
        raise SchemaToolError("The adoption migration head is not supported.")
    MigrationContext.configure(connection, opts={"transactional_ddl": True}).stamp(
        script, HEAD_REVISION
    )


def _assert_adoption_candidate(report, actual):
    if (not report["metadata_matches"] or not report["data_checks_ok"]
            or report["revision_state"] != "unstamped"):
        raise SchemaToolError("Adoption preconditions were not satisfied.")
    allowed = {
        ("users." + name, "missing_unique_key") for name in ADOPTION_INDEXES.values()
    } | {(name, "index_definition_mismatch") for name in ADOPTION_INDEXES}
    if any((item["object"], item["issue"]) not in allowed for item in report["differences"]):
        raise SchemaToolError("Unrecognized schema drift prevents adoption.")
    for name in ADOPTION_INDEXES:
        if any(item["object"] == name for item in report["differences"]):
            if name in actual["tables"]["users"]["indexes"]:
                raise SchemaToolError("An existing adoption index has an unexpected definition.")


def adopt_sqlite(value, *, backup_path, expected_fingerprint, confirm_maintenance=False,
                 paid_plan_names=("basic", "premium")):
    try:
        return _adopt_sqlite(value, backup_path=backup_path,
                             expected_fingerprint=expected_fingerprint,
                             confirm_maintenance=confirm_maintenance,
                             paid_plan_names=paid_plan_names)
    except SchemaToolError:
        raise
    except Exception:
        raise SchemaToolError("The adoption transaction could not be completed.") from None


def _adopt_sqlite(value, *, backup_path, expected_fingerprint, confirm_maintenance=False,
                  paid_plan_names=("basic", "premium")):
    """Adopt a recognized historical DB without rebuilding or changing any row.

    The operator must stop all writers and provide an independently created,
    consistent backup. Its full logical contents/schema are checked while the
    target has an exclusive write transaction. This is not an online migration.
    """
    if confirm_maintenance is not True or not re.fullmatch(r"[0-9a-f]{64}", str(expected_fingerprint)):
        raise SchemaToolError("Explicit maintenance confirmation and audit fingerprint are required.")
    path = _canonical_path(value, existing=True)
    backup = _canonical_path(backup_path, existing=True)
    identity = path.stat()
    backup_identity = backup.stat()
    if identity.st_nlink != 1 or backup_identity.st_nlink != 1 or path == backup or path.samefile(backup):
        raise SchemaToolError("An independent backup and single-link target are required.")
    if os.name != "nt" and backup_identity.st_mode & 0o077:
        raise SchemaToolError("The adoption backup must be private to its owner.")
    expected, metadata_drift = _reference_contract()
    # Reference engines are closed before acquiring the live write transaction.
    backup_engine = _engine(backup, readonly=True)
    try:
        with backup_engine.begin() as connection:
            backup_snapshot = _snapshot(connection)
            backup_manifest = _logical_manifest(connection, backup_snapshot)
    finally:
        backup_engine.dispose()
    engine = _engine(path, exclusive=True)
    try:
        with engine.begin() as connection:
            current = path.stat()
            if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino):
                raise SchemaToolError("Database identity changed before adoption.")
            before = _audit_connection(connection, expected, metadata_drift,
                                        paid_plan_names=paid_plan_names, require_idle=True)
            if before["revision_state"] == "head" and before["ok"]:
                return {**before, "operation": "adopt_sqlite", "changed": False}
            if before["schema_fingerprint"] != expected_fingerprint:
                raise SchemaToolError("Database schema changed since the approved audit.")
            actual = _snapshot(connection)
            _assert_adoption_candidate(before, actual)
            manifest_before = _logical_manifest(connection, actual)
            if actual != backup_snapshot or manifest_before != backup_manifest:
                raise SchemaToolError("Backup contents do not match the locked database.")
            for index, column in ADOPTION_INDEXES.items():
                if index not in actual["tables"]["users"]["indexes"]:
                    connection.exec_driver_sql(
                        "CREATE UNIQUE INDEX " + _quote(index) + " ON users (" + _quote(column) + ")"
                    )
            ready = _audit_connection(connection, expected, metadata_drift,
                                       paid_plan_names=paid_plan_names, require_idle=True)
            if not ready["ok"] or ready["revision_state"] != "unstamped":
                raise SchemaToolError("Adopted schema failed verification before stamping.")
            _stamp_adopted_connection(connection)
            after = _audit_connection(connection, expected, metadata_drift,
                                       paid_plan_names=paid_plan_names, require_idle=True)
            if not after["ok"] or after["revision_state"] != "head":
                raise SchemaToolError("Adopted revision failed verification.")
            if _logical_manifest(connection, _snapshot(connection)) != manifest_before:
                raise SchemaToolError("Adoption changed application data; transaction refused.")
            current = path.stat()
            if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino):
                raise SchemaToolError("Database identity changed during adoption.")
        return {**after, "operation": "adopt_sqlite", "read_only": False,
                "changed": True, "application_rows_unchanged": True}
    finally:
        engine.dispose()


def assert_runtime_schema(engine, migrations_dir, *, paid_plan_names=("basic", "premium")):
    """Read-only startup gate; never repair schema, stamp, or legacy data."""
    from runtime_guardrails import RuntimeConfigError, assert_alembic_at_head
    try:
        if engine.dialect.name != "sqlite":
            raise SchemaToolError("SQLite is the only enabled runtime backend.")
        if assert_alembic_at_head(engine, migrations_dir) != HEAD_REVISION:
            raise SchemaToolError("The runtime migration head is not supported.")
        expected, metadata_drift = _reference_contract()
        with engine.connect() as connection:
            driver = connection.connection.driver_connection
            previous_query_only = connection.exec_driver_sql("PRAGMA query_only").scalar_one()
            try:
                if driver.in_transaction:
                    raise SchemaToolError("Runtime audit requires a clean connection.")
                connection.exec_driver_sql("PRAGMA query_only=ON")
                connection.exec_driver_sql("BEGIN")
                deadline = time.monotonic() + 30
                driver.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
                report = _audit_connection(connection, expected, metadata_drift,
                                           paid_plan_names=paid_plan_names)
            finally:
                driver.set_progress_handler(None, 0)
                connection.rollback()
                connection.exec_driver_sql("PRAGMA query_only=" + str(int(previous_query_only)))
                connection.rollback()
        if not report["ok"] or report["revision_state"] != "head":
            raise SchemaToolError("Runtime schema or legacy data requires offline attention.")
    except Exception:
        raise RuntimeConfigError(
            "Runtime schema validation failed; run the standalone read-only audit."
        ) from None
    return HEAD_REVISION


def bootstrap_disposable(value):
    path = _canonical_path(value, existing=False)
    if path.exists():
        raise SchemaToolError("Bootstrap requires a new, unused database filename.")
    # Never open the caller's destination for writing. Build in our private
    # same-filesystem directory, verify it, then atomically publish with link()
    # (which cannot overwrite an existing file or follow a destination symlink).
    # This also closes the create-close-reopen filename race.
    temporary = Path(tempfile.mkdtemp(prefix=".hourboost-bootstrap-", dir=path.parent))
    resolved = temporary.resolve()
    if resolved != temporary or resolved.parent != path.parent:
        raise SchemaToolError("Private bootstrap directory identity changed.")
    try:
        candidate = temporary / "candidate.sqlite"
        fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        engine = _engine(candidate)
        try:
            with engine.begin() as connection:
                _bootstrap_connection(connection)
        finally:
            engine.dispose()
        result = audit_sqlite(str(candidate))
        if not result["ok"]:
            raise SchemaToolError("The disposable baseline failed its own audit.")
        with candidate.open("r+b") as handle:
            os.fsync(handle.fileno())
        try:
            os.link(candidate, path)
        except OSError:
            raise SchemaToolError("Atomic publication requires an unused filename and hard-link support.") from None
    finally:
        # Delete only the exact private directory created by this invocation.
        if temporary.resolve() != resolved or resolved.parent != path.parent:
            raise SchemaToolError("Private bootstrap cleanup refused after identity change.")
        shutil.rmtree(temporary)
    result.update(operation="bootstrap_disposable", read_only=False, existing_database_touched=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("audit", "bootstrap-disposable", "adopt-sqlite"))
    parser.add_argument("--sqlite-path", required=True)
    parser.add_argument("--backup-path")
    parser.add_argument("--expect-fingerprint")
    parser.add_argument("--confirm-maintenance", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "audit":
            result = audit_sqlite(args.sqlite_path)
        elif args.action == "bootstrap-disposable":
            result = bootstrap_disposable(args.sqlite_path)
        else:
            result = adopt_sqlite(args.sqlite_path, backup_path=args.backup_path,
                                 expected_fingerprint=args.expect_fingerprint,
                                 confirm_maintenance=args.confirm_maintenance)
    except Exception:
        # Even malformed DB schema and driver exceptions can contain arbitrary
        # data. Keep CLI failures constant; no traceback/URL/path/token leakage.
        print(json.dumps({"ok": False, "error": "schema_operation_failed", "stamp_permitted": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
