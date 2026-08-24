"""Forward-only, lossless BoostLog history migration helpers.

The migration keeps operational foreign keys nullable and preserves the former
owner/account identity in immutable snapshot columns.  It never deletes or
rewrites usage measurements.
"""

from __future__ import annotations

import sqlite3

from sqlalchemy import inspect, text

from usage_ledger import (
    MAX_DURATION_MICROSECONDS,
    MICROSECONDS_PER_SECOND,
)


_SNAPSHOT_COLUMNS = {
    "account_id_snapshot": "VARCHAR(32)",
    "steam_username_snapshot": "VARCHAR(100)",
    "owner_user_id_snapshot": "INTEGER",
    "owner_username_snapshot": "VARCHAR(80)",
}


def enable_sqlite_foreign_keys(dbapi_connection) -> bool:
    """Enable and verify SQLite FK enforcement on one DB-API connection."""

    if not isinstance(dbapi_connection, sqlite3.Connection):
        return False
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA foreign_keys")
        if cursor.fetchone()[0] != 1:
            raise RuntimeError(
                "SQLite foreign-key enforcement could not be enabled"
            )
    finally:
        cursor.close()
    return True


def _scalar(conn, statement: str, parameters=None):
    return conn.execute(text(statement), parameters or {}).scalar_one()


def _changed(result) -> int:
    return max(0, int(result.rowcount or 0))


def _integer_sum(conn, statement: str) -> int:
    """Accumulate integers in Python so SQLite SUM cannot overflow."""

    total = 0
    for (value,) in conn.execute(text(statement)):
        if value is not None:
            total += int(value)
    return total


def _duration_ledger_check_sql(prefix="") -> str:
    seconds = f"{prefix}duration_seconds"
    microseconds = f"{prefix}duration_microseconds"
    maximum_seconds = (
        MAX_DURATION_MICROSECONDS // MICROSECONDS_PER_SECOND
    )
    return (
        f"{seconds} IS NULL OR {seconds} < 0 "
        f"OR {seconds} > {maximum_seconds} "
        f"OR ({microseconds} IS NOT NULL AND ("
        f"{microseconds} < 0 "
        f"OR {microseconds} > {MAX_DURATION_MICROSECONDS} "
        f"OR ({seconds} = 0 AND {microseconds} <> 0) "
        f"OR ({seconds} > 0 AND ("
        f"{microseconds} <= (CAST({seconds} AS BIGINT) - 1) "
        f"* {MICROSECONDS_PER_SECOND} "
        f"OR {microseconds} > CAST({seconds} AS BIGINT) "
        f"* {MICROSECONDS_PER_SECOND}))))"
    )


def _install_duration_ledger_enforcement(conn, dialect: str) -> int:
    """Reject invalid dual-writes while still allowing old seconds-only code."""

    constraint_name = "ck_boost_logs_duration_ledger"
    if dialect == "sqlite":
        trigger_names = {
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'trigger' AND name IN ("
                "'trg_boost_logs_duration_ledger_insert', "
                "'trg_boost_logs_duration_ledger_update')"
            ).all()
        }
        added = 0
        definitions = (
            (
                "trg_boost_logs_duration_ledger_insert",
                "BEFORE INSERT",
            ),
            (
                "trg_boost_logs_duration_ledger_update",
                "BEFORE UPDATE OF duration_seconds, duration_microseconds",
            ),
        )
        for name, event in definitions:
            if name in trigger_names:
                continue
            conn.exec_driver_sql(
                f"CREATE TRIGGER {name} {event} ON boost_logs "
                "WHEN typeof(NEW.duration_seconds) <> 'integer' "
                "OR (NEW.duration_microseconds IS NOT NULL AND "
                "typeof(NEW.duration_microseconds) <> 'integer') "
                f"OR {_duration_ledger_check_sql('NEW.')} "
                "BEGIN SELECT RAISE(ABORT, "
                "'invalid boost duration ledger'); END"
            )
            added += 1
        return added

    if dialect == "postgresql":
        constraints = {
            item.get("name")
            for item in inspect(conn).get_check_constraints("boost_logs")
        }
        if constraint_name in constraints:
            return 0
        conn.execute(text(
            "ALTER TABLE boost_logs ADD CONSTRAINT "
            f"{constraint_name} CHECK (NOT ("
            f"{_duration_ledger_check_sql()}))"
        ))
        return 1

    raise RuntimeError(
        f"Phase 5G.2 does not support database dialect: {dialect}"
    )


def migrate_boost_log_history(engine) -> dict[str, int | str]:
    """Add snapshots, detach dangling FKs, and prove accounting invariants.

    The function is intentionally idempotent.  Known blockers are checked
    before schema mutation because Python's sqlite3 legacy transaction mode
    does not reliably roll back ``ALTER TABLE``.  All data changes then run in
    one transaction; any count, duration, ownership, or FK invariant failure
    aborts startup and rolls the data migration back.
    """

    dialect = engine.dialect.name
    with engine.begin() as conn:
        table_names = set(inspect(conn).get_table_names())
        required_tables = {"boost_logs", "steam_accounts", "users"}
        missing_tables = sorted(required_tables - table_names)
        if missing_tables:
            raise RuntimeError(
                "Phase 5F migration requires tables: "
                + ", ".join(missing_tables)
            )

        columns = {
            column["name"]
            for column in inspect(conn).get_columns("boost_logs")
        }
        required_legacy_columns = {
            "id",
            "account_id",
            "user_id",
            "duration_seconds",
        }
        missing_columns = sorted(required_legacy_columns - columns)
        if missing_columns:
            raise RuntimeError(
                "boost_logs is missing required columns: "
                + ", ".join(missing_columns)
            )
        foreign_keys = {
            (
                tuple(item.get("constrained_columns") or ()),
                item.get("referred_table"),
                tuple(item.get("referred_columns") or ()),
            )
            for item in inspect(conn).get_foreign_keys("boost_logs")
        }
        required_foreign_keys = {
            (("account_id",), "steam_accounts", ("id",)),
            (("user_id",), "users", ("id",)),
        }
        missing_foreign_keys = required_foreign_keys - foreign_keys
        if missing_foreign_keys:
            raise RuntimeError(
                "boost_logs is missing required foreign keys: "
                f"{sorted(missing_foreign_keys)}"
            )

        rows_before = int(_scalar(conn, "SELECT COUNT(*) FROM boost_logs"))
        duration_before = int(_scalar(
            conn,
            "SELECT COALESCE(SUM(duration_seconds), 0) FROM boost_logs",
        ))
        users_before = int(_scalar(conn, "SELECT COUNT(*) FROM users"))
        accounts_before = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM steam_accounts",
        ))
        dangling_accounts_before = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs AS log "
            "WHERE log.account_id IS NOT NULL "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM steam_accounts AS account "
            "  WHERE account.id = log.account_id"
            ")",
        ))
        dangling_users_before = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs AS log "
            "WHERE log.user_id IS NOT NULL "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM users AS owner "
            "  WHERE owner.id = log.user_id"
            ")",
        ))
        ownership_mismatches_before = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs AS log "
            "JOIN steam_accounts AS account ON account.id = log.account_id "
            "WHERE log.user_id IS NOT NULL "
            "AND account.user_id <> log.user_id",
        ))
        if ownership_mismatches_before:
            raise RuntimeError(
                "Phase 5F migration found cross-owner BoostLog rows: "
                f"{ownership_mismatches_before}"
            )

        foreign_keys_enabled = 1
        if dialect == "sqlite":
            foreign_keys_enabled = int(
                conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
            )
            if not foreign_keys_enabled:
                raise RuntimeError(
                    "SQLite foreign-key enforcement is disabled"
                )

            # Only the two BoostLog orphan classes repaired below are allowed
            # through the migration gate.  Any unrelated legacy FK violation
            # must stop startup before SQLite persists ALTER TABLE columns.
            sqlite_fk_definitions = {
                int(row["id"]): (
                    row["from"],
                    row["table"],
                    row["to"],
                )
                for row in conn.exec_driver_sql(
                    "PRAGMA foreign_key_list(boost_logs)"
                ).mappings()
                if int(row["seq"]) == 0
            }
            required_sqlite_fk_definitions = {
                ("account_id", "steam_accounts", "id"):
                    dangling_accounts_before,
                ("user_id", "users", "id"): dangling_users_before,
            }
            violation_counts = {
                definition: 0
                for definition in required_sqlite_fk_definitions
            }
            unexpected_violations = []
            for violation in conn.exec_driver_sql(
                "PRAGMA foreign_key_check"
            ).all():
                table_name, row_id, parent_table, fk_id = violation
                definition = sqlite_fk_definitions.get(int(fk_id))
                if (
                    table_name != "boost_logs"
                    or definition not in violation_counts
                    or definition[1] != parent_table
                ):
                    unexpected_violations.append(
                        (table_name, row_id, parent_table, fk_id)
                    )
                    continue
                violation_counts[definition] += 1
            expected_counts_match = all(
                violation_counts[definition] == expected
                for definition, expected
                in required_sqlite_fk_definitions.items()
            )
            if unexpected_violations or not expected_counts_match:
                raise RuntimeError(
                    "Phase 5F migration found unrelated or unsupported "
                    "foreign-key violations"
                )

        added_columns = 0
        for name, ddl_type in _SNAPSHOT_COLUMNS.items():
            if name in columns:
                continue
            conn.execute(text(
                f"ALTER TABLE boost_logs ADD COLUMN {name} {ddl_type}"
            ))
            columns.add(name)
            added_columns += 1

        account_snapshot_backfilled = _changed(conn.execute(text(
            "UPDATE boost_logs "
            "SET account_id_snapshot = account_id "
            "WHERE account_id_snapshot IS NULL "
            "AND account_id IS NOT NULL"
        )))
        steam_username_backfilled = _changed(conn.execute(text(
            "UPDATE boost_logs "
            "SET steam_username_snapshot = ("
            "  SELECT steam_username FROM steam_accounts "
            "  WHERE steam_accounts.id = boost_logs.account_id"
            ") "
            "WHERE steam_username_snapshot IS NULL "
            "AND account_id IS NOT NULL "
            "AND EXISTS ("
            "  SELECT 1 FROM steam_accounts "
            "  WHERE steam_accounts.id = boost_logs.account_id"
            ")"
        )))
        owner_id_backfilled = _changed(conn.execute(text(
            "UPDATE boost_logs "
            "SET owner_user_id_snapshot = COALESCE("
            "  user_id, "
            "  (SELECT user_id FROM steam_accounts "
            "   WHERE steam_accounts.id = boost_logs.account_id)"
            ") "
            "WHERE owner_user_id_snapshot IS NULL "
            "AND (user_id IS NOT NULL "
            "OR EXISTS ("
            "  SELECT 1 FROM steam_accounts "
            "  WHERE steam_accounts.id = boost_logs.account_id"
            "))"
        )))
        owner_username_backfilled = _changed(conn.execute(text(
            "UPDATE boost_logs "
            "SET owner_username_snapshot = ("
            "  SELECT username FROM users "
            "  WHERE users.id = COALESCE("
            "    boost_logs.user_id, "
            "    (SELECT user_id FROM steam_accounts "
            "     WHERE steam_accounts.id = boost_logs.account_id)"
            "  )"
            ") "
            "WHERE owner_username_snapshot IS NULL "
            "AND EXISTS ("
            "  SELECT 1 FROM users "
            "  WHERE users.id = COALESCE("
            "    boost_logs.user_id, "
            "    (SELECT user_id FROM steam_accounts "
            "     WHERE steam_accounts.id = boost_logs.account_id)"
            "  )"
            ")"
        )))

        orphan_accounts_detached = _changed(conn.execute(text(
            "UPDATE boost_logs "
            "SET account_id = NULL "
            "WHERE account_id IS NOT NULL "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM steam_accounts "
            "  WHERE steam_accounts.id = boost_logs.account_id"
            ")"
        )))
        orphan_users_detached = _changed(conn.execute(text(
            "UPDATE boost_logs "
            "SET user_id = NULL "
            "WHERE user_id IS NOT NULL "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM users "
            "  WHERE users.id = boost_logs.user_id"
            ")"
        )))

        rows_after = int(_scalar(conn, "SELECT COUNT(*) FROM boost_logs"))
        duration_after = int(_scalar(
            conn,
            "SELECT COALESCE(SUM(duration_seconds), 0) FROM boost_logs",
        ))
        users_after = int(_scalar(conn, "SELECT COUNT(*) FROM users"))
        accounts_after = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM steam_accounts",
        ))
        dangling_accounts_after = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs AS log "
            "WHERE log.account_id IS NOT NULL "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM steam_accounts AS account "
            "  WHERE account.id = log.account_id"
            ")",
        ))
        dangling_users_after = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs AS log "
            "WHERE log.user_id IS NOT NULL "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM users AS owner "
            "  WHERE owner.id = log.user_id"
            ")",
        ))
        ownership_mismatches_after = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs AS log "
            "JOIN steam_accounts AS account ON account.id = log.account_id "
            "WHERE log.user_id IS NOT NULL "
            "AND account.user_id <> log.user_id",
        ))
        missing_account_snapshots = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE account_id IS NOT NULL "
            "AND account_id_snapshot IS NULL",
        ))
        missing_owner_snapshots = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE (user_id IS NOT NULL OR account_id IS NOT NULL) "
            "AND (owner_user_id_snapshot IS NULL "
            "OR owner_username_snapshot IS NULL)",
        ))

        foreign_key_violations = 0
        if dialect == "sqlite":
            foreign_key_violations = len(
                conn.exec_driver_sql("PRAGMA foreign_key_check").all()
            )

        invariant_values = {
            "rows": (rows_before, rows_after),
            "duration_seconds": (duration_before, duration_after),
            "users": (users_before, users_after),
            "steam_accounts": (accounts_before, accounts_after),
        }
        changed_invariants = {
            name: values
            for name, values in invariant_values.items()
            if values[0] != values[1]
        }
        if changed_invariants:
            raise RuntimeError(
                "Phase 5F migration changed protected totals: "
                f"{changed_invariants}"
            )
        if dangling_accounts_after or dangling_users_after:
            raise RuntimeError(
                "Phase 5F migration left dangling BoostLog references: "
                f"accounts={dangling_accounts_after}, "
                f"users={dangling_users_after}"
            )
        if ownership_mismatches_after:
            raise RuntimeError(
                "Phase 5F migration found cross-owner BoostLog rows: "
                f"{ownership_mismatches_after}"
            )
        if missing_account_snapshots or missing_owner_snapshots:
            raise RuntimeError(
                "Phase 5F migration left recoverable snapshots empty: "
                f"accounts={missing_account_snapshots}, "
                f"owners={missing_owner_snapshots}"
            )
        if foreign_key_violations:
            raise RuntimeError(
                "Phase 5F migration left global FK violations: "
                f"{foreign_key_violations}"
            )

        unknown_account_snapshots = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE account_id IS NULL "
            "AND account_id_snapshot IS NULL",
        ))
        unknown_steam_usernames = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE account_id_snapshot IS NOT NULL "
            "AND steam_username_snapshot IS NULL",
        ))

        return {
            "dialect": dialect,
            "rows": rows_after,
            "duration_seconds": duration_after,
            "added_columns": added_columns,
            "account_snapshot_backfilled": account_snapshot_backfilled,
            "steam_username_backfilled": steam_username_backfilled,
            "owner_id_backfilled": owner_id_backfilled,
            "owner_username_backfilled": owner_username_backfilled,
            "orphan_accounts_detached": orphan_accounts_detached,
            "orphan_users_detached": orphan_users_detached,
            "unknown_account_snapshots": unknown_account_snapshots,
            "unknown_steam_usernames": unknown_steam_usernames,
            "foreign_key_violations": foreign_key_violations,
        }


def migrate_boost_duration_ledger(engine) -> dict[str, int | str]:
    """Add and backfill the Phase 5G.2 integer-microsecond usage ledger.

    The legacy seconds measurement is never changed.  Existing rows gain only
    the precision they actually contain (seconds multiplied by one million),
    while already migrated fractional rows remain untouched.  Keeping the new
    column nullable is intentional rollback compatibility: an older writer may
    insert a seconds-only row, which this idempotent bridge fills on next boot.
    """

    dialect = engine.dialect.name
    with engine.begin() as conn:
        table_names = set(inspect(conn).get_table_names())
        if "boost_logs" not in table_names:
            raise RuntimeError(
                "Phase 5G.2 migration requires the boost_logs table"
            )

        columns = {
            column["name"]
            for column in inspect(conn).get_columns("boost_logs")
        }
        required_columns = {"id", "duration_seconds"}
        missing_columns = sorted(required_columns - columns)
        if missing_columns:
            raise RuntimeError(
                "boost_logs is missing required columns: "
                + ", ".join(missing_columns)
            )

        rows_before = int(_scalar(conn, "SELECT COUNT(*) FROM boost_logs"))
        if dialect == "sqlite":
            non_integer_legacy = int(_scalar(
                conn,
                "SELECT COUNT(*) FROM boost_logs "
                "WHERE duration_seconds IS NOT NULL "
                "AND typeof(duration_seconds) <> 'integer'",
            ))
            if non_integer_legacy:
                raise RuntimeError(
                    "Phase 5G.2 migration found non-integer legacy "
                    f"durations: {non_integer_legacy}"
                )
        invalid_legacy = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE duration_seconds IS NULL OR duration_seconds < 0 "
            "OR duration_seconds > :maximum_seconds",
            {
                "maximum_seconds": (
                    MAX_DURATION_MICROSECONDS // MICROSECONDS_PER_SECOND
                ),
            },
        ))
        if invalid_legacy:
            raise RuntimeError(
                "Phase 5G.2 migration found invalid legacy durations: "
                f"{invalid_legacy}"
            )
        seconds_before = _integer_sum(
            conn,
            "SELECT duration_seconds FROM boost_logs",
        )
        if (
            "duration_microseconds" not in columns
            and seconds_before
            > MAX_DURATION_MICROSECONDS // MICROSECONDS_PER_SECOND
        ):
            raise RuntimeError(
                "Phase 5G.2 legacy duration total exceeds the canonical "
                "ledger range"
            )
        added_columns = 0
        if "duration_microseconds" not in columns:
            conn.execute(text(
                "ALTER TABLE boost_logs ADD COLUMN "
                "duration_microseconds BIGINT"
            ))
            columns.add("duration_microseconds")
            added_columns = 1

        invalid_microseconds = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE duration_microseconds IS NOT NULL "
            "AND (duration_microseconds < 0 "
            "OR duration_microseconds > :maximum_microseconds "
            "OR (duration_seconds = 0 AND duration_microseconds <> 0) "
            "OR (duration_seconds > 0 AND ("
            "duration_microseconds <= "
            "(CAST(duration_seconds AS BIGINT) - 1) "
            "* :microseconds_per_second "
            "OR duration_microseconds > CAST(duration_seconds AS BIGINT) "
            "* :microseconds_per_second)))",
            {
                "microseconds_per_second": MICROSECONDS_PER_SECOND,
                "maximum_microseconds": MAX_DURATION_MICROSECONDS,
            },
        ))
        if invalid_microseconds:
            raise RuntimeError(
                "Phase 5G.2 migration found invalid canonical durations: "
                f"{invalid_microseconds}"
            )
        if dialect == "sqlite":
            non_integer_microseconds = int(_scalar(
                conn,
                "SELECT COUNT(*) FROM boost_logs "
                "WHERE duration_microseconds IS NOT NULL "
                "AND typeof(duration_microseconds) <> 'integer'",
            ))
            if non_integer_microseconds:
                raise RuntimeError(
                    "Phase 5G.2 migration found non-integer canonical "
                    f"durations: {non_integer_microseconds}"
                )

        missing_before = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE duration_microseconds IS NULL",
        ))
        existing_microseconds_before = _integer_sum(
            conn,
            "SELECT duration_microseconds FROM boost_logs "
            "WHERE duration_microseconds IS NOT NULL",
        )
        missing_seconds_before = _integer_sum(
            conn,
            "SELECT duration_seconds FROM boost_logs "
            "WHERE duration_microseconds IS NULL",
        )
        expected_microseconds = (
            existing_microseconds_before
            + missing_seconds_before * MICROSECONDS_PER_SECOND
        )
        if expected_microseconds > MAX_DURATION_MICROSECONDS:
            raise RuntimeError(
                "Phase 5G.2 duration total exceeds the canonical ledger range"
            )

        backfilled_rows = _changed(conn.execute(text(
            "UPDATE boost_logs SET duration_microseconds = "
            "CAST(duration_seconds AS BIGINT) * :microseconds_per_second "
            "WHERE duration_microseconds IS NULL"
        ), {
            "microseconds_per_second": MICROSECONDS_PER_SECOND,
        }))

        rows_after = int(_scalar(conn, "SELECT COUNT(*) FROM boost_logs"))
        seconds_after = _integer_sum(
            conn,
            "SELECT duration_seconds FROM boost_logs",
        )
        microseconds_after = _integer_sum(
            conn,
            "SELECT duration_microseconds FROM boost_logs",
        )
        missing_after = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE duration_microseconds IS NULL",
        ))
        negative_after = int(_scalar(
            conn,
            "SELECT COUNT(*) FROM boost_logs "
            "WHERE duration_microseconds < 0",
        ))

        if rows_before != rows_after or seconds_before != seconds_after:
            raise RuntimeError(
                "Phase 5G.2 migration changed protected legacy totals"
            )
        if backfilled_rows != missing_before or missing_after or negative_after:
            raise RuntimeError(
                "Phase 5G.2 migration left an incomplete canonical ledger"
            )
        if microseconds_after != expected_microseconds:
            raise RuntimeError(
                "Phase 5G.2 migration changed canonical duration totals"
            )

        enforcement_added = _install_duration_ledger_enforcement(
            conn,
            dialect,
        )

        return {
            "dialect": dialect,
            "rows": rows_after,
            "duration_seconds": seconds_after,
            "duration_microseconds": microseconds_after,
            "added_columns": added_columns,
            "backfilled_rows": backfilled_rows,
            "enforcement_added": enforcement_added,
        }
