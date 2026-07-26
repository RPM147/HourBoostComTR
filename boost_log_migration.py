"""Forward-only, lossless BoostLog history migration helpers.

The migration keeps operational foreign keys nullable and preserves the former
owner/account identity in immutable snapshot columns.  It never deletes or
rewrites usage measurements.
"""

from __future__ import annotations

import sqlite3

from sqlalchemy import inspect, text


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


def _scalar(conn, statement: str):
    return conn.execute(text(statement)).scalar_one()


def _changed(result) -> int:
    return max(0, int(result.rowcount or 0))


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
