import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError

from boost_log_migration import (
    enable_sqlite_foreign_keys,
    migrate_boost_log_history,
)


class Phase5FMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "legacy.db"
        self._create_legacy_database(self.db_path)
        self.engine = self._engine(self.db_path)

    def tearDown(self):
        self.engine.dispose()
        self.tempdir.cleanup()

    @staticmethod
    def _engine(path):
        engine = create_engine(f"sqlite:///{path}")

        @event.listens_for(engine, "connect")
        def _enable_fk(dbapi_connection, _connection_record):
            enable_sqlite_foreign_keys(dbapi_connection)

        return engine

    @staticmethod
    def _create_legacy_database(path, *, include_foreign_keys=True):
        account_fk = (
            ", FOREIGN KEY(account_id) REFERENCES steam_accounts(id)"
            if include_foreign_keys else ""
        )
        user_fk = (
            ", FOREIGN KEY(user_id) REFERENCES users(id)"
            if include_foreign_keys else ""
        )
        conn = sqlite3.connect(path)
        conn.executescript(
            f"""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username VARCHAR(80) NOT NULL
            );
            CREATE TABLE steam_accounts (
                id VARCHAR(32) PRIMARY KEY,
                user_id INTEGER NOT NULL,
                steam_username VARCHAR(100) NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE boost_logs (
                id INTEGER PRIMARY KEY,
                account_id VARCHAR(32),
                user_id INTEGER,
                started_at DATETIME NOT NULL,
                stopped_at DATETIME,
                remote_stopped_at DATETIME,
                duration_seconds INTEGER,
                games_count INTEGER,
                app_ids_json TEXT
                {account_fk}
                {user_fk}
            );
            """
        )
        conn.executemany(
            "INSERT INTO users(id, username) VALUES (?, ?)",
            [(1, "owner-one"), (2, "owner-two")],
        )
        conn.executemany(
            "INSERT INTO steam_accounts(id, user_id, steam_username) "
            "VALUES (?, ?, ?)",
            [
                ("valid-account", 1, "valid-steam-user"),
                ("other-account", 2, "other-steam-user"),
            ],
        )
        conn.executemany(
            "INSERT INTO boost_logs("
            "id, account_id, user_id, started_at, stopped_at, "
            "remote_stopped_at, duration_seconds, games_count, app_ids_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    "valid-account",
                    1,
                    "2026-01-01 00:00:00",
                    "2026-01-01 00:00:10",
                    "2026-01-01 00:00:10",
                    10,
                    1,
                    "[730]",
                ),
                (
                    2,
                    "deleted-account",
                    1,
                    "2026-01-01 00:01:00",
                    "2026-01-01 00:01:20",
                    None,
                    20,
                    1,
                    "[570]",
                ),
                (
                    3,
                    None,
                    1,
                    "2026-01-01 00:02:00",
                    "2026-01-01 00:02:30",
                    None,
                    30,
                    0,
                    "[]",
                ),
                (
                    4,
                    None,
                    999,
                    "2026-01-01 00:03:00",
                    "2026-01-01 00:03:40",
                    None,
                    40,
                    0,
                    "{legacy-malformed-json",
                ),
            ],
        )
        conn.commit()
        conn.close()

    def _measurement_digest(self):
        with self.engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT id, started_at, stopped_at, remote_stopped_at, "
                "duration_seconds, games_count, app_ids_json "
                "FROM boost_logs ORDER BY id"
            )).all()
        payload = "\n".join(
            "|".join("" if value is None else str(value) for value in row)
            for row in rows
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def test_migration_is_lossless_idempotent_and_enforces_foreign_keys(self):
        digest_before = self._measurement_digest()

        first = migrate_boost_log_history(self.engine)

        self.assertEqual(first["rows"], 4)
        self.assertEqual(first["duration_seconds"], 100)
        self.assertEqual(first["added_columns"], 4)
        self.assertEqual(first["orphan_accounts_detached"], 1)
        self.assertEqual(first["orphan_users_detached"], 1)
        self.assertEqual(first["unknown_account_snapshots"], 2)
        self.assertEqual(first["unknown_steam_usernames"], 1)
        self.assertEqual(first["foreign_key_violations"], 0)
        self.assertEqual(self._measurement_digest(), digest_before)

        with self.engine.connect() as conn:
            rows = {
                row.id: row
                for row in conn.execute(text(
                    "SELECT * FROM boost_logs ORDER BY id"
                )).mappings()
            }
            self.assertEqual(
                conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one(),
                1,
            )
            self.assertEqual(
                conn.exec_driver_sql("PRAGMA foreign_key_check").all(),
                [],
            )

        self.assertEqual(rows[1]["account_id"], "valid-account")
        self.assertEqual(
            rows[1]["account_id_snapshot"],
            "valid-account",
        )
        self.assertEqual(
            rows[1]["steam_username_snapshot"],
            "valid-steam-user",
        )
        self.assertEqual(rows[1]["owner_user_id_snapshot"], 1)
        self.assertEqual(rows[1]["owner_username_snapshot"], "owner-one")

        self.assertIsNone(rows[2]["account_id"])
        self.assertEqual(
            rows[2]["account_id_snapshot"],
            "deleted-account",
        )
        self.assertIsNone(rows[2]["steam_username_snapshot"])
        self.assertEqual(rows[2]["owner_username_snapshot"], "owner-one")

        self.assertIsNone(rows[3]["account_id"])
        self.assertIsNone(rows[3]["account_id_snapshot"])
        self.assertEqual(rows[3]["owner_username_snapshot"], "owner-one")

        self.assertIsNone(rows[4]["user_id"])
        self.assertEqual(rows[4]["owner_user_id_snapshot"], 999)
        self.assertIsNone(rows[4]["owner_username_snapshot"])
        self.assertEqual(rows[4]["app_ids_json"], "{legacy-malformed-json")

        with self.engine.begin() as conn:
            conn.execute(text(
                "UPDATE boost_logs "
                "SET account_id_snapshot = 'immutable-account', "
                "steam_username_snapshot = 'immutable-username' "
                "WHERE id = 1"
            ))
        second = migrate_boost_log_history(self.engine)
        for key in (
            "added_columns",
            "account_snapshot_backfilled",
            "steam_username_backfilled",
            "owner_id_backfilled",
            "owner_username_backfilled",
            "orphan_accounts_detached",
            "orphan_users_detached",
        ):
            self.assertEqual(second[key], 0, key)
        self.assertEqual(self._measurement_digest(), digest_before)
        with self.engine.connect() as conn:
            immutable = conn.execute(text(
                "SELECT account_id_snapshot, steam_username_snapshot "
                "FROM boost_logs WHERE id = 1"
            )).one()
        self.assertEqual(
            tuple(immutable),
            ("immutable-account", "immutable-username"),
        )

        with self.assertRaises(IntegrityError):
            with self.engine.begin() as conn:
                conn.execute(text(
                    "INSERT INTO boost_logs("
                    "account_id, user_id, started_at, duration_seconds"
                    ") VALUES ('missing-account', 1, "
                    "'2026-01-02 00:00:00', 1)"
                ))
        with self.assertRaises(IntegrityError):
            with self.engine.begin() as conn:
                conn.execute(text(
                    "INSERT INTO boost_logs("
                    "account_id, user_id, started_at, duration_seconds"
                    ") VALUES (NULL, 987654, "
                    "'2026-01-02 00:00:00', 1)"
                ))

    def test_every_pooled_sqlite_connection_enforces_foreign_keys(self):
        with self.engine.connect() as first, self.engine.connect() as second:
            self.assertIsNot(
                first.connection.driver_connection,
                second.connection.driver_connection,
            )
            self.assertEqual(
                first.exec_driver_sql("PRAGMA foreign_keys").scalar_one(),
                1,
            )
            self.assertEqual(
                second.exec_driver_sql("PRAGMA foreign_keys").scalar_one(),
                1,
            )

    def test_migration_fails_closed_when_legacy_fk_definitions_are_missing(self):
        other_path = Path(self.tempdir.name) / "no-fks.db"
        self._create_legacy_database(
            other_path,
            include_foreign_keys=False,
        )
        other_engine = self._engine(other_path)
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "missing required foreign keys",
            ):
                migrate_boost_log_history(other_engine)
            with other_engine.connect() as conn:
                columns = {
                    row["name"]
                    for row in conn.exec_driver_sql(
                        "PRAGMA table_info(boost_logs)"
                    ).mappings()
                }
            self.assertNotIn("account_id_snapshot", columns)
        finally:
            other_engine.dispose()

    def test_unrelated_fk_debt_is_rejected_before_schema_mutation(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE unrelated_child (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            INSERT INTO unrelated_child(id, user_id) VALUES (1, 999999);
            """
        )
        conn.commit()
        conn.close()

        with self.assertRaisesRegex(
            RuntimeError,
            "unrelated or unsupported",
        ):
            migrate_boost_log_history(self.engine)

        with self.engine.connect() as connection:
            columns = {
                row["name"]
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(boost_logs)"
                ).mappings()
            }
        self.assertNotIn("account_id_snapshot", columns)

    def test_valid_account_recovers_missing_live_owner_into_snapshots(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO boost_logs("
            "id, account_id, user_id, started_at, stopped_at, "
            "duration_seconds, games_count, app_ids_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                5,
                "valid-account",
                None,
                "2026-01-01 00:04:00",
                "2026-01-01 00:04:50",
                50,
                1,
                "[440]",
            ),
        )
        conn.commit()
        conn.close()

        migrate_boost_log_history(self.engine)

        with self.engine.connect() as connection:
            recovered = connection.execute(text(
                "SELECT account_id, user_id, account_id_snapshot, "
                "steam_username_snapshot, owner_user_id_snapshot, "
                "owner_username_snapshot FROM boost_logs WHERE id = 5"
            )).one()
        self.assertEqual(
            tuple(recovered),
            (
                "valid-account",
                None,
                "valid-account",
                "valid-steam-user",
                1,
                "owner-one",
            ),
        )

    def test_cross_owner_history_aborts_without_measurement_changes(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO boost_logs("
            "id, account_id, user_id, started_at, stopped_at, "
            "duration_seconds, games_count, app_ids_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                5,
                "other-account",
                1,
                "2026-01-01 00:04:00",
                "2026-01-01 00:04:50",
                50,
                1,
                "[440]",
            ),
        )
        conn.commit()
        conn.close()
        digest_before = self._measurement_digest()

        with self.assertRaisesRegex(RuntimeError, "cross-owner"):
            migrate_boost_log_history(self.engine)

        self.assertEqual(self._measurement_digest(), digest_before)
        with self.engine.connect() as conn:
            self.assertEqual(
                conn.execute(text(
                    "SELECT COUNT(*) FROM boost_logs"
                )).scalar_one(),
                5,
            )
            columns = {
                row["name"]
                for row in conn.exec_driver_sql(
                    "PRAGMA table_info(boost_logs)"
                ).mappings()
            }
        self.assertNotIn("account_id_snapshot", columns)


if __name__ == "__main__":
    unittest.main()
