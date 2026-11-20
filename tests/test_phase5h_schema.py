"""Isolated Phase 5H.1A regressions; never import the app or open runtime data."""

from contextlib import closing, contextmanager, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import schema_tools


ALEMBIC_AVAILABLE = importlib.util.find_spec("alembic") is not None
ROOT = Path(__file__).resolve().parents[1]
SECRET = "never-print-private-token-518a"


@contextmanager
def database(path):
    # sqlite3's transaction context does not close its connection. Explicit
    # close keeps fixture teardown reliable on Windows as well as Linux.
    with closing(sqlite3.connect(path)) as connection, connection:
        yield connection


def row_hash(path):
    """Logical hash independent of SQLite page/WAL bookkeeping."""
    with database(path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"
        ).fetchall()
        rows = {
            name: connection.execute(
                'SELECT * FROM "' + name.replace('"', '""') + '" ORDER BY rowid'
            ).fetchall()
            for (name,) in tables
        }
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


@unittest.skipUnless(ALEMBIC_AVAILABLE, "Alembic is not installed in this interpreter")
class SchemaBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_dir = tempfile.TemporaryDirectory(prefix="hourboost-schema-fixture-")
        cls.fixture = Path(cls.fixture_dir.name).resolve() / "baseline.sqlite"
        report = schema_tools.bootstrap_disposable(str(cls.fixture))
        if not report["ok"]:
            raise AssertionError(report)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_dir.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hourboost-schema-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.path = self.root / "test.sqlite"
        shutil.copy2(self.fixture, self.path)

    def execute(self, statement, parameters=()):
        with database(self.path) as connection:
            connection.execute(statement, parameters)

    def audit(self):
        return schema_tools.audit_sqlite(str(self.path))

    def assert_drift(self, issue=None, object_name=None):
        report = self.audit()
        self.assertFalse(report["ok"])
        self.assertFalse(report["schema_matches"])
        self.assertFalse(report["stamp_permitted"])
        if issue:
            self.assertTrue(any(
                item["issue"] == issue and
                (object_name is None or item["object"] == object_name)
                for item in report["differences"]
            ), report["differences"])
        return report

    def rebuild_table(self, name, transform):
        """Alter only a disposable fixture using SQLite's documented rebuild pattern."""
        with database(self.path) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            original = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", (name,)
            ).fetchone()[0]
            indexes = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='index' AND tbl_name=? "
                "AND sql IS NOT NULL", (name,)
            ).fetchall()
            triggers = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=?", (name,)
            ).fetchall()
            temporary = name + "_replacement"
            replacement = re.sub(
                r'^CREATE TABLE (?:"' + re.escape(name) + r'"|' + re.escape(name) + r')(?=\s*\()',
                'CREATE TABLE ' + temporary, transform(original), count=1,
            )
            self.assertNotEqual(replacement, original)
            connection.execute(replacement)
            connection.execute(f"INSERT INTO {temporary} SELECT * FROM {name}")
            connection.execute(f"DROP TABLE {name}")
            connection.execute(f"ALTER TABLE {temporary} RENAME TO {name}")
            for (sql,) in indexes + triggers:
                connection.execute(sql)

    def test_frozen_baseline_exact_inventory_and_metadata_parity(self):
        report = self.audit()
        self.assertTrue(report["ok"])
        self.assertTrue(report["read_only"])
        self.assertTrue(report["metadata_matches"])
        self.assertEqual(report["revision_state"], "head")
        with database(self.path) as connection:
            objects = connection.execute(
                "SELECT type,name FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'"
            ).fetchall()
            tables = [name for kind, name in objects
                      if kind == "table" and name != "alembic_version"]
            self.assertEqual(len(tables), 9)
            self.assertEqual(sum(kind == "index" for kind, _ in objects), 14)
            self.assertEqual(sum(kind == "trigger" for kind, _ in objects), 2)
            self.assertEqual(sum(len(connection.execute(
                f"PRAGMA table_info({name})").fetchall()) for name in tables), 103)
            self.assertEqual(sum(len(connection.execute(
                f"PRAGMA foreign_key_list({name})").fetchall()) for name in tables), 7)

    def test_bootstrap_creates_only_requested_new_file(self):
        path = self.root / "new.sqlite"
        self.assertTrue(schema_tools.bootstrap_disposable(str(path))["ok"])
        self.assertEqual({p.name for p in self.root.iterdir()}, {"test.sqlite", "new.sqlite"})

    def test_legacy_integer_zero_default_is_explicit_compatibility(self):
        self.rebuild_table("payments", lambda sql: sql.replace(
            "verification_attempts INTEGER DEFAULT '0'", "verification_attempts INTEGER DEFAULT 0"))
        report = self.audit()
        self.assertTrue(report["ok"], report["differences"])
        self.assertIn({"object": "payments.verification_attempts", "issue": "default_mismatch"},
                      report["compatibility_notes"])

    def test_bootstrap_existing_populated_file_is_never_replaced(self):
        self.execute("INSERT INTO announcements(id,title,content) VALUES(1,?,?)", (SECRET, SECRET))
        before = self.path.read_bytes()
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.bootstrap_disposable(str(self.path))
        self.assertEqual(self.path.read_bytes(), before)

    def test_bootstrap_existing_empty_file_is_also_rejected(self):
        empty = self.root / "empty.sqlite"
        empty.touch()
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.bootstrap_disposable(str(empty))
        self.assertEqual(empty.stat().st_size, 0)

    def test_audit_never_modifies_rows_bytes_or_revision(self):
        self.execute("INSERT INTO announcements(id,title,content) VALUES(1,?,?)", (SECRET, SECRET))
        self.execute("INSERT INTO boost_logs(started_at,duration_seconds,duration_microseconds) "
                     "VALUES('2026-09-07 00:00:00',2,1500001)")
        before_rows, before_bytes = row_hash(self.path), self.path.read_bytes()
        report = self.audit()
        self.assertTrue(report["ok"])
        self.assertEqual(report["data_checks"]["duration_microseconds_total"], 1500001)
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertEqual(row_hash(self.path), before_rows)
        self.assertEqual(self.path.read_bytes(), before_bytes)

    def test_unstamped_valid_schema_is_not_implicitly_stamped(self):
        self.execute("DROP TABLE alembic_version")
        before = self.path.read_bytes()
        report = self.audit()
        self.assertTrue(report["ok"])
        self.assertEqual(report["revision_state"], "unstamped")
        self.assertFalse(report["stamp_permitted"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_outdated_or_multiple_revision_rows_are_rejected_without_value_leak(self):
        self.execute("UPDATE alembic_version SET version_num=?", (SECRET,))
        report = self.audit()
        self.assertFalse(report["ok"])
        self.assertEqual(report["revision_state"], "unexpected")
        self.assertNotIn(SECRET, json.dumps(report))
        self.execute("INSERT INTO alembic_version(version_num) VALUES(?)", (schema_tools.BASELINE_REVISION,))
        self.assertEqual(self.audit()["revision_state"], "unexpected")

    def test_matching_index_name_with_wrong_columns_is_detected(self):
        self.execute("DROP INDEX ix_payments_verification_due")
        self.execute("CREATE INDEX ix_payments_verification_due ON payments(status)")
        self.assert_drift("index_definition_mismatch", "ix_payments_verification_due")

    def test_matching_index_name_with_wrong_unique_flag_is_detected(self):
        self.execute("DROP INDEX ux_payments_match_token")
        self.execute("CREATE INDEX ux_payments_match_token ON payments(match_token) WHERE match_token IS NOT NULL")
        self.assert_drift("index_definition_mismatch", "ux_payments_match_token")

    def test_matching_index_name_with_wrong_predicate_is_detected(self):
        self.execute("DROP INDEX ux_payments_one_open_checkout")
        self.execute("CREATE UNIQUE INDEX ux_payments_one_open_checkout ON payments(user_id) "
                     "WHERE user_id IS NOT NULL AND status IN ('checkout_started')")
        self.assert_drift("index_definition_mismatch", "ux_payments_one_open_checkout")

    def test_double_quoted_null_is_not_normalized_to_null_keyword(self):
        self.execute("DROP INDEX ux_payments_match_token")
        self.execute('CREATE UNIQUE INDEX ux_payments_match_token ON payments(match_token) '
                     'WHERE match_token IS NOT "null"')
        self.assert_drift("index_definition_mismatch", "ux_payments_match_token")
        self.assertNotEqual(schema_tools.sql_tokens('IS NOT "null"'),
                            schema_tools.sql_tokens("IS NOT NULL"))

    def test_index_sort_direction_and_collation_are_checked(self):
        self.execute("DROP INDEX ix_payments_match_token")
        self.execute("CREATE INDEX ix_payments_match_token ON payments(match_token COLLATE NOCASE DESC)")
        self.assert_drift("index_definition_mismatch", "ix_payments_match_token")

    def test_same_name_trigger_with_weakened_body_is_detected(self):
        self.execute("DROP TRIGGER trg_boost_logs_duration_ledger_insert")
        self.execute("CREATE TRIGGER trg_boost_logs_duration_ledger_insert BEFORE INSERT ON boost_logs "
                     "BEGIN SELECT 1; END")
        self.assert_drift("triggers_definition_mismatch", "trg_boost_logs_duration_ledger_insert")

    def test_missing_four_nullable_user_uniques_is_blocking(self):
        for column in schema_tools.USER_UNIQUE_FIELDS:
            self.execute("DROP INDEX ux_users_" + column)
        report = self.assert_drift("missing_unique_key", "users.steam_id")
        self.assertEqual({item["object"] for item in report["differences"]
                          if item["issue"] == "missing_unique_key"}, {
            "users." + field for field in schema_tools.USER_UNIQUE_FIELDS
        })
        self.assertTrue(report["data_checks_ok"], "Missing constraints matter even before duplicates occur")

    def test_duplicate_nullable_user_unique_values_are_reported_without_values(self):
        self.execute("DROP INDEX ux_users_steam_id")
        for number in (1, 2):
            self.execute("INSERT INTO users(id,username,email,password_hash,steam_id) VALUES(?,?,?,?,?)",
                         (number, "user" + str(number), f"{number}@example.invalid", "dummy", SECRET))
        report = self.assert_drift("missing_unique_key", "users.steam_id")
        self.assertFalse(report["data_checks_ok"])
        self.assertEqual(report["data_checks"]["duplicate_user_unique_groups"]["steam_id"], 1)
        self.assertNotIn(SECRET, json.dumps(report))

    def test_foreign_key_definition_drift_is_detected(self):
        self.rebuild_table("boost_games", lambda sql: sql.replace(
            "REFERENCES steam_accounts (id)", "REFERENCES steam_accounts (id) ON DELETE CASCADE"))
        self.assert_drift("foreign_keys_mismatch", "boost_games")

    def test_column_collation_changes_are_not_hidden_by_pragma_reflection(self):
        self.rebuild_table("users", lambda sql: sql.replace(
            "username VARCHAR(80)", "username VARCHAR(80) COLLATE NOCASE", 1))
        self.assert_drift("ddl_features_mismatch", "users")

    def test_replace_conflict_policy_is_detected(self):
        self.rebuild_table("users", lambda sql: sql.replace(
            "UNIQUE (username)", "UNIQUE (username) ON CONFLICT REPLACE", 1))
        self.assert_drift("ddl_features_mismatch", "users")

    def test_deferred_foreign_key_is_detected(self):
        self.rebuild_table("boost_games", lambda sql: sql.replace(
            "REFERENCES steam_accounts (id)",
            "REFERENCES steam_accounts (id) DEFERRABLE INITIALLY DEFERRED", 1))
        self.assert_drift("ddl_features_mismatch", "boost_games")

    def test_inline_desc_primary_key_does_not_masquerade_as_rowid_alias(self):
        def change_primary_key(sql):
            sql, count = re.subn(r",\s*PRIMARY KEY\s*\(id\)", "", sql)
            self.assertEqual(count, 1)
            return sql.replace("id INTEGER NOT NULL", "id INTEGER PRIMARY KEY DESC NOT NULL", 1)
        self.rebuild_table("announcements", change_primary_key)
        self.assert_drift("primary_indexes_mismatch", "announcements")

    def test_existing_foreign_key_violations_are_counted(self):
        self.execute("INSERT INTO boost_games(account_id,app_id) VALUES(?,440)", (SECRET,))
        report = self.audit()
        self.assertFalse(report["ok"])
        self.assertTrue(report["schema_matches"])
        self.assertEqual(report["data_checks"]["foreign_key_violations"], 1)
        self.assertNotIn(SECRET, json.dumps(report))

    def test_altered_named_check_constraint_is_detected(self):
        self.rebuild_table("boost_logs", lambda sql: sql.replace(
            "duration_seconds >= 0", "duration_seconds >= 1", 1))
        self.assert_drift("check_definition_mismatch", "boost_logs")

    def test_ledger_triggers_reject_invalid_insert_and_update(self):
        invalid = ((-1, None), (1.5, None), (None, None), (0, 1), (2, 1000000), (1, 1000001))
        for seconds, micros in invalid:
            with self.subTest(seconds=seconds, micros=micros):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.execute("INSERT INTO boost_logs(started_at,duration_seconds,duration_microseconds) "
                                 "VALUES('2026-09-07',?,?)", (seconds, micros))
        self.execute("INSERT INTO boost_logs(id,started_at,duration_seconds,duration_microseconds) "
                     "VALUES(1,'2026-09-07',1,1)")
        with self.assertRaises(sqlite3.IntegrityError):
            self.execute("UPDATE boost_logs SET duration_microseconds=1000001 WHERE id=1")

    def test_invalid_legacy_ledger_data_is_reported(self):
        self.execute("DROP TRIGGER trg_boost_logs_duration_ledger_insert")
        with database(self.path) as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute("INSERT INTO boost_logs(started_at,duration_seconds,duration_microseconds) "
                               "VALUES('2026-09-07',-1,-1)")
        report = self.audit()
        self.assertFalse(report["data_checks_ok"])
        self.assertEqual(report["data_checks"]["invalid_ledger_rows"], 1)

    def test_wal_audit_reads_one_snapshot_despite_concurrent_commit(self):
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        writer.execute("INSERT INTO boost_logs(started_at,duration_seconds,duration_microseconds) "
                       "VALUES('2026-09-07 00:00:00',1,500000)")
        writer.commit()
        real_summary = schema_tools._data_summary

        def concurrent_summary(connection, actual):
            writer.execute("INSERT INTO boost_logs(started_at,duration_seconds,duration_microseconds) "
                           "VALUES('2026-09-07 00:00:00',2,1500001)")
            writer.commit()
            return real_summary(connection, actual)

        with patch.object(schema_tools, "_data_summary", side_effect=concurrent_summary):
            report = self.audit()
        self.assertTrue(report["ok"])
        self.assertEqual(report["data_checks"]["duration_microseconds_total"], 500000)
        final = self.audit()
        self.assertEqual(final["data_checks"]["duration_microseconds_total"], 2000001)

    def test_invalid_paths_are_rejected_without_creating_files(self):
        missing = self.root / "missing.sqlite"
        empty = self.root / "empty.sqlite"
        empty.touch()
        cases = (str(missing), str(empty), str(self.root), "relative.sqlite",
                 str(self.root / "missing-parent" / "x.sqlite"),
                 str(self.root / "child" / ".." / self.path.name))
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(schema_tools.SchemaToolError):
                    schema_tools.audit_sqlite(value)
        self.assertFalse(missing.exists())
        self.assertEqual(empty.stat().st_size, 0)

    def test_symlink_database_is_rejected(self):
        link = self.root / "linked.sqlite"
        try:
            link.symlink_to(self.path)
        except OSError as error:
            self.skipTest("Host does not permit symlink creation: " + type(error).__name__)
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.audit_sqlite(str(link))
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.bootstrap_disposable(str(link))

    def test_cli_exit_codes_and_errors_never_contain_private_input(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(schema_tools.main(["audit", "--sqlite-path", str(self.path)]), 0)
        self.assertTrue(json.loads(stream.getvalue())["ok"])
        self.execute("DROP INDEX ux_payments_match_token")
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(schema_tools.main(["audit", "--sqlite-path", str(self.path)]), 1)
        self.assertFalse(json.loads(stream.getvalue())["ok"])
        for action in ("audit", "bootstrap-disposable"):
            stream = io.StringIO()
            with redirect_stdout(stream), patch.object(
                schema_tools, "_canonical_path", side_effect=RuntimeError(SECRET)
            ):
                self.assertEqual(schema_tools.main([action, "--sqlite-path", SECRET]), 2)
            self.assertEqual(json.loads(stream.getvalue()), {
                "ok": False, "error": "schema_operation_failed", "stamp_permitted": False,
            })
            self.assertNotIn(SECRET, stream.getvalue())

    def test_unknown_schema_object_names_and_bodies_are_not_exposed(self):
        self.execute(f'CREATE TABLE "{SECRET}" ("{SECRET}" TEXT)')
        self.execute(f'CREATE VIEW "view-{SECRET}" AS SELECT \'{SECRET}\'')
        self.execute(f'CREATE INDEX "index-{SECRET}" ON announcements(title)')
        self.execute(f'CREATE TRIGGER "trigger-{SECRET}" AFTER INSERT ON announcements BEGIN SELECT \'{SECRET}\'; END')
        report = self.assert_drift()
        self.assertNotIn(SECRET, json.dumps(report))

    def test_bootstrap_and_audit_do_not_import_app_config_or_dotenv(self):
        code = """
import builtins, sys
from pathlib import Path
real_import = builtins.__import__
def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name.split('.')[0] in {'app', 'config', 'dotenv', 'steam_manager'}:
        raise AssertionError('Application startup module was imported')
    return real_import(name, globals, locals, fromlist, level)
builtins.__import__ = safe_import
import schema_tools
assert schema_tools.bootstrap_disposable(sys.argv[1])['ok']
assert schema_tools.audit_sqlite(sys.argv[1])['ok']
assert not {'app', 'config', 'dotenv', 'steam_manager'}.intersection(sys.modules)
"""
        result = subprocess.run([sys.executable, "-c", code, str(self.root / "isolated.sqlite")],
                                cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_standalone_alembic_rejects_url_only_invocation_and_offline_sql(self):
        from alembic import command
        from alembic.config import Config
        config = Config()
        config.set_main_option("script_location", str(ROOT / "migrations").replace("%", "%%"))
        target = self.root / "must-not-exist.sqlite"
        config.set_main_option("sqlalchemy.url", "sqlite:///" + str(target).replace("%", "%%"))
        for sql in (False, True):
            with self.subTest(sql=sql):
                with self.assertRaises(RuntimeError):
                    command.upgrade(config, "head", sql=sql)
        self.assertFalse(target.exists())

    def test_existing_database_cannot_be_stamped_upgraded_or_downgraded(self):
        from alembic import command
        from alembic.config import Config
        before = row_hash(self.path)
        engine = schema_tools._engine(self.path)
        self.addCleanup(engine.dispose)
        for operation, revision in ((command.upgrade, "head"), (command.stamp, "head"),
                                    (command.downgrade, "base")):
            with self.subTest(operation=operation.__name__):
                with engine.begin() as connection:
                    config = Config()
                    config.set_main_option("script_location", str(ROOT / "migrations").replace("%", "%%"))
                    config.attributes.update(connection=connection, bootstrap_disposable=True)
                    with self.assertRaises(RuntimeError):
                        operation(config, revision)
        self.assertEqual(row_hash(self.path), before)

    def test_atomic_bootstrap_does_not_overwrite_destination_created_during_rehearsal(self):
        target = self.root / "race.sqlite"
        real_link = os.link
        appeared = []

        def publish_after_competitor(source, destination, *args, **kwargs):
            self.assertEqual(Path(destination), target)
            with database(target) as connection:
                connection.execute("CREATE TABLE keep_me(value TEXT)")
                connection.execute("INSERT INTO keep_me VALUES(?)", (SECRET,))
            appeared.append(target.read_bytes())
            return real_link(source, destination, *args, **kwargs)

        with patch.object(schema_tools.os, "link", side_effect=publish_after_competitor):
            with self.assertRaises(schema_tools.SchemaToolError):
                schema_tools.bootstrap_disposable(str(target))
        self.assertEqual(len(appeared), 1, "Bootstrap must atomically publish its private rehearsal")
        self.assertEqual(target.read_bytes(), appeared[0])
        with database(target) as connection:
            self.assertEqual(connection.execute("SELECT value FROM keep_me").fetchall(), [(SECRET,)])

    def test_sqlite_baseline_cannot_activate_postgresql_through_manual_stamp(self):
        from runtime_guardrails import RuntimeConfigError, assert_alembic_at_head
        engine = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"), connect=Mock())
        self.assertTrue((ROOT / "migrations" / "env.py").is_file())
        with self.assertRaises(RuntimeConfigError):
            assert_alembic_at_head(engine, ROOT / "migrations")
        engine.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
