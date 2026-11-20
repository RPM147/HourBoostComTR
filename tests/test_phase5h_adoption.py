"""Guarded SQLite adoption regressions using private, synthetic databases only."""

from contextlib import closing, contextmanager, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, event

import schema_tools


ALEMBIC_AVAILABLE = importlib.util.find_spec("alembic") is not None
SECRET = "private-adoption-value-never-report-5531"
USER_FIELDS = ("steam_id", "verification_token", "reset_token", "email_change_token")
INDEXES = {"ux_users_" + name for name in USER_FIELDS}


@contextmanager
def database(path):
    with closing(sqlite3.connect(path)) as connection, connection:
        yield connection


def state(path):
    """Complete logical data and schema, excluding only Alembic bookkeeping."""
    with database(path) as connection:
        schema = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT GLOB 'sqlite_*' AND name <> 'alembic_version' "
            "ORDER BY type,name"
        ).fetchall()
        tables = [name for kind, name, _, _ in schema if kind == "table"]
        rows = {
            name: connection.execute(
                'SELECT * FROM "' + name.replace('"', '""') + '" ORDER BY rowid'
            ).fetchall()
            for name in tables
        }
    return schema, hashlib.sha256(repr(rows).encode()).hexdigest(), {
        name: len(values) for name, values in rows.items()
    }


@unittest.skipUnless(ALEMBIC_AVAILABLE, "Alembic is not installed in this interpreter")
class GuardedAdoptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_directory = tempfile.TemporaryDirectory(prefix="hourboost-adoption-fixture-")
        cls.fixture = Path(cls.fixture_directory.name).resolve() / "head.sqlite"
        report = schema_tools.bootstrap_disposable(str(cls.fixture))
        if not report["ok"]:
            raise AssertionError(report)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hourboost-adoption-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.path = self.root / "source.sqlite"
        self.backup = self.root / "backup.sqlite"
        shutil.copy2(self.fixture, self.path)
        with database(self.path) as connection:
            for name in INDEXES:
                connection.execute('DROP INDEX "' + name + '"')
            connection.execute("DROP TABLE alembic_version")
            for user_id in (1, 2):
                connection.execute(
                    "INSERT INTO users(id,username,email,password_hash,plan,is_admin) "
                    "VALUES(?,?,?,?, 'free',0)",
                    (user_id, "user" + str(user_id), "user" + str(user_id) + "@example.invalid", SECRET),
                )
            connection.execute(
                "INSERT INTO steam_accounts(id,user_id,steam_username,steam_id) "
                "VALUES('account-a',1,'worker-a','76561198000000000')"
            )
            connection.execute("INSERT INTO boost_games(id,account_id,app_id) VALUES(1,'account-a',730)")
            connection.execute(
                "INSERT INTO boost_logs(id,account_id,user_id,account_id_snapshot,"
                "steam_username_snapshot,owner_user_id_snapshot,owner_username_snapshot,"
                "started_at,stopped_at,duration_seconds,duration_microseconds,games_count) "
                "VALUES(1,'account-a',1,'account-a','worker-a',1,'user1',"
                "'2026-09-08 00:00:00','2026-09-08 00:00:01',1,1000000,1)"
            )
            connection.execute(
                "INSERT INTO payments(id,user_id,owner_user_id_snapshot,owner_username_snapshot,"
                "amount,plan,status,transaction_id,match_token) "
                "VALUES(1,1,1,'user1',19.99,'basic','completed','order-1',?)",
                ("HB-" + "A" * 32,),
            )
            connection.execute(
                "INSERT INTO payment_audit_logs(id,payment_id,actor_user_id,actor_username,"
                "action,reason,created_at) VALUES(1,1,1,'user1','review',?,"
                "'2026-09-08 00:00:00')", (SECRET,),
            )
            connection.execute(
                "INSERT INTO user_sessions(id,user_id,token_jti,is_active,expires_at) "
                "VALUES(1,1,'synthetic-session-jti',1,'2026-09-09 00:00:00')"
            )
            connection.execute(
                "INSERT INTO revoked_tokens(id,token_jti,user_id,revoked_at,expires_at) "
                "VALUES(1,'synthetic-revoked-jti',1,'2026-09-08 00:00:00',"
                "'2026-09-09 00:00:00')"
            )
            connection.execute("INSERT INTO announcements(id,title,content) VALUES(1,?,?)", (SECRET, SECRET))

    def execute(self, statement, parameters=()):
        with database(self.path) as connection:
            connection.execute(statement, parameters)

    def prepare(self):
        if self.backup.exists():
            self.backup.unlink()
        with closing(sqlite3.connect(self.path)) as source, closing(sqlite3.connect(self.backup)) as target:
            source.backup(target)
        self.backup.chmod(0o600)
        return schema_tools.audit_sqlite(str(self.path))["schema_fingerprint"]

    def adopt(self, **overrides):
        parameters = dict(
            backup_path=str(self.backup), expected_fingerprint=self.prepare(),
            confirm_maintenance=True,
        )
        parameters.update(overrides)
        return schema_tools.adopt_sqlite(str(self.path), **parameters)

    def assert_rejected(self, **overrides):
        parameters = dict(
            backup_path=str(self.backup), expected_fingerprint=self.prepare(),
            confirm_maintenance=True,
        )
        parameters.update(overrides)
        before = self.path.read_bytes(), state(self.path)
        with self.assertRaises(schema_tools.SchemaToolError) as caught:
            schema_tools.adopt_sqlite(str(self.path), **parameters)
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)
        self.assertNotIn(SECRET, str(caught.exception))
        return caught.exception

    def test_adoption_changes_only_four_indexes_and_version_preserving_all_rows(self):
        before_schema, before_rows, counts = state(self.path)
        self.assertEqual(len(counts), 9)
        self.assertTrue(all(counts.values()))
        before_bytes = self.path.read_bytes()
        report = self.adopt()
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["changed"])
        after_schema, after_rows, after_counts = state(self.path)
        self.assertEqual((after_rows, after_counts), (before_rows, counts))
        self.assertEqual([row for row in after_schema if row[1] not in INDEXES], before_schema)
        self.assertEqual({row[1] for row in after_schema if row not in before_schema}, INDEXES)
        self.assertNotEqual(self.path.read_bytes(), before_bytes)
        self.assertTrue(schema_tools.audit_sqlite(str(self.path))["ok"])
        with database(self.path) as connection:
            self.assertEqual(connection.execute("SELECT version_num FROM alembic_version").fetchall(),
                             [(schema_tools.HEAD_REVISION,)])
        self.assertNotIn(SECRET, json.dumps(report))

    def test_multiple_nulls_remain_valid_and_each_nonnull_unique_is_enforced(self):
        self.adopt()
        for field in USER_FIELDS:
            with self.subTest(field=field), database(self.path) as connection:
                self.assertEqual(connection.execute(
                    'SELECT count(*) FROM users WHERE "' + field + '" IS NULL').fetchone()[0], 2)
                connection.execute('UPDATE users SET "' + field + '" = ? WHERE id=1', (SECRET,))
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute('UPDATE users SET "' + field + '" = ? WHERE id=2', (SECRET,))

    def test_already_head_is_idempotent_and_does_not_rewrite_source(self):
        self.adopt()
        fingerprint = self.prepare()
        before = self.path.read_bytes(), state(self.path)
        report = schema_tools.adopt_sqlite(
            str(self.path), backup_path=str(self.backup),
            expected_fingerprint=fingerprint, confirm_maintenance=True,
        )
        self.assertTrue(report["ok"])
        self.assertFalse(report["changed"])
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)

    def test_success_does_not_modify_backup(self):
        fingerprint = self.prepare()
        before = self.backup.read_bytes(), state(self.backup)
        schema_tools.adopt_sqlite(str(self.path), backup_path=str(self.backup),
                                 expected_fingerprint=fingerprint, confirm_maintenance=True)
        self.assertEqual((self.backup.read_bytes(), state(self.backup)), before)

    def test_confirmation_required_and_truthy_nonbool_does_not_authorize(self):
        for value in (False, None, "yes", 1):
            with self.subTest(value=value):
                self.assert_rejected(confirm_maintenance=value)

    def test_expected_fingerprint_must_match_current_full_schema(self):
        for value in ("0" * 64, "", SECRET, None):
            with self.subTest(value=value):
                self.assert_rejected(expected_fingerprint=value)

    def test_source_changed_after_operator_audit_is_rejected(self):
        fingerprint = self.prepare()
        self.execute("CREATE INDEX unexpected_drift ON announcements(title)")
        self.assert_rejected(expected_fingerprint=fingerprint)

    def test_existing_wrong_same_name_index_is_not_silently_replaced(self):
        self.execute("CREATE UNIQUE INDEX ux_users_steam_id ON users(reset_token)")
        self.assert_rejected()

    def test_existing_nonunique_same_name_index_is_rejected(self):
        self.execute("CREATE INDEX ux_users_steam_id ON users(steam_id)")
        self.assert_rejected()

    def test_existing_partial_same_name_index_is_rejected(self):
        self.execute("CREATE UNIQUE INDEX ux_users_steam_id ON users(steam_id) WHERE steam_id IS NOT NULL")
        self.assert_rejected()

    def test_unexpected_view_is_rejected_without_repair(self):
        self.execute("CREATE VIEW unexpected_view AS SELECT username FROM users")
        self.assert_rejected()

    def test_unexpected_trigger_is_rejected_without_repair(self):
        self.execute("CREATE TRIGGER unexpected_trigger AFTER INSERT ON announcements BEGIN SELECT 1; END")
        self.assert_rejected()

    def test_duplicate_nonnull_user_fields_are_rejected_without_row_changes(self):
        for field in USER_FIELDS:
            with self.subTest(field=field):
                self.execute('UPDATE users SET "' + field + '"=?', (SECRET,))
                self.assert_rejected()
                self.execute('UPDATE users SET "' + field + '"=NULL')

    def test_unexpected_alembic_revision_is_rejected(self):
        self.execute("CREATE TABLE alembic_version(version_num VARCHAR(32) NOT NULL PRIMARY KEY)")
        self.execute("INSERT INTO alembic_version(version_num) VALUES(?)", (SECRET,))
        self.assert_rejected()

    def test_stale_backup_with_identical_schema_but_different_rows_is_rejected(self):
        fingerprint = self.prepare()
        self.execute("UPDATE announcements SET title='changed-after-backup' WHERE id=1")
        before = self.path.read_bytes(), state(self.path)
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.adopt_sqlite(str(self.path), backup_path=str(self.backup),
                                     expected_fingerprint=fingerprint, confirm_maintenance=True)
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)

    def test_backup_with_changed_row_not_just_same_counts_is_rejected(self):
        fingerprint = self.prepare()
        with database(self.backup) as connection:
            connection.execute("UPDATE announcements SET content=?", ("different-" + SECRET,))
        before = self.path.read_bytes(), state(self.path)
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.adopt_sqlite(str(self.path), backup_path=str(self.backup),
                                     expected_fingerprint=fingerprint, confirm_maintenance=True)
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)

    def test_backup_with_extra_schema_object_is_rejected(self):
        fingerprint = self.prepare()
        with database(self.backup) as connection:
            connection.execute("CREATE VIEW backup_only_view AS SELECT 1")
        before = self.path.read_bytes()
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.adopt_sqlite(str(self.path), backup_path=str(self.backup),
                                     expected_fingerprint=fingerprint, confirm_maintenance=True)
        self.assertEqual(self.path.read_bytes(), before)

    def test_backup_cannot_be_source_itself(self):
        self.assert_rejected(backup_path=str(self.path))

    def test_backup_must_be_existing_absolute_regular_file(self):
        for path in (self.root / "missing.sqlite", self.root, Path("relative.sqlite")):
            with self.subTest(path=path):
                self.assert_rejected(backup_path=str(path))
        self.assertFalse((self.root / "missing.sqlite").exists())

    def test_empty_backup_is_rejected(self):
        empty = self.root / "empty.sqlite"
        empty.touch()
        self.assert_rejected(backup_path=str(empty))
        self.assertEqual(empty.stat().st_size, 0)

    def test_source_must_be_existing_absolute_regular_file(self):
        fingerprint = self.prepare()
        before = self.path.read_bytes()
        for path in (self.root / "missing.sqlite", self.root, Path("relative.sqlite")):
            with self.subTest(path=path), self.assertRaises(schema_tools.SchemaToolError):
                schema_tools.adopt_sqlite(str(path), backup_path=str(self.backup),
                                         expected_fingerprint=fingerprint, confirm_maintenance=True)
        self.assertFalse((self.root / "missing.sqlite").exists())
        self.assertEqual(self.path.read_bytes(), before)

    def test_hard_linked_source_is_refused_before_writes(self):
        alias = self.root / "source-link.sqlite"
        try:
            os.link(self.path, alias)
        except (OSError, NotImplementedError):
            self.skipTest("Filesystem does not support hard links")
        self.assert_rejected()

    def test_hard_linked_backup_is_refused(self):
        self.prepare()
        alias = self.root / "backup-link.sqlite"
        try:
            os.link(self.backup, alias)
        except (OSError, NotImplementedError):
            self.skipTest("Filesystem does not support hard links")
        fingerprint = schema_tools.audit_sqlite(str(self.path))["schema_fingerprint"]
        before = self.path.read_bytes()
        with self.assertRaises(schema_tools.SchemaToolError):
            schema_tools.adopt_sqlite(str(self.path), backup_path=str(alias),
                                     expected_fingerprint=fingerprint, confirm_maintenance=True)
        self.assertEqual(self.path.read_bytes(), before)

    def test_symlink_source_and_backup_are_refused(self):
        self.prepare()
        alias = self.root / "source-symlink.sqlite"
        backup_alias = self.root / "backup-symlink.sqlite"
        try:
            alias.symlink_to(self.path)
            backup_alias.symlink_to(self.backup)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")
        fingerprint = schema_tools.audit_sqlite(str(self.path))["schema_fingerprint"]
        before = self.path.read_bytes()
        for source_path, backup_path in ((alias, self.backup), (self.path, backup_alias)):
            with self.subTest(source=source_path), self.assertRaises(schema_tools.SchemaToolError):
                schema_tools.adopt_sqlite(str(source_path), backup_path=str(backup_path),
                                         expected_fingerprint=fingerprint, confirm_maintenance=True)
        self.assertEqual(self.path.read_bytes(), before)

    def test_active_boost_blocks_adoption(self):
        self.execute("UPDATE steam_accounts SET is_boosting=1")
        self.assert_rejected()

    def test_legacy_data_preconditions_reject_each_unfinished_startup_repair(self):
        mutations = (
            ("UPDATE users SET plan='basic' WHERE id=1", "UPDATE users SET plan='free' WHERE id=1"),
            ("UPDATE user_sessions SET token_jti=NULL", "UPDATE user_sessions SET token_jti='synthetic-session-jti'"),
            ("UPDATE payments SET owner_user_id_snapshot=NULL", "UPDATE payments SET owner_user_id_snapshot=1"),
            ("UPDATE boost_logs SET duration_microseconds=NULL", "UPDATE boost_logs SET duration_microseconds=1000000"),
            ("UPDATE boost_logs SET account_id_snapshot=NULL", "UPDATE boost_logs SET account_id_snapshot='account-a'"),
            ("UPDATE steam_accounts SET steam_id='invalid'", "UPDATE steam_accounts SET steam_id='76561198000000000'"),
            ("UPDATE users SET last_login='2026-09-08T00:00:00Z' WHERE id=1", "UPDATE users SET last_login=NULL WHERE id=1"),
            ("UPDATE users SET is_admin=7 WHERE id=1", "UPDATE users SET is_admin=0 WHERE id=1"),
        )
        for change, restore in mutations:
            with self.subTest(change=change):
                self.execute(change)
                self.assert_rejected()
                self.execute(restore)

    def test_explicit_custom_paid_plan_list_is_checked(self):
        self.execute("UPDATE users SET plan='organization' WHERE id=1")
        self.assert_rejected(paid_plan_names=("organization",))

    def test_stamp_failure_rolls_back_all_new_indexes_and_version(self):
        with patch.object(schema_tools, "_stamp_adopted_connection", side_effect=RuntimeError(SECRET)):
            self.assert_rejected()
        with database(self.path) as connection:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema")}
        self.assertFalse(names & INDEXES)
        self.assertNotIn("alembic_version", names)

    def test_stamp_is_called_inside_real_exclusive_sqlite_transaction(self):
        original = schema_tools._stamp_adopted_connection
        observed = []

        def inspect_stamp(connection, *args, **kwargs):
            observed.append(connection.connection.driver_connection.in_transaction)
            with closing(sqlite3.connect(self.path, timeout=0.01)) as competitor:
                with self.assertRaises(sqlite3.OperationalError):
                    competitor.execute("BEGIN IMMEDIATE")
            return original(connection, *args, **kwargs)

        with patch.object(schema_tools, "_stamp_adopted_connection", side_effect=inspect_stamp):
            report = self.adopt()
        self.assertTrue(report["ok"])
        self.assertEqual(observed, [True])

    def test_cli_requires_confirmation_and_returns_secret_free_failure(self):
        fingerprint = self.prepare()
        before = self.path.read_bytes()
        output = io.StringIO()
        with redirect_stdout(output):
            code = schema_tools.main([
                "adopt-sqlite", "--sqlite-path", str(self.path), "--backup-path", str(self.backup),
                "--expect-fingerprint", fingerprint,
            ])
        self.assertEqual(code, 2)
        report = json.loads(output.getvalue())
        self.assertFalse(report["ok"])
        self.assertNotIn(SECRET, output.getvalue())
        self.assertNotIn(str(self.path), output.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_cli_success_requires_explicit_target_backup_fingerprint_confirmation(self):
        fingerprint = self.prepare()
        output = io.StringIO()
        with redirect_stdout(output):
            code = schema_tools.main([
                "adopt-sqlite", "--sqlite-path", str(self.path), "--backup-path", str(self.backup),
                "--expect-fingerprint", fingerprint, "--confirm-maintenance",
            ])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["ok"])
        self.assertTrue(report["changed"])
        self.assertNotIn(SECRET, output.getvalue())

    def test_runtime_gate_is_readonly_and_restores_connection_query_only(self):
        self.adopt()
        before = self.path.read_bytes(), state(self.path)
        engine = create_engine("sqlite:///" + str(self.path))
        self.addCleanup(engine.dispose)
        original = schema_tools._audit_connection
        statements, modes = [], []

        @event.listens_for(engine, "before_cursor_execute")
        def record_statement(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement.lstrip().split()[0].upper())

        def inspect_audit(connection, *args, **kwargs):
            modes.append(connection.exec_driver_sql("PRAGMA query_only").scalar_one())
            self.assertTrue(connection.connection.driver_connection.in_transaction)
            return original(connection, *args, **kwargs)

        with patch.object(schema_tools, "_audit_connection", side_effect=inspect_audit):
            revision = schema_tools.assert_runtime_schema(engine, schema_tools.ROOT / "migrations")
        self.assertEqual(revision, schema_tools.HEAD_REVISION)
        self.assertEqual(modes, [1])
        self.assertFalse(set(statements) & {"CREATE", "DROP", "ALTER", "INSERT", "UPDATE", "DELETE"})
        with engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql("PRAGMA query_only").scalar_one(), 0)
            self.assertFalse(connection.connection.driver_connection.in_transaction)
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)

    def test_runtime_audit_failure_restores_query_only_and_suppresses_secret(self):
        from runtime_guardrails import RuntimeConfigError
        self.adopt()
        before = self.path.read_bytes(), state(self.path)
        engine = create_engine("sqlite:///" + str(self.path))
        self.addCleanup(engine.dispose)
        with patch.object(schema_tools, "_audit_connection", side_effect=RuntimeError(SECRET)):
            with self.assertRaises(RuntimeConfigError) as caught:
                schema_tools.assert_runtime_schema(engine, schema_tools.ROOT / "migrations")
        self.assertNotIn(SECRET, str(caught.exception))
        with engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql("PRAGMA query_only").scalar_one(), 0)
            self.assertFalse(connection.connection.driver_connection.in_transaction)
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)

    def test_runtime_gate_preserves_preexisting_query_only_policy(self):
        self.adopt()
        engine = create_engine("sqlite:///" + str(self.path))
        self.addCleanup(engine.dispose)
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA query_only=ON")
        self.assertEqual(schema_tools.assert_runtime_schema(engine, schema_tools.ROOT / "migrations"),
                         schema_tools.HEAD_REVISION)
        with engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql("PRAGMA query_only").scalar_one(), 1)

    def test_runtime_gate_does_not_treat_recovery_boost_state_as_adoption_blocker(self):
        self.adopt()
        self.execute("UPDATE steam_accounts SET is_boosting=1")
        before = self.path.read_bytes(), state(self.path)
        engine = create_engine("sqlite:///" + str(self.path))
        self.addCleanup(engine.dispose)
        self.assertEqual(schema_tools.assert_runtime_schema(engine, schema_tools.ROOT / "migrations"),
                         schema_tools.HEAD_REVISION)
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)

    def test_runtime_gate_refuses_unstamped_schema_without_automatic_adoption(self):
        from runtime_guardrails import RuntimeConfigError
        before = self.path.read_bytes(), state(self.path)
        engine = create_engine("sqlite:///" + str(self.path))
        self.addCleanup(engine.dispose)
        with self.assertRaises(RuntimeConfigError):
            schema_tools.assert_runtime_schema(engine, schema_tools.ROOT / "migrations")
        self.assertEqual((self.path.read_bytes(), state(self.path)), before)

    def test_new_revision_refuses_populated_baseline_before_ddl(self):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        revision_path = schema_tools.ROOT / "migrations" / "versions" / "20260908_01_sqlite_adoption.py"
        spec = importlib.util.spec_from_file_location("adoption_revision_under_test", revision_path)
        revision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(revision)
        engine = schema_tools._engine()
        self.addCleanup(engine.dispose)
        with engine.begin() as connection:
            schema_tools._bootstrap_connection(connection, revision=schema_tools.BASELINE_REVISION)
            connection.exec_driver_sql("INSERT INTO announcements(title,content) VALUES('fixture', 'fixture')")
            before = connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name").fetchall()
            context = MigrationContext.configure(connection)
            with Operations.context(context), self.assertRaisesRegex(RuntimeError, "Populated"):
                revision.upgrade()
            self.assertEqual(connection.exec_driver_sql(
                "SELECT type,name,sql FROM sqlite_schema ORDER BY type,name").fetchall(), before)
            self.assertEqual(connection.exec_driver_sql("SELECT count(*) FROM announcements").scalar_one(), 1)

    def test_new_revision_rejects_logical_autobegin_without_physical_begin(self):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        revision_path = schema_tools.ROOT / "migrations" / "versions" / "20260908_01_sqlite_adoption.py"
        spec = importlib.util.spec_from_file_location("adoption_revision_no_begin_test", revision_path)
        revision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(revision)
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        with engine.begin() as connection:
            self.assertFalse(connection.connection.driver_connection.in_transaction)
            context = MigrationContext.configure(connection)
            with Operations.context(context), self.assertRaisesRegex(RuntimeError, "explicit SQLite transaction"):
                revision.upgrade()


if __name__ == "__main__":
    unittest.main()
