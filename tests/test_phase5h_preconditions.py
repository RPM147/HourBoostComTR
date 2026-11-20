"""Focused read-only legacy-data prerequisites; never load runtime app/config."""

from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sqlalchemy import event, text

import schema_preconditions as checks_module
from schema_preconditions import LegacyDataCheckError, check_legacy_data
import schema_tools


ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-09 12:30:45.123456"
TOKEN = "HB-" + "A" * 32
SECRET = "private-row-value-do-not-print"


@unittest.skipUnless(importlib.util.find_spec("alembic"), "Alembic unavailable")
class LegacyDataPreconditionTests(unittest.TestCase):
    def setUp(self):
        self.connection = self.enterContext(schema_tools._reference_database())

    def execute(self, statement, values=None):
        return self.connection.execute(text(statement), values or {})

    def insert(self, table, **values):
        # Test-owned table/column identifiers, never user-controlled inputs.
        columns = ", ".join('"' + name + '"' for name in values)
        placeholders = ", ".join(":" + name for name in values)
        self.execute(f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders})', values)

    def user(self, user_id=1, **changes):
        values = dict(id=user_id, username="owner-" + str(user_id),
                      email="owner-" + str(user_id) + "@example.invalid",
                      password_hash="fixture-not-a-password", plan="free")
        values.update(changes)
        self.insert("users", **values)

    def account(self, **changes):
        values = dict(id="account-1", user_id=1, steam_username="steam-fixture",
                      steam_id="76561198000000001", is_boosting=0)
        values.update(changes)
        self.insert("steam_accounts", **values)

    def payment(self, **changes):
        values = dict(id=1, user_id=1, owner_user_id_snapshot=1,
                      owner_username_snapshot="owner-1", amount=29.99,
                      plan="basic", status="checkout_started", match_token=TOKEN)
        values.update(changes)
        self.insert("payments", **values)

    def boost(self, **changes):
        values = dict(id=1, account_id="account-1", user_id=1,
                      account_id_snapshot="account-1",
                      steam_username_snapshot="steam-fixture",
                      owner_user_id_snapshot=1, owner_username_snapshot="owner-1",
                      started_at=NOW, duration_seconds=1, duration_microseconds=500_001)
        values.update(changes)
        self.insert("boost_logs", **values)

    def audit(self, **options):
        return check_legacy_data(self.connection, **options)

    def assert_fails(self, *names):
        report = self.audit()
        self.assertFalse(report["ok"], report)
        for name in names:
            self.assertGreater(report["checks"][name], 0, report)
        return report

    def test_empty_head_passes_without_mutating(self):
        before = self.connection.connection.driver_connection.total_changes
        report = self.audit(require_idle=True)
        self.assertEqual(set(report), {"ok", "scope", "checks"})
        self.assertTrue(report["ok"])
        self.assertTrue(all(type(count) is int and count == 0
                            for count in report["checks"].values()))
        self.assertEqual(before, self.connection.connection.driver_connection.total_changes)

    def test_complete_current_rows_pass(self):
        self.user(plan="premium", plan_activated_at=NOW, created_at=NOW)
        self.account()
        self.payment()
        self.boost()
        self.insert("boost_games", id=1, account_id="account-1", app_id=730)
        self.insert("user_sessions", id=1, user_id=1, token_jti="fixture-jti",
                    expires_at=NOW, created_at=NOW, last_seen=NOW, is_active=1)
        self.insert("revoked_tokens", id=1, user_id=1, token_jti="revoked-jti",
                    revoked_at=NOW, expires_at=NOW)
        self.insert("payment_audit_logs", id=1, payment_id=1,
                    actor_username="deleted-admin", action="hide",
                    reason="operator requested", created_at=NOW)
        self.insert("announcements", id=1, title="Notice", content="Content",
                    type="info", is_active=1, created_at=NOW)
        self.assertTrue(self.audit(require_idle=True)["ok"])

    def test_frozen_storage_inventory_covers_every_model_column(self):
        from models import db
        from time_utils import UTCDateTime
        expected_dates = {}
        for table in db.metadata.sorted_tables:
            dates = {column.name for column in table.columns
                     if isinstance(column.type, UTCDateTime)}
            if dates:
                expected_dates[table.name] = dates
            frozen = set(checks_module._STORAGE[table.name]) | dates
            self.assertEqual(frozen, set(table.columns.keys()), table.name)
        self.assertEqual(expected_dates, {
            table: set(columns) for table, columns in checks_module.UTC_DATETIME_COLUMNS.items()
        })
        expected_required = {(table.name, column.name)
                             for table in db.metadata.sorted_tables
                             for column in table.columns
                             if isinstance(column.type, UTCDateTime) and not column.nullable}
        self.assertEqual(expected_required, checks_module._REQUIRED_TIMESTAMPS)

    def test_valid_timestamp_variations_and_nullable_old_dates_pass(self):
        self.user()
        for value in (None, "1970-01-01 00:00:00", "2024-02-29 01:02:03.1",
                      "9999-12-31 23:59:59.999999"):
            with self.subTest(value=value):
                self.execute("UPDATE users SET created_at=:value", {"value": value})
                self.assertTrue(self.audit()["ok"])

    def test_invalid_timestamp_storage_format_and_calendar_are_counted(self):
        self.user()
        invalid = ("2026-02-29 00:00:00", "2026-01-01T00:00:00",
                   "2026-01-01 00:00:00+00:00", "2026-01-01 00:00:00Z",
                   "2026-01-01 00:00:00.1234567", "2026-01-01", "",
                   "0000-01-01 00:00:00", "2026-01-01 24:00:00",
                   "2026-01-01 24:00:00.000000", "2026-01-01 23:60:00",
                   "2026-01-01 23:59:60", 123,
                   sqlite3.Binary(b"2026-01-01 00:00:00"))
        for value in invalid:
            with self.subTest(value=repr(value)):
                self.execute("UPDATE users SET created_at=:value", {"value": value})
                self.assert_fails("users.created_at.invalid_timestamp")

    def test_required_timestamp_nulls_are_counted_even_in_invalid_legacy_storage(self):
        # A disposable fake result exercises NULLs that modern DDL rejects.
        real_execute = self.connection.execute
        def fake_execute(statement, *args, **kwargs):
            if str(statement) == 'SELECT "created_at" FROM "payment_audit_logs"':
                return [(None,)]
            return real_execute(statement, *args, **kwargs)
        with patch.object(self.connection, "execute", side_effect=fake_execute):
            self.assert_fails("payment_audit_logs.created_at.invalid_timestamp")

    def test_paid_activation_policy_is_explicit_and_free_null_is_valid(self):
        self.user(plan="basic")
        self.assert_fails("users.paid_missing_activation")
        self.assertTrue(self.audit(paid_plan_names=())["ok"])
        self.execute("UPDATE users SET plan='enterprise'")
        self.assertTrue(self.audit()["ok"])
        self.assertFalse(self.audit(paid_plan_names=("enterprise",))["ok"])
        self.execute("UPDATE users SET plan='free'")
        self.assertTrue(self.audit()["ok"])

    def test_plan_names_are_bound_not_interpolated(self):
        malicious_name = "basic'); DROP TABLE users; --"
        self.user(plan=malicious_name)
        report = self.audit(paid_plan_names=(malicious_name,))
        self.assertEqual(report["checks"]["users.paid_missing_activation"], 1)
        self.assertNotIn(malicious_name, json.dumps(report))
        self.assertEqual(self.execute("SELECT COUNT(*) FROM users").scalar_one(), 1)

    def test_active_boost_gate_only_applies_to_offline_adoption(self):
        self.user()
        self.account(is_boosting=1)
        self.assertTrue(self.audit()["ok"])
        self.assertNotIn("steam_accounts.active_boost", self.audit()["checks"])
        self.assertEqual(self.audit(require_idle=True)["checks"]["steam_accounts.active_boost"], 1)

    def test_steam_id_policy_matches_legacy_whitespace_and_unicode_digits(self):
        self.user()
        self.account()
        for value in (None, "76561198000000001", " 76561198000000001 ", "١" * 17):
            with self.subTest(value=value):
                self.execute("UPDATE steam_accounts SET steam_id=:value", {"value": value})
                self.assertTrue(self.audit()["ok"])
        for value in ("None", "", "123", "A" * 17):
            with self.subTest(value=value):
                self.execute("UPDATE steam_accounts SET steam_id=:value", {"value": value})
                self.assert_fails("steam_accounts.invalid_steam_id")

    def test_active_session_missing_jti_or_expiry_blocks_even_when_expired(self):
        self.user()
        self.insert("user_sessions", id=1, user_id=1, is_active=1,
                    expires_at="2000-01-01 00:00:00", token_jti=None)
        self.assert_fails("user_sessions.active_missing_auth")
        self.execute("UPDATE user_sessions SET token_jti='   '")
        self.assert_fails("user_sessions.active_missing_auth")
        self.execute("UPDATE user_sessions SET token_jti='normal', expires_at=NULL")
        self.assert_fails("user_sessions.active_missing_auth")
        self.execute("UPDATE user_sessions SET is_active=0")
        self.assertTrue(self.audit()["ok"])

    def test_inactive_legacy_session_and_nullable_flags_remain_valid(self):
        self.user(is_admin=None, is_verified=None)
        self.insert("user_sessions", id=1, user_id=1, is_active=0)
        self.account(is_boosting=None)
        self.assertTrue(self.audit(require_idle=True)["ok"])

    def test_payment_missing_and_mismatched_owner_snapshots_block(self):
        self.user()
        self.payment(owner_user_id_snapshot=None, owner_username_snapshot=None)
        self.assert_fails("payments.missing_owner_snapshot")
        self.execute("UPDATE payments SET owner_user_id_snapshot=2, owner_username_snapshot='old'")
        self.assert_fails("payments.owner_id_mismatch")

    def test_unmatched_webhook_and_old_manual_pending_allow_null_hb(self):
        self.insert("payments", id=1, status="verification_pending",
                    transaction_id="unmatched-order")
        self.insert("payments", id=2, status="pending")
        self.assertTrue(self.audit()["ok"])

    def test_detached_financial_rows_keep_unknown_or_historical_snapshots(self):
        self.insert("payments", id=1, status="completed", user_id=None,
                    owner_user_id_snapshot=987, owner_username_snapshot=None,
                    owner_detached_at=NOW, match_token="HB-ABC123")
        self.insert("payments", id=2, status="cancelled", user_id=None)
        self.assertTrue(self.audit()["ok"])

    def test_pending_checkout_intent_must_be_migrated(self):
        self.user()
        self.payment(status="pending")
        self.assert_fails("payments.pending_checkout_intent")
        self.execute("UPDATE payments SET transaction_id='already-received'")
        self.assertTrue(self.audit()["ok"])

    def test_present_active_hb_must_be_canonical_128_bit(self):
        self.user()
        self.payment()
        for status in ("checkout_started", "pending", "verification_pending"):
            for value in ("HB-ABC123", "", "hB-" + "a" * 32, " " + TOKEN):
                with self.subTest(status=status, value=value):
                    self.execute("UPDATE payments SET status=:status, match_token=:value, "
                                 "transaction_id='seen'", {"status": status, "value": value})
                    report = self.audit()
                    self.assertFalse(report["ok"])
                    self.assertTrue(report["checks"]["payments.invalid_active_hb"]
                                    or report["checks"]["payments.noncanonical_hb"])

    def test_archived_hb_is_not_silently_renormalized(self):
        self.insert("payments", id=1, status="cancelled", match_token=" hb-abc123 ")
        self.assert_fails("payments.noncanonical_hb")
        self.assertEqual(self.execute("SELECT match_token FROM payments").scalar_one(), " hb-abc123 ")

    def test_duplicate_normalized_hb_is_counted_without_values(self):
        self.insert("payments", id=1, status="cancelled", match_token="HB-ABC123")
        self.insert("payments", id=2, status="completed", match_token="hb-abc123")
        report = self.assert_fails("payments.duplicate_normalized_hb_groups")
        self.assertEqual(report["checks"]["payments.duplicate_normalized_hb_groups"], 1)
        self.assertNotIn("ABC123", json.dumps(report))

    def test_duplicate_open_checkout_groups_are_counted(self):
        self.user()
        # Schema audit detects this missing index separately; data gate must
        # independently identify old duplicate rows before any adoption DDL.
        self.execute("DROP INDEX ux_payments_one_open_checkout")
        self.payment()
        self.payment(id=2, match_token="HB-" + "B" * 32, status="verification_pending")
        self.assert_fails("payments.duplicate_open_checkout_groups")

    def test_duplicate_transaction_groups_are_counted(self):
        # The current UNIQUE cannot store duplicates. Simulate only the row
        # count, so the test does not rewrite the frozen financial table.
        count_original = checks_module._count
        def duplicate_count(connection, statement, parameters=None):
            if "GROUP BY transaction_id HAVING COUNT(*) > 1" in statement:
                return 1
            return count_original(connection, statement, parameters)
        with patch.object(checks_module, "_count", side_effect=duplicate_count):
            self.assert_fails("payments.duplicate_transaction_groups")

    def test_nonfinite_negative_and_invalid_financial_storage_block(self):
        self.insert("payments", id=1, status="cancelled")
        for value in (-0.01, float("inf"), SECRET, sqlite3.Binary(b"private-amount")):
            with self.subTest(value=repr(value)):
                self.execute("UPDATE payments SET amount=:value", {"value": value})
                report = self.assert_fails("payments.invalid_amount")
                self.assertNotIn(SECRET, json.dumps(report))
        self.execute("UPDATE payments SET amount=0, verification_attempts=-1")
        self.assert_fails("payments.negative_financial_integer")
        self.execute("UPDATE payments SET verification_attempts=0, verified_amount_minor=-1")
        self.assert_fails("payments.negative_financial_integer")
        self.execute("UPDATE payments SET verified_amount_minor=0, shopier_timestamp=-1")
        self.assert_fails("payments.negative_financial_integer")

    def test_blob_text_and_nonboolean_integer_storage_are_counted(self):
        self.user()
        self.account()
        self.execute("UPDATE users SET username=:value, is_admin=2", {"value": sqlite3.Binary(SECRET.encode())})
        self.execute("UPDATE steam_accounts SET persona_state='not-an-integer'")
        report = self.assert_fails("users.invalid_storage", "steam_accounts.invalid_storage")
        self.assertNotIn(SECRET, json.dumps(report))

    def test_missing_recoverable_boost_snapshots_block(self):
        self.user()
        self.account()
        self.boost(account_id_snapshot=None, steam_username_snapshot=None,
                   owner_user_id_snapshot=None, owner_username_snapshot=None)
        self.assert_fails("boost_logs.missing_account_snapshot",
                          "boost_logs.missing_steam_username_snapshot",
                          "boost_logs.missing_owner_id_snapshot",
                          "boost_logs.missing_owner_username_snapshot")

    def test_boost_owner_fallback_without_direct_user_still_requires_snapshot(self):
        self.user()
        self.account()
        self.boost(user_id=None, owner_user_id_snapshot=None,
                   owner_username_snapshot=None)
        self.assert_fails("boost_logs.missing_owner_id_snapshot",
                          "boost_logs.missing_owner_username_snapshot")

    def test_detached_boost_history_with_unknown_snapshots_is_preserved(self):
        self.boost(account_id=None, user_id=None, account_id_snapshot=None,
                   steam_username_snapshot=None, owner_user_id_snapshot=None,
                   owner_username_snapshot=None)
        self.boost(id=2, account_id=None, user_id=None,
                   account_id_snapshot="deleted-account", steam_username_snapshot=None,
                   owner_user_id_snapshot=999, owner_username_snapshot=None)
        self.assertTrue(self.audit()["ok"])

    def test_live_owner_with_deleted_account_allows_unknown_account_snapshot(self):
        self.user()
        self.boost(account_id=None, account_id_snapshot=None,
                   steam_username_snapshot=None)
        self.assertTrue(self.audit()["ok"])

    def test_cross_owner_and_snapshot_identity_mismatch_block(self):
        self.user()
        self.user(2)
        self.account()
        self.boost(user_id=2, owner_user_id_snapshot=1, account_id_snapshot="wrong-account")
        self.assert_fails("boost_logs.cross_owner_reference",
                          "boost_logs.owner_id_mismatch", "boost_logs.account_id_mismatch")

    def test_legacy_seconds_only_is_reported_without_backfill(self):
        self.boost(account_id=None, user_id=None, duration_microseconds=None)
        self.assert_fails("boost_logs.legacy_seconds_only")
        self.assertIsNone(self.execute("SELECT duration_microseconds FROM boost_logs").scalar_one())

    def test_existing_snapshot_username_is_not_compared_to_renamed_live_owner(self):
        self.user(username="renamed-owner")
        self.account(steam_username="renamed-steam")
        self.payment(owner_username_snapshot="original-owner")
        self.boost(owner_username_snapshot="original-owner", steam_username_snapshot="original-steam")
        self.assertTrue(self.audit()["ok"])

    def test_audit_uses_only_selects_and_works_with_query_only(self):
        self.user()
        statements = []
        def collect(connection, cursor, statement, parameters, context, many):
            statements.append(statement)
        self.execute("PRAGMA query_only=ON")
        event.listen(self.connection, "before_cursor_execute", collect)
        try:
            self.assertTrue(self.audit()["ok"])
        finally:
            event.remove(self.connection, "before_cursor_execute", collect)
            self.execute("PRAGMA query_only=OFF")
        self.assertTrue(statements)
        self.assertTrue(all(statement.lstrip().upper().startswith("SELECT ")
                            for statement in statements), statements)

    def test_safe_constant_error_hides_sql_and_driver_exception(self):
        with patch.object(self.connection, "execute", side_effect=RuntimeError(SECRET)):
            with self.assertRaises(LegacyDataCheckError) as raised:
                self.audit()
        self.assertEqual(str(raised.exception), "Legacy data precondition audit could not be completed.")
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)

    def test_rejects_missing_transaction_wrong_backend_and_invalid_policies(self):
        fake = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"), in_transaction=lambda: False)
        for connection in (fake, SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))):
            with self.subTest(connection=connection), self.assertRaises(LegacyDataCheckError):
                check_legacy_data(connection)
        for options in ({"require_idle": 1}, {"paid_plan_names": "basic"},
                        {"paid_plan_names": b"basic"}, {"paid_plan_names": [""]},
                        {"paid_plan_names": [None]}, {"paid_plan_names": ["basic"] * 101}):
            with self.subTest(options=options), self.assertRaises(LegacyDataCheckError):
                self.audit(**options)

    def test_import_never_loads_runtime_or_environment_modules(self):
        script = """
import importlib.abc, sys
class BlockRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'app', 'config', 'models', 'dotenv', 'boost_log_migration'}:
            raise AssertionError('forbidden runtime import')
sys.meta_path.insert(0, BlockRuntime())
import schema_preconditions
assert 'app' not in sys.modules and 'config' not in sys.modules
print('isolated-import-ok')
"""
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT,
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "isolated-import-ok")

    def test_audit_holds_one_wal_snapshot_across_concurrent_commit(self):
        with tempfile.TemporaryDirectory(prefix="hourboost-precondition-wal-") as directory:
            path = Path(directory).resolve() / "fixture.sqlite"
            with closing(sqlite3.connect(path)) as raw:
                raw.execute("PRAGMA journal_mode=WAL")
            engine = schema_tools._engine(path)
            try:
                with engine.begin() as connection:
                    schema_tools._bootstrap_connection(connection)
                    connection.exec_driver_sql("INSERT INTO users "
                        "(id, username, email, password_hash, plan) VALUES "
                        "(1, 'owner', 'owner@example.invalid', 'fixture', 'free')")
                readonly = schema_tools._engine(path, readonly=True)
                try:
                    with readonly.begin() as connection:
                        # First SELECT establishes the old snapshot.
                        connection.exec_driver_sql("SELECT COUNT(*) FROM users").scalar_one()
                        with engine.begin() as writer:
                            writer.exec_driver_sql("UPDATE users SET plan='premium'")
                        self.assertTrue(check_legacy_data(connection)["ok"])
                    with readonly.begin() as connection:
                        report = check_legacy_data(connection)
                        self.assertFalse(report["ok"])
                        self.assertEqual(report["checks"]["users.paid_missing_activation"], 1)
                finally:
                    readonly.dispose()
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
