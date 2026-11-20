"""Offline tests for the Phase 5H.1C transfer boundary.

These tests exercise only a disposable SQLite backup and fail closed when a
real PostgreSQL connection is unavailable.  They are not A2 acceptance.
"""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import sqlite3
import tempfile
import unittest

import sqlalchemy as sa
from sqlalchemy import create_engine
from unittest import mock

from postgresql_contract import POSTGRESQL_BASELINE_REVISION, TRANSFER_TABLES
from postgresql_transfer import (
    PostgreSQLTransferError,
    SQLITE_SOURCE_REVISION,
    inspect_sqlite_backup,
    iter_sqlite_rows,
    open_sqlite_backup,
    _postgresql_target_revision,
    _reset_identities,
    _validate_postgresql_column_contract,
    transfer_sqlite_backup,
)
from schema_tools import bootstrap_disposable


ROOT = Path(__file__).resolve().parents[1]


class PostgreSQLTransferOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="hourboost-pg-transfer-"))
        self.source = self.temp_dir / "accepted-backup.sqlite"
        result = bootstrap_disposable(str(self.source))
        self.assertTrue(result["ok"])

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_empty_accepted_backup_has_sanitized_deterministic_evidence(self):
        first = inspect_sqlite_backup(self.source)
        second = inspect_sqlite_backup(self.source)

        self.assertEqual(first, second)
        self.assertEqual(first["source_revision"], SQLITE_SOURCE_REVISION)
        self.assertRegex(first["source_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(tuple(first["tables"]), TRANSFER_TABLES)
        self.assertTrue(all(
            evidence["rows"] == 0
            for evidence in first["tables"].values()
        ))
        self.assertEqual(
            first["boost_ledger"],
            {"rows": 0, "duration_seconds": 0, "duration_microseconds": 0},
        )
        self.assertEqual(
            first["payment_minor"],
            {"rows": 0, "verified_amount_minor": 0},
        )

    def test_source_rows_are_read_in_strict_primary_key_order(self):
        raw = sqlite3.connect(self.source)
        try:
            raw.executemany(
                "INSERT INTO users(id,username,email,password_hash) "
                "VALUES (?,?,?,?)",
                (
                    (9, "later", "later@example.test", "hash"),
                    (3, "earlier", "earlier@example.test", "hash"),
                ),
            )
            raw.execute(
                "INSERT INTO payments(id,admin_hidden,verification_attempts,"
                "verified_amount_minor) VALUES (?,?,?,?)",
                (4, 0, 0, 2999),
            )
            raw.execute(
                "INSERT INTO boost_logs(id,started_at,duration_seconds,"
                "duration_microseconds) VALUES (?,?,?,?)",
                (7, "2026-09-14 00:00:00.123456", 2, 1_500_001),
            )
            raw.commit()
        finally:
            raw.close()

        with open_sqlite_backup(self.source) as (_path, connection, _sha256):
            rows = list(iter_sqlite_rows(connection, "users", batch_size=1))
        self.assertEqual([row["id"] for row in rows], [3, 9])

        evidence = inspect_sqlite_backup(self.source)
        self.assertEqual(evidence["tables"]["users"]["rows"], 2)
        self.assertEqual(
            evidence["payment_minor"],
            {"rows": 1, "verified_amount_minor": 2999},
        )
        self.assertEqual(
            evidence["boost_ledger"],
            {"rows": 1, "duration_seconds": 2, "duration_microseconds": 1_500_001},
        )

    def test_noncanonical_revision_sidecars_and_relative_paths_fail_closed(self):
        raw = sqlite3.connect(self.source)
        try:
            raw.execute(
                "UPDATE alembic_version SET version_num = 'unaccepted'"
            )
            raw.commit()
        finally:
            raw.close()
        with self.assertRaisesRegex(PostgreSQLTransferError, "revision"):
            inspect_sqlite_backup(self.source)

        replacement = self.temp_dir / "sidecar-source.sqlite"
        bootstrap_disposable(str(replacement))
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(replacement) + suffix)
            sidecar.write_bytes(b"not-a-consistent-copy")
            with self.subTest(sidecar=suffix), self.assertRaisesRegex(
                PostgreSQLTransferError, "standalone"
            ):
                inspect_sqlite_backup(replacement)
            sidecar.unlink()
        with self.assertRaisesRegex(PostgreSQLTransferError, "canonical"):
            inspect_sqlite_backup(Path("relative.sqlite"))

    def test_transfer_rejects_non_postgresql_target_before_any_load(self):
        engine = create_engine("sqlite:///:memory:", hide_parameters=True)
        try:
            with engine.begin() as connection:
                with self.assertRaisesRegex(
                    PostgreSQLTransferError,
                    "explicit target transaction",
                ):
                    transfer_sqlite_backup(
                        self.source,
                        connection,
                        target_schema="hourboost_rehearsal_test",
                    )
        finally:
            engine.dispose()

    def test_source_identity_change_during_snapshot_is_rejected(self):
        with self.assertRaisesRegex(PostgreSQLTransferError, "changed"):
            with open_sqlite_backup(self.source):
                stat = self.source.stat()
                # Change only metadata; the guard must still refuse to attest
                # that this is the same immutable backup snapshot.
                os.utime(
                    self.source,
                    ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000),
                )

        hash_source = self.temp_dir / "hash-change-source.sqlite"
        bootstrap_disposable(str(hash_source))
        with self.assertRaisesRegex(PostgreSQLTransferError, "changed"):
            with open_sqlite_backup(hash_source):
                stat = hash_source.stat()
                content = bytearray(hash_source.read_bytes())
                content[-1] ^= 1
                hash_source.write_bytes(content)
                # Restoring size and mtime must not bypass the content digest.
                os.utime(
                    hash_source,
                    ns=(stat.st_atime_ns, stat.st_mtime_ns),
                )

    def test_target_revision_must_be_one_exact_accepted_row(self):
        class _Scalars:
            def __init__(self, rows):
                self.rows = rows

            def all(self):
                return self.rows

        for rows in (
            [],
            ["wrong"],
            [POSTGRESQL_BASELINE_REVISION, POSTGRESQL_BASELINE_REVISION],
        ):
            connection = mock.Mock()
            connection.execute.return_value.scalars.return_value = _Scalars(rows)
            with self.subTest(rows=rows), self.assertRaisesRegex(
                PostgreSQLTransferError, "revision"
            ):
                _postgresql_target_revision(
                    connection,
                    "hourboost_rehearsal_test",
                )

        connection = mock.Mock()
        connection.execute.return_value.scalars.return_value = _Scalars(
            [POSTGRESQL_BASELINE_REVISION]
        )
        self.assertEqual(
            _postgresql_target_revision(
                connection,
                "hourboost_rehearsal_test",
            ),
            POSTGRESQL_BASELINE_REVISION,
        )
        statement = connection.execute.call_args.args[0]
        self.assertIn(
            '"hourboost_rehearsal_test".alembic_version',
            str(statement),
        )

    def test_wrong_postgresql_physical_type_is_rejected(self):
        bad_timestamp = sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=True,
        )
        with self.assertRaisesRegex(PostgreSQLTransferError, "column contract"):
            _validate_postgresql_column_contract("users", bad_timestamp)

    def test_identity_restart_uses_transactional_ddl_and_rejects_schema_injection(self):
        source, target = mock.Mock(), mock.Mock()
        source.execute.return_value.fetchone.return_value = (37,)
        planned = _reset_identities(source, target, {}, "hourboost_rehearsal_test")
        self.assertTrue(all(value == 38 for value in planned.values()))
        statements = [str(call.args[0]) for call in target.execute.call_args_list]
        self.assertEqual(len(statements), len(planned))
        self.assertTrue(all(statement.startswith('ALTER TABLE "hourboost_rehearsal_test".') for statement in statements))
        self.assertTrue(all(statement.endswith('ALTER COLUMN "id" RESTART WITH 38') for statement in statements))
        rejected = mock.Mock()
        with self.assertRaisesRegex(PostgreSQLTransferError, "schema"):
            _reset_identities(source, rejected, {}, 'public"; DROP SCHEMA public; --')
        rejected.execute.assert_not_called()

    def test_any_transfer_failure_rolls_back_the_outer_target_transaction(self):
        target = mock.Mock()
        with mock.patch(
            "postgresql_transfer._postgresql_target_tables",
            side_effect=PostgreSQLTransferError("rejected target"),
        ):
            with self.assertRaisesRegex(PostgreSQLTransferError, "rejected target"):
                transfer_sqlite_backup(
                    self.source,
                    target,
                    target_schema="hourboost_rehearsal_test",
                )
        target.rollback.assert_called_once_with()

        invalid_batch_target = mock.Mock()
        with self.assertRaisesRegex(PostgreSQLTransferError, "batch size"):
            transfer_sqlite_backup(
                self.source,
                invalid_batch_target,
                target_schema="hourboost_rehearsal_test",
                batch_size=0,
            )
        invalid_batch_target.rollback.assert_called_once_with()

    def test_loader_source_has_no_runtime_config_or_literal_value_insert(self):
        source = (ROOT / "postgresql_transfer.py").read_text(encoding="utf-8")
        for forbidden in (
            "import app",
            "from app",
            "import config",
            "from config",
            "load_dotenv",
            "DATABASE_URL",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("target.execute(table.insert(), batch)", source)
        self.assertNotIn("target.execute(f\"INSERT", source)


if __name__ == "__main__":
    unittest.main()
