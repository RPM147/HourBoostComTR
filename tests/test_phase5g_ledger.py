import math
import unittest

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from boost_log_migration import (
    _duration_ledger_check_sql,
    migrate_boost_duration_ledger,
)
from usage_ledger import (
    MAX_DURATION_MICROSECONDS,
    MICROSECONDS_PER_SECOND,
    billable_microseconds,
    capped_microseconds,
    effective_microseconds,
    legacy_seconds_for_microseconds,
)


class UsageLedgerPrimitiveTests(unittest.TestCase):
    def test_runtime_seconds_are_rounded_once_to_a_microsecond(self):
        self.assertEqual(billable_microseconds(0), 0)
        self.assertEqual(billable_microseconds(0.0000001), 1)
        self.assertEqual(billable_microseconds(0.25), 250_000)
        self.assertEqual(billable_microseconds(1.0000000000000002), 1_000_000)
        self.assertEqual(billable_microseconds(1.000001), 1_000_001)

    def test_legacy_dual_write_is_conservative_without_becoming_canonical(self):
        self.assertEqual(legacy_seconds_for_microseconds(0), 0)
        self.assertEqual(legacy_seconds_for_microseconds(1), 1)
        self.assertEqual(legacy_seconds_for_microseconds(250_000), 1)
        self.assertEqual(legacy_seconds_for_microseconds(1_000_000), 1)
        self.assertEqual(legacy_seconds_for_microseconds(1_000_001), 2)

    def test_hard_cap_floor_absorbs_large_epoch_float_noise(self):
        started_epoch = 1_787_550_000.0
        wall_microseconds = 10_000_001 // 3
        stopped_epoch = (
            started_epoch
            + wall_microseconds / MICROSECONDS_PER_SECOND
        )
        observed = stopped_epoch - started_epoch

        self.assertEqual(capped_microseconds(observed), wall_microseconds)
        self.assertEqual(billable_microseconds(observed), wall_microseconds + 1)
        self.assertLessEqual(capped_microseconds(observed) * 3, 10_000_001)

    def test_reader_prefers_microseconds_and_falls_back_to_legacy_seconds(self):
        self.assertEqual(effective_microseconds(250_000, 99), 250_000)
        self.assertEqual(effective_microseconds(None, 7), 7_000_000)

    def test_invalid_or_unrepresentable_values_fail_closed(self):
        for value in (True, False, -1, math.nan, math.inf, -math.inf, "bad"):
            with self.subTest(value=value):
                with self.assertRaises((ValueError, OverflowError)):
                    billable_microseconds(value)
        with self.assertRaises(OverflowError):
            billable_microseconds(
                MAX_DURATION_MICROSECONDS / MICROSECONDS_PER_SECOND + 1
            )


class DurationLedgerMigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def _create_legacy_table(self):
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE boost_logs ("
                "id INTEGER PRIMARY KEY, "
                "duration_seconds INTEGER NOT NULL)"
            )

    def test_database_check_casts_legacy_seconds_before_multiplication(self):
        check_sql = _duration_ledger_check_sql()

        self.assertIn("CAST(duration_seconds AS BIGINT)", check_sql)
        self.assertNotIn("duration_seconds * 1000000", check_sql)

    def test_additive_backfill_preserves_seconds_and_is_idempotent(self):
        self._create_legacy_table()
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO boost_logs (id, duration_seconds) "
                "VALUES (1, 7), (2, 0)"
            )

        first = migrate_boost_duration_ledger(self.engine)
        second = migrate_boost_duration_ledger(self.engine)

        self.assertEqual(first["added_columns"], 1)
        self.assertEqual(first["backfilled_rows"], 2)
        self.assertEqual(first["duration_seconds"], 7)
        self.assertEqual(first["duration_microseconds"], 7_000_000)
        self.assertEqual(second["added_columns"], 0)
        self.assertEqual(second["backfilled_rows"], 0)
        self.assertIn(
            "duration_microseconds",
            {column["name"] for column in inspect(self.engine).get_columns(
                "boost_logs"
            )},
        )

    def test_mixed_rollback_row_is_backfilled_without_touching_fractional_row(self):
        self._create_legacy_table()
        migrate_boost_duration_ledger(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO boost_logs "
                "(id, duration_seconds, duration_microseconds) VALUES "
                "(1, 1, 250000), (2, 2, NULL)"
            ))

        report = migrate_boost_duration_ledger(self.engine)
        with self.engine.begin() as connection:
            rows = connection.execute(text(
                "SELECT id, duration_seconds, duration_microseconds "
                "FROM boost_logs ORDER BY id"
            )).all()

        self.assertEqual(report["backfilled_rows"], 1)
        self.assertEqual(rows, [(1, 1, 250_000), (2, 2, 2_000_000)])

    def test_invalid_legacy_duration_fails_before_schema_mutation(self):
        self._create_legacy_table()
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO boost_logs (id, duration_seconds) VALUES (1, -1)"
            )

        with self.assertRaisesRegex(RuntimeError, "invalid legacy durations"):
            migrate_boost_duration_ledger(self.engine)
        self.assertNotIn(
            "duration_microseconds",
            {column["name"] for column in inspect(self.engine).get_columns(
                "boost_logs"
            )},
        )

    def test_inconsistent_dual_write_is_rejected(self):
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE boost_logs ("
                "id INTEGER PRIMARY KEY, "
                "duration_seconds INTEGER NOT NULL, "
                "duration_microseconds BIGINT)"
            )
            connection.execute(text(
                "INSERT INTO boost_logs "
                "(id, duration_seconds, duration_microseconds) "
                "VALUES (1, 3600, 1)"
            ))

        with self.assertRaisesRegex(RuntimeError, "invalid canonical durations"):
            migrate_boost_duration_ledger(self.engine)

    def test_database_enforcement_rejects_invalid_dual_write(self):
        self._create_legacy_table()
        migrate_boost_duration_ledger(self.engine)

        with self.assertRaises(IntegrityError):
            with self.engine.begin() as connection:
                connection.execute(text(
                    "INSERT INTO boost_logs "
                    "(id, duration_seconds, duration_microseconds) "
                    "VALUES (1, 3600, 1)"
                ))

        for row_id, seconds, microseconds in (
            (2, 1, 1.5),
            (3, "one", 1),
            (4, 1, "one"),
        ):
            with self.subTest(
                seconds=seconds,
                microseconds=microseconds,
            ):
                with self.assertRaises(IntegrityError):
                    with self.engine.begin() as connection:
                        connection.execute(text(
                            "INSERT INTO boost_logs "
                            "(id, duration_seconds, duration_microseconds) "
                            "VALUES (:id, :seconds, :microseconds)"
                        ), {
                            "id": row_id,
                            "seconds": seconds,
                            "microseconds": microseconds,
                        })

        with self.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO boost_logs "
                "(id, duration_seconds, duration_microseconds) "
                "VALUES (5, 1, 250000)"
            ))
        with self.assertRaises(IntegrityError):
            with self.engine.begin() as connection:
                connection.execute(text(
                    "UPDATE boost_logs "
                    "SET duration_microseconds = 1000001 WHERE id = 5"
                ))

    def test_aggregate_overflow_is_rejected_without_backfill(self):
        self._create_legacy_table()
        too_large = (
            MAX_DURATION_MICROSECONDS // MICROSECONDS_PER_SECOND // 2 + 1
        )
        with self.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO boost_logs (id, duration_seconds) "
                "VALUES (1, :value), (2, :value)"
            ), {"value": too_large})

        with self.assertRaisesRegex(RuntimeError, "total exceeds"):
            migrate_boost_duration_ledger(self.engine)
        self.assertNotIn(
            "duration_microseconds",
            {column["name"] for column in inspect(self.engine).get_columns(
                "boost_logs"
            )},
        )


if __name__ == "__main__":
    unittest.main()
