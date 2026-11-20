from datetime import datetime, timedelta, timezone
import math
import unittest
from zoneinfo import ZoneInfo

from sqlalchemy import Column, Integer, MetaData, Table, create_engine, select

from time_utils import (
    Clock,
    UTC,
    UTCDateTime,
    as_utc,
    utc_iso_z,
)


class Phase5GDateTimeTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        self.metadata = MetaData()
        self.events = Table(
            "events",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("occurred_at", UTCDateTime(), nullable=False),
        )
        self.metadata.create_all(self.engine)

    def test_legacy_sqlite_value_reads_as_aware_utc_without_rewrite(self):
        legacy = "2026-07-26 14:13:53.516181"
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO events (id, occurred_at) VALUES (?, ?)",
                (1, legacy),
            )
            raw_before = connection.exec_driver_sql(
                "SELECT occurred_at FROM events WHERE id = 1"
            ).scalar_one()
            value = connection.execute(
                select(self.events.c.occurred_at).where(self.events.c.id == 1)
            ).scalar_one()
            raw_after = connection.exec_driver_sql(
                "SELECT occurred_at FROM events WHERE id = 1"
            ).scalar_one()

        self.assertEqual(raw_before, legacy)
        self.assertEqual(raw_after, legacy)
        self.assertEqual(
            value,
            datetime(2026, 7, 26, 14, 13, 53, 516181, tzinfo=UTC),
        )

    def test_aware_offset_write_is_normalized_to_naive_utc_storage(self):
        plus_three = timezone(timedelta(hours=3))
        supplied = datetime(
            2026,
            7,
            26,
            17,
            13,
            53,
            516181,
            tzinfo=plus_three,
        )
        with self.engine.begin() as connection:
            connection.execute(
                self.events.insert().values(id=1, occurred_at=supplied)
            )
            raw = connection.exec_driver_sql(
                "SELECT occurred_at FROM events WHERE id = 1"
            ).scalar_one()
            value = connection.execute(
                select(self.events.c.occurred_at).where(self.events.c.id == 1)
            ).scalar_one()

        self.assertEqual(raw, "2026-07-26 14:13:53.516181")
        self.assertEqual(
            value,
            datetime(2026, 7, 26, 14, 13, 53, 516181, tzinfo=UTC),
        )

    def test_aware_query_bound_compares_against_legacy_naive_rows(self):
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO events (id, occurred_at) VALUES (?, ?)",
                (1, "2026-07-26 14:13:53.000000"),
            )
            ids = connection.execute(
                select(self.events.c.id).where(
                    self.events.c.occurred_at
                    <= datetime(2026, 7, 26, 14, 13, 53, tzinfo=UTC)
                )
            ).scalars().all()

        self.assertEqual(ids, [1])

    def test_dst_repeated_hour_maps_to_two_distinct_utc_instants(self):
        berlin = ZoneInfo("Europe/Berlin")
        first = datetime(2026, 10, 25, 2, 30, tzinfo=berlin, fold=0)
        second = datetime(2026, 10, 25, 2, 30, tzinfo=berlin, fold=1)

        self.assertEqual(utc_iso_z(first), "2026-10-25T00:30:00Z")
        self.assertEqual(utc_iso_z(second), "2026-10-25T01:30:00Z")
        self.assertNotEqual(as_utc(first), as_utc(second))

    def test_month_year_and_leap_day_boundaries(self):
        cases = (
            (
                datetime(2024, 2, 29, 23, 59, 59, tzinfo=UTC),
                datetime(2024, 3, 1, 0, 0, 0, tzinfo=UTC),
            ),
            (
                datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC),
                datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
            ),
        )
        for before, expected in cases:
            with self.subTest(before=before):
                self.assertEqual(before + timedelta(seconds=1), expected)
                self.assertTrue(utc_iso_z(expected).endswith("Z"))

    def test_clock_rejects_non_finite_sources(self):
        for bad in (math.nan, math.inf, -math.inf):
            with self.subTest(kind="epoch", value=bad):
                with self.assertRaises(ValueError):
                    Clock(epoch_source=lambda bad=bad: bad).epoch()
            with self.subTest(kind="monotonic", value=bad):
                with self.assertRaises(ValueError):
                    Clock(monotonic_source=lambda bad=bad: bad).monotonic()

    def test_steady_epoch_ignores_wall_steps_and_tracks_monotonic_elapsed(self):
        state = {"wall": 2_000_000_000.0, "monotonic": 10_000.0}
        test_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        self.assertEqual(test_clock.steady_epoch(), 2_000_000_000.0)

        state["wall"] -= 3600.0
        state["monotonic"] += 90.0
        self.assertEqual(test_clock.epoch(), 1_999_996_400.0)
        self.assertEqual(test_clock.steady_epoch(), 2_000_000_090.0)

        state["wall"] += 86400.0
        state["monotonic"] += 30.0
        self.assertEqual(test_clock.steady_epoch(), 2_000_000_120.0)

    def test_advance_steady_floor_never_rewinds_and_keeps_elapsed_time(self):
        state = {"wall": 1_000.0, "monotonic": 10.0}
        test_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )

        self.assertEqual(test_clock.advance_steady_floor(1_010.0), 1_010.0)
        state["monotonic"] += 5.0
        self.assertEqual(test_clock.steady_epoch(), 1_015.0)
        self.assertEqual(test_clock.advance_steady_floor(900.0), 1_015.0)
        state["monotonic"] += 5.0
        self.assertEqual(test_clock.steady_epoch(), 1_020.0)

        for bad in (math.nan, math.inf, -math.inf):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    test_clock.advance_steady_floor(bad)


if __name__ == "__main__":
    unittest.main()
