import atexit
import copy
import itertools
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest import mock

import gevent
from gevent.event import Event
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.schema import CreateTable


_TEMP_DIR = tempfile.mkdtemp(prefix="hourboost-boost-tests-")
atexit.register(lambda: shutil.rmtree(_TEMP_DIR, ignore_errors=True))
_DB_PATH = Path(_TEMP_DIR, "boost-tests.db").as_posix()
os.environ["SECRET_KEY"] = "test-secret-key-" + "x" * 48
os.environ["DATABASE_URL"] = "sqlite:///" + _DB_PATH
os.environ["DB_SCHEMA_MODE"] = "alembic"
os.environ["STEAM_STATE_DIR"] = _TEMP_DIR
os.environ["SHOPIER_API_VERIFY_ENABLED"] = "false"
os.environ["SHOPIER_VERIFICATION_WORKER_ENABLED"] = "false"

from schema_fixture import (
    initialize_test_database, reset_test_schema,
)

initialize_test_database(_DB_PATH)

import app as app_module
from config import Config
from models import db, BoostGame, BoostLog, SteamAccount, User
import steam_manager
from steam_compat import EResult
from time_utils import Clock


_FIXTURE_IDS = itertools.count(1)


class _FakeSteamClient:
    def __init__(self):
        self._closed = False
        self.connected = True
        self.logged_in = True
        self.refresh_token = None
        self.steam_id = "76561198000000000"
        self.handlers = defaultdict(list)
        self.status_calls = []
        self.games_calls = []
        self.stop_calls = 0
        self.force_disconnect_calls = 0
        self.stop_result = EResult.OK
        self.force_disconnect_result = True

    def on(self, event_name):
        def decorator(callback):
            self.handlers[event_name].append(callback)
            return callback

        return decorator

    def set_credential_location(self, _path):
        return None

    def change_status(self, persona_state):
        self.status_calls.append(int(persona_state))
        return EResult.OK

    def games_played(self, app_ids):
        self.games_calls.append(list(app_ids))
        return EResult.OK

    def stop_games(self):
        self.stop_calls += 1
        return self.stop_result

    def force_disconnect(self):
        self.force_disconnect_calls += 1
        if self.force_disconnect_result:
            self.connected = False
            self.logged_in = False
        return self.force_disconnect_result

    def mark_closed(self):
        self._closed = True
        self.connected = False
        self.logged_in = False

    def disconnect(self, permanent=False):
        if permanent:
            self.mark_closed()
        else:
            self.connected = False
            self.logged_in = False


class _KillableTimer:
    def __init__(self):
        self.killed = False

    def kill(self):
        self.killed = True


class BoostStateTests(unittest.TestCase):
    def setUp(self):
        # Legacy boost tests historically advance elapsed time by patching the
        # shared ``time.time`` function. Keep that deterministic contract local
        # to this test class; dedicated Phase 5G tests exercise independent wall
        # and monotonic sources.
        test_clock_anchor = app_module.time.time()
        self._test_clock = Clock(
            epoch_source=lambda: app_module.time.time(),
            monotonic_source=lambda: app_module.time.time(),
        )
        # Both injected sources intentionally share the same synthetic domain.
        # Anchor them to one sample so Linux's sub-microsecond delay between
        # Clock.__init__ samples cannot turn an exact 120s boundary into
        # 120.000001s and exercise integer-ceiling behavior by accident.
        self._test_clock._steady_epoch_anchor = test_clock_anchor
        self._test_clock._steady_monotonic_anchor = test_clock_anchor
        self._app_clock_patch = mock.patch.object(
            app_module,
            "clock",
            self._test_clock,
        )
        self._steam_clock_patch = mock.patch.object(
            steam_manager,
            "clock",
            self._test_clock,
        )
        self._app_clock_patch.start()
        self._steam_clock_patch.start()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        database_uri = app_module.app.config["SQLALCHEMY_DATABASE_URI"]
        if not (
            database_uri.startswith("sqlite:///")
            and "hourboost-" in database_uri
            and "-tests" in database_uri
        ):
            raise RuntimeError(
                "Refusing to run destructive boost tests outside an isolated temp DB"
            )

        self._plans = copy.deepcopy(Config.PLANS)
        self._clear_runtime()
        with app_module.app.app_context():
            reset_test_schema(app_module)
        app_module._plan_expiry_cache.clear()
        with app_module._user_operation_locks_guard:
            app_module._user_operation_locks.clear()
        app_module.boost_service.fatal_disconnect_callback = (
            app_module._handle_fatal_disconnect
        )
        self.client = app_module.app.test_client()

    def tearDown(self):
        Config.PLANS = self._plans
        self._clear_runtime()
        self._steam_clock_patch.stop()
        self._app_clock_patch.stop()

    @staticmethod
    def _clear_runtime():
        with app_module._quota_watchdog_lock:
            quota_entries = list(app_module._user_quota_watchdogs.values())
            app_module._user_quota_watchdogs.clear()
            app_module._user_quota_hard_fences.clear()
        cancelled_greenlets = []
        for entry in quota_entries:
            greenlet = entry.get("greenlet")
            if greenlet is not None:
                app_module._kill_greenlet_nonblocking(greenlet)
                cancelled_greenlets.append(greenlet)
        with app_module._timer_lock:
            account_timers = [
                timer
                for timers in app_module._active_timers.values()
                for timer in timers
            ]
        for account_id in list(app_module._active_timers):
            app_module._clear_timers(account_id)
        cancelled_greenlets.extend(account_timers)

        # Production cancellation must remain non-blocking because a greenlet's
        # ``finally`` block may need a lock held by the caller. Test teardown is
        # outside those locks, so drain cancelled jobs before the next test
        # recreates the shared SQLite schema. Otherwise a previous timer can
        # finish against the next test's database on slower/Linux runtimes.
        joinable = [
            greenlet
            for greenlet in cancelled_greenlets
            if greenlet is not gevent.getcurrent() and hasattr(greenlet, "join")
        ]
        if joinable:
            gevent.joinall(joinable, timeout=1, raise_error=False)
        with app_module._timer_lock:
            app_module._active_timers.clear()
            app_module._account_user_timer_deadlines.clear()
        app_module.boost_service._managers.clear()

    def _future_large_epoch(self):
        """Return a whole-second epoch ahead of this test's steady-clock floor.

        Hard-cap precision tests need a modern, large Unix timestamp, but a
        calendar-fixed value eventually falls behind the Clock anchor and is
        correctly clamped as a backwards wall-clock jump.  Keeping the base in
        the injected clock domain preserves both the precision scenario and
        deterministic behavior regardless of the date the suite is executed.
        """

        return float(int(self._test_clock.steady_epoch()) + 60)

    def _fixture(self, *, plan="free", app_ids=(730,), account_id=None):
        suffix = next(_FIXTURE_IDS)
        account_id = account_id or f"{suffix:016x}"
        with app_module.app.app_context():
            user = User(
                username=f"boost-user-{suffix}",
                email=f"boost-{suffix}@example.test",
                password_hash="unused",
                plan=plan,
                plan_activated_at=app_module.utc_now() - timedelta(days=1),
                is_verified=True,
            )
            db.session.add(user)
            db.session.flush()
            account = SteamAccount(
                id=account_id,
                user_id=user.id,
                steam_username=f"steam-user-{suffix}",
                persona_state=1,
                is_boosting=False,
            )
            db.session.add(account)
            db.session.flush()
            for app_id in app_ids:
                db.session.add(BoostGame(account_id=account_id, app_id=app_id))
            db.session.commit()
            user_id = user.id
            token = app_module.generate_api_token(user_id)

        with app_module.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "198.51.100.120"}
        ):
            self.assertIsNotNone(
                app_module._create_session_record(user_id, token)
            )

        fake_client = _FakeSteamClient()
        with mock.patch.object(
            steam_manager, "_make_client", return_value=fake_client
        ):
            manager = steam_manager.SteamAccountManager(
                account_id, f"steam-user-{suffix}"
            )
        manager.logged_in = True
        app_module.boost_service._managers[account_id] = manager
        return {
            "user_id": user_id,
            "account_id": account_id,
            "headers": {"Authorization": f"Bearer {token}"},
            "manager": manager,
            "client": fake_client,
        }

    def _add_account(self, fixture, *, app_ids=(730,), account_id=None):
        suffix = next(_FIXTURE_IDS)
        account_id = account_id or f"{suffix:016x}"
        steam_username = f"steam-user-{suffix}"
        with app_module.app.app_context():
            account = SteamAccount(
                id=account_id,
                user_id=fixture["user_id"],
                steam_username=steam_username,
                persona_state=1,
                is_boosting=False,
            )
            db.session.add(account)
            for app_id in app_ids:
                db.session.add(BoostGame(account_id=account_id, app_id=app_id))
            db.session.commit()

        fake_client = _FakeSteamClient()
        with mock.patch.object(
            steam_manager, "_make_client", return_value=fake_client
        ):
            manager = steam_manager.SteamAccountManager(
                account_id,
                steam_username,
            )
        manager.logged_in = True
        app_module.boost_service._managers[account_id] = manager
        return {
            "user_id": fixture["user_id"],
            "account_id": account_id,
            "headers": fixture["headers"],
            "manager": manager,
            "client": fake_client,
        }

    @staticmethod
    def _set_db_boost_state(account_id, *, boosting, target=None):
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, account_id)
            account.is_boosting = boosting
            account.target_stop_time = target
            db.session.commit()

    @staticmethod
    def _age_active_segment(manager, seconds):
        started = time.time() - seconds
        with manager.state_lock:
            manager.start_time = started
            manager.original_start_time = started
            manager._segment_clock_epoch = started
            manager._segment_clock_monotonic = (
                manager._clock.monotonic() - seconds
            )
        return started

    def _fire_current_quota_watchdog(self, user_id, *, deadline_epoch=None):
        """Run the registered callback now while preserving its identity checks."""
        gate = Event()
        with app_module._quota_watchdog_lock:
            entry = app_module._user_quota_watchdogs.get(user_id)
            self.assertIsNotNone(entry)
            scheduled_greenlet = entry["greenlet"]
            if deadline_epoch is not None:
                entry["deadline_epoch"] = float(deadline_epoch)
                entry["deadline_monotonic"] = app_module.clock.monotonic()
            generation = entry["generation"]
            token = entry["token"]
            reason = entry["reason"]

        def run_callback():
            gate.wait()
            app_module._run_user_quota_watchdog(
                user_id,
                generation,
                token,
                reason,
            )

        callback_greenlet = gevent.spawn(run_callback)
        with app_module._quota_watchdog_lock:
            current = app_module._user_quota_watchdogs.get(user_id)
            self.assertIsNotNone(current)
            self.assertEqual(current["generation"], generation)
            self.assertEqual(current["token"], token)
            current["greenlet"] = callback_greenlet
        app_module._kill_greenlet_nonblocking(scheduled_greenlet)
        gate.set()
        return callback_greenlet, {
            "generation": generation,
            "token": token,
            "reason": reason,
            "deadline_epoch": (
                float(deadline_epoch)
                if deadline_epoch is not None
                else entry["deadline_epoch"]
            ),
        }

    def test_invalid_body_and_account_id_have_no_boost_side_effects(self):
        fixture = self._fixture()
        manager = fixture["manager"]

        with (
            mock.patch.object(manager, "start_boost", wraps=manager.start_boost) as start,
            mock.patch.object(manager, "stop_boost", wraps=manager.stop_boost) as stop,
            mock.patch.object(app_module, "_clear_timers") as clear_timers,
            mock.patch.object(app_module, "_schedule_boost_stop_timer") as schedule,
        ):
            requests = [
                {"data": "not-json", "content_type": "text/plain"},
                {"json": []},
                {"json": {}},
                {"json": {"acct_id": True}},
                {"json": {"acct_id": "../outside"}},
                {"json": {"acct_id": "ABCDEF0123456789"}},
                {"json": {"acct_id": fixture["account_id"]}},
                {"json": {"acct_id": fixture["account_id"], "action": "toggle"}},
            ]
            for request_kwargs in requests:
                with self.subTest(request=request_kwargs):
                    response = self.client.post(
                        "/boost/toggle",
                        headers=fixture["headers"],
                        **request_kwargs,
                    )
                    self.assertEqual(
                        response.status_code, 400, response.get_data(as_text=True)
                    )

        start.assert_not_called()
        stop.assert_not_called()
        clear_timers.assert_not_called()
        schedule.assert_not_called()
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertIsNone(account.target_stop_time)
            self.assertEqual(BoostLog.query.count(), 0)

    def test_total_limit_rejection_after_daily_check_creates_no_timer_or_start(self):
        Config.PLANS["boost-test-limits"] = {
            "max_accounts": 2,
            "max_games": 4,
            "daily_hours": 8,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="boost-test-limits")
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_now() - timedelta(hours=1),
                stopped_at=app_module.utc_now(),
                duration_seconds=3600,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        manager = fixture["manager"]
        with (
            mock.patch.object(manager, "start_boost", wraps=manager.start_boost) as start,
            mock.patch.object(app_module, "_schedule_boost_stop_timer") as schedule,
        ):
            response = self.client.post(
                "/boost/toggle",
                json={"acct_id": fixture["account_id"], "action": "start"},
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["upgrade"])
        self.assertIn("all 1 hours", payload["error"])
        start.assert_not_called()
        schedule.assert_not_called()
        self.assertNotIn(fixture["account_id"], app_module._active_timers)

    def test_daily_quota_and_stats_split_completed_segment_at_midnight(self):
        fixture = self._fixture(plan="free")
        today_start = app_module.utc_now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        fixed_now = today_start + timedelta(hours=12)
        fixed_now_epoch = fixed_now.timestamp()
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=today_start - timedelta(hours=1),
                stopped_at=today_start + timedelta(hours=8),
                duration_seconds=9 * 3600,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        manager = fixture["manager"]
        with (
            mock.patch.object(app_module, "utc_now", return_value=fixed_now),
            mock.patch.object(
                app_module.clock,
                "epoch",
                return_value=fixed_now_epoch,
            ),
            mock.patch.object(
                app_module.clock,
                "steady_epoch",
                return_value=fixed_now_epoch,
            ),
            mock.patch.object(manager, "start_boost", wraps=manager.start_boost) as start,
            mock.patch.object(app_module, "_schedule_boost_stop_timer") as schedule,
        ):
            response = self.client.post(
                "/boost/toggle",
                json={"acct_id": fixture["account_id"], "action": "start"},
                headers=fixture["headers"],
            )
            stats_response = self.client.get(
                "/stats/my",
                headers=fixture["headers"],
            )
            detailed_response = self.client.get(
                "/stats/detailed",
                headers=fixture["headers"],
            )

            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
            payload = response.get_json()
            self.assertFalse(payload["ok"])
            self.assertTrue(payload["upgrade"])
            self.assertIn("daily 8-hour limit", payload["error"])
            start.assert_not_called()
            schedule.assert_not_called()
        self.assertEqual(stats_response.status_code, 200)
        self.assertEqual(detailed_response.status_code, 200)
        self.assertEqual(stats_response.get_json()["today_hours"], 8.0)
        self.assertEqual(
            detailed_response.get_json()["summary"]["today_hours"],
            8.0,
        )
        my_daily = {
            item["day"]: item["hours"]
            for item in stats_response.get_json()["daily"]
        }
        detailed_daily = {
            item["date"]: item["hours"]
            for item in detailed_response.get_json()["weekly_hours"]
        }
        previous_day = str((today_start - timedelta(days=1)).date())
        current_day = str(today_start.date())
        self.assertEqual(my_daily[previous_day], 1.0)
        self.assertEqual(my_daily[current_day], 8.0)
        self.assertEqual(detailed_daily[previous_day], 1.0)
        self.assertEqual(detailed_daily[current_day], 8.0)

    def test_postgresql_legacy_ledger_fallback_casts_before_multiplication(self):
        sql = str(app_module._boost_duration_microseconds_sql().compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        ))
        model_sql = str(CreateTable(BoostLog.__table__).compile(
            dialect=postgresql.dialect(),
        ))

        self.assertIn(
            "CAST(coalesce(boost_logs.duration_seconds, 0) AS BIGINT)",
            sql,
        )
        self.assertIn("CAST(duration_seconds AS BIGINT)", model_sql)

    def test_microsecond_window_partition_is_exactly_additive(self):
        boundary = app_module.utc_now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        started_at = boundary - timedelta(microseconds=500_000)
        stopped_at = boundary + timedelta(microseconds=500_001)
        duration_microseconds = 1_000_001

        before = app_module._boost_log_microseconds_in_window(
            started_at,
            stopped_at,
            duration_microseconds,
            2,
            started_at,
            boundary,
        )
        after = app_module._boost_log_microseconds_in_window(
            started_at,
            stopped_at,
            duration_microseconds,
            2,
            boundary,
            stopped_at,
        )

        self.assertEqual(before + after, duration_microseconds)
        self.assertEqual((before, after), (500_000, 500_001))

    def test_subsecond_segments_dual_write_without_legacy_rounding_bias(self):
        fixture = self._fixture(plan="basic")
        started_epoch = app_module.clock.steady_epoch() - 2.0
        with app_module.app.app_context():
            for index in range(4):
                segment_start = started_epoch + index * 0.25
                self.assertTrue(app_module._add_boost_log_if_missing(
                    fixture["account_id"],
                    fixture["user_id"],
                    segment_start,
                    segment_start + 0.25,
                    0.25,
                    [730],
                ))
            db.session.commit()
            logs = BoostLog.query.order_by(BoostLog.started_at).all()

            self.assertEqual(
                [log.duration_microseconds for log in logs],
                [250_000] * 4,
            )
            self.assertEqual([log.duration_seconds for log in logs], [1] * 4)
            self.assertEqual(
                app_module._get_logged_microseconds(fixture["user_id"]),
                1_000_000,
            )
            self.assertEqual(
                app_module._get_logged_seconds(fixture["user_id"]),
                1.0,
            )

    def test_rollback_seconds_row_deduplicates_fractional_pending_replay(self):
        fixture = self._fixture(plan="basic")
        started_epoch = 1_787_550_000.0
        stopped_epoch = started_epoch + 1.5
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_from_epoch(started_epoch),
                stopped_at=app_module.utc_from_epoch(stopped_epoch),
                duration_seconds=2,
                duration_microseconds=2_000_000,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

            self.assertFalse(app_module._add_boost_log_if_missing(
                fixture["account_id"],
                fixture["user_id"],
                started_epoch,
                stopped_epoch,
                1.5,
                [730],
                duration_microseconds=1_500_000,
            ))
            db.session.commit()
            self.assertEqual(BoostLog.query.count(), 1)
            self.assertEqual(
                BoostLog.query.one().duration_microseconds,
                2_000_000,
            )

    def test_same_segment_identity_with_canonical_conflict_fails_closed(self):
        fixture = self._fixture(plan="basic")
        started_epoch = 1_787_550_100.0
        stopped_epoch = started_epoch + 1.5
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_from_epoch(started_epoch),
                stopped_at=app_module.utc_from_epoch(stopped_epoch),
                duration_seconds=2,
                duration_microseconds=1_400_000,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

            with self.assertRaises(app_module.UsageLedgerConflictError):
                app_module._add_boost_log_if_missing(
                    fixture["account_id"],
                    fixture["user_id"],
                    started_epoch,
                    stopped_epoch,
                    1.5,
                    [730],
                    duration_microseconds=1_500_000,
                )
            db.session.rollback()
            self.assertEqual(BoostLog.query.count(), 1)

    def test_duplicate_segment_identities_fail_closed(self):
        fixture = self._fixture(plan="basic")
        started_epoch = 1_787_550_200.0
        stopped_epoch = started_epoch + 1.5
        with app_module.app.app_context():
            for _index in range(2):
                db.session.add(BoostLog(
                    account_id=fixture["account_id"],
                    user_id=fixture["user_id"],
                    started_at=app_module.utc_from_epoch(started_epoch),
                    stopped_at=app_module.utc_from_epoch(stopped_epoch),
                    duration_seconds=2,
                    duration_microseconds=1_500_000,
                    games_count=1,
                    app_ids_json="[730]",
                ))
            db.session.commit()

            with self.assertRaises(app_module.UsageLedgerConflictError):
                app_module._add_boost_log_if_missing(
                    fixture["account_id"],
                    fixture["user_id"],
                    started_epoch,
                    stopped_epoch,
                    1.5,
                    [730],
                    duration_microseconds=1_500_000,
                )
            db.session.rollback()
            self.assertEqual(BoostLog.query.count(), 2)

    def test_quota_snapshot_accumulates_finalized_usage_as_integer_microseconds(self):
        Config.PLANS["micro-ledger"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1 / 3600,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="micro-ledger")
        started_epoch = app_module.clock.steady_epoch() - 1.0
        with app_module.app.app_context():
            for index in range(2):
                segment_start = started_epoch + index * 0.25
                app_module._add_boost_log_if_missing(
                    fixture["account_id"],
                    fixture["user_id"],
                    segment_start,
                    segment_start + 0.25,
                    0.25,
                    [730],
                )
            db.session.commit()
            with app_module._user_operation_lock(fixture["user_id"]):
                snapshot = app_module._quota_usage_snapshot(
                    fixture["user_id"]
                )

        self.assertEqual(snapshot["total_used_microseconds"], 500_000)
        self.assertEqual(snapshot["total_remaining_microseconds"], 500_000)
        self.assertEqual(snapshot["total_used_seconds"], 0.5)
        self.assertEqual(snapshot["total_remaining_seconds"], 0.5)

    def test_one_microsecond_remaining_is_not_reported_as_depleted(self):
        Config.PLANS["one-second-ledger"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1 / 3600,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="one-second-ledger")
        now_utc = app_module.utc_now()
        with app_module.app.app_context():
            log = BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=now_utc - timedelta(microseconds=999_999),
                stopped_at=now_utc,
                duration_seconds=1,
                duration_microseconds=999_999,
                games_count=1,
                app_ids_json="[730]",
            )
            db.session.add(log)
            db.session.commit()
            snapshot = app_module._quota_usage_snapshot(fixture["user_id"])

            self.assertEqual(snapshot["total_remaining_microseconds"], 1)
            self.assertFalse(snapshot["quota_depleted"])

            log.duration_microseconds = 1_000_000
            db.session.commit()
            depleted = app_module._quota_usage_snapshot(fixture["user_id"])

        self.assertEqual(depleted["total_remaining_microseconds"], 0)
        self.assertTrue(depleted["quota_depleted"])

    def test_multi_account_remainder_uses_conservative_integer_wall_time(self):
        Config.PLANS["remainder-ledger"] = {
            "max_accounts": 3,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 10.000001 / 3600,
            "price": 0,
            "duration_days": None,
        }
        for active_count in (2, 3):
            with self.subTest(active_count=active_count):
                fixture = self._fixture(plan="remainder-ledger")
                accounts = [fixture]
                while len(accounts) < active_count:
                    accounts.append(self._add_account(fixture))
                base_epoch = app_module.clock.steady_epoch()
                patches = []
                try:
                    for account in accounts:
                        patches.append(mock.patch.object(
                            account["manager"],
                            "boost_snapshot",
                            return_value={
                                "boosting": True,
                                "start_time": base_epoch,
                                "observed_stop_time": base_epoch,
                                "segment_elapsed": 0.0,
                            },
                        ))
                        patches[-1].start()
                    with app_module.app.app_context():
                        snapshot = app_module._quota_usage_snapshot(
                            fixture["user_id"],
                            now_epoch=base_epoch,
                        )
                finally:
                    for patcher in reversed(patches):
                        patcher.stop()

                wall_microseconds = round(
                    snapshot["estimated_wall_seconds"]
                    * 1_000_000
                )
                remaining = snapshot["remaining_usage_microseconds"]
                self.assertEqual(snapshot["active_count"], active_count)
                self.assertLessEqual(
                    wall_microseconds * active_count,
                    remaining,
                )
                self.assertLess(
                    remaining - wall_microseconds * active_count,
                    active_count,
                )

    def test_pending_segment_journal_preserves_canonical_microseconds(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        segment = {
            "account_id": fixture["account_id"],
            "session_id": "micro-journal",
            "generation": 1,
            "started_at": 100.0,
            "stopped_at": 100.25,
            "elapsed": 0.25,
            "app_ids": [730],
            "remote_stop_confirmed": True,
            "remote_stopped_at": None,
            "checkpoint_only": True,
        }

        self.assertTrue(manager._remember_final_segment_unlocked(segment))
        reloaded = steam_manager._read_pending_final_segments(
            fixture["account_id"],
            manager.steam_username,
        )

        self.assertEqual(segment["elapsed_microseconds"], 250_000)
        self.assertEqual(reloaded[0]["elapsed_microseconds"], 250_000)
        self.assertEqual(reloaded[0]["elapsed"], 0.25)

        capped = manager.cap_final_segment_stopped_at(segment, 100.125)
        capped_reloaded = steam_manager._read_pending_final_segments(
            fixture["account_id"],
            manager.steam_username,
        )
        self.assertEqual(capped["elapsed_microseconds"], 125_000)
        self.assertEqual(
            capped_reloaded[0]["elapsed_microseconds"],
            125_000,
        )

    def test_equal_hard_cap_refloors_pending_segment_at_large_epoch(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        started_epoch = 1_787_550_000.0
        intended_microseconds = 190_000_001 // 3
        stopped_epoch = (
            started_epoch + intended_microseconds / 1_000_000
        )
        observed_elapsed = stopped_epoch - started_epoch
        segment = {
            "account_id": fixture["account_id"],
            "session_id": "equal-micro-cap",
            "generation": 1,
            "started_at": started_epoch,
            "stopped_at": stopped_epoch,
            "elapsed": observed_elapsed,
            "app_ids": [730],
            "remote_stop_confirmed": True,
            "remote_stopped_at": None,
            "checkpoint_only": False,
        }

        self.assertTrue(manager._remember_final_segment_unlocked(segment))
        self.assertEqual(
            segment["elapsed_microseconds"],
            intended_microseconds + 1,
        )

        capped = manager.cap_final_segment_stopped_at(
            segment,
            stopped_epoch,
        )
        reloaded = steam_manager._read_pending_final_segments(
            fixture["account_id"],
            manager.steam_username,
        )

        self.assertEqual(capped["elapsed_microseconds"], intended_microseconds)
        self.assertEqual(
            reloaded[0]["elapsed_microseconds"],
            intended_microseconds,
        )

    def test_prepared_hard_stop_journal_is_floored_before_ipc(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        started_epoch = self._future_large_epoch()
        intended_microseconds = 190_000_001 // 3
        stopped_epoch = (
            started_epoch + intended_microseconds / 1_000_000
        )
        with mock.patch.object(
            app_module.time,
            "time",
            return_value=started_epoch,
        ):
            started = manager.start_boost([730], 1)

        segment = manager.prepare_stop_boost_segment(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
            stopped_at=stopped_epoch,
            hard_cap=True,
        )
        reloaded = steam_manager._read_pending_final_segments(
            fixture["account_id"],
            manager.steam_username,
        )

        self.assertEqual(segment["elapsed_microseconds"], intended_microseconds)
        self.assertEqual(
            reloaded[0]["elapsed_microseconds"],
            intended_microseconds,
        )

    def test_runtime_deadline_auto_floors_prepared_stop_journal(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        started_epoch = self._future_large_epoch()
        intended_microseconds = 190_000_001 // 3
        stopped_epoch = (
            started_epoch + intended_microseconds / 1_000_000
        )
        with mock.patch.object(
            app_module.time,
            "time",
            return_value=started_epoch,
        ):
            started = manager.start_boost([730], 1)
        self.assertTrue(manager.set_runtime_stop_deadline(
            stopped_epoch,
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
        ))

        segment = manager.prepare_stop_boost_segment(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
            stopped_at=stopped_epoch,
        )
        reloaded = steam_manager._read_pending_final_segments(
            fixture["account_id"],
            manager.steam_username,
        )

        self.assertEqual(segment["elapsed_microseconds"], intended_microseconds)
        self.assertEqual(
            reloaded[0]["elapsed_microseconds"],
            intended_microseconds,
        )

    def test_active_seconds_count_only_post_midnight_overlap(self):
        fixture = self._fixture(plan="free")
        today_start = app_module.utc_now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        active_start = today_start - timedelta(minutes=5)
        fixed_now = today_start + timedelta(minutes=10)
        active_start_epoch = active_start.replace(tzinfo=timezone.utc).timestamp()
        fixed_now_epoch = fixed_now.replace(tzinfo=timezone.utc).timestamp()

        manager = fixture["manager"]
        with manager.state_lock:
            manager.boosting = True
            manager.start_time = active_start_epoch
            manager.original_start_time = active_start_epoch
            manager.boost_session_id = "cross-midnight-session"

        with (
            app_module.app.app_context(),
            mock.patch.object(app_module.time, "time", return_value=fixed_now_epoch),
        ):
            self.assertEqual(
                app_module._get_active_seconds(fixture["user_id"], today_start),
                10 * 60,
            )
            self.assertEqual(
                app_module._get_active_seconds(fixture["user_id"]),
                15 * 60,
            )

    def test_successful_start_commits_db_before_generation_timer_is_created(self):
        fixture = self._fixture(plan="basic")
        observed = {}

        def observe_timer(account_id, user_id, session_id, generation, delay, reason):
            with app_module.app.app_context():
                account = db.session.get(SteamAccount, account_id)
                observed.update({
                    "db_boosting": account.is_boosting,
                    "db_target": account.target_stop_time,
                    "session_id": session_id,
                    "generation": generation,
                    "delay": delay,
                    "reason": reason,
                    "user_id": user_id,
                })
            return _KillableTimer()

        with mock.patch.object(
            app_module,
            "_schedule_boost_stop_timer",
            side_effect=observe_timer,
        ) as schedule:
            response = self.client.post(
                "/boost/toggle",
                json={
                    "acct_id": fixture["account_id"],
                    "timer_hours": 1,
                    "action": "start",
                },
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["boosting"])
        schedule.assert_called_once()
        snapshot = fixture["manager"].boost_snapshot()
        self.assertTrue(observed["db_boosting"])
        self.assertIsNotNone(observed["db_target"])
        self.assertEqual(observed["session_id"], snapshot["session_id"])
        self.assertEqual(observed["generation"], snapshot["generation"])
        self.assertEqual(observed["user_id"], fixture["user_id"])
        self.assertGreater(observed["delay"], 0)
        self.assertIn(observed["reason"], {"total_limit", "user_timer"})

    def test_start_commit_error_compensates_manager_and_leaves_no_timer(self):
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            session_type = type(db.session())
        real_commit = session_type.commit
        failed_start_commit = False

        def fail_first_commit(session):
            nonlocal failed_start_commit
            if (
                not failed_start_commit
                and fixture["manager"].boost_snapshot().get("boosting")
            ):
                failed_start_commit = True
                raise SQLAlchemyError("forced start commit failure")
            return real_commit(session)

        with (
            mock.patch.object(
                session_type,
                "commit",
                autospec=True,
                side_effect=fail_first_commit,
            ),
            mock.patch.object(app_module, "_schedule_boost_stop_timer") as schedule,
        ):
            response = self.client.post(
                "/boost/toggle",
                json={
                    "acct_id": fixture["account_id"],
                    "timer_hours": 1,
                    "action": "start",
                },
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])
        self.assertEqual(fixture["client"].stop_calls, 1)
        schedule.assert_not_called()
        self.assertNotIn(fixture["account_id"], app_module._active_timers)
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertIsNone(account.target_stop_time)

    def test_first_start_slow_commit_cannot_exceed_absolute_quota(self):
        Config.PLANS["quota-one-second"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1 / 3600,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-one-second")
        with app_module.app.app_context():
            session_type = type(db.session())
        real_commit = session_type.commit
        delayed_start_commit = False

        def delay_first_start_commit(session):
            nonlocal delayed_start_commit
            if (
                not delayed_start_commit
                and fixture["manager"].boost_snapshot().get("boosting")
            ):
                delayed_start_commit = True
                gevent.sleep(1.4)
            return real_commit(session)

        with mock.patch.object(
            session_type,
            "commit",
            autospec=True,
            side_effect=delay_first_start_commit,
        ):
            response = self.client.post(
                "/boost/toggle",
                json={"acct_id": fixture["account_id"], "action": "start"},
                headers=fixture["headers"],
            )

        self.assertIn(response.status_code, (409, 503), response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])
        self.assertGreaterEqual(fixture["client"].force_disconnect_calls, 1)
        for _attempt in range(200):
            if app_module._active_user_quota_hard_fence(
                fixture["user_id"]
            ) is None:
                break
            gevent.sleep(0.01)
        self.assertIsNone(
            app_module._active_user_quota_hard_fence(fixture["user_id"])
        )
        with app_module.app.app_context():
            logs = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).all()
            self.assertEqual(len(logs), 1)
            self.assertLessEqual(sum(log.duration_seconds for log in logs), 1)
            self.assertLessEqual(
                (logs[0].stopped_at - logs[0].started_at).total_seconds(),
                1.001,
            )

    def test_exhausted_after_start_slow_snapshot_does_not_deadlock(self):
        Config.PLANS["quota-snapshot-deadlock"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 0.12 / 3600,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-snapshot-deadlock")
        manager = fixture["manager"]
        original_snapshot = app_module._quota_usage_snapshot
        delayed_after_start = False

        def slow_post_start_snapshot(user_id, **kwargs):
            nonlocal delayed_after_start
            if manager.boosting and not delayed_after_start:
                delayed_after_start = True
                # Let the provisional absolute watchdog claim the boundary
                # while this request still owns the user operation lock.  The
                # old route also owned manager.state_lock here, then deadlocked
                # when reconciliation spawned a manager finalizer greenlet.
                gevent.sleep(0.2)
            return original_snapshot(user_id, **kwargs)

        def start_request():
            with app_module.app.test_client() as client:
                return client.post(
                    "/boost/toggle",
                    json={"acct_id": fixture["account_id"], "action": "start"},
                    headers=fixture["headers"],
                )

        with mock.patch.object(
            app_module,
            "_quota_usage_snapshot",
            side_effect=slow_post_start_snapshot,
        ):
            job = gevent.spawn(start_request)
            job.join(timeout=2)

        if not job.ready():
            job.kill(block=False)
            gevent.joinall([job], timeout=1)
            self.fail("post-start quota exhaustion deadlocked the start route")
        self.assertIsNone(job.exception)
        response = job.value
        self.assertIn(response.status_code, (409, 503), response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertTrue(delayed_after_start)
        self.assertFalse(manager.boost_snapshot()["boosting"])

    def test_failed_start_durability_compensation_runs_without_manager_lock(self):
        Config.PLANS["quota-compensation-lock-order"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 0.12 / 3600,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-compensation-lock-order")
        manager = fixture["manager"]
        with app_module.app.app_context():
            session_type = type(db.session())
        real_commit = session_type.commit
        failed_start_commit = False
        restore_observed_unlocked = False
        original_restore = app_module._restore_quota_after_failed_start_locked

        def fail_slow_start_commit(session):
            nonlocal failed_start_commit
            if not failed_start_commit and manager.boost_snapshot().get("boosting"):
                failed_start_commit = True
                gevent.sleep(0.2)
                raise SQLAlchemyError("forced slow start commit failure")
            return real_commit(session)

        def assert_restore_lock_order(user_id, cause):
            nonlocal restore_observed_unlocked
            acquired = Event()

            def acquire_manager_lock():
                with manager.state_lock:
                    acquired.set()

            probe = gevent.spawn(acquire_manager_lock)
            try:
                if not acquired.wait(timeout=0.5):
                    raise AssertionError(
                        "failed-start restore ran while manager.state_lock was held"
                    )
                restore_observed_unlocked = True
            finally:
                probe.kill(block=False)
                probe.join(timeout=1)
            return original_restore(user_id, cause)

        def start_request():
            with app_module.app.test_client() as client:
                return client.post(
                    "/boost/toggle",
                    json={"acct_id": fixture["account_id"], "action": "start"},
                    headers=fixture["headers"],
                )

        with (
            mock.patch.object(
                session_type,
                "commit",
                autospec=True,
                side_effect=fail_slow_start_commit,
            ),
            mock.patch.object(
                manager,
                "_save_pending_final_segments_unlocked",
                return_value=False,
            ),
            # Isolate lock ordering from the watchdog; the slow failed commit
            # itself consumes the tiny allowance before restore reconciles it.
            mock.patch.object(
                app_module,
                "_install_user_quota_watchdog",
                return_value={"test": "watchdog-disabled"},
            ),
            mock.patch.object(
                app_module,
                "_restore_quota_after_failed_start_locked",
                side_effect=assert_restore_lock_order,
            ),
        ):
            job = gevent.spawn(start_request)
            job.join(timeout=2)

        if not job.ready():
            job.kill(block=False)
            gevent.joinall([job], timeout=1)
            self.fail("durability-failure compensation deadlocked the start route")
        self.assertIsNone(job.exception)
        response = job.value
        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertTrue(failed_start_commit)
        self.assertTrue(restore_observed_unlocked)
        self.assertTrue(manager.boost_snapshot()["boosting"])
        self.assertEqual(fixture["client"].stop_calls, 0)

    def test_first_start_publishes_plan_expiry_before_exact_snapshot(self):
        Config.PLANS["quota-provisional-plan-expiry"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "duration_days": 1,
        }
        fixture = self._fixture(plan="quota-provisional-plan-expiry")
        manager = fixture["manager"]
        plan_expiry = app_module.utc_now() + timedelta(seconds=60)
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_expires = plan_expiry
            db.session.commit()

        exact_snapshot_entered = Event()
        release_exact_snapshot = Event()
        original_snapshot = app_module._quota_usage_snapshot
        delayed_after_start = False

        def block_exact_post_start_snapshot(user_id, **kwargs):
            nonlocal delayed_after_start
            if manager.boosting and not delayed_after_start:
                delayed_after_start = True
                exact_snapshot_entered.set()
                release_exact_snapshot.wait(timeout=2)
            return original_snapshot(user_id, **kwargs)

        def start_request():
            with app_module.app.test_client() as client:
                return client.post(
                    "/boost/toggle",
                    json={"acct_id": fixture["account_id"], "action": "start"},
                    headers=fixture["headers"],
                )

        job = None
        with mock.patch.object(
            app_module,
            "_quota_usage_snapshot",
            side_effect=block_exact_post_start_snapshot,
        ):
            job = gevent.spawn(start_request)
            try:
                self.assertTrue(exact_snapshot_entered.wait(timeout=1))
                with app_module._quota_watchdog_lock:
                    watchdog = dict(
                        app_module._user_quota_watchdogs[fixture["user_id"]]
                    )
                self.assertEqual(watchdog["reason"], "plan_expiry")
                self.assertAlmostEqual(
                    watchdog["deadline_epoch"],
                    plan_expiry.replace(tzinfo=timezone.utc).timestamp(),
                    delta=0.05,
                )
                # Plan expiry is a soft plan-transition event. It must be
                # scheduled promptly but must not truncate billable runtime.
                self.assertIsNone(
                    manager.boost_snapshot()["runtime_stop_deadline"]
                )
            finally:
                release_exact_snapshot.set()
                if job is not None:
                    job.join(timeout=2)

        self.assertTrue(job.ready())
        self.assertIsNone(job.exception)
        response = job.value
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])

    def test_stale_timer_does_not_stop_new_boost_session(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        old = manager.start_boost([730], 1)
        old_segment = manager.stop_boost_segment(
            expected_session_id=old["session_id"],
            expected_generation=old["generation"],
        )
        self.assertTrue(old_segment["remote_stop_confirmed"])
        # This test isolates stale-timer session matching. Simulate the route's
        # post-commit acknowledgement so the old durable segment cannot be
        # reconciled opportunistically by the timer under test.
        self.assertTrue(manager.acknowledge_final_segment(old_segment))
        new = manager.start_boost([730], 1)
        target = app_module.utc_now() + timedelta(hours=1)
        self._set_db_boost_state(
            fixture["account_id"], boosting=True, target=target
        )
        app_module._remember_account_user_timer_deadline(
            fixture["account_id"],
            new["session_id"],
            new["generation"],
            target.timestamp(),
        )
        stop_calls = fixture["client"].stop_calls

        app_module._run_boost_stop_timer(
            fixture["account_id"],
            fixture["user_id"],
            old["session_id"],
            old["generation"],
            "stale-test",
        )

        current = manager.boost_snapshot()
        self.assertTrue(current["boosting"])
        self.assertEqual(current["session_id"], new["session_id"])
        self.assertEqual(current["generation"], new["generation"])
        self.assertEqual(fixture["client"].stop_calls, stop_calls)
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertTrue(account.is_boosting)
            self.assertIsNotNone(account.target_stop_time)
            self.assertGreater(account.target_stop_time, app_module.utc_now())
            self.assertEqual(BoostLog.query.count(), 0)

    def test_manual_stop_writes_one_log_and_clears_database_target(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(
            fixture["account_id"],
            boosting=True,
            target=app_module.utc_now() + timedelta(hours=1),
        )

        response = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "stop"},
            headers=fixture["headers"],
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["boosting"])
        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertEqual(fixture["client"].stop_calls, 1)
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertIsNone(account.target_stop_time)
            logs = BoostLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].account_id, fixture["account_id"])
            self.assertEqual(logs[0].user_id, fixture["user_id"])
            self.assertGreaterEqual(logs[0].duration_seconds, 119)
            self.assertLessEqual(logs[0].duration_seconds, 121)

    def test_duplicate_stop_request_does_not_start_a_new_boost(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        games_calls_after_start = len(fixture["client"].games_calls)

        first = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "stop"},
            headers=fixture["headers"],
        )
        second = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "stop"},
            headers=fixture["headers"],
        )

        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True))
        self.assertTrue(first.get_json()["ok"])
        self.assertTrue(second.get_json()["ok"])
        self.assertFalse(second.get_json()["boosting"])
        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertEqual(len(fixture["client"].games_calls), games_calls_after_start)
        with app_module.app.app_context():
            self.assertEqual(BoostLog.query.count(), 1)
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)

    def test_start_db_refresh_error_compensates_runtime(self):
        fixture = self._fixture(plan="basic")
        fixed_epoch = time.time()
        with app_module.app.app_context():
            session_type = type(db.session())
        real_get = session_type.get
        failed_refresh = False

        def fail_post_start_get(session, entity, ident, *args, **kwargs):
            nonlocal failed_refresh
            if (
                entity is SteamAccount
                and ident == fixture["account_id"]
                and fixture["manager"].boost_snapshot().get("boosting")
                and not failed_refresh
            ):
                failed_refresh = True
                raise SQLAlchemyError("forced post-start refresh failure")
            return real_get(session, entity, ident, *args, **kwargs)

        with (
            mock.patch.object(
                session_type,
                "get",
                autospec=True,
                side_effect=fail_post_start_get,
            ),
            mock.patch.object(app_module, "_schedule_boost_stop_timer") as schedule,
            mock.patch.object(
                app_module.time,
                "time",
                return_value=fixed_epoch,
            ),
        ):
            response = self.client.post(
                "/boost/toggle",
                json={
                    "acct_id": fixture["account_id"],
                    "timer_hours": 1,
                    "action": "start",
                },
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])
        self.assertEqual(fixture["client"].stop_calls, 1)
        schedule.assert_not_called()
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertEqual(BoostLog.query.count(), 0)

    def test_remote_stop_unconfirmed_is_not_reported_as_success(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        fixture["client"].stop_result = EResult.Fail
        fixture["client"].force_disconnect_result = False

        response = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "stop"},
            headers=fixture["headers"],
        )

        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["boosting"])
        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertEqual(fixture["client"].force_disconnect_calls, 1)
        self.assertEqual(
            len(manager.pending_final_segments()),
            1,
        )
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertTrue(account.is_boosting)
            self.assertEqual(BoostLog.query.count(), 0)

        fixture["client"].force_disconnect_result = True
        retry = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "stop"},
            headers=fixture["headers"],
        )

        self.assertEqual(retry.status_code, 200, retry.get_data(as_text=True))
        self.assertTrue(retry.get_json()["ok"])
        self.assertFalse(retry.get_json()["boosting"])
        self.assertEqual(fixture["client"].force_disconnect_calls, 2)
        self.assertEqual(manager.pending_final_segments(), [])
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertEqual(BoostLog.query.count(), 1)

    def test_pending_state_write_failure_aborts_stop_before_runtime_change(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with mock.patch.object(
            manager,
            "_save_pending_final_segments_unlocked",
            return_value=False,
        ):
            response = self.client.post(
                "/boost/toggle",
                json={"acct_id": fixture["account_id"], "action": "stop"},
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertTrue(response.get_json()["boosting"])
        self.assertTrue(manager.boost_snapshot()["boosting"])
        self.assertEqual(manager.pending_final_segments(), [])
        self.assertEqual(fixture["client"].stop_calls, 0)
        self.assertEqual(fixture["client"].force_disconnect_calls, 0)
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertTrue(account.is_boosting)
            self.assertEqual(BoostLog.query.count(), 0)

    def test_stop_persist_failure_retry_does_not_start_new_boost(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        original_persist = app_module._persist_stopped_boost_state
        failed_once = False

        def fail_first_persist(*args, **kwargs):
            nonlocal failed_once
            if not failed_once:
                failed_once = True
                return False
            return original_persist(*args, **kwargs)

        with mock.patch.object(
            app_module,
            "_persist_stopped_boost_state",
            side_effect=fail_first_persist,
        ):
            first = self.client.post(
                "/boost/toggle",
                json={"acct_id": fixture["account_id"], "action": "stop"},
                headers=fixture["headers"],
            )
            second = self.client.post(
                "/boost/toggle",
                json={"acct_id": fixture["account_id"], "action": "stop"},
                headers=fixture["headers"],
            )

        self.assertEqual(first.status_code, 503, first.get_data(as_text=True))
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True))
        self.assertFalse(second.get_json()["boosting"])
        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertEqual(len(manager.pending_final_segments()), 0)
        self.assertEqual(len(fixture["client"].games_calls), 1)
        with app_module.app.app_context():
            self.assertEqual(BoostLog.query.count(), 1)

    def test_game_list_mutations_are_rejected_while_boosting(self):
        fixture = self._fixture(app_ids=(730, 440))
        fixture["manager"].start_boost([730, 440], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        add_response = self.client.post(
            "/apps/add",
            json={"acct_id": fixture["account_id"], "id": 570},
            headers=fixture["headers"],
        )
        remove_response = self.client.post(
            "/apps/remove",
            json={"acct_id": fixture["account_id"], "id": 440},
            headers=fixture["headers"],
        )

        self.assertEqual(add_response.status_code, 409)
        self.assertEqual(remove_response.status_code, 409)
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertEqual(sorted(account.app_ids()), [440, 730])
        self.assertEqual(
            sorted(fixture["manager"].boost_snapshot()["app_ids"]),
            [440, 730],
        )

    def test_fatal_disconnect_clears_db_timer_and_writes_one_log(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        started_epoch = self._age_active_segment(manager, 180)
        self._set_db_boost_state(
            fixture["account_id"],
            boosting=True,
            target=app_module.utc_now() + timedelta(hours=1),
        )
        timer = _KillableTimer()
        with app_module._timer_lock:
            app_module._active_timers[fixture["account_id"]] = [timer]

        app_module._handle_fatal_disconnect(
            fixture["account_id"],
            180,
            started["session_id"],
            started["generation"],
            started_epoch,
            [730],
        )

        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertTrue(timer.killed)
        self.assertNotIn(fixture["account_id"], app_module._active_timers)
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertIsNone(account.target_stop_time)
            logs = BoostLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertGreaterEqual(logs[0].duration_seconds, 180)
            self.assertLessEqual(logs[0].duration_seconds, 181)

    def test_zero_elapsed_fatal_disconnect_still_clears_db_and_timer(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        fixed_epoch = 1_900_000_000.0
        with mock.patch.object(steam_manager.time, "time", return_value=fixed_epoch):
            started = manager.start_boost([730], 1)

        self._set_db_boost_state(
            fixture["account_id"],
            boosting=True,
            target=app_module.utc_now() + timedelta(hours=1),
        )
        timer = _KillableTimer()
        with app_module._timer_lock:
            app_module._active_timers[fixture["account_id"]] = [timer]

        with mock.patch.object(steam_manager.time, "time", return_value=fixed_epoch):
            finalized = manager._finalize_fatal_session(
                started["generation"],
                "zero elapsed test",
            )

        self.assertTrue(finalized)
        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertTrue(timer.killed)
        self.assertNotIn(fixture["account_id"], app_module._active_timers)
        self.assertEqual(
            manager.pending_final_segments(
                session_id=started["session_id"],
                generation=started["generation"],
            ),
            [],
        )
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertIsNone(account.target_stop_time)
            self.assertEqual(BoostLog.query.count(), 0)

    def test_fatal_disconnect_uses_manager_stopped_at_timestamp(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        with manager.state_lock:
            manager.start_time = 1_900_000_000.0
            manager.original_start_time = 1_900_000_000.0
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with mock.patch.object(steam_manager.time, "time", return_value=1_900_000_120.0):
            segment = manager.stop_boost_segment(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
                context="timestamp propagation test",
            )

        with mock.patch.object(app_module.time, "time", return_value=1_900_000_999.0):
            app_module._handle_fatal_disconnect(
                fixture["account_id"],
                segment["elapsed"],
                segment["session_id"],
                segment["generation"],
                segment["started_at"],
                segment["app_ids"],
                segment["stopped_at"],
            )

        with app_module.app.app_context():
            log = BoostLog.query.one()
            self.assertEqual(log.duration_seconds, 120)
            self.assertEqual(
                log.stopped_at,
                app_module.utc_from_epoch(1_900_000_120.0),
            )

    def test_account_remove_persists_pending_final_segment_before_delete(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        manager.stop_boost_segment(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
            context="simulated fatal before delete",
        )

        response = self.client.post(
            "/accounts/remove",
            json={"acct_id": fixture["account_id"]},
            headers=fixture["headers"],
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        with app_module.app.app_context():
            self.assertIsNone(db.session.get(SteamAccount, fixture["account_id"]))
            logs = BoostLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertIsNone(logs[0].account_id)
            self.assertEqual(logs[0].user_id, fixture["user_id"])
            self.assertGreaterEqual(logs[0].duration_seconds, 119)

    def test_account_remove_reports_post_commit_quota_reconcile_warning(self):
        fixture = self._fixture()
        original_reconcile = app_module._reconcile_user_quota_locked

        def fail_only_after_delete(user_id, cause, *, enforce=True):
            if cause == "account_removed":
                raise RuntimeError("forced post-commit quota failure")
            return original_reconcile(user_id, cause, enforce=enforce)

        with (
            mock.patch.object(
                app_module,
                "_reconcile_user_quota_locked",
                side_effect=fail_only_after_delete,
            ),
            mock.patch.object(
                app_module,
                "_install_user_quota_watchdog",
                return_value={"generation": 1},
            ) as schedule_retry,
        ):
            response = self.client.post(
                "/accounts/remove",
                json={"acct_id": fixture["account_id"]},
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["cleanup_warning"])
        self.assertTrue(payload["quota_warning"])
        schedule_retry.assert_called_once_with(
            fixture["user_id"],
            app_module.QUOTA_RECONCILE_RETRY_SECONDS,
            "reconcile_retry",
        )
        with app_module.app.app_context():
            self.assertIsNone(db.session.get(SteamAccount, fixture["account_id"]))

    def test_old_fatal_callback_does_not_clear_a_new_boost_session(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        old = manager.start_boost([730], 1)
        old_started = self._age_active_segment(manager, 90)
        manager.stop_boost(
            expected_session_id=old["session_id"],
            expected_generation=old["generation"],
        )
        new = manager.start_boost([730], 1)
        target = app_module.utc_now() + timedelta(hours=1)
        self._set_db_boost_state(
            fixture["account_id"], boosting=True, target=target
        )
        app_module._remember_account_user_timer_deadline(
            fixture["account_id"],
            new["session_id"],
            new["generation"],
            target.timestamp(),
        )
        timer = _KillableTimer()
        with app_module._timer_lock:
            app_module._active_timers[fixture["account_id"]] = [timer]

        app_module._handle_fatal_disconnect(
            fixture["account_id"],
            90,
            old["session_id"],
            old["generation"],
            old_started,
            [730],
        )

        current = manager.boost_snapshot()
        self.assertTrue(current["boosting"])
        self.assertEqual(current["session_id"], new["session_id"])
        self.assertFalse(timer.killed)
        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertTrue(account.is_boosting)
            self.assertIsNotNone(account.target_stop_time)
            self.assertGreater(account.target_stop_time, app_module.utc_now())
            self.assertEqual(BoostLog.query.count(), 1)

    def test_checkpoint_commit_error_keeps_advanced_boundary_durable(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        initial_start = self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with app_module.app.app_context(), mock.patch.object(
            db.session,
            "commit",
            side_effect=SQLAlchemyError("forced checkpoint failure"),
        ):
            saved = app_module._checkpoint_active_boosts_once()
            self.assertEqual(saved, 0)
            self.assertEqual(BoostLog.query.count(), 0)

        snapshot = manager.boost_snapshot()
        self.assertGreater(snapshot["start_time"], initial_start)
        pending = manager.pending_final_segments()
        self.assertEqual(len(pending), 1)
        self.assertTrue(pending[0]["checkpoint_only"])
        self.assertEqual(pending[0]["started_at"], initial_start)
        self.assertEqual(pending[0]["stopped_at"], snapshot["start_time"])

    def test_checkpoint_success_persists_segment_then_advances_boundary(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        cutoff = 2_000_000_000.0
        initial_start = cutoff - 120
        with manager.state_lock:
            manager.start_time = initial_start
            manager.original_start_time = initial_start
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with app_module.app.app_context(), mock.patch.object(
            app_module.time, "time", return_value=cutoff
        ):
            saved = app_module._checkpoint_active_boosts_once()
            self.assertEqual(saved, 1)
            logs = BoostLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].duration_seconds, 120)
            self.assertEqual(logs[0].account_id, fixture["account_id"])

        self.assertEqual(manager.boost_snapshot()["start_time"], cutoff)
        self.assertEqual(manager.pending_final_segments(), [])

    def test_backward_wall_step_checkpoint_remains_counted_in_total_quota(self):
        original_total = Config.PLANS["basic"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 100.0 / 3600.0
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours",
                original_total,
            )
        )
        fixture = self._fixture(plan="basic")
        state = {"wall": 2_000_000_000.0, "monotonic": 10_000.0}
        fake_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        fixture["manager"]._clock = fake_clock

        with mock.patch.object(app_module, "clock", fake_clock):
            with app_module.app.app_context():
                user = db.session.get(User, fixture["user_id"])
                user.plan_activated_at = app_module.utc_from_epoch(
                    fake_clock.steady_epoch() - 86400.0
                )
                db.session.commit()

            started = fixture["manager"].start_boost([730], 1)
            state["wall"] -= 3600.0
            state["monotonic"] += 10.0
            checkpoint = fixture["manager"].prepare_boost_checkpoint(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
            )
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint["elapsed"], 10.0)

            with app_module.app.app_context():
                self.assertTrue(app_module._add_boost_log_if_missing(
                    fixture["account_id"],
                    fixture["user_id"],
                    checkpoint["started_at"],
                    checkpoint["stopped_at"],
                    checkpoint["elapsed"],
                    checkpoint["app_ids"],
                ))
                db.session.commit()
                self.assertTrue(
                    fixture["manager"].acknowledge_final_segment(checkpoint)
                )
                quota = app_module._quota_usage_snapshot(fixture["user_id"])

        self.assertAlmostEqual(quota["total_used_seconds"], 10.0, delta=1e-6)
        self.assertAlmostEqual(
            quota["total_remaining_seconds"],
            90.0,
            delta=1e-6,
        )
        self.assertEqual(quota["active_count"], 1)

    def test_restart_restores_finalized_ledger_and_new_usage_domain(self):
        original_total = Config.PLANS["basic"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 30.0 / 3600.0
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours",
                original_total,
            )
        )
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_activated_at = app_module.utc_from_epoch(900.0)
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_from_epoch(1_000.0),
                stopped_at=app_module.utc_from_epoch(1_010.0),
                duration_seconds=10,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        state = {"wall": 940.0, "monotonic": 50.0}
        restarted_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        fixture["manager"]._clock = restarted_clock
        with mock.patch.object(app_module, "clock", restarted_clock):
            with app_module.app.app_context():
                restored = app_module._restore_accounting_clock_on_startup()
                first_quota = app_module._quota_usage_snapshot(
                    fixture["user_id"]
                )

            self.assertTrue(restored["advanced"])
            self.assertEqual(restored["high_water"], 1_010.0)
            self.assertEqual(restarted_clock.steady_epoch(), 1_010.0)
            self.assertAlmostEqual(
                first_quota["total_used_seconds"],
                10.0,
                delta=1e-6,
            )

            fixture["manager"].start_boost([730], 1)
            state["monotonic"] += 10.0
            with app_module.app.app_context():
                second_quota = app_module._quota_usage_snapshot(
                    fixture["user_id"]
                )

        self.assertAlmostEqual(
            second_quota["total_used_seconds"],
            20.0,
            delta=1e-6,
        )

    def test_restart_high_water_uses_fractional_canonical_duration(self):
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_activated_at = app_module.utc_from_epoch(900.0)
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_from_epoch(1_000.0),
                stopped_at=None,
                duration_seconds=1,
                duration_microseconds=250_000,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        state = {"wall": 940.0, "monotonic": 50.0}
        restarted_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        with mock.patch.object(app_module, "clock", restarted_clock):
            with app_module.app.app_context():
                restored = app_module._restore_accounting_clock_on_startup()

        self.assertTrue(restored["advanced"])
        self.assertEqual(restored["high_water"], 1_000.25)
        self.assertEqual(restarted_clock.steady_epoch(), 1_000.25)

    def test_restart_restores_plan_boundary_without_existing_log(self):
        original_total = Config.PLANS["basic"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 30.0 / 3600.0
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours",
                original_total,
            )
        )
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_activated_at = app_module.utc_from_epoch(1_010.0)
            db.session.commit()

        state = {"wall": 940.0, "monotonic": 50.0}
        restarted_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        fixture["manager"]._clock = restarted_clock
        with mock.patch.object(app_module, "clock", restarted_clock):
            with app_module.app.app_context():
                restored = app_module._restore_accounting_clock_on_startup()
            fixture["manager"].start_boost([730], 1)
            state["monotonic"] += 10.0
            with app_module.app.app_context():
                quota = app_module._quota_usage_snapshot(fixture["user_id"])

        self.assertTrue(restored["advanced"])
        self.assertEqual(restored["high_water"], 1_010.0)
        self.assertAlmostEqual(quota["total_used_seconds"], 10.0, delta=1e-6)

    def test_restart_restores_pending_segment_before_reconciliation(self):
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_activated_at = app_module.utc_from_epoch(900.0)
            db.session.commit()
        segment = {
            "account_id": fixture["account_id"],
            "session_id": "pending-restart",
            "generation": 1,
            "started_at": 1_000.0,
            "stopped_at": 1_010.0,
            "elapsed": 10.0,
            "app_ids": [730],
            "remote_stop_confirmed": True,
            "remote_stopped_at": None,
            "checkpoint_only": False,
        }
        with fixture["manager"]._pending_lock:
            fixture["manager"]._pending_final_segments = [segment]
            self.assertTrue(
                fixture["manager"]._save_pending_final_segments_unlocked()
            )

        state = {"wall": 940.0, "monotonic": 50.0}
        restarted_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        with mock.patch.object(app_module, "clock", restarted_clock):
            with app_module.app.app_context():
                restored = app_module._restore_accounting_clock_on_startup()

        self.assertTrue(restored["advanced"])
        self.assertEqual(restored["high_water"], 1_010.0)
        self.assertEqual(restarted_clock.steady_epoch(), 1_010.0)

    def test_restart_aborts_on_corrupt_current_account_pending_state(self):
        fixture = self._fixture(plan="basic")
        pending_path = steam_manager._pending_final_segments_path(
            fixture["account_id"]
        )
        os.makedirs(os.path.dirname(pending_path), exist_ok=True)
        with open(pending_path, "w", encoding="utf-8") as handle:
            handle.write('{"not": "a segment list"}')

        base_clock = app_module.clock
        restarted_clock = Clock(
            epoch_source=base_clock.epoch,
            monotonic_source=base_clock.monotonic,
        )
        with mock.patch.object(app_module, "clock", restarted_clock):
            with app_module.app.app_context():
                with self.assertRaisesRegex(
                    RuntimeError,
                    "Corrupt pending boost state",
                ):
                    app_module._restore_accounting_clock_on_startup()

    def test_restart_floor_preserves_logical_utc_day_and_rejects_bad_lead(self):
        fixture = self._fixture(plan="free")
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_from_epoch(86_390.0),
                stopped_at=app_module.utc_from_epoch(86_410.0),
                duration_seconds=20,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        state = {"wall": 86_300.0, "monotonic": 50.0}
        restarted_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        with mock.patch.object(app_module, "clock", restarted_clock):
            with app_module.app.app_context():
                app_module._restore_accounting_clock_on_startup()
                quota = app_module._quota_usage_snapshot(fixture["user_id"])

        # The logical day remains Jan 2 after restart, so only the ten seconds
        # after midnight are charged once; wall rollback cannot grant Jan 1
        # again.
        self.assertAlmostEqual(quota["daily_used_seconds"], 10.0, delta=1e-6)

        rejected_clock = Clock(
            epoch_source=lambda: 86_300.0,
            monotonic_source=lambda: 50.0,
        )
        with (
            mock.patch.object(app_module, "clock", rejected_clock),
            mock.patch.object(
                Config,
                "ACCOUNTING_CLOCK_MAX_FUTURE_SECONDS",
                100,
            ),
            app_module.app.app_context(),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "exceeds wall UTC",
            ):
                app_module._restore_accounting_clock_on_startup()

    def test_total_quota_counts_finalized_row_above_supplied_now(self):
        original_total = Config.PLANS["basic"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 30.0 / 3600.0
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours",
                original_total,
            )
        )
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_activated_at = app_module.utc_from_epoch(900.0)
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_from_epoch(1_000.0),
                stopped_at=app_module.utc_from_epoch(1_010.0),
                duration_seconds=10,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()
            quota = app_module._quota_usage_snapshot(
                fixture["user_id"],
                now_epoch=950.0,
            )

        self.assertAlmostEqual(quota["total_used_seconds"], 10.0, delta=1e-6)
        current_clock = Clock(
            epoch_source=lambda: 2_000.0,
            monotonic_source=lambda: 50.0,
        )
        with mock.patch.object(app_module, "clock", current_clock):
            with app_module.app.app_context():
                restored = app_module._restore_accounting_clock_on_startup()
        self.assertFalse(restored["advanced"])
        self.assertGreaterEqual(restored["steady_epoch"], 2_000.0)

    def test_cross_account_wall_step_keeps_one_shared_hard_boundary(self):
        original_total = Config.PLANS["basic"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 30.0 / 3600.0
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours",
                original_total,
            )
        )
        first = self._fixture(plan="basic")
        second = self._add_account(first)
        state = {"wall": 2_000_000_000.0, "monotonic": 10_000.0}
        fake_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        first["manager"]._clock = fake_clock
        second["manager"]._clock = fake_clock

        with mock.patch.object(app_module, "clock", fake_clock):
            with app_module.app.app_context():
                user = db.session.get(User, first["user_id"])
                user.plan_activated_at = app_module.utc_from_epoch(
                    fake_clock.steady_epoch() - 86400.0
                )
                db.session.commit()

            first_started = first["manager"].start_boost([730], 1)
            state["wall"] -= 1_000_000_000.0
            state["monotonic"] += 10.0
            second_started = second["manager"].start_boost([730], 1)

            with app_module.app.app_context():
                quota = app_module._quota_usage_snapshot(first["user_id"])

            self.assertAlmostEqual(
                first_started["start_time"],
                2_000_000_000.0,
                delta=1e-6,
            )
            self.assertAlmostEqual(
                second_started["start_time"],
                2_000_000_010.0,
                delta=1e-6,
            )
            self.assertAlmostEqual(quota["total_used_seconds"], 10.0, delta=1e-6)
            self.assertAlmostEqual(
                quota["estimated_wall_seconds"],
                10.0,
                delta=1e-6,
            )
            boundary = quota["quota_deadline_epoch"]
            self.assertAlmostEqual(boundary, 2_000_000_020.0, delta=1e-6)

            state["monotonic"] += 10.0
            segments = []
            for fixture in (first, second):
                segment = fixture["manager"].prepare_stop_boost_segment(
                    stopped_at=boundary,
                    context="cross-account clock-step regression",
                )
                segment = fixture["manager"].confirm_prepared_stop_segment(
                    segment,
                    context="cross-account clock-step regression",
                )
                self.assertTrue(
                    fixture["manager"].acknowledge_final_segment(segment)
                )
                segments.append(segment)

        self.assertEqual(
            {segment["stopped_at"] for segment in segments},
            {boundary},
        )
        self.assertAlmostEqual(
            sum(segment["elapsed"] for segment in segments),
            30.0,
            delta=1e-6,
        )
        self.assertEqual(
            [segment["elapsed"] for segment in segments],
            [20.0, 10.0],
        )

    def test_plan_activation_after_forward_wall_step_uses_accounting_clock(self):
        original_total = Config.PLANS["basic"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 30.0 / 3600.0
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours",
                original_total,
            )
        )
        fixture = self._fixture(plan="free")
        state = {"wall": 1000.0, "monotonic": 0.0}
        fake_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["monotonic"],
        )
        fixture["manager"]._clock = fake_clock

        state["wall"] = 1100.0
        with mock.patch.object(app_module, "clock", fake_clock):
            with app_module.app.app_context():
                user = db.session.get(User, fixture["user_id"])
                app_module._activate_plan(user, "basic")
                db.session.commit()
                self.assertEqual(
                    user.plan_activated_at,
                    app_module.utc_from_epoch(1000.0),
                )

            started = fixture["manager"].start_boost([730], 1)
            state["monotonic"] += 10.0
            with app_module.app.app_context():
                quota = app_module._quota_usage_snapshot(fixture["user_id"])

        self.assertEqual(started["start_time"], 1000.0)
        self.assertEqual(
            fixture["manager"].boost_snapshot()["segment_elapsed"],
            10.0,
        )
        self.assertAlmostEqual(quota["total_used_seconds"], 10.0, delta=1e-6)
        self.assertAlmostEqual(
            quota["total_remaining_seconds"],
            20.0,
            delta=1e-6,
        )

    def test_hard_fence_during_checkpoint_commit_does_not_double_bill(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        checkpoint_epoch = 2_050_000_000.0
        deadline_epoch = checkpoint_epoch + 30
        with mock.patch.object(app_module.time, "time", return_value=checkpoint_epoch):
            manager.start_boost([730], 1)
        with manager.state_lock:
            manager.start_time = checkpoint_epoch - 120
            manager.original_start_time = checkpoint_epoch - 120
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            app_module._install_user_quota_watchdog(
                fixture["user_id"],
                3600,
                "total_limit",
                deadline_epoch=deadline_epoch,
            )
            original_commit = db.session.commit

        commit_entered = Event()
        release_commit = Event()
        commit_calls = 0
        clock = {"now": checkpoint_epoch}

        def blocking_first_commit():
            nonlocal commit_calls
            commit_calls += 1
            if commit_calls == 1:
                commit_entered.set()
                release_commit.wait(timeout=5)
            return original_commit()

        def run_checkpoint():
            with app_module.app.app_context():
                return app_module._checkpoint_active_boosts_once()

        watchdog_job = None
        with (
            mock.patch.object(
                app_module.time,
                "time",
                side_effect=lambda: clock["now"],
            ),
            mock.patch.object(
                db.session,
                "commit",
                side_effect=blocking_first_commit,
            ),
        ):
            checkpoint_job = gevent.spawn(run_checkpoint)
            self.assertTrue(commit_entered.wait(timeout=2))
            clock["now"] = deadline_epoch
            watchdog_job, _watchdog = self._fire_current_quota_watchdog(
                fixture["user_id"],
                deadline_epoch=deadline_epoch,
            )
            try:
                for _attempt in range(200):
                    if fixture["client"].force_disconnect_calls >= 1:
                        break
                    gevent.sleep(0.01)
                self.assertEqual(fixture["client"].force_disconnect_calls, 1)
                pending = manager.pending_final_segments()
                self.assertEqual(len(pending), 2)
                self.assertEqual(
                    sorted(segment["checkpoint_only"] for segment in pending),
                    [False, True],
                )
                self.assertFalse(checkpoint_job.ready())
                self.assertFalse(watchdog_job.ready())
            finally:
                release_commit.set()
                gevent.joinall(
                    [checkpoint_job, watchdog_job],
                    timeout=5,
                    raise_error=False,
                )

        self.assertTrue(checkpoint_job.ready())
        self.assertIsNone(checkpoint_job.exception)
        self.assertTrue(watchdog_job.ready())
        self.assertIsNone(watchdog_job.exception)
        with app_module.app.app_context():
            logs = BoostLog.query.filter_by(user_id=fixture["user_id"]).order_by(
                BoostLog.started_at
            ).all()
            self.assertEqual(len(logs), 2)
            self.assertEqual(
                [(log.started_at, log.stopped_at) for log in logs],
                [
                    (
                        app_module.utc_from_epoch(checkpoint_epoch - 120),
                        app_module.utc_from_epoch(checkpoint_epoch),
                    ),
                    (
                        app_module.utc_from_epoch(checkpoint_epoch),
                        app_module.utc_from_epoch(deadline_epoch),
                    ),
                ],
            )
            self.assertEqual(sum(log.duration_seconds for log in logs), 150)
        self.assertEqual(manager.pending_final_segments(), [])

    def test_late_checkpoint_never_bills_past_published_hard_deadline(self):
        Config.PLANS["quota-hard-late"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 120 / 3600,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-hard-late")
        manager = fixture["manager"]
        deadline_epoch = time.time() + 120
        observed_epoch = deadline_epoch + 30
        with mock.patch.object(
            app_module.time,
            "time",
            return_value=deadline_epoch - 120,
        ):
            manager.start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with app_module.app.app_context():
            app_module._install_user_quota_watchdog(
                fixture["user_id"],
                120,
                "total_limit",
                deadline_epoch=deadline_epoch,
            )
            # Deliberately omit manager.set_runtime_stop_deadline(): this models
            # the narrow publication race and proves the app-level boundary is
            # independently authoritative.
            with mock.patch.object(
                app_module.time,
                "time",
                return_value=observed_epoch,
            ):
                self.assertEqual(app_module._checkpoint_active_boosts_once(), 1)

            logs = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).all()

        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].duration_seconds, 120)
        self.assertEqual(
            logs[0].stopped_at,
            app_module.utc_from_epoch(deadline_epoch),
        )
        self.assertEqual(
            logs[0].remote_stopped_at,
            app_module.utc_from_epoch(observed_epoch),
        )
        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertEqual(manager.pending_final_segments(), [])

    def test_checkpoint_error_for_one_account_does_not_block_next_account(self):
        first = self._fixture(account_id="00000000000000a1")
        second = self._fixture(account_id="00000000000000a2")
        cutoff = 2_100_000_000.0
        for fixture in (first, second):
            fixture["manager"].start_boost([730], 1)
            with fixture["manager"].state_lock:
                fixture["manager"].start_time = cutoff - 120
                fixture["manager"].original_start_time = cutoff - 120
            self._set_db_boost_state(fixture["account_id"], boosting=True)

        original_add = app_module._add_boost_log_if_missing

        def fail_first(account_id, *args, **kwargs):
            if account_id == first["account_id"]:
                raise RuntimeError("forced account checkpoint failure")
            return original_add(account_id, *args, **kwargs)

        with (
            app_module.app.app_context(),
            mock.patch.object(app_module.time, "time", return_value=cutoff),
            mock.patch.object(
                app_module,
                "_add_boost_log_if_missing",
                side_effect=fail_first,
            ),
        ):
            saved = app_module._checkpoint_active_boosts_once()
            self.assertEqual(saved, 1)
            logs = BoostLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0].account_id, second["account_id"])

        self.assertEqual(first["manager"].boost_snapshot()["start_time"], cutoff)
        first_pending = first["manager"].pending_final_segments()
        self.assertEqual(len(first_pending), 1)
        self.assertTrue(first_pending[0]["checkpoint_only"])
        self.assertEqual(second["manager"].boost_snapshot()["start_time"], cutoff)
        self.assertEqual(second["manager"].pending_final_segments(), [])

    def test_pending_final_segment_survives_manager_recreation(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        fixture["client"].stop_result = EResult.Fail
        fixture["client"].force_disconnect_result = False

        segment = manager.stop_boost_segment(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
            context="restart durability test",
        )
        self.assertFalse(segment["remote_stop_confirmed"])

        replacement_client = _FakeSteamClient()
        replacement_client.stop_result = EResult.Fail
        replacement_client.force_disconnect_result = True
        with mock.patch.object(
            steam_manager,
            "_make_client",
            return_value=replacement_client,
        ):
            replacement = steam_manager.SteamAccountManager(
                fixture["account_id"],
                manager.steam_username,
            )
        app_module.boost_service._managers[fixture["account_id"]] = replacement
        self.assertEqual(len(replacement.pending_final_segments()), 1)

        with app_module.app.app_context():
            result = app_module._stop_boost_session_and_persist(
                fixture["account_id"],
                fixture["user_id"],
                replacement,
            )
            self.assertTrue(result["persisted"])
            self.assertTrue(result["remote_stop_confirmed"])
            self.assertEqual(BoostLog.query.count(), 1)
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
        self.assertEqual(replacement.pending_final_segments(), [])

        clean_client = _FakeSteamClient()
        with mock.patch.object(
            steam_manager,
            "_make_client",
            return_value=clean_client,
        ):
            reloaded = steam_manager.SteamAccountManager(
                fixture["account_id"],
                manager.steam_username,
            )
        self.assertEqual(reloaded.pending_final_segments(), [])

    def test_runtime_deadline_caps_fatal_stop_before_pending_write(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        deadline_epoch = time.time() + 120
        observed_epoch = deadline_epoch + 30
        with mock.patch.object(
            app_module.time,
            "time",
            return_value=deadline_epoch - 120,
        ):
            started = manager.start_boost([730], 1)
        self.assertTrue(manager.set_runtime_stop_deadline(
            deadline_epoch,
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
        ))

        with mock.patch.object(
            steam_manager.time,
            "time",
            return_value=observed_epoch,
        ):
            segment = manager.stop_boost_segment(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
                context="late fatal boundary",
            )

        self.assertEqual(segment["stopped_at"], deadline_epoch)
        self.assertEqual(segment["elapsed"], 120)
        self.assertEqual(segment["remote_stopped_at"], observed_epoch)
        pending = manager.pending_final_segments()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["stopped_at"], deadline_epoch)

    def test_hard_deadline_cap_survives_db_failure_and_manager_reload(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        deadline_epoch = time.time() + 120
        observed_epoch = deadline_epoch + 30
        with mock.patch.object(
            app_module.time,
            "time",
            return_value=deadline_epoch - 120,
        ):
            manager.start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            app_module._install_user_quota_watchdog(
                fixture["user_id"],
                120,
                "total_limit",
                deadline_epoch=deadline_epoch,
            )

        with mock.patch.object(
            steam_manager.time,
            "time",
            return_value=observed_epoch,
        ):
            uncapped = manager.stop_boost_segment(context="late fatal fallback")
        self.assertEqual(uncapped["stopped_at"], observed_epoch)

        with (
            app_module.app.app_context(),
            mock.patch.object(
                db.session,
                "commit",
                side_effect=SQLAlchemyError("forced durable-cap DB failure"),
            ),
        ):
            self.assertFalse(app_module._persist_manager_final_segment(
                fixture["account_id"],
                fixture["user_id"],
                manager,
                uncapped,
            ))
        capped_pending = manager.pending_final_segments()
        self.assertEqual(len(capped_pending), 1)
        self.assertEqual(capped_pending[0]["stopped_at"], deadline_epoch)

        app_module._cancel_user_quota_watchdog(fixture["user_id"])
        with mock.patch.object(
            steam_manager,
            "_make_client",
            return_value=_FakeSteamClient(),
        ):
            replacement = steam_manager.SteamAccountManager(
                fixture["account_id"],
                manager.steam_username,
            )
        reloaded = replacement.pending_final_segments()
        self.assertEqual(len(reloaded), 1)
        self.assertEqual(reloaded[0]["stopped_at"], deadline_epoch)

        with app_module.app.app_context():
            self.assertTrue(app_module._persist_manager_final_segment(
                fixture["account_id"],
                fixture["user_id"],
                replacement,
                reloaded[0],
            ))
            logs = BoostLog.query.filter_by(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
            ).all()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].duration_seconds, 120)
        self.assertEqual(replacement.pending_final_segments(), [])

    def test_acknowledge_final_segment_is_idempotent(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        segment = manager.stop_boost_segment(context="double ack")

        self.assertTrue(manager.acknowledge_final_segment(segment))
        self.assertFalse(manager.acknowledge_final_segment(segment))

    def test_pending_writer_never_creates_state_the_loader_rejects(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]

        def queued_segment(index, *, checkpoint_only):
            started_at = 2_070_000_000.0 + index * 2
            return {
                "account_id": fixture["account_id"],
                "session_id": f"queued-{index}",
                "generation": index,
                "started_at": started_at,
                "stopped_at": started_at + 1,
                "elapsed": 1.0,
                "app_ids": [730],
                "remote_stop_confirmed": True,
                "remote_stopped_at": started_at + 1,
                "checkpoint_only": checkpoint_only,
            }

        manager._pending_final_segments = [
            queued_segment(index, checkpoint_only=True)
            for index in range(steam_manager.MAX_PENDING_CHECKPOINT_SEGMENTS)
        ]
        self.assertFalse(manager._remember_final_segment_unlocked(
            queued_segment(500, checkpoint_only=True)
        ))
        self.assertTrue(manager._remember_final_segment_unlocked(
            queued_segment(501, checkpoint_only=False)
        ))
        self.assertFalse(manager._remember_final_segment_unlocked(
            queued_segment(502, checkpoint_only=False)
        ))
        self.assertEqual(
            len(manager.pending_final_segments()),
            steam_manager.MAX_PENDING_FINAL_SEGMENTS,
        )

        with mock.patch.object(
            steam_manager,
            "_make_client",
            return_value=_FakeSteamClient(),
        ):
            replacement = steam_manager.SteamAccountManager(
                fixture["account_id"],
                manager.steam_username,
            )
        loaded = replacement.pending_final_segments()
        self.assertEqual(len(loaded), steam_manager.MAX_PENDING_FINAL_SEGMENTS)
        self.assertFalse(any(segment.get("state_corrupt") for segment in loaded))

    def test_legacy_pending_segment_without_remote_timestamp_still_loads(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        segment = manager.prepare_stop_boost_segment(context="legacy fixture")
        self.assertIsNotNone(segment)
        pending_path = steam_manager._pending_final_segments_path(
            fixture["account_id"]
        )
        with open(pending_path, "r", encoding="utf-8") as handle:
            raw_segments = app_module.json.load(handle)
        for raw_segment in raw_segments:
            raw_segment.pop("remote_stopped_at", None)
        with open(pending_path, "w", encoding="utf-8") as handle:
            app_module.json.dump(raw_segments, handle)

        with mock.patch.object(
            steam_manager,
            "_make_client",
            return_value=_FakeSteamClient(),
        ):
            replacement = steam_manager.SteamAccountManager(
                fixture["account_id"],
                manager.steam_username,
            )

        loaded = replacement.pending_final_segments()
        self.assertEqual(len(loaded), 1)
        self.assertIsNone(loaded[0]["remote_stopped_at"])

    def test_fatal_disconnect_between_remove_snapshot_and_stop_is_not_lost(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        original_stop = manager.stop_boost_segment
        injected = False

        def fatal_wins(*args, **kwargs):
            nonlocal injected
            if not injected:
                injected = True
                original_stop(*args, context="fatal race winner", **{
                    key: value
                    for key, value in kwargs.items()
                    if key != "context"
                })
                return None
            return original_stop(*args, **kwargs)

        with mock.patch.object(
            manager,
            "stop_boost_segment",
            side_effect=fatal_wins,
        ):
            response = self.client.post(
                "/accounts/remove",
                json={"acct_id": fixture["account_id"]},
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        with app_module.app.app_context():
            self.assertIsNone(db.session.get(SteamAccount, fixture["account_id"]))
            logs = BoostLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertIsNone(logs[0].account_id)

    def test_manual_stop_and_timer_race_writes_one_segment(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        gate = Event()
        responses = []

        def manual_stop():
            gate.wait()
            with app_module.app.test_client() as client:
                responses.append(client.post(
                    "/boost/toggle",
                    json={"acct_id": fixture["account_id"], "action": "stop"},
                    headers=fixture["headers"],
                ))

        def timer_stop():
            gate.wait()
            app_module._run_boost_stop_timer(
                fixture["account_id"],
                fixture["user_id"],
                started["session_id"],
                started["generation"],
                "race-test",
            )

        jobs = [gevent.spawn(manual_stop), gevent.spawn(timer_stop)]
        gevent.sleep(0)
        gate.set()
        gevent.joinall(jobs, timeout=5, raise_error=True)

        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].status_code, 200)
        self.assertFalse(manager.boost_snapshot()["boosting"])
        with app_module.app.app_context():
            self.assertEqual(BoostLog.query.count(), 1)

    def test_timer_and_fatal_disconnect_race_writes_one_segment(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        started_epoch = self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        gate = Event()

        def timer_stop():
            gate.wait()
            app_module._run_boost_stop_timer(
                fixture["account_id"],
                fixture["user_id"],
                started["session_id"],
                started["generation"],
                "timer-fatal-race",
            )

        def fatal_stop():
            gate.wait()
            app_module._handle_fatal_disconnect(
                fixture["account_id"],
                120,
                started["session_id"],
                started["generation"],
                started_epoch,
                [730],
            )

        jobs = [gevent.spawn(timer_stop), gevent.spawn(fatal_stop)]
        gevent.sleep(0)
        gate.set()
        gevent.joinall(jobs, timeout=5, raise_error=True)

        self.assertFalse(manager.boost_snapshot()["boosting"])
        with app_module.app.app_context():
            self.assertEqual(BoostLog.query.count(), 1)

    def test_timer_persists_fatal_pending_then_callback_clears_db_state(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        started_epoch = self._age_active_segment(manager, 120)
        target = app_module.utc_now() + timedelta(hours=1)
        self._set_db_boost_state(
            fixture["account_id"],
            boosting=True,
            target=target,
        )

        segment = manager.stop_boost_segment(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
            context="fatal-before-user-lock",
        )
        app_module._run_boost_stop_timer(
            fixture["account_id"],
            fixture["user_id"],
            started["session_id"],
            started["generation"],
            "fatal-pending-winner",
        )

        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertIsNone(account.target_stop_time)
            self.assertEqual(BoostLog.query.count(), 1)
        self.assertEqual(manager.pending_final_segments(), [])

        app_module._handle_fatal_disconnect(
            fixture["account_id"],
            segment["elapsed"],
            segment["session_id"],
            segment["generation"],
            segment["started_at"],
            segment["app_ids"],
            segment["stopped_at"],
        )

        with app_module.app.app_context():
            account = db.session.get(SteamAccount, fixture["account_id"])
            self.assertFalse(account.is_boosting)
            self.assertIsNone(account.target_stop_time)
            self.assertEqual(BoostLog.query.count(), 1)

    def test_account_delete_and_timer_race_keeps_one_detached_segment(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        gate = Event()
        responses = []

        def delete_account():
            gate.wait()
            with app_module.app.test_client() as client:
                responses.append(client.post(
                    "/accounts/remove",
                    json={"acct_id": fixture["account_id"]},
                    headers=fixture["headers"],
                ))

        def timer_stop():
            gate.wait()
            app_module._run_boost_stop_timer(
                fixture["account_id"],
                fixture["user_id"],
                started["session_id"],
                started["generation"],
                "delete-timer-race",
            )

        jobs = [gevent.spawn(delete_account), gevent.spawn(timer_stop)]
        gevent.sleep(0)
        gate.set()
        gevent.joinall(jobs, timeout=5, raise_error=True)

        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].status_code, 200)
        self.assertTrue(responses[0].get_json()["ok"])
        with app_module.app.app_context():
            self.assertIsNone(db.session.get(SteamAccount, fixture["account_id"]))
            logs = BoostLog.query.all()
            self.assertEqual(len(logs), 1)
            self.assertIsNone(logs[0].account_id)

    def test_user_quota_deadline_scales_for_one_two_and_three_accounts(self):
        Config.PLANS["quota-scale"] = {
            "max_accounts": 3,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-scale")
        fixtures = [fixture, self._add_account(fixture), self._add_account(fixture)]
        fixed_epoch = time.time()
        fixed_now = app_module.utc_from_epoch(fixed_epoch)
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=fixed_now - timedelta(seconds=3000),
                stopped_at=fixed_now,
                duration_seconds=3000,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        with mock.patch.object(app_module.time, "time", return_value=fixed_epoch):
            for index, account_fixture in enumerate(fixtures, start=1):
                account_fixture["manager"].start_boost([730], 1)
                with app_module.app.app_context():
                    state = app_module._quota_usage_snapshot(fixture["user_id"])
                self.assertEqual(state["active_count"], index)
                self.assertAlmostEqual(
                    state["remaining_usage_seconds"],
                    600.0,
                    delta=0.01,
                )
                self.assertAlmostEqual(
                    state["estimated_wall_seconds"],
                    600.0 / index,
                    delta=0.01,
                )

    def test_second_start_replaces_single_user_watchdog_with_half_deadline(self):
        Config.PLANS["quota-route"] = {
            "max_accounts": 3,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-route")
        second = self._add_account(fixture)
        now_utc = app_module.utc_now()
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=now_utc - timedelta(seconds=3590),
                stopped_at=now_utc,
                duration_seconds=3590,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        first_response = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "start"},
            headers=fixture["headers"],
        )
        self.assertTrue(first_response.get_json()["ok"])
        with app_module._quota_watchdog_lock:
            first_entry = dict(
                app_module._user_quota_watchdogs[fixture["user_id"]]
            )
        first_delay = first_entry["deadline_epoch"] - time.time()

        second_response = self.client.post(
            "/boost/toggle",
            json={"acct_id": second["account_id"], "action": "start"},
            headers=fixture["headers"],
        )
        self.assertTrue(second_response.get_json()["ok"])
        with app_module._quota_watchdog_lock:
            self.assertEqual(len(app_module._user_quota_watchdogs), 1)
            second_entry = dict(
                app_module._user_quota_watchdogs[fixture["user_id"]]
            )
        second_delay = second_entry["deadline_epoch"] - time.time()
        self.assertGreater(second_entry["generation"], first_entry["generation"])
        self.assertAlmostEqual(first_delay, 10.0, delta=1.0)
        self.assertAlmostEqual(second_delay, 5.0, delta=1.0)

    def test_staggered_stop_extends_remaining_account_wall_deadline(self):
        Config.PLANS["quota-staggered"] = {
            "max_accounts": 2,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-staggered")
        second = self._add_account(fixture)
        fixed_epoch = time.time()
        fixed_now = app_module.utc_from_epoch(fixed_epoch)
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=fixed_now - timedelta(seconds=3000),
                stopped_at=fixed_now,
                duration_seconds=3000,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()
        with mock.patch.object(app_module.time, "time", return_value=fixed_epoch):
            fixture["manager"].start_boost([730], 1)
            second_started = second["manager"].start_boost([730], 1)
            with app_module.app.app_context():
                with app_module._user_operation_lock(fixture["user_id"]):
                    first_state = app_module._reconcile_user_quota_locked(
                        fixture["user_id"], "staggered_start"
                    )
        self.assertAlmostEqual(first_state["estimated_wall_seconds"], 300, delta=0.01)

        later_epoch = fixed_epoch + 100
        with mock.patch.object(app_module.time, "time", return_value=later_epoch):
            with app_module.app.app_context():
                with app_module._user_operation_lock(fixture["user_id"]):
                    stop_result = app_module._stop_boost_session_and_persist(
                        second["account_id"],
                        fixture["user_id"],
                        second["manager"],
                        expected_session_id=second_started["session_id"],
                        expected_generation=second_started["generation"],
                    )
                    second_state = app_module._reconcile_user_quota_locked(
                        fixture["user_id"], "staggered_stop"
                    )
        self.assertTrue(stop_result["persisted"])
        self.assertEqual(second_state["active_count"], 1)
        self.assertAlmostEqual(second_state["estimated_wall_seconds"], 400, delta=0.01)

    def test_admin_concurrent_starts_are_serialized_by_explicit_user_lock(self):
        Config.PLANS["quota-admin-race"] = {
            "max_accounts": 2,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-admin-race")
        second = self._add_account(fixture)
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.is_admin = True
            db.session.commit()

        entered = Event()
        release = Event()
        original_games_played = fixture["client"].games_played

        def blocking_games_played(app_ids):
            entered.set()
            release.wait(timeout=2)
            return original_games_played(app_ids)

        fixture["client"].games_played = blocking_games_played
        first_client = app_module.app.test_client()
        second_client = app_module.app.test_client()

        first_job = gevent.spawn(
            first_client.post,
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "start"},
            headers=fixture["headers"],
        )
        self.assertTrue(entered.wait(timeout=1))
        second_job = gevent.spawn(
            second_client.post,
            "/boost/toggle",
            json={"acct_id": second["account_id"], "action": "start"},
            headers=fixture["headers"],
        )
        gevent.sleep(0)
        self.assertFalse(second["manager"].boost_snapshot()["boosting"])
        release.set()
        gevent.joinall([first_job, second_job], timeout=5, raise_error=True)

        self.assertTrue(first_job.value.get_json()["ok"])
        self.assertTrue(second_job.value.get_json()["ok"])
        with app_module._quota_watchdog_lock:
            entry = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertEqual(len(app_module._user_quota_watchdogs), 1)
        remaining_delay = entry["deadline_epoch"] - time.time()
        self.assertLessEqual(remaining_delay, 1800)
        self.assertGreater(remaining_delay, 1700)

    def test_quota_stop_finalizes_three_accounts_at_one_canonical_timestamp(self):
        fixture = self._fixture(plan="premium")
        fixtures = [fixture, self._add_account(fixture), self._add_account(fixture)]
        stopped_epoch = time.time()
        for account_fixture in fixtures:
            account_fixture["manager"].start_boost([730], 1)
            self._age_active_segment(account_fixture["manager"], 120)
            self._set_db_boost_state(account_fixture["account_id"], boosting=True)

        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                result = app_module._stop_all_user_boosts_locked(
                    fixture["user_id"],
                    "test_exhaustion",
                    stopped_epoch=stopped_epoch,
                )

        self.assertTrue(result["ok"])
        self.assertEqual(result["active_count"], 3)
        self.assertEqual(result["persisted_count"], 3)
        for account_fixture in fixtures:
            self.assertFalse(account_fixture["manager"].boost_snapshot()["boosting"])
            self.assertEqual(account_fixture["client"].stop_calls, 1)
        with app_module.app.app_context():
            logs = BoostLog.query.order_by(BoostLog.id).all()
            self.assertEqual(len(logs), 3)
            self.assertEqual(len({log.stopped_at for log in logs}), 1)
            self.assertEqual(
                logs[0].stopped_at,
                app_module.utc_from_epoch(stopped_epoch),
            )

    def test_stale_user_watchdog_cannot_stop_new_generation(self):
        fixture = self._fixture(plan="basic")
        fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                first = app_module._install_user_quota_watchdog(
                    fixture["user_id"], 3600, "total_limit"
                )
                second = app_module._install_user_quota_watchdog(
                    fixture["user_id"], 3600, "total_limit"
                )

        app_module._run_user_quota_watchdog(
            fixture["user_id"],
            first["generation"],
            first["token"],
            first["reason"],
        )

        self.assertTrue(fixture["manager"].boost_snapshot()["boosting"])
        with app_module._quota_watchdog_lock:
            current = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertEqual(current["generation"], second["generation"])
            self.assertEqual(current["token"], second["token"])

    def test_daily_watchdog_reschedules_at_utc_midnight_before_exhaustion(self):
        fixture = self._fixture(plan="free")
        fixed_now = datetime(2031, 5, 4, 23, 59, 0)
        fixed_epoch = fixed_now.replace(tzinfo=timezone.utc).timestamp()
        with mock.patch.object(app_module.time, "time", return_value=fixed_epoch):
            fixture["manager"].start_boost([730], 1)
            with app_module.app.app_context():
                state = app_module._quota_usage_snapshot(fixture["user_id"])
        self.assertEqual(state["next_reason"], "utc_midnight")
        self.assertAlmostEqual(state["next_delay_seconds"], 60.0, delta=0.01)

    def test_delayed_midnight_callback_does_not_cap_new_day_usage(self):
        Config.PLANS["quota-midnight-delay"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": 1 / 60,
            "total_hours": None,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-midnight-delay")
        midnight = datetime(2031, 5, 5, tzinfo=timezone.utc).timestamp()
        started_epoch = midnight - 60
        with mock.patch.object(
            app_module.time,
            "time",
            return_value=started_epoch,
        ):
            started = fixture["manager"].start_boost([730], 1)
            with app_module.app.app_context():
                with app_module._user_operation_lock(fixture["user_id"]):
                    state = app_module._reconcile_user_quota_locked(
                        fixture["user_id"],
                        "midnight_delay_start",
                    )

        self.assertEqual(state["next_reason"], "utc_midnight")
        self.assertIsNone(state["quota_deadline_epoch"])
        self.assertIsNone(
            fixture["manager"].boost_snapshot()["runtime_stop_deadline"]
        )

        observed_stop = midnight + 30
        with mock.patch.object(
            steam_manager.time,
            "time",
            return_value=observed_stop,
        ):
            segment = fixture["manager"].stop_boost_segment(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
                context="delayed midnight callback",
            )
        self.assertEqual(segment["stopped_at"], observed_stop)
        self.assertEqual(segment["elapsed"], 90)

    def test_plan_expiry_before_paid_quota_does_not_publish_late_hard_cap(self):
        Config.PLANS["quota-expiry-before-hard-cap"] = {
            "max_accounts": 1,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1 / 60,
            "price": 0,
            "duration_days": 1,
        }
        fixture = self._fixture(plan="quota-expiry-before-hard-cap")
        base_epoch = datetime(2031, 5, 4, 12, tzinfo=timezone.utc).timestamp()
        expiry_epoch = base_epoch + 30.0
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_activated_at = app_module.utc_from_epoch(base_epoch)
            user.plan_expires = app_module.utc_from_epoch(expiry_epoch)
            db.session.commit()

        with (
            mock.patch.object(app_module.time, "time", return_value=base_epoch),
            mock.patch.object(steam_manager.time, "time", return_value=base_epoch),
        ):
            started = fixture["manager"].start_boost([730], 1)
            with app_module.app.app_context():
                with app_module._user_operation_lock(fixture["user_id"]):
                    state = app_module._reconcile_user_quota_locked(
                        fixture["user_id"],
                        "expiry_before_hard_cap",
                    )

        self.assertEqual(state["next_reason"], "plan_expiry")
        self.assertAlmostEqual(state["next_deadline_epoch"], expiry_epoch, delta=0.01)
        self.assertIsNone(state["quota_deadline_epoch"])
        self.assertIsNone(
            fixture["manager"].boost_snapshot()["runtime_stop_deadline"]
        )

        observed_stop = base_epoch + 90.0
        with mock.patch.object(
            steam_manager.time,
            "time",
            return_value=observed_stop,
        ):
            segment = fixture["manager"].stop_boost_segment(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
                context="late plan expiry callback",
            )
        self.assertEqual(segment["stopped_at"], observed_stop)
        self.assertEqual(segment["elapsed"], 90)

    def test_account_user_timer_remains_shorter_than_shared_quota_deadline(self):
        Config.PLANS["quota-user-timer"] = {
            "max_accounts": 2,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan="quota-user-timer")
        second = self._add_account(fixture)
        fixed_epoch = time.time()
        fixed_now = app_module.utc_from_epoch(fixed_epoch)
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=fixed_now - timedelta(seconds=3000),
                stopped_at=fixed_now,
                duration_seconds=3000,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()
        with mock.patch.object(app_module.time, "time", return_value=fixed_epoch):
            first_started = fixture["manager"].start_boost([730], 1)
            second["manager"].start_boost([730], 1)
            app_module._remember_account_user_timer_deadline(
                fixture["account_id"],
                first_started["session_id"],
                first_started["generation"],
                fixed_epoch + 100,
            )
            with app_module.app.app_context():
                with app_module._user_operation_lock(fixture["user_id"]):
                    state = app_module._reconcile_user_quota_locked(
                        fixture["user_id"],
                        "test_user_timer",
                    )
                first_account = db.session.get(
                    SteamAccount, fixture["account_id"]
                )
                second_account = db.session.get(
                    SteamAccount, second["account_id"]
                )
                self.assertEqual(
                    first_account.target_stop_time,
                    app_module.utc_from_epoch(fixed_epoch + 100),
                )
                self.assertAlmostEqual(
                    (second_account.target_stop_time - fixed_now).total_seconds(),
                    300.0,
                    delta=0.01,
                )
        self.assertTrue(state["ok"])

    def test_watchdog_spawn_failure_compensates_new_start(self):
        fixture = self._fixture(plan="basic")
        with mock.patch.object(
            app_module,
            "_install_user_quota_watchdog",
            side_effect=RuntimeError("forced watchdog spawn failure"),
        ):
            response = self.client.post(
                "/boost/toggle",
                json={"acct_id": fixture["account_id"], "action": "start"},
                headers=fixture["headers"],
            )
        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])
        self.assertEqual(fixture["client"].stop_calls, 1)

    def test_start_reconciles_pending_usage_from_another_account(self):
        fixture = self._fixture(plan="basic")
        second = self._add_account(fixture)
        old = second["manager"].start_boost([730], 1)
        self._age_active_segment(second["manager"], 120)
        segment = second["manager"].stop_boost_segment(
            expected_session_id=old["session_id"],
            expected_generation=old["generation"],
            context="cross-account pending test",
        )
        self.assertTrue(segment["remote_stop_confirmed"])
        self.assertEqual(len(second["manager"].pending_final_segments()), 1)

        response = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "start"},
            headers=fixture["headers"],
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(second["manager"].pending_final_segments(), [])
        with app_module.app.app_context():
            self.assertEqual(BoostLog.query.count(), 1)

    def test_start_hydrates_other_accounts_pending_file_after_registry_reset(self):
        fixture = self._fixture(plan="basic")
        second = self._add_account(fixture)
        old = second["manager"].start_boost([730], 1)
        self._age_active_segment(second["manager"], 120)
        segment = second["manager"].stop_boost_segment(
            expected_session_id=old["session_id"],
            expected_generation=old["generation"],
            context="restart hydration test",
        )
        self.assertTrue(segment["remote_stop_confirmed"])
        self.assertEqual(len(second["manager"].pending_final_segments()), 1)

        # Simulate a process-local registry reset for only the account that
        # owns the durable file. The start route must hydrate it from DB/disk.
        app_module.boost_service._managers.pop(second["account_id"])
        self.assertIsNone(app_module.boost_service.get(second["account_id"]))

        response = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "start"},
            headers=fixture["headers"],
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        hydrated = app_module.boost_service.get(second["account_id"])
        self.assertIsNotNone(hydrated)
        self.assertEqual(hydrated.pending_final_segments(), [])
        with app_module.app.app_context():
            log = BoostLog.query.one()
            self.assertEqual(log.account_id, second["account_id"])
            self.assertGreaterEqual(log.duration_seconds, 119)

    def test_unconfirmed_pending_usage_on_other_account_blocks_start(self):
        fixture = self._fixture(plan="basic")
        second = self._add_account(fixture)
        second["client"].stop_result = EResult.Fail
        second["client"].force_disconnect_result = False
        old = second["manager"].start_boost([730], 1)
        segment = second["manager"].stop_boost_segment(
            expected_session_id=old["session_id"],
            expected_generation=old["generation"],
            context="unconfirmed cross-account pending test",
        )
        self.assertFalse(segment["remote_stop_confirmed"])

        response = self.client.post(
            "/boost/toggle",
            json={"acct_id": fixture["account_id"], "action": "start"},
            headers=fixture["headers"],
        )
        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])

    def test_plan_downgrade_preserves_usage_window_and_stops_over_limit(self):
        original_basic_total = Config.PLANS["basic"]["total_hours"]
        original_premium_total = Config.PLANS["premium"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 1
        Config.PLANS["premium"]["total_hours"] = 2
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours", original_basic_total
            )
        )
        self.addCleanup(
            lambda: Config.PLANS["premium"].__setitem__(
                "total_hours", original_premium_total
            )
        )
        fixture = self._fixture(plan="premium")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            original_activation = user.plan_activated_at
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=app_module.utc_now() - timedelta(seconds=5400),
                stopped_at=app_module.utc_now(),
                duration_seconds=5400,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()
        fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                user = db.session.get(User, fixture["user_id"])
                app_module._activate_plan(
                    user,
                    "basic",
                    reset_usage_window=False,
                )
                db.session.commit()
                result = app_module._reconcile_user_quota_locked(
                    fixture["user_id"],
                    "test_downgrade",
                    enforce=True,
                )
                user = db.session.get(User, fixture["user_id"])
                self.assertEqual(user.plan_activated_at, original_activation)
        self.assertTrue(result["quota_stopped"])
        self.assertTrue(result["ok"])
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])

    def test_plan_upgrade_reschedules_without_stopping_active_boost(self):
        original_basic_total = Config.PLANS["basic"]["total_hours"]
        original_premium_total = Config.PLANS["premium"]["total_hours"]
        Config.PLANS["basic"]["total_hours"] = 1
        Config.PLANS["premium"]["total_hours"] = 2
        self.addCleanup(
            lambda: Config.PLANS["basic"].__setitem__(
                "total_hours", original_basic_total
            )
        )
        self.addCleanup(
            lambda: Config.PLANS["premium"].__setitem__(
                "total_hours", original_premium_total
            )
        )
        fixture = self._fixture(plan="basic")
        now_utc = app_module.utc_now()
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=now_utc - timedelta(seconds=3500),
                stopped_at=now_utc,
                duration_seconds=3500,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()
        fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                before = app_module._quota_usage_snapshot(fixture["user_id"])
                user = db.session.get(User, fixture["user_id"])
                app_module._activate_plan(user, "premium", reset_usage_window=True)
                db.session.commit()
                after = app_module._reconcile_user_quota_locked(
                    fixture["user_id"],
                    "test_upgrade",
                    enforce=True,
                )
        self.assertLess(before["estimated_wall_seconds"], 101)
        self.assertGreater(after["estimated_wall_seconds"], 7100)
        self.assertFalse(after.get("quota_stopped", False))
        self.assertTrue(fixture["manager"].boost_snapshot()["boosting"])

    def test_plan_expiry_is_enforced_without_a_followup_http_request(self):
        fixture = self._fixture(plan="basic")
        now_utc = app_module.utc_now().replace(
            hour=12, minute=0, second=0, microsecond=0
        )
        now_epoch = now_utc.timestamp()
        with (
            mock.patch.object(app_module, "utc_now", return_value=now_utc),
            mock.patch.object(app_module.clock, "epoch", return_value=now_epoch),
            mock.patch.object(
                app_module.clock,
                "steady_epoch",
                return_value=now_epoch,
            ),
        ):
            with app_module.app.app_context():
                user = db.session.get(User, fixture["user_id"])
                user.plan_expires = now_utc - timedelta(seconds=1)
                db.session.add(BoostLog(
                    account_id=fixture["account_id"],
                    user_id=fixture["user_id"],
                    started_at=now_utc - timedelta(hours=9),
                    stopped_at=now_utc,
                    duration_seconds=9 * 3600,
                    games_count=1,
                    app_ids_json="[730]",
                ))
                db.session.commit()
            fixture["manager"].start_boost([730], 1)
            self._set_db_boost_state(fixture["account_id"], boosting=True)

            with app_module.app.app_context():
                with app_module._user_operation_lock(fixture["user_id"]):
                    result = app_module._reconcile_user_quota_locked(
                        fixture["user_id"],
                        "test_plan_expiry",
                        enforce=True,
                    )
                    user = db.session.get(User, fixture["user_id"])
                    self.assertEqual(user.plan, "free")
        self.assertTrue(result["quota_stopped"])
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])

    def test_snapshot_deadline_is_not_reanchored_after_install_latency(self):
        fixture = self._fixture(plan="basic")
        fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        base_epoch = time.time()
        expiry_epoch = base_epoch + 90.0
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_expires = app_module.utc_from_epoch(expiry_epoch)
            db.session.commit()

        clock = {"now": base_epoch}
        original_snapshot = app_module._quota_usage_snapshot

        def snapshot_then_delay(*args, **kwargs):
            state = original_snapshot(*args, **kwargs)
            # Deterministically model expensive reconciliation work after the
            # accounting instant but before watchdog installation.
            clock["now"] = base_epoch + 30.0
            return state

        with (
            mock.patch.object(
                app_module.time,
                "time",
                side_effect=lambda: clock["now"],
            ),
            mock.patch.object(
                app_module,
                "_quota_usage_snapshot",
                side_effect=snapshot_then_delay,
            ),
        ):
            with app_module.app.app_context():
                with app_module._user_operation_lock(fixture["user_id"]):
                    result = app_module._reconcile_user_quota_locked(
                        fixture["user_id"],
                        "install_latency_regression",
                    )

        self.assertTrue(result["ok"])
        self.assertEqual(result["next_reason"], "plan_expiry")
        self.assertAlmostEqual(
            result["next_deadline_epoch"], expiry_epoch, delta=0.001
        )
        with app_module._quota_watchdog_lock:
            entry = dict(
                app_module._user_quota_watchdogs[fixture["user_id"]]
            )
        self.assertEqual(entry["reason"], "plan_expiry")
        self.assertAlmostEqual(entry["deadline_epoch"], expiry_epoch, delta=0.001)

    def test_early_watchdog_rearm_preserves_original_absolute_deadline(self):
        fixture = self._fixture(plan="basic")
        base_epoch = time.time()
        clock = {"now": base_epoch}
        original_claim = app_module._claim_user_quota_hard_fence

        with mock.patch.object(
            app_module.time,
            "time",
            side_effect=lambda: clock["now"],
        ):
            first = app_module._install_user_quota_watchdog(
                fixture["user_id"],
                60.0,
                "total_limit",
                deadline_epoch=base_epoch + 60.0,
            )

            def claim_then_delay(*args, **kwargs):
                claim = original_claim(*args, **kwargs)
                clock["now"] = base_epoch + 20.0
                return claim

            with mock.patch.object(
                app_module,
                "_claim_user_quota_hard_fence",
                side_effect=claim_then_delay,
            ):
                app_module._run_user_quota_watchdog(
                    fixture["user_id"],
                    first["generation"],
                    first["token"],
                    first["reason"],
                )

        with app_module._quota_watchdog_lock:
            current = dict(
                app_module._user_quota_watchdogs[fixture["user_id"]]
            )
        self.assertGreater(current["generation"], first["generation"])
        self.assertAlmostEqual(
            current["deadline_epoch"], base_epoch + 60.0, delta=0.001
        )

    def test_plan_activation_commit_rollback_keeps_existing_watchdog(self):
        fixture = self._fixture(plan="basic")
        original = app_module._install_user_quota_watchdog(
            fixture["user_id"], 3600.0, "total_limit"
        )

        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            app_module._activate_plan(user, "premium")
            session_type = type(db.session())
            with mock.patch.object(
                session_type,
                "commit",
                autospec=True,
                side_effect=SQLAlchemyError("forced activation commit failure"),
            ):
                with self.assertRaises(SQLAlchemyError):
                    db.session.commit()
            db.session.rollback()
            self.assertEqual(db.session.get(User, fixture["user_id"]).plan, "basic")

        with app_module._quota_watchdog_lock:
            current = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertEqual(current["generation"], original["generation"])
            self.assertEqual(current["token"], original["token"])

    def test_plan_expiry_commit_rollback_keeps_existing_watchdog(self):
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.plan_expires = app_module.utc_now() - timedelta(seconds=1)
            db.session.commit()
        original = app_module._install_user_quota_watchdog(
            fixture["user_id"], 3600.0, "plan_expiry"
        )

        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            session_type = type(db.session())
            with mock.patch.object(
                session_type,
                "commit",
                autospec=True,
                side_effect=SQLAlchemyError("forced expiry commit failure"),
            ):
                with self.assertRaises(SQLAlchemyError):
                    app_module._expire_user_plan_if_needed_locked(user)
            db.session.rollback()
            self.assertEqual(db.session.get(User, fixture["user_id"]).plan, "basic")

        with app_module._quota_watchdog_lock:
            current = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertEqual(current["generation"], original["generation"])
            self.assertEqual(current["token"], original["token"])

    def test_admin_free_commit_rollback_keeps_existing_watchdog(self):
        fixture = self._fixture(plan="basic")
        with app_module.app.app_context():
            user = db.session.get(User, fixture["user_id"])
            user.is_admin = True
            db.session.commit()
            session_type = type(db.session())
        original = app_module._install_user_quota_watchdog(
            fixture["user_id"], 3600.0, "total_limit"
        )
        # Skip the throttled last-seen write so the injected failure targets
        # the admin plan transaction deterministically.
        app_module._plan_expiry_cache[fixture["user_id"]] = time.time()

        with mock.patch.object(
            session_type,
            "commit",
            autospec=True,
            side_effect=SQLAlchemyError("forced admin plan commit failure"),
        ):
            with self.assertRaises(SQLAlchemyError):
                self.client.post(
                    "/admin/users/update",
                    json={"user_id": fixture["user_id"], "plan": "free"},
                    headers=fixture["headers"],
                )

        with app_module._quota_watchdog_lock:
            current = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertEqual(current["generation"], original["generation"])
            self.assertEqual(current["token"], original["token"])
        with app_module.app.app_context():
            db.session.rollback()
            self.assertEqual(db.session.get(User, fixture["user_id"]).plan, "basic")

    def test_user_quota_watchdog_exhausts_one_two_and_three_accounts_at_r_over_n(self):
        remaining_seconds = 60
        base_epoch = 2_000_000_000.0

        for active_count in (1, 2, 3):
            with self.subTest(active_count=active_count):
                plan = f"quota-exhaustion-{active_count}"
                Config.PLANS[plan] = {
                    "max_accounts": 3,
                    "max_games": 4,
                    "daily_hours": None,
                    "total_hours": remaining_seconds / 3600,
                    "price": 0,
                    "duration_days": None,
                }
                fixture = self._fixture(plan=plan)
                fixtures = [fixture]
                fixtures.extend(
                    self._add_account(fixture)
                    for _ in range(active_count - 1)
                )
                started_epoch = base_epoch + active_count * 10_000

                with mock.patch.object(
                    app_module.time,
                    "time",
                    return_value=started_epoch,
                ):
                    for account_fixture in fixtures:
                        account_fixture["manager"].start_boost([730], 1)
                    with app_module.app.app_context():
                        with app_module._user_operation_lock(fixture["user_id"]):
                            state = app_module._reconcile_user_quota_locked(
                                fixture["user_id"],
                                "synthetic_n_start",
                            )

                expected_wall_seconds = remaining_seconds / active_count
                self.assertEqual(state["active_count"], active_count)
                self.assertAlmostEqual(
                    state["remaining_usage_seconds"],
                    remaining_seconds,
                    delta=0.001,
                )
                self.assertAlmostEqual(
                    state["estimated_wall_seconds"],
                    expected_wall_seconds,
                    delta=0.001,
                )
                with app_module._quota_watchdog_lock:
                    watchdog = dict(
                        app_module._user_quota_watchdogs[fixture["user_id"]]
                    )

                exhausted_epoch = started_epoch + expected_wall_seconds
                with mock.patch.object(
                    app_module.time,
                    "time",
                    return_value=exhausted_epoch,
                ):
                    app_module._run_user_quota_watchdog(
                        fixture["user_id"],
                        watchdog["generation"],
                        watchdog["token"],
                        watchdog["reason"],
                    )

                for account_fixture in fixtures:
                    self.assertFalse(
                        account_fixture["manager"].boost_snapshot()["boosting"]
                    )
                with app_module.app.app_context():
                    logs = BoostLog.query.filter_by(
                        user_id=fixture["user_id"]
                    ).all()
                    self.assertEqual(len(logs), active_count)
                    self.assertEqual(
                        sum(log.duration_seconds for log in logs),
                        remaining_seconds,
                    )
                    self.assertEqual(len({log.stopped_at for log in logs}), 1)
                with app_module._quota_watchdog_lock:
                    self.assertNotIn(
                        fixture["user_id"],
                        app_module._user_quota_watchdogs,
                    )

    def test_odd_microsecond_multi_account_hard_fence_never_overbills(self):
        remaining_microseconds = 10_000_001
        base_epoch = 1_787_550_000.0

        for active_count in (2, 3):
            with self.subTest(active_count=active_count):
                plan = f"micro-hard-fence-{active_count}"
                Config.PLANS[plan] = {
                    "max_accounts": 3,
                    "max_games": 4,
                    "daily_hours": None,
                    "total_hours": remaining_microseconds / 3_600_000_000,
                    "price": 0,
                    "duration_days": None,
                }
                fixture = self._fixture(plan=plan)
                fixtures = [fixture]
                fixtures.extend(
                    self._add_account(fixture)
                    for _ in range(active_count - 1)
                )
                started_epoch = base_epoch + active_count * 10_000

                with mock.patch.object(
                    app_module.time,
                    "time",
                    return_value=started_epoch,
                ):
                    for account_fixture in fixtures:
                        account_fixture["manager"].start_boost([730], 1)
                    with app_module.app.app_context():
                        with app_module._user_operation_lock(fixture["user_id"]):
                            state = app_module._reconcile_user_quota_locked(
                                fixture["user_id"],
                                "synthetic_micro_n_start",
                            )

                self.assertEqual(
                    state["remaining_usage_microseconds"],
                    remaining_microseconds,
                )
                with app_module._quota_watchdog_lock:
                    watchdog = dict(
                        app_module._user_quota_watchdogs[fixture["user_id"]]
                    )

                wall_microseconds = remaining_microseconds // active_count
                stopped_epoch = (
                    started_epoch + wall_microseconds / 1_000_000
                )
                with mock.patch.object(
                    app_module.time,
                    "time",
                    return_value=stopped_epoch,
                ):
                    app_module._run_user_quota_watchdog(
                        fixture["user_id"],
                        watchdog["generation"],
                        watchdog["token"],
                        watchdog["reason"],
                    )

                with app_module.app.app_context():
                    logs = BoostLog.query.filter_by(
                        user_id=fixture["user_id"]
                    ).all()
                    canonical_total = sum(
                        log.duration_microseconds for log in logs
                    )
                self.assertEqual(len(logs), active_count)
                self.assertLessEqual(canonical_total, remaining_microseconds)
                self.assertLess(
                    remaining_microseconds - canonical_total,
                    active_count,
                )

    def test_checkpoint_at_hard_deadline_never_ceils_past_microsecond_cap(self):
        fixture = self._fixture(plan="basic")
        started_epoch = self._future_large_epoch()
        intended_microseconds = 190_000_001 // 3
        deadline_epoch = (
            started_epoch + intended_microseconds / 1_000_000
        )

        with mock.patch.object(
            app_module.time,
            "time",
            return_value=started_epoch,
        ):
            fixture["manager"].start_boost([730], 1)
            with app_module.app.app_context():
                app_module._install_user_quota_watchdog(
                    fixture["user_id"],
                    120,
                    "total_limit",
                    deadline_epoch=deadline_epoch,
                )
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with (
            mock.patch.object(
                app_module.time,
                "time",
                return_value=deadline_epoch + 5,
            ),
            app_module.app.app_context(),
        ):
            self.assertEqual(app_module._checkpoint_active_boosts_once(), 1)
            logs = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).all()

        self.assertEqual(len(logs), 1)
        self.assertEqual(
            logs[0].duration_microseconds,
            intended_microseconds,
        )
        self.assertEqual(fixture["manager"].pending_final_segments(), [])

    def test_plan_info_exposes_usage_quota_and_estimated_multi_account_wall_time(self):
        plan = "quota-plan-info"
        Config.PLANS[plan] = {
            "max_accounts": 2,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan=plan)
        peer = self._add_account(fixture)
        fixed_epoch = time.time()
        fixed_now = app_module.utc_from_epoch(fixed_epoch)
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=fixed_now - timedelta(seconds=3000),
                stopped_at=fixed_now,
                duration_seconds=3000,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        with mock.patch.object(
            app_module.time,
            "time",
            return_value=fixed_epoch,
        ):
            fixture["manager"].start_boost([730], 1)
            peer["manager"].start_boost([730], 1)
            response = self.client.get(
                "/plan/info",
                headers=fixture["headers"],
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertEqual(payload["quota_window"], "total")
        self.assertEqual(payload["quota_active_accounts"], 2)
        self.assertAlmostEqual(payload["quota_remaining_seconds"], 600, delta=0.01)
        self.assertAlmostEqual(
            payload["quota_total_remaining_seconds"],
            600,
            delta=0.01,
        )
        self.assertIsNone(payload["quota_daily_remaining_seconds"])
        self.assertAlmostEqual(
            payload["quota_estimated_wall_seconds"],
            300,
            delta=0.01,
        )

    def test_exact_utc_midnight_stop_and_watchdog_race_writes_one_segment(self):
        for order_index, order in enumerate(("watchdog_first", "stop_first")):
            with self.subTest(order=order):
                plan = f"quota-midnight-race-{order_index}"
                Config.PLANS[plan] = {
                    "max_accounts": 1,
                    "max_games": 1,
                    "daily_hours": 1 / 60,
                    "total_hours": None,
                    "price": 0,
                    "duration_days": None,
                }
                fixture = self._fixture(plan=plan)
                midnight = datetime(
                    2032,
                    6,
                    10 + order_index,
                    tzinfo=timezone.utc,
                )
                midnight_epoch = midnight.timestamp()
                started_epoch = midnight_epoch - 60

                with mock.patch.object(
                    app_module.time,
                    "time",
                    return_value=started_epoch,
                ):
                    fixture["manager"].start_boost([730], 1)
                    with app_module.app.app_context():
                        with app_module._user_operation_lock(fixture["user_id"]):
                            state = app_module._reconcile_user_quota_locked(
                                fixture["user_id"],
                                "midnight_race_start",
                            )
                self.assertEqual(state["next_reason"], "utc_midnight")
                self.assertAlmostEqual(state["next_delay_seconds"], 60, delta=0.001)
                with app_module._quota_watchdog_lock:
                    watchdog = dict(
                        app_module._user_quota_watchdogs[fixture["user_id"]]
                    )

                gate = Event()

                def manual_stop():
                    gate.wait()
                    with app_module.app.app_context():
                        with app_module._user_operation_lock(fixture["user_id"]):
                            snapshot = fixture["manager"].boost_snapshot()
                            result = app_module._stop_boost_session_and_persist(
                                fixture["account_id"],
                                fixture["user_id"],
                                fixture["manager"],
                                expected_session_id=snapshot.get("session_id"),
                                expected_generation=snapshot.get("generation"),
                            )
                            app_module._reconcile_user_quota_locked(
                                fixture["user_id"],
                                "midnight_manual_stop",
                            )
                            return result

                def watchdog_fire():
                    gate.wait()
                    app_module._run_user_quota_watchdog(
                        fixture["user_id"],
                        watchdog["generation"],
                        watchdog["token"],
                        watchdog["reason"],
                    )

                factories = (
                    (watchdog_fire, manual_stop)
                    if order == "watchdog_first"
                    else (manual_stop, watchdog_fire)
                )
                with mock.patch.object(
                    app_module.time,
                    "time",
                    return_value=midnight_epoch,
                ):
                    jobs = [gevent.spawn(factory) for factory in factories]
                    gate.set()
                    gevent.joinall(jobs, timeout=5, raise_error=True)

                self.assertTrue(all(job.ready() for job in jobs))
                self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])
                with app_module.app.app_context():
                    logs = BoostLog.query.filter_by(
                        user_id=fixture["user_id"]
                    ).all()
                    self.assertEqual(len(logs), 1)
                    self.assertEqual(logs[0].duration_seconds, 60)
                    self.assertEqual(logs[0].stopped_at, midnight)
                with app_module._quota_watchdog_lock:
                    self.assertNotIn(
                        fixture["user_id"],
                        app_module._user_quota_watchdogs,
                    )

    def test_restart_clears_stale_runtime_without_fabricating_quota_usage(self):
        plan = "quota-restart-no-fabrication"
        Config.PLANS[plan] = {
            "max_accounts": 1,
            "max_games": 1,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        fixture = self._fixture(plan=plan)
        fixed_epoch = 2_010_000_000.0
        fixed_now = app_module.utc_from_epoch(fixed_epoch)
        with app_module.app.app_context():
            db.session.add(BoostLog(
                account_id=fixture["account_id"],
                user_id=fixture["user_id"],
                started_at=fixed_now - timedelta(seconds=400),
                stopped_at=fixed_now - timedelta(seconds=100),
                duration_seconds=300,
                games_count=1,
                app_ids_json="[730]",
            ))
            db.session.commit()

        with mock.patch.object(
            app_module.time,
            "time",
            return_value=fixed_epoch - 120,
        ):
            fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(
            fixture["account_id"],
            boosting=True,
            target=fixed_now + timedelta(hours=1),
        )
        with (
            app_module.app.app_context(),
            mock.patch.object(app_module.time, "time", return_value=fixed_epoch),
        ):
            with app_module._user_operation_lock(fixture["user_id"]):
                before = app_module._quota_usage_snapshot(fixture["user_id"])
        self.assertAlmostEqual(before["total_used_seconds"], 420, delta=0.001)

        # A real service restart loses process-local Steam runtime. The startup
        # reconciler must clear stale DB flags without inventing a final segment.
        self._clear_runtime()
        with (
            app_module.app.app_context(),
            mock.patch.object(app_module.time, "time", return_value=fixed_epoch),
        ):
            app_module._reconcile_boost_state_on_startup()
            with app_module._user_operation_lock(fixture["user_id"]):
                after = app_module._quota_usage_snapshot(fixture["user_id"])
            account = db.session.get(SteamAccount, fixture["account_id"])
            logs = BoostLog.query.filter_by(user_id=fixture["user_id"]).all()

        self.assertFalse(account.is_boosting)
        self.assertIsNone(account.target_stop_time)
        self.assertEqual(len(logs), 1)
        self.assertEqual(sum(log.duration_seconds for log in logs), 300)
        self.assertEqual(after["active_count"], 0)
        self.assertAlmostEqual(after["total_used_seconds"], 300, delta=0.001)
        self.assertAlmostEqual(after["total_remaining_seconds"], 3300, delta=0.001)

    def test_account_delete_replaces_watchdog_and_old_callback_cannot_stop_peer(self):
        fixture = self._fixture(plan="basic")
        peer = self._add_account(fixture)
        fixture["manager"].start_boost([730], 1)
        peer["manager"].start_boost([730], 1)
        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                app_module._reconcile_user_quota_locked(
                    fixture["user_id"],
                    "delete_stale_watchdog_start",
                )
        with app_module._quota_watchdog_lock:
            old_watchdog = dict(
                app_module._user_quota_watchdogs[fixture["user_id"]]
            )

        response = self.client.post(
            "/accounts/remove",
            json={"acct_id": fixture["account_id"]},
            headers=fixture["headers"],
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        with app_module._quota_watchdog_lock:
            current = dict(app_module._user_quota_watchdogs[fixture["user_id"]])
        self.assertGreater(current["generation"], old_watchdog["generation"])

        app_module._run_user_quota_watchdog(
            fixture["user_id"],
            old_watchdog["generation"],
            old_watchdog["token"],
            old_watchdog["reason"],
        )

        self.assertTrue(peer["manager"].boost_snapshot()["boosting"])
        with app_module._quota_watchdog_lock:
            still_current = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertEqual(still_current["generation"], current["generation"])
            self.assertEqual(still_current["token"], current["token"])

    def test_fatal_disconnect_replaces_watchdog_and_old_callback_cannot_stop_peer(self):
        fixture = self._fixture(plan="basic")
        peer = self._add_account(fixture)
        disconnected = fixture["manager"].start_boost([730], 1)
        peer["manager"].start_boost([730], 1)
        disconnected_started = self._age_active_segment(fixture["manager"], 30)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        self._set_db_boost_state(peer["account_id"], boosting=True)
        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                app_module._reconcile_user_quota_locked(
                    fixture["user_id"],
                    "disconnect_stale_watchdog_start",
                )
        with app_module._quota_watchdog_lock:
            old_watchdog = dict(
                app_module._user_quota_watchdogs[fixture["user_id"]]
            )

        app_module._handle_fatal_disconnect(
            fixture["account_id"],
            30,
            disconnected["session_id"],
            disconnected["generation"],
            disconnected_started,
            [730],
            disconnected_started + 30,
        )
        with app_module._quota_watchdog_lock:
            current = dict(app_module._user_quota_watchdogs[fixture["user_id"]])
        self.assertGreater(current["generation"], old_watchdog["generation"])

        app_module._run_user_quota_watchdog(
            fixture["user_id"],
            old_watchdog["generation"],
            old_watchdog["token"],
            old_watchdog["reason"],
        )

        self.assertTrue(peer["manager"].boost_snapshot()["boosting"])
        with app_module._quota_watchdog_lock:
            still_current = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertEqual(still_current["generation"], current["generation"])
            self.assertEqual(still_current["token"], current["token"])
        with app_module.app.app_context():
            logs = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).all()
            self.assertEqual(len(logs), 1)

    def test_clear_timers_does_not_deadlock_on_user_lock_in_cancelled_timer_finally(self):
        fixture = self._fixture(plan="basic")
        timer_started = Event()
        finalizer_started = Event()
        finalizer_finished = Event()
        clear_returned = Event()
        park_timer = Event()

        def timer_body():
            try:
                timer_started.set()
                park_timer.wait()
            finally:
                finalizer_started.set()
                with app_module._user_operation_lock(fixture["user_id"]):
                    finalizer_finished.set()

        timer = gevent.spawn(timer_body)
        self.assertTrue(timer_started.wait(timeout=1))
        app_module._add_timer(fixture["account_id"], timer)

        def clear_while_holding_user_lock():
            with app_module._user_operation_lock(fixture["user_id"]):
                app_module._clear_timers(fixture["account_id"])
                clear_returned.set()

        clearer = gevent.spawn(clear_while_holding_user_lock)
        clearer.join(timeout=1)
        if not clearer.ready():
            # Keep a future regression from wedging the entire test process.
            clearer.kill(block=False)
            gevent.sleep(0)
            timer.kill(block=False)
            gevent.joinall([clearer, timer], timeout=1)
            self.fail("_clear_timers blocked while the timer finalizer waited for user lock")

        self.assertIsNone(clearer.exception)
        self.assertTrue(clear_returned.is_set())
        self.assertTrue(finalizer_started.wait(timeout=1))
        timer.join(timeout=1)
        self.assertTrue(timer.ready())
        self.assertTrue(finalizer_finished.is_set())
        with app_module._timer_lock:
            self.assertNotIn(fixture["account_id"], app_module._active_timers)

    def test_emergency_quota_cutoff_persists_before_worker_termination(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        boundary_epoch = time.time()
        with manager.state_lock:
            manager.start_time = boundary_epoch - 60
            manager.original_start_time = boundary_epoch - 60

        original_force_disconnect = fixture["client"].force_disconnect

        def assert_durable_then_disconnect():
            segments = manager.pending_final_segments()
            self.assertEqual(len(segments), 1)
            self.assertFalse(segments[0]["remote_stop_confirmed"])
            pending_path = steam_manager._pending_final_segments_path(
                fixture["account_id"]
            )
            self.assertTrue(os.path.isfile(pending_path))
            with open(pending_path, "r", encoding="utf-8") as handle:
                on_disk = app_module.json.load(handle)
            self.assertEqual(len(on_disk), 1)
            self.assertFalse(on_disk[0]["remote_stop_confirmed"])
            return original_force_disconnect()

        with mock.patch.object(
            fixture["client"],
            "force_disconnect",
            side_effect=assert_durable_then_disconnect,
        ):
            result = manager.emergency_quota_cutoff(
                boundary_epoch,
                "durability-fence",
                reason="test",
            )

        self.assertTrue(result["durable"])
        self.assertTrue(result["remote_stop_confirmed"])
        self.assertIsNotNone(result["segment"]["remote_stopped_at"])
        manager.release_quota_fence("durability-fence")

    def test_emergency_confirmation_save_failure_stays_unconfirmed(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        boundary_epoch = time.time()
        original_save = manager._save_pending_final_segments_unlocked
        save_calls = 0

        def fail_confirmation_save():
            nonlocal save_calls
            save_calls += 1
            if save_calls == 2:
                return False
            return original_save()

        with mock.patch.object(
            manager,
            "_save_pending_final_segments_unlocked",
            side_effect=fail_confirmation_save,
        ):
            result = manager.emergency_quota_cutoff(
                boundary_epoch,
                "undurable-confirmation-fence",
                reason="test",
            )

        self.assertFalse(result["remote_stop_confirmed"])
        pending = manager.pending_final_segments()
        self.assertEqual(len(pending), 1)
        self.assertFalse(pending[0]["remote_stop_confirmed"])
        self.assertIsNone(pending[0]["remote_stopped_at"])
        manager.release_quota_fence("undurable-confirmation-fence")

    def test_idle_manager_is_fenced_without_disconnect(self):
        fixture = self._fixture(plan="basic")
        result = fixture["manager"].emergency_quota_cutoff(
            time.time(),
            "idle-fence",
            reason="test",
        )

        self.assertFalse(result["force_required"])
        self.assertTrue(result["remote_stop_confirmed"])
        self.assertEqual(fixture["client"].force_disconnect_calls, 0)
        self.assertTrue(fixture["client"].connected)
        fixture["manager"].release_quota_fence("idle-fence")

    def test_duplicate_final_persist_backfills_remote_cutoff_without_new_log(self):
        fixture = self._fixture(plan="basic")
        stopped_epoch = time.time()
        started_epoch = stopped_epoch - 60
        remote_epoch = stopped_epoch + 0.25
        with app_module.app.app_context():
            self.assertTrue(app_module._persist_stopped_boost_state(
                fixture["account_id"],
                fixture["user_id"],
                started_epoch=started_epoch,
                stopped_epoch=stopped_epoch,
                duration_seconds=60,
                app_ids=[730],
            ))
            self.assertTrue(app_module._persist_stopped_boost_state(
                fixture["account_id"],
                fixture["user_id"],
                started_epoch=started_epoch,
                stopped_epoch=stopped_epoch,
                remote_stopped_epoch=remote_epoch,
                duration_seconds=60,
                app_ids=[730],
            ))
            logs = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).all()

        self.assertEqual(len(logs), 1)
        self.assertEqual(
            logs[0].stopped_at,
            app_module.utc_from_epoch(stopped_epoch),
        )
        self.assertEqual(
            logs[0].remote_stopped_at,
            app_module.utc_from_epoch(remote_epoch),
        )

    def test_exact_deadline_session_stop_uses_hard_cap_floor(self):
        fixture = self._fixture(plan="basic")
        started_epoch = self._future_large_epoch()
        intended_microseconds = 190_000_001 // 3
        deadline_epoch = (
            started_epoch + intended_microseconds / 1_000_000
        )
        with mock.patch.object(
            app_module.time,
            "time",
            return_value=started_epoch,
        ):
            fixture["manager"].start_boost([730], 1)
            with app_module.app.app_context():
                app_module._install_user_quota_watchdog(
                    fixture["user_id"],
                    120,
                    "total_limit",
                    deadline_epoch=deadline_epoch,
                )
        self._set_db_boost_state(fixture["account_id"], boosting=True)

        with (
            mock.patch.object(
                app_module.time,
                "time",
                return_value=deadline_epoch,
            ),
            app_module.app.app_context(),
        ):
            result = app_module._stop_boost_session_and_persist(
                fixture["account_id"],
                fixture["user_id"],
                fixture["manager"],
            )
            log = BoostLog.query.one()

        self.assertTrue(result["persisted"])
        self.assertEqual(log.duration_microseconds, intended_microseconds)

    def test_managerless_exact_deadline_segment_uses_hard_cap_floor(self):
        fixture = self._fixture(plan="basic")
        started_epoch = 1_787_550_000.0
        intended_microseconds = 190_000_001 // 3
        stopped_epoch = (
            started_epoch + intended_microseconds / 1_000_000
        )
        observed_elapsed = stopped_epoch - started_epoch
        with (
            mock.patch.object(
                app_module.time,
                "time",
                return_value=started_epoch,
            ),
            app_module.app.app_context(),
        ):
            app_module._install_user_quota_watchdog(
                fixture["user_id"],
                120,
                "total_limit",
                deadline_epoch=stopped_epoch,
            )
            segment = {
                "started_at": started_epoch,
                "stopped_at": stopped_epoch,
                "elapsed": observed_elapsed,
                "elapsed_microseconds": intended_microseconds + 1,
                "app_ids": [730],
                "remote_stop_confirmed": True,
                "remote_stopped_at": stopped_epoch,
            }
            self.assertTrue(app_module._persist_manager_final_segment(
                fixture["account_id"],
                fixture["user_id"],
                None,
                segment,
            ))
            log = BoostLog.query.one()

        self.assertEqual(log.duration_microseconds, intended_microseconds)

    def test_zero_length_hard_fence_backfills_exact_checkpoint_boundary(self):
        fixture = self._fixture(plan="basic")
        boundary_epoch = 2_060_000_000.0
        remote_epoch = boundary_epoch + 0.25
        with app_module.app.app_context():
            self.assertTrue(app_module._persist_stopped_boost_state(
                fixture["account_id"],
                fixture["user_id"],
                started_epoch=boundary_epoch - 120,
                stopped_epoch=boundary_epoch,
                duration_seconds=120,
                app_ids=[730],
                clear_account_state=False,
            ))
            self.assertTrue(app_module._persist_stopped_boost_state(
                fixture["account_id"],
                fixture["user_id"],
                started_epoch=boundary_epoch,
                stopped_epoch=boundary_epoch,
                remote_stopped_epoch=remote_epoch,
                duration_seconds=0,
                app_ids=[730],
            ))
            logs = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).all()

        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].duration_seconds, 120)
        self.assertEqual(
            logs[0].remote_stopped_at,
            app_module.utc_from_epoch(remote_epoch),
        )

    def test_released_fence_serial_rejects_late_start_response(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        entered_ipc = Event()
        release_ipc = Event()
        original_games_played = fixture["client"].games_played

        def blocking_games_played(app_ids):
            entered_ipc.set()
            release_ipc.wait(timeout=5)
            return original_games_played(app_ids)

        def late_start():
            try:
                return manager.start_boost([730], 1)
            except Exception as exc:
                return exc

        with mock.patch.object(
            fixture["client"],
            "games_played",
            side_effect=blocking_games_played,
        ):
            start_job = gevent.spawn(late_start)
            self.assertTrue(entered_ipc.wait(timeout=2))
            cutoff = manager.emergency_quota_cutoff(
                time.time(),
                "released-serial-fence",
                reason="test",
            )
            self.assertTrue(cutoff["inflight"])
            self.assertTrue(
                manager.release_quota_fence("released-serial-fence")
            )
            release_ipc.set()
            start_job.join(timeout=5)

        self.assertTrue(start_job.ready())
        self.assertIsNone(start_job.exception)
        self.assertIsInstance(start_job.value, steam_manager.QuotaFenceActiveError)
        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertEqual(fixture["client"].force_disconnect_calls, 1)

    def test_released_fence_keeps_old_session_from_resuming(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        started = manager.start_boost([730], 1)
        entered_ipc = Event()
        release_ipc = Event()
        original_games_played = fixture["client"].games_played

        def blocking_games_played(app_ids):
            entered_ipc.set()
            release_ipc.wait(timeout=5)
            return original_games_played(app_ids)

        with mock.patch.object(
            fixture["client"],
            "games_played",
            side_effect=blocking_games_played,
        ):
            resume_job = gevent.spawn(
                manager._resume_boost,
                started["generation"],
            )
            self.assertTrue(entered_ipc.wait(timeout=2))
            boundary_epoch = time.time()
            cutoff = manager.emergency_quota_cutoff(
                boundary_epoch,
                "released-resume-fence",
                reason="test",
            )
            self.assertTrue(cutoff["active"])
            self.assertTrue(cutoff["inflight"])
            manager.release_quota_fence("released-resume-fence")
            release_ipc.set()
            resume_job.join(timeout=5)

        self.assertTrue(resume_job.ready())
        self.assertIsNone(resume_job.exception)
        self.assertFalse(resume_job.value)
        self.assertEqual(fixture["client"].force_disconnect_calls, 1)
        # Emergency does not mutate state without state_lock. The persistent
        # fenced-session key prevents a late resume until normal convergence.
        self.assertTrue(manager.boost_snapshot()["boosting"])
        segment = manager.prepare_stop_boost_segment(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
            stopped_at=boundary_epoch,
            context="test cleanup",
        )
        confirmed = manager.confirm_prepared_stop_segment(
            segment,
            context="test cleanup",
        )
        self.assertTrue(confirmed["remote_stop_confirmed"])
        self.assertFalse(manager.boost_snapshot()["boosting"])

    def test_hard_watchdog_cuts_worker_and_persists_while_state_lock_is_held(self):
        fixture = self._fixture(plan="basic")
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        boundary_epoch = time.time()
        with manager.state_lock:
            manager.start_time = boundary_epoch - 60
            manager.original_start_time = boundary_epoch - 60
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            app_module._install_user_quota_watchdog(
                fixture["user_id"],
                3600,
                "total_limit",
            )

        lock_held = Event()
        release_lock = Event()

        def hold_manager_state_lock():
            with manager.state_lock:
                lock_held.set()
                release_lock.wait(timeout=5)

        holder = gevent.spawn(hold_manager_state_lock)
        self.assertTrue(lock_held.wait(timeout=2))
        watchdog_job, _watchdog = self._fire_current_quota_watchdog(
            fixture["user_id"],
            deadline_epoch=boundary_epoch,
        )
        try:
            cutoff_deadline = time.time() + 2
            while (
                fixture["client"].force_disconnect_calls < 1
                and time.time() < cutoff_deadline
            ):
                gevent.sleep(0.01)

            self.assertEqual(fixture["client"].force_disconnect_calls, 1)
            self.assertFalse(fixture["client"].connected)
            pending = manager.pending_final_segments()
            self.assertEqual(len(pending), 1)
            self.assertTrue(pending[0]["remote_stop_confirmed"])
            self.assertIsNotNone(pending[0]["remote_stopped_at"])
            self.assertFalse(watchdog_job.ready())
        finally:
            release_lock.set()
            gevent.joinall([holder, watchdog_job], timeout=5)

        self.assertTrue(holder.ready())
        self.assertTrue(watchdog_job.ready())
        self.assertIsNone(watchdog_job.exception)
        with manager._quota_fence_lock:
            self.assertEqual(manager._active_quota_fences, set())
        with app_module.app.app_context():
            log = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).one()
            self.assertEqual(
                log.stopped_at,
                app_module.utc_from_epoch(boundary_epoch),
            )
            self.assertIsNotNone(log.remote_stopped_at)
            self.assertGreaterEqual(log.remote_stopped_at, log.stopped_at)

    def test_hard_quota_fence_stops_peer_while_start_holds_user_and_state_locks(self):
        Config.PLANS["quota-hard-fence-peer"] = {
            "max_accounts": 2,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        peer = self._fixture(plan="quota-hard-fence-peer")
        inflight = self._add_account(peer)
        peer["manager"].start_boost([730], 1)
        self._set_db_boost_state(peer["account_id"], boosting=True)

        entered_ipc = Event()
        release_ipc = Event()
        original_games_played = inflight["client"].games_played

        def blocking_games_played(app_ids):
            entered_ipc.set()
            release_ipc.wait(timeout=5)
            return original_games_played(app_ids)

        def start_inflight_account():
            with app_module.app.test_client() as client:
                return client.post(
                    "/boost/toggle",
                    json={"acct_id": inflight["account_id"], "action": "start"},
                    headers=peer["headers"],
                )

        watchdog_job = None
        with mock.patch.object(
            inflight["client"],
            "games_played",
            side_effect=blocking_games_played,
        ):
            start_job = gevent.spawn(start_inflight_account)
            try:
                self.assertTrue(entered_ipc.wait(timeout=2))
                boundary_epoch = time.time()
                with peer["manager"].state_lock:
                    # Simulate the already scheduled quota time elapsing while
                    # the second account is blocked in Steam IPC.
                    peer["manager"].start_time = boundary_epoch - 3600
                    peer["manager"].original_start_time = boundary_epoch - 3600
                watchdog_job, _watchdog = self._fire_current_quota_watchdog(
                    peer["user_id"],
                    deadline_epoch=boundary_epoch,
                )

                stop_wait_deadline = time.time() + 2
                while (
                    peer["manager"].boost_snapshot()["boosting"]
                    and time.time() < stop_wait_deadline
                ):
                    gevent.sleep(0.01)

                self.assertFalse(peer["manager"].boost_snapshot()["boosting"])
                self.assertFalse(start_job.ready())
                self.assertFalse(watchdog_job.ready())
                self.assertEqual(inflight["client"].force_disconnect_calls, 1)
                self.assertFalse(inflight["client"].connected)
            finally:
                release_ipc.set()
                jobs = [start_job]
                if watchdog_job is not None:
                    jobs.append(watchdog_job)
                gevent.joinall(jobs, timeout=5)

        self.assertTrue(start_job.ready())
        self.assertIsNone(start_job.exception)
        self.assertIsNotNone(watchdog_job)
        self.assertTrue(watchdog_job.ready())
        self.assertIsNone(watchdog_job.exception)
        with app_module.app.app_context():
            peer_log = BoostLog.query.filter_by(
                user_id=peer["user_id"],
                account_id=peer["account_id"],
            ).one()
            self.assertEqual(
                peer_log.stopped_at,
                app_module.utc_from_epoch(boundary_epoch),
            )

    def test_inflight_start_crossing_hard_quota_fence_cannot_return_success(self):
        Config.PLANS["quota-hard-fence-start-response"] = {
            "max_accounts": 2,
            "max_games": 4,
            "daily_hours": None,
            "total_hours": 1,
            "price": 0,
            "duration_days": None,
        }
        peer = self._fixture(plan="quota-hard-fence-start-response")
        inflight = self._add_account(peer)
        peer["manager"].start_boost([730], 1)
        self._set_db_boost_state(peer["account_id"], boosting=True)

        entered_ipc = Event()
        release_ipc = Event()
        original_games_played = inflight["client"].games_played

        def blocking_games_played(app_ids):
            entered_ipc.set()
            release_ipc.wait(timeout=5)
            return original_games_played(app_ids)

        def start_inflight_account():
            with app_module.app.test_client() as client:
                return client.post(
                    "/boost/toggle",
                    json={"acct_id": inflight["account_id"], "action": "start"},
                    headers=peer["headers"],
                )

        watchdog_job = None
        with mock.patch.object(
            inflight["client"],
            "games_played",
            side_effect=blocking_games_played,
        ):
            start_job = gevent.spawn(start_inflight_account)
            try:
                self.assertTrue(entered_ipc.wait(timeout=2))
                boundary_epoch = time.time()
                with peer["manager"].state_lock:
                    peer["manager"].start_time = boundary_epoch - 3600
                    peer["manager"].original_start_time = boundary_epoch - 3600
                watchdog_job, _watchdog = self._fire_current_quota_watchdog(
                    peer["user_id"],
                    deadline_epoch=boundary_epoch,
                )

                stop_wait_deadline = time.time() + 2
                while (
                    peer["manager"].boost_snapshot()["boosting"]
                    and time.time() < stop_wait_deadline
                ):
                    gevent.sleep(0.01)
                self.assertFalse(peer["manager"].boost_snapshot()["boosting"])
                self.assertEqual(inflight["client"].force_disconnect_calls, 1)
                self.assertFalse(inflight["client"].connected)
            finally:
                release_ipc.set()
                jobs = [start_job]
                if watchdog_job is not None:
                    jobs.append(watchdog_job)
                gevent.joinall(jobs, timeout=5)

        self.assertTrue(start_job.ready())
        self.assertIsNone(start_job.exception)
        response = start_job.value
        self.assertEqual(response.status_code, 409, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["boosting"])
        self.assertIn("expired while Steam was responding", payload["error"])
        self.assertFalse(inflight["manager"].boost_snapshot()["boosting"])
        self.assertTrue(watchdog_job.ready())
        self.assertIsNone(watchdog_job.exception)
        with app_module.app.app_context():
            logs = BoostLog.query.filter_by(user_id=peer["user_id"]).all()
            self.assertLessEqual(
                sum(log.duration_seconds for log in logs),
                3600,
            )
            self.assertTrue(
                all(
                    log.stopped_at
                    <= app_module.utc_from_epoch(boundary_epoch)
                    for log in logs
                )
            )

    def test_plan_upgrade_cancel_wins_over_early_watchdog_rearm(self):
        fixture = self._fixture(plan="basic")
        fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                app_module._reconcile_user_quota_locked(
                    fixture["user_id"],
                    "early_rearm_upgrade_setup",
                )
        with app_module._quota_watchdog_lock:
            old_watchdog = dict(
                app_module._user_quota_watchdogs[fixture["user_id"]]
            )

        rearm_entered = Event()
        allow_rearm = Event()
        original_install = app_module._install_user_quota_watchdog

        def gated_install(*args, **kwargs):
            if kwargs.get("expected_generation") == old_watchdog["generation"]:
                rearm_entered.set()
                allow_rearm.wait(timeout=2)
            return original_install(*args, **kwargs)

        callback_job = None
        with mock.patch.object(
            app_module,
            "_install_user_quota_watchdog",
            side_effect=gated_install,
        ):
            callback_job, _watchdog = self._fire_current_quota_watchdog(
                fixture["user_id"]
            )
            try:
                self.assertTrue(rearm_entered.wait(timeout=2))
                # Post-commit reconciliation must swap generation/token so the
                # stale early callback cannot rearm itself afterward.
                with mock.patch.object(
                    app_module,
                    "_kill_greenlet_nonblocking",
                    return_value=None,
                ):
                    with app_module.app.app_context():
                        with app_module._user_operation_lock(fixture["user_id"]):
                            user = db.session.get(User, fixture["user_id"])
                            app_module._activate_plan(
                                user,
                                "premium",
                                reset_usage_window=True,
                            )
                            db.session.commit()
                            app_module._reconcile_user_quota_locked(
                                fixture["user_id"],
                                "early_rearm_upgrade_committed",
                            )
            finally:
                allow_rearm.set()
                if callback_job is not None:
                    callback_job.join(timeout=5)

        self.assertTrue(callback_job.ready())
        self.assertIsNone(callback_job.exception)
        self.assertTrue(fixture["manager"].boost_snapshot()["boosting"])
        with app_module._quota_watchdog_lock:
            current = app_module._user_quota_watchdogs[fixture["user_id"]]
            self.assertGreater(current["generation"], old_watchdog["generation"])
            self.assertNotEqual(current["token"], old_watchdog["token"])
        with app_module.app.app_context():
            self.assertEqual(
                db.session.get(User, fixture["user_id"]).plan,
                "premium",
            )

    def test_claimed_hard_quota_fence_wins_if_plan_upgrade_races_after_claim(self):
        fixture = self._fixture(plan="basic")
        fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                app_module._reconcile_user_quota_locked(
                    fixture["user_id"],
                    "claimed_upgrade_setup",
                )

        claim_observed = Event()
        allow_preemption = Event()
        original_preempt = app_module._preempt_user_quota_hard_fence

        def gated_preempt(user_id, fence):
            claim_observed.set()
            allow_preemption.wait(timeout=5)
            return original_preempt(user_id, fence)

        callback_job = None
        boundary_epoch = time.time()
        with mock.patch.object(
            app_module,
            "_preempt_user_quota_hard_fence",
            side_effect=gated_preempt,
        ):
            callback_job, old_watchdog = self._fire_current_quota_watchdog(
                fixture["user_id"],
                deadline_epoch=boundary_epoch,
            )
            try:
                self.assertTrue(claim_observed.wait(timeout=2))
                self.assertIsNotNone(
                    app_module._active_user_quota_hard_fence(fixture["user_id"])
                )
                with app_module.app.app_context():
                    with app_module._user_operation_lock(fixture["user_id"]):
                        user = db.session.get(User, fixture["user_id"])
                        app_module._activate_plan(
                            user,
                            "premium",
                            reset_usage_window=True,
                        )
                        db.session.commit()
                with app_module._quota_watchdog_lock:
                    claimed = app_module._user_quota_watchdogs[
                        fixture["user_id"]
                    ]
                    self.assertTrue(claimed.get("cutoff_claimed"))
            finally:
                allow_preemption.set()
                if callback_job is not None:
                    callback_job.join(timeout=5)

        self.assertTrue(callback_job.ready())
        self.assertIsNone(callback_job.exception)
        self.assertFalse(fixture["manager"].boost_snapshot()["boosting"])
        self.assertIsNone(
            app_module._active_user_quota_hard_fence(fixture["user_id"])
        )
        with app_module.app.app_context():
            self.assertEqual(
                db.session.get(User, fixture["user_id"]).plan,
                "premium",
            )
            log = BoostLog.query.filter_by(
                user_id=fixture["user_id"],
                account_id=fixture["account_id"],
            ).one()
            self.assertEqual(
                log.stopped_at,
                app_module.utc_from_epoch(old_watchdog["deadline_epoch"]),
            )

    def test_preemption_exception_releases_every_published_manager_fence(self):
        fixture = self._fixture(plan="basic")
        fixture["manager"].start_boost([730], 1)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                app_module._reconcile_user_quota_locked(
                    fixture["user_id"],
                    "preemption_exception_setup",
                )

        original_clear_timers = app_module._clear_timers
        calls = {"count": 0}

        def fail_first_clear(account_id):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("injected post-fence cleanup failure")
            return original_clear_timers(account_id)

        boundary_epoch = time.time()
        with mock.patch.object(
            app_module,
            "_clear_timers",
            side_effect=fail_first_clear,
        ):
            callback_job, watchdog = self._fire_current_quota_watchdog(
                fixture["user_id"],
                deadline_epoch=boundary_epoch,
            )
            callback_job.join(timeout=5)

        self.assertTrue(callback_job.ready())
        self.assertIsNone(callback_job.exception)
        self.assertGreaterEqual(calls["count"], 1)
        self.assertIsNone(
            app_module._active_user_quota_hard_fence(fixture["user_id"])
        )
        with fixture["manager"]._quota_fence_lock:
            self.assertNotIn(
                watchdog["token"],
                fixture["manager"]._active_quota_fences,
            )

    def test_user_operation_lock_entries_are_released_after_waiters(self):
        user_id = 900001
        entered = Event()
        release = Event()

        def waiter():
            entered.set()
            with app_module._user_operation_lock(user_id):
                release.wait()

        with app_module._user_operation_lock(user_id):
            job = gevent.spawn(waiter)
            entered.wait(timeout=1)
            gevent.sleep(0)
            with app_module._user_operation_locks_guard:
                entry = app_module._user_operation_locks.get(user_id)
                self.assertIsNotNone(entry)
                self.assertEqual(entry.references, 2)
        release.set()
        job.join(timeout=2)
        self.assertIsNone(job.exception)
        with app_module._user_operation_locks_guard:
            self.assertNotIn(user_id, app_module._user_operation_locks)

    def test_admin_user_delete_finalizes_active_runtime_before_deletion(self):
        fixture = self._fixture()
        manager = fixture["manager"]
        manager.start_boost([730], 1)
        self._age_active_segment(manager, 120)
        self._set_db_boost_state(fixture["account_id"], boosting=True)
        with app_module.app.app_context():
            with app_module._user_operation_lock(fixture["user_id"]):
                app_module._install_user_quota_watchdog(
                    fixture["user_id"], 3600, "test_user_delete"
                )

        with app_module.app.app_context():
            admin = User(
                username="boost-delete-admin",
                email="boost-delete-admin@example.test",
                password_hash="unused",
                is_verified=True,
                is_admin=True,
            )
            db.session.add(admin)
            db.session.commit()
            admin_id = admin.id
            token = app_module.generate_api_token(admin_id)
        with app_module.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "198.51.100.121"}
        ):
            self.assertIsNotNone(
                app_module._create_session_record(admin_id, token)
            )

        with mock.patch.object(
            app_module,
            "_stop_boost_session_and_persist",
            wraps=app_module._stop_boost_session_and_persist,
        ) as finalize:
            response = self.client.post(
                "/admin/users/delete",
                json={"user_id": fixture["user_id"]},
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        finalize.assert_called_once()
        self.assertEqual(fixture["client"].stop_calls, 1)
        self.assertTrue(manager.client._closed)
        with app_module._quota_watchdog_lock:
            self.assertNotIn(
                fixture["user_id"], app_module._user_quota_watchdogs
            )
        with app_module.app.app_context():
            self.assertIsNone(db.session.get(User, fixture["user_id"]))
            self.assertIsNone(db.session.get(SteamAccount, fixture["account_id"]))


if __name__ == "__main__":
    unittest.main()
