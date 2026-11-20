import hashlib
import hmac
import json
import os
import atexit
import sqlite3
from pathlib import Path
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
import unittest
from unittest import mock

from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError, SQLAlchemyError


_TEMP_DIR = tempfile.mkdtemp(prefix="hourboost-payment-tests-")
atexit.register(lambda: shutil.rmtree(_TEMP_DIR, ignore_errors=True))
_DB_PATH = Path(_TEMP_DIR, "payment-tests.db").as_posix()
os.environ["SECRET_KEY"] = "test-secret-key-" + "x" * 48
os.environ["DATABASE_URL"] = "sqlite:///" + _DB_PATH
os.environ["DB_SCHEMA_MODE"] = "alembic"
os.environ["STEAM_STATE_DIR"] = _TEMP_DIR
os.environ["SHOPIER_API_VERIFY_ENABLED"] = "false"
os.environ["SHOPIER_VERIFICATION_WORKER_ENABLED"] = "false"
os.environ["SHOPIER_WEBHOOK_SECRET"] = "test-webhook-secret"
os.environ["SHOPIER_ACCOUNT_ID"] = "account-1"
os.environ["SHOPIER_WEBHOOK_ID"] = "subscription-1"
os.environ["SHOPIER_BASIC_PRODUCT_ID"] = "basic-id"
os.environ["SHOPIER_PREMIUM_PRODUCT_ID"] = "premium-id"
os.environ["MAX_CONTENT_LENGTH_BYTES"] = str(512 * 1024)

from schema_fixture import (
    initialize_test_database, repair_legacy_fixture, reset_test_schema,
)

initialize_test_database(_DB_PATH)

import app as app_module
from config import Config
from models import (
    db,
    BoostGame,
    BoostLog,
    Announcement,
    Payment,
    PaymentAuditLog,
    RevokedToken,
    SteamAccount,
    User,
    UserSession,
)
import shopier


TOKEN = "HB-" + "A" * 32


def order_payload(order_id="order-1", token=TOKEN, product_id="basic-id"):
    price = "29.99" if product_id == "basic-id" else "59.99"
    return {
        "id": order_id,
        "paymentStatus": "paid",
        "currency": "TRY",
        "note": f"HourBoost {token}",
        "lineItems": [{
            "productId": product_id,
            "quantity": 1,
            "price": price,
            "total": price,
        }],
        "totals": {
            "subtotal": price,
            "shipping": "0.00",
            "discount": "0.00",
            "total": price,
        },
        "discounts": [],
    }


class PaymentIntegrationTests(unittest.TestCase):
    def setUp(self):
        Config.SHOPIER_API_VERIFY_ENABLED = True
        # Worker import sırasında kapalıydı; route için aktif görünür, fakat
        # testte yalnızca deterministik one-shot worker çağrılır.
        Config.SHOPIER_VERIFICATION_WORKER_ENABLED = True
        Config.SHOPIER_WEBHOOK_SECRET = "test-webhook-secret"
        Config.SHOPIER_ACCOUNT_ID = "account-1"
        Config.SHOPIER_WEBHOOK_ID = "subscription-1"
        Config.SHOPIER_PAT = "test-pat"
        Config.SHOPIER_BASIC_PRODUCT_ID = "basic-id"
        Config.SHOPIER_PREMIUM_PRODUCT_ID = "premium-id"
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        with app_module.app.app_context():
            reset_test_schema(app_module)
        app_module._plan_expiry_cache.clear()
        app_module._payment_verification_wakeup.clear()
        app_module.steam_profile_resolver.clear()
        self.client = app_module.app.test_client()

    def _insert_legacy_payment_with_missing_owner(self, **values):
        """Seed a pre-enforcement orphan without weakening app connections."""

        normalized = {
            key: (
                value.isoformat(sep=" ")
                if isinstance(value, datetime)
                else value
            )
            for key, value in values.items()
        }
        columns = list(normalized)
        placeholders = ", ".join("?" for _ in columns)
        with app_module.app.app_context():
            db.session.remove()
            database_path = db.engine.url.database
        raw = sqlite3.connect(database_path)
        try:
            self.assertEqual(
                raw.execute("PRAGMA foreign_keys").fetchone()[0],
                0,
            )
            cursor = raw.execute(
                f"INSERT INTO payments ({', '.join(columns)}) "
                f"VALUES ({placeholders})",
                [normalized[column] for column in columns],
            )
            raw.commit()
            return cursor.lastrowid
        finally:
            raw.close()

    def _create_checkout(self, token=TOKEN, plan="basic", user_plan="free", age_hours=0):
        with app_module.app.app_context():
            user = User(
                username=f"user-{token[-6:]}",
                email=f"{token[-6:].lower()}@example.test",
                password_hash="unused",
                plan=user_plan,
                is_verified=True,
            )
            db.session.add(user)
            db.session.flush()
            payment = Payment(
                user_id=user.id,
                amount=Config.PLANS[plan]["price"],
                plan=plan,
                status="checkout_started",
                match_token=token,
                created_at=datetime.utcnow() - timedelta(hours=age_hours),
            )
            db.session.add(payment)
            db.session.commit()
            return user.id, payment.id

    def _post_webhook(self, payload, **header_overrides):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        signature = hmac.new(
            Config.SHOPIER_WEBHOOK_SECRET.encode(), raw, hashlib.sha256
        ).hexdigest()
        headers = {
            "Shopier-Signature": signature,
            "Shopier-Event": "order.created",
            "Shopier-Webhook-Id": "subscription-1",
            "Shopier-Account-Id": "account-1",
            "Shopier-Timestamp": str(int(datetime.utcnow().timestamp())),
            "Content-Type": "application/json",
        }
        headers.update(header_overrides)
        return self.client.post("/shopier/webhook", data=raw, headers=headers)

    def _tracked_bearer(self, username, *, is_admin):
        with app_module.app.app_context():
            user = User(
                username=username,
                email=f"{username}@example.test",
                password_hash="unused",
                is_admin=is_admin,
                is_verified=True,
            )
            db.session.add(user)
            db.session.commit()
            user_id = user.id
            token = app_module.generate_api_token(user_id)
        with app_module.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "198.51.100.90"}
        ):
            self.assertIsNotNone(
                app_module._create_session_record(user_id, token)
            )
        app_module._plan_expiry_cache[user_id] = app_module.time.time()
        return user_id, {"Authorization": f"Bearer {token}"}

    def test_all_json_instant_fields_emit_canonical_utc_z(self):
        user_id, user_headers = self._tracked_bearer(
            "time-contract-user",
            is_admin=False,
        )
        admin_id, admin_headers = self._tracked_bearer(
            "time-contract-admin",
            is_admin=True,
        )
        source_time = datetime(
            2025,
            1,
            2,
            3,
            4,
            5,
            678901,
            tzinfo=timezone(timedelta(hours=3)),
        )
        plan_expiry = datetime(
            2027,
            1,
            2,
            3,
            4,
            5,
            678901,
            tzinfo=timezone(timedelta(hours=3)),
        )

        with app_module.app.app_context():
            user = db.session.get(User, user_id)
            user.plan = "basic"
            user.plan_activated_at = source_time
            user.plan_expires = plan_expiry
            user.created_at = source_time
            user.last_login = source_time

            admin = db.session.get(User, admin_id)
            admin.plan_expires = plan_expiry
            admin.created_at = source_time
            admin.last_login = source_time

            for tracked_session in UserSession.query.filter(
                UserSession.user_id.in_([user_id, admin_id])
            ):
                tracked_session.created_at = source_time
                tracked_session.last_seen = source_time

            payment = Payment(
                user_id=user_id,
                amount=29.99,
                plan="basic",
                status="completed",
                transaction_id="order-json-time-contract",
                verified_at=source_time,
                verified_amount_minor=2999,
                created_at=source_time,
            )
            announcement = Announcement(
                title="UTC contract",
                content="UTC contract",
                is_active=True,
                created_at=source_time,
            )
            db.session.add_all([payment, announcement])
            db.session.commit()
            payment_id = payment.id
            announcement_id = announcement.id

        plan_response = self.client.get("/plan/info", headers=user_headers)
        sessions_response = self.client.get("/sessions", headers=user_headers)
        stats_response = self.client.get("/stats/my", headers=user_headers)
        announcements_response = self.client.get("/announcements")
        users_response = self.client.get("/admin/users", headers=admin_headers)
        payments_response = self.client.get(
            "/admin/payments",
            headers=admin_headers,
        )

        for response in (
            plan_response,
            sessions_response,
            stats_response,
            announcements_response,
            users_response,
            payments_response,
        ):
            self.assertEqual(
                response.status_code,
                200,
                response.get_data(as_text=True),
            )

        session_payload = sessions_response.get_json()["sessions"]
        user_session = next(item for item in session_payload if item["is_current"])
        announcement_payload = next(
            item
            for item in announcements_response.get_json()
            if item["id"] == announcement_id
        )
        admin_user_payload = next(
            item
            for item in users_response.get_json()["users"]
            if item["id"] == user_id
        )
        payment_payload = next(
            item
            for item in payments_response.get_json()["payments"]
            if item["id"] == payment_id
        )
        instant_fields = {
            "plan.info.plan_expires": plan_response.get_json()["plan_expires"],
            "sessions.created_at": user_session["created_at"],
            "sessions.last_seen": user_session["last_seen"],
            "stats.my.member_since": stats_response.get_json()["member_since"],
            "announcements.date": announcement_payload["date"],
            "admin.users.plan_expires": admin_user_payload["plan_expires"],
            "admin.users.created_at": admin_user_payload["created_at"],
            "admin.users.last_login": admin_user_payload["last_login"],
            "admin.payments.verified_at": payment_payload["verified_at"],
            "admin.payments.created_at": payment_payload["created_at"],
        }
        for label, value in instant_fields.items():
            with self.subTest(field=label):
                self.assertIsInstance(value, str)
                self.assertTrue(value.endswith("Z"), value)
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                self.assertEqual(parsed.utcoffset(), timedelta(0))

    def _create_retry_payment(
        self,
        suffix,
        *,
        status="verification_failed",
        admin_hidden=False,
        transaction_id=None,
    ):
        with app_module.app.app_context():
            user = User(
                username=f"retry-customer-{suffix}",
                email=f"retry-{suffix}@example.test",
                password_hash="unused",
                plan="free",
                is_verified=True,
            )
            db.session.add(user)
            db.session.flush()
            payment = Payment(
                user_id=user.id,
                amount=29.99,
                plan="basic",
                status=status,
                transaction_id=(
                    transaction_id
                    if transaction_id is not None
                    else f"order-retry-{suffix}"
                ),
                admin_hidden=admin_hidden,
                verification_attempts=4,
                verification_error="retry_exhausted:api_not_found",
                verification_last_http_status=404,
            )
            db.session.add(payment)
            db.session.commit()
            return user.id, payment.id

    def _create_user_deletion_fixture(self, suffix):
        now = datetime.utcnow().replace(microsecond=0)
        checkout_token = "HB-" + hashlib.sha256(
            f"checkout-{suffix}".encode()
        ).hexdigest()[:32].upper()
        with app_module.app.app_context():
            user = User(
                username=f"delete-customer-{suffix}",
                email=f"delete-{suffix}@example.test",
                password_hash="unused",
                plan="premium",
                is_verified=True,
            )
            db.session.add(user)
            db.session.flush()

            completed = Payment(
                user_id=user.id,
                amount=59.99,
                plan="premium",
                status="completed",
                transaction_id=f"delete-order-{suffix}",
                admin_hidden=True,
                shopier_webhook_id="delete-subscription",
                shopier_event="order.created",
                shopier_account_id="delete-account",
                shopier_timestamp=1_720_000_000,
                webhook_body_sha256="d" * 64,
                webhook_received_at=now - timedelta(minutes=2),
                verification_attempts=2,
                verification_last_http_status=200,
                verified_at=now - timedelta(minutes=1),
                verified_amount_minor=5999,
                created_at=now - timedelta(days=1),
            )
            checkout = Payment(
                user_id=user.id,
                amount=29.99,
                plan="basic",
                status="checkout_started",
                match_token=checkout_token,
                created_at=now,
            )
            account = SteamAccount(
                id=f"steam-delete-{suffix}",
                user_id=user.id,
                steam_username=f"steam-{suffix}",
                is_boosting=True,
            )
            db.session.add_all([completed, checkout, account])
            db.session.flush()
            game = BoostGame(account_id=account.id, app_id=730)
            boost_log = BoostLog(
                account_id=account.id,
                user_id=user.id,
                started_at=now - timedelta(hours=1),
                duration_seconds=60,
                games_count=1,
                app_ids_json="[730]",
            )
            session = UserSession(
                user_id=user.id,
                token_jti=hashlib.sha256(
                    f"session-{suffix}".encode()
                ).hexdigest()[:32],
                expires_at=now + timedelta(days=1),
                is_active=True,
            )
            revoked = RevokedToken(
                user_id=user.id,
                token_jti=hashlib.sha256(
                    f"revoked-{suffix}".encode()
                ).hexdigest()[:32],
                expires_at=now + timedelta(days=1),
            )
            db.session.add_all([game, boost_log, session, revoked])
            db.session.commit()

            completed_fields = {
                "amount": completed.amount,
                "plan": completed.plan,
                "status": completed.status,
                "transaction_id": completed.transaction_id,
                "admin_hidden": completed.admin_hidden,
                "shopier_webhook_id": completed.shopier_webhook_id,
                "shopier_event": completed.shopier_event,
                "shopier_account_id": completed.shopier_account_id,
                "shopier_timestamp": completed.shopier_timestamp,
                "webhook_body_sha256": completed.webhook_body_sha256,
                "webhook_received_at": completed.webhook_received_at,
                "verification_attempts": completed.verification_attempts,
                "verification_last_http_status": (
                    completed.verification_last_http_status
                ),
                "verified_at": completed.verified_at,
                "verified_amount_minor": completed.verified_amount_minor,
                "created_at": completed.created_at,
            }
            return {
                "user_id": user.id,
                "username": user.username,
                "completed_id": completed.id,
                "checkout_id": checkout.id,
                "checkout_token": checkout_token,
                "account_id": account.id,
                "steam_username": account.steam_username,
                "game_id": game.id,
                "boost_log_id": boost_log.id,
                "session_id": session.id,
                "revoked_id": revoked.id,
                "completed_fields": completed_fields,
            }

    def _create_account_removal_fixture(
        self,
        user_id,
        suffix,
        *,
        steam_username=None,
        is_boosting=False,
    ):
        now = datetime.utcnow().replace(microsecond=0)
        account_id = hashlib.sha256(
            f"account-remove-{suffix}".encode()
        ).hexdigest()[:16]
        with app_module.app.app_context():
            account = SteamAccount(
                id=account_id,
                user_id=user_id,
                steam_username=(
                    steam_username or f"steam-remove-{suffix}"
                ),
                is_boosting=is_boosting,
            )
            db.session.add(account)
            db.session.flush()
            game = BoostGame(account_id=account.id, app_id=730)
            boost_log = BoostLog(
                account_id=account.id,
                user_id=user_id,
                started_at=now - timedelta(minutes=5),
                stopped_at=now - timedelta(minutes=4),
                duration_seconds=60,
                games_count=1,
                app_ids_json="[730]",
            )
            db.session.add_all([game, boost_log])
            db.session.commit()
            return {
                "account_id": account.id,
                "steam_username": account.steam_username,
                "game_id": game.id,
                "boost_log_id": boost_log.id,
                "user_id": user_id,
            }

    def test_webhook_only_persists_pending_and_never_calls_api_inline(self):
        user_id, payment_id = self._create_checkout()
        with mock.patch.object(app_module.shopier_lib, "get_order") as get_order:
            response = self._post_webhook(order_payload())
        self.assertEqual(response.status_code, 200)
        get_order.assert_not_called()
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            user = db.session.get(User, user_id)
            self.assertEqual(payment.status, "verification_pending")
            self.assertEqual(payment.transaction_id, "order-1")
            self.assertEqual(user.plan, "free")

    def test_webhook_rejects_auth_and_event_errors_without_state(self):
        self._create_checkout()
        payload = order_payload()
        invalid = self._post_webhook(payload, **{"Shopier-Signature": "0" * 64})
        self.assertEqual(invalid.status_code, 401)
        empty_event = self._post_webhook(payload, **{"Shopier-Event": ""})
        self.assertEqual(empty_event.status_code, 400)
        wrong_account = self._post_webhook(payload, **{"Shopier-Account-Id": "other"})
        self.assertEqual(wrong_account.status_code, 403)
        unsupported = self._post_webhook(payload, **{"Shopier-Event": "payment.completed"})
        self.assertEqual(unsupported.status_code, 200)
        self.assertTrue(unsupported.get_json()["ignored"])
        with app_module.app.app_context():
            self.assertEqual(Payment.query.filter_by(status="verification_pending").count(), 0)

    def test_global_request_body_limit_returns_json_413(self):
        self.assertEqual(
            app_module.app.config["MAX_CONTENT_LENGTH"],
            512 * 1024,
        )
        oversized = json.dumps({"padding": "x" * 256}).encode()
        with mock.patch.dict(
            app_module.app.config,
            {"MAX_CONTENT_LENGTH": 128},
        ):
            response = self.client.post(
                "/site_login",
                data=oversized,
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json(), {
            "ok": False,
            "error": "Payload too large.",
        })

    def test_global_request_body_limit_covers_unknown_length_streams(self):
        oversized = json.dumps({"padding": "x" * 256}).encode()
        headers = {
            "Shopier-Signature": "0" * 64,
            "Shopier-Event": "order.created",
            "Shopier-Webhook-Id": "subscription-1",
            "Shopier-Account-Id": "account-1",
            "Shopier-Timestamp": str(int(datetime.utcnow().timestamp())),
            "Content-Type": "application/json",
        }
        with (
            mock.patch.dict(
                app_module.app.config,
                {"MAX_CONTENT_LENGTH": 128},
            ),
            mock.patch.object(
                shopier,
                "verify_webhook",
                return_value=False,
            ) as verify_webhook,
        ):
            response = self.client.post(
                "/shopier/webhook",
                data=oversized,
                headers=headers,
                environ_overrides={
                    "CONTENT_LENGTH": "",
                    "wsgi.input_terminated": True,
                },
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "Invalid signature")
        verify_webhook.assert_called_once()
        bounded_body = verify_webhook.call_args.args[0]
        self.assertEqual(len(bounded_body), 128)
        self.assertLess(len(bounded_body), len(oversized))

    def test_webhook_fails_closed_when_runtime_verifier_is_unavailable(self):
        payload = order_payload()
        Config.SHOPIER_VERIFICATION_WORKER_ENABLED = False
        self.assertEqual(self._post_webhook(payload).status_code, 503)
        Config.SHOPIER_VERIFICATION_WORKER_ENABLED = True
        Config.SHOPIER_PAT = None
        self.assertEqual(self._post_webhook(payload).status_code, 503)
        Config.SHOPIER_PAT = "test-pat"
        response = self._post_webhook(payload)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("payment_id", response.get_json())

    def test_same_subscription_accepts_distinct_orders_and_dedupes_order_id(self):
        first = order_payload("order-1", token="")
        first["note"] = "missing token"
        second = order_payload("order-2", token="")
        second["note"] = "missing token"
        self.assertEqual(self._post_webhook(first).status_code, 200)
        self.assertEqual(self._post_webhook(second).status_code, 200)
        duplicate = self._post_webhook(first)
        self.assertEqual(duplicate.status_code, 200)
        self.assertTrue(duplicate.get_json()["duplicate"])
        with app_module.app.app_context():
            self.assertEqual(Payment.query.filter_by(status="verification_pending").count(), 2)

    def test_worker_completes_paid_order_atomically(self):
        user_id, payment_id = self._create_checkout()
        self.assertEqual(self._post_webhook(order_payload()).status_code, 200)
        with mock.patch.object(
            app_module.shopier_lib, "get_order", return_value=order_payload()
        ):
            self.assertEqual(app_module.process_due_payment_verifications(1), 1)
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            user = db.session.get(User, user_id)
            self.assertEqual(payment.status, "completed")
            self.assertEqual(payment.verified_amount_minor, 2999)
            self.assertIsNotNone(payment.verified_at)
            self.assertEqual(user.plan, "basic")

    def test_transient_api_error_is_persisted_for_retry(self):
        _, payment_id = self._create_checkout()
        self._post_webhook(order_payload())
        error = shopier.ShopierAPIError(
            "api_not_found", status_code=404, retryable=True
        )
        with mock.patch.object(app_module.shopier_lib, "get_order", side_effect=error):
            app_module.process_due_payment_verifications(1)
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "verification_pending")
            self.assertEqual(payment.verification_attempts, 1)
            self.assertEqual(payment.verification_error, "api_not_found")
            self.assertIsNotNone(payment.next_verification_at)
            self.assertIsNone(payment.verification_lock_until)

    def test_business_validation_failure_never_activates_plan(self):
        user_id, payment_id = self._create_checkout()
        self._post_webhook(order_payload())
        unpaid = order_payload()
        unpaid["paymentStatus"] = "unpaid"
        with mock.patch.object(app_module.shopier_lib, "get_order", return_value=unpaid):
            app_module.process_due_payment_verifications(1)
        with app_module.app.app_context():
            self.assertEqual(db.session.get(Payment, payment_id).status, "verification_failed")
            self.assertEqual(db.session.get(User, user_id).plan, "free")

    def test_late_basic_order_cannot_downgrade_premium(self):
        user_id, payment_id = self._create_checkout(user_plan="premium")
        self._post_webhook(order_payload())
        with mock.patch.object(
            app_module.shopier_lib, "get_order", return_value=order_payload()
        ):
            app_module.process_due_payment_verifications(1)
        with app_module.app.app_context():
            self.assertEqual(db.session.get(Payment, payment_id).status, "completed")
            self.assertEqual(db.session.get(User, user_id).plan, "premium")

    def test_expired_checkout_token_becomes_verified_unmatched(self):
        user_id, old_payment_id = self._create_checkout(age_hours=25)
        self.assertEqual(self._post_webhook(order_payload()).status_code, 200)
        with app_module.app.app_context():
            placeholder_id = Payment.query.filter_by(transaction_id="order-1").one().id
        self.assertNotEqual(placeholder_id, old_payment_id)
        with mock.patch.object(
            app_module.shopier_lib, "get_order", return_value=order_payload()
        ):
            app_module.process_due_payment_verifications(1)
        with app_module.app.app_context():
            placeholder = db.session.get(Payment, placeholder_id)
            self.assertEqual(placeholder.status, "unmatched")
            self.assertIsNotNone(placeholder.verified_at)
            self.assertEqual(db.session.get(User, user_id).plan, "free")

    def test_claim_lease_prevents_double_processing(self):
        with app_module.app.app_context():
            payment = Payment(
                status="verification_pending",
                transaction_id="order-lease",
                next_verification_at=datetime.utcnow() - timedelta(seconds=1),
            )
            db.session.add(payment)
            db.session.commit()
            now = datetime.utcnow()
            with mock.patch.object(
                app_module,
                "build_postgresql_due_payment_claim_select",
            ) as postgresql_claim_select:
                first = app_module._claim_due_payment(now)
                second = app_module._claim_due_payment(now)
            self.assertIsNotNone(first)
            self.assertIsNone(second)
            postgresql_claim_select.assert_not_called()

    def test_stale_attempt_cannot_clear_or_fail_a_newer_payment_lease(self):
        now = datetime.utcnow()
        with app_module.app.app_context():
            payment = Payment(
                status="verification_pending",
                transaction_id="order-stale-attempt-fence",
                verification_attempts=2,
                verification_error="newer_attempt_active",
                verification_last_http_status=503,
                next_verification_at=now - timedelta(seconds=1),
                verification_lock_until=now + timedelta(minutes=1),
            )
            db.session.add(payment)
            db.session.commit()
            payment_id = payment.id

            stale_error = app_module.shopier_lib.ShopierAPIError(
                "stale_worker_failure",
                retryable=True,
            )
            self.assertFalse(
                app_module._schedule_verification_retry(
                    payment_id,
                    1,
                    stale_error,
                )
            )
            self.assertFalse(
                app_module._mark_verification_failed(
                    payment_id,
                    1,
                    "stale_worker_terminal_failure",
                    500,
                )
            )

            db.session.expire_all()
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "verification_pending")
            self.assertEqual(payment.verification_attempts, 2)
            self.assertEqual(payment.verification_error, "newer_attempt_active")
            self.assertEqual(payment.verification_last_http_status, 503)
            self.assertEqual(
                payment.verification_lock_until,
                app_module.as_utc(now + timedelta(minutes=1)),
            )

    def test_legacy_naive_payment_lease_preserves_exact_due_instant(self):
        boundary = datetime(
            2026, 7, 26, 15, 30, 45, 123456, tzinfo=timezone.utc
        )
        legacy_text = boundary.replace(tzinfo=None).isoformat(sep=" ")
        created_text = "2026-07-25 10:20:30.654321"

        with app_module.app.app_context():
            payment = Payment(
                status="verification_pending",
                transaction_id="order-legacy-lease-boundary",
                verification_attempts=0,
            )
            db.session.add(payment)
            db.session.flush()
            payment_id = payment.id
            db.session.execute(
                db.text(
                    "UPDATE payments SET created_at = :created_at, "
                    "next_verification_at = :boundary, "
                    "verification_lock_until = :boundary "
                    "WHERE id = :payment_id"
                ),
                {
                    "created_at": created_text,
                    "boundary": legacy_text,
                    "payment_id": payment_id,
                },
            )
            db.session.commit()
            db.session.expire_all()

            claim = app_module._claim_due_payment(boundary)
            self.assertIsNotNone(claim)
            self.assertEqual(claim["payment_id"], payment_id)
            self.assertEqual(claim["attempt"], 1)

            db.session.expire_all()
            claimed = db.session.get(Payment, payment_id)
            self.assertEqual(claimed.created_at, app_module.as_utc(
                datetime.fromisoformat(created_text)
            ))
            self.assertEqual(claimed.next_verification_at, boundary)
            self.assertEqual(
                claimed.verification_lock_until,
                boundary + timedelta(
                    seconds=app_module.SHOPIER_VERIFICATION_LOCK_SECONDS
                ),
            )

            raw = db.session.execute(
                db.text(
                    "SELECT created_at, next_verification_at, "
                    "verification_lock_until FROM payments WHERE id = :payment_id"
                ),
                {"payment_id": payment_id},
            ).mappings().one()
            self.assertEqual(raw["created_at"], created_text)
            self.assertEqual(raw["next_verification_at"], legacy_text)
            self.assertNotIn("+", raw["verification_lock_until"])
            self.assertFalse(raw["verification_lock_until"].endswith("Z"))

    def test_expired_claim_lease_is_recovered_after_restart(self):
        user_id, payment_id = self._create_checkout()
        self.assertEqual(self._post_webhook(order_payload()).status_code, 200)
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            payment.verification_attempts = 1
            payment.verification_lock_until = datetime.utcnow() - timedelta(seconds=1)
            payment.next_verification_at = datetime.utcnow() - timedelta(seconds=1)
            db.session.commit()
        with mock.patch.object(
            app_module.shopier_lib, "get_order", return_value=order_payload()
        ):
            self.assertEqual(app_module.process_due_payment_verifications(1), 1)
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "completed")
            self.assertEqual(payment.verification_attempts, 2)
            self.assertEqual(db.session.get(User, user_id).plan, "basic")

    def test_second_order_reusing_same_token_never_activates_twice(self):
        user_id, payment_id = self._create_checkout()
        first = order_payload("order-1")
        second = order_payload("order-2")
        self.assertEqual(self._post_webhook(first).status_code, 200)
        self.assertEqual(self._post_webhook(second).status_code, 200)
        with mock.patch.object(
            app_module.shopier_lib,
            "get_order",
            side_effect=lambda _pat, order_id: first if order_id == "order-1" else second,
        ):
            self.assertEqual(app_module.process_due_payment_verifications(2), 2)
        with app_module.app.app_context():
            original = db.session.get(Payment, payment_id)
            replay = Payment.query.filter_by(transaction_id="order-2").one()
            self.assertEqual(original.status, "completed")
            self.assertEqual(replay.status, "unmatched")
            self.assertEqual(db.session.get(User, user_id).plan, "basic")

    def test_unverified_manual_approval_is_blocked(self):
        with app_module.app.app_context():
            admin = User(
                username="admin", email="admin@example.test", password_hash="x", is_admin=True
            )
            payment = Payment(
                status="unmatched", transaction_id="order-unverified", plan="basic", amount=29.99
            )
            db.session.add_all([admin, payment])
            db.session.commit()
            payment_id = payment.id
            admin_id = admin.id
        with app_module.app.test_request_context(
            "/admin/payments/approve",
            method="POST",
            json={"payment_id": payment_id, "username": "admin", "reason": "test reason"},
        ):
            app_module.g.user = db.session.get(User, admin_id)
            response, status = app_module.admin_approve_payment.__wrapped__()
            self.assertEqual(status, 409)

    def test_verified_manual_match_writes_append_only_audit(self):
        with app_module.app.app_context():
            admin = User(
                username="admin", email="admin@example.test", password_hash="x", is_admin=True
            )
            customer = User(
                username="customer", email="customer@example.test", password_hash="x", plan="free"
            )
            payment = Payment(
                status="unmatched",
                transaction_id="order-verified",
                plan="basic",
                amount=29.99,
                verified_amount_minor=2999,
                verified_at=datetime.utcnow(),
            )
            db.session.add_all([admin, customer, payment])
            db.session.commit()
            payment_id, admin_id = payment.id, admin.id
        with app_module.app.test_request_context(
            "/admin/payments/approve",
            method="POST",
            json={
                "payment_id": payment_id,
                "username": "customer",
                "reason": "Customer supplied matching receipt",
            },
        ):
            app_module.g.user = db.session.get(User, admin_id)
            response = app_module.admin_approve_payment.__wrapped__()
            self.assertTrue(response.get_json()["ok"])
        with app_module.app.app_context():
            self.assertEqual(db.session.get(Payment, payment_id).status, "completed")
            self.assertEqual(PaymentAuditLog.query.filter_by(payment_id=payment_id).count(), 1)

    def test_admin_hide_is_idempotent_and_writes_only_one_audit(self):
        admin_id, headers = self._tracked_bearer("hide-admin", is_admin=True)
        with app_module.app.app_context():
            payment = Payment(
                status="verification_failed",
                transaction_id="order-hide-idempotent",
                verification_attempts=3,
            )
            db.session.add(payment)
            db.session.commit()
            payment_id = payment.id

        first = self.client.post(
            "/admin/payments/hide",
            json={"payment_id": payment_id},
            headers=headers,
        )
        second = self.client.post(
            "/admin/payments/hide",
            json={"payment_id": payment_id},
            headers=headers,
        )

        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True))
        with app_module.app.app_context():
            self.assertTrue(db.session.get(Payment, payment_id).admin_hidden)
            audits = PaymentAuditLog.query.filter_by(
                payment_id=payment_id,
                actor_user_id=admin_id,
                action="admin_hide",
            ).all()
            self.assertEqual(len(audits), 1)

    def test_admin_payment_routes_reject_non_object_json_and_invalid_ids(self):
        _, headers = self._tracked_bearer("payment-route-admin", is_admin=True)
        for route in ("/admin/payments/approve", "/admin/payments/hide"):
            with self.subTest(route=route, body=[]):
                response = self.client.post(route, json=[], headers=headers)
                self.assertEqual(response.status_code, 400)
            with self.subTest(route=route, body={"payment_id": True}):
                response = self.client.post(
                    route,
                    json={"payment_id": True},
                    headers=headers,
                )
                self.assertEqual(response.status_code, 400)

    def test_admin_plan_upgrade_locks_user_and_cannot_downgrade_paid_plan(self):
        with app_module.app.app_context():
            admin = User(
                username="plan-lock-admin",
                email="plan-lock-admin@example.test",
                password_hash="unused",
                plan="premium",
                is_admin=True,
            )
            db.session.add(admin)
            db.session.commit()
            admin_id = admin.id

        with app_module.app.test_request_context(
            "/plan/upgrade",
            method="POST",
            json={"plan": "basic"},
        ):
            app_module.g.user = db.session.get(User, admin_id)
            real_locked_user = app_module._locked_user
            with mock.patch.object(
                app_module,
                "_locked_user",
                wraps=real_locked_user,
            ) as locked_user:
                response, status = app_module.plan_upgrade.__wrapped__()

        self.assertEqual(status, 409)
        self.assertFalse(response.get_json()["ok"])
        locked_user.assert_called_once_with(admin_id)
        with app_module.app.app_context():
            self.assertEqual(db.session.get(User, admin_id).plan, "premium")

    def test_checkout_database_error_rolls_back_and_returns_503(self):
        with app_module.app.app_context():
            user = User(
                username="checkout-db-error-user",
                email="checkout-db-error@example.test",
                password_hash="unused",
                plan="free",
            )
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        with app_module.app.test_request_context(
            "/plan/checkout",
            method="POST",
            json={"plan": "basic"},
        ):
            app_module.g.user = db.session.get(User, user_id)
            with mock.patch.object(
                db.session,
                "commit",
                side_effect=SQLAlchemyError("forced checkout failure"),
            ):
                response, status = app_module.plan_checkout.__wrapped__()

        self.assertEqual(status, 503)
        self.assertFalse(response.get_json()["ok"])
        with app_module.app.app_context():
            self.assertEqual(Payment.query.filter_by(user_id=user_id).count(), 0)

    def test_admin_retry_success_is_atomic_audited_and_idempotent(self):
        admin_id, headers = self._tracked_bearer("retry-admin", is_admin=True)
        _, payment_id = self._create_retry_payment("success")
        body = {
            "payment_id": payment_id,
            "reason": "Retry after Shopier API recovery",
        }

        with mock.patch.object(
            app_module, "_payment_verification_wakeup"
        ) as wakeup_event:
            response = self.client.post(
                "/admin/payments/retry", json=body, headers=headers
            )
            duplicate = self.client.post(
                "/admin/payments/retry", json=body, headers=headers
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(duplicate.status_code, 409)
        wakeup_event.set.assert_called_once_with()
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "verification_pending")
            # Retry reopens the row without recycling a claim generation.
            # Resetting this to zero would let an old attempt become valid
            # again after the next claim (the classic ABA fencing bug).
            self.assertEqual(payment.verification_attempts, 4)
            self.assertIsNone(payment.verification_error)
            self.assertIsNone(payment.verification_last_http_status)
            self.assertIsNotNone(payment.next_verification_at)
            self.assertIsNone(payment.verification_lock_until)
            audit = PaymentAuditLog.query.filter_by(payment_id=payment_id).one()
            self.assertEqual(audit.actor_user_id, admin_id)
            self.assertEqual(audit.actor_username, "retry-admin")
            self.assertEqual(audit.action, "verification_retry")
            self.assertEqual(audit.from_status, "verification_failed")
            self.assertEqual(audit.to_status, "verification_pending")
            self.assertEqual(audit.reason, body["reason"])

    def test_admin_retry_preserves_monotonic_attempt_fence_across_reclaim(self):
        _, headers = self._tracked_bearer("retry-admin-fence", is_admin=True)
        _, payment_id = self._create_retry_payment("monotonic-fence")

        response = self.client.post(
            "/admin/payments/retry",
            json={
                "payment_id": payment_id,
                "reason": "Reopen without recycling the claim generation",
            },
            headers=headers,
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

        with app_module.app.app_context():
            reopened = db.session.get(Payment, payment_id)
            self.assertEqual(reopened.verification_attempts, 4)
            claim = app_module._claim_due_payment(
                app_module.utc_now() + timedelta(seconds=1)
            )
            self.assertEqual(claim["payment_id"], payment_id)
            self.assertEqual(claim["attempt"], 5)

            self.assertFalse(
                app_module._mark_verification_failed(
                    payment_id,
                    4,
                    "stale_pre_retry_worker",
                    500,
                )
            )
            current = db.session.get(Payment, payment_id)
            self.assertEqual(current.status, "verification_pending")
            self.assertEqual(current.verification_attempts, 5)
            self.assertNotEqual(current.verification_error, "stale_pre_retry_worker")

    def test_admin_retry_update_fences_the_observed_attempt_generation(self):
        _, headers = self._tracked_bearer("retry-admin-observed", is_admin=True)
        _, payment_id = self._create_retry_payment("observed-generation")
        real_execute = db.session.execute
        captured_updates = []

        def capture_retry_update(statement, *args, **kwargs):
            if (
                getattr(statement, "is_update", False)
                and getattr(getattr(statement, "table", None), "name", None)
                == "payments"
            ):
                captured_updates.append(statement)
                return mock.Mock(rowcount=0)
            return real_execute(statement, *args, **kwargs)

        with (
            mock.patch.object(
                db.session,
                "execute",
                side_effect=capture_retry_update,
            ),
            mock.patch.object(
                app_module,
                "_payment_verification_wakeup",
            ) as wakeup_event,
        ):
            response = self.client.post(
                "/admin/payments/retry",
                json={
                    "payment_id": payment_id,
                    "reason": "Reject a stale admin retry generation",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 409, response.get_data(as_text=True))
        self.assertEqual(len(captured_updates), 1)
        self.assertIn(
            "payments.verification_attempts",
            str(captured_updates[0].whereclause),
        )
        wakeup_event.set.assert_not_called()
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "verification_failed")
            self.assertEqual(payment.verification_attempts, 4)
            self.assertEqual(
                PaymentAuditLog.query.filter_by(payment_id=payment_id).count(),
                0,
            )

    def test_admin_retry_rejects_malformed_payload_and_payment_id(self):
        _, headers = self._tracked_bearer("retry-admin-invalid", is_admin=True)
        _, payment_id = self._create_retry_payment("invalid")
        reason = "Valid audit reason"
        invalid_bodies = [
            None,
            [],
            {},
            {"payment_id": None, "reason": reason},
            {"payment_id": True, "reason": reason},
            {"payment_id": 0, "reason": reason},
            {"payment_id": -1, "reason": reason},
            {"payment_id": str(payment_id), "reason": reason},
            {"payment_id": {}, "reason": reason},
            {"payment_id": 1.5, "reason": reason},
            {"payment_id": payment_id, "reason": {}},
        ]

        with mock.patch.object(
            app_module, "_payment_verification_wakeup"
        ) as wakeup_event:
            for body in invalid_bodies:
                with self.subTest(body=body):
                    response = self.client.post(
                        "/admin/payments/retry", json=body, headers=headers
                    )
                    self.assertEqual(
                        response.status_code, 400, response.get_data(as_text=True)
                    )

        wakeup_event.set.assert_not_called()
        with app_module.app.app_context():
            self.assertEqual(
                db.session.get(Payment, payment_id).status,
                "verification_failed",
            )
            self.assertEqual(
                PaymentAuditLog.query.filter_by(payment_id=payment_id).count(), 0
            )

    def test_admin_retry_requires_authenticated_admin(self):
        _, payment_id = self._create_retry_payment("auth")
        _, user_headers = self._tracked_bearer(
            "retry-non-admin", is_admin=False
        )
        body = {"payment_id": payment_id, "reason": "Valid audit reason"}

        anonymous = self.client.post(
            "/admin/payments/retry",
            json=body,
            headers={"Authorization": "Bearer invalid"},
        )
        non_admin = self.client.post(
            "/admin/payments/retry", json=body, headers=user_headers
        )

        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(non_admin.status_code, 403)
        with app_module.app.app_context():
            self.assertEqual(
                db.session.get(Payment, payment_id).status,
                "verification_failed",
            )
            self.assertEqual(PaymentAuditLog.query.count(), 0)

    def test_admin_retry_rejects_ineligible_payment_states(self):
        _, headers = self._tracked_bearer("retry-admin-state", is_admin=True)
        _, completed_id = self._create_retry_payment(
            "completed", status="completed"
        )
        _, hidden_id = self._create_retry_payment(
            "hidden", admin_hidden=True
        )
        _, missing_transaction_id = self._create_retry_payment(
            "missing-order", transaction_id=""
        )

        with mock.patch.object(
            app_module, "_payment_verification_wakeup"
        ) as wakeup_event:
            for payment_id in (
                completed_id,
                hidden_id,
                missing_transaction_id,
            ):
                with self.subTest(payment_id=payment_id):
                    response = self.client.post(
                        "/admin/payments/retry",
                        json={
                            "payment_id": payment_id,
                            "reason": "Valid audit reason",
                        },
                        headers=headers,
                    )
                    self.assertEqual(response.status_code, 409)

        wakeup_event.set.assert_not_called()
        with app_module.app.app_context():
            self.assertEqual(PaymentAuditLog.query.count(), 0)

    def test_admin_retry_rejects_another_open_checkout(self):
        admin_id, headers = self._tracked_bearer(
            "retry-admin-conflict", is_admin=True
        )
        user_id, payment_id = self._create_retry_payment("conflict")
        with app_module.app.app_context():
            open_checkout = Payment(
                user_id=user_id,
                amount=59.99,
                plan="premium",
                status="checkout_started",
                match_token="HB-" + "B" * 32,
            )
            db.session.add(open_checkout)
            db.session.commit()
            open_checkout_id = open_checkout.id

        with mock.patch.object(
            app_module, "_payment_verification_wakeup"
        ) as wakeup_event:
            response = self.client.post(
                "/admin/payments/retry",
                json={
                    "payment_id": payment_id,
                    "reason": "Retry requested by support",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["conflict"], "open_payment_exists")
        wakeup_event.set.assert_not_called()
        with app_module.app.app_context():
            self.assertEqual(
                db.session.get(Payment, payment_id).status,
                "verification_failed",
            )
            self.assertEqual(
                db.session.get(Payment, open_checkout_id).status,
                "checkout_started",
            )
            self.assertEqual(
                PaymentAuditLog.query.filter_by(
                    payment_id=payment_id,
                    actor_user_id=admin_id,
                ).count(),
                0,
            )

    def test_admin_retry_integrity_error_rolls_back_without_audit(self):
        _, headers = self._tracked_bearer("retry-admin-race", is_admin=True)
        _, payment_id = self._create_retry_payment("race")
        error = IntegrityError(
            "UPDATE payments", {}, RuntimeError("unique race")
        )
        real_rollback = db.session.rollback

        with (
            mock.patch.object(db.session, "commit", side_effect=error),
            mock.patch.object(
                db.session, "rollback", wraps=real_rollback
            ) as rollback,
            mock.patch.object(
                app_module, "_payment_verification_wakeup"
            ) as wakeup_event,
        ):
            response = self.client.post(
                "/admin/payments/retry",
                json={
                    "payment_id": payment_id,
                    "reason": "Retry after transient outage",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 409, response.get_data(as_text=True))
        rollback.assert_called_once_with()
        wakeup_event.set.assert_not_called()
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "verification_failed")
            self.assertEqual(payment.verification_attempts, 4)
            self.assertEqual(
                payment.verification_error,
                "retry_exhausted:api_not_found",
            )
            self.assertEqual(payment.verification_last_http_status, 404)
            self.assertEqual(
                PaymentAuditLog.query.filter_by(payment_id=payment_id).count(), 0
            )

    def test_account_login_reuses_case_insensitive_username_at_plan_limit(self):
        user_id, headers = self._tracked_bearer(
            "account-login-casefold", is_admin=False
        )
        account_id = "abcdef0123456789"
        canonical_username = "CaseSensitiveSteam"
        with app_module.app.app_context():
            db.session.add(SteamAccount(
                id=account_id,
                user_id=user_id,
                steam_username=canonical_username,
            ))
            db.session.commit()

        manager = mock.MagicMock()
        manager.has_credentials.return_value = False
        manager.has_token.return_value = False
        manager.login.return_value = app_module.EResult.OK
        manager.client.steam_id = "76561198000000002"

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
            return_value=manager,
        ) as get_manager:
            response = self.client.post(
                "/accounts/login",
                json={
                    "username": canonical_username.swapcase(),
                    "password": "Steam-Password-123!",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        get_manager.assert_called_once_with(account_id, canonical_username)
        with app_module.app.app_context():
            accounts = SteamAccount.query.filter_by(user_id=user_id).all()
            self.assertEqual(len(accounts), 1)
            self.assertEqual(accounts[0].id, account_id)
            self.assertEqual(accounts[0].steam_username, canonical_username)

    def test_account_login_treats_legacy_sentinel_as_a_literal_password(self):
        _user_id, headers = self._tracked_bearer(
            "account-login-literal-sentinel", is_admin=False
        )
        manager = mock.MagicMock()
        manager.has_credentials.return_value = True
        manager.has_token.return_value = True
        manager.login.return_value = app_module.EResult.OK
        manager.client.steam_id = "76561198000000003"

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
            return_value=manager,
        ):
            response = self.client.post(
                "/accounts/login",
                json={
                    "username": "literal-sentinel-steam",
                    "password": "_use_saved_",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        manager.login.assert_called_once_with(
            "_use_saved_",
            code=None,
            code_type="email",
        )
        manager._login_with_credentials.assert_not_called()

    def test_account_login_keeps_saved_credentials_behind_explicit_flag(self):
        user_id, headers = self._tracked_bearer(
            "account-login-explicit-saved", is_admin=False
        )
        account_id = "fedcba9876543210"
        with app_module.app.app_context():
            db.session.add(SteamAccount(
                id=account_id,
                user_id=user_id,
                steam_username="ExplicitSavedSteam",
            ))
            db.session.commit()

        manager = mock.MagicMock()
        manager.has_credentials.return_value = True
        saved_credentials = {
            "password": "stored-secret",
            "refresh_token": "stored-refresh-token",
        }
        manager.load_credentials.return_value = saved_credentials
        manager._login_with_saved_credentials.return_value = app_module.EResult.OK
        manager.client.steam_id = "76561198000000004"

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
            return_value=manager,
        ):
            response = self.client.post(
                "/accounts/login",
                json={
                    "acct_id": account_id,
                    "use_credentials": True,
                    "code": "123456",
                    "code_type": "2fa",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        manager._login_with_saved_credentials.assert_called_once_with(
            saved_credentials,
            code="123456",
            code_type="2fa",
        )
        manager._login_with_credentials.assert_not_called()
        manager.login.assert_not_called()

    def test_account_login_supports_token_only_saved_credentials(self):
        user_id, headers = self._tracked_bearer(
            "account-login-token-only", is_admin=False
        )
        account_id = "0123456789abcdef"
        with app_module.app.app_context():
            db.session.add(SteamAccount(
                id=account_id,
                user_id=user_id,
                steam_username="TokenOnlySteam",
            ))
            db.session.commit()

        manager = mock.MagicMock()
        manager.has_credentials.return_value = True
        saved_credentials = {
            "password": None,
            "refresh_token": "stored-refresh-token",
        }
        manager.load_credentials.return_value = saved_credentials
        manager._login_with_saved_credentials.return_value = app_module.EResult.OK
        manager.client.steam_id = "76561198000000005"

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
            return_value=manager,
        ):
            response = self.client.post(
                "/accounts/login",
                json={
                    "acct_id": account_id,
                    "use_credentials": True,
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        manager._login_with_saved_credentials.assert_called_once_with(
            saved_credentials,
            code=None,
            code_type="email",
        )
        manager._login_with_credentials.assert_not_called()
        manager.login.assert_not_called()

    def test_account_login_keeps_wrong_two_factor_code_in_guard_flow(self):
        _user_id, headers = self._tracked_bearer(
            "account-login-wrong-two-factor", is_admin=False
        )
        manager = mock.MagicMock()
        manager.has_credentials.return_value = False
        manager.has_token.return_value = False
        manager.login.return_value = app_module.EResult.TwoFactorCodeMismatch

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
            return_value=manager,
        ):
            response = self.client.post(
                "/accounts/login",
                json={
                    "username": "wrong-two-factor-steam",
                    "password": "Steam-Password-123!",
                    "code": "123456",
                    "code_type": "2fa",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["need_code"])
        self.assertEqual(payload["code_type"], "2fa")
        self.assertNotIn("error", payload)

    def test_account_login_rejects_unknown_guard_code_type(self):
        _user_id, headers = self._tracked_bearer(
            "account-login-invalid-code-type", is_admin=False
        )

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
        ) as get_or_create:
            response = self.client.post(
                "/accounts/login",
                json={
                    "username": "invalid-code-type-steam",
                    "password": "Steam-Password-123!",
                    "code": "123456",
                    "code_type": "sms",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        get_or_create.assert_not_called()

    def test_account_login_rejects_non_string_guard_code_type(self):
        _user_id, headers = self._tracked_bearer(
            "account-login-non-string-code-type", is_admin=False
        )

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
        ) as get_or_create:
            response = self.client.post(
                "/accounts/login",
                json={
                    "username": "non-string-code-type-steam",
                    "password": "Steam-Password-123!",
                    "code_type": [],
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
        self.assertFalse(response.get_json()["ok"])
        get_or_create.assert_not_called()

    def test_account_login_legacy_token_flow_returns_typed_two_factor_contract(self):
        user_id, headers = self._tracked_bearer(
            "account-login-legacy-token-guard", is_admin=False
        )
        account_id = "abcdef0123456789"
        with app_module.app.app_context():
            db.session.add(SteamAccount(
                id=account_id,
                user_id=user_id,
                steam_username="LegacyTokenGuardSteam",
            ))
            db.session.commit()

        manager = mock.MagicMock()
        manager.has_credentials.return_value = False
        manager.login.return_value = (
            app_module.EResult.AccountLoginDeniedNeedTwoFactor
        )

        with mock.patch.object(
            app_module.boost_service,
            "get_or_create",
            return_value=manager,
        ):
            response = self.client.post(
                "/accounts/login",
                json={
                    "acct_id": account_id,
                    "use_token": True,
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["need_code"])
        self.assertTrue(payload["need_2fa"])
        self.assertEqual(payload["code_type"], "2fa")
        manager.login.assert_called_once_with()

    def test_game_info_strictly_validates_and_normalizes_app_ids(self):
        _user_id, headers = self._tracked_bearer(
            "game-info-validation", is_admin=False
        )
        invalid_requests = (
            None,
            [],
            {"app_ids": "730"},
            {"app_ids": [True]},
            {"app_ids": [0]},
            {"app_ids": [-1]},
            {"app_ids": [2 ** 32]},
            {"app_ids": [1.5]},
            {"app_ids": ["730&l=turkish"]},
        )

        with mock.patch.object(app_module, "safe_urlopen") as open_url:
            for body in invalid_requests:
                with self.subTest(body=body):
                    if body is None:
                        response = self.client.post("/game_info", headers=headers)
                    else:
                        response = self.client.post(
                            "/game_info", json=body, headers=headers
                        )
                    self.assertEqual(
                        response.status_code,
                        400,
                        response.get_data(as_text=True),
                    )
            open_url.assert_not_called()

        cached_info = {
            "name": "Counter-Strike 2",
            "header_image": "",
            "genres": ["Action"],
        }
        with (
            mock.patch.dict(
                app_module.game_cache,
                {
                    730: {
                        "data": cached_info,
                        "ts": app_module.time.time(),
                    },
                },
                clear=True,
            ),
            mock.patch.object(app_module, "safe_urlopen") as open_url,
        ):
            response = self.client.post(
                "/game_info",
                json={"app_ids": ["730"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json(), {"730": cached_info})
        open_url.assert_not_called()

    def test_account_remove_strictly_validates_body_and_id_without_side_effects(self):
        user_id, headers = self._tracked_bearer(
            "account-remove-validation", is_admin=False
        )
        fixture = self._create_account_removal_fixture(user_id, "validation")

        invalid_json_bodies = [
            [],
            {},
            {"acct_id": None},
            {"acct_id": True},
            {"acct_id": 123},
            {"acct_id": ""},
            {"acct_id": "a" * 15},
            {"acct_id": "A" * 16},
            {"acct_id": "g" * 16},
            {"acct_id": {}},
        ]
        with (
            mock.patch.object(
                app_module, "quarantine_saved_credentials"
            ) as quarantine,
            mock.patch.object(
                app_module.boost_service, "get_or_create"
            ) as get_manager,
            mock.patch.object(app_module.boost_service, "detach") as detach,
            mock.patch.object(app_module.boost_service, "remove") as remove,
            mock.patch.object(app_module, "_clear_timers") as clear_timers,
        ):
            no_body = self.client.post("/accounts/remove", headers=headers)
            malformed = self.client.post(
                "/accounts/remove",
                data="{",
                content_type="application/json",
                headers=headers,
            )
            self.assertEqual(no_body.status_code, 400)
            self.assertEqual(malformed.status_code, 400)

            for body in invalid_json_bodies:
                with self.subTest(body=body):
                    response = self.client.post(
                        "/accounts/remove", json=body, headers=headers
                    )
                    self.assertEqual(
                        response.status_code,
                        400,
                        response.get_data(as_text=True),
                    )

            missing = self.client.post(
                "/accounts/remove",
                json={"acct_id": "f" * 16},
                headers=headers,
            )

        self.assertEqual(missing.status_code, 404)
        quarantine.assert_not_called()
        get_manager.assert_not_called()
        detach.assert_not_called()
        remove.assert_not_called()
        clear_timers.assert_not_called()
        with app_module.app.app_context():
            self.assertIsNotNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            self.assertIsNotNone(db.session.get(BoostGame, fixture["game_id"]))
            self.assertEqual(
                db.session.get(BoostLog, fixture["boost_log_id"]).account_id,
                fixture["account_id"],
            )

    def test_account_remove_blocks_cross_owner_history_before_runtime_side_effects(self):
        user_id, headers = self._tracked_bearer(
            "account-remove-owner-mismatch", is_admin=False
        )
        fixture = self._create_account_removal_fixture(
            user_id,
            "owner-mismatch",
        )
        with app_module.app.app_context():
            other_user = User(
                username="account-remove-history-owner",
                email="account-remove-history-owner@example.test",
                password_hash="unused",
                is_verified=True,
            )
            db.session.add(other_user)
            db.session.flush()
            mismatch = BoostLog(
                account_id=fixture["account_id"],
                user_id=other_user.id,
                started_at=datetime.utcnow() - timedelta(minutes=3),
                stopped_at=datetime.utcnow() - timedelta(minutes=2),
                duration_seconds=60,
                games_count=1,
                app_ids_json="[730]",
            )
            db.session.add(mismatch)
            db.session.commit()
            mismatch_id = mismatch.id

        with (
            mock.patch.object(
                app_module.boost_service, "get_or_create"
            ) as get_manager,
            mock.patch.object(
                app_module, "quarantine_saved_credentials"
            ) as quarantine,
        ):
            response = self.client.post(
                "/accounts/remove",
                json={"acct_id": fixture["account_id"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 409, response.get_data(as_text=True))
        get_manager.assert_not_called()
        quarantine.assert_not_called()
        with app_module.app.app_context():
            self.assertIsNotNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            self.assertEqual(
                BoostLog.query.filter_by(account_id=fixture["account_id"]).count(),
                2,
            )
            self.assertIsNotNone(db.session.get(BoostLog, mismatch_id))

    def test_account_remove_commits_before_runtime_cleanup_and_preserves_history(self):
        user_id, headers = self._tracked_bearer(
            "account-remove-success", is_admin=False
        )
        fixture = self._create_account_removal_fixture(
            user_id, "success", is_boosting=True
        )
        with app_module.app.app_context():
            ownerless_history = BoostLog(
                account_id=fixture["account_id"],
                user_id=None,
                started_at=datetime.utcnow() - timedelta(minutes=8),
                stopped_at=datetime.utcnow() - timedelta(minutes=7),
                duration_seconds=60,
                games_count=1,
                app_ids_json="[570]",
            )
            db.session.add(ownerless_history)
            db.session.commit()
            ownerless_history_id = ownerless_history.id
        fixed_now = 1_720_000_300.0
        manager = mock.Mock()
        manager.boosting = True
        manager.start_time = fixed_now - 300
        manager.boost_snapshot.return_value = {
            "boosting": True,
            "start_time": fixed_now - 300,
            "session_id": "remove-session",
            "generation": 7,
            "pending_final_segments": [],
        }
        final_segment = {
            "account_id": fixture["account_id"],
            "session_id": "remove-session",
            "generation": 7,
            "started_at": fixed_now - 300,
            "stopped_at": fixed_now,
            "elapsed": 300,
            "app_ids": [730],
            "remote_stop_confirmed": True,
        }
        manager.stop_boost_segment.return_value = final_segment
        manager.pending_final_segments.return_value = []
        manager.acknowledge_final_segment.return_value = True
        events = []
        quarantined = [("active-secret", "quarantined-secret")]
        real_commit = db.session.commit

        def commit_and_record():
            real_commit()
            events.append("commit")

        def detach_and_record(account_id):
            events.append("detach")
            self.assertEqual(account_id, fixture["account_id"])
            return manager

        def clear_timers_and_record(account_id):
            events.append("timers")
            self.assertEqual(account_id, fixture["account_id"])

        def remove_and_record(**kwargs):
            events.append("remove")
            return True

        manager.remove_completely.side_effect = remove_and_record
        with (
            mock.patch.object(app_module.time, "time", return_value=fixed_now),
            mock.patch.object(
                app_module,
                "quarantine_saved_credentials",
                return_value=quarantined,
            ) as quarantine,
            mock.patch.object(
                app_module, "purge_quarantined_credentials", return_value=True
            ) as purge,
            mock.patch.object(
                app_module, "restore_quarantined_credentials"
            ) as restore,
            mock.patch.object(
                app_module.boost_service, "get_or_create", return_value=manager
            ),
            mock.patch.object(
                app_module.boost_service,
                "detach",
                side_effect=detach_and_record,
            ),
            mock.patch.object(
                app_module, "_clear_timers", side_effect=clear_timers_and_record
            ),
            mock.patch.object(db.session, "commit", side_effect=commit_and_record),
        ):
            response = self.client.post(
                "/accounts/remove",
                json={"acct_id": fixture["account_id"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json(), {"ok": True, "cleanup_warning": False})
        self.assertEqual(events, ["commit", "commit", "detach", "timers", "remove"])
        quarantine.assert_called_once_with(
            fixture["account_id"],
            fixture["steam_username"],
            include_legacy_machine_auth=True,
        )
        manager.remove_completely.assert_called_once_with(
            include_legacy_machine_auth=True
        )
        purge.assert_called_once_with(quarantined)
        restore.assert_not_called()

        with app_module.app.app_context():
            self.assertIsNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            self.assertIsNone(db.session.get(BoostGame, fixture["game_id"]))
            historical = db.session.get(BoostLog, fixture["boost_log_id"])
            self.assertIsNotNone(historical)
            self.assertIsNone(historical.account_id)
            self.assertEqual(
                historical.account_id_snapshot,
                fixture["account_id"],
            )
            self.assertEqual(
                historical.steam_username_snapshot,
                fixture["steam_username"],
            )
            self.assertEqual(historical.owner_user_id_snapshot, user_id)
            logs = BoostLog.query.filter_by(user_id=user_id).order_by(
                BoostLog.id
            ).all()
            self.assertEqual(len(logs), 2)
            final_segments = [log for log in logs if log.id != historical.id]
            self.assertEqual(len(final_segments), 1)
            final_segment = final_segments[0]
            self.assertIsNone(final_segment.account_id)
            self.assertEqual(
                final_segment.account_id_snapshot,
                fixture["account_id"],
            )
            self.assertEqual(
                final_segment.steam_username_snapshot,
                fixture["steam_username"],
            )
            self.assertEqual(final_segment.owner_user_id_snapshot, user_id)
            self.assertEqual(final_segment.duration_seconds, 300)
            self.assertEqual(final_segment.games_count, 1)
            self.assertEqual(json.loads(final_segment.app_ids_json), [730])
            self.assertEqual(
                final_segment.started_at,
                app_module.utc_from_epoch(fixed_now - 300),
            )
            ownerless = db.session.get(BoostLog, ownerless_history_id)
            self.assertIsNotNone(ownerless)
            self.assertIsNone(ownerless.account_id)
            self.assertIsNone(ownerless.user_id)
            self.assertEqual(
                ownerless.account_id_snapshot,
                fixture["account_id"],
            )
            self.assertEqual(
                ownerless.steam_username_snapshot,
                fixture["steam_username"],
            )
            self.assertEqual(ownerless.owner_user_id_snapshot, user_id)
            self.assertEqual(
                ownerless.owner_username_snapshot,
                "account-remove-success",
            )

    def test_account_remove_database_error_restores_credentials_and_runtime(self):
        user_id, headers = self._tracked_bearer(
            "account-remove-rollback", is_admin=False
        )
        fixture = self._create_account_removal_fixture(
            user_id, "rollback", is_boosting=False
        )
        manager = mock.Mock()
        manager.boosting = False
        manager.start_time = None
        manager.boost_snapshot.return_value = {
            "boosting": False,
            "start_time": None,
            "pending_final_segments": [],
        }
        manager.pending_final_segments.return_value = []
        quarantined = [("active-secret", "quarantined-secret")]
        real_rollback = db.session.rollback

        with (
            mock.patch.object(
                app_module,
                "quarantine_saved_credentials",
                return_value=quarantined,
            ) as quarantine,
            mock.patch.object(
                app_module,
                "restore_quarantined_credentials",
                return_value=True,
            ) as restore,
            mock.patch.object(
                app_module, "purge_quarantined_credentials", return_value=True
            ) as purge,
            mock.patch.object(
                app_module.boost_service, "get_or_create", return_value=manager
            ),
            mock.patch.object(app_module.boost_service, "detach") as detach,
            mock.patch.object(app_module.boost_service, "remove") as remove,
            mock.patch.object(app_module, "_clear_timers") as clear_timers,
            mock.patch.object(
                db.session,
                "commit",
                side_effect=SQLAlchemyError("forced account delete failure"),
            ),
            mock.patch.object(
                db.session, "rollback", wraps=real_rollback
            ) as rollback,
        ):
            response = self.client.post(
                "/accounts/remove",
                json={"acct_id": fixture["account_id"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        quarantine.assert_called_once_with(
            fixture["account_id"],
            fixture["steam_username"],
            include_legacy_machine_auth=True,
        )
        rollback.assert_called_once_with()
        restore.assert_called_once_with(quarantined)
        purge.assert_not_called()
        detach.assert_not_called()
        clear_timers.assert_not_called()
        remove.assert_not_called()
        manager.remove_completely.assert_not_called()

        with app_module.app.app_context():
            self.assertIsNotNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            self.assertIsNotNone(db.session.get(BoostGame, fixture["game_id"]))
            history = db.session.get(BoostLog, fixture["boost_log_id"])
            self.assertEqual(history.account_id, fixture["account_id"])
            self.assertIsNone(history.account_id_snapshot)
            self.assertIsNone(history.steam_username_snapshot)
            self.assertIsNone(history.owner_user_id_snapshot)
            self.assertIsNone(history.owner_username_snapshot)
            self.assertEqual(
                BoostLog.query.filter_by(user_id=user_id).count(), 1
            )

    def test_account_remove_postcommit_cleanup_failure_keeps_database_delete(self):
        user_id, headers = self._tracked_bearer(
            "account-remove-cleanup", is_admin=False
        )
        fixture = self._create_account_removal_fixture(user_id, "cleanup")
        manager = mock.Mock()
        manager.boosting = False
        manager.start_time = None
        manager.boost_snapshot.return_value = {
            "boosting": False,
            "start_time": None,
            "pending_final_segments": [],
        }
        manager.pending_final_segments.return_value = []
        manager.remove_completely.side_effect = RuntimeError(
            "forced runtime cleanup failure"
        )
        quarantined = [("active-secret", "quarantined-secret")]

        with (
            mock.patch.object(
                app_module,
                "quarantine_saved_credentials",
                return_value=quarantined,
            ),
            mock.patch.object(
                app_module, "purge_quarantined_credentials", return_value=True
            ) as purge,
            mock.patch.object(
                app_module.boost_service, "get_or_create", return_value=manager
            ),
            mock.patch.object(
                app_module.boost_service, "detach", return_value=manager
            ) as detach,
            mock.patch.object(app_module.boost_service, "remove") as remove,
            mock.patch.object(app_module, "_clear_timers") as clear_timers,
        ):
            response = self.client.post(
                "/accounts/remove",
                json={"acct_id": fixture["account_id"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json(), {"ok": True, "cleanup_warning": True})
        detach.assert_called_once_with(fixture["account_id"])
        clear_timers.assert_called_once_with(fixture["account_id"])
        manager.remove_completely.assert_called_once_with(
            include_legacy_machine_auth=True
        )
        remove.assert_not_called()
        purge.assert_called_once_with(quarantined)
        with app_module.app.app_context():
            self.assertIsNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            self.assertIsNone(db.session.get(BoostGame, fixture["game_id"]))
            historical = db.session.get(BoostLog, fixture["boost_log_id"])
            self.assertIsNotNone(historical)
            self.assertIsNone(historical.account_id)
            self.assertEqual(
                BoostLog.query.filter_by(user_id=user_id).count(), 1
            )

    def test_account_remove_only_deletes_legacy_token_for_last_username_reference(self):
        user_id, headers = self._tracked_bearer(
            "account-remove-shared-username", is_admin=False
        )
        shared_username = "shared-steam-login"
        first = self._create_account_removal_fixture(
            user_id, "shared-first", steam_username=shared_username
        )
        second = self._create_account_removal_fixture(
            user_id, "shared-second", steam_username=shared_username.upper()
        )
        idle_manager = mock.Mock()
        idle_manager.boost_snapshot.return_value = {
            "boosting": False,
            "pending_final_segments": [],
        }
        idle_manager.pending_final_segments.return_value = []

        with (
            mock.patch.object(
                app_module,
                "quarantine_saved_credentials",
                return_value=[],
            ) as quarantine,
            mock.patch.object(
                app_module, "purge_quarantined_credentials", return_value=True
            ),
            mock.patch.object(
                app_module.boost_service,
                "get_or_create",
                return_value=idle_manager,
            ),
            mock.patch.object(
                app_module.boost_service, "detach", return_value=None
            ),
            mock.patch.object(
                app_module.boost_service, "remove", return_value=True
            ) as remove,
            mock.patch.object(app_module, "_clear_timers"),
        ):
            first_response = self.client.post(
                "/accounts/remove",
                json={"acct_id": first["account_id"]},
                headers=headers,
            )
            self.assertEqual(first_response.status_code, 200)
            quarantine.assert_called_once_with(
                first["account_id"],
                first["steam_username"],
                include_legacy_machine_auth=False,
            )
            remove.assert_called_once_with(
                first["account_id"],
                first["steam_username"],
                include_legacy_machine_auth=False,
            )

            quarantine.reset_mock()
            remove.reset_mock()
            second_response = self.client.post(
                "/accounts/remove",
                json={"acct_id": second["account_id"]},
                headers=headers,
            )
            self.assertEqual(second_response.status_code, 200)
            quarantine.assert_called_once_with(
                second["account_id"],
                second["steam_username"],
                include_legacy_machine_auth=True,
            )
            remove.assert_called_once_with(
                second["account_id"],
                second["steam_username"],
                include_legacy_machine_auth=True,
            )

    def test_admin_user_delete_retains_financial_ledger_and_removes_operational_data(self):
        admin_id, headers = self._tracked_bearer(
            "delete-admin-success", is_admin=True
        )
        fixture = self._create_user_deletion_fixture("success")
        with app_module.app.app_context():
            ownerless_history = BoostLog(
                account_id=fixture["account_id"],
                user_id=None,
                started_at=datetime.utcnow() - timedelta(minutes=8),
                stopped_at=datetime.utcnow() - timedelta(minutes=7),
                duration_seconds=60,
                games_count=1,
                app_ids_json="[570]",
            )
            db.session.add(ownerless_history)
            db.session.commit()
            ownerless_history_id = ownerless_history.id
        app_module._plan_expiry_cache[fixture["user_id"]] = app_module.time.time()
        idle_manager = mock.Mock()
        idle_manager.boost_snapshot.return_value = {
            "boosting": False,
            "pending_final_segments": [],
        }
        idle_manager.pending_final_segments.return_value = []

        with (
            mock.patch.object(
                app_module.boost_service,
                "get_or_create",
                return_value=idle_manager,
            ),
            mock.patch.object(
                app_module.boost_service, "remove", return_value=True
            ) as remove,
        ):
            response = self.client.post(
                "/admin/users/delete",
                json={"user_id": fixture["user_id"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        remove.assert_called_once_with(
            fixture["account_id"],
            fixture["steam_username"],
            include_legacy_machine_auth=True,
        )
        self.assertNotIn(fixture["user_id"], app_module._plan_expiry_cache)

        with app_module.app.app_context():
            self.assertIsNone(db.session.get(User, fixture["user_id"]))
            completed = db.session.get(Payment, fixture["completed_id"])
            checkout = db.session.get(Payment, fixture["checkout_id"])
            self.assertIsNotNone(completed)
            self.assertIsNotNone(checkout)

            for field, value in fixture["completed_fields"].items():
                self.assertEqual(getattr(completed, field), value, field)
            for payment in (completed, checkout):
                self.assertIsNone(payment.user_id)
                self.assertEqual(
                    payment.owner_user_id_snapshot, fixture["user_id"]
                )
                self.assertEqual(
                    payment.owner_username_snapshot, fixture["username"]
                )
                self.assertIsNotNone(payment.owner_detached_at)

                audits = PaymentAuditLog.query.filter_by(
                    payment_id=payment.id,
                    action="owner_detached_on_user_delete",
                ).all()
                self.assertEqual(len(audits), 1)
                self.assertEqual(audits[0].actor_user_id, admin_id)
                self.assertEqual(audits[0].actor_username, "delete-admin-success")
                self.assertEqual(audits[0].from_status, fixture[
                    "completed_fields"
                ]["status"] if payment.id == completed.id else "checkout_started")
                self.assertEqual(audits[0].to_status, payment.status)

            self.assertEqual(checkout.status, "cancelled")
            self.assertIsNone(checkout.match_token)
            self.assertEqual(
                checkout.verification_error, "owner_deleted_before_payment"
            )
            self.assertIsNone(checkout.next_verification_at)
            self.assertIsNone(checkout.verification_lock_until)

            self.assertIsNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            self.assertIsNone(db.session.get(BoostGame, fixture["game_id"]))
            history = db.session.get(BoostLog, fixture["boost_log_id"])
            self.assertIsNotNone(history)
            self.assertIsNone(history.account_id)
            self.assertIsNone(history.user_id)
            self.assertEqual(
                history.account_id_snapshot,
                fixture["account_id"],
            )
            self.assertEqual(
                history.steam_username_snapshot,
                fixture["steam_username"],
            )
            self.assertEqual(
                history.owner_user_id_snapshot,
                fixture["user_id"],
            )
            self.assertEqual(
                history.owner_username_snapshot,
                fixture["username"],
            )
            self.assertEqual(history.duration_seconds, 60)
            self.assertEqual(history.app_ids_json, "[730]")
            ownerless = db.session.get(BoostLog, ownerless_history_id)
            self.assertIsNotNone(ownerless)
            self.assertIsNone(ownerless.account_id)
            self.assertIsNone(ownerless.user_id)
            self.assertEqual(
                ownerless.account_id_snapshot,
                fixture["account_id"],
            )
            self.assertEqual(
                ownerless.steam_username_snapshot,
                fixture["steam_username"],
            )
            self.assertEqual(
                ownerless.owner_user_id_snapshot,
                fixture["user_id"],
            )
            self.assertEqual(
                ownerless.owner_username_snapshot,
                fixture["username"],
            )
            self.assertIsNone(db.session.get(UserSession, fixture["session_id"]))
            self.assertIsNone(db.session.get(RevokedToken, fixture["revoked_id"]))

    def test_admin_user_delete_blocks_cross_owner_history_before_runtime_side_effects(self):
        _, headers = self._tracked_bearer(
            "delete-admin-owner-mismatch", is_admin=True
        )
        fixture = self._create_user_deletion_fixture("owner-mismatch")
        with app_module.app.app_context():
            other_user = User(
                username="delete-history-owner-mismatch",
                email="delete-history-owner-mismatch@example.test",
                password_hash="unused",
                is_verified=True,
            )
            db.session.add(other_user)
            db.session.flush()
            mismatch = BoostLog(
                account_id=fixture["account_id"],
                user_id=other_user.id,
                started_at=datetime.utcnow() - timedelta(minutes=3),
                stopped_at=datetime.utcnow() - timedelta(minutes=2),
                duration_seconds=60,
                games_count=1,
                app_ids_json="[730]",
            )
            db.session.add(mismatch)
            db.session.commit()
            mismatch_id = mismatch.id

        with (
            mock.patch.object(
                app_module.boost_service, "get_or_create"
            ) as get_manager,
            mock.patch.object(
                app_module, "quarantine_saved_credentials"
            ) as quarantine,
        ):
            response = self.client.post(
                "/admin/users/delete",
                json={"user_id": fixture["user_id"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 409, response.get_data(as_text=True))
        get_manager.assert_not_called()
        quarantine.assert_not_called()
        with app_module.app.app_context():
            self.assertIsNotNone(db.session.get(User, fixture["user_id"]))
            self.assertIsNotNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            self.assertIsNotNone(db.session.get(BoostLog, mismatch_id))
            self.assertEqual(
                BoostLog.query.filter_by(account_id=fixture["account_id"]).count(),
                2,
            )

    def test_admin_user_update_strictly_validates_target_and_mutations(self):
        admin_id, admin_headers = self._tracked_bearer(
            "update-admin-validation", is_admin=True
        )
        target_id, target_headers = self._tracked_bearer(
            "update-user-validation", is_admin=False
        )

        anonymous = self.client.post(
            "/admin/users/update",
            json={"user_id": target_id, "plan": "basic"},
            headers={"Authorization": "Bearer invalid"},
        )
        real_user_lock = app_module._user_operation_lock
        with mock.patch.object(
            app_module,
            "_user_operation_lock",
            side_effect=real_user_lock,
        ) as operation_lock:
            non_admin = self.client.post(
                "/admin/users/update",
                json={"user_id": admin_id, "plan": "basic"},
                headers=target_headers,
            )
        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(non_admin.status_code, 403)
        self.assertEqual(
            [call.args[0] for call in operation_lock.call_args_list],
            [target_id],
        )

        invalid_bodies = [
            None,
            [],
            "not-an-object",
            {},
            {"user_id": None, "plan": "basic"},
            {"user_id": True, "plan": "basic"},
            {"user_id": 0, "plan": "basic"},
            {"user_id": -1, "plan": "basic"},
            {"user_id": str(target_id), "plan": "basic"},
            {"user_id": [target_id], "is_admin": False},
            {"user_id": {}, "plan": "basic"},
            {"user_id": 1.5, "plan": "basic"},
        ]
        for body in invalid_bodies:
            with self.subTest(body=body):
                response = self.client.post(
                    "/admin/users/update", json=body, headers=admin_headers
                )
                self.assertEqual(
                    response.status_code, 400, response.get_data(as_text=True)
                )

        invalid_mutations = [
            {"user_id": target_id},
            {"user_id": target_id, "plan": None},
            {"user_id": target_id, "plan": "enterprise"},
            {"user_id": target_id, "plan": True},
            {"user_id": target_id, "plan": []},
            {"user_id": target_id, "is_admin": None},
            {"user_id": target_id, "is_admin": 0},
            {"user_id": target_id, "is_admin": 1},
            {"user_id": target_id, "is_admin": "false"},
            {"user_id": target_id, "is_admin": []},
        ]
        for body in invalid_mutations:
            with self.subTest(body=body):
                response = self.client.post(
                    "/admin/users/update", json=body, headers=admin_headers
                )
                self.assertEqual(
                    response.status_code, 400, response.get_data(as_text=True)
                )

        self_demote = self.client.post(
            "/admin/users/update",
            json={"user_id": admin_id, "is_admin": False},
            headers=admin_headers,
        )
        missing = self.client.post(
            "/admin/users/update",
            json={"user_id": 2_147_483_647, "plan": "basic"},
            headers=admin_headers,
        )

        self.assertEqual(self_demote.status_code, 409)
        self.assertEqual(missing.status_code, 404)
        with app_module.app.app_context():
            admin = db.session.get(User, admin_id)
            target = db.session.get(User, target_id)
            self.assertTrue(admin.is_admin)
            self.assertEqual(target.plan, "free")
            self.assertFalse(target.is_admin)

    def test_admin_user_update_serializes_target_and_applies_valid_changes(self):
        _, admin_headers = self._tracked_bearer(
            "update-admin-success", is_admin=True
        )
        target_id, _ = self._tracked_bearer(
            "update-user-success", is_admin=False
        )

        real_user_lock = app_module._user_operation_lock
        with mock.patch.object(
            app_module,
            "_user_operation_lock",
            side_effect=real_user_lock,
        ) as operation_lock:
            response = self.client.post(
                "/admin/users/update",
                json={
                    "user_id": target_id,
                    "plan": "premium",
                    "is_admin": True,
                },
                headers=admin_headers,
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(
            [call.args[0] for call in operation_lock.call_args_list],
            [target_id],
        )
        with app_module.app.app_context():
            target = db.session.get(User, target_id)
            self.assertEqual(target.plan, "premium")
            self.assertIsNotNone(target.plan_activated_at)
            self.assertTrue(target.is_admin)

    def test_admin_user_delete_strictly_validates_auth_identity_and_target(self):
        admin_id, admin_headers = self._tracked_bearer(
            "delete-admin-validation", is_admin=True
        )
        user_id, user_headers = self._tracked_bearer(
            "delete-user-validation", is_admin=False
        )
        other_admin_id, _ = self._tracked_bearer(
            "delete-other-admin", is_admin=True
        )

        anonymous = self.client.post(
            "/admin/users/delete",
            json={"user_id": other_admin_id},
            headers={"Authorization": "Bearer invalid"},
        )
        real_user_lock = app_module._user_operation_lock
        with mock.patch.object(
            app_module,
            "_user_operation_lock",
            side_effect=real_user_lock,
        ) as operation_lock:
            non_admin = self.client.post(
                "/admin/users/delete",
                json={"user_id": other_admin_id},
                headers=user_headers,
            )
        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(non_admin.status_code, 403)
        self.assertEqual(
            [call.args[0] for call in operation_lock.call_args_list],
            [user_id],
        )

        invalid_bodies = [
            None,
            [],
            {},
            {"user_id": None},
            {"user_id": True},
            {"user_id": 0},
            {"user_id": -1},
            {"user_id": str(other_admin_id)},
            {"user_id": {}},
            {"user_id": 1.5},
        ]
        with mock.patch.object(app_module.boost_service, "remove") as remove:
            for body in invalid_bodies:
                with self.subTest(body=body):
                    response = self.client.post(
                        "/admin/users/delete", json=body, headers=admin_headers
                    )
                    self.assertEqual(
                        response.status_code, 400, response.get_data(as_text=True)
                    )

            self_delete = self.client.post(
                "/admin/users/delete",
                json={"user_id": admin_id},
                headers=admin_headers,
            )
            admin_delete = self.client.post(
                "/admin/users/delete",
                json={"user_id": other_admin_id},
                headers=admin_headers,
            )
            missing = self.client.post(
                "/admin/users/delete",
                json={"user_id": 2_147_483_647},
                headers=admin_headers,
            )

        self.assertEqual(self_delete.status_code, 409)
        self.assertEqual(admin_delete.status_code, 409)
        self.assertEqual(missing.status_code, 404)
        remove.assert_not_called()
        with app_module.app.app_context():
            self.assertIsNotNone(db.session.get(User, admin_id))
            self.assertIsNotNone(db.session.get(User, other_admin_id))

    def test_admin_user_delete_database_error_rolls_back_every_database_change(self):
        _, headers = self._tracked_bearer("delete-admin-rollback", is_admin=True)
        fixture = self._create_user_deletion_fixture("rollback")
        app_module._plan_expiry_cache[fixture["user_id"]] = app_module.time.time()
        real_rollback = db.session.rollback
        quarantined = [("active-secret", "quarantined-secret")]
        idle_manager = mock.Mock()
        idle_manager.boost_snapshot.return_value = {
            "boosting": False,
            "pending_final_segments": [],
        }
        idle_manager.pending_final_segments.return_value = []

        with (
            mock.patch.object(
                app_module.boost_service,
                "get_or_create",
                return_value=idle_manager,
            ),
            mock.patch.object(
                app_module.boost_service, "remove", return_value=True
            ) as remove,
            mock.patch.object(
                app_module,
                "quarantine_saved_credentials",
                return_value=quarantined,
            ),
            mock.patch.object(
                app_module, "restore_quarantined_credentials", return_value=True
            ) as restore,
            mock.patch.object(
                app_module, "purge_quarantined_credentials", return_value=True
            ) as purge,
            mock.patch.object(
                db.session,
                "commit",
                side_effect=SQLAlchemyError("forced delete commit failure"),
            ),
            mock.patch.object(
                db.session, "rollback", wraps=real_rollback
            ) as rollback,
        ):
            response = self.client.post(
                "/admin/users/delete",
                json={"user_id": fixture["user_id"]},
                headers=headers,
            )

        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        self.assertEqual(rollback.call_count, 2)
        restore.assert_called_once_with(quarantined)
        purge.assert_not_called()
        remove.assert_not_called()
        self.assertIn(fixture["user_id"], app_module._plan_expiry_cache)
        with app_module.app.app_context():
            self.assertIsNotNone(db.session.get(User, fixture["user_id"]))
            for payment_id in (
                fixture["completed_id"],
                fixture["checkout_id"],
            ):
                payment = db.session.get(Payment, payment_id)
                self.assertEqual(payment.user_id, fixture["user_id"])
                self.assertIsNone(payment.owner_user_id_snapshot)
                self.assertIsNone(payment.owner_username_snapshot)
                self.assertIsNone(payment.owner_detached_at)
                self.assertEqual(
                    PaymentAuditLog.query.filter_by(
                        payment_id=payment_id,
                        action="owner_detached_on_user_delete",
                    ).count(),
                    0,
                )
            self.assertEqual(
                db.session.get(Payment, fixture["checkout_id"]).status,
                "checkout_started",
            )
            self.assertIsNotNone(
                db.session.get(SteamAccount, fixture["account_id"])
            )
            history = db.session.get(BoostLog, fixture["boost_log_id"])
            self.assertIsNotNone(history)
            self.assertEqual(history.account_id, fixture["account_id"])
            self.assertEqual(history.user_id, fixture["user_id"])
            self.assertIsNone(history.account_id_snapshot)
            self.assertIsNone(history.steam_username_snapshot)
            self.assertIsNone(history.owner_user_id_snapshot)
            self.assertIsNone(history.owner_username_snapshot)
            self.assertIsNotNone(db.session.get(UserSession, fixture["session_id"]))
            self.assertIsNotNone(db.session.get(RevokedToken, fixture["revoked_id"]))

    def test_missing_direct_owner_finishes_verified_unmatched_and_is_not_reclaimed(self):
        missing_user_id = 900_001
        order_id = "order-missing-direct-owner"
        payment_id = self._insert_legacy_payment_with_missing_owner(
            user_id=missing_user_id,
            amount=29.99,
            plan="basic",
            status="verification_pending",
            transaction_id=order_id,
            match_token=TOKEN,
            next_verification_at=datetime.utcnow() - timedelta(seconds=1),
            created_at=datetime.utcnow(),
        )

        with mock.patch.object(
            app_module.shopier_lib,
            "get_order",
            return_value=order_payload(order_id),
        ):
            self.assertEqual(app_module.process_due_payment_verifications(1), 1)
            self.assertEqual(app_module.process_due_payment_verifications(1), 0)

        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "unmatched")
            self.assertIsNone(payment.user_id)
            self.assertIsNone(payment.match_token)
            self.assertEqual(payment.owner_user_id_snapshot, missing_user_id)
            self.assertIsNone(payment.owner_username_snapshot)
            self.assertIsNotNone(payment.owner_detached_at)
            self.assertEqual(payment.verification_error, "owner_not_found")
            self.assertEqual(payment.verification_last_http_status, 200)
            self.assertEqual(payment.verified_amount_minor, 2999)
            self.assertIsNotNone(payment.verified_at)
            self.assertIsNone(payment.next_verification_at)
            self.assertIsNone(payment.verification_lock_until)

    def test_missing_checkout_owner_preserves_placeholder_and_cancels_checkout(self):
        missing_user_id = 900_002
        token = "HB-" + "B" * 32
        order_id = "order-missing-checkout-owner"
        now = datetime.utcnow()
        with app_module.app.app_context():
            placeholder = Payment(
                status="verification_pending",
                transaction_id=order_id,
                shopier_event="order.created",
                webhook_received_at=now,
                next_verification_at=now - timedelta(seconds=1),
            )
            db.session.add(placeholder)
            db.session.commit()
            placeholder_id = placeholder.id
        checkout_id = self._insert_legacy_payment_with_missing_owner(
            user_id=missing_user_id,
            owner_user_id_snapshot=missing_user_id,
            owner_username_snapshot="deleted-checkout-owner",
            amount=29.99,
            plan="basic",
            status="checkout_started",
            match_token=token,
            created_at=now,
        )

        with mock.patch.object(
            app_module.shopier_lib,
            "get_order",
            return_value=order_payload(order_id, token=token),
        ):
            self.assertEqual(app_module.process_due_payment_verifications(1), 1)
            self.assertEqual(app_module.process_due_payment_verifications(1), 0)

        with app_module.app.app_context():
            checkout = db.session.get(Payment, checkout_id)
            placeholder = db.session.get(Payment, placeholder_id)
            self.assertIsNotNone(checkout)
            self.assertIsNotNone(placeholder)
            self.assertEqual(checkout.status, "cancelled")
            self.assertIsNone(checkout.user_id)
            self.assertIsNone(checkout.match_token)
            self.assertEqual(checkout.verification_error, "owner_not_found")
            self.assertIsNotNone(checkout.owner_detached_at)

            self.assertEqual(placeholder.status, "unmatched")
            self.assertIsNone(placeholder.user_id)
            self.assertIsNone(placeholder.match_token)
            self.assertEqual(
                placeholder.owner_user_id_snapshot, missing_user_id
            )
            self.assertEqual(
                placeholder.owner_username_snapshot,
                "deleted-checkout-owner",
            )
            self.assertIsNotNone(placeholder.owner_detached_at)
            self.assertEqual(placeholder.verification_error, "owner_not_found")
            self.assertEqual(placeholder.verified_amount_minor, 2999)
            self.assertIsNotNone(placeholder.verified_at)
            self.assertIsNone(placeholder.next_verification_at)
            self.assertIsNone(placeholder.verification_lock_until)

    def test_integrity_conflict_finalization_fails_closed_without_blind_retry(self):
        for attempt in (1, app_module.SHOPIER_MAX_ATTEMPTS):
            order_id = f"order-integrity-finalize-{attempt}"
            with self.subTest(attempt=attempt), app_module.app.app_context():
                payment = Payment(
                    status="verification_pending",
                    transaction_id=order_id,
                    verification_attempts=attempt,
                    verification_lock_until=datetime.utcnow() + timedelta(minutes=1),
                )
                db.session.add(payment)
                db.session.commit()
                payment_id = payment.id

            conflict = IntegrityError(
                "UPDATE payments", {}, RuntimeError("forced finalize race")
            )
            with (
                mock.patch.object(
                    app_module.shopier_lib,
                    "get_order",
                    return_value=order_payload(order_id),
                ),
                mock.patch.object(
                    app_module,
                    "_finalize_canonical_order",
                    side_effect=conflict,
                ),
            ):
                self.assertFalse(app_module._process_payment_claim({
                    "payment_id": payment_id,
                    "order_id": order_id,
                    "attempt": attempt,
                }))

            with app_module.app.app_context():
                payment = db.session.get(Payment, payment_id)
                self.assertIsNone(payment.verification_lock_until)
                self.assertEqual(payment.status, "verification_failed")
                self.assertEqual(
                    payment.verification_error,
                    "finalize_integrity_error",
                )
                self.assertIsNone(payment.next_verification_at)

    def test_postgresql_transaction_retry_never_replays_quota_side_effects(self):
        retryable = RuntimeError("redacted")
        retryable.sqlstate = "40P01"
        post_commit = {
            "user_id": 31,
            "payment_id": 47,
            "order_id": "order-transaction-retry",
            "plan": "basic",
            "amount_minor": 2999,
            "plan_changed": True,
        }

        with (
            app_module.app.app_context(),
            mock.patch.object(
                db.engine.dialect,
                "name",
                "postgresql",
            ),
            mock.patch.object(
                app_module,
                "_finalize_canonical_order_transaction",
                side_effect=[retryable, (True, post_commit)],
            ) as transaction,
            mock.patch.object(
                app_module,
                "_payment_transaction_retry_delay",
                return_value=0,
            ),
            mock.patch.object(app_module.gevent, "sleep") as sleep,
            mock.patch.object(
                app_module,
                "_reconcile_user_quota_locked",
                return_value={"ok": True},
            ) as reconcile,
        ):
            self.assertTrue(
                app_module._finalize_canonical_order(47, 3, mock.sentinel.canonical)
            )

        self.assertEqual(transaction.call_count, 2)
        sleep.assert_called_once_with(0.0)
        reconcile.assert_called_once_with(
            31,
            "verified_payment_plan_change",
            enforce=True,
        )

    def test_finalization_rechecks_attempt_after_lock_target_discovery(self):
        order_id = "order-post-lock-attempt-fence"
        with app_module.app.app_context():
            user = User(
                username="post-lock-fence-user",
                email="post-lock-fence@example.test",
                password_hash="unused",
                plan="free",
            )
            db.session.add(user)
            db.session.flush()
            payment = Payment(
                user_id=user.id,
                amount=29.99,
                plan="basic",
                status="verification_pending",
                transaction_id=order_id,
                match_token=TOKEN,
                verification_attempts=1,
            )
            db.session.add(payment)
            db.session.commit()
            user_id = user.id
            payment_id = payment.id
            canonical = app_module.validate_canonical_order(
                order_payload(order_id),
                expected_order_id=order_id,
                products=app_module._shopier_products(),
            )
            real_locked_payments = app_module._locked_payment_rows

            def supersede_claim_before_lock(*payment_ids):
                db.session.execute(
                    app_module.update(Payment)
                    .where(Payment.id == payment_id)
                    .values(
                        verification_attempts=2,
                        verification_error="newer_claim_active",
                    )
                )
                db.session.commit()
                return real_locked_payments(*payment_ids)

            with mock.patch.object(
                app_module,
                "_locked_payment_rows",
                side_effect=supersede_claim_before_lock,
            ):
                self.assertFalse(
                    app_module._finalize_canonical_order(
                        payment_id,
                        1,
                        canonical,
                    )
                )

            db.session.expire_all()
            self.assertEqual(db.session.get(User, user_id).plan, "free")
            current = db.session.get(Payment, payment_id)
            self.assertEqual(current.status, "verification_pending")
            self.assertEqual(current.verification_attempts, 2)
            self.assertEqual(current.verification_error, "newer_claim_active")

    def test_user_id_without_bound_token_cannot_activate_a_plan(self):
        order_id = "order-unbound-legacy-owner"
        with app_module.app.app_context():
            user = User(
                username="unbound-legacy-owner",
                email="unbound-legacy-owner@example.test",
                password_hash="unused",
                plan="free",
            )
            db.session.add(user)
            db.session.flush()
            payment = Payment(
                user_id=user.id,
                owner_user_id_snapshot=user.id,
                owner_username_snapshot=user.username,
                amount=29.99,
                plan="basic",
                status="verification_pending",
                transaction_id=order_id,
                match_token=None,
                verification_attempts=1,
            )
            db.session.add(payment)
            db.session.commit()
            user_id = user.id
            payment_id = payment.id

            canonical = app_module.validate_canonical_order(
                order_payload(order_id, token="HB-" + "D" * 32),
                expected_order_id=order_id,
                products=app_module._shopier_products(),
            )
            self.assertTrue(
                app_module._finalize_canonical_order(
                    payment_id,
                    1,
                    canonical,
                )
            )

            db.session.expire_all()
            self.assertEqual(db.session.get(User, user_id).plan, "free")
            current = db.session.get(Payment, payment_id)
            self.assertEqual(current.status, "unmatched")
            self.assertIsNone(current.user_id)
            self.assertIsNone(current.match_token)
            self.assertEqual(
                current.verification_error,
                "active_token_not_found",
            )

    def test_post_commit_quota_exception_does_not_reclassify_paid_order(self):
        order_id = "order-postcommit-quota-exception"
        with app_module.app.app_context():
            user = User(
                username="postcommit-quota-owner",
                email="postcommit-quota-owner@example.test",
                password_hash="unused",
                plan="free",
            )
            db.session.add(user)
            db.session.flush()
            payment = Payment(
                user_id=user.id,
                owner_user_id_snapshot=user.id,
                owner_username_snapshot=user.username,
                amount=29.99,
                plan="basic",
                status="verification_pending",
                transaction_id=order_id,
                match_token=TOKEN,
                verification_attempts=1,
            )
            db.session.add(payment)
            db.session.commit()
            user_id = user.id
            payment_id = payment.id
            canonical = app_module.validate_canonical_order(
                order_payload(order_id),
                expected_order_id=order_id,
                products=app_module._shopier_products(),
            )

            lock_state = {"depth": 0}
            lock_events = []

            class _TrackingLock:
                def __enter__(self):
                    lock_state["depth"] += 1
                    lock_events.append(("enter", lock_state["depth"]))
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    lock_events.append(("exit", lock_state["depth"]))
                    lock_state["depth"] -= 1
                    return False

            def fail_reconcile(*_args, **_kwargs):
                lock_events.append(("reconcile", lock_state["depth"]))
                raise RuntimeError("forced post-commit failure")

            def record_watchdog(*_args, **_kwargs):
                lock_events.append(("watchdog", lock_state["depth"]))

            with (
                mock.patch.object(
                    app_module,
                    "_user_operation_lock",
                    side_effect=lambda _user_id: _TrackingLock(),
                ),
                mock.patch.object(
                    app_module,
                    "_reconcile_user_quota_locked",
                    side_effect=fail_reconcile,
                ),
                mock.patch.object(
                    app_module,
                    "_install_user_quota_watchdog",
                    side_effect=record_watchdog,
                ) as install_watchdog,
            ):
                self.assertTrue(
                    app_module._finalize_canonical_order(
                        payment_id,
                        1,
                        canonical,
                    )
                )

            db.session.expire_all()
            self.assertEqual(db.session.get(User, user_id).plan, "basic")
            current = db.session.get(Payment, payment_id)
            self.assertEqual(current.status, "completed")
            self.assertEqual(current.transaction_id, order_id)
            install_watchdog.assert_called_once_with(
                user_id,
                app_module.QUOTA_RECONCILE_RETRY_SECONDS,
                "reconcile_retry",
            )
            self.assertEqual(
                lock_events,
                [
                    ("enter", 1),
                    ("exit", 1),
                    ("enter", 1),
                    ("reconcile", 1),
                    ("watchdog", 1),
                    ("exit", 1),
                ],
            )

    def test_finalization_locks_user_before_payment_rows(self):
        order_id = "order-deterministic-lock-order"
        with app_module.app.app_context():
            user = User(
                username="lock-order-user",
                email="lock-order@example.test",
                password_hash="unused",
                plan="free",
            )
            db.session.add(user)
            db.session.flush()
            payment = Payment(
                user_id=user.id,
                amount=29.99,
                plan="basic",
                status="verification_pending",
                transaction_id=order_id,
                match_token=TOKEN,
                verification_attempts=1,
            )
            db.session.add(payment)
            db.session.commit()
            user_id = user.id
            payment_id = payment.id
            canonical = app_module.validate_canonical_order(
                order_payload(order_id),
                expected_order_id=order_id,
                products=app_module._shopier_products(),
            )
            events = []
            real_locked_user = app_module._locked_user
            real_locked_payments = app_module._locked_payment_rows

            def record_user(owner_id):
                events.append(("user", owner_id))
                return real_locked_user(owner_id)

            def record_payments(*payment_ids):
                events.append(("payments", tuple(payment_ids)))
                return real_locked_payments(*payment_ids)

            with (
                mock.patch.object(
                    app_module,
                    "_locked_user",
                    side_effect=record_user,
                ),
                mock.patch.object(
                    app_module,
                    "_locked_payment_rows",
                    side_effect=record_payments,
                ),
                mock.patch.object(
                    app_module,
                    "_reconcile_user_quota_locked",
                    return_value={"ok": True},
                ),
            ):
                self.assertTrue(
                    app_module._finalize_canonical_order(
                        payment_id,
                        1,
                        canonical,
                    )
                )

        self.assertEqual(events[0], ("user", user_id))
        self.assertEqual(events[1][0], "payments")
        self.assertIn(payment_id, events[1][1])

    def test_payment_lock_helper_returns_rows_in_ascending_id_order(self):
        with app_module.app.app_context():
            first = Payment(status="cancelled")
            second = Payment(status="cancelled")
            db.session.add_all([first, second])
            db.session.commit()
            locked = app_module._locked_payment_rows(second.id, first.id)
            self.assertEqual(list(locked), [first.id, second.id])
            db.session.rollback()

    def test_unknown_finalization_error_is_terminal_and_redacts_exception(self):
        order_id = "order-terminal-internal-error"
        secret_marker = "HB-DO-NOT-LOG-THIS-SECRET"
        with app_module.app.app_context():
            payment = Payment(
                status="verification_pending",
                transaction_id=order_id,
                verification_attempts=1,
                verification_lock_until=(
                    datetime.utcnow() + timedelta(minutes=1)
                ),
            )
            db.session.add(payment)
            db.session.commit()
            payment_id = payment.id

        with (
            mock.patch.object(
                app_module.shopier_lib,
                "get_order",
                return_value=order_payload(order_id),
            ),
            mock.patch.object(
                app_module,
                "_finalize_canonical_order",
                side_effect=RuntimeError(secret_marker),
            ),
            self.assertLogs(app_module.logger, level="ERROR") as captured,
        ):
            self.assertFalse(app_module._process_payment_claim({
                "payment_id": payment_id,
                "order_id": order_id,
                "attempt": 1,
            }))

        self.assertNotIn(secret_marker, "\n".join(captured.output))
        with app_module.app.app_context():
            payment = db.session.get(Payment, payment_id)
            self.assertEqual(payment.status, "verification_failed")
            self.assertEqual(payment.verification_error, "internal_finalize_error")
            self.assertIsNone(payment.next_verification_at)
            self.assertIsNone(payment.verification_lock_until)

    def test_silent_finalization_stall_has_bounded_retry_and_terminal_failure(self):
        for attempt in (1, app_module.SHOPIER_MAX_ATTEMPTS):
            order_id = f"order-silent-finalize-{attempt}"
            with self.subTest(attempt=attempt), app_module.app.app_context():
                payment = Payment(
                    status="verification_pending",
                    transaction_id=order_id,
                    verification_attempts=attempt,
                    verification_lock_until=datetime.utcnow() + timedelta(minutes=1),
                )
                db.session.add(payment)
                db.session.commit()
                payment_id = payment.id

            with (
                mock.patch.object(
                    app_module.shopier_lib,
                    "get_order",
                    return_value=order_payload(order_id),
                ),
                mock.patch.object(
                    app_module, "_finalize_canonical_order", return_value=False
                ),
            ):
                self.assertFalse(app_module._process_payment_claim({
                    "payment_id": payment_id,
                    "order_id": order_id,
                    "attempt": attempt,
                }))

            with app_module.app.app_context():
                payment = db.session.get(Payment, payment_id)
                self.assertIsNone(payment.verification_lock_until)
                if attempt < app_module.SHOPIER_MAX_ATTEMPTS:
                    self.assertEqual(payment.status, "verification_pending")
                    self.assertEqual(
                        payment.verification_error,
                        "finalize_without_transition",
                    )
                    self.assertIsNotNone(payment.next_verification_at)
                else:
                    self.assertEqual(payment.status, "verification_failed")
                    self.assertEqual(
                        payment.verification_error,
                        "retry_exhausted:finalize_without_transition",
                    )
                    self.assertIsNone(payment.next_verification_at)

    def test_placeholder_merge_moves_audit_and_preserves_admin_hidden(self):
        token = "HB-" + "C" * 32
        order_id = "order-placeholder-merge"
        now = datetime.utcnow()
        with app_module.app.app_context():
            user = User(
                username="placeholder-owner",
                email="placeholder-owner@example.test",
                password_hash="unused",
                plan="free",
                is_verified=True,
            )
            db.session.add(user)
            db.session.flush()
            checkout = Payment(
                user_id=user.id,
                owner_user_id_snapshot=user.id,
                owner_username_snapshot=user.username,
                amount=29.99,
                plan="basic",
                status="checkout_started",
                match_token=token,
                created_at=now,
            )
            placeholder = Payment(
                status="verification_pending",
                transaction_id=order_id,
                shopier_webhook_id="merge-subscription",
                shopier_event="order.created",
                shopier_account_id="merge-account",
                shopier_timestamp=1_720_000_001,
                webhook_body_sha256="c" * 64,
                webhook_received_at=now,
                next_verification_at=now - timedelta(seconds=1),
                admin_hidden=True,
            )
            db.session.add_all([checkout, placeholder])
            db.session.flush()
            audit = PaymentAuditLog(
                payment_id=placeholder.id,
                actor_user_id=None,
                actor_username="system",
                action="webhook_received",
                from_status=None,
                to_status="verification_pending",
                reason="Signed webhook received.",
            )
            db.session.add(audit)
            db.session.commit()
            user_id = user.id
            checkout_id = checkout.id
            placeholder_id = placeholder.id
            audit_id = audit.id

        with mock.patch.object(
            app_module.shopier_lib,
            "get_order",
            return_value=order_payload(order_id, token=token),
        ):
            self.assertEqual(app_module.process_due_payment_verifications(1), 1)

        with app_module.app.app_context():
            self.assertIsNone(db.session.get(Payment, placeholder_id))
            checkout = db.session.get(Payment, checkout_id)
            self.assertEqual(checkout.status, "completed")
            self.assertEqual(checkout.transaction_id, order_id)
            self.assertTrue(checkout.admin_hidden)
            self.assertEqual(checkout.shopier_webhook_id, "merge-subscription")
            self.assertEqual(checkout.verified_amount_minor, 2999)
            self.assertIsNotNone(checkout.verified_at)
            self.assertEqual(db.session.get(User, user_id).plan, "basic")
            audit = db.session.get(PaymentAuditLog, audit_id)
            self.assertEqual(audit.payment_id, checkout_id)
            self.assertEqual(
                PaymentAuditLog.query.filter_by(payment_id=placeholder_id).count(),
                0,
            )

    def test_schema_bridge_adds_backfills_and_preserves_owner_snapshots_idempotently(self):
        with app_module.app.app_context():
            user = User(
                username="legacy-owner",
                email="legacy-owner@example.test",
                password_hash="unused",
                is_verified=True,
            )
            db.session.add(user)
            db.session.flush()
            payment = Payment(
                user_id=user.id,
                amount=29.99,
                plan="basic",
                status="completed",
                transaction_id="legacy-owner-order",
            )
            db.session.add(payment)
            db.session.commit()
            user_id = user.id
            payment_id = payment.id
            db.session.remove()

            with db.engine.begin() as conn:
                conn.exec_driver_sql(
                    "ALTER TABLE payments DROP COLUMN owner_user_id_snapshot"
                )
                conn.exec_driver_sql(
                    "ALTER TABLE payments DROP COLUMN owner_username_snapshot"
                )
                conn.exec_driver_sql(
                    "ALTER TABLE payments DROP COLUMN owner_detached_at"
                )

            self.assertNotIn(
                "owner_user_id_snapshot",
                {column["name"] for column in inspect(db.engine).get_columns("payments")},
            )
            repair_legacy_fixture(app_module)

            columns = {
                column["name"] for column in inspect(db.engine).get_columns("payments")
            }
            self.assertTrue({
                "owner_user_id_snapshot",
                "owner_username_snapshot",
                "owner_detached_at",
            }.issubset(columns))
            row = db.session.execute(
                db.text(
                    "SELECT owner_user_id_snapshot, owner_username_snapshot, "
                    "owner_detached_at FROM payments WHERE id = :payment_id"
                ),
                {"payment_id": payment_id},
            ).mappings().one()
            self.assertEqual(row["owner_user_id_snapshot"], user_id)
            self.assertEqual(row["owner_username_snapshot"], "legacy-owner")
            self.assertIsNone(row["owner_detached_at"])

            db.session.execute(
                db.text("UPDATE users SET username = 'renamed-owner' WHERE id = :id"),
                {"id": user_id},
            )
            db.session.commit()
            repair_legacy_fixture(app_module)
            repair_legacy_fixture(app_module)
            row = db.session.execute(
                db.text(
                    "SELECT owner_user_id_snapshot, owner_username_snapshot "
                    "FROM payments WHERE id = :payment_id"
                ),
                {"payment_id": payment_id},
            ).mappings().one()
            self.assertEqual(row["owner_user_id_snapshot"], user_id)
            self.assertEqual(row["owner_username_snapshot"], "legacy-owner")

    def test_schema_bridge_is_idempotent_and_indexes_exist(self):
        with app_module.app.app_context():
            repair_legacy_fixture(app_module)
            repair_legacy_fixture(app_module)
            indexes = {
                row[1]
                for row in db.session.execute(db.text("PRAGMA index_list('payments')"))
            }
            self.assertIn("ux_payments_match_token", indexes)
            self.assertIn("ux_payments_transaction_id", indexes)
            self.assertIn("ux_payments_one_open_checkout", indexes)
            self.assertIn("ix_payments_verification_due", indexes)

    def test_schema_bridge_adds_and_conservatively_backfills_plan_window(self):
        created_at = datetime(2024, 1, 2, 3, 4, 5)
        with app_module.app.app_context():
            db.session.remove()
            with db.engine.begin() as conn:
                conn.exec_driver_sql(
                    "ALTER TABLE users DROP COLUMN plan_activated_at"
                )
                conn.execute(db.text(
                    "INSERT INTO users "
                    "(username, email, password_hash, plan, is_verified, created_at) "
                    "VALUES "
                    "('legacy-basic', 'legacy-basic@example.test', 'x', "
                    "'basic', 1, :created_at), "
                    "('legacy-premium', 'legacy-premium@example.test', 'x', "
                    "'premium', 1, NULL), "
                    "('legacy-free', 'legacy-free@example.test', 'x', "
                    "'free', 1, :created_at)"
                ), {"created_at": created_at})

            self.assertNotIn(
                "plan_activated_at",
                {
                    column["name"]
                    for column in inspect(db.engine).get_columns("users")
                },
            )

            repair_legacy_fixture(app_module)
            rows = {
                row["username"]: row
                for row in db.session.execute(db.text(
                    "SELECT username, plan_activated_at FROM users "
                    "WHERE username LIKE 'legacy-%'"
                )).mappings()
            }
            self.assertEqual(
                datetime.fromisoformat(rows["legacy-basic"]["plan_activated_at"]),
                created_at,
            )
            self.assertEqual(
                datetime.fromisoformat(rows["legacy-premium"]["plan_activated_at"]),
                datetime(1970, 1, 1),
            )
            self.assertIsNone(rows["legacy-free"]["plan_activated_at"])

            preserved = datetime(2025, 6, 7, 8, 9, 10)
            db.session.execute(db.text(
                "UPDATE users SET plan_activated_at = :preserved "
                "WHERE username = 'legacy-basic'"
            ), {"preserved": preserved})
            db.session.commit()
            repair_legacy_fixture(app_module)
            repair_legacy_fixture(app_module)
            migrated = User.query.filter_by(username="legacy-basic").one()
            self.assertEqual(
                migrated.plan_activated_at,
                app_module.as_utc(preserved),
            )

            boost_index = next(
                index
                for index in inspect(db.engine).get_indexes("boost_logs")
                if index["name"] == "ix_boost_logs_user_window"
            )
            self.assertEqual(
                boost_index["column_names"],
                ["user_id", "stopped_at", "started_at"],
            )

    def test_schema_bridge_adds_remote_boost_cutoff_column_idempotently(self):
        with app_module.app.app_context():
            db.session.remove()
            with db.engine.begin() as conn:
                conn.exec_driver_sql(
                    "ALTER TABLE boost_logs DROP COLUMN remote_stopped_at"
                )
            self.assertNotIn(
                "remote_stopped_at",
                {
                    column["name"]
                    for column in inspect(db.engine).get_columns("boost_logs")
                },
            )

            repair_legacy_fixture(app_module)
            repair_legacy_fixture(app_module)

            self.assertIn(
                "remote_stopped_at",
                {
                    column["name"]
                    for column in inspect(db.engine).get_columns("boost_logs")
                },
            )

    def test_steam_profile_is_available_offline_with_persisted_steam_id(self):
        user_id, headers = self._tracked_bearer(
            "offline-profile-user",
            is_admin=False,
        )
        account_id = "a1b2c3d4e5f60708"
        with app_module.app.app_context():
            db.session.add(SteamAccount(
                id=account_id,
                user_id=user_id,
                steam_username="login_name",
                steam_id="76561198000000021",
            ))
            db.session.commit()

        with (
            mock.patch.object(app_module.boost_service, "get", return_value=None),
            mock.patch.object(
                app_module,
                "_get_steam_profile",
                return_value={
                    "name": "Offline Persona",
                    "avatar": "https://avatars.steamstatic.com/offline_full.jpg",
                },
            ) as get_profile,
        ):
            response = self.client.get(
                f"/steam_profile?acct_id={account_id}",
                headers=headers,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["name"], "Offline Persona")
        get_profile.assert_called_once()
        self.assertIsNone(get_profile.call_args.kwargs["live_profile_loader"])

    def test_credential_redirect_rejection_never_logs_or_raises_secret_url(self):
        request_secret = "REQUEST-KEY-MUST-NOT-LEAK"
        redirect_secret = "REDIRECT-KEY-MUST-NOT-LEAK"
        request = app_module.urllib.request.Request(
            "https://api.steampowered.com/profile?key=" + request_secret
        )
        handler = app_module._RejectRedirectHandler()

        with self.assertLogs(app_module.logger, level="WARNING") as captured:
            with self.assertRaises(app_module.urllib.error.HTTPError) as raised:
                handler.redirect_request(
                    request,
                    None,
                    302,
                    "Found",
                    {},
                    "https://steamcommunity.com/redirect?key=" + redirect_secret,
                )

        rendered = "\n".join(captured.output)
        self.assertNotIn(request_secret, rendered)
        self.assertNotIn(redirect_secret, rendered)
        self.assertNotIn(request_secret, raised.exception.url)
        self.assertEqual(
            raised.exception.url,
            "https://api.steampowered.com/",
        )

    def test_safe_url_policy_rejects_http_downgrade_and_redacts_query(self):
        redirect_secret = "DOWNGRADE-KEY-MUST-NOT-LEAK"
        self.assertFalse(
            app_module.is_safe_url("http://api.steampowered.com/profile")
        )

        handler = app_module._SafeRedirectHandler()
        request = app_module.urllib.request.Request(
            "https://api.steampowered.com/profile"
        )
        with self.assertLogs(app_module.logger, level="WARNING") as captured:
            with self.assertRaisesRegex(ValueError, "Güvensiz redirect"):
                handler.redirect_request(
                    request,
                    None,
                    302,
                    "Found",
                    {},
                    "http://api.steampowered.com/profile?key=" + redirect_secret,
                )

        self.assertNotIn(redirect_secret, "\n".join(captured.output))

    def test_schema_bridge_clears_only_invalid_persisted_steam_ids(self):
        user_id, _headers = self._tracked_bearer(
            "profile-id-migration-user",
            is_admin=False,
        )
        invalid_id = "c1d2e3f405162738"
        valid_id = "d1e2f30415263748"
        with app_module.app.app_context():
            db.session.add_all([
                SteamAccount(
                    id=invalid_id,
                    user_id=user_id,
                    steam_username="invalid_login",
                    steam_id="None",
                ),
                SteamAccount(
                    id=valid_id,
                    user_id=user_id,
                    steam_username="valid_login",
                    steam_id="76561198000000024",
                ),
            ])
            db.session.commit()

            repair_legacy_fixture(app_module)
            repair_legacy_fixture(app_module)

            self.assertIsNone(db.session.get(SteamAccount, invalid_id).steam_id)
            self.assertEqual(
                db.session.get(SteamAccount, valid_id).steam_id,
                "76561198000000024",
            )

    def test_login_never_persists_none_or_malformed_worker_steam_id(self):
        account = mock.Mock(id="profile-id-validation")
        account.steam_id = None
        manager = mock.Mock()

        manager.client.steam_id = None
        self.assertIsNone(
            app_module._persist_manager_steam_id(account, manager)
        )
        self.assertIsNone(account.steam_id)

        manager.client.steam_id = "not-a-steam-id"
        self.assertIsNone(
            app_module._persist_manager_steam_id(account, manager)
        )
        self.assertIsNone(account.steam_id)

    def test_steam_profile_repairs_literal_none_id_from_live_worker(self):
        user_id, headers = self._tracked_bearer(
            "profile-id-repair-user",
            is_admin=False,
        )
        account_id = "b1c2d3e4f5061728"
        with app_module.app.app_context():
            db.session.add(SteamAccount(
                id=account_id,
                user_id=user_id,
                steam_username="login_name",
                steam_id="None",
            ))
            db.session.commit()

        manager = mock.MagicMock()
        manager.boost_snapshot.return_value = {"logged_in": True}
        manager.client.steam_id = "76561198000000022"
        manager.client.get_profile.return_value = {
            "name": "Live Persona",
            "avatar": "https://avatars.steamstatic.com/live_full.jpg",
        }
        with (
            mock.patch.object(
                app_module.boost_service,
                "get",
                return_value=manager,
            ),
            mock.patch.object(
                app_module,
                "_get_steam_profile",
                return_value=manager.client.get_profile.return_value,
            ) as get_profile,
        ):
            response = self.client.get(
                f"/steam_profile?acct_id={account_id}",
                headers=headers,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["steamid"], "76561198000000022")
        self.assertIs(
            get_profile.call_args.kwargs["live_profile_loader"],
            manager.client.get_profile,
        )
        with app_module.app.app_context():
            self.assertEqual(
                db.session.get(SteamAccount, account_id).steam_id,
                "76561198000000022",
            )

    def test_openid_profile_outage_preserves_known_good_profile(self):
        steam_id = "76561198000000023"
        with app_module.app.app_context():
            user = User(
                username="openid-profile-user",
                email="openid-profile@example.test",
                password_hash="unused",
                is_verified=True,
                steam_id=steam_id,
                steam_display_name="Known Persona",
                steam_avatar="https://avatars.steamstatic.com/known_full.jpg",
            )
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        with self.client.session_transaction() as browser_session:
            browser_session["steam_state"] = "profile-state"
        with (
            mock.patch.object(
                app_module,
                "_verify_steam_callback",
                return_value=steam_id,
            ),
            mock.patch.object(app_module, "_get_steam_profile", return_value={}),
        ):
            response = self.client.get(
                "/steam/callback?state=profile-state&lang=tr"
            )

        self.assertEqual(response.status_code, 302)
        with app_module.app.app_context():
            user = db.session.get(User, user_id)
            self.assertEqual(user.steam_display_name, "Known Persona")
            self.assertEqual(
                user.steam_avatar,
                "https://avatars.steamstatic.com/known_full.jpg",
            )


def tearDownModule():
    with app_module.app.app_context():
        db.session.remove()


if __name__ == "__main__":
    unittest.main()
