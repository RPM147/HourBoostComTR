import atexit
from contextlib import ExitStack
from datetime import datetime, timedelta
import io
import logging
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
import urllib.parse
from unittest import mock


_TEMP_DIR = tempfile.mkdtemp(prefix="hourboost-session-tests-maintenance-")
atexit.register(lambda: shutil.rmtree(_TEMP_DIR, ignore_errors=True))
_DB_PATH = Path(_TEMP_DIR, "maintenance-tests.db").as_posix()
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
import mailer
from models import db, User, UserSession
import steam_manager


class MaintenanceAccessTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        database_uri = app_module.app.config["SQLALCHEMY_DATABASE_URI"]
        if not (
            database_uri.startswith("sqlite:///")
            and "hourboost-session-tests-" in database_uri
        ):
            raise RuntimeError(
                "Refusing to run maintenance tests outside an isolated temp DB"
            )
        app_module.MAINTENANCE_FLAG_PATH = os.path.join(
            _TEMP_DIR, "maintenance.flag"
        )
        app_module.set_maintenance_mode(False)
        with app_module.app.app_context():
            reset_test_schema(app_module)
        with app_module._failed_logins_lock:
            app_module._failed_logins.clear()

    def tearDown(self):
        app_module.set_maintenance_mode(False)

    def _create_user(self, username, *, is_admin=False):
        with app_module.app.app_context():
            user = User(
                username=username,
                email=f"{username}@example.test",
                is_verified=True,
                is_admin=is_admin,
            )
            user.set_password("Correct-Password-123!")
            db.session.add(user)
            db.session.commit()
            return user.id

    def _csrf_token(self, client, expected_status=200):
        page = client.get("/")
        self.assertEqual(page.status_code, expected_status)
        match = re.search(
            r'<meta name="csrf-token" content="([^"]+)"',
            page.get_data(as_text=True),
        )
        self.assertIsNotNone(match, "CSRF meta token not found")
        return match.group(1)

    def _login(self, client, username, csrf_token):
        return client.post(
            "/site_login",
            json={
                "username": username,
                "password": "Correct-Password-123!",
            },
            headers={"X-CSRFToken": csrf_token},
            environ_base={"REMOTE_ADDR": "198.51.100.70"},
        )

    def test_non_admin_login_is_blocked_without_auth_side_effects(self):
        user_id = self._create_user("maintenance-user")
        client = app_module.app.test_client()
        app_module.set_maintenance_mode(True)
        csrf_token = self._csrf_token(client, expected_status=503)

        with ExitStack() as stack:
            generate_token = stack.enter_context(
                mock.patch.object(app_module, "generate_api_token")
            )
            establish_session = None
            if hasattr(app_module, "_establish_authenticated_session"):
                establish_session = stack.enter_context(
                    mock.patch.object(
                        app_module, "_establish_authenticated_session"
                    )
                )
            response = self._login(client, "maintenance-user", csrf_token)

        self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["maintenance"])
        self.assertNotIn("token", payload)
        with app_module.app.app_context():
            user = db.session.get(User, user_id)
            self.assertIsNone(user.last_login)
            self.assertEqual(UserSession.query.filter_by(user_id=user_id).count(), 0)
        with client.session_transaction() as browser_session:
            self.assertNotIn("user_id", browser_session)
            self.assertNotIn("auth_jti", browser_session)
        generate_token.assert_not_called()
        if establish_session is not None:
            establish_session.assert_not_called()
        self.assertFalse(client.get("/session_check").get_json()["logged_in"])

    def test_admin_login_remains_available_during_maintenance(self):
        user_id = self._create_user("maintenance-admin", is_admin=True)
        client = app_module.app.test_client()
        app_module.set_maintenance_mode(True)
        csrf_token = self._csrf_token(client, expected_status=503)

        response = self._login(client, "maintenance-admin", csrf_token)

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["is_admin"])
        self.assertTrue(payload.get("token"))
        with app_module.app.app_context():
            user = db.session.get(User, user_id)
            self.assertIsNotNone(user.last_login)
            self.assertEqual(UserSession.query.filter_by(user_id=user_id).count(), 1)
        self.assertTrue(client.get("/session_check").get_json()["logged_in"])
        self.assertEqual(client.get("/admin").status_code, 200)

    def test_invalid_credentials_remain_generic_during_maintenance(self):
        user_id = self._create_user("maintenance-known")
        expected = {"ok": False, "error": "Invalid username or password."}

        for enabled, username, ip in (
            (False, "maintenance-known", "198.51.100.71"),
            (True, "maintenance-known", "198.51.100.72"),
            (True, "maintenance-unknown", "198.51.100.73"),
        ):
            app_module.set_maintenance_mode(enabled)
            client = app_module.app.test_client()
            csrf_token = self._csrf_token(
                client,
                expected_status=503 if enabled else 200,
            )
            response = client.post(
                "/site_login",
                json={
                    "username": username,
                    "password": "Wrong-Password-123!",
                },
                headers={"X-CSRFToken": csrf_token},
                environ_base={"REMOTE_ADDR": ip},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json(), expected)

        with app_module.app.app_context():
            user = db.session.get(User, user_id)
            self.assertIsNone(user.last_login)
            self.assertEqual(UserSession.query.count(), 0)

    def test_unknown_username_still_runs_password_hash_verification(self):
        client = app_module.app.test_client()
        csrf_token = self._csrf_token(client)

        with mock.patch.object(
            app_module, "check_password_hash", return_value=False
        ) as verify_password:
            response = client.post(
                "/site_login",
                json={
                    "username": "definitely-unknown-user",
                    "password": "Wrong-Password-123!",
                },
                headers={"X-CSRFToken": csrf_token},
                environ_base={"REMOTE_ADDR": "198.51.100.201"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "Invalid username or password."},
        )
        verify_password.assert_called_once_with(
            app_module._LOGIN_DUMMY_PASSWORD_HASH,
            "Wrong-Password-123!",
        )

    def test_email_action_tokens_never_use_http_url_paths(self):
        verification_token = "V" * 43
        reset_token = "R" * 43
        email_change_token = "E" * 43
        with app_module.app.app_context():
            verify_user = User(
                username="fragment-verify",
                email="fragment-verify@example.test",
                is_verified=False,
                verification_token=verification_token,
                verification_sent_at=datetime.utcnow(),
                lang="en",
            )
            verify_user.set_password("Correct-Password-123!")
            reset_user = User(
                username="fragment-reset",
                email="fragment-reset@example.test",
                is_verified=True,
                reset_token=reset_token,
                reset_token_expires=datetime.utcnow() + timedelta(hours=1),
                lang="en",
            )
            reset_user.set_password("Correct-Password-123!")
            email_user = User(
                username="fragment-email",
                email="fragment-email@example.test",
                is_verified=True,
                email_change_token=email_change_token,
                email_change_new="fragment-email-new@example.test",
                email_change_expires=datetime.utcnow() + timedelta(hours=1),
                lang="en",
            )
            email_user.set_password("Correct-Password-123!")
            db.session.add_all((verify_user, reset_user, email_user))
            db.session.commit()
            verify_user_id = verify_user.id
            reset_user_id = reset_user.id
            email_user_id = email_user.id

        rules = {rule.rule for rule in app_module.app.url_map.iter_rules()}
        for path in (
            "/verify-email/<token>",
            "/reset-password/<token>",
            "/confirm-email-change/<token>",
        ):
            self.assertNotIn(path, rules)

        client = app_module.app.test_client()
        for legacy_path in (
            f"/verify-email/{verification_token}",
            f"/reset-password/{reset_token}",
            f"/confirm-email-change/{email_change_token}",
        ):
            self.assertEqual(client.get(legacy_path).status_code, 404)

        page_tokens = (
            ("/verify-email?lang=en", verification_token),
            ("/reset-password?lang=en", reset_token),
            ("/confirm-email-change?lang=en", email_change_token),
        )
        csrf_token = None
        for path, secret in page_tokens:
            page = client.get(path)
            self.assertEqual(page.status_code, 200, page.get_data(as_text=True))
            page_html = page.get_data(as_text=True)
            self.assertNotIn(secret, page_html)
            self.assertEqual(page.headers.get("Referrer-Policy"), "no-referrer")
            script_policy = page.headers["Content-Security-Policy"].split(
                "script-src ", 1
            )[1].split(";", 1)[0]
            self.assertNotIn("'unsafe-inline'", script_policy)
            match = re.search(
                r'<meta name="csrf-token" content="([^"]+)"',
                page_html,
            )
            self.assertIsNotNone(match)
            csrf_token = match.group(1)

        headers = {"X-CSRFToken": csrf_token}
        without_csrf = client.post(
            "/verify-email?lang=en",
            json={"token": verification_token},
        )
        self.assertEqual(without_csrf.status_code, 400)
        with app_module.app.app_context():
            verify_user = db.session.get(User, verify_user_id)
            self.assertFalse(verify_user.is_verified)
            self.assertEqual(verify_user.verification_token, verification_token)

        with mock.patch.object(app_module.gevent, "spawn") as spawn:
            verified = client.post(
                "/verify-email?lang=en",
                json={"token": verification_token},
                headers=headers,
            )
        self.assertEqual(verified.status_code, 200, verified.get_data(as_text=True))
        self.assertTrue(verified.get_json()["ok"])
        spawn.assert_called_once()

        validated = client.post(
            "/reset-password/validate?lang=en",
            json={"token": reset_token},
            headers=headers,
        )
        self.assertEqual(validated.status_code, 200, validated.get_data(as_text=True))
        self.assertTrue(validated.get_json()["ok"])

        reset = client.post(
            "/reset-password?lang=en",
            json={
                "token": reset_token,
                "password": "Updated-Password-123!",
            },
            headers=headers,
        )
        self.assertEqual(reset.status_code, 200, reset.get_data(as_text=True))
        self.assertTrue(reset.get_json()["ok"])

        changed = client.post(
            "/confirm-email-change?lang=en",
            json={"token": email_change_token},
            headers=headers,
        )
        self.assertEqual(changed.status_code, 200, changed.get_data(as_text=True))
        self.assertTrue(changed.get_json()["ok"])

        with app_module.app.app_context():
            verify_user = db.session.get(User, verify_user_id)
            self.assertTrue(verify_user.is_verified)
            self.assertIsNone(verify_user.verification_token)

            reset_user = db.session.get(User, reset_user_id)
            self.assertTrue(reset_user.check_password("Updated-Password-123!"))
            self.assertIsNone(reset_user.reset_token)
            self.assertIsNone(reset_user.reset_token_expires)

            email_user = db.session.get(User, email_user_id)
            self.assertEqual(email_user.email, "fragment-email-new@example.test")
            self.assertIsNone(email_user.email_change_token)
            self.assertIsNone(email_user.email_change_new)
            self.assertIsNone(email_user.email_change_expires)

    def test_steam_login_start_is_blocked_during_maintenance(self):
        client = app_module.app.test_client()
        app_module.set_maintenance_mode(True)

        response = client.get("/steam/login")

        self.assertEqual(response.status_code, 503)
        with client.session_transaction() as browser_session:
            self.assertNotIn("steam_state", browser_session)

    def test_steam_callback_cannot_issue_session_during_maintenance(self):
        client = app_module.app.test_client()
        with client.session_transaction() as browser_session:
            browser_session["steam_state"] = "phase4-state"
        app_module.set_maintenance_mode(True)

        with mock.patch.object(app_module, "_verify_steam_callback") as verify:
            response = client.get("/steam/callback?state=phase4-state")

        self.assertEqual(response.status_code, 503)
        verify.assert_not_called()
        with app_module.app.app_context():
            self.assertEqual(User.query.count(), 0)
            self.assertEqual(UserSession.query.count(), 0)

    def test_admin_session_cannot_switch_identity_via_steam_during_maintenance(self):
        self._create_user("maintenance-admin", is_admin=True)
        client = app_module.app.test_client()
        app_module.set_maintenance_mode(True)
        csrf_token = self._csrf_token(client, expected_status=503)
        login = self._login(client, "maintenance-admin", csrf_token)
        self.assertEqual(login.status_code, 200)
        with client.session_transaction() as browser_session:
            browser_session["steam_state"] = "admin-steam-state"

        with mock.patch.object(app_module, "_verify_steam_callback") as verify:
            response = client.get("/steam/callback?state=admin-steam-state")

        self.assertEqual(response.status_code, 503)
        verify.assert_not_called()
        session_payload = client.get("/session_check").get_json()
        self.assertTrue(session_payload["logged_in"])
        self.assertEqual(session_payload["username"], "maintenance-admin")
        with client.session_transaction() as browser_session:
            self.assertNotIn("steam_state", browser_session)

    def test_steam_login_whitelists_lang_before_building_return_url(self):
        cases = (
            ("en", "en"),
            ("en&openid.claimed_id=https://attacker.example", "tr"),
        )

        for requested_lang, expected_lang in cases:
            with self.subTest(requested_lang=requested_lang):
                client = app_module.app.test_client()
                query = urllib.parse.urlencode({"lang": requested_lang})
                response = client.get(f"/steam/login?{query}")

                self.assertEqual(response.status_code, 302)
                openid_query = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(response.headers["Location"]).query
                )
                return_to = openid_query["openid.return_to"][0]
                return_query = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(return_to).query
                )
                with client.session_transaction() as browser_session:
                    state = browser_session["steam_state"]

                self.assertEqual(
                    return_query,
                    {"lang": [expected_lang], "state": [state]},
                )

    def test_application_loggers_escape_argument_line_breaks(self):
        payload = "alice\r\n2026-07-19 [INFO] forged-entry"
        escaped_payload = "alice\\r\\n2026-07-19 [INFO] forged-entry"
        expected = "".join(
            (
                f"username={escaped_payload}\n",
                f"raw={escaped_payload}\n",
                f"mapping={escaped_payload}\n",
            )
        )

        for target_logger in (
            app_module.logger,
            steam_manager.logger,
            mailer.logger,
        ):
            with self.subTest(logger=target_logger.name):
                output = io.StringIO()
                handler = logging.StreamHandler(output)
                previous_level = target_logger.level
                previous_propagate = target_logger.propagate
                target_logger.setLevel(logging.INFO)
                target_logger.propagate = False
                target_logger.addHandler(handler)
                try:
                    target_logger.info("username=%s", payload)
                    target_logger.info(f"raw={payload}")
                    target_logger.info("mapping=%(username)s", {"username": payload})
                finally:
                    target_logger.removeHandler(handler)
                    target_logger.setLevel(previous_level)
                    target_logger.propagate = previous_propagate
                    handler.close()

                self.assertEqual(output.getvalue(), expected)

    def test_steam_callback_persists_only_a_supported_language(self):
        client = app_module.app.test_client()
        with client.session_transaction() as browser_session:
            browser_session["steam_state"] = "whitelisted-lang-state"

        with (
            mock.patch.object(
                app_module,
                "_verify_steam_callback",
                return_value="76561198000000001",
            ),
            mock.patch.object(app_module, "_get_steam_profile", return_value={}),
        ):
            response = client.get(
                "/steam/callback?lang=unsupported&state=whitelisted-lang-state"
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")
        with app_module.app.app_context():
            user = User.query.filter_by(steam_id="76561198000000001").one()
            self.assertEqual(user.lang, "tr")


if __name__ == "__main__":
    unittest.main()
