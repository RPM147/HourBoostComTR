import atexit
from datetime import datetime, timedelta, timezone
import itertools
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock

_TEMP_DIR = tempfile.mkdtemp(prefix="hourboost-session-tests-")
atexit.register(lambda: shutil.rmtree(_TEMP_DIR, ignore_errors=True))
_DB_PATH = Path(_TEMP_DIR, "session-tests.db").as_posix()
os.environ["SECRET_KEY"] = "test-secret-key-" + "x" * 48
os.environ["DATABASE_URL"] = "sqlite:///" + _DB_PATH
os.environ["DB_SCHEMA_MODE"] = "alembic"
os.environ["STEAM_STATE_DIR"] = _TEMP_DIR
os.environ["SHOPIER_API_VERIFY_ENABLED"] = "false"
os.environ["SHOPIER_VERIFICATION_WORKER_ENABLED"] = "false"

from schema_fixture import (
    initialize_test_database, repair_legacy_fixture, reset_test_schema,
)

initialize_test_database(_DB_PATH)

import app as app_module
import jwt as pyjwt
from sqlalchemy import inspect, text
from config import Config
from models import db, RevokedToken, User, UserSession


_IP_COUNTER = itertools.count(10)


class SessionSecurityTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        database_uri = app_module.app.config["SQLALCHEMY_DATABASE_URI"]
        if not (
            database_uri.startswith("sqlite:///")
            and (
                "hourboost-session-tests-" in database_uri
                or "hourboost-payment-tests-" in database_uri
            )
        ):
            raise RuntimeError(
                "Refusing to run destructive session tests outside an isolated temp DB"
            )
        app_module.MAINTENANCE_FLAG_PATH = os.path.join(
            _TEMP_DIR, "maintenance.flag"
        )
        with app_module.app.app_context():
            reset_test_schema(app_module)
        with app_module._blacklist_lock:
            app_module._token_blacklist.clear()
        with app_module._failed_logins_lock:
            app_module._failed_logins.clear()
        app_module._plan_expiry_cache.clear()

    def _create_user(self, suffix="one"):
        with app_module.app.app_context():
            user = User(
                username=f"session-user-{suffix}",
                email=f"session-{suffix}@example.test",
                is_verified=True,
            )
            user.set_password("Correct-Password-123!")
            db.session.add(user)
            db.session.commit()
            return user.id

    def _login(self, client, username="session-user-one"):
        remote_addr = f"198.51.100.{next(_IP_COUNTER) % 240 + 10}"
        csrf_token = self._csrf_token(client)
        response = client.post(
            "/site_login",
            json={
                "username": username,
                "password": "Correct-Password-123!",
            },
            headers={"X-CSRFToken": csrf_token},
            environ_base={"REMOTE_ADDR": remote_addr},
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"], payload)
        return payload["token"]

    @staticmethod
    def _auth(token):
        return {"Authorization": f"Bearer {token}"}

    def _csrf_token(self, client):
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        match = re.search(
            r'<meta name="csrf-token" content="([^"]+)"',
            page.get_data(as_text=True),
        )
        self.assertIsNotNone(match, "CSRF meta token not found")
        return match.group(1)

    def test_two_logins_have_distinct_server_side_session_identity(self):
        user_id = self._create_user()
        first = app_module.app.test_client()
        second = app_module.app.test_client()
        token_a = self._login(first)
        token_b = self._login(second)

        payload_a = pyjwt.decode(token_a, Config.SECRET_KEY, algorithms=["HS256"])
        payload_b = pyjwt.decode(token_b, Config.SECRET_KEY, algorithms=["HS256"])
        self.assertNotEqual(payload_a["jti"], payload_b["jti"])

        with app_module.app.app_context():
            rows = UserSession.query.filter_by(user_id=user_id, is_active=True).all()
            self.assertEqual(len(rows), 2)
            self.assertEqual({row.token_jti for row in rows}, {
                payload_a["jti"], payload_b["jti"],
            })

        sessions = second.get("/sessions", headers=self._auth(token_b)).get_json()["sessions"]
        self.assertEqual(sum(1 for item in sessions if item["is_current"]), 1)

    def test_single_revoke_blocks_target_jwt_and_cookie_only(self):
        self._create_user()
        client_a = app_module.app.test_client()
        client_b = app_module.app.test_client()
        token_a = self._login(client_a)
        token_b = self._login(client_b)

        sessions_b = client_b.get(
            "/sessions", headers=self._auth(token_b)
        ).get_json()["sessions"]
        target_id = next(item["id"] for item in sessions_b if item["is_current"])
        response = client_a.post(
            "/sessions/revoke",
            json={"session_id": target_id},
            headers=self._auth(token_a),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])

        self.assertIsNone(self._verify(token_b))
        self.assertFalse(client_b.get(
            "/session_check", headers=self._auth(token_b)
        ).get_json()["logged_in"])
        revoked_post = client_b.post(
            "/sessions/revoke-all",
            json={},
            headers=self._auth(token_b),
        )
        self.assertEqual(revoked_post.status_code, 401)
        self.assertFalse(client_b.get("/session_check").get_json()["logged_in"])
        self.assertTrue(client_a.get(
            "/session_check", headers=self._auth(token_a)
        ).get_json()["logged_in"])
        with app_module.app.app_context():
            revoked_jti = pyjwt.decode(
                token_b, Config.SECRET_KEY, algorithms=["HS256"]
            )["jti"]
            self.assertEqual(
                RevokedToken.query.filter_by(token_jti=revoked_jti).count(),
                1,
            )

    def test_invalid_bearer_never_falls_back_to_valid_cookie(self):
        self._create_user()
        client = app_module.app.test_client()
        self._login(client)

        invalid = client.get(
            "/session_check",
            headers={"Authorization": "Bearer invalid-token"},
        )
        self.assertFalse(invalid.get_json()["logged_in"])
        self.assertTrue(client.get("/session_check").get_json()["logged_in"])

    def test_deleted_numeric_ids_cannot_rebind_old_cookie_to_new_user(self):
        old_user_id = self._create_user("old")
        old_client = app_module.app.test_client()
        self._login(old_client, "session-user-old")
        cookie_name = app_module.app.config.get("SESSION_COOKIE_NAME", "session")
        old_cookie = old_client.get_cookie(cookie_name)
        self.assertIsNotNone(old_cookie)

        with app_module.app.app_context():
            old_session_id = UserSession.query.filter_by(
                user_id=old_user_id
            ).one().id
            old_user = db.session.get(User, old_user_id)
            db.session.delete(old_user)
            db.session.commit()

        new_user_id = self._create_user("new")
        new_client = app_module.app.test_client()
        self._login(new_client, "session-user-new")
        with app_module.app.app_context():
            new_session_id = UserSession.query.filter_by(
                user_id=new_user_id
            ).one().id
        # Test gerçekten SQLite'ın sayısal ID reuse koşulunu oluşturmuş olmalı.
        self.assertEqual(new_user_id, old_user_id)
        self.assertEqual(new_session_id, old_session_id)

        replay_client = app_module.app.test_client()
        replay_client.set_cookie(cookie_name, old_cookie.value)
        replay = replay_client.get("/session_check").get_json()
        self.assertFalse(replay["logged_in"])
        self.assertTrue(new_client.get("/session_check").get_json()["logged_in"])

    def test_inflight_request_revalidates_session_after_user_id_reuse(self):
        old_user_id = self._create_user("inflight-old")
        old_client = app_module.app.test_client()
        old_token = self._login(old_client, "session-user-inflight-old")
        old_payload = pyjwt.decode(
            old_token, Config.SECRET_KEY, algorithms=["HS256"]
        )
        replacement = {}

        class ReplaceIdentityWhileWaiting:
            def __enter__(self_inner):
                old_session = UserSession.query.filter_by(
                    user_id=old_user_id,
                    token_jti=old_payload["jti"],
                ).one()
                old_session_id = old_session.id
                db.session.delete(old_session)
                db.session.delete(db.session.get(User, old_user_id))
                db.session.commit()

                new_user = User(
                    username="session-user-inflight-new",
                    email="session-inflight-new@example.test",
                    is_verified=True,
                )
                new_user.set_password("Correct-Password-123!")
                db.session.add(new_user)
                db.session.flush()
                new_session = UserSession(
                    user_id=new_user.id,
                    token_jti="f" * 32,
                    expires_at=datetime.utcnow() + timedelta(hours=1),
                    is_active=True,
                )
                db.session.add(new_session)
                db.session.commit()
                replacement.update(
                    user_id=new_user.id,
                    session_id=new_session.id,
                    old_session_id=old_session_id,
                )
                return self_inner

            def __exit__(self_inner, exc_type, exc, traceback):
                return False

        with mock.patch.object(
            app_module,
            "_user_operation_lock",
            return_value=ReplaceIdentityWhileWaiting(),
        ):
            response = old_client.get(
                "/sessions", headers=self._auth(old_token)
            )

        self.assertEqual(replacement["user_id"], old_user_id)
        self.assertEqual(
            replacement["session_id"], replacement["old_session_id"]
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("no longer active", response.get_json()["error"])

    def test_revoke_all_preserves_only_current_session(self):
        user_id = self._create_user()
        clients = [app_module.app.test_client() for _ in range(3)]
        tokens = [self._login(client) for client in clients]

        response = clients[1].post(
            "/sessions/revoke-all", json={}, headers=self._auth(tokens[1])
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])

        self.assertIsNone(self._verify(tokens[0]))
        self.assertEqual(self._verify(tokens[1]), user_id)
        self.assertIsNone(self._verify(tokens[2]))
        self.assertFalse(clients[0].get("/session_check").get_json()["logged_in"])
        self.assertTrue(clients[1].get("/session_check").get_json()["logged_in"])
        self.assertFalse(clients[2].get("/session_check").get_json()["logged_in"])

        with app_module.app.app_context():
            self.assertEqual(
                UserSession.query.filter_by(user_id=user_id, is_active=True).count(),
                1,
            )
            self.assertEqual(
                RevokedToken.query.filter_by(user_id=user_id).count(),
                2,
            )

    def test_logout_is_persistent_and_idempotent(self):
        self._create_user()
        client = app_module.app.test_client()
        token = self._login(client)

        first = client.post("/site_logout", headers=self._auth(token))
        second = client.post("/site_logout", headers=self._auth(token))
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

        with app_module._blacklist_lock:
            app_module._token_blacklist.clear()
        with app_module.app.app_context():
            db.session.remove()
            payload = pyjwt.decode(
                token,
                Config.SECRET_KEY,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
            self.assertEqual(
                RevokedToken.query.filter_by(token_jti=payload["jti"]).count(),
                1,
            )
            self.assertIsNone(app_module.verify_api_token(token))
        self.assertFalse(client.get("/session_check").get_json()["logged_in"])

    def test_logout_closes_cookie_even_with_invalid_or_different_bearer(self):
        user_id = self._create_user()
        client_a = app_module.app.test_client()
        client_b = app_module.app.test_client()
        token_a = self._login(client_a)
        token_b = self._login(client_b)
        cookie_name = app_module.app.config.get("SESSION_COOKIE_NAME", "session")
        saved_cookie_b = client_b.get_cookie(cookie_name)

        invalid = client_b.post(
            "/site_logout",
            headers={"Authorization": "Bearer invalid-token"},
        )
        self.assertEqual(invalid.status_code, 200)
        replay = app_module.app.test_client()
        replay.set_cookie(cookie_name, saved_cookie_b.value)
        self.assertFalse(replay.get("/session_check").get_json()["logged_in"])
        self.assertIsNone(self._verify(token_b))
        self.assertEqual(self._verify(token_a), user_id)

        # Bearer A + cookie C birlikte geldiyse logout iki credential'ı da kapatır.
        client_c = app_module.app.test_client()
        token_c = self._login(client_c)
        mixed = client_c.post("/site_logout", headers=self._auth(token_a))
        self.assertEqual(mixed.status_code, 200)
        self.assertIsNone(self._verify(token_a))
        self.assertIsNone(self._verify(token_c))

        client_d = app_module.app.test_client()
        token_d = self._login(client_d)
        cookie_csrf = self._csrf_token(client_d)
        cookie_only = client_d.post(
            "/site_logout",
            headers={"X-CSRFToken": cookie_csrf},
        )
        self.assertEqual(cookie_only.status_code, 200)
        self.assertIsNone(self._verify(token_d))

    def test_cross_user_session_cannot_be_revoked(self):
        self._create_user("one")
        self._create_user("two")
        client_a = app_module.app.test_client()
        client_b = app_module.app.test_client()
        token_a = self._login(client_a, "session-user-one")
        token_b = self._login(client_b, "session-user-two")
        sessions_b = client_b.get(
            "/sessions", headers=self._auth(token_b)
        ).get_json()["sessions"]
        target_id = next(item["id"] for item in sessions_b if item["is_current"])

        response = client_a.post(
            "/sessions/revoke",
            json={"session_id": target_id},
            headers=self._auth(token_a),
        )
        self.assertFalse(response.get_json()["ok"])
        self.assertIsNotNone(self._verify(token_b))
        self.assertTrue(client_b.get("/session_check").get_json()["logged_in"])

    def test_untracked_expired_and_legacy_sessions_fail_closed(self):
        user_id = self._create_user()
        untracked = app_module.generate_api_token(user_id)
        self.assertIsNone(self._verify(untracked))

        client = app_module.app.test_client()
        tracked = self._login(client)
        with app_module.app.app_context():
            session_row = UserSession.query.filter_by(user_id=user_id).one()
            session_row.expires_at = datetime.utcnow() - timedelta(seconds=1)
            legacy = UserSession(
                user_id=user_id,
                token_hint="legacy",
                is_active=True,
            )
            db.session.add(legacy)
            db.session.commit()
            repair_legacy_fixture(app_module)
            db.session.refresh(legacy)
            self.assertFalse(legacy.is_active)
            repair_legacy_fixture(app_module)

            indexes = {
                item["name"]: item for item in inspect(db.engine).get_indexes("user_sessions")
            }
            self.assertTrue(indexes["ix_user_sessions_token_jti"]["unique"])

        self.assertIsNone(self._verify(tracked))
        self.assertFalse(client.get("/session_check").get_json()["logged_in"])

    def test_legacy_naive_session_expiry_preserves_exact_utc_boundary(self):
        user_id = self._create_user()
        client = app_module.app.test_client()
        token = self._login(client)
        boundary = app_module.utc_now().replace(microsecond=123456) + timedelta(
            hours=1
        )
        legacy_text = boundary.replace(tzinfo=None).isoformat(sep=" ")

        with app_module.app.app_context():
            db.session.execute(
                text(
                    "UPDATE user_sessions SET expires_at = :expires_at "
                    "WHERE user_id = :user_id"
                ),
                {"expires_at": legacy_text, "user_id": user_id},
            )
            db.session.commit()
            db.session.expire_all()
            stored = db.session.execute(
                text(
                    "SELECT expires_at FROM user_sessions "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            ).scalar_one()
            session_row = UserSession.query.filter_by(user_id=user_id).one()
            self.assertEqual(stored, legacy_text)
            self.assertEqual(session_row.expires_at, boundary)
            self.assertEqual(session_row.expires_at.tzinfo, timezone.utc)

        with mock.patch.object(
            app_module,
            "utc_now",
            return_value=boundary - timedelta(microseconds=1),
        ):
            self.assertEqual(self._verify(token), user_id)

        with mock.patch.object(app_module, "utc_now", return_value=boundary):
            self.assertIsNone(self._verify(token))

        with app_module.app.app_context():
            stored_after = db.session.execute(
                text(
                    "SELECT expires_at FROM user_sessions "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            ).scalar_one()
            self.assertEqual(stored_after, legacy_text)

    def test_schema_bridge_upgrades_real_legacy_session_table(self):
        user_id = self._create_user()
        with app_module.app.app_context():
            db.session.remove()
            with db.engine.begin() as connection:
                connection.execute(text(
                    "DROP INDEX IF EXISTS ix_user_sessions_token_jti"
                ))
                connection.execute(text(
                    "ALTER TABLE user_sessions DROP COLUMN expires_at"
                ))
                connection.execute(text(
                    "ALTER TABLE user_sessions DROP COLUMN token_jti"
                ))
                connection.execute(text(
                    "INSERT INTO user_sessions "
                    "(user_id, token_hint, created_at, last_seen, is_active) "
                    "VALUES (:user_id, 'legacy', :now, :now, 1)"
                ), {"user_id": user_id, "now": datetime.utcnow()})

            repair_legacy_fixture(app_module)
            repair_legacy_fixture(app_module)
            columns = {
                item["name"] for item in inspect(db.engine).get_columns("user_sessions")
            }
            indexes = {
                item["name"]: item for item in inspect(db.engine).get_indexes("user_sessions")
            }
            with db.engine.connect() as connection:
                active = connection.execute(text(
                    "SELECT is_active FROM user_sessions WHERE token_hint = 'legacy'"
                )).scalar_one()
                cutoff = connection.execute(text(
                    "SELECT tokens_valid_after FROM users WHERE id = :user_id"
                ), {"user_id": user_id}).scalar_one()

            self.assertIn("token_jti", columns)
            self.assertIn("expires_at", columns)
            self.assertTrue(indexes["ix_user_sessions_token_jti"]["unique"])
            self.assertEqual(active, 0)
            self.assertIsNotNone(cutoff)

    def test_session_limit_invalidates_evicted_credential(self):
        user_id = self._create_user()
        clients = [app_module.app.test_client() for _ in range(11)]
        tokens = [self._login(client) for client in clients]

        self.assertIsNone(self._verify(tokens[0]))
        self.assertEqual(self._verify(tokens[-1]), user_id)
        self.assertFalse(clients[0].get("/session_check").get_json()["logged_in"])
        with app_module.app.app_context():
            self.assertEqual(
                UserSession.query.filter_by(user_id=user_id, is_active=True).count(),
                10,
            )
            evicted_jti = pyjwt.decode(
                tokens[0], Config.SECRET_KEY, algorithms=["HS256"]
            )["jti"]
            self.assertEqual(
                RevokedToken.query.filter_by(token_jti=evicted_jti).count(),
                1,
            )

    def test_revocation_transaction_failure_rolls_back_and_returns_error(self):
        self._create_user()
        client_a = app_module.app.test_client()
        client_b = app_module.app.test_client()
        token_a = self._login(client_a)
        token_b = self._login(client_b)
        target = next(
            item["id"]
            for item in client_b.get(
                "/sessions", headers=self._auth(token_b)
            ).get_json()["sessions"]
            if item["is_current"]
        )

        with mock.patch.object(
            app_module, "_revoke_session_records", return_value=False
        ):
            response = client_a.post(
                "/sessions/revoke",
                json={"session_id": target},
                headers=self._auth(token_a),
            )
        self.assertEqual(response.status_code, 503)
        self.assertIsNotNone(self._verify(token_b))

        with app_module.app.app_context():
            row = db.session.get(UserSession, target)
            with mock.patch.object(
                db.session, "commit", side_effect=RuntimeError("forced failure")
            ):
                self.assertFalse(app_module._revoke_session_records([row]))
            db.session.expire_all()
            self.assertTrue(db.session.get(UserSession, target).is_active)
            self.assertEqual(
                RevokedToken.query.filter_by(token_jti=row.token_jti).count(),
                0,
            )

    def test_password_change_revokes_old_sessions_and_returns_working_token(self):
        user_id = self._create_user()
        current = app_module.app.test_client()
        other = app_module.app.test_client()
        old_current = self._login(current)
        old_other = self._login(other)

        response = current.post(
            "/change-password",
            json={
                "current_password": "Correct-Password-123!",
                "new_password": "New-Correct-Password-456!",
            },
            headers=self._auth(old_current),
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        new_token = payload["token"]

        self.assertIsNone(self._verify(old_current))
        self.assertIsNone(self._verify(old_other))
        self.assertEqual(self._verify(new_token), user_id)
        self.assertFalse(other.get("/session_check").get_json()["logged_in"])
        self.assertTrue(current.get("/session_check").get_json()["logged_in"])

    def test_login_fails_closed_when_session_record_cannot_be_created(self):
        self._create_user()
        client = app_module.app.test_client()
        csrf_token = self._csrf_token(client)
        with mock.patch.object(
            app_module, "_create_session_record", return_value=None
        ):
            response = client.post(
                "/site_login",
                json={
                    "username": "session-user-one",
                    "password": "Correct-Password-123!",
                },
                headers={"X-CSRFToken": csrf_token},
                environ_base={"REMOTE_ADDR": "198.51.100.250"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.get_json()["ok"])
        self.assertNotIn("token", response.get_json())
        self.assertFalse(client.get("/session_check").get_json()["logged_in"])

    @staticmethod
    def _verify(token):
        with app_module.app.app_context():
            return app_module.verify_api_token(token)


if __name__ == "__main__":
    unittest.main()
