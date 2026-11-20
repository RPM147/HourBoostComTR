import json
import atexit
import os
import shutil
import tempfile
import unittest
from unittest import mock

from gevent.event import Event

_MODULE_STATE_DIR = tempfile.mkdtemp(prefix="hourboost-steam-state-tests-")
atexit.register(lambda: shutil.rmtree(_MODULE_STATE_DIR, ignore_errors=True))
os.environ.setdefault("STEAM_STATE_DIR", _MODULE_STATE_DIR)
import steam_manager
from time_utils import Clock


class SteamCredentialCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="hourboost-credential-tests-"
        )
        self.token_dir_patch = mock.patch.object(
            steam_manager, "TOKEN_DIR", self.temp_dir.name
        )
        self.node_dir = os.path.join(self.temp_dir.name, "node")
        os.makedirs(self.node_dir)
        self.node_dir_patch = mock.patch.object(
            steam_manager, "NODE_DATA_DIR", self.node_dir
        )
        self.token_dir_patch.start()
        self.node_dir_patch.start()

    def tearDown(self):
        self.node_dir_patch.stop()
        self.token_dir_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def _write(path, contents):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(contents)

    @staticmethod
    def _read(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_account_specific_worker_directories_are_distinct_and_contained(self):
        first = steam_manager._make_client("account-one")
        second = steam_manager._make_client("account-two")
        account_root = os.path.abspath(steam_manager._node_account_data_root())

        self.assertNotEqual(first.data_directory, second.data_directory)
        for data_directory in (first.data_directory, second.data_directory):
            self.assertEqual(
                os.path.commonpath((account_root, os.path.abspath(data_directory))),
                account_root,
            )
        with self.assertRaises(ValueError):
            steam_manager._node_account_data_dir("../escape")

    def test_each_worker_receives_only_its_account_data_directory(self):
        first = steam_manager._make_client("account-one")
        second = steam_manager._make_client("account-two")

        def fake_process():
            process = mock.MagicMock()
            process.poll.return_value = None
            return process

        with (
            mock.patch.object(
                steam_manager.subprocess,
                "Popen",
                side_effect=[fake_process(), fake_process()],
            ) as popen,
            mock.patch.object(steam_manager.gevent, "spawn"),
        ):
            self.assertTrue(first._ensure_process())
            self.assertTrue(second._ensure_process())

        first_env = popen.call_args_list[0].kwargs["env"]
        second_env = popen.call_args_list[1].kwargs["env"]
        self.assertEqual(
            first_env["STEAM_WORKER_DATA_DIR"], first.data_directory
        )
        self.assertEqual(
            second_env["STEAM_WORKER_DATA_DIR"], second.data_directory
        )
        self.assertNotEqual(
            first_env["STEAM_WORKER_DATA_DIR"],
            second_env["STEAM_WORKER_DATA_DIR"],
        )

    def test_worker_rejects_a_data_directory_outside_account_storage(self):
        outside = os.path.join(self.temp_dir.name, "outside-worker-data")
        client = steam_manager.SteamWorkerClient(outside)

        with mock.patch.object(steam_manager.subprocess, "Popen") as popen:
            self.assertFalse(client._ensure_process())

        popen.assert_not_called()
        self.assertFalse(os.path.exists(outside))

    def test_legacy_token_is_copied_to_every_matching_account_without_overwrite(self):
        username = "SameSteamUser"
        first_id = "account-one"
        second_id = "account-two"
        shared_path = steam_manager._node_machine_auth_path(username)
        first_path = steam_manager._account_node_machine_auth_path(
            first_id, username
        )
        second_path = steam_manager._account_node_machine_auth_path(
            second_id, username
        )
        self._write(shared_path, "legacy-shared-secret")
        self._write(first_path, "newer-account-secret")

        self.assertTrue(
            steam_manager.migrate_legacy_node_credentials(
                ((first_id, username), (second_id, username.lower()))
            )
        )

        self.assertFalse(os.path.lexists(shared_path))
        self.assertEqual(self._read(first_path), "newer-account-secret")
        self.assertEqual(self._read(second_path), "legacy-shared-secret")

    def test_remove_without_manager_keeps_legacy_token_by_default(self):
        account_id = "account-123"
        username = "Steam_User_Name"
        credential_path = steam_manager._credential_path(account_id, username)
        account_dir = steam_manager._node_account_data_dir(account_id)
        account_machine_auth_path = steam_manager._account_node_machine_auth_path(
            account_id, username
        )
        legacy_machine_auth_path = steam_manager._node_machine_auth_path(username)
        self._write(credential_path, "encrypted-secret")
        self._write(account_machine_auth_path, "account-machine-auth-secret")
        self._write(
            os.path.join(account_dir, "cellid-test.txt"), "account-worker-state"
        )
        self._write(legacy_machine_auth_path, "legacy-machine-auth-secret")

        service = steam_manager.BoostService()

        self.assertTrue(service.remove(account_id, username))
        self.assertFalse(os.path.lexists(credential_path))
        self.assertFalse(os.path.lexists(account_dir))
        self.assertTrue(os.path.exists(legacy_machine_auth_path))

        self.assertTrue(
            steam_manager.delete_saved_credentials(
                account_id,
                username,
                include_legacy_machine_auth=True,
            )
        )
        self.assertFalse(os.path.lexists(legacy_machine_auth_path))

    def test_credential_path_escape_fails_closed_and_preserves_outside_file(self):
        outside_path = os.path.realpath(
            os.path.join(self.temp_dir.name, "..", "outside_.cred")
        )
        self._write(outside_path, "must-not-delete")
        self.addCleanup(
            lambda: os.path.exists(outside_path) and os.remove(outside_path)
        )

        result = steam_manager.delete_saved_credentials("../outside", "")

        self.assertFalse(result)
        self.assertTrue(os.path.exists(outside_path))

    def test_quarantine_is_reversible_when_database_commit_fails(self):
        account_id = "account-rollback"
        username = "RollbackSteamUser"
        credential_path = steam_manager._credential_path(account_id, username)
        machine_auth_path = steam_manager._account_node_machine_auth_path(
            account_id, username
        )
        self._write(credential_path, "encrypted-secret")
        self._write(machine_auth_path, "machine-auth-secret")

        quarantined = steam_manager.quarantine_saved_credentials(
            account_id, username
        )

        self.assertIsNotNone(quarantined)
        self.assertEqual(len(quarantined), 2)
        self.assertFalse(os.path.lexists(credential_path))
        self.assertFalse(os.path.lexists(machine_auth_path))
        self.assertTrue(steam_manager.restore_quarantined_credentials(quarantined))
        self.assertEqual(self._read(credential_path), "encrypted-secret")
        self.assertEqual(self._read(machine_auth_path), "machine-auth-secret")

    def test_file_and_directory_quarantine_can_be_restored_then_purged(self):
        account_id = "account-directory"
        username = "DirectorySteamUser"
        credential_path = steam_manager._credential_path(account_id, username)
        account_dir = steam_manager._node_account_data_dir(account_id)
        account_machine_auth_path = steam_manager._account_node_machine_auth_path(
            account_id, username
        )
        worker_state_path = os.path.join(account_dir, "cellid-test.txt")
        legacy_machine_auth_path = steam_manager._node_machine_auth_path(username)
        self._write(credential_path, "encrypted-secret")
        self._write(account_machine_auth_path, "account-machine-auth-secret")
        self._write(worker_state_path, "worker-state")
        self._write(legacy_machine_auth_path, "legacy-machine-auth-secret")

        quarantined = steam_manager.quarantine_saved_credentials(
            account_id,
            username,
            include_legacy_machine_auth=True,
            include_account_directory=True,
        )

        self.assertIsNotNone(quarantined)
        self.assertEqual(len(quarantined), 3)
        for original in (
            credential_path,
            account_dir,
            legacy_machine_auth_path,
        ):
            self.assertFalse(os.path.lexists(original))
        self.assertTrue(steam_manager.restore_quarantined_credentials(quarantined))
        self.assertEqual(self._read(credential_path), "encrypted-secret")
        self.assertEqual(
            self._read(account_machine_auth_path), "account-machine-auth-secret"
        )
        self.assertEqual(self._read(worker_state_path), "worker-state")
        self.assertEqual(
            self._read(legacy_machine_auth_path), "legacy-machine-auth-secret"
        )

        quarantined = steam_manager.quarantine_saved_credentials(
            account_id,
            username,
            include_legacy_machine_auth=True,
            include_account_directory=True,
        )
        self.assertIsNotNone(quarantined)
        self.assertTrue(steam_manager.purge_quarantined_credentials(quarantined))
        for original, tombstone in quarantined:
            self.assertFalse(os.path.lexists(original))
            self.assertFalse(os.path.lexists(tombstone))

    def test_reconcile_restores_active_account_and_purges_orphan_tombstones(self):
        account_id = "active-account"
        username = "ActiveSteamUser"
        credential_path = steam_manager._credential_path(account_id, username)
        account_dir = steam_manager._node_account_data_dir(account_id)
        worker_state_path = os.path.join(account_dir, "cellid-active.txt")
        self._write(credential_path, "active-encrypted-secret")
        self._write(worker_state_path, "active-worker-state")
        active_tombstones = steam_manager.quarantine_saved_credentials(
            account_id,
            username,
            include_account_directory=True,
        )
        self.assertIsNotNone(active_tombstones)

        orphan_credential = steam_manager._credential_path(
            "orphan-account", "OrphanSteamUser"
        )
        orphan_directory = steam_manager._node_account_data_dir("orphan-account")
        self._write(orphan_credential, "orphan-secret")
        self._write(
            os.path.join(orphan_directory, "cellid-orphan.txt"), "orphan-state"
        )
        orphan_credential_tombstone = (
            f"{orphan_credential}.delete-{'a' * 32}"
        )
        orphan_directory_tombstone = f"{orphan_directory}.delete-{'b' * 32}"
        os.replace(orphan_credential, orphan_credential_tombstone)
        os.replace(orphan_directory, orphan_directory_tombstone)

        self.assertTrue(
            steam_manager.reconcile_credential_quarantines(
                ((account_id, username),)
            )
        )

        self.assertEqual(self._read(credential_path), "active-encrypted-secret")
        self.assertEqual(self._read(worker_state_path), "active-worker-state")
        for _original, tombstone in active_tombstones:
            self.assertFalse(os.path.lexists(tombstone))
        self.assertFalse(os.path.lexists(orphan_credential_tombstone))
        self.assertFalse(os.path.lexists(orphan_directory_tombstone))

    def test_restore_never_overwrites_a_newer_worker_artifact(self):
        account_id = "account-collision"
        username = "CollisionSteamUser"
        credential_path = steam_manager._credential_path(account_id, username)
        self._write(credential_path, "older-quarantined-secret")
        quarantined = steam_manager.quarantine_saved_credentials(
            account_id, username
        )
        self.assertIsNotNone(quarantined)

        self._write(credential_path, "newer-worker-secret")

        self.assertTrue(steam_manager.restore_quarantined_credentials(quarantined))
        self.assertEqual(self._read(credential_path), "newer-worker-secret")
        self.assertTrue(
            all(
                not os.path.lexists(quarantine_path)
                for _original, quarantine_path in quarantined
            )
        )

    def test_atomic_save_failure_preserves_the_previous_credential(self):
        account_id = "account-atomic-save"
        username = "AtomicSaveSteamUser"
        manager = steam_manager.SteamAccountManager(account_id, username)
        credential_path = steam_manager._credential_path(account_id, username)
        previous = {
            "password": "previous-encrypted-password",
            "refresh_token": "previous-encrypted-token",
            "saved_at": 1,
        }
        self._write(credential_path, json.dumps(previous, separators=(",", ":")))
        before = self._read(credential_path)
        real_replace = os.replace

        def fail_final_replace(source, destination):
            if destination == credential_path and ".tmp-" in source:
                raise OSError("simulated atomic replace failure")
            return real_replace(source, destination)

        with (
            mock.patch.object(
                steam_manager, "encrypt_password", return_value="new-encrypted-password"
            ),
            mock.patch.object(
                steam_manager.os, "replace", side_effect=fail_final_replace
            ),
        ):
            self.assertFalse(manager.save_credentials(password="new-password"))

        self.assertEqual(self._read(credential_path), before)
        self.assertFalse(
            any(
                entry.startswith(os.path.basename(credential_path) + ".tmp-")
                for entry in os.listdir(os.path.dirname(credential_path))
            )
        )

    def test_closed_worker_releases_pending_request_and_cannot_resurrect(self):
        client = steam_manager._make_client("account-pending")
        pending = steam_manager.queue.Queue(maxsize=1)
        client._pending["request-id"] = pending

        client.mark_closed()

        response = pending.get_nowait()
        self.assertEqual(response["eresult"], int(steam_manager.EResult.NoConnection))
        self.assertEqual(client._pending, {})
        with mock.patch.object(steam_manager.subprocess, "Popen") as popen:
            self.assertFalse(client._ensure_process())
            request_response = client._request("login")
        popen.assert_not_called()
        self.assertEqual(
            request_response["eresult"], int(steam_manager.EResult.NoConnection)
        )

    def test_stale_worker_reader_cannot_mutate_or_fail_replacement_generation(self):
        class ControlledStream:
            def __init__(self):
                self.entered = Event()
                self.lines = steam_manager.queue.Queue()

            def readline(self):
                self.entered.set()
                return self.lines.get()

        class ControlledProcess:
            def __init__(self):
                self.stdout = ControlledStream()
                self.stderr = ControlledStream()
                self.stdin = mock.MagicMock()
                self.returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = -15

            def kill(self):
                self.returncode = -9

            def wait(self):
                return self.returncode

        client = steam_manager._make_client("account-worker-generation")
        first_process = ControlledProcess()
        first_pending = steam_manager.queue.Queue(maxsize=1)
        disconnected_events = []
        client.on("disconnected")(
            lambda: disconnected_events.append("disconnected")
        )
        with client._process_lock:
            client._process_generation = 1
            client._process = first_process
            client.connected = True
            client.logged_in = True
            client._pending["first-request"] = (1, first_pending)

        first_reader = steam_manager.gevent.spawn(
            client._read_stdout,
            first_process,
            1,
        )
        self.assertTrue(first_process.stdout.entered.wait(timeout=0.5))

        self.assertTrue(client.force_disconnect())
        self.assertEqual(
            first_pending.get_nowait()["eresult"],
            int(steam_manager.EResult.NoConnection),
        )

        second_process = ControlledProcess()
        with (
            mock.patch.object(
                steam_manager.subprocess,
                "Popen",
                return_value=second_process,
            ),
            mock.patch.object(steam_manager.gevent, "spawn"),
        ):
            self.assertTrue(client._ensure_process())

        second_pending = steam_manager.queue.Queue(maxsize=1)
        with client._process_lock:
            second_generation = client._process_generation
            client.logged_in = True
            client.refresh_token = "replacement-token"
            client.steam_id = "replacement-steam-id"
            client._pending["second-request"] = (
                second_generation,
                second_pending,
            )

        first_process.stdout.lines.put(
            json.dumps(
                {
                    "event": "logged_on",
                    "refresh_token": "stale-token",
                    "steam_id": "stale-steam-id",
                }
            )
            + "\n"
        )
        first_reader.join(timeout=0.5)

        self.assertTrue(first_reader.ready())
        self.assertIs(client._process, second_process)
        self.assertEqual(client._process_generation, second_generation)
        self.assertTrue(client.connected)
        self.assertTrue(client.logged_in)
        self.assertEqual(client.refresh_token, "replacement-token")
        self.assertEqual(client.steam_id, "replacement-steam-id")
        self.assertTrue(second_pending.empty())
        self.assertIn("second-request", client._pending)
        self.assertEqual(disconnected_events, [])

    def test_worker_profile_ipc_maps_presentation_fields_without_state_change(self):
        client = steam_manager._make_client("account-profile-ipc")
        client.connected = True
        client.logged_in = True
        client.steam_id = "76561198000000031"
        with mock.patch.object(
            client,
            "_request",
            return_value={
                "ok": True,
                "eresult": 1,
                "steam_id": "76561198000000031",
                "name": "CM Persona",
                "avatar": "https://avatars.steamstatic.com/cm_full.jpg",
            },
        ) as request_profile:
            profile = client.get_profile()

        request_profile.assert_called_once_with("get_profile", timeout=15)
        self.assertEqual(profile["name"], "CM Persona")
        self.assertTrue(client.connected)
        self.assertTrue(client.logged_in)
        self.assertEqual(client.steam_id, "76561198000000031")

    def test_worker_profile_ipc_failure_is_presentation_only(self):
        client = steam_manager._make_client("account-profile-ipc-failure")
        client.connected = True
        client.logged_in = True
        with mock.patch.object(
            client,
            "_request",
            return_value={"ok": False, "eresult": 3},
        ):
            with self.assertRaisesRegex(RuntimeError, "profile is unavailable"):
                client.get_profile()

        self.assertTrue(client.connected)
        self.assertTrue(client.logged_in)

    def test_malformed_worker_stdout_never_logs_partial_refresh_token(self):
        refresh_token = "REFRESH-TOKEN-MUST-NOT-LEAK"

        class _Stream:
            def __init__(self):
                self.lines = iter([
                    '{"event":"refresh_token","refresh_token":"'
                    + refresh_token,
                    "",
                ])

            def readline(self):
                return next(self.lines)

        class _Process:
            def __init__(self):
                self.stdout = _Stream()

            def poll(self):
                return None

        client = steam_manager._make_client("account-malformed-stdout")
        process = _Process()
        with client._process_lock:
            client._process = process
            client._process_generation = 7
            client.connected = True

        with self.assertLogs(steam_manager.logger, level="WARNING") as captured:
            client._read_stdout(process, 7)

        rendered = "\n".join(captured.output)
        self.assertNotIn(refresh_token, rendered)
        self.assertIn("generation=7", rendered)
        self.assertIn("chars=", rendered)

    def test_worker_runtime_events_publish_typed_disconnect_and_clear_state(self):
        cases = (
            ("disconnected", int(steam_manager.EResult.NoConnection), False),
            ("error", int(steam_manager.EResult.LoggedInElsewhere), True),
        )

        for event_name, raw_eresult, terminal in cases:
            with self.subTest(event=event_name, eresult=raw_eresult):
                client = steam_manager._make_client(f"runtime-{event_name}")
                process = object()
                observed = []
                client.on("disconnected")(
                    lambda result, is_terminal: observed.append(
                        (result, is_terminal)
                    )
                )
                with client._process_lock:
                    client._process = process
                    client._process_generation = 1
                    client.connected = True
                    client.logged_in = True

                client._handle_message(
                    {
                        "event": event_name,
                        "eresult": raw_eresult,
                        "terminal": terminal,
                        "message": "redacted runtime event",
                    },
                    process,
                    1,
                )

                self.assertFalse(client.connected)
                self.assertFalse(client.logged_in)
                self.assertEqual(observed, [(raw_eresult, terminal)])

    def test_refresh_token_event_is_persisted_by_account_manager(self):
        manager = steam_manager.SteamAccountManager(
            "account-refresh-token-event", "RefreshTokenEventSteamUser"
        )
        manager.logged_in = True
        process = object()
        with manager.client._process_lock:
            manager.client._process = process
            manager.client._process_generation = 1
            manager.client.connected = True
            manager.client.logged_in = True

        with mock.patch.object(
            manager,
            "_persist_refresh_token_if_current",
        ) as persist_refresh_token:
            manager.client._handle_message(
                {
                    "event": "refresh_token",
                    "refresh_token": "rotated-refresh-token",
                },
                process,
                1,
            )
            steam_manager.gevent.sleep(0)

        self.assertEqual(
            manager.client.refresh_token,
            "rotated-refresh-token",
        )
        persist_refresh_token.assert_called_once_with("rotated-refresh-token")

    def test_stale_refresh_token_event_cannot_overwrite_the_latest_token(self):
        manager = steam_manager.SteamAccountManager(
            "account-refresh-token-cas", "RefreshTokenCasSteamUser"
        )
        manager.logged_in = True
        manager.client.logged_in = True
        manager.client.refresh_token = "latest-refresh-token"

        with mock.patch.object(
            manager,
            "_save_credentials_unlocked",
            return_value=True,
        ) as save_unlocked:
            self.assertFalse(
                manager._persist_refresh_token_if_current("stale-refresh-token")
            )
            save_unlocked.assert_not_called()
            self.assertTrue(
                manager._persist_refresh_token_if_current("latest-refresh-token")
            )

        save_unlocked.assert_called_once_with(
            refresh_token="latest-refresh-token"
        )

    def test_refresh_token_is_not_persisted_before_cm_login_succeeds(self):
        manager = steam_manager.SteamAccountManager(
            "account-refresh-token-pre-login", "RefreshTokenPreLoginSteamUser"
        )
        manager.client.refresh_token = "pre-login-refresh-token"

        with mock.patch.object(
            manager,
            "_save_credentials_unlocked",
            return_value=True,
        ) as save_unlocked:
            self.assertFalse(
                manager._persist_refresh_token_if_current(
                    "pre-login-refresh-token"
                )
            )

        save_unlocked.assert_not_called()

    def test_mark_removed_blocks_queued_reconnect_and_credential_save(self):
        account_id = "account-removed"
        username = "RemovedSteamUser"
        manager = steam_manager.SteamAccountManager(account_id, username)
        credential_path = steam_manager._credential_path(account_id, username)
        manager.boosting = True

        with (
            mock.patch.object(manager, "load_credentials") as load_credentials,
            mock.patch.object(manager.client, "reconnect") as reconnect,
            mock.patch.object(steam_manager.gevent, "spawn_later") as spawn_later,
            mock.patch.object(
                steam_manager, "encrypt_password", return_value="encrypted-secret"
            ),
        ):
            manager.mark_removed()
            manager._schedule_reconnect()
            manager._try_reconnect()
            manager.client._emit("logged_on")
            steam_manager.gevent.sleep(0)
            self.assertFalse(manager._record_login_success(password="password"))
            self.assertFalse(manager.save_credentials(password="password"))

        load_credentials.assert_not_called()
        reconnect.assert_not_called()
        spawn_later.assert_not_called()
        self.assertTrue(manager._removed)
        self.assertTrue(manager.client._closed)
        self.assertFalse(manager.logged_in)
        self.assertFalse(manager.boosting)
        self.assertFalse(os.path.lexists(credential_path))

    def test_stale_session_stop_cannot_stop_a_new_boost(self):
        manager = steam_manager.SteamAccountManager(
            "account-session-race", "SessionRaceSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "stop_games", return_value=steam_manager.EResult.OK
            ) as stop_games,
        ):
            first = manager.start_boost([730], persona_state=1)
            self.assertEqual(first["session_id"], manager.boost_session_id)
            self.assertEqual(first["generation"], manager.boost_generation)
            manager.stop_boost(
                expected_session_id=first["session_id"],
                expected_generation=first["generation"],
            )

            second = manager.start_boost([570], persona_state=2)
            calls_before_stale_stop = stop_games.call_count
            self.assertEqual(
                manager.stop_boost(
                    expected_session_id=first["session_id"],
                    expected_generation=first["generation"],
                ),
                0,
            )

        self.assertEqual(stop_games.call_count, calls_before_stale_stop)
        snapshot = manager.boost_snapshot()
        self.assertTrue(snapshot["boosting"])
        self.assertEqual(snapshot["session_id"], second["session_id"])
        self.assertEqual(snapshot["app_ids"], [570])
        self.assertGreater(second["generation"], first["generation"])

    def test_stop_games_failure_disconnects_fail_closed_and_clears_state(self):
        manager = steam_manager.SteamAccountManager(
            "account-stop-failure", "StopFailureSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client,
                "stop_games",
                return_value=steam_manager.EResult.NoConnection,
            ),
            mock.patch.object(manager.client, "force_disconnect") as force_disconnect,
        ):
            started = manager.start_boost([730])
            elapsed = manager.stop_boost(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
            )

        self.assertGreaterEqual(elapsed, 0)
        force_disconnect.assert_called_once_with()
        snapshot = manager.boost_snapshot()
        self.assertFalse(snapshot["boosting"])
        self.assertIsNone(snapshot["session_id"])
        self.assertIsNone(snapshot["start_time"])
        self.assertFalse(snapshot["logged_in"])
        self.assertGreater(snapshot["generation"], started["generation"])

    def test_ambiguous_start_failure_is_compensated_fail_closed(self):
        manager = steam_manager.SteamAccountManager(
            "account-start-failure", "StartFailureSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.ServiceUnavailable,
            ),
            mock.patch.object(
                manager.client,
                "stop_games",
                return_value=steam_manager.EResult.NoConnection,
            ) as stop_games,
            mock.patch.object(manager.client, "force_disconnect") as force_disconnect,
        ):
            with self.assertRaisesRegex(Exception, "boost baslatilamadi"):
                manager.start_boost([730])

        stop_games.assert_called_once_with()
        force_disconnect.assert_called_once_with()
        snapshot = manager.boost_snapshot()
        self.assertFalse(snapshot["boosting"])
        self.assertIsNone(snapshot["session_id"])
        self.assertFalse(snapshot["logged_in"])

    def test_checkpoint_advance_and_rollback_are_session_guarded(self):
        clock_state = {"now": 100.0}
        test_clock = Clock(
            epoch_source=lambda: clock_state["now"],
            monotonic_source=lambda: clock_state["now"],
        )
        manager = steam_manager.SteamAccountManager(
            "account-checkpoint",
            "CheckpointSteamUser",
            clock_source=test_clock,
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "stop_games", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(steam_manager.time, "time", return_value=100.0),
        ):
            started = manager.start_boost([730, 570])

        self.assertIsNone(
            manager.advance_boost_checkpoint(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
                min_elapsed=61,
                now=160,
            )
        )
        checkpoint = manager.advance_boost_checkpoint(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
            min_elapsed=60,
            now=160,
        )
        self.assertEqual(checkpoint["elapsed"], 60)
        self.assertEqual(checkpoint["started_at"], 100)
        self.assertEqual(checkpoint["app_ids"], [730, 570])
        self.assertEqual(manager.boost_snapshot()["start_time"], 160)
        self.assertTrue(manager.rollback_boost_checkpoint(checkpoint))
        self.assertEqual(manager.boost_snapshot()["start_time"], 100)

        with mock.patch.object(
            manager.client, "stop_games", return_value=steam_manager.EResult.OK
        ):
            manager.stop_boost(
                expected_session_id=started["session_id"],
                expected_generation=started["generation"],
            )
        self.assertFalse(manager.rollback_boost_checkpoint(checkpoint))

    def test_boost_elapsed_ignores_backward_and_forward_wall_clock_jumps(self):
        for label, wall_delta in (
            ("backward", -3600.0),
            ("forward", 86400.0),
        ):
            with self.subTest(label=label):
                state = {"wall": 2_000_000_000.0, "mono": 10_000.0}
                fake_clock = Clock(
                    epoch_source=lambda: state["wall"],
                    monotonic_source=lambda: state["mono"],
                )
                manager = steam_manager.SteamAccountManager(
                    f"clock-jump-{label}",
                    f"ClockJump{label}",
                    clock_source=fake_clock,
                )
                manager.logged_in = True
                with (
                    mock.patch.object(
                        manager.client,
                        "change_status",
                        return_value=steam_manager.EResult.OK,
                    ),
                    mock.patch.object(
                        manager.client,
                        "games_played",
                        return_value=steam_manager.EResult.OK,
                    ),
                    mock.patch.object(
                        manager.client,
                        "stop_games",
                        return_value=steam_manager.EResult.OK,
                    ),
                ):
                    started = manager.start_boost([730])
                    state["wall"] += wall_delta
                    state["mono"] += 90.0
                    snapshot = manager.boost_snapshot()
                    segment = manager.stop_boost_segment(
                        expected_session_id=started["session_id"],
                        expected_generation=started["generation"],
                    )

                self.assertEqual(snapshot["segment_elapsed"], 90.0)
                self.assertEqual(
                    snapshot["observed_stop_time"],
                    started["start_time"] + 90.0,
                )
                self.assertEqual(segment["elapsed"], 90.0)
                self.assertEqual(
                    segment["stopped_at"],
                    started["start_time"] + 90.0,
                )
                self.assertTrue(manager.acknowledge_final_segment(segment))

    def test_monotonic_checkpoint_rollback_restores_exact_anchor(self):
        state = {"wall": 2_000_000_000.0, "mono": 10_000.0}
        fake_clock = Clock(
            epoch_source=lambda: state["wall"],
            monotonic_source=lambda: state["mono"],
        )
        manager = steam_manager.SteamAccountManager(
            "clock-checkpoint",
            "ClockCheckpoint",
            clock_source=fake_clock,
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            started = manager.start_boost([730])

        state["wall"] -= 3600.0
        state["mono"] += 60.0
        checkpoint = manager.prepare_boost_checkpoint(
            expected_session_id=started["session_id"],
            expected_generation=started["generation"],
        )
        self.assertEqual(checkpoint["elapsed"], 60.0)
        self.assertTrue(manager.rollback_boost_checkpoint(checkpoint))

        state["mono"] += 15.0
        snapshot = manager.boost_snapshot()
        self.assertEqual(snapshot["segment_elapsed"], 75.0)
        self.assertEqual(
            snapshot["observed_stop_time"],
            started["start_time"] + 75.0,
        )

    def test_terminal_reconnect_finalizes_once_with_lock_free_snapshot_callback(self):
        manager = steam_manager.SteamAccountManager(
            "account-terminal-reconnect", "TerminalReconnectSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(steam_manager.time, "time", return_value=100.0),
        ):
            started = manager.start_boost([730, 570])
        with manager.state_lock:
            manager.start_time = 90.0

        callbacks = []

        def fatal_callback(
            account_id,
            elapsed,
            session_id,
            generation,
            started_at,
            app_ids,
        ):
            lock_probe = {"acquired": False}

            def acquire_from_another_greenlet():
                with manager.state_lock:
                    lock_probe["acquired"] = True

            probe = steam_manager.gevent.spawn(acquire_from_another_greenlet)
            probe.join(timeout=0.2)
            callbacks.append({
                "account_id": account_id,
                "elapsed": elapsed,
                "session_id": session_id,
                "generation": generation,
                "started_at": started_at,
                "app_ids": app_ids,
                "lock_free": lock_probe["acquired"],
            })

        old_callback = steam_manager.boost_service.fatal_disconnect_callback
        steam_manager.boost_service.fatal_disconnect_callback = fatal_callback
        self.addCleanup(
            setattr,
            steam_manager.boost_service,
            "fatal_disconnect_callback",
            old_callback,
        )

        with (
            mock.patch.object(manager, "load_credentials", return_value={"password": "x"}),
            mock.patch.object(
                manager,
                "_login_with_saved_credentials",
                return_value=steam_manager.EResult.InvalidPassword,
            ) as reconnect_login,
            mock.patch.object(
                manager.client, "stop_games", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(steam_manager.time, "time", return_value=100.0),
        ):
            manager._try_reconnect(started["generation"])
            manager._try_reconnect(started["generation"])

        reconnect_login.assert_called_once()
        self.assertEqual(len(callbacks), 1)
        self.assertTrue(callbacks[0]["lock_free"])
        self.assertEqual(callbacks[0]["account_id"], manager.account_id)
        self.assertEqual(callbacks[0]["session_id"], started["session_id"])
        self.assertEqual(callbacks[0]["generation"], started["generation"])
        self.assertEqual(callbacks[0]["started_at"], 90)
        self.assertEqual(callbacks[0]["elapsed"], 10)
        self.assertEqual(callbacks[0]["app_ids"], [730, 570])
        self.assertFalse(manager.boost_snapshot()["boosting"])

    def test_transient_runtime_disconnect_burst_schedules_one_reconnect_ticket(self):
        manager = steam_manager.SteamAccountManager(
            "account-transient-runtime", "TransientRuntimeSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            started = manager.start_boost([730])

        process = object()
        with manager.client._process_lock:
            manager.client._process = process
            manager.client._process_generation = 1
            manager.client.connected = True
            manager.client.logged_in = True

        with mock.patch.object(steam_manager.gevent, "spawn_later") as spawn_later:
            for _ in range(2):
                manager.client._handle_message(
                    {
                        "event": "disconnected",
                        "eresult": int(steam_manager.EResult.NoConnection),
                        "message": "transient disconnect",
                    },
                    process,
                    1,
                )
            steam_manager.gevent.sleep(0)

        self.assertFalse(manager.boost_snapshot()["logged_in"])
        self.assertEqual(manager._reconnect_attempts, 1)
        self.assertEqual(
            manager._reconnect_pending_generation,
            started["generation"],
        )
        self.assertIsNotNone(manager._reconnect_pending_token)
        spawn_later.assert_called_once()
        self.assertEqual(spawn_later.call_args.args[1], manager._try_reconnect)
        self.assertEqual(
            spawn_later.call_args.args[2],
            started["generation"],
        )

    def test_terminal_runtime_error_finalizes_active_boost_once(self):
        manager = steam_manager.SteamAccountManager(
            "account-terminal-runtime", "TerminalRuntimeSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            started = manager.start_boost([730, 570])

        process = object()
        with manager.client._process_lock:
            manager.client._process = process
            manager.client._process_generation = 1
            manager.client.connected = True
            manager.client.logged_in = True

        callbacks = []
        finalized = Event()

        def fatal_callback(*args):
            callbacks.append(args)
            finalized.set()

        old_callback = steam_manager.boost_service.fatal_disconnect_callback
        steam_manager.boost_service.fatal_disconnect_callback = fatal_callback
        self.addCleanup(
            setattr,
            steam_manager.boost_service,
            "fatal_disconnect_callback",
            old_callback,
        )

        with mock.patch.object(
            manager.client,
            "stop_games",
            return_value=steam_manager.EResult.OK,
        ) as stop_games:
            for _ in range(2):
                manager.client._handle_message(
                    {
                        "event": "error",
                        "eresult": int(
                            steam_manager.EResult.LoggedInElsewhere
                        ),
                        "message": "LoggedInElsewhere",
                    },
                    process,
                    1,
                )
            self.assertTrue(finalized.wait(timeout=0.5))

        snapshot = manager.boost_snapshot()
        self.assertFalse(snapshot["logged_in"])
        self.assertFalse(snapshot["boosting"])
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0][0], manager.account_id)
        self.assertEqual(callbacks[0][2], started["session_id"])
        self.assertEqual(callbacks[0][3], started["generation"])
        stop_games.assert_called_once_with()

    def test_saved_refresh_transient_results_do_not_fallback_to_password(self):
        transient_results = (
            steam_manager.EResult.Invalid,
            steam_manager.EResult.Fail,
            steam_manager.EResult.NoConnection,
            steam_manager.EResult.ServiceUnavailable,
            steam_manager.EResult.TryAnotherCM,
            steam_manager.EResult.LimitExceeded,
            steam_manager.EResult.RateLimitExceeded,
        )

        for expected_result in transient_results:
            raw_result = int(expected_result)
            with self.subTest(eresult=expected_result.name):
                manager = steam_manager.SteamAccountManager(
                    f"account-refresh-transient-{raw_result}",
                    f"RefreshTransient{raw_result}",
                )
                credentials = {
                    "refresh_token": "saved-refresh-token",
                    "password": "saved-password",
                }
                with mock.patch.object(
                    manager.client,
                    "login",
                    return_value=expected_result,
                ) as login:
                    result = manager._login_with_saved_credentials(credentials)

                self.assertEqual(result, expected_result)
                login.assert_called_once_with(
                    username=manager.steam_username,
                    refresh_token="saved-refresh-token",
                )

    def test_saved_refresh_terminal_error_keeps_password_fallback(self):
        manager = steam_manager.SteamAccountManager(
            "account-refresh-terminal", "RefreshTerminalSteamUser"
        )
        credentials = {
            "refresh_token": "expired-refresh-token",
            "password": "saved-password",
        }
        with (
            mock.patch.object(
                manager.client,
                "login",
                side_effect=(
                    steam_manager.EResult.InvalidPassword,
                    steam_manager.EResult.OK,
                ),
            ) as login,
            mock.patch.object(
                manager,
                "_record_login_success",
                return_value=True,
            ) as record_success,
        ):
            result = manager._login_with_saved_credentials(credentials)

        self.assertEqual(result, steam_manager.EResult.OK)
        self.assertEqual(
            login.call_args_list,
            [
                mock.call(
                    username=manager.steam_username,
                    refresh_token="expired-refresh-token",
                ),
                mock.call(
                    username=manager.steam_username,
                    password="saved-password",
                ),
            ],
        )
        record_success.assert_called_once_with(
            password="saved-password",
            expected_connection_generation=0,
        )

    def test_stale_scheduled_reconnect_does_not_touch_new_session(self):
        manager = steam_manager.SteamAccountManager(
            "account-stale-reconnect", "StaleReconnectSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "stop_games", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(steam_manager.gevent, "spawn_later") as spawn_later,
        ):
            first = manager.start_boost([730])
            manager._schedule_reconnect(first["generation"])
            manager._schedule_reconnect(first["generation"])
            self.assertEqual(spawn_later.call_count, 1)
            scheduled_callback = spawn_later.call_args.args[1]
            scheduled_generation = spawn_later.call_args.args[2]
            scheduled_token = spawn_later.call_args.args[3]

            manager.stop_boost(
                expected_session_id=first["session_id"],
                expected_generation=first["generation"],
            )
            second = manager.start_boost([570])
            with mock.patch.object(manager, "load_credentials") as load_credentials:
                scheduled_callback(scheduled_generation, scheduled_token)

        load_credentials.assert_not_called()
        snapshot = manager.boost_snapshot()
        self.assertTrue(snapshot["boosting"])
        self.assertEqual(snapshot["session_id"], second["session_id"])

    def test_successful_login_cancels_pending_reconnect_ticket(self):
        manager = steam_manager.SteamAccountManager(
            "account-cancel-reconnect", "CancelReconnectSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(steam_manager.gevent, "spawn_later") as spawn_later,
        ):
            started = manager.start_boost([730])
            manager._schedule_reconnect(started["generation"])
            scheduled_callback = spawn_later.call_args.args[1]
            scheduled_generation = spawn_later.call_args.args[2]
            scheduled_token = spawn_later.call_args.args[3]
            self.assertTrue(manager._record_login_success())
            steam_manager.gevent.sleep(0)
            with mock.patch.object(manager, "load_credentials") as load_credentials:
                scheduled_callback(scheduled_generation, scheduled_token)

        load_credentials.assert_not_called()
        self.assertTrue(manager.boost_snapshot()["boosting"])

    def test_manual_login_success_invalidates_inflight_terminal_reconnect(self):
        manager = steam_manager.SteamAccountManager(
            "account-inflight-reconnect", "InflightReconnectSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            started = manager.start_boost([730])

        reconnect_token = "older-reconnect-ticket"
        with manager.state_lock:
            manager._reconnect_pending_generation = started["generation"]
            manager._reconnect_pending_token = reconnect_token

        reconnect_entered = Event()
        release_terminal_result = Event()

        def delayed_terminal_result(_creds):
            reconnect_entered.set()
            release_terminal_result.wait()
            return steam_manager.EResult.InvalidPassword

        with (
            mock.patch.object(
                manager,
                "load_credentials",
                return_value={"password": "saved-password"},
            ),
            mock.patch.object(
                manager,
                "_login_with_saved_credentials",
                side_effect=delayed_terminal_result,
            ),
            mock.patch.object(manager, "_resume_boost", return_value=True),
            mock.patch.object(
                manager.client,
                "stop_games",
                return_value=steam_manager.EResult.OK,
            ) as stop_games,
        ):
            reconnect = steam_manager.gevent.spawn(
                manager._try_reconnect,
                started["generation"],
                reconnect_token,
            )
            self.assertTrue(reconnect_entered.wait(timeout=0.5))

            self.assertTrue(manager._record_login_success())
            release_terminal_result.set()
            reconnect.join(timeout=0.5)

        self.assertTrue(reconnect.ready())
        self.assertIsNone(reconnect.exception)
        stop_games.assert_not_called()
        snapshot = manager.boost_snapshot()
        self.assertTrue(snapshot["logged_in"])
        self.assertTrue(snapshot["boosting"])
        self.assertEqual(snapshot["session_id"], started["session_id"])
        self.assertIsNone(manager._reconnect_pending_generation)
        self.assertIsNone(manager._reconnect_pending_token)

    def test_manual_login_success_invalidates_max_attempt_finalization(self):
        manager = steam_manager.SteamAccountManager(
            "account-max-attempt-race", "MaxAttemptRaceSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            started = manager.start_boost([730])

        with manager.state_lock:
            manager._reconnect_attempts = 5

        finalize_entered = Event()
        release_finalization = Event()
        original_finalize = manager._finalize_fatal_session

        def delayed_finalize(*args, **kwargs):
            finalize_entered.set()
            release_finalization.wait()
            return original_finalize(*args, **kwargs)

        reconnect = None
        try:
            with (
                mock.patch.object(
                    manager,
                    "_finalize_fatal_session",
                    side_effect=delayed_finalize,
                ),
                mock.patch.object(manager, "_resume_boost", return_value=True),
                mock.patch.object(
                    manager.client,
                    "stop_games",
                    return_value=steam_manager.EResult.OK,
                ) as stop_games,
            ):
                reconnect = steam_manager.gevent.spawn(
                    manager._schedule_reconnect,
                    started["generation"],
                )
                self.assertTrue(finalize_entered.wait(timeout=0.5))

                self.assertTrue(manager._record_login_success())
                release_finalization.set()
                reconnect.join(timeout=0.5)

            self.assertTrue(reconnect.ready())
            self.assertIsNone(reconnect.exception)
            stop_games.assert_not_called()
            snapshot = manager.boost_snapshot()
            self.assertTrue(snapshot["logged_in"])
            self.assertTrue(snapshot["boosting"])
            self.assertEqual(snapshot["session_id"], started["session_id"])
            self.assertIsNone(manager._reconnect_pending_generation)
            self.assertIsNone(manager._reconnect_pending_token)
        finally:
            release_finalization.set()
            if reconnect is not None:
                reconnect.join(timeout=0.5)

    def test_connection_generation_change_replaces_inflight_reconnect_ticket(self):
        manager = steam_manager.SteamAccountManager(
            "account-generation-reconnect", "GenerationReconnectSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            started = manager.start_boost([730])

        old_token = "transport-generation-one"
        with manager.state_lock:
            manager._reconnect_pending_generation = started["generation"]
            manager._reconnect_pending_token = old_token

        def disconnect_during_login(_credentials):
            with manager.state_lock:
                manager._connection_event_generation += 1
            return steam_manager.EResult.Fail

        with (
            mock.patch.object(
                manager,
                "load_credentials",
                return_value={"password": "saved-password"},
            ),
            mock.patch.object(
                manager,
                "_login_with_saved_credentials",
                side_effect=disconnect_during_login,
            ),
            mock.patch.object(steam_manager.gevent, "spawn_later") as spawn_later,
            mock.patch.object(manager.client, "stop_games") as stop_games,
        ):
            manager._try_reconnect(started["generation"], old_token)

        spawn_later.assert_called_once()
        self.assertEqual(spawn_later.call_args.args[1], manager._try_reconnect)
        successor_generation = spawn_later.call_args.args[2]
        successor_token = spawn_later.call_args.args[3]
        self.assertEqual(successor_generation, started["generation"])
        self.assertNotEqual(successor_token, old_token)
        self.assertEqual(
            manager._reconnect_pending_generation,
            started["generation"],
        )
        self.assertEqual(manager._reconnect_pending_token, successor_token)
        stop_games.assert_not_called()
        self.assertTrue(manager.boost_snapshot()["boosting"])

    def test_fatal_finalization_durability_failure_retries_with_cas_ticket(self):
        manager = steam_manager.SteamAccountManager(
            "account-fatal-durable-retry", "FatalDurableRetrySteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            started = manager.start_boost([730])

        old_token = "fatal-durability-ticket"
        with manager.state_lock:
            manager._reconnect_pending_generation = started["generation"]
            manager._reconnect_pending_token = old_token
            connection_generation = manager._connection_event_generation

        with (
            mock.patch.object(
                manager,
                "_remember_final_segment_unlocked",
                return_value=False,
            ),
            mock.patch.object(steam_manager.gevent, "spawn_later") as spawn_later,
            mock.patch.object(manager.client, "stop_games") as stop_games,
        ):
            finalized = manager._finalize_fatal_session(
                started["generation"],
                "durability test",
                expected_reconnect_token=old_token,
                expected_connection_generation=connection_generation,
            )

        self.assertFalse(finalized)
        self.assertTrue(manager.boost_snapshot()["boosting"])
        stop_games.assert_not_called()
        spawn_later.assert_called_once()
        retry_call = spawn_later.call_args
        retry_token = retry_call.kwargs["expected_reconnect_token"]
        self.assertNotEqual(retry_token, old_token)
        self.assertEqual(
            retry_call.args[0],
            steam_manager.FATAL_FINALIZATION_RETRY_SECONDS,
        )
        self.assertEqual(retry_call.args[1], manager._finalize_fatal_session)
        self.assertEqual(manager._reconnect_pending_token, retry_token)

        # A newer successful/manual login owns the session and invalidates the
        # delayed fatal retry. Executing the stale callback must not stop games.
        with mock.patch.object(manager, "_resume_boost", return_value=True):
            self.assertTrue(manager._record_login_success())
            steam_manager.gevent.sleep(0)
        with mock.patch.object(manager.client, "stop_games") as stale_stop_games:
            result = retry_call.args[1](
                *retry_call.args[2:],
                **retry_call.kwargs,
            )
        self.assertFalse(result)
        stale_stop_games.assert_not_called()
        self.assertTrue(manager.boost_snapshot()["boosting"])
        self.assertIsNone(manager._reconnect_pending_generation)
        self.assertIsNone(manager._reconnect_pending_token)

    def test_hard_quota_cutoff_invalidates_inflight_login_success(self):
        manager = steam_manager.SteamAccountManager(
            "account-fenced-login", "FencedLoginSteamUser"
        )
        manager.logged_in = True
        manager.client.connected = True
        manager.client.logged_in = True
        with (
            mock.patch.object(
                manager.client,
                "change_status",
                return_value=steam_manager.EResult.OK,
            ),
            mock.patch.object(
                manager.client,
                "games_played",
                return_value=steam_manager.EResult.OK,
            ),
        ):
            manager.start_boost([730])

        login_entered = Event()
        release_login = Event()

        def delayed_login(**_kwargs):
            login_entered.set()
            release_login.wait(timeout=2)
            return steam_manager.EResult.OK

        with (
            mock.patch.object(
                manager.client,
                "login",
                side_effect=delayed_login,
            ),
            mock.patch.object(
                manager.client,
                "force_disconnect",
                wraps=manager.client.force_disconnect,
            ) as force_disconnect,
            mock.patch.object(manager, "save_credentials") as save_credentials,
        ):
            login_job = steam_manager.gevent.spawn(
                manager._login_with_credentials,
                "correct-password",
            )
            self.assertTrue(login_entered.wait(timeout=0.5))
            cutoff = manager.emergency_quota_cutoff(
                steam_manager.time.time(),
                "login-race-fence",
                reason="test",
            )
            release_login.set()
            login_job.join(timeout=1)

        self.assertTrue(cutoff["remote_stop_confirmed"])
        self.assertTrue(login_job.ready())
        self.assertIsNone(login_job.exception)
        self.assertEqual(login_job.value, steam_manager.EResult.NoConnection)
        self.assertFalse(manager.boost_snapshot()["logged_in"])
        force_disconnect.assert_called_once_with()
        save_credentials.assert_not_called()
        manager.release_quota_fence("login-race-fence")

    def test_worker_event_reader_never_blocks_on_account_state_lock(self):
        manager = steam_manager.SteamAccountManager(
            "account-event-lock", "EventLockSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
        ):
            manager.start_boost([730])

        with mock.patch.object(manager, "_schedule_reconnect") as schedule:
            with manager.state_lock:
                # _emit represents the worker stdout reader. It must enqueue the
                # state mutation and return even while another greenlet owns the
                # manager lock.
                manager.client._emit("disconnected")
                schedule.assert_not_called()
            steam_manager.gevent.sleep(0)

        schedule.assert_called_once()

    def test_resume_failure_finalizes_session_without_ghost_state(self):
        manager = steam_manager.SteamAccountManager(
            "account-resume-failure", "ResumeFailureSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
        ):
            started = manager.start_boost([730])
        with manager.state_lock:
            manager.start_time = steam_manager.time.time() - 1

        callbacks = []
        old_callback = steam_manager.boost_service.fatal_disconnect_callback
        steam_manager.boost_service.fatal_disconnect_callback = (
            lambda *args: callbacks.append(args)
        )
        self.addCleanup(
            setattr,
            steam_manager.boost_service,
            "fatal_disconnect_callback",
            old_callback,
        )
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.Fail
            ),
            mock.patch.object(
                manager.client, "stop_games", return_value=steam_manager.EResult.OK
            ),
        ):
            self.assertFalse(manager._resume_boost(started["generation"]))

        self.assertFalse(manager.boost_snapshot()["boosting"])
        self.assertEqual(len(callbacks), 1)

    def test_legacy_two_argument_fatal_callback_remains_compatible(self):
        manager = steam_manager.SteamAccountManager(
            "account-legacy-callback", "LegacyCallbackSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
        ):
            started = manager.start_boost([730])
        with manager.state_lock:
            manager.start_time = steam_manager.time.time() - 1

        callbacks = []
        old_callback = steam_manager.boost_service.fatal_disconnect_callback
        steam_manager.boost_service.fatal_disconnect_callback = (
            lambda account_id, elapsed: callbacks.append((account_id, elapsed))
        )
        self.addCleanup(
            setattr,
            steam_manager.boost_service,
            "fatal_disconnect_callback",
            old_callback,
        )
        with mock.patch.object(
            manager.client, "stop_games", return_value=steam_manager.EResult.OK
        ):
            self.assertTrue(
                manager._finalize_fatal_session(
                    started["generation"], "legacy callback test"
                )
            )

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0][0], manager.account_id)

    def test_fatal_callback_type_error_is_not_retried_with_legacy_arity(self):
        manager = steam_manager.SteamAccountManager(
            "account-callback-error", "CallbackErrorSteamUser"
        )
        manager.logged_in = True
        with (
            mock.patch.object(
                manager.client, "change_status", return_value=steam_manager.EResult.OK
            ),
            mock.patch.object(
                manager.client, "games_played", return_value=steam_manager.EResult.OK
            ),
        ):
            started = manager.start_boost([730])
        with manager.state_lock:
            manager.start_time = steam_manager.time.time() - 1

        calls = []

        def broken_callback(
            account_id,
            elapsed,
            session_id,
            generation,
            started_at,
            app_ids,
        ):
            calls.append(account_id)
            raise TypeError("callback implementation error")

        old_callback = steam_manager.boost_service.fatal_disconnect_callback
        steam_manager.boost_service.fatal_disconnect_callback = broken_callback
        self.addCleanup(
            setattr,
            steam_manager.boost_service,
            "fatal_disconnect_callback",
            old_callback,
        )
        with (
            mock.patch.object(
                manager.client, "stop_games", return_value=steam_manager.EResult.OK
            ),
            self.assertLogs(steam_manager.logger, level="ERROR") as captured_logs,
        ):
            self.assertTrue(
                manager._finalize_fatal_session(
                    started["generation"], "callback error test"
                )
            )

        self.assertEqual(calls, [manager.account_id])
        self.assertTrue(
            any(
                "Fatal disconnect callback hatasi" in line
                for line in captured_logs.output
            )
        )


if __name__ == "__main__":
    unittest.main()
