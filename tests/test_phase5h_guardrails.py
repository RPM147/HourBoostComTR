import builtins
import ast
from contextlib import closing
from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import runpy
import sqlite3
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, text
from sqlalchemy.dialects import postgresql, sqlite

import runtime_guardrails
from runtime_guardrails import (
    RuntimeConfigError,
    assert_alembic_at_head,
    runtime_sqlite_path,
    sqlite_runtime_creator,
    validate_runtime_config,
)
from time_utils import UTCDateTime


POSTGRES_URL = (
    "postgresql+psycopg://hourboost:do-not-print-this@db.internal/hourboost"
)
ALEMBIC_AVAILABLE = importlib.util.find_spec("alembic") is not None


class RuntimeConfigurationGuardrailTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name).resolve() / "runtime.sqlite"
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY)")
            connection.commit()
        self.database_url = "sqlite:///" + self.database.as_posix()

    def validate(self, overrides=None, **kwargs):
        env = {"DATABASE_URL": self.database_url}
        env.update(overrides or {})
        return validate_runtime_config(env, **kwargs)

    def test_default_mode_requires_offline_owned_single_worker_sqlite(self):
        profile = self.validate()

        self.assertEqual(profile.database_backend, "sqlite")
        self.assertEqual(profile.schema_mode, "alembic")
        self.assertEqual(profile.security_state_backend, "local")
        self.assertEqual(profile.limiter_backend, "memory")
        self.assertEqual(profile.workers, 1)
        self.assertTrue(profile.uses_alembic)

    def test_database_url_must_be_explicit(self):
        with self.assertRaisesRegex(RuntimeConfigError, "explicitly"):
            validate_runtime_config({})

    def test_sqlite_runtime_accepts_only_existing_canonical_regular_files(self):
        nonexistent = Path(self.directory.name) / "missing-private-name.sqlite"
        empty = Path(self.directory.name) / "empty.sqlite"
        empty.touch()
        invalid = (
            "sqlite:///relative-private-name.sqlite",
            "sqlite:///" + nonexistent.as_posix(),
            "sqlite:///" + empty.as_posix(),
            "sqlite:///" + Path(self.directory.name).as_posix(),
            self.database_url + "?mode=rw",
            self.database_url + "?uri=true",
            self.database_url + "#private-fragment",
            "sqlite://user:private-secret@localhost/fixture.sqlite",
            "sqlite+pysqlite:///" + self.database.as_posix(),
            "sqlite:///" + self.database.parent.as_posix() + "/../"
            + self.database.parent.name + "/runtime.sqlite",
        )
        for value in invalid:
            with self.subTest(url_type=value.split(":", 1)[0]):
                with self.assertRaises(RuntimeConfigError) as caught:
                    self.validate({"DATABASE_URL": value})
                self.assertNotIn("private-", str(caught.exception))
        self.assertFalse(nonexistent.exists())
        self.assertEqual(empty.stat().st_size, 0)

    def test_symlink_database_and_parent_are_rejected(self):
        linked = Path(self.directory.name) / "linked.sqlite"
        linked_directory = Path(self.directory.name) / "linked-directory"
        try:
            linked.symlink_to(self.database)
            linked_directory.symlink_to(self.database.parent, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("Creating symlinks is unavailable on this host")
        for candidate in (linked, linked_directory / self.database.name):
            with self.assertRaises(RuntimeConfigError):
                self.validate({"DATABASE_URL": "sqlite:///" + candidate.as_posix()})

    def test_sqlite_creator_opens_existing_file_with_foreign_keys_enabled(self):
        creator = sqlite_runtime_creator(self.database_url)
        with closing(creator()) as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            connection.execute("INSERT INTO fixture VALUES (1)")
            connection.commit()
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM fixture").fetchone()[0], 1)

    def test_sqlite_creator_never_recreates_removed_file(self):
        creator = sqlite_runtime_creator(self.database_url)
        self.database.unlink()
        with self.assertRaisesRegex(RuntimeConfigError, "opened safely"):
            creator()
        self.assertFalse(self.database.exists())

    def test_sqlite_creator_mode_rw_closes_validation_to_open_missing_file_race(self):
        creator = sqlite_runtime_creator(self.database_url)
        connect = sqlite3.connect

        def remove_before_open(*args, **kwargs):
            self.assertIn("?mode=rw", args[0])
            self.database.unlink()
            return connect(*args, **kwargs)

        with patch.object(runtime_guardrails.sqlite3, "connect", side_effect=remove_before_open):
            with self.assertRaises(RuntimeConfigError):
                creator()
        self.assertFalse(self.database.exists())

    def test_sqlite_creator_rejects_replacement_file(self):
        creator = sqlite_runtime_creator(self.database_url)
        saved = self.database.with_suffix(".original")
        self.database.rename(saved)
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("CREATE TABLE replacement (id INTEGER)")
            connection.commit()
        with self.assertRaises(RuntimeConfigError):
            creator()

    def test_sqlite_creator_database_driver_failure_is_secret_safe(self):
        creator = sqlite_runtime_creator(self.database_url)
        with patch.object(runtime_guardrails.sqlite3, "connect", side_effect=OSError("private-path")):
            with self.assertRaises(RuntimeConfigError) as caught:
                creator()
        self.assertNotIn("private-path", str(caught.exception))

    def test_config_rejects_postgresql_before_database_engine_creation(self):
        root = Path(__file__).resolve().parents[1]
        with patch.dict("os.environ", {
            "DATABASE_URL": POSTGRES_URL,
            "DB_SCHEMA_MODE": "alembic",
            "SECRET_KEY": "isolated-test-secret",
            "SECURITY_STATE_BACKEND": "local",
            "LIMITER_STORAGE_URI": "memory://",
            "WEB_CONCURRENCY": "1",
        }, clear=True), patch("dotenv.load_dotenv"):
            with self.assertRaisesRegex(RuntimeConfigError, "5H.1C"):
                runpy.run_path(str(root / "config.py"))

    def test_config_uses_open_existing_creator_without_application_import(self):
        root = Path(__file__).resolve().parents[1]
        with patch.dict("os.environ", {
            "DATABASE_URL": self.database_url,
            "SECRET_KEY": "isolated-test-secret",
        }, clear=True), patch("dotenv.load_dotenv"):
            configuration = runpy.run_path(str(root / "config.py"))["Config"]
        self.assertEqual(configuration.DB_SCHEMA_MODE, "alembic")
        self.assertEqual(configuration.SQLALCHEMY_DATABASE_URI, self.database_url)
        options = configuration.SQLALCHEMY_ENGINE_OPTIONS
        self.assertTrue(options["hide_parameters"])
        engine = create_engine(configuration.SQLALCHEMY_DATABASE_URI, **options)
        try:
            with engine.connect() as connection:
                self.assertEqual(connection.execute(text("PRAGMA foreign_keys")).scalar(), 1)
        finally:
            engine.dispose()
        self.database.unlink()
        with self.assertRaises(RuntimeConfigError):
            options["creator"]()
        self.assertFalse(self.database.exists())

    def test_config_has_no_implicit_database_fallback(self):
        root = Path(__file__).resolve().parents[1]
        with patch.dict("os.environ", {
            "SECRET_KEY": "isolated-test-secret",
        }, clear=True), patch("dotenv.load_dotenv"):
            with self.assertRaisesRegex(RuntimeConfigError, "explicitly"):
                runpy.run_path(str(root / "config.py"))

    def test_profile_is_frozen_and_contains_no_connection_urls(self):
        profile = self.validate(
            {
                "DATABASE_URL": POSTGRES_URL,
                "DB_SCHEMA_MODE": "alembic",
            }
        )

        with self.assertRaises(FrozenInstanceError):
            profile.workers = 2
        rendered = repr(profile) + repr(asdict(profile))
        self.assertNotIn("do-not-print-this", rendered)
        self.assertNotIn("db.internal", rendered)

    def test_sqlite_and_postgresql_reject_retired_runtime_schema_mode(self):
        invalid = (
            {
                "DATABASE_URL": self.database_url,
                "DB_SCHEMA_MODE": "runtime_sqlite",
            },
            {
                "DATABASE_URL": POSTGRES_URL,
                "DB_SCHEMA_MODE": "runtime_sqlite",
            },
        )
        for env in invalid:
            with self.subTest(env=env["DB_SCHEMA_MODE"]):
                with self.assertRaises(RuntimeConfigError):
                    self.validate(env)

    def test_exact_postgresql_psycopg_alembic_pair_is_accepted(self):
        profile = self.validate(
            {
                "DATABASE_URL": POSTGRES_URL,
                "DB_SCHEMA_MODE": "alembic",
            }
        )

        self.assertEqual(profile.database_backend, "postgresql")
        self.assertTrue(profile.uses_alembic)

    def test_legacy_and_wrong_postgresql_driver_names_are_rejected(self):
        for scheme in (
            "postgres",
            "postgresql",
            "postgresql+psycopg2",
            "postgresql+asyncpg",
            "mysql+pymysql",
        ):
            secret = "driver-secret"
            with self.subTest(scheme=scheme):
                with self.assertRaises(RuntimeConfigError) as caught:
                    self.validate(
                        {
                            "DATABASE_URL": (
                                f"{scheme}://hourboost:{secret}@db/hourboost"
                            ),
                            "DB_SCHEMA_MODE": "alembic",
                        }
                    )
                self.assertNotIn(secret, str(caught.exception))

    def test_invalid_or_empty_database_url_is_secret_safe(self):
        for value in ("", "not-a-url://user:parse-secret@host/db"):
            with self.subTest(value=bool(value)):
                with self.assertRaises(RuntimeConfigError) as caught:
                    self.validate({"DATABASE_URL": value})
                self.assertNotIn("parse-secret", str(caught.exception))
                if value:
                    self.assertNotIn(value, str(caught.exception))

    def test_runtime_sqlite_requires_a_persistent_file(self):
        for value in (
            "sqlite://",
            "sqlite:///:memory:",
            "sqlite:///file::memory:?cache=shared&uri=true",
            "sqlite:///file:hourboost?mode=memory&cache=shared&uri=true",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeConfigError, "persistent"):
                    self.validate({"DATABASE_URL": value})

    def test_postgresql_requires_a_named_database(self):
        with self.assertRaises(RuntimeConfigError) as caught:
            self.validate(
                {
                    "DATABASE_URL": (
                        "postgresql+psycopg://user:hidden-password@db.internal"
                    ),
                    "DB_SCHEMA_MODE": "alembic",
                }
            )
        self.assertNotIn("hidden-password", str(caught.exception))

    def test_unknown_or_empty_modes_are_rejected(self):
        cases = (
            {"DB_SCHEMA_MODE": ""},
            {"DB_SCHEMA_MODE": "automatic"},
            {"SECURITY_STATE_BACKEND": ""},
            {"SECURITY_STATE_BACKEND": "fallback"},
        )
        for env in cases:
            with self.subTest(env=env):
                with self.assertRaises(RuntimeConfigError):
                    self.validate(env)

    def test_local_security_state_accepts_only_memory_limiter(self):
        secret_uri = "redis://:limiter-secret@redis.internal:6379/0"
        with self.assertRaises(RuntimeConfigError) as caught:
            self.validate({"LIMITER_STORAGE_URI": secret_uri})
        self.assertNotIn("limiter-secret", str(caught.exception))
        self.assertNotIn("redis.internal", str(caught.exception))

    def test_redis_url_presence_does_not_implicitly_activate_redis(self):
        profile = self.validate(
            {"REDIS_URL": "redis://:unused-secret@redis.internal:6379/0"}
        )
        self.assertEqual(profile.security_state_backend, "local")
        self.assertEqual(profile.limiter_backend, "memory")

    def test_explicit_redis_selection_fails_closed_until_adapter_exists(self):
        secret = "redis-secret"
        with self.assertRaises(RuntimeConfigError) as caught:
            self.validate(
                {
                    "SECURITY_STATE_BACKEND": "redis",
                    "REDIS_URL": f"redis://:{secret}@redis.internal:6379/0",
                    "LIMITER_STORAGE_URI": (
                        f"redis://:{secret}@redis.internal:6379/1"
                    ),
                }
            )
        self.assertIn("unavailable", str(caught.exception).lower())
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("redis.internal", str(caught.exception))

    def test_future_redis_capability_still_requires_two_valid_redis_urls(self):
        cases = (
            {
                "SECURITY_STATE_BACKEND": "redis",
                "LIMITER_STORAGE_URI": "redis://redis.internal:6379/1",
            },
            {
                "SECURITY_STATE_BACKEND": "redis",
                "REDIS_URL": "http://redis.internal/secret",
                "LIMITER_STORAGE_URI": "redis://redis.internal:6379/1",
            },
            {
                "SECURITY_STATE_BACKEND": "redis",
                "REDIS_URL": "redis://redis.internal:6379/0",
                "LIMITER_STORAGE_URI": "memory://",
            },
        )
        with patch.object(
            runtime_guardrails,
            "REDIS_SECURITY_STATE_CAPABLE",
            True,
        ):
            for env in cases:
                with self.subTest(env=env):
                    with self.assertRaises(RuntimeConfigError):
                        self.validate(env)

            profile = self.validate(
                {
                    "SECURITY_STATE_BACKEND": "redis",
                    "REDIS_URL": "rediss://redis.internal:6380/0",
                    "LIMITER_STORAGE_URI": "redis://redis.internal:6379/1",
                }
            )
        self.assertEqual(profile.security_state_backend, "redis")
        self.assertEqual(profile.limiter_backend, "redis")

    def test_worker_count_must_be_exactly_one(self):
        for value in (0, 2, -1, True, 1.0, "01", "2", "many", None):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeConfigError):
                    self.validate({}, workers=value)
        self.assertEqual(self.validate({}, workers="1").workers, 1)


class RuntimeSchemaOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / "app.py"
        cls.tree = ast.parse(source.read_text(encoding="utf-8"))
        cls.initialize = next(node for node in cls.tree.body
                              if isinstance(node, ast.FunctionDef)
                              and node.name == "_initialize_database_schema")

    def test_startup_contains_no_schema_mutators_and_keeps_recovery_order(self):
        calls = [node.func for node in ast.walk(self.initialize) if isinstance(node, ast.Call)]
        forbidden = {"create_all", "_ensure_schema", "execute", "exec_driver_sql"}
        self.assertFalse(any(
            (isinstance(func, ast.Name) and func.id in forbidden)
            or (isinstance(func, ast.Attribute) and func.attr in forbidden)
            for func in calls
        ))
        self.assertTrue(any(isinstance(func, ast.Name) and func.id == "assert_runtime_schema"
                            for func in calls))
        startup = next(
            node for node in self.tree.body if isinstance(node, ast.With)
            and any(isinstance(statement, ast.Expr)
                    and isinstance(statement.value, ast.Call)
                    and isinstance(statement.value.func, ast.Name)
                    and statement.value.func.id == "_initialize_database_schema"
                    for statement in node.body)
        )
        self.assertEqual([
            statement.value.func.id for statement in startup.body
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
        ], ["_initialize_database_schema", "_restore_accounting_clock_on_startup",
            "_reconcile_steam_credentials_on_startup", "_reconcile_boost_state_on_startup"])

    def test_schema_validation_passes_finite_paid_plans_and_propagates_failure(self):
        from unittest.mock import Mock
        namespace = {
            "app": SimpleNamespace(root_path="test-root", config={
                "DB_SCHEMA_MODE": "alembic", "DATABASE_BACKEND": "sqlite",
                "PLANS": {"free": {"total_hours": None},
                          "basic": {"total_hours": 1500},
                          "premium": {"total_hours": 3500},
                          "unlimited": {"total_hours": None}},
            }),
            "db": SimpleNamespace(engine=SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))),
            "os": __import__("os"), "assert_runtime_schema": Mock(),
        }
        exec(compile(ast.Module(body=[self.initialize], type_ignores=[]), "startup-unit", "exec"), namespace)
        namespace["_initialize_database_schema"]()
        namespace["assert_runtime_schema"].assert_called_once_with(
            namespace["db"].engine,
            namespace["os"].path.join("test-root", "migrations"),
            paid_plan_names=("basic", "premium"),
        )
        namespace["assert_runtime_schema"].side_effect = RuntimeError("schema rejected")
        with self.assertRaisesRegex(RuntimeError, "schema rejected"):
            namespace["_initialize_database_schema"]()

    def test_retired_schema_helper_fails_before_any_legacy_operation(self):
        helper = next(node for node in self.tree.body
                      if isinstance(node, ast.FunctionDef) and node.name == "_ensure_schema")
        namespace = {}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), "retired-helper", "exec"), namespace)
        with self.assertRaisesRegex(RuntimeError, "retired"):
            namespace["_ensure_schema"]()

    def test_runtime_schema_gate_rejects_mismatch_and_non_sqlite_before_audit(self):
        from unittest.mock import Mock
        for configured, active, mode in (
            ("sqlite", "postgresql", "alembic"),
            ("postgresql", "postgresql", "alembic"),
            ("sqlite", "sqlite", "runtime_sqlite"),
        ):
            with self.subTest(configured=configured, active=active, mode=mode):
                audit = Mock()
                namespace = {
                    "app": SimpleNamespace(config={
                        "DB_SCHEMA_MODE": mode, "DATABASE_BACKEND": configured,
                    }),
                    "db": SimpleNamespace(engine=SimpleNamespace(
                        dialect=SimpleNamespace(name=active),
                    )),
                    "assert_runtime_schema": audit,
                }
                exec(compile(ast.Module(body=[self.initialize], type_ignores=[]),
                             "startup-unit", "exec"), namespace)
                with self.assertRaises(RuntimeError):
                    namespace["_initialize_database_schema"]()
                audit.assert_not_called()


class AlembicHeadGuardrailTests(unittest.TestCase):
    @staticmethod
    def _write_tree(root: Path, revisions):
        (root / "versions").mkdir(parents=True)
        (root / "env.py").write_text("# test tree\n", encoding="utf-8")
        for index, (revision, down_revision) in enumerate(revisions):
            (root / "versions" / f"{index:03d}_{revision}.py").write_text(
                "\n".join(
                    (
                        f"revision = {revision!r}",
                        f"down_revision = {down_revision!r}",
                        "branch_labels = None",
                        "depends_on = None",
                        "",
                    )
                ),
                encoding="utf-8",
            )

    @staticmethod
    def _stamp(engine, revision):
        with engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE alembic_version "
                "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
            ))
            if revision is not None:
                connection.execute(
                    text("INSERT INTO alembic_version (version_num) VALUES (:rev)"),
                    {"rev": revision},
                )

    @unittest.skipUnless(ALEMBIC_AVAILABLE, "Alembic is not installed")
    def test_matching_single_head_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "migrations"
            self._write_tree(root, (("base001", None),))
            engine = create_engine("sqlite:///:memory:")
            try:
                self._stamp(engine, "base001")
                self.assertEqual(assert_alembic_at_head(engine, root), "base001")
            finally:
                engine.dispose()

    @unittest.skipUnless(ALEMBIC_AVAILABLE, "Alembic is not installed")
    def test_missing_or_incomplete_migration_tree_fails_closed(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with tempfile.TemporaryDirectory() as directory:
                missing = Path(directory) / "missing"
                with self.assertRaises(RuntimeConfigError):
                    assert_alembic_at_head(engine, missing)

                incomplete = Path(directory) / "incomplete"
                incomplete.mkdir()
                (incomplete / "env.py").write_text("", encoding="utf-8")
                with self.assertRaises(RuntimeConfigError):
                    assert_alembic_at_head(engine, incomplete)
        finally:
            engine.dispose()

    @unittest.skipUnless(ALEMBIC_AVAILABLE, "Alembic is not installed")
    def test_empty_and_multiple_head_trees_are_rejected(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with tempfile.TemporaryDirectory() as directory:
                empty = Path(directory) / "empty"
                self._write_tree(empty, ())
                with self.assertRaisesRegex(RuntimeConfigError, "no head"):
                    assert_alembic_at_head(engine, empty)

                multiple = Path(directory) / "multiple"
                self._write_tree(
                    multiple,
                    (("head_a", None), ("head_b", None)),
                )
                with self.assertRaisesRegex(RuntimeConfigError, "exactly one"):
                    assert_alembic_at_head(engine, multiple)
        finally:
            engine.dispose()

    @unittest.skipUnless(ALEMBIC_AVAILABLE, "Alembic is not installed")
    def test_unstamped_and_behind_database_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "migrations"
            self._write_tree(
                root,
                (("base001", None), ("head002", "base001")),
            )
            for current in (None, "base001"):
                engine = create_engine("sqlite:///:memory:")
                try:
                    self._stamp(engine, current)
                    with self.subTest(current=current):
                        with self.assertRaises(RuntimeConfigError):
                            assert_alembic_at_head(engine, root)
                finally:
                    engine.dispose()

    @unittest.skipUnless(ALEMBIC_AVAILABLE, "Alembic is not installed")
    def test_database_read_failure_does_not_expose_driver_secret(self):
        class BrokenEngine:
            dialect = SimpleNamespace(name="sqlite")

            def connect(self):
                raise RuntimeError(
                    "postgresql+psycopg://user:driver-secret@db/hourboost"
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "migrations"
            self._write_tree(root, (("base001", None),))
            with self.assertRaises(RuntimeConfigError) as caught:
                assert_alembic_at_head(BrokenEngine(), root)
        self.assertNotIn("driver-secret", str(caught.exception))
        self.assertNotIn("postgresql", str(caught.exception))

    def test_missing_optional_alembic_dependency_fails_closed(self):
        real_import = builtins.__import__

        def reject_alembic(name, *args, **kwargs):
            if name.startswith("alembic"):
                raise ImportError("simulated")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=reject_alembic):
            with self.assertRaisesRegex(RuntimeConfigError, "unavailable"):
                assert_alembic_at_head(
                    SimpleNamespace(dialect=SimpleNamespace(name="sqlite")), "unused"
                )


class UTCDateTimeDialectContractTests(unittest.TestCase):
    def test_sqlite_and_postgresql_bind_values_use_dialect_correct_utc(self):
        value = datetime(
            2026,
            9,
            5,
            15,
            30,
            45,
            123456,
            tzinfo=timezone(timedelta(hours=3)),
        )
        expected_naive = datetime(2026, 9, 5, 12, 30, 45, 123456)
        expected_aware = expected_naive.replace(tzinfo=timezone.utc)
        value_type = UTCDateTime()

        for dialect in (sqlite.dialect(), postgresql.dialect()):
            with self.subTest(dialect=dialect.name):
                expected = (
                    expected_aware
                    if dialect.name == "postgresql"
                    else expected_naive
                )
                self.assertEqual(
                    value_type.process_bind_param(value, dialect),
                    expected,
                )

    def test_physical_datetime_timezone_flag_is_dialect_correct(self):
        value_type = UTCDateTime()

        sqlite_impl = value_type.dialect_impl(sqlite.dialect()).impl
        postgres_impl = value_type.dialect_impl(postgresql.dialect()).impl

        self.assertFalse(sqlite_impl.timezone)
        self.assertTrue(postgres_impl.timezone)

    def test_sqlite_and_postgresql_results_are_aware_utc(self):
        stored = datetime(2026, 9, 5, 12, 30, 45, 123456)
        value_type = UTCDateTime()

        for dialect in (sqlite.dialect(), postgresql.dialect()):
            with self.subTest(dialect=dialect.name):
                result = value_type.process_result_value(stored, dialect)
                self.assertEqual(result, stored.replace(tzinfo=timezone.utc))
                self.assertIs(result.tzinfo, timezone.utc)


class GunicornSingleWorkerGuardrailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.gunicorn_config = runpy.run_path(str(root / "gunicorn_config.py"))

    def test_effective_single_worker_is_accepted(self):
        server = SimpleNamespace(cfg=SimpleNamespace(workers=1))
        self.gunicorn_config["on_starting"](server)

    def test_command_line_multi_worker_override_is_rejected(self):
        server = SimpleNamespace(cfg=SimpleNamespace(workers=2))
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            self.gunicorn_config["on_starting"](server)

    def test_worker_change_hook_rejects_runtime_ttin_growth(self):
        server = SimpleNamespace(
            cfg=SimpleNamespace(workers=1, preload_app=False)
        )
        self.gunicorn_config["nworkers_changed"](server, 1, None)
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            self.gunicorn_config["nworkers_changed"](server, 2, 1)

    def test_preload_override_is_rejected_before_application_import(self):
        server = SimpleNamespace(
            cfg=SimpleNamespace(workers=1, preload_app=True)
        )
        with self.assertRaisesRegex(RuntimeError, "preloading"):
            self.gunicorn_config["nworkers_changed"](server, 1, None)

    def test_dirty_worker_pool_is_rejected(self):
        server = SimpleNamespace(
            cfg=SimpleNamespace(
                workers=1,
                preload_app=False,
                dirty_workers=1,
                dirty_apps=["some.module:App"],
            )
        )
        with self.assertRaisesRegex(RuntimeError, "dirty workers"):
            self.gunicorn_config["nworkers_changed"](server, 1, None)

    def test_hup_reload_is_rejected_to_prevent_worker_overlap(self):
        server = SimpleNamespace(
            cfg=SimpleNamespace(workers=1, preload_app=False)
        )
        with self.assertRaisesRegex(RuntimeError, "HUP reload"):
            self.gunicorn_config["on_reload"](server)

    def test_usr2_reexec_master_is_rejected_before_application_import(self):
        server = SimpleNamespace(
            cfg=SimpleNamespace(workers=1, preload_app=False)
        )
        with patch.dict("os.environ", {"GUNICORN_PID": "1234"}):
            with self.assertRaisesRegex(RuntimeError, "USR2"):
                self.gunicorn_config["nworkers_changed"](server, 1, None)


if __name__ == "__main__":
    unittest.main()
