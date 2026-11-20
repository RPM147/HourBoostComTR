"""Fail-closed runtime configuration boundaries for Phase 5H.

This module deliberately has no Flask or application imports.  It can therefore
validate deployment configuration before extensions, database schema helpers,
background greenlets, or Gunicorn workers are started.

The returned profile contains classifications only.  Connection URLs are never
stored on it, which makes ``repr()``, dataclass serialization, and routine
configuration logging safe by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
import stat
from typing import Mapping, Union
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url


DEFAULT_SCHEMA_MODE = "alembic"
DEFAULT_SECURITY_STATE_BACKEND = "local"
DEFAULT_LIMITER_STORAGE_URI = "memory://"

# Phase 5H.0 installs the activation guard before the Redis-backed security
# adapters exist.  This is a code capability, not an environment override: an
# operator must never be able to claim that Redis protects security state while
# the application is still using process-local dictionaries.
REDIS_SECURITY_STATE_CAPABLE = False


class RuntimeConfigError(RuntimeError):
    """Raised when a runtime combination is unsupported or unsafe."""


@dataclass(frozen=True)
class RuntimeProfile:
    """Secret-free, validated runtime classification.

    Raw database and Redis URLs intentionally do not belong in this object.
    Callers may safely log the profile, while retaining the original URLs only
    in the configuration fields consumed by their respective clients.
    """

    database_backend: str
    schema_mode: str
    security_state_backend: str
    limiter_backend: str
    workers: int

    @property
    def uses_alembic(self) -> bool:
        return self.schema_mode == "alembic"


def _env_value(
    env: Mapping[str, str],
    name: str,
    *,
    default: str | None = None,
    allow_empty: bool = False,
) -> str | None:
    """Read one environment value without ever echoing its content."""

    try:
        value = env.get(name)
    except Exception:
        raise RuntimeConfigError(
            f"Unable to read the {name} environment variable."
        ) from None
    if value is None:
        return default
    if not isinstance(value, str):
        raise RuntimeConfigError(f"{name} must be a string.")
    value = value.strip()
    if not value and not allow_empty:
        raise RuntimeConfigError(f"{name} must not be empty.")
    return value or default


def _worker_count(value: Union[int, str]) -> int:
    if isinstance(value, bool):
        raise RuntimeConfigError("The web worker count must be exactly 1.")
    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError):
        raise RuntimeConfigError("The web worker count must be exactly 1.") from None
    # Reject coercions such as 1.0 even though int(1.0) happens to succeed.
    if not isinstance(value, (int, str)):
        raise RuntimeConfigError("The web worker count must be exactly 1.")
    if isinstance(value, str) and value.strip() != "1":
        raise RuntimeConfigError("The web worker count must be exactly 1.")
    if normalized != 1:
        raise RuntimeConfigError("The web worker count must be exactly 1.")
    return normalized


def _database_backend(database_url: str, *, explicitly_configured: bool) -> str:
    try:
        parsed = make_url(database_url)
    except Exception:
        # SQLAlchemy's parsing exception may include the supplied URL.  Suppress
        # its exception chain and return a constant, secret-free message.
        raise RuntimeConfigError("DATABASE_URL is not a valid database URL.") from None

    if parsed.drivername == "sqlite":
        runtime_sqlite_path(database_url)
        return "sqlite"
    if parsed.drivername == "postgresql+psycopg":
        if not explicitly_configured:
            raise RuntimeConfigError(
                "PostgreSQL requires an explicit DATABASE_URL."
            )
        if not parsed.database:
            raise RuntimeConfigError(
                "PostgreSQL DATABASE_URL must name a database."
            )
        return "postgresql"
    raise RuntimeConfigError(
        "DATABASE_URL must use sqlite or the postgresql+psycopg driver."
    )


def runtime_sqlite_path(database_url: str) -> Path:
    """Validate an explicitly named, existing SQLite file without opening it.

    URL options and alternate SQLite drivers are not an escape hatch for URI
    modes, relative paths, attached databases or shared in-memory databases.
    Every failure deliberately omits the operator-supplied URL and path.
    """
    try:
        parsed = make_url(database_url)
        database = parsed.database or ""
        if (
            parsed.drivername != "sqlite"
            or parsed.query
            or any(value is not None for value in (
                parsed.username, parsed.password, parsed.host, parsed.port,
            ))
            or not database
            or database == ":memory:"
            or database.startswith("file:")
            or "#" in database
            or "\x00" in database
            or any(part in {".", ".."} for part in database.replace("\\", "/").split("/"))
        ):
            raise ValueError
        path = Path(database)
        if not path.is_absolute() or path != path.resolve(strict=True):
            raise ValueError
        for component in (path, *path.parents):
            if component.is_symlink() or (
                hasattr(component, "is_junction") and component.is_junction()
            ):
                raise ValueError
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            raise ValueError
    except Exception:
        raise RuntimeConfigError(
            "Runtime SQLite requires an explicit absolute canonical existing "
            "nonempty persistent file, without URL options or symlinks."
        ) from None
    return path


def sqlite_runtime_creator(database_url: str):
    """Return a DBAPI factory that can open, but never create, the runtime DB.

    Revalidate on each pool connection and reject replaced files. ``mode=rw``
    closes the ordinary missing-file race after validation: SQLite cannot
    silently create a fresh database if the validated path disappears.
    Database directories must remain writable only by trusted operators.
    """
    path = runtime_sqlite_path(database_url)
    original = path.stat(follow_symlinks=False)
    identity = (original.st_dev, original.st_ino)

    def connect():
        connection = None
        try:
            current_path = runtime_sqlite_path(database_url)
            before = current_path.stat(follow_symlinks=False)
            if (before.st_dev, before.st_ino) != identity:
                raise ValueError
            connection = sqlite3.connect(
                path.as_uri() + "?mode=rw", uri=True,
                check_same_thread=False, timeout=5,
            )
            after = current_path.stat(follow_symlinks=False)
            if (after.st_dev, after.st_ino) != identity:
                raise ValueError
            connection.execute("PRAGMA foreign_keys=ON")
            return connection
        except Exception:
            if connection is not None:
                connection.close()
            raise RuntimeConfigError(
                "The configured runtime SQLite file could not be opened safely."
            ) from None

    return connect


def _valid_redis_url(value: str) -> bool:
    """Return whether a Redis TCP URL has the deliberately narrow shape used here."""

    try:
        parsed = urlsplit(value)
        # Reading ``port`` also rejects malformed/out-of-range port values.
        parsed.port
    except Exception:
        return False
    return (
        parsed.scheme in {"redis", "rediss"}
        and bool(parsed.hostname)
        and not parsed.fragment
    )


def validate_runtime_config(
    env: Mapping[str, str],
    *,
    workers: Union[int, str] = 1,
) -> RuntimeProfile:
    """Validate the only runtime combinations currently supported.

    Phase 5H.1B permits existing SQLite/Alembic/local-state only at runtime.
    The PostgreSQL/Alembic pairing is classified for future configuration work,
    but Config and the runtime schema guard reject activation before 5H.1C.
    Redis selection remains explicit and fails until its adapter has landed.
    """

    worker_count = _worker_count(workers)

    database_was_set = "DATABASE_URL" in env
    database_url = _env_value(env, "DATABASE_URL")
    if not database_was_set or database_url is None:
        raise RuntimeConfigError("DATABASE_URL must be explicitly configured.")
    schema_mode = _env_value(
        env,
        "DB_SCHEMA_MODE",
        default=DEFAULT_SCHEMA_MODE,
    )
    if schema_mode != "alembic":
        raise RuntimeConfigError(
            "DB_SCHEMA_MODE must be alembic; runtime schema mutation is retired."
        )

    database_backend = _database_backend(
        database_url,
        explicitly_configured=database_was_set,
    )

    security_state_backend = _env_value(
        env,
        "SECURITY_STATE_BACKEND",
        default=DEFAULT_SECURITY_STATE_BACKEND,
    )
    if security_state_backend not in {"local", "redis"}:
        raise RuntimeConfigError(
            "SECURITY_STATE_BACKEND must be local or redis."
        )

    limiter_uri = _env_value(
        env,
        "LIMITER_STORAGE_URI",
        default=DEFAULT_LIMITER_STORAGE_URI,
    )
    if security_state_backend == "local":
        if limiter_uri != DEFAULT_LIMITER_STORAGE_URI:
            raise RuntimeConfigError(
                "Local security state requires LIMITER_STORAGE_URI=memory://."
            )
        limiter_backend = "memory"
    else:
        # Check the immutable code capability before parsing either secret URL.
        # This keeps the current Phase 5H.0 rejection deterministic and safe.
        if not REDIS_SECURITY_STATE_CAPABLE:
            raise RuntimeConfigError(
                "Redis security-state support is unavailable in this build."
            )
        redis_url = _env_value(env, "REDIS_URL")
        if not _valid_redis_url(redis_url):
            raise RuntimeConfigError("REDIS_URL must be a valid Redis URL.")
        if not _valid_redis_url(limiter_uri):
            raise RuntimeConfigError(
                "Redis security state requires a Redis LIMITER_STORAGE_URI."
            )
        limiter_backend = "redis"

    return RuntimeProfile(
        database_backend=database_backend,
        schema_mode=schema_mode,
        security_state_backend=security_state_backend,
        limiter_backend=limiter_backend,
        workers=worker_count,
    )


def assert_alembic_at_head(engine, migrations_dir) -> str:
    """Return the sole Alembic head after proving the database is current.

    This is a revision-only primitive, not the full runtime startup gate.
    ``schema_tools.assert_runtime_schema`` additionally verifies schema/data.
    Alembic is imported lazily. All failures use constant messages and suppress
    underlying exception chains because DB driver errors can contain connection
    URLs or credentials.
    """

    # A migration directory now exists, but its first baseline is deliberately
    # SQLite-only. A manually stamped PostgreSQL DB must not activate runtime
    # merely because its version string matches. Phase 5H.1C owns this gate.
    if engine.dialect.name == "postgresql":
        raise RuntimeConfigError(
            "PostgreSQL runtime is not enabled before Phase 5H.1C acceptance."
        )

    try:
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory
    except ImportError:
        raise RuntimeConfigError(
            "Alembic support is unavailable in this build."
        ) from None

    try:
        root = Path(migrations_dir)
    except (TypeError, ValueError, OSError):
        raise RuntimeConfigError("Alembic migration directory is invalid.") from None
    if not root.is_dir():
        raise RuntimeConfigError("Alembic migration directory is missing.")
    if not (root / "env.py").is_file() or not (root / "versions").is_dir():
        raise RuntimeConfigError("Alembic migration tree is incomplete.")

    try:
        script = ScriptDirectory(str(root))
        heads = tuple(script.get_heads())
    except Exception:
        raise RuntimeConfigError(
            "Alembic migration tree could not be loaded."
        ) from None
    if not heads:
        raise RuntimeConfigError("Alembic migration tree has no head revision.")
    if len(heads) != 1:
        raise RuntimeConfigError(
            "Alembic migration tree must have exactly one head revision."
        )

    try:
        with engine.connect() as connection:
            current_heads = tuple(
                MigrationContext.configure(connection).get_current_heads()
            )
    except Exception:
        raise RuntimeConfigError(
            "Alembic database revision could not be read."
        ) from None
    if not current_heads:
        raise RuntimeConfigError("Database has no Alembic revision.")
    if len(current_heads) != 1 or current_heads[0] != heads[0]:
        raise RuntimeConfigError(
            "Database is not at the Alembic head revision."
        )
    return heads[0]
