"""UTC and elapsed-time primitives for HourBoost.

SQLite has no native timezone-aware timestamp type.  Persistent values therefore
remain stored as timezone-naive UTC for rollback compatibility, while the Python
side of the application always receives aware UTC datetimes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import math
import time
from threading import RLock
from typing import Callable, Optional

from sqlalchemy.types import DateTime, TypeDecorator


UTC = timezone.utc
UTC_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class Clock:
    """Injectable wall/monotonic clock.

    ``epoch`` is for persistent instants and protocol timestamps. ``monotonic``
    is for elapsed durations and process-local throttles. ``steady_epoch`` is
    one process-wide UTC-shaped timeline derived from the monotonic source.
    Boost accounting uses that shared timeline so a wall-clock correction
    cannot put accounts or checkpoints into incompatible epoch domains.

    The default sources are resolved on every call so tests can inject or patch
    them deterministically.  The steady anchors are captured once per Clock
    instance; all managers sharing that instance therefore share one epoch
    domain.
    """

    def __init__(
        self,
        *,
        epoch_source: Optional[Callable[[], float]] = None,
        monotonic_source: Optional[Callable[[], float]] = None,
    ):
        self._epoch_source = epoch_source
        self._monotonic_source = monotonic_source
        self._steady_lock = RLock()
        self._steady_epoch_anchor = self.epoch()
        self._steady_monotonic_anchor = self.monotonic()

    def epoch(self) -> float:
        value = float(
            self._epoch_source() if self._epoch_source is not None else time.time()
        )
        if not math.isfinite(value):
            raise ValueError("wall-clock epoch must be finite")
        return value

    def monotonic(self) -> float:
        value = float(
            self._monotonic_source()
            if self._monotonic_source is not None
            else time.monotonic()
        )
        if not math.isfinite(value):
            raise ValueError("monotonic clock must be finite")
        return value

    def steady_epoch(self) -> float:
        """Return a UTC-shaped epoch that advances only with monotonic time."""

        with self._steady_lock:
            return self._steady_epoch_anchor + max(
                0.0,
                self.monotonic() - self._steady_monotonic_anchor,
            )

    def advance_steady_floor(self, minimum_epoch: float) -> float:
        """Advance, but never rewind, the process-wide accounting timeline.

        The caller restores ``minimum_epoch`` from durable accounting facts at
        process startup. Re-anchoring at the current monotonic sample preserves
        elapsed-time behavior after a backward wall-clock correction without
        creating an independently persisted clock.
        """

        minimum_epoch = float(minimum_epoch)
        if not math.isfinite(minimum_epoch):
            raise ValueError("steady epoch floor must be finite")
        with self._steady_lock:
            monotonic_now = self.monotonic()
            current = self._steady_epoch_anchor + max(
                0.0,
                monotonic_now - self._steady_monotonic_anchor,
            )
            if minimum_epoch <= current:
                return current
            self._steady_epoch_anchor = minimum_epoch
            self._steady_monotonic_anchor = monotonic_now
            return minimum_epoch

    def now_utc(self) -> datetime:
        return utc_from_epoch(self.epoch())


clock = Clock()


def as_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime.

    Legacy naive values are defined by the application contract as UTC.  Their
    wall fields are tagged, never shifted.  Aware values are converted to the
    equivalent UTC instant.
    """

    if not isinstance(value, datetime):
        raise TypeError("datetime value is required")
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def utc_now() -> datetime:
    return clock.now_utc()


def utc_from_epoch(value) -> datetime:
    epoch = float(value)
    if not math.isfinite(epoch):
        raise ValueError("epoch must be finite")
    return datetime.fromtimestamp(epoch, tz=UTC)


def utc_to_epoch(value: datetime) -> float:
    return as_utc(value).timestamp()


def storage_utc(value: datetime) -> datetime:
    """Normalize to UTC and remove tzinfo for portable DB storage."""

    return as_utc(value).replace(tzinfo=None)


def utc_iso_z(value: Optional[datetime]) -> Optional[str]:
    """Serialize an instant as ISO-8601 with an explicit UTC ``Z`` suffix."""

    if value is None:
        return None
    return as_utc(value).isoformat().replace("+00:00", "Z")


class UTCDateTime(TypeDecorator):
    """Portable aware-UTC ORM type backed by naive UTC storage.

    Existing SQLite rows remain byte-for-byte compatible with the old
    ``DateTime`` mapping.  New and legacy naive writes are interpreted as UTC;
    ORM reads always return aware UTC.  PostgreSQL's physical TIMESTAMPTZ
    conversion intentionally remains a separate Phase 5H migration.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return storage_utc(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return as_utc(value)
