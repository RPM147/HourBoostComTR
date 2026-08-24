"""Exact integer primitives for HourBoost usage accounting.

Boost runtime observations arrive as floating-point seconds, but floats are not
stored or accumulated.  New segments are rounded up once to the nearest
microsecond so a positive session can never become free.  The legacy integer
seconds column is still dual-written with a conservative ceiling to keep a
source rollback safe.
"""

from __future__ import annotations

import math


MICROSECONDS_PER_SECOND = 1_000_000
# The canonical value must also be representable by the rollback-compatible
# ceiling in ``duration_seconds`` and safely backfillable as ``seconds * 1e6``.
MAX_DURATION_MICROSECONDS = (
    ((1 << 63) - 1) // MICROSECONDS_PER_SECOND
) * MICROSECONDS_PER_SECOND


def billable_microseconds(duration_seconds) -> int:
    """Convert one runtime observation to a non-negative integer ledger value.

    A tiny tolerance removes binary noise immediately above an exact
    microsecond boundary.  The remaining upward bias is strictly below one
    microsecond per finalized segment instead of below one second.
    """

    if duration_seconds is None:
        return 0
    if isinstance(duration_seconds, bool):
        raise ValueError("duration_seconds must be numeric")
    try:
        duration = float(duration_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("duration_seconds must be numeric") from exc
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("duration_seconds must be finite and non-negative")
    if duration == 0:
        return 0

    scaled = duration * MICROSECONDS_PER_SECOND
    if not math.isfinite(scaled) or scaled > MAX_DURATION_MICROSECONDS:
        raise OverflowError("duration exceeds the signed 64-bit ledger range")

    # The tolerance is one millionth of a microsecond.  It only absorbs float
    # representation noise and cannot erase a meaningful positive duration.
    return max(1, int(math.ceil(scaled - 1e-6)))


def capped_microseconds(duration_seconds) -> int:
    """Quantize an absolute hard cap without ever exceeding that boundary.

    Epoch subtraction can carry a fraction of one microsecond because a modern
    Unix timestamp is a large float.  Flooring is required at quota fences;
    ordinary finalized segments continue to use ``billable_microseconds``.
    """

    if duration_seconds is None:
        return 0
    if isinstance(duration_seconds, bool):
        raise ValueError("duration_seconds must be numeric")
    try:
        duration = float(duration_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("duration_seconds must be numeric") from exc
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("duration_seconds must be finite and non-negative")
    scaled = duration * MICROSECONDS_PER_SECOND
    if not math.isfinite(scaled) or scaled > MAX_DURATION_MICROSECONDS:
        raise OverflowError("duration exceeds the signed 64-bit ledger range")
    return max(0, int(math.floor(scaled)))


def legacy_seconds_for_microseconds(duration_microseconds) -> int:
    """Return the conservative integer-seconds value written for rollback."""

    duration = _validated_integer_microseconds(duration_microseconds)
    if duration == 0:
        return 0
    return (
        duration + MICROSECONDS_PER_SECOND - 1
    ) // MICROSECONDS_PER_SECOND


def effective_microseconds(duration_microseconds, duration_seconds) -> int:
    """Read canonical microseconds, falling back to an old seconds-only row."""

    if duration_microseconds is not None:
        return _validated_integer_microseconds(duration_microseconds)

    if duration_seconds is None:
        return 0
    if isinstance(duration_seconds, bool):
        raise ValueError("duration_seconds must be an integer")
    try:
        seconds = int(duration_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("duration_seconds must be an integer") from exc
    if seconds != duration_seconds or seconds < 0:
        raise ValueError("duration_seconds must be a non-negative integer")
    if seconds > MAX_DURATION_MICROSECONDS // MICROSECONDS_PER_SECOND:
        raise OverflowError("legacy duration exceeds the ledger range")
    return seconds * MICROSECONDS_PER_SECOND


def microseconds_to_seconds(duration_microseconds) -> float:
    """Expose a ledger value at API/runtime boundaries as seconds."""

    return (
        _validated_integer_microseconds(duration_microseconds)
        / MICROSECONDS_PER_SECOND
    )


def _validated_integer_microseconds(value) -> int:
    if isinstance(value, bool):
        raise ValueError("duration_microseconds must be an integer")
    try:
        duration = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("duration_microseconds must be an integer") from exc
    if duration != value or duration < 0:
        raise ValueError(
            "duration_microseconds must be a non-negative integer"
        )
    if duration > MAX_DURATION_MICROSECONDS:
        raise OverflowError("duration exceeds the signed 64-bit ledger range")
    return duration
