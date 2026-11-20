"""Frozen logical contract for the Phase 5H.1C PostgreSQL rehearsal.

This module is deliberately independent from Flask, application configuration,
environment loading and database drivers.  It describes how already-audited
SQLite rows are validated and encoded before a later transfer tool writes them
to a disposable PostgreSQL target.  It does not enable the PostgreSQL runtime.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import hashlib
import math
import re
import struct


POSTGRESQL_BASELINE_REVISION = "20260913_01"
REHEARSAL_URL_ENV = "HOURBOOST_POSTGRESQL_REHEARSAL_URL"
TEXT_COLLATION = "C"
MICROSECONDS_PER_SECOND = 1_000_000
MAX_LEDGER_SECONDS = 9_223_372_036_854
MAX_LEDGER_MICROSECONDS = 9_223_372_036_854_000_000
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


# This order satisfies every live foreign-key dependency without disabling
# constraints.  Audit/snapshot columns intentionally are not foreign keys.
TRANSFER_TABLES = (
    "announcements",
    "users",
    "payment_audit_logs",
    "payments",
    "revoked_tokens",
    "steam_accounts",
    "user_sessions",
    "boost_games",
    "boost_logs",
)

TABLE_COLUMNS = {
    "announcements": (
        "id", "title", "content", "type", "is_active", "created_at",
    ),
    "users": (
        "id", "username", "email", "password_hash", "plan",
        "plan_expires", "plan_activated_at", "is_admin", "created_at",
        "last_login", "tokens_valid_after", "lang", "steam_id",
        "steam_avatar", "steam_display_name", "is_verified",
        "verification_token", "verification_sent_at", "reset_token",
        "reset_token_expires", "email_change_token", "email_change_new",
        "email_change_expires",
    ),
    "payment_audit_logs": (
        "id", "payment_id", "actor_user_id", "actor_username", "action",
        "from_status", "to_status", "reason", "created_at",
    ),
    "payments": (
        "id", "user_id", "owner_user_id_snapshot", "owner_username_snapshot",
        "owner_detached_at", "amount", "plan", "status", "transaction_id",
        "match_token", "admin_hidden", "shopier_webhook_id", "shopier_event",
        "shopier_account_id", "shopier_timestamp", "webhook_body_sha256",
        "webhook_received_at", "verification_attempts", "verification_error",
        "verification_last_http_status", "next_verification_at",
        "verification_lock_until", "verified_at", "verified_amount_minor",
        "created_at",
    ),
    "revoked_tokens": (
        "id", "token_jti", "user_id", "revoked_at", "expires_at",
    ),
    "steam_accounts": (
        "id", "user_id", "steam_username", "steam_id", "persona_state",
        "is_boosting", "target_stop_time", "created_at",
    ),
    "user_sessions": (
        "id", "user_id", "token_jti", "token_hint", "expires_at",
        "ip_address", "user_agent", "created_at", "last_seen", "is_active",
    ),
    "boost_games": ("id", "account_id", "app_id"),
    "boost_logs": (
        "id", "account_id", "user_id", "account_id_snapshot",
        "steam_username_snapshot", "owner_user_id_snapshot",
        "owner_username_snapshot", "started_at", "stopped_at",
        "remote_stopped_at", "duration_seconds", "duration_microseconds",
        "games_count", "app_ids_json",
    ),
}

PRIMARY_KEYS = {table: "id" for table in TRANSFER_TABLES}
IDENTITY_TABLES = frozenset(TRANSFER_TABLES) - {"steam_accounts"}

FOREIGN_KEYS = {
    ("payments", "user_id"): ("users", "id"),
    ("revoked_tokens", "user_id"): ("users", "id"),
    ("steam_accounts", "user_id"): ("users", "id"),
    ("user_sessions", "user_id"): ("users", "id"),
    ("boost_games", "account_id"): ("steam_accounts", "id"),
    ("boost_logs", "account_id"): ("steam_accounts", "id"),
    ("boost_logs", "user_id"): ("users", "id"),
}

UNIQUE_CONSTRAINTS = {
    ("users", "uq_users_username"): ("username",),
    ("users", "uq_users_email"): ("email",),
    ("payments", "uq_payments_transaction_id"): ("transaction_id",),
}

INDEX_CONTRACT = {
    "ux_users_steam_id": ("users", ("steam_id",), True, None),
    "ux_users_verification_token": (
        "users", ("verification_token",), True, None,
    ),
    "ux_users_reset_token": ("users", ("reset_token",), True, None),
    "ux_users_email_change_token": (
        "users", ("email_change_token",), True, None,
    ),
    "ix_payment_audit_logs_payment_id": (
        "payment_audit_logs", ("payment_id",), False, None,
    ),
    "ix_payments_match_token": ("payments", ("match_token",), False, None),
    "ux_payments_match_token": (
        "payments", ("match_token",), True, "match_token IS NOT NULL",
    ),
    "ux_payments_transaction_id": (
        "payments", ("transaction_id",), True,
        "transaction_id IS NOT NULL",
    ),
    "ux_payments_one_open_checkout": (
        "payments", ("user_id",), True,
        "user_id IS NOT NULL "
        "AND status IN ('checkout_started', 'verification_pending')",
    ),
    "ix_payments_shopier_webhook_id": (
        "payments", ("shopier_webhook_id",), False, None,
    ),
    "ix_payments_verification_due": (
        "payments",
        ("status", "next_verification_at", "verification_lock_until"),
        False,
        None,
    ),
    "ix_revoked_tokens_token_jti": (
        "revoked_tokens", ("token_jti",), True, None,
    ),
    "ix_user_sessions_token_jti": (
        "user_sessions", ("token_jti",), True, None,
    ),
    "ix_boost_logs_user_window": (
        "boost_logs", ("user_id", "stopped_at", "started_at"), False, None,
    ),
}

UTC_DATETIME_COLUMNS = frozenset({
    ("users", "plan_expires"),
    ("users", "plan_activated_at"),
    ("users", "created_at"),
    ("users", "last_login"),
    ("users", "tokens_valid_after"),
    ("users", "verification_sent_at"),
    ("users", "reset_token_expires"),
    ("users", "email_change_expires"),
    ("steam_accounts", "target_stop_time"),
    ("steam_accounts", "created_at"),
    ("payments", "owner_detached_at"),
    ("payments", "webhook_received_at"),
    ("payments", "next_verification_at"),
    ("payments", "verification_lock_until"),
    ("payments", "verified_at"),
    ("payments", "created_at"),
    ("payment_audit_logs", "created_at"),
    ("boost_logs", "started_at"),
    ("boost_logs", "stopped_at"),
    ("boost_logs", "remote_stopped_at"),
    ("announcements", "created_at"),
    ("user_sessions", "expires_at"),
    ("user_sessions", "created_at"),
    ("user_sessions", "last_seen"),
    ("revoked_tokens", "revoked_at"),
    ("revoked_tokens", "expires_at"),
})

BOOLEAN_COLUMNS = frozenset({
    ("users", "is_admin"),
    ("users", "is_verified"),
    ("steam_accounts", "is_boosting"),
    ("payments", "admin_hidden"),
    ("announcements", "is_active"),
    ("user_sessions", "is_active"),
})

FLOAT64_COLUMNS = frozenset({("payments", "amount")})

BIGINT_COLUMNS = frozenset({
    ("users", "id"),
    ("steam_accounts", "user_id"),
    ("boost_games", "id"),
    ("boost_games", "app_id"),
    ("payments", "id"),
    ("payments", "user_id"),
    ("payments", "owner_user_id_snapshot"),
    ("payments", "shopier_timestamp"),
    ("payments", "verified_amount_minor"),
    ("payment_audit_logs", "id"),
    ("payment_audit_logs", "payment_id"),
    ("payment_audit_logs", "actor_user_id"),
    ("boost_logs", "id"),
    ("boost_logs", "user_id"),
    ("boost_logs", "owner_user_id_snapshot"),
    ("boost_logs", "duration_seconds"),
    ("boost_logs", "duration_microseconds"),
    ("announcements", "id"),
    ("user_sessions", "id"),
    ("user_sessions", "user_id"),
    ("revoked_tokens", "id"),
    ("revoked_tokens", "user_id"),
})

INTEGER_COLUMNS = frozenset({
    ("steam_accounts", "persona_state"),
    ("payments", "verification_attempts"),
    ("payments", "verification_last_http_status"),
    ("boost_logs", "games_count"),
})

# None means PostgreSQL TEXT.  Integer limits are character counts, matching
# PostgreSQL VARCHAR rather than UTF-8 byte length.
TEXT_LIMITS = {
    ("announcements", "title"): 200,
    ("announcements", "content"): None,
    ("announcements", "type"): 20,
    ("users", "username"): 80,
    ("users", "email"): 120,
    ("users", "password_hash"): 256,
    ("users", "plan"): 20,
    ("users", "lang"): 5,
    ("users", "steam_id"): 20,
    ("users", "steam_avatar"): 256,
    ("users", "steam_display_name"): 100,
    ("users", "verification_token"): 64,
    ("users", "reset_token"): 64,
    ("users", "email_change_token"): 64,
    ("users", "email_change_new"): 120,
    ("payment_audit_logs", "actor_username"): 80,
    ("payment_audit_logs", "action"): 50,
    ("payment_audit_logs", "from_status"): 32,
    ("payment_audit_logs", "to_status"): 32,
    ("payment_audit_logs", "reason"): 255,
    ("payments", "owner_username_snapshot"): 80,
    ("payments", "plan"): 20,
    ("payments", "status"): 32,
    ("payments", "transaction_id"): 100,
    ("payments", "match_token"): 64,
    ("payments", "shopier_webhook_id"): 100,
    ("payments", "shopier_event"): 50,
    ("payments", "shopier_account_id"): 100,
    ("payments", "webhook_body_sha256"): 64,
    ("payments", "verification_error"): 255,
    ("revoked_tokens", "token_jti"): 128,
    ("steam_accounts", "id"): 32,
    ("steam_accounts", "steam_username"): 100,
    ("steam_accounts", "steam_id"): 20,
    ("user_sessions", "token_jti"): 64,
    ("user_sessions", "token_hint"): 32,
    ("user_sessions", "ip_address"): 64,
    ("user_sessions", "user_agent"): 256,
    ("boost_games", "account_id"): 32,
    ("boost_logs", "account_id"): 32,
    ("boost_logs", "account_id_snapshot"): 32,
    ("boost_logs", "steam_username_snapshot"): 100,
    ("boost_logs", "owner_username_snapshot"): 80,
    ("boost_logs", "app_ids_json"): None,
}

REQUIRED_COLUMNS = frozenset({
    ("announcements", "id"),
    ("announcements", "title"),
    ("announcements", "content"),
    ("users", "id"),
    ("users", "username"),
    ("users", "email"),
    ("users", "password_hash"),
    ("payment_audit_logs", "id"),
    ("payment_audit_logs", "payment_id"),
    ("payment_audit_logs", "actor_username"),
    ("payment_audit_logs", "action"),
    ("payment_audit_logs", "reason"),
    ("payment_audit_logs", "created_at"),
    ("payments", "id"),
    ("payments", "admin_hidden"),
    ("payments", "verification_attempts"),
    ("revoked_tokens", "id"),
    ("revoked_tokens", "token_jti"),
    ("revoked_tokens", "user_id"),
    ("revoked_tokens", "revoked_at"),
    ("revoked_tokens", "expires_at"),
    ("steam_accounts", "id"),
    ("steam_accounts", "user_id"),
    ("steam_accounts", "steam_username"),
    ("user_sessions", "id"),
    ("user_sessions", "user_id"),
    ("boost_games", "id"),
    ("boost_games", "app_id"),
    ("boost_logs", "id"),
    ("boost_logs", "started_at"),
    # The physical column stays nullable for source rollback compatibility,
    # but the named ledger CHECK makes NULL invalid on both databases.
    ("boost_logs", "duration_seconds"),
})

# ``duration_seconds`` remains physically nullable for source rollback
# compatibility, while the named ledger CHECK makes NULL rows invalid.
PHYSICAL_NOT_NULL_COLUMNS = REQUIRED_COLUMNS - {
    ("boost_logs", "duration_seconds"),
}

PARTIAL_INDEX_PREDICATES = {
    "ux_payments_match_token": "match_token IS NOT NULL",
    "ux_payments_transaction_id": "transaction_id IS NOT NULL",
    "ux_payments_one_open_checkout": (
        "user_id IS NOT NULL "
        "AND status IN ('checkout_started', 'verification_pending')"
    ),
}

DURATION_LEDGER_CHECK = (
    "duration_seconds IS NOT NULL "
    "AND duration_seconds >= 0 "
    "AND duration_seconds <= 9223372036854 "
    "AND (duration_microseconds IS NULL OR ("
    "(duration_seconds = 0 AND duration_microseconds = 0) OR "
    "(duration_seconds > 0 "
    "AND duration_microseconds > (duration_seconds - 1) * 1000000 "
    "AND duration_microseconds <= duration_seconds * 1000000)))"
)

CHECK_CONSTRAINTS = {
    ("boost_logs", "ck_boost_logs_duration_ledger"): DURATION_LEDGER_CHECK,
}

# Observed pg_get_expr() output on the real PostgreSQL 17.11 rehearsal.
# These are exact reviewed forms, not a general-purpose SQL equivalence parser.
# Preserve grouping, casts and case-sensitive literals; unknown forms fail closed.
POSTGRESQL17_EXPRESSION_FORMS = {
    DURATION_LEDGER_CHECK: (
        "((duration_seconds IS NOT NULL) AND (duration_seconds >= 0) "
        "AND (duration_seconds <= '9223372036854'::bigint) "
        "AND ((duration_microseconds IS NULL) OR (((duration_seconds = 0) "
        "AND (duration_microseconds = 0)) OR ((duration_seconds > 0) "
        "AND (duration_microseconds > ((duration_seconds - 1) * 1000000)) "
        "AND (duration_microseconds <= (duration_seconds * 1000000))))))",
        "duration_seconds IS NOT NULL AND duration_seconds >= 0 "
        "AND duration_seconds <= '9223372036854'::bigint "
        "AND (duration_microseconds IS NULL OR duration_seconds = 0 "
        "AND duration_microseconds = 0 OR duration_seconds > 0 "
        "AND duration_microseconds > ((duration_seconds - 1) * 1000000) "
        "AND duration_microseconds <= (duration_seconds * 1000000))",
    ),
    "match_token IS NOT NULL": ("(match_token IS NOT NULL)",),
    "transaction_id IS NOT NULL": ("(transaction_id IS NOT NULL)",),
    PARTIAL_INDEX_PREDICATES["ux_payments_one_open_checkout"]: (
        "((user_id IS NOT NULL) AND ((status)::text = ANY "
        "((ARRAY['checkout_started'::character varying, "
        "'verification_pending'::character varying])::text[])))",
    ),
}

SERVER_DEFAULTS = {
    ("users", "lang"): "tr",
    ("users", "is_verified"): False,
    ("payments", "admin_hidden"): False,
    ("payments", "verification_attempts"): 0,
    ("steam_accounts", "is_boosting"): False,
}

_SQLITE_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2}) "
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?"
)
_UTC = timezone.utc
_UTC_EPOCH = datetime(1970, 1, 1, tzinfo=_UTC)
_ALL_COLUMNS = frozenset(
    (table, column)
    for table, columns in TABLE_COLUMNS.items()
    for column in columns
)
_CATEGORIZED_COLUMNS = (
    UTC_DATETIME_COLUMNS
    | BOOLEAN_COLUMNS
    | FLOAT64_COLUMNS
    | BIGINT_COLUMNS
    | INTEGER_COLUMNS
    | frozenset(TEXT_LIMITS)
)

if tuple(TABLE_COLUMNS) != TRANSFER_TABLES:
    raise RuntimeError("PostgreSQL transfer table order is inconsistent.")
if len(_ALL_COLUMNS) != 103 or _ALL_COLUMNS != _CATEGORIZED_COLUMNS:
    raise RuntimeError("PostgreSQL column contract is incomplete or overlapping.")
if {
    name: contract[3]
    for name, contract in INDEX_CONTRACT.items()
    if contract[3] is not None
} != PARTIAL_INDEX_PREDICATES:
    raise RuntimeError("PostgreSQL partial-index contract is inconsistent.")


class PostgreSQLContractError(ValueError):
    """Constant failure for a value outside the reviewed transfer contract."""


def normalize_utc_timestamp(value) -> datetime:
    """Normalize a SQLite/driver timestamp to an aware UTC datetime."""

    if isinstance(value, str):
        match = _SQLITE_TIMESTAMP.fullmatch(value)
        if match is None:
            raise PostgreSQLContractError("Timestamp value is not canonical UTC.")
        fields = [int(part) if part is not None else 0 for part in match.groups()]
        fields[-1] = int((match.group(7) or "").ljust(6, "0") or "0")
        try:
            value = datetime(*fields[:6], microsecond=fields[6], tzinfo=_UTC)
        except ValueError:
            raise PostgreSQLContractError(
                "Timestamp value is not canonical UTC."
            ) from None
    elif isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=_UTC)
        else:
            value = value.astimezone(_UTC)
    else:
        raise PostgreSQLContractError("Timestamp value is not canonical UTC.")
    return value


def _timestamp_microseconds(value) -> int:
    value = normalize_utc_timestamp(value)
    delta = value - _UTC_EPOCH
    return (
        (delta.days * 86_400 + delta.seconds) * MICROSECONDS_PER_SECOND
        + delta.microseconds
    )


def canonical_value(table: str, column: str, value) -> bytes:
    """Return one driver-independent, type-tagged logical value."""

    key = (table, column)
    if key not in _ALL_COLUMNS:
        raise PostgreSQLContractError("Unknown PostgreSQL contract column.")
    if value is None:
        if key in REQUIRED_COLUMNS:
            raise PostgreSQLContractError("Required transfer value is missing.")
        return b"N"
    if key in BOOLEAN_COLUMNS:
        if isinstance(value, bool):
            normalized = value
        elif type(value) is int and value in (0, 1):
            normalized = bool(value)
        else:
            raise PostgreSQLContractError("Boolean transfer value is invalid.")
        return b"B1" if normalized else b"B0"
    if key in UTC_DATETIME_COLUMNS:
        return b"T" + str(_timestamp_microseconds(value)).encode("ascii")
    if key in BIGINT_COLUMNS or key in INTEGER_COLUMNS:
        if type(value) is not int:
            raise PostgreSQLContractError("Integer transfer value is invalid.")
        minimum, maximum = (
            (INT64_MIN, INT64_MAX) if key in BIGINT_COLUMNS
            else (INT32_MIN, INT32_MAX)
        )
        if not minimum <= value <= maximum:
            raise PostgreSQLContractError("Integer transfer value is out of range.")
        return b"I" + str(value).encode("ascii")
    if key in FLOAT64_COLUMNS:
        if isinstance(value, bool):
            raise PostgreSQLContractError("Floating transfer value is invalid.")
        try:
            normalized = float(value)
        except (TypeError, ValueError, OverflowError):
            raise PostgreSQLContractError(
                "Floating transfer value is invalid."
            ) from None
        if not math.isfinite(normalized) or normalized < 0:
            raise PostgreSQLContractError("Floating transfer value is invalid.")
        return b"F" + struct.pack(">d", normalized)
    if key in TEXT_LIMITS:
        if not isinstance(value, str) or "\x00" in value:
            raise PostgreSQLContractError("Text transfer value is invalid.")
        limit = TEXT_LIMITS[key]
        if limit is not None and len(value) > limit:
            raise PostgreSQLContractError("Text transfer value exceeds its limit.")
        try:
            encoded = value.encode("utf-8")
        except UnicodeError:
            raise PostgreSQLContractError("Text transfer value is invalid.") from None
        return b"S" + encoded
    raise PostgreSQLContractError("PostgreSQL column contract is incomplete.")


def normalize_row_for_postgresql(
    table: str,
    row: Mapping[str, object],
) -> dict[str, object]:
    """Return a driver-ready row after enforcing the logical contract."""

    validate_row(table, row)
    normalized = {}
    for column in TABLE_COLUMNS[table]:
        key = (table, column)
        value = row[column]
        if value is None:
            normalized[column] = None
        elif key in BOOLEAN_COLUMNS:
            normalized[column] = bool(value)
        elif key in UTC_DATETIME_COLUMNS:
            normalized[column] = normalize_utc_timestamp(value)
        elif key in FLOAT64_COLUMNS:
            normalized[column] = float(value)
        else:
            normalized[column] = value
    return normalized


def identity_restart_value(table: str, maximum_id) -> int:
    """Return the next safe identity value after an explicit-ID copy."""

    if table not in IDENTITY_TABLES:
        raise PostgreSQLContractError("Table has no PostgreSQL identity contract.")
    if maximum_id is None:
        return 1
    if type(maximum_id) is not int or not INT64_MIN <= maximum_id <= INT64_MAX:
        raise PostgreSQLContractError("Identity maximum is invalid.")
    if maximum_id >= INT64_MAX:
        raise PostgreSQLContractError("Identity range is exhausted.")
    return max(1, maximum_id + 1)


def boost_ledger_totals(rows: Iterable[Mapping[str, object]]) -> dict[str, int]:
    """Return backend-neutral duration totals for already ordered rows."""

    seconds = 0
    microseconds = 0
    row_count = 0
    for row in rows:
        validate_row("boost_logs", row)
        seconds += row["duration_seconds"]
        if row["duration_microseconds"] is not None:
            microseconds += row["duration_microseconds"]
        row_count += 1
    return {
        "rows": row_count,
        "duration_seconds": seconds,
        "duration_microseconds": microseconds,
    }


def payment_minor_total(rows: Iterable[Mapping[str, object]]) -> dict[str, int]:
    """Return the canonical verified-minor-unit total, never display floats."""

    amount_minor = 0
    row_count = 0
    for row in rows:
        validate_row("payments", row)
        if row["verified_amount_minor"] is not None:
            amount_minor += row["verified_amount_minor"]
        row_count += 1
    return {"rows": row_count, "verified_amount_minor": amount_minor}


def validate_row(table: str, row: Mapping[str, object]) -> None:
    """Validate one complete row, including cross-column ledger invariants."""

    columns = TABLE_COLUMNS.get(table)
    if columns is None or set(row) != set(columns):
        raise PostgreSQLContractError("Transfer row shape is invalid.")
    for column in columns:
        canonical_value(table, column, row[column])

    if table == "boost_logs":
        seconds = row["duration_seconds"]
        microseconds = row["duration_microseconds"]
        if (
            type(seconds) is not int
            or seconds < 0
            or seconds > MAX_LEDGER_SECONDS
        ):
            raise PostgreSQLContractError("Boost duration ledger is invalid.")
        if microseconds is not None and not (
            type(microseconds) is int
            and 0 <= microseconds <= MAX_LEDGER_MICROSECONDS
            and (
                (seconds == 0 and microseconds == 0)
                or (
                    seconds > 0
                    and (seconds - 1) * MICROSECONDS_PER_SECOND < microseconds
                    <= seconds * MICROSECONDS_PER_SECOND
                )
            )
        ):
            raise PostgreSQLContractError("Boost duration ledger is invalid.")

    if table == "payments":
        for column in (
            "shopier_timestamp", "verification_attempts", "verified_amount_minor",
        ):
            value = row[column]
            if value is not None and value < 0:
                raise PostgreSQLContractError("Financial integer value is invalid.")


def canonical_row_bytes(table: str, row: Mapping[str, object]) -> bytes:
    """Encode one complete row without backend-specific repr or text casts."""

    validate_row(table, row)
    encoded = bytearray()
    for column in TABLE_COLUMNS[table]:
        name = column.encode("ascii")
        value = canonical_value(table, column, row[column])
        encoded.extend(len(name).to_bytes(2, "big"))
        encoded.extend(name)
        encoded.extend(len(value).to_bytes(8, "big"))
        encoded.extend(value)
    return bytes(encoded)


def digest_ordered_rows(
    table: str,
    rows: Iterable[Mapping[str, object]],
) -> dict[str, int | str]:
    """Hash rows already ordered by the table's primary key."""

    if table not in TABLE_COLUMNS:
        raise PostgreSQLContractError("Unknown PostgreSQL contract table.")
    digest = hashlib.sha256()
    count = 0
    previous_primary_key = None
    for row in rows:
        encoded = canonical_row_bytes(table, row)
        primary_key = row.get(PRIMARY_KEYS[table])
        if count and primary_key <= previous_primary_key:
            raise PostgreSQLContractError(
                "Transfer rows are not in strict primary-key order."
            )
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        previous_primary_key = primary_key
        count += 1
    return {"rows": count, "sha256": digest.hexdigest()}
