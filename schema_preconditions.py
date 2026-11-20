"""Read-only prerequisites for retiring HourBoost's legacy startup migrations.

The caller must first verify the frozen SQLite schema and hold one explicit
transaction throughout this audit. This module never imports the application,
configuration, current models, or a legacy mutating migration helper. It never
repairs data: an incomplete legacy migration requires a separate reviewed job.
Reports contain only fixed schema/check names and counts, never row values.
"""

from __future__ import annotations

from datetime import datetime
import math
import re

from sqlalchemy import text


# Frozen physical timestamp inventory. Model parity is checked by tests, not
# by importing evolving ORM definitions into the migration acceptance path.
UTC_DATETIME_COLUMNS = {
    "users": (
        "plan_expires", "plan_activated_at", "created_at", "last_login",
        "tokens_valid_after", "verification_sent_at", "reset_token_expires",
        "email_change_expires",
    ),
    "steam_accounts": ("target_stop_time", "created_at"),
    "payments": (
        "owner_detached_at", "webhook_received_at", "next_verification_at",
        "verification_lock_until", "verified_at", "created_at",
    ),
    "payment_audit_logs": ("created_at",),
    "boost_logs": ("started_at", "stopped_at", "remote_stopped_at"),
    "announcements": ("created_at",),
    "user_sessions": ("expires_at", "created_at", "last_seen"),
    "revoked_tokens": ("revoked_at", "expires_at"),
}
_REQUIRED_TIMESTAMPS = {
    ("payment_audit_logs", "created_at"), ("boost_logs", "started_at"),
    ("revoked_tokens", "revoked_at"), ("revoked_tokens", "expires_at"),
}
_SQLITE_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?"
)
# Match the removed valid_steam_id helper exactly, including its strip and
# Unicode-decimal semantics. Broadening/tightening identity policy is separate.
_STEAM_ID = re.compile(r"\d{17}")
_ACTIVE_HB = re.compile(r"HB-[0-9A-F]{32}")
_ACTIVE_PAYMENT_STATES = {"checkout_started", "pending", "verification_pending"}

# name -> allowed SQLite storage class; '?' permits NULL. VARCHAR affinity
# alone cannot reject BLOB data, nor can INTEGER affinity reject arbitrary text.
_STORAGE = {
    "users": {
        "id": "integer", "username": "text", "email": "text",
        "password_hash": "text", "plan": "text?", "is_admin": "boolean?",
        "lang": "text?", "steam_id": "text?", "steam_avatar": "text?",
        "steam_display_name": "text?", "is_verified": "boolean?",
        "verification_token": "text?", "reset_token": "text?",
        "email_change_token": "text?", "email_change_new": "text?",
    },
    "steam_accounts": {
        "id": "text", "user_id": "integer", "steam_username": "text",
        "steam_id": "text?", "persona_state": "integer?",
        "is_boosting": "boolean?",
    },
    "boost_games": {"id": "integer", "account_id": "text?", "app_id": "integer"},
    "payments": {
        "id": "integer", "user_id": "integer?", "owner_user_id_snapshot": "integer?",
        "owner_username_snapshot": "text?", "amount": "number?", "plan": "text?",
        "status": "text?", "transaction_id": "text?", "match_token": "text?",
        "admin_hidden": "boolean", "shopier_webhook_id": "text?",
        "shopier_event": "text?", "shopier_account_id": "text?",
        "shopier_timestamp": "integer?", "webhook_body_sha256": "text?",
        "verification_attempts": "integer", "verification_error": "text?",
        "verification_last_http_status": "integer?", "verified_amount_minor": "integer?",
    },
    "payment_audit_logs": {
        "id": "integer", "payment_id": "integer", "actor_user_id": "integer?",
        "actor_username": "text", "action": "text", "from_status": "text?",
        "to_status": "text?", "reason": "text",
    },
    "boost_logs": {
        "id": "integer", "account_id": "text?", "user_id": "integer?",
        "account_id_snapshot": "text?", "steam_username_snapshot": "text?",
        "owner_user_id_snapshot": "integer?", "owner_username_snapshot": "text?",
        "duration_seconds": "integer", "duration_microseconds": "integer?",
        "games_count": "integer?", "app_ids_json": "text?",
    },
    "announcements": {
        "id": "integer", "title": "text", "content": "text",
        "type": "text?", "is_active": "boolean?",
    },
    "user_sessions": {
        "id": "integer", "user_id": "integer", "token_jti": "text?",
        "token_hint": "text?", "ip_address": "text?", "user_agent": "text?",
        "is_active": "boolean?",
    },
    "revoked_tokens": {"id": "integer", "token_jti": "text", "user_id": "integer"},
}


class LegacyDataCheckError(RuntimeError):
    """Safe constant failure: the audit itself could not be completed."""


def _count(connection, statement, parameters=None):
    return int(connection.execute(text(statement), parameters or {}).scalar_one())


def _storage_checks(connection, checks):
    for table, columns in _STORAGE.items():
        clauses = []
        for name, contract in columns.items():
            nullable = contract.endswith("?")
            kind = contract.rstrip("?")
            # Identifiers and types originate solely in the frozen allowlist.
            column = '"' + name + '"'
            if kind == "boolean":
                invalid = f"typeof({column}) <> 'integer' OR {column} NOT IN (0, 1)"
            elif kind == "number":
                invalid = f"typeof({column}) NOT IN ('integer', 'real')"
            else:
                invalid = f"typeof({column}) <> '{kind}'"
            if nullable:
                invalid = f"{column} IS NOT NULL AND ({invalid})"
            clauses.append("(" + invalid + ")")
        checks[table + ".invalid_storage"] = _count(
            connection, f'SELECT COUNT(*) FROM "{table}" WHERE ' + " OR ".join(clauses)
        )


def _timestamp_checks(connection, checks):
    for table, columns in UTC_DATETIME_COLUMNS.items():
        names = ", ".join('"' + name + '"' for name in columns)
        counts = [0] * len(columns)
        for row in connection.execute(text(f'SELECT {names} FROM "{table}"')):
            for index, value in enumerate(row):
                if value is None:
                    counts[index] += int((table, columns[index]) in _REQUIRED_TIMESTAMPS)
                    continue
                valid = isinstance(value, str) and _SQLITE_TIMESTAMP.fullmatch(value)
                if valid:
                    try:
                        # Python 3.14 accepts ISO end-of-day 24:00:00 and
                        # normalizes it to the next day. SQLite/ORM storage
                        # must remain canonical across supported runtimes;
                        # the constructor checks fields without normalization.
                        datetime(
                            int(value[0:4]), int(value[5:7]), int(value[8:10]),
                            int(value[11:13]), int(value[14:16]), int(value[17:19]),
                            int(value[20:].ljust(6, "0")) if len(value) > 19 else 0,
                        )
                    except ValueError:
                        valid = False
                counts[index] += int(not valid)
        for name, count in zip(columns, counts):
            checks[f"{table}.{name}.invalid_timestamp"] = count


def _payment_checks(connection, checks):
    checks["payments.missing_owner_snapshot"] = _count(connection,
        "SELECT COUNT(*) FROM payments WHERE user_id IS NOT NULL AND "
        "(owner_user_id_snapshot IS NULL OR owner_username_snapshot IS NULL)")
    checks["payments.owner_id_mismatch"] = _count(connection,
        "SELECT COUNT(*) FROM payments WHERE user_id IS NOT NULL AND "
        "owner_user_id_snapshot IS NOT NULL AND owner_user_id_snapshot <> user_id")
    checks["payments.pending_checkout_intent"] = _count(connection,
        "SELECT COUNT(*) FROM payments WHERE status = 'pending' "
        "AND match_token IS NOT NULL AND transaction_id IS NULL")
    checks["payments.duplicate_open_checkout_groups"] = _count(connection,
        "SELECT COUNT(*) FROM (SELECT user_id FROM payments "
        "WHERE user_id IS NOT NULL "
        "AND status IN ('checkout_started', 'verification_pending') "
        "GROUP BY user_id HAVING COUNT(*) > 1)")
    checks["payments.duplicate_transaction_groups"] = _count(connection,
        "SELECT COUNT(*) FROM (SELECT transaction_id FROM payments "
        "WHERE transaction_id IS NOT NULL "
        "GROUP BY transaction_id HAVING COUNT(*) > 1)")
    for name in ("noncanonical_hb", "duplicate_normalized_hb_groups", "invalid_active_hb"):
        checks["payments." + name] = 0
    normalized_counts = {}
    for token, status in connection.execute(text("SELECT match_token, status FROM payments")):
        normalized = str(token or "").strip().upper()
        if token is not None:
            if not normalized or not isinstance(token, str) or token != normalized:
                checks["payments.noncanonical_hb"] += 1
            if normalized:
                normalized_counts[normalized] = normalized_counts.get(normalized, 0) + 1
        # Unmatched webhook placeholders intentionally have no HB token until
        # API verification resolves the owner. The retired helper likewise
        # inspected only non-NULL tokens; NULL is not an invalid active code.
        if (token is not None and status in _ACTIVE_PAYMENT_STATES
                and not _ACTIVE_HB.fullmatch(normalized)):
            checks["payments.invalid_active_hb"] += 1
    checks["payments.duplicate_normalized_hb_groups"] = sum(
        count > 1 for count in normalized_counts.values()
    )
    checks["payments.invalid_amount"] = sum(
        1 for (amount,) in connection.execute(text("SELECT amount FROM payments WHERE amount IS NOT NULL"))
        if not isinstance(amount, (int, float)) or not math.isfinite(amount) or amount < 0
    )
    checks["payments.negative_financial_integer"] = _count(connection,
        "SELECT COUNT(*) FROM payments WHERE verification_attempts < 0 "
        "OR verified_amount_minor < 0 OR shopier_timestamp < 0")


def _boost_checks(connection, checks):
    checks["boost_logs.missing_account_snapshot"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs WHERE account_id IS NOT NULL "
        "AND account_id_snapshot IS NULL")
    checks["boost_logs.missing_steam_username_snapshot"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs AS log "
        "WHERE steam_username_snapshot IS NULL AND EXISTS ("
        "SELECT 1 FROM steam_accounts AS account WHERE account.id = log.account_id)")
    checks["boost_logs.missing_owner_id_snapshot"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs AS log WHERE owner_user_id_snapshot IS NULL "
        "AND (user_id IS NOT NULL OR EXISTS (SELECT 1 FROM steam_accounts AS account "
        "WHERE account.id = log.account_id))")
    checks["boost_logs.missing_owner_username_snapshot"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs AS log WHERE owner_username_snapshot IS NULL "
        "AND EXISTS (SELECT 1 FROM users WHERE users.id = COALESCE(log.user_id, "
        "(SELECT user_id FROM steam_accounts WHERE steam_accounts.id = log.account_id)))")
    checks["boost_logs.cross_owner_reference"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs AS log "
        "JOIN steam_accounts AS account ON account.id = log.account_id "
        "WHERE log.user_id IS NOT NULL AND account.user_id <> log.user_id")
    checks["boost_logs.owner_id_mismatch"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs AS log "
        "WHERE owner_user_id_snapshot IS NOT NULL AND owner_user_id_snapshot <> "
        "COALESCE(log.user_id, (SELECT user_id FROM steam_accounts "
        "WHERE steam_accounts.id = log.account_id))")
    checks["boost_logs.account_id_mismatch"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs WHERE account_id IS NOT NULL "
        "AND account_id_snapshot IS NOT NULL AND account_id_snapshot <> account_id")
    checks["boost_logs.legacy_seconds_only"] = _count(connection,
        "SELECT COUNT(*) FROM boost_logs WHERE duration_microseconds IS NULL")


def check_legacy_data(connection, *, paid_plan_names=("basic", "premium"), require_idle=False):
    """Return a safe count-only report for an already schema-verified SQLite DB.

    ``ok`` requires every count to be zero. Expired-but-still-active sessions
    with missing authentication facts also block: the old helper closed those
    rows without an expiry exemption. ``require_idle`` is for stopped-service
    adoption only; runtime startup must preserve boost reconciliation ownership.
    SQL/schema failures raise a constant error without driver text or row data.
    """
    try:
        if connection.dialect.name != "sqlite" or not connection.in_transaction():
            raise ValueError("unsupported audit connection")
        if not isinstance(require_idle, bool):
            raise ValueError("invalid idle policy")
        if isinstance(paid_plan_names, (str, bytes)):
            raise ValueError("invalid paid plan names")
        plans = tuple(paid_plan_names)
        if len(plans) > 100 or any(not isinstance(name, str) or not name for name in plans):
            raise ValueError("invalid paid plan names")
        checks = {}
        _storage_checks(connection, checks)
        _timestamp_checks(connection, checks)
        parameters = {"plan_" + str(index): name for index, name in enumerate(plans)}
        checks["users.paid_missing_activation"] = _count(connection,
            "SELECT COUNT(*) FROM users WHERE plan_activated_at IS NULL AND plan IN ("
            + ", ".join(":" + name for name in parameters) + ")", parameters
        ) if parameters else 0
        checks["steam_accounts.invalid_steam_id"] = sum(
            not bool(_STEAM_ID.fullmatch(str(value or "").strip()))
            for (value,) in connection.execute(text(
                "SELECT steam_id FROM steam_accounts WHERE steam_id IS NOT NULL"))
        )
        checks["user_sessions.active_missing_auth"] = _count(connection,
            "SELECT COUNT(*) FROM user_sessions WHERE is_active = 1 "
            "AND (token_jti IS NULL OR TRIM(token_jti) = '' OR expires_at IS NULL)")
        _payment_checks(connection, checks)
        _boost_checks(connection, checks)
        if require_idle:
            checks["steam_accounts.active_boost"] = _count(connection,
                "SELECT COUNT(*) FROM steam_accounts WHERE is_boosting = 1")
        return {"ok": not any(checks.values()), "scope": "legacy_data", "checks": checks}
    except Exception:
        raise LegacyDataCheckError(
            "Legacy data precondition audit could not be completed."
        ) from None
