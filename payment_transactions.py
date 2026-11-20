"""Database-only primitives for the durable payment verification queue.

The helpers in this module deliberately do not import Flask, the application,
or concrete models.  This keeps PostgreSQL SQL generation and transaction
error classification testable without starting application background work.
"""

from __future__ import annotations

from sqlalchemy import or_, select, update


POSTGRESQL_RETRYABLE_TRANSACTION_SQLSTATES = frozenset({"40001", "40P01"})


def build_postgresql_due_payment_claim_select(payment_model, now):
    """Return the PostgreSQL row-locking query for one due payment job."""

    return (
        select(payment_model)
        .where(
            payment_model.status == "verification_pending",
            payment_model.transaction_id.is_not(None),
            or_(
                payment_model.next_verification_at.is_(None),
                payment_model.next_verification_at <= now,
            ),
            or_(
                payment_model.verification_lock_until.is_(None),
                payment_model.verification_lock_until <= now,
            ),
        )
        # PostgreSQL sorts NULL last for ASC by default, while the historical
        # SQLite queue sorts it first.  Make the queue contract explicit.
        .order_by(
            payment_model.next_verification_at.asc().nulls_first(),
            payment_model.id.asc(),
        )
        .limit(1)
        .with_for_update(skip_locked=True)
    )


def build_payment_claim_transition(
    payment_model,
    *,
    payment_id,
    attempt,
    values,
):
    """Build an attempt-fenced transition for a leased payment row."""

    return (
        update(payment_model)
        .where(
            payment_model.id == payment_id,
            payment_model.status == "verification_pending",
            payment_model.verification_attempts == attempt,
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )


def postgresql_transaction_sqlstate(error):
    """Return a retryable PostgreSQL transaction SQLSTATE, otherwise ``None``.

    Psycopg 3 exposes ``sqlstate`` on the wrapped driver exception. ``pgcode``
    is accepted as a compatibility fallback without importing a DB driver.
    Connection errors and uniqueness violations are intentionally excluded:
    their commit outcome or business meaning requires separate handling.
    """

    candidates = (error, getattr(error, "orig", None))
    for candidate in candidates:
        if candidate is None:
            continue
        sqlstate = (
            getattr(candidate, "sqlstate", None)
            or getattr(candidate, "pgcode", None)
        )
        if sqlstate in POSTGRESQL_RETRYABLE_TRANSACTION_SQLSTATES:
            return sqlstate
    return None


def run_postgresql_transaction_with_retry(
    operation,
    *,
    dialect_name,
    rollback,
    sleep,
    delay,
    max_attempts=3,
):
    """Run one DB-only operation with bounded PostgreSQL transaction retry.

    ``operation`` must not perform network calls, IPC, sleeps, or any other
    side effect that cannot be rolled back with the database transaction. The
    failed session is rolled back before either sleeping or re-raising.
    """

    if not callable(operation) or not callable(rollback):
        raise TypeError("Transaction retry requires callable operations.")
    if not callable(sleep) or not callable(delay):
        raise TypeError("Transaction retry requires callable timing hooks.")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
        raise ValueError("Transaction retry attempts are out of range.")

    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except Exception as error:
            rollback()
            sqlstate = (
                postgresql_transaction_sqlstate(error)
                if dialect_name == "postgresql"
                else None
            )
            if sqlstate is None or attempt >= max_attempts:
                raise
            wait_seconds = float(delay(attempt))
            if not 0 <= wait_seconds <= 1:
                raise ValueError("Transaction retry delay is out of range.") from None
            sleep(wait_seconds)

    raise RuntimeError("Transaction retry loop ended unexpectedly.")
