from datetime import datetime, timezone
from types import SimpleNamespace
import unittest

from sqlalchemy import Column, DateTime, Integer, String, create_engine, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import declarative_base

from payment_transactions import (
    build_payment_claim_transition,
    build_postgresql_due_payment_claim_select,
    postgresql_transaction_sqlstate,
    run_postgresql_transaction_with_retry,
)


Base = declarative_base()


class PaymentFixture(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True)
    status = Column(String(32))
    transaction_id = Column(String(100))
    verification_attempts = Column(Integer)
    next_verification_at = Column(DateTime(timezone=True))
    verification_lock_until = Column(DateTime(timezone=True))
    verification_error = Column(String(255))


class PaymentTransactionTests(unittest.TestCase):
    def test_postgresql_claim_select_skips_locked_rows_with_stable_null_order(self):
        statement = build_postgresql_due_payment_claim_select(
            PaymentFixture,
            datetime(2026, 9, 13, tzinfo=timezone.utc),
        )
        compiled = statement.compile(dialect=postgresql.dialect())
        sql = str(compiled)

        self.assertIn("ORDER BY payments.next_verification_at ASC NULLS FIRST", sql)
        self.assertIn("payments.id ASC", sql)
        self.assertIn("FOR UPDATE SKIP LOCKED", sql)
        self.assertIn("payments.transaction_id IS NOT NULL", sql)

    def test_claim_select_lock_clause_is_not_emitted_by_sqlite(self):
        statement = build_postgresql_due_payment_claim_select(
            PaymentFixture,
            datetime(2026, 9, 13, tzinfo=timezone.utc),
        )
        sql = str(statement.compile(dialect=sqlite.dialect()))

        self.assertNotIn("FOR UPDATE", sql)
        self.assertNotIn("SKIP LOCKED", sql)

    def test_claim_transition_is_fenced_by_status_and_attempt(self):
        statement = build_payment_claim_transition(
            PaymentFixture,
            payment_id=17,
            attempt=4,
            values={
                "verification_error": "temporary_failure",
                "verification_lock_until": None,
            },
        )
        compiled = statement.compile(dialect=postgresql.dialect())
        sql = str(compiled)

        self.assertIn("payments.id =", sql)
        self.assertIn("payments.status =", sql)
        self.assertIn("payments.verification_attempts =", sql)
        self.assertEqual(
            compiled.params["verification_error"],
            "temporary_failure",
        )

    def test_sqlite_claim_transition_rejects_a_stale_attempt(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(PaymentFixture.__table__.insert().values(
                id=17,
                status="verification_pending",
                transaction_id="order-newer-lease",
                verification_attempts=2,
                verification_error="newer_attempt_active",
                verification_lock_until=datetime(
                    2026, 9, 13, 12, 1, tzinfo=timezone.utc
                ),
            ))

            result = connection.execute(build_payment_claim_transition(
                PaymentFixture,
                payment_id=17,
                attempt=1,
                values={
                    "status": "verification_failed",
                    "verification_error": "stale_worker",
                    "verification_lock_until": None,
                },
            ))

            self.assertEqual(result.rowcount, 0)
            row = connection.execute(
                select(PaymentFixture.__table__).where(PaymentFixture.id == 17)
            ).mappings().one()
            self.assertEqual(row["status"], "verification_pending")
            self.assertEqual(row["verification_attempts"], 2)
            self.assertEqual(row["verification_error"], "newer_attempt_active")
            self.assertIsNotNone(row["verification_lock_until"])

    def test_only_deadlock_and_serialization_sqlstates_are_retryable(self):
        for sqlstate in ("40001", "40P01"):
            with self.subTest(sqlstate=sqlstate):
                error = SimpleNamespace(orig=SimpleNamespace(sqlstate=sqlstate))
                self.assertEqual(postgresql_transaction_sqlstate(error), sqlstate)

        legacy_driver_error = SimpleNamespace(
            orig=SimpleNamespace(pgcode="40P01")
        )
        self.assertEqual(
            postgresql_transaction_sqlstate(legacy_driver_error),
            "40P01",
        )

        for sqlstate in ("23505", "08006", "55P03", None):
            with self.subTest(sqlstate=sqlstate):
                error = SimpleNamespace(orig=SimpleNamespace(sqlstate=sqlstate))
                self.assertIsNone(postgresql_transaction_sqlstate(error))

    def test_retry_is_bounded_rolls_back_first_and_never_replays_unknown_errors(self):
        events = []
        outcomes = iter(("40P01", "40001", None))

        def operation():
            sqlstate = next(outcomes)
            events.append(("operation", sqlstate))
            if sqlstate:
                error = RuntimeError("redacted")
                error.sqlstate = sqlstate
                raise error
            return "committed"

        result = run_postgresql_transaction_with_retry(
            operation,
            dialect_name="postgresql",
            rollback=lambda: events.append(("rollback", None)),
            sleep=lambda value: events.append(("sleep", value)),
            delay=lambda attempt: attempt / 100,
        )
        self.assertEqual(result, "committed")
        self.assertEqual(events, [
            ("operation", "40P01"),
            ("rollback", None),
            ("sleep", 0.01),
            ("operation", "40001"),
            ("rollback", None),
            ("sleep", 0.02),
            ("operation", None),
        ])

        for dialect_name, sqlstate in (
            ("sqlite", "40P01"),
            ("postgresql", "23505"),
        ):
            with self.subTest(dialect=dialect_name, sqlstate=sqlstate):
                calls = []

                def rejected_operation():
                    calls.append("operation")
                    error = RuntimeError("redacted")
                    error.sqlstate = sqlstate
                    raise error

                with self.assertRaises(RuntimeError):
                    run_postgresql_transaction_with_retry(
                        rejected_operation,
                        dialect_name=dialect_name,
                        rollback=lambda: calls.append("rollback"),
                        sleep=lambda _value: calls.append("sleep"),
                        delay=lambda _attempt: 0,
                    )
                self.assertEqual(calls, ["operation", "rollback"])

    def test_retry_validates_bounds_without_running_operation(self):
        called = []
        with self.assertRaises(ValueError):
            run_postgresql_transaction_with_retry(
                lambda: called.append(True),
                dialect_name="postgresql",
                rollback=lambda: None,
                sleep=lambda _value: None,
                delay=lambda _attempt: 0,
                max_attempts=0,
            )
        self.assertEqual(called, [])

    def test_retry_exhaustion_is_bounded_and_rolls_back_every_failure(self):
        events = []

        def deadlocked_operation():
            events.append("operation")
            error = RuntimeError("redacted")
            error.sqlstate = "40P01"
            raise error

        with self.assertRaises(RuntimeError):
            run_postgresql_transaction_with_retry(
                deadlocked_operation,
                dialect_name="postgresql",
                rollback=lambda: events.append("rollback"),
                sleep=lambda _value: events.append("sleep"),
                delay=lambda _attempt: 0,
                max_attempts=3,
            )

        self.assertEqual(events, [
            "operation", "rollback", "sleep",
            "operation", "rollback", "sleep",
            "operation", "rollback",
        ])


if __name__ == "__main__":
    unittest.main()
