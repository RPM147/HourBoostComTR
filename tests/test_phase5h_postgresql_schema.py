"""Offline contract tests for the isolated PostgreSQL migration lineage.

No test in this module opens a network connection or imports the Flask app.
Successful compilation is readiness evidence, never a real PostgreSQL pass.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateIndex, CreateTable

from models import db
from postgresql_contract import (
    BIGINT_COLUMNS,
    BOOLEAN_COLUMNS,
    CHECK_CONSTRAINTS,
    DURATION_LEDGER_CHECK,
    FOREIGN_KEYS,
    IDENTITY_TABLES,
    INDEX_CONTRACT,
    INTEGER_COLUMNS,
    PARTIAL_INDEX_PREDICATES,
    POSTGRESQL17_EXPRESSION_FORMS,
    PHYSICAL_NOT_NULL_COLUMNS,
    POSTGRESQL_BASELINE_REVISION,
    PostgreSQLContractError,
    REQUIRED_COLUMNS,
    SERVER_DEFAULTS,
    TABLE_COLUMNS,
    TEXT_LIMITS,
    TRANSFER_TABLES,
    UNIQUE_CONSTRAINTS,
    UTC_DATETIME_COLUMNS,
    boost_ledger_totals,
    canonical_value,
    digest_ordered_rows,
    identity_restart_value,
    normalize_row_for_postgresql,
    payment_minor_total,
    validate_row,
)
from postgresql_transfer import (
    PostgreSQLTransferError,
    _validate_postgresql_table_contract,
    _normalized_sql_expression,
    _normalized_server_default,
)


ROOT = Path(__file__).resolve().parents[1]
REVISION_PATH = (
    ROOT
    / "migrations_postgresql"
    / "versions"
    / "20260913_01_postgresql_baseline.py"
)
ALEMBIC_AVAILABLE = importlib.util.find_spec("alembic") is not None
SQLITE_REVISION_HASHES = {
    "20260907_01_baseline.py": (
        "e5288e4b5eafa406dbcf0bc3e312ff48fa5920789ddd057de6fed56d7937daef"
    ),
    "20260908_01_sqlite_adoption.py": (
        "56bc7d104367f20aa7e27c55bfb0da7d8a333c9c32099ea2e639bb366425ea5d"
    ),
}


def _load_revision():
    spec = importlib.util.spec_from_file_location(
        "hourboost_postgresql_baseline",
        REVISION_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("PostgreSQL baseline could not be loaded.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _OperationRecorder:
    def __init__(self):
        self.metadata = sa.MetaData()
        self.indexes = []
        self.executed = []

    def create_table(self, name, *items, **kwargs):
        return sa.Table(name, self.metadata, *items, **kwargs)

    def create_index(self, name, table_name, columns, *, unique=False, **kwargs):
        table = self.metadata.tables[table_name]
        index = sa.Index(
            name,
            *(table.c[column] for column in columns),
            unique=unique,
            **kwargs,
        )
        self.indexes.append(index)
        return index

    def execute(self, statement):
        self.executed.append(statement)


def _valid_row(table):
    row = {}
    for column in TABLE_COLUMNS[table]:
        key = (table, column)
        if key in UTC_DATETIME_COLUMNS:
            value = "2026-09-13 00:00:00.123456"
        elif key in BOOLEAN_COLUMNS:
            value = 0
        elif key in BIGINT_COLUMNS:
            value = 1
        elif key in TEXT_LIMITS:
            value = "x"
        else:
            value = 1
        row[column] = value

    # Optional values are allowed to be present and non-null in the generic
    # fixture. Cross-column financial/ledger constraints need exact values.
    if table == "payments":
        row["amount"] = 1.0
        row["shopier_timestamp"] = 1
        row["verification_attempts"] = 0
        row["verified_amount_minor"] = 100
    if table == "boost_logs":
        row["duration_seconds"] = 2
        row["duration_microseconds"] = 1_500_001
    return row


class PostgreSQLLogicalContractTests(unittest.TestCase):
    def test_contract_has_exact_table_column_and_fk_scale(self):
        self.assertEqual(tuple(TABLE_COLUMNS), TRANSFER_TABLES)
        self.assertEqual(len(TABLE_COLUMNS), 9)
        self.assertEqual(sum(map(len, TABLE_COLUMNS.values())), 103)
        self.assertEqual(len(UTC_DATETIME_COLUMNS), 26)
        self.assertEqual(len(IDENTITY_TABLES), 8)

    def test_timestamps_normalize_to_the_same_epoch_microsecond(self):
        naive = "2026-09-13 12:34:56.123456"
        aware = datetime(
            2026, 9, 13, 15, 34, 56, 123456,
            tzinfo=timezone(timedelta(hours=3)),
        )
        self.assertEqual(
            canonical_value("users", "created_at", naive),
            canonical_value("users", "created_at", aware),
        )

    def test_boolean_float_text_and_integer_encoding_is_strict(self):
        self.assertEqual(
            canonical_value("users", "is_admin", 1),
            canonical_value("users", "is_admin", True),
        )
        self.assertEqual(
            canonical_value("payments", "amount", 29.99),
            canonical_value("payments", "amount", float("29.99")),
        )
        invalid = (
            ("users", "is_admin", 2),
            ("payments", "amount", float("nan")),
            ("users", "username", "x\x00y"),
            ("users", "username", "x" * 81),
            ("payments", "id", 1 << 63),
        )
        for table, column, value in invalid:
            with self.subTest(table=table, column=column):
                with self.assertRaises(PostgreSQLContractError):
                    canonical_value(table, column, value)

    def test_ledger_contract_rejects_inconsistent_pairs(self):
        valid = _valid_row("boost_logs")
        validate_row("boost_logs", valid)
        for seconds, microseconds in ((0, 1), (2, 1_000_000), (-1, 0)):
            with self.subTest(seconds=seconds, microseconds=microseconds):
                invalid = dict(valid)
                invalid["duration_seconds"] = seconds
                invalid["duration_microseconds"] = microseconds
                with self.assertRaises(PostgreSQLContractError):
                    validate_row("boost_logs", invalid)

    def test_digest_is_order_and_driver_representation_stable(self):
        first = _valid_row("users")
        second = dict(first)
        second["id"] = 2
        naive = digest_ordered_rows("users", (first, second))
        first["created_at"] = datetime(
            2026, 9, 13, 3, 0, 0, 123456,
            tzinfo=timezone(timedelta(hours=3)),
        )
        second["created_at"] = first["created_at"]
        aware = digest_ordered_rows("users", (first, second))
        self.assertEqual(naive, aware)
        self.assertEqual(naive["rows"], 2)
        self.assertRegex(naive["sha256"], r"^[0-9a-f]{64}$")

        for disordered in ((second, first), (first, first)):
            with self.subTest(ids=[row["id"] for row in disordered]):
                with self.assertRaises(PostgreSQLContractError):
                    digest_ordered_rows("users", disordered)

    def test_driver_normalization_totals_and_identity_planning(self):
        payment = _valid_row("payments")
        payment["admin_hidden"] = 1
        normalized = normalize_row_for_postgresql("payments", payment)
        self.assertIs(normalized["admin_hidden"], True)
        self.assertEqual(normalized["created_at"].tzinfo, timezone.utc)
        self.assertIs(type(normalized["amount"]), float)
        self.assertEqual(
            payment_minor_total((payment, payment)),
            {"rows": 2, "verified_amount_minor": 200},
        )

        boost = _valid_row("boost_logs")
        self.assertEqual(
            boost_ledger_totals((boost, boost)),
            {
                "rows": 2,
                "duration_seconds": 4,
                "duration_microseconds": 3_000_002,
            },
        )
        self.assertEqual(identity_restart_value("users", None), 1)
        self.assertEqual(identity_restart_value("users", -10), 1)
        self.assertEqual(identity_restart_value("users", 41), 42)
        with self.assertRaises(PostgreSQLContractError):
            identity_restart_value("steam_accounts", 1)
        with self.assertRaises(PostgreSQLContractError):
            identity_restart_value("users", (1 << 63) - 1)


class PostgreSQLBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ALEMBIC_AVAILABLE:
            raise AssertionError(
                "Alembic is required for Phase 5H.1C-A schema acceptance; "
                "missing migration tooling is a hard failure, not a skip."
            )
        cls.revision = _load_revision()
        cls.recorder = _OperationRecorder()
        with (
            mock.patch.object(cls.revision, "op", cls.recorder),
            mock.patch.object(
                cls.revision,
                "_require_empty_postgresql_schema",
                return_value=None,
            ),
        ):
            cls.revision.upgrade()

    def test_sqlite_revision_bytes_remain_frozen(self):
        for name, expected in SQLITE_REVISION_HASHES.items():
            with self.subTest(revision=name):
                actual = hashlib.sha256(
                    (ROOT / "migrations" / "versions" / name).read_bytes()
                ).hexdigest()
                self.assertEqual(actual, expected)

    def test_postgresql_lineage_is_independent_and_single_head(self):
        from alembic.script import ScriptDirectory

        self.assertEqual(self.revision.revision, POSTGRESQL_BASELINE_REVISION)
        self.assertIsNone(self.revision.down_revision)
        self.assertEqual(self.revision.branch_labels, ("postgresql",))
        script = ScriptDirectory(str(ROOT / "migrations_postgresql"))
        self.assertEqual(script.get_heads(), [POSTGRESQL_BASELINE_REVISION])
        self.assertEqual(script.get_bases(), [POSTGRESQL_BASELINE_REVISION])
        source = REVISION_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "from app import",
            "import app",
            "from config import",
            "load_dotenv",
            "db.metadata.create_all",
            "sqlite_where=",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_exact_inventory_compiles_for_postgresql(self):
        metadata = self.recorder.metadata
        self.assertEqual(tuple(metadata.tables), TRANSFER_TABLES)
        self.assertEqual(sum(len(table.c) for table in metadata.tables.values()), 103)
        self.assertEqual(
            sum(len(table.foreign_keys) for table in metadata.tables.values()),
            7,
        )
        self.assertEqual(len(self.recorder.indexes), 14)
        dialect = postgresql.dialect()
        for table in metadata.sorted_tables:
            with self.subTest(table=table.name):
                str(CreateTable(table).compile(dialect=dialect))
        for index in self.recorder.indexes:
            with self.subTest(index=index.name):
                str(CreateIndex(index).compile(dialect=dialect))

    def test_transfer_gate_accepts_the_exact_frozen_baseline_contract(self):
        _validate_postgresql_table_contract(dict(self.recorder.metadata.tables))

    def test_observed_deparse_forms_do_not_erase_literals_or_grouping(self):
        for canonical, observed in POSTGRESQL17_EXPRESSION_FORMS.items():
            for expression in observed:
                self.assertEqual(_normalized_sql_expression(canonical), _normalized_sql_expression(expression))
        original = PARTIAL_INDEX_PREDICATES["ux_payments_one_open_checkout"]
        for changed in (original.replace("checkout_started", "CHECKOUT_STARTED"),
                        original.replace(" AND ", " OR "), original + " OR true"):
            self.assertNotEqual(_normalized_sql_expression(original), _normalized_sql_expression(changed))
        self.assertNotEqual(_normalized_sql_expression("a * (b + c)"), _normalized_sql_expression("(a * b) + c"))
        self.assertNotEqual(_normalized_sql_expression("'a b'"), _normalized_sql_expression("'ab'"))

    def test_default_normalization_preserves_case_sensitive_text(self):
        lower = sa.Column("lang", sa.String(5), server_default=sa.text("'tr'::character varying"))
        upper = sa.Column("lang", sa.String(5), server_default=sa.text("'TR'::character varying"))
        self.assertEqual(_normalized_server_default(lower), "tr")
        self.assertEqual(_normalized_server_default(upper), "TR")
        for literal in ("tr::text", "::texttr", "t r", "tr::integer"):
            changed = sa.Column("lang", sa.String(30), server_default=sa.text("'" + literal + "'::character varying"))
            self.assertEqual(_normalized_server_default(changed), literal)
        quoted = sa.Column("lang", sa.String(30), server_default=sa.text("('it''s::text'::text)"))
        self.assertEqual(_normalized_server_default(quoted), "it's::text")

    def _cloned_baseline_tables(self):
        metadata = sa.MetaData()
        for table in self.recorder.metadata.sorted_tables:
            table.to_metadata(metadata)
        return dict(metadata.tables)

    def test_transfer_gate_rejects_nonbaseline_structural_options(self):
        cases = []

        tables = self._cloned_baseline_tables()
        tables["payments"].append_constraint(sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ))
        cases.append(("duplicate foreign key", tables))

        tables = self._cloned_baseline_tables()
        unique = next(
            constraint
            for constraint in tables["users"].constraints
            if isinstance(constraint, sa.UniqueConstraint)
        )
        unique.deferrable = True
        cases.append(("deferrable unique", tables))

        tables = self._cloned_baseline_tables()
        tables["users"].c.id.identity.start = 5
        cases.append(("identity start", tables))

        tables = self._cloned_baseline_tables()
        tables["users"].c.created_at.type.precision = 3
        cases.append(("timestamp precision", tables))

        tables = self._cloned_baseline_tables()
        index = next(iter(tables["payments"].indexes))
        index.dialect_options["postgresql"]["nulls_not_distinct"] = True
        cases.append(("index nulls not distinct", tables))

        for label, tables in cases:
            with self.subTest(label=label), self.assertRaises(
                PostgreSQLTransferError
            ):
                _validate_postgresql_table_contract(tables)

    def test_orm_and_frozen_baseline_have_normalized_column_shape_parity(self):
        dialect = postgresql.dialect()
        for table_name in TRANSFER_TABLES:
            with self.subTest(table=table_name):
                model_table = db.metadata.tables[table_name]
                baseline_table = self.recorder.metadata.tables[table_name]
                self.assertEqual(
                    tuple(model_table.c.keys()),
                    tuple(baseline_table.c.keys()),
                )
                for column_name in baseline_table.c.keys():
                    with self.subTest(table=table_name, column=column_name):
                        model_column = model_table.c[column_name]
                        baseline_column = baseline_table.c[column_name]
                        self.assertIs(
                            model_column.nullable,
                            baseline_column.nullable,
                        )
                        model_type = str(
                            model_column.type.compile(dialect=dialect)
                        ).upper()
                        baseline_type = str(
                            baseline_column.type.compile(dialect=dialect)
                        ).upper()
                        # Text collation is deliberately migration-owned.  ORM
                        # query compilation need not repeat it, while the
                        # frozen baseline and transfer gate require exact C.
                        baseline_type = baseline_type.replace(' COLLATE "C"', "")
                        self.assertEqual(model_type, baseline_type)

    def test_exact_nullability_foreign_key_unique_and_check_contract(self):
        metadata = self.recorder.metadata
        actual_required = {
            (table.name, column.name)
            for table in metadata.tables.values()
            for column in table.columns
            if not column.nullable
        }
        self.assertEqual(actual_required, PHYSICAL_NOT_NULL_COLUMNS)

        actual_foreign_keys = {
            (table.name, foreign_key.parent.name): (
                foreign_key.column.table.name,
                foreign_key.column.name,
            )
            for table in metadata.tables.values()
            for foreign_key in table.foreign_keys
        }
        self.assertEqual(actual_foreign_keys, FOREIGN_KEYS)
        for table in metadata.tables.values():
            for foreign_key in table.foreign_keys:
                with self.subTest(
                    table=table.name,
                    column=foreign_key.parent.name,
                ):
                    self.assertIsNone(foreign_key.ondelete)
                    self.assertIsNone(foreign_key.onupdate)

        actual_unique = {}
        for table in metadata.tables.values():
            for constraint in table.constraints:
                if isinstance(constraint, sa.UniqueConstraint):
                    actual_unique[(table.name, constraint.name)] = tuple(
                        column.name for column in constraint.columns
                    )
        self.assertEqual(actual_unique, UNIQUE_CONSTRAINTS)

        actual_checks = {
            (table.name, constraint.name): str(constraint.sqltext)
            for table in metadata.tables.values()
            for constraint in table.constraints
            if isinstance(constraint, sa.CheckConstraint)
        }
        self.assertEqual(actual_checks, CHECK_CONSTRAINTS)
        self.assertEqual(
            actual_checks[("boost_logs", "ck_boost_logs_duration_ledger")],
            DURATION_LEDGER_CHECK,
        )

    def test_exact_text_numeric_boolean_default_and_index_contract(self):
        metadata = self.recorder.metadata
        dialect = postgresql.dialect()

        for (table_name, column_name), limit in TEXT_LIMITS.items():
            with self.subTest(table=table_name, column=column_name):
                column_type = metadata.tables[table_name].c[column_name].type
                self.assertEqual(column_type.length, limit)
                self.assertEqual(column_type.collation, "C")

        for table_name, column_name in BOOLEAN_COLUMNS:
            with self.subTest(table=table_name, column=column_name):
                self.assertIsInstance(
                    metadata.tables[table_name].c[column_name].type,
                    sa.Boolean,
                )
        for table_name, column_name in INTEGER_COLUMNS:
            with self.subTest(table=table_name, column=column_name):
                column_type = metadata.tables[table_name].c[column_name].type
                self.assertIsInstance(column_type, sa.Integer)
                self.assertNotIsInstance(column_type, sa.BigInteger)

        actual_defaults = {
            (table.name, column.name): str(column.server_default.arg)
            for table in metadata.tables.values()
            for column in table.columns
            if column.server_default is not None
            and hasattr(column.server_default, "arg")
        }
        expected_defaults = {
            key: ("'tr'" if value == "tr" else str(value).lower())
            for key, value in SERVER_DEFAULTS.items()
        }
        self.assertEqual(actual_defaults, expected_defaults)

        indexes = {index.name: index for index in self.recorder.indexes}
        self.assertEqual(set(indexes), set(INDEX_CONTRACT))
        for name, (table_name, columns, unique, predicate) in INDEX_CONTRACT.items():
            with self.subTest(index=name):
                index = indexes[name]
                self.assertEqual(index.table.name, table_name)
                self.assertEqual(
                    tuple(column.name for column in index.columns),
                    columns,
                )
                self.assertIs(bool(index.unique), unique)
                compiled = str(CreateIndex(index).compile(dialect=dialect))
                if predicate is None:
                    self.assertNotIn(" WHERE ", compiled)
                else:
                    self.assertIn(" WHERE " + predicate, compiled)

    def test_physical_types_identity_and_timestamp_contract(self):
        metadata = self.recorder.metadata
        dialect = postgresql.dialect()
        for table_name in IDENTITY_TABLES:
            column = metadata.tables[table_name].c.id
            self.assertIsInstance(column.type, sa.BigInteger)
            self.assertIsNotNone(column.identity)
        self.assertIsNone(metadata.tables["steam_accounts"].c.id.identity)
        for table_name, column_name in UTC_DATETIME_COLUMNS:
            column = metadata.tables[table_name].c[column_name]
            self.assertEqual(
                str(column.type.compile(dialect=dialect)).upper(),
                "TIMESTAMP WITH TIME ZONE",
            )
        for table_name, column_name in BIGINT_COLUMNS:
            self.assertIsInstance(
                metadata.tables[table_name].c[column_name].type,
                sa.BigInteger,
            )
        self.assertEqual(
            str(metadata.tables["payments"].c.amount.type.compile(dialect=dialect)),
            "DOUBLE PRECISION",
        )
        self.assertEqual(
            str(
                db.metadata.tables["payments"].c.amount.type.compile(
                    dialect=dialect
                )
            ),
            "DOUBLE PRECISION",
        )

    def test_all_named_indexes_and_partial_predicates_are_exact(self):
        indexes = {index.name: index for index in self.recorder.indexes}
        self.assertEqual(len(indexes), 14)
        for name, predicate in PARTIAL_INDEX_PREDICATES.items():
            with self.subTest(index=name):
                index = indexes[name]
                self.assertTrue(index.unique)
                sql = str(
                    CreateIndex(index).compile(dialect=postgresql.dialect())
                )
                self.assertIn(" WHERE " + predicate, sql)
        self.assertNotIn("trg_boost_logs", REVISION_PATH.read_text("utf-8"))

    def test_model_variants_preserve_sqlite_rowid_types_and_postgresql_bigint(self):
        native_sqlite_bigints = {
            ("payments", "shopier_timestamp"),
            ("boost_logs", "duration_microseconds"),
        }
        for table_name, column_name in BIGINT_COLUMNS:
            model_column = db.metadata.tables[table_name].c[column_name]
            with self.subTest(table=table_name, column=column_name):
                self.assertEqual(
                    str(model_column.type.compile(dialect=sqlite.dialect())).upper(),
                    (
                        "BIGINT"
                        if (table_name, column_name) in native_sqlite_bigints
                        else "INTEGER"
                    ),
                )
                self.assertEqual(
                    str(
                        model_column.type.compile(dialect=postgresql.dialect())
                    ).upper(),
                    "BIGINT",
                )

    def test_baseline_guards_reject_offline_wrong_dialect_and_no_transaction(self):
        revision = self.revision
        cases = (
            (types.SimpleNamespace(as_sql=True, dialect=types.SimpleNamespace(name="postgresql")), None),
            (types.SimpleNamespace(as_sql=False, dialect=types.SimpleNamespace(name="sqlite")), None),
            (
                types.SimpleNamespace(as_sql=False, dialect=types.SimpleNamespace(name="postgresql")),
                types.SimpleNamespace(in_transaction=lambda: False),
            ),
        )
        for migration_context, bind in cases:
            fake_op = types.SimpleNamespace(
                get_context=lambda: migration_context,
                get_bind=lambda: bind,
            )
            with self.subTest(context=migration_context), mock.patch.object(
                revision, "op", fake_op
            ):
                with self.assertRaises(RuntimeError):
                    revision._require_empty_postgresql_schema()


if __name__ == "__main__":
    unittest.main()
