# HourBoost PostgreSQL migration lineage

This directory is independent from the deployed SQLite lineage in
`migrations/`. Revision `20260913_01` is a frozen baseline for an empty,
disposable PostgreSQL schema. It is not permission to enable PostgreSQL in the
application or to stamp an existing database.

Safety rules:

- Never edit or reuse the SQLite revisions for PostgreSQL.
- Never run this environment from a URL stored in an ini file or command line.
- A reviewed runner must inject an already-open PostgreSQL connection inside an
  explicit outer transaction.
- The target schema must be empty apart from Alembic's own version relation.
- Do not import `app.py`, `config.py`, dotenv, or worker code.
- Downgrade is intentionally disabled because dropping financial and usage
  history is not a rollback strategy.
- Compiler/unit tests are readiness evidence only. A real disposable
  PostgreSQL rehearsal remains mandatory before acceptance.
