"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

Review generated operations before use. Freeze physical schema types here;
never import app, config, models or mutable runtime migration helpers.
"""

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}


revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    """Apply only explicitly reviewed forward operations."""
    ${upgrades if upgrades else "raise RuntimeError('Migration upgrade requires explicit review')"}


def downgrade() -> None:
    """Data-destructive generated downgrades are intentionally not emitted."""
    raise RuntimeError("Downgrade requires a separately reviewed recovery procedure")
