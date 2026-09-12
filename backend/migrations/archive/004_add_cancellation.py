"""add cancellation_reason column and cancelled status to scanstatus enum

Revision ID: 004_add_cancellation
Revises: 003_add_task_id_to_scans
Create Date: 2026-07-29 00:00:00.000000

Adds:
  - scans.cancellation_reason (String 255, nullable)
  - 'cancelled' value to the scanstatus PostgreSQL enum

Works correctly on both SQLite (development/test) and PostgreSQL (production).
On SQLite, ALTER TYPE is not supported and not needed (SQLite enums are stored
as strings); only the new column is added.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers
revision: str = "004_add_cancellation"
down_revision: Union[str, None] = "003_add_task_id_to_scans"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    bind = op.get_bind()
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    # 1. Add cancellation_reason column (works on both SQLite and PostgreSQL)
    # Use batch_alter_table for SQLite compatibility
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(
            sa.Column("cancellation_reason", sa.String(255), nullable=True)
        )

    # 2. Add 'cancelled' to the scanstatus enum (PostgreSQL only)
    if _is_postgresql():
        # PostgreSQL requires ALTER TYPE to add enum values
        op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'cancelled'")


def downgrade() -> None:
    # Remove the column (both dialects)
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_column("cancellation_reason")

    # Note: PostgreSQL does not support removing enum values.
    # To fully downgrade on PostgreSQL you would need to:
    # 1. Change all rows with status='cancelled' to 'failed'
    # 2. Create new enum without 'cancelled'
    # 3. Alter column type
    # 4. Drop old enum
    # This is intentionally omitted as it is destructive.
    if _is_postgresql():
        op.execute(
            "UPDATE scans SET status = 'failed' WHERE status = 'cancelled'"
        )
