"""add task_id to scans

Revision ID: 003_add_task_id_to_scans
Revises: 16dd5c96c8e6
Create Date: 2026-07-28 00:00:00.000000

Adds task_id column to scans table for ARQ job tracking.
Works on both SQLite (development) and PostgreSQL (production).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision: str = "003_add_task_id_to_scans"
down_revision: Union[str, None] = "16dd5c96c8e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("task_id", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "task_id")
