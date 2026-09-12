"""Remove target_verifications and favorites

Revision ID: 006_cleanup
Revises: 16dd5c96c8e6
Create Date: 2026-08-23 10:48:00.000000+00:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '006_cleanup'
down_revision: Union[str, None] = '005_add_missing_columns'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Drop target_verifications table if it exists
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()
    if 'target_verifications' in tables:
        op.drop_table('target_verifications')

    # 2. Drop is_favorite column from scans table if it exists
    columns = [c['name'] for c in inspector.get_columns('scans')]
    if 'is_favorite' in columns:
        with op.batch_alter_table('scans') as batch_op:
            batch_op.drop_column('is_favorite')


def downgrade() -> None:
    # Recreate is_favorite on scans
    with op.batch_alter_table('scans') as batch_op:
        batch_op.add_column(sa.Column('is_favorite', sa.Boolean(), server_default='false', nullable=False))
