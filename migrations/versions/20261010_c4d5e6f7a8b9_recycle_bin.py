"""recycle bin: remember that a user asked for permanent deletion (item stays recoverable by admins)

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-10-10 02:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = 'c4d5e6f7a8b9'
down_revision = 'b3c4d5e6f7a8'
branch_labels = None
depends_on = None

TABLES = ['folders', 'documents']


def upgrade() -> None:
    for t in TABLES:
        op.add_column(t, sa.Column('purge_requested_at', sa.DateTime(timezone=True), nullable=True), schema='dms')
        op.add_column(
            t,
            sa.Column(
                'purge_requested_by',
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey('dms.users.id', ondelete='SET NULL'),
                nullable=True,
            ),
            schema='dms',
        )


def downgrade() -> None:
    for t in TABLES:
        op.drop_column(t, 'purge_requested_by', schema='dms')
        op.drop_column(t, 'purge_requested_at', schema='dms')
