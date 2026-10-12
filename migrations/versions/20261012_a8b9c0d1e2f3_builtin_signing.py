"""built-in signing: per-recipient consent evidence and decline reason (additive, nullable)

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-10-12 06:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = 'a8b9c0d1e2f3'
down_revision = 'f7a8b9c0d1e2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('signature_recipients', sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True), schema='dms')
    op.add_column('signature_recipients', sa.Column('decline_reason', sa.String(length=500), nullable=True), schema='dms')


def downgrade() -> None:
    op.drop_column('signature_recipients', 'decline_reason', schema='dms')
    op.drop_column('signature_recipients', 'evidence', schema='dms')
