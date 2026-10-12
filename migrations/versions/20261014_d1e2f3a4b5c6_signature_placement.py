"""signature placement: where the signature box was placed on the signing PDF (additive, nullable)

Revision ID: d1e2f3a4b5c6
Revises: c0d1e2f3a4b5
Create Date: 2026-10-14 00:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = 'd1e2f3a4b5c6'
down_revision = 'c0d1e2f3a4b5'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('signature_requests', sa.Column('placement', postgresql.JSONB(astext_type=sa.Text()), nullable=True), schema='dms')


def downgrade() -> None:
    op.drop_column('signature_requests', 'placement', schema='dms')
