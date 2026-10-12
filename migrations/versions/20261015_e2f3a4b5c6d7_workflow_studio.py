"""workflow studio: binding mode + priority on automations, approval definitions on versions (additive)

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
Create Date: 2026-10-15 00:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = 'e2f3a4b5c6d7'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('automations', sa.Column('binding_mode', sa.String(length=16), server_default='additive', nullable=False), schema='dms')
    op.add_column('automations', sa.Column('priority', sa.Integer(), server_default='0', nullable=False), schema='dms')
    op.create_check_constraint(op.f('ck_automations_binding_mode'), 'automations', "binding_mode IN ('additive', 'exclusive')", schema='dms')
    op.add_column('automation_versions', sa.Column('approval_definitions', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False), schema='dms')


def downgrade() -> None:
    op.drop_column('automation_versions', 'approval_definitions', schema='dms')
    op.drop_constraint(op.f('ck_automations_binding_mode'), 'automations', schema='dms')
    op.drop_column('automations', 'priority', schema='dms')
    op.drop_column('automations', 'binding_mode', schema='dms')
