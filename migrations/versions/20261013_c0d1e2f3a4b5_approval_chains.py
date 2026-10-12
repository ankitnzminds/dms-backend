"""approval chains: optional/super approver flags on tasks and the per-folder chain binding (additive)

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-10-13 06:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'c0d1e2f3a4b5'
down_revision = 'b9c0d1e2f3a4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('workflow_tasks', sa.Column('optional', sa.Boolean(), server_default='false', nullable=False), schema='dms')
    op.add_column('workflow_tasks', sa.Column('is_super_approver', sa.Boolean(), server_default='false', nullable=False), schema='dms')
    op.create_table(
        'folder_approval_chains',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('folder_id', sa.Uuid(), nullable=False),
        sa.Column('definition_id', sa.Uuid(), nullable=False),
        sa.Column('updated_by', sa.Uuid(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['folder_id', 'organization_id'], ['dms.folders.id', 'dms.folders.organization_id'], name='fk_folder_approval_chains_folder_org', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['definition_id', 'organization_id'], ['dms.workflow_definitions.id', 'dms.workflow_definitions.organization_id'], name='fk_folder_approval_chains_definition_org', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['updated_by'], ['dms.users.id'], name=op.f('fk_folder_approval_chains_updated_by_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_folder_approval_chains')),
        sa.UniqueConstraint('folder_id', name='uq_folder_approval_chains_folder'),
        schema='dms',
    )
    op.execute("ALTER TABLE dms.folder_approval_chains ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.drop_table('folder_approval_chains', schema='dms')
    op.drop_column('workflow_tasks', 'is_super_approver', schema='dms')
    op.drop_column('workflow_tasks', 'optional', schema='dms')
