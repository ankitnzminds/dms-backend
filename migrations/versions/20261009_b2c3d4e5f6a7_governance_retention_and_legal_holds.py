"""governance retention and legal holds

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-09 14:34:17.010314
"""
from alembic import op
import sqlalchemy as sa


revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('legal_holds',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('released_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('released_by', sa.Uuid(), nullable=True),
    sa.Column('release_reason', sa.Text(), nullable=True),
    sa.CheckConstraint("status IN ('active', 'released')", name=op.f('ck_legal_holds_status')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_legal_holds_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_legal_holds_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['released_by'], ['dms.users.id'], name=op.f('fk_legal_holds_released_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_legal_holds')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_legal_holds_id_org'),
    schema='dms'
    )
    op.create_index('ix_legal_holds_org_status', 'legal_holds', ['organization_id', 'status'], unique=False, schema='dms')
    op.create_table('retention_policies',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('scope_folder_id', sa.Uuid(), nullable=True),
    sa.Column('min_retention_days', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('min_retention_days BETWEEN 1 AND 36500', name=op.f('ck_retention_policies_days_range')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_retention_policies_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_retention_policies_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_retention_policies')),
    schema='dms'
    )
    op.create_index('ix_retention_policies_org', 'retention_policies', ['organization_id', 'enabled'], unique=False, schema='dms')
    op.create_index('uq_retention_policies_name', 'retention_policies', ['organization_id', sa.literal_column('lower(name)')], unique=True, schema='dms')
    op.create_table('legal_hold_items',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('hold_id', sa.Uuid(), nullable=False),
    sa.Column('resource_type', sa.String(length=16), nullable=False),
    sa.Column('resource_id', sa.Uuid(), nullable=False),
    sa.Column('added_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("resource_type IN ('folder', 'document')", name=op.f('ck_legal_hold_items_resource_type')),
    sa.ForeignKeyConstraint(['added_by'], ['dms.users.id'], name=op.f('fk_legal_hold_items_added_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['hold_id', 'organization_id'], ['dms.legal_holds.id', 'dms.legal_holds.organization_id'], name='fk_legal_hold_items_hold_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_legal_hold_items')),
    sa.UniqueConstraint('hold_id', 'resource_type', 'resource_id', name='uq_legal_hold_items'),
    schema='dms'
    )
    op.create_index('ix_legal_hold_items_resource', 'legal_hold_items', ['organization_id', 'resource_type', 'resource_id'], unique=False, schema='dms')
    for table in ("retention_policies", "legal_holds", "legal_hold_items"):
        op.execute(f"ALTER TABLE dms.{table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.drop_index('ix_legal_hold_items_resource', table_name='legal_hold_items', schema='dms')
    op.drop_table('legal_hold_items', schema='dms')
    op.drop_index('uq_retention_policies_name', table_name='retention_policies', schema='dms')
    op.drop_index('ix_retention_policies_org', table_name='retention_policies', schema='dms')
    op.drop_table('retention_policies', schema='dms')
    op.drop_index('ix_legal_holds_org_status', table_name='legal_holds', schema='dms')
    op.drop_table('legal_holds', schema='dms')
