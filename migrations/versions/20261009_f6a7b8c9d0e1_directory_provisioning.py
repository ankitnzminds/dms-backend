"""directory provisioning

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-09 15:07:02.621830
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('directory_sources',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('secret_ref', sa.String(length=200), nullable=True),
    sa.Column('enabled', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('sync_interval_minutes', sa.Integer(), nullable=True),
    sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("kind IN ('static', 'entra', 'ldap')", name=op.f('ck_directory_sources_kind')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_directory_sources_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_directory_sources_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_directory_sources')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_directory_sources_id_org'),
    sa.UniqueConstraint('organization_id', 'name', name='uq_directory_sources_name'),
    schema='dms'
    )
    op.create_table('directory_group_links',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('external_id', sa.String(length=255), nullable=False),
    sa.Column('group_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['group_id', 'organization_id'], ['dms.groups.id', 'dms.groups.organization_id'], name='fk_directory_group_links_group_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['source_id', 'organization_id'], ['dms.directory_sources.id', 'dms.directory_sources.organization_id'], name='fk_directory_group_links_source_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_directory_group_links')),
    sa.UniqueConstraint('group_id', name='uq_directory_group_links_group'),
    sa.UniqueConstraint('source_id', 'external_id', name='uq_directory_group_links_external'),
    schema='dms'
    )
    op.create_table('directory_sync_runs',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('dry_run', sa.Boolean(), nullable=False),
    sa.Column('triggered_by', sa.Uuid(), nullable=True),
    sa.Column('stats', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("state IN ('running', 'succeeded', 'failed', 'aborted')", name=op.f('ck_directory_sync_runs_state')),
    sa.ForeignKeyConstraint(['source_id', 'organization_id'], ['dms.directory_sources.id', 'dms.directory_sources.organization_id'], name='fk_directory_sync_runs_source_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['triggered_by'], ['dms.users.id'], name=op.f('fk_directory_sync_runs_triggered_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_directory_sync_runs')),
    schema='dms'
    )
    op.create_index('ix_directory_sync_runs_source', 'directory_sync_runs', ['source_id', 'started_at'], unique=False, schema='dms')
    op.create_table('directory_user_links',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('external_id', sa.String(length=255), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('deprovisioned_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['source_id', 'organization_id'], ['dms.directory_sources.id', 'dms.directory_sources.organization_id'], name='fk_directory_user_links_source_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_directory_user_links_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_directory_user_links')),
    sa.UniqueConstraint('source_id', 'external_id', name='uq_directory_user_links_external'),
    sa.UniqueConstraint('source_id', 'user_id', name='uq_directory_user_links_user'),
    schema='dms'
    )
    for table in (
        "directory_sources",
        "directory_user_links",
        "directory_group_links",
        "directory_sync_runs",
    ):
        op.execute(f"ALTER TABLE dms.{table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.drop_table('directory_user_links', schema='dms')
    op.drop_index('ix_directory_sync_runs_source', table_name='directory_sync_runs', schema='dms')
    op.drop_table('directory_sync_runs', schema='dms')
    op.drop_table('directory_group_links', schema='dms')
    op.drop_table('directory_sources', schema='dms')
