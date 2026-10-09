"""initial schema

Revision ID: 03af22e4d963
Revises: 
Create Date: 2026-10-09 13:37:42.150032
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '03af22e4d963'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('organizations',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('slug', sa.String(length=100), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('settings', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('quota_bytes', sa.BigInteger(), nullable=True),
    sa.Column('quota_used_bytes', sa.BigInteger(), server_default='0', nullable=False),
    sa.Column('quota_reserved_bytes', sa.BigInteger(), server_default='0', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('active', 'suspended', 'offboarding', 'deletion_requested')", name=op.f('ck_organizations_status')),
    sa.CheckConstraint('quota_bytes IS NULL OR quota_bytes >= 0', name=op.f('ck_organizations_quota_nonneg')),
    sa.CheckConstraint('quota_reserved_bytes >= 0', name=op.f('ck_organizations_reserved_nonneg')),
    sa.CheckConstraint('quota_used_bytes >= 0', name=op.f('ck_organizations_used_nonneg')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_organizations')),
    sa.UniqueConstraint('slug', name=op.f('uq_organizations_slug')),
    schema='dms'
    )
    op.create_table('processed_events',
    sa.Column('consumer', sa.String(length=100), nullable=False),
    sa.Column('event_id', sa.Uuid(), nullable=False),
    sa.Column('processed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('consumer', 'event_id', name=op.f('pk_processed_events')),
    schema='dms'
    )
    op.create_table('users',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('display_name', sa.String(length=200), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('identity_provider', sa.String(length=50), nullable=True),
    sa.Column('external_subject', sa.String(length=255), nullable=True),
    sa.Column('email_verified', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('sessions_valid_after', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('invited', 'active', 'disabled')", name=op.f('ck_users_status')),
    sa.CheckConstraint('(external_subject IS NULL) = (identity_provider IS NULL)', name=op.f('ck_users_identity_pair')),
    sa.CheckConstraint('email = lower(email)', name=op.f('ck_users_email_lowercase')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    schema='dms'
    )
    op.create_index('uq_users_email', 'users', ['email'], unique=True, schema='dms')
    op.create_index('uq_users_identity', 'users', ['identity_provider', 'external_subject'], unique=True, schema='dms', postgresql_where=sa.text('external_subject IS NOT NULL'))
    op.create_table('audit_events',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=True),
    sa.Column('actor_user_id', sa.Uuid(), nullable=True),
    sa.Column('action', sa.String(length=100), nullable=False),
    sa.Column('resource_type', sa.String(length=50), nullable=True),
    sa.Column('resource_id', sa.Uuid(), nullable=True),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.Column('request_id', sa.String(length=64), nullable=True),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=300), nullable=True),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("outcome IN ('success', 'denied', 'failure')", name=op.f('ck_audit_events_outcome')),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_audit_events_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events')),
    schema='dms'
    )
    op.create_index('ix_audit_events_actor', 'audit_events', ['organization_id', 'actor_user_id'], unique=False, schema='dms')
    op.create_index('ix_audit_events_org_action', 'audit_events', ['organization_id', 'action', sa.literal_column('created_at DESC')], unique=False, schema='dms')
    op.create_index('ix_audit_events_org_created', 'audit_events', ['organization_id', sa.literal_column('created_at DESC')], unique=False, schema='dms')
    op.create_index('ix_audit_events_resource', 'audit_events', ['organization_id', 'resource_type', 'resource_id'], unique=False, schema='dms')
    op.create_table('folders',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('parent_folder_id', sa.Uuid(), nullable=True),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('is_team_folder', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deleted_by', sa.Uuid(), nullable=True),
    sa.Column('delete_batch_id', sa.UUID(), nullable=True),
    sa.Column('row_version', sa.Integer(), server_default='1', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("name !~ '[/\\\\]'", name=op.f('ck_folders_name_no_separators')),
    sa.CheckConstraint('length(btrim(name)) > 0', name=op.f('ck_folders_name_nonempty')),
    sa.CheckConstraint('parent_folder_id IS NULL OR parent_folder_id <> id', name=op.f('ck_folders_not_own_parent')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_folders_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['deleted_by'], ['dms.users.id'], name=op.f('fk_folders_deleted_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_folders_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['parent_folder_id', 'organization_id'], ['dms.folders.id', 'dms.folders.organization_id'], name='fk_folders_parent_org', ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_folders')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_folders_id_org'),
    schema='dms'
    )
    op.create_index('ix_folders_delete_batch', 'folders', ['delete_batch_id'], unique=False, schema='dms', postgresql_where=sa.text('delete_batch_id IS NOT NULL'))
    op.create_index('ix_folders_parent', 'folders', ['organization_id', 'parent_folder_id'], unique=False, schema='dms')
    op.create_index('uq_folders_one_root', 'folders', ['organization_id'], unique=True, schema='dms', postgresql_where=sa.text('parent_folder_id IS NULL'))
    op.create_index('uq_folders_sibling_name', 'folders', ['organization_id', 'parent_folder_id', sa.literal_column('lower(name)')], unique=True, schema='dms', postgresql_where=sa.text('deleted_at IS NULL AND parent_folder_id IS NOT NULL'))
    op.create_table('groups',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('external_id', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("kind IN ('group', 'department', 'team')", name=op.f('ck_groups_kind')),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_groups_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_groups')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_groups_id_org'),
    schema='dms'
    )
    op.create_index('uq_groups_org_external', 'groups', ['organization_id', 'external_id'], unique=True, schema='dms', postgresql_where=sa.text('external_id IS NOT NULL'))
    op.create_index('uq_groups_org_name', 'groups', ['organization_id', sa.literal_column('lower(name)')], unique=True, schema='dms')
    op.create_table('memberships',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('invited_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("role IN ('owner', 'admin', 'member', 'auditor')", name=op.f('ck_memberships_role')),
    sa.CheckConstraint("status IN ('invited', 'active', 'suspended', 'removed')", name=op.f('ck_memberships_status')),
    sa.ForeignKeyConstraint(['invited_by'], ['dms.users.id'], name=op.f('fk_memberships_invited_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_memberships_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_memberships_user_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_memberships')),
    sa.UniqueConstraint('organization_id', 'user_id', name='uq_memberships_org_user'),
    schema='dms'
    )
    op.create_index('ix_memberships_user', 'memberships', ['user_id'], unique=False, schema='dms')
    op.create_table('notifications',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('body', sa.Text(), nullable=True),
    sa.Column('resource_type', sa.String(length=50), nullable=True),
    sa.Column('resource_id', sa.Uuid(), nullable=True),
    sa.Column('source_event_id', sa.Uuid(), nullable=True),
    sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_notifications_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_notifications_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notifications')),
    sa.UniqueConstraint('user_id', 'source_event_id', 'type', name='uq_notifications_event'),
    schema='dms'
    )
    op.create_index('ix_notifications_user_created', 'notifications', ['user_id', sa.literal_column('created_at DESC')], unique=False, schema='dms')
    op.create_table('outbox_events',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=True),
    sa.Column('event_type', sa.String(length=100), nullable=False),
    sa.Column('aggregate_type', sa.String(length=50), nullable=False),
    sa.Column('aggregate_id', sa.Uuid(), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
    sa.Column('max_attempts', sa.Integer(), server_default='8', nullable=False),
    sa.Column('next_attempt_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status IN ('pending', 'processing', 'done', 'dead')", name=op.f('ck_outbox_events_status')),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_outbox_events_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_outbox_events')),
    schema='dms'
    )
    op.create_index('ix_outbox_aggregate', 'outbox_events', ['aggregate_type', 'aggregate_id'], unique=False, schema='dms')
    op.create_index('ix_outbox_claimable', 'outbox_events', ['next_attempt_at'], unique=False, schema='dms', postgresql_where=sa.text("status IN ('pending', 'processing')"))
    op.create_table('permission_grants',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('resource_type', sa.String(length=16), nullable=False),
    sa.Column('resource_id', sa.Uuid(), nullable=False),
    sa.Column('subject_type', sa.String(length=16), nullable=False),
    sa.Column('subject_id', sa.Uuid(), nullable=True),
    sa.Column('actions', postgresql.ARRAY(sa.String(length=32)), nullable=False),
    sa.Column('inherit', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_by', sa.Uuid(), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(subject_type = 'organization') = (subject_id IS NULL)", name=op.f('ck_permission_grants_subject_id_matches_type')),
    sa.CheckConstraint("resource_type IN ('folder', 'document')", name=op.f('ck_permission_grants_resource_type')),
    sa.CheckConstraint("subject_type IN ('user', 'group', 'organization')", name=op.f('ck_permission_grants_subject_type')),
    sa.CheckConstraint('cardinality(actions) > 0', name=op.f('ck_permission_grants_actions_nonempty')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_permission_grants_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_permission_grants_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['revoked_by'], ['dms.users.id'], name=op.f('fk_permission_grants_revoked_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_permission_grants')),
    schema='dms'
    )
    op.create_index('ix_permission_grants_resource', 'permission_grants', ['organization_id', 'resource_type', 'resource_id'], unique=False, schema='dms')
    op.create_index('ix_permission_grants_subject', 'permission_grants', ['organization_id', 'subject_type', 'subject_id'], unique=False, schema='dms')
    op.create_table('quota_ledger_entries',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('entry_type', sa.String(length=16), nullable=False),
    sa.Column('reserved_delta', sa.BigInteger(), nullable=False),
    sa.Column('used_delta', sa.BigInteger(), nullable=False),
    sa.Column('upload_session_id', sa.Uuid(), nullable=True),
    sa.Column('document_version_id', sa.Uuid(), nullable=True),
    sa.Column('idempotency_key', sa.String(length=200), nullable=False),
    sa.Column('note', sa.String(length=500), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("entry_type IN ('reserve', 'commit', 'release', 'adjust')", name=op.f('ck_quota_ledger_entries_type')),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_quota_ledger_entries_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_quota_ledger_entries')),
    sa.UniqueConstraint('organization_id', 'idempotency_key', name='uq_quota_ledger_idem'),
    schema='dms'
    )
    op.create_index('ix_quota_ledger_org_created', 'quota_ledger_entries', ['organization_id', 'created_at'], unique=False, schema='dms')
    op.create_index('ix_quota_ledger_session', 'quota_ledger_entries', ['upload_session_id'], unique=False, schema='dms')
    op.create_table('share_grants',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('resource_type', sa.String(length=16), nullable=False),
    sa.Column('resource_id', sa.Uuid(), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=False),
    sa.Column('actions', postgresql.ARRAY(sa.String(length=32)), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_by', sa.Uuid(), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('expiry_recorded_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("resource_type IN ('folder', 'document')", name=op.f('ck_share_grants_resource_type')),
    sa.CheckConstraint('cardinality(actions) > 0', name=op.f('ck_share_grants_actions_nonempty')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_share_grants_created_by_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_share_grants_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['revoked_by'], ['dms.users.id'], name=op.f('fk_share_grants_revoked_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_share_grants')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_share_grants_id_org'),
    schema='dms'
    )
    op.create_index('ix_share_grants_active_expiry', 'share_grants', ['organization_id', 'expires_at'], unique=False, schema='dms', postgresql_where=sa.text('revoked_at IS NULL'))
    op.create_index('ix_share_grants_creator', 'share_grants', ['organization_id', 'created_by'], unique=False, schema='dms')
    op.create_index('ix_share_grants_resource', 'share_grants', ['organization_id', 'resource_type', 'resource_id'], unique=False, schema='dms')
    op.create_table('storage_locations',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('provider_type', sa.String(length=50), nullable=False),
    sa.Column('bucket', sa.String(length=200), nullable=False),
    sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('secret_ref', sa.String(length=200), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('is_default', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('active', 'disabled')", name=op.f('ck_storage_locations_status')),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_storage_locations_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_storage_locations')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_storage_locations_id_org'),
    schema='dms'
    )
    op.create_index('uq_storage_locations_default', 'storage_locations', ['organization_id'], unique=True, schema='dms', postgresql_where=sa.text('is_default'))
    op.create_table('documents',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('folder_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('owner_id', sa.Uuid(), nullable=True),
    sa.Column('current_version_id', sa.Uuid(), nullable=True),
    sa.Column('latest_version_number', sa.Integer(), server_default='0', nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('classification', sa.String(length=50), server_default='internal', nullable=False),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deleted_by', sa.Uuid(), nullable=True),
    sa.Column('delete_batch_id', sa.UUID(), nullable=True),
    sa.Column('row_version', sa.Integer(), server_default='1', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('search_vector', postgresql.TSVECTOR(), sa.Computed("to_tsvector('simple', coalesce(name, ''))", persisted=True), nullable=True),
    sa.CheckConstraint("name !~ '[/\\\\]'", name=op.f('ck_documents_name_no_separators')),
    sa.CheckConstraint("status IN ('processing', 'available', 'quarantined', 'failed')", name=op.f('ck_documents_status')),
    sa.CheckConstraint('latest_version_number >= 0', name=op.f('ck_documents_latest_nonneg')),
    sa.CheckConstraint('length(btrim(name)) > 0', name=op.f('ck_documents_name_nonempty')),
    sa.ForeignKeyConstraint(['current_version_id', 'organization_id'], ['dms.document_versions.id', 'dms.document_versions.organization_id'], name='fk_documents_current_version_org', ondelete='RESTRICT', use_alter=True),
    sa.ForeignKeyConstraint(['deleted_by'], ['dms.users.id'], name=op.f('fk_documents_deleted_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['folder_id', 'organization_id'], ['dms.folders.id', 'dms.folders.organization_id'], name='fk_documents_folder_org', ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_documents_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['owner_id'], ['dms.users.id'], name=op.f('fk_documents_owner_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_documents')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_documents_id_org'),
    schema='dms'
    )
    op.create_index('ix_documents_delete_batch', 'documents', ['delete_batch_id'], unique=False, schema='dms', postgresql_where=sa.text('delete_batch_id IS NOT NULL'))
    op.create_index('ix_documents_folder', 'documents', ['organization_id', 'folder_id'], unique=False, schema='dms')
    op.create_index('ix_documents_owner', 'documents', ['organization_id', 'owner_id'], unique=False, schema='dms')
    op.create_index('ix_documents_search', 'documents', ['search_vector'], unique=False, schema='dms', postgresql_using='gin')
    op.create_index('uq_documents_sibling_name', 'documents', ['organization_id', 'folder_id', sa.literal_column('lower(name)')], unique=True, schema='dms', postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_table('group_memberships',
    sa.Column('group_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['group_id', 'organization_id'], ['dms.groups.id', 'dms.groups.organization_id'], name='fk_group_memberships_group_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_group_memberships_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('group_id', 'user_id', name=op.f('pk_group_memberships')),
    schema='dms'
    )
    op.create_index('ix_group_memberships_user_org', 'group_memberships', ['user_id', 'organization_id'], unique=False, schema='dms')
    op.create_table('share_recipients',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('share_grant_id', sa.Uuid(), nullable=False),
    sa.Column('recipient_type', sa.String(length=16), nullable=False),
    sa.Column('recipient_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("recipient_type IN ('user', 'group')", name=op.f('ck_share_recipients_recipient_type')),
    sa.ForeignKeyConstraint(['share_grant_id', 'organization_id'], ['dms.share_grants.id', 'dms.share_grants.organization_id'], name='fk_share_recipients_grant_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_share_recipients')),
    sa.UniqueConstraint('share_grant_id', 'recipient_type', 'recipient_id', name='uq_share_recipients_unique'),
    schema='dms'
    )
    op.create_index('ix_share_recipients_lookup', 'share_recipients', ['organization_id', 'recipient_type', 'recipient_id'], unique=False, schema='dms')
    op.create_table('document_stars',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['document_id', 'organization_id'], ['dms.documents.id', 'dms.documents.organization_id'], name='fk_document_stars_document_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_document_stars_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'document_id', name=op.f('pk_document_stars')),
    schema='dms'
    )
    op.create_table('document_versions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('version_number', sa.Integer(), nullable=False),
    sa.Column('storage_location_id', sa.Uuid(), nullable=False),
    sa.Column('object_key', sa.String(length=512), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('content_type', sa.String(length=255), nullable=False),
    sa.Column('original_filename', sa.String(length=255), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('restored_from_version_id', sa.Uuid(), nullable=True),
    sa.Column('scan_status', sa.String(length=32), nullable=False),
    sa.Column('scan_engine', sa.String(length=100), nullable=True),
    sa.Column('scan_detail', sa.Text(), nullable=True),
    sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("scan_status IN ('pending', 'clean', 'infected', 'error')", name=op.f('ck_document_versions_scan_status')),
    sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_document_versions_sha256_hex')),
    sa.CheckConstraint('size_bytes >= 0', name=op.f('ck_document_versions_size_nonneg')),
    sa.CheckConstraint('version_number >= 1', name=op.f('ck_document_versions_number_positive')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_document_versions_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['document_id', 'organization_id'], ['dms.documents.id', 'dms.documents.organization_id'], name='fk_document_versions_document_org', ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_document_versions_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['restored_from_version_id'], ['dms.document_versions.id'], name=op.f('fk_document_versions_restored_from_version_id_document_versions'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['storage_location_id', 'organization_id'], ['dms.storage_locations.id', 'dms.storage_locations.organization_id'], name='fk_document_versions_location_org', ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_document_versions')),
    sa.UniqueConstraint('document_id', 'version_number', name='uq_document_versions_doc_number'),
    sa.UniqueConstraint('id', 'organization_id', name='uq_document_versions_id_org'),
    sa.UniqueConstraint('storage_location_id', 'object_key', name='uq_document_versions_object'),
    schema='dms'
    )
    op.create_index('ix_document_versions_org_scan', 'document_versions', ['organization_id', 'scan_status'], unique=False, schema='dms')
    op.create_table('recent_documents',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('last_action', sa.String(length=32), nullable=False),
    sa.Column('last_accessed_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['document_id', 'organization_id'], ['dms.documents.id', 'dms.documents.organization_id'], name='fk_recent_documents_document_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_recent_documents_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'document_id', name=op.f('pk_recent_documents')),
    schema='dms'
    )
    op.create_index('ix_recent_user_time', 'recent_documents', ['user_id', 'organization_id', sa.literal_column('last_accessed_at DESC')], unique=False, schema='dms')
    op.create_table('upload_sessions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('folder_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=True),
    sa.Column('expected_latest_version', sa.Integer(), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('content_type', sa.String(length=255), nullable=False),
    sa.Column('declared_size', sa.BigInteger(), nullable=False),
    sa.Column('declared_sha256', sa.String(length=64), nullable=True),
    sa.Column('state', sa.String(length=32), nullable=False),
    sa.Column('storage_location_id', sa.Uuid(), nullable=False),
    sa.Column('object_key', sa.String(length=512), nullable=False),
    sa.Column('received_size', sa.BigInteger(), nullable=True),
    sa.Column('received_sha256', sa.String(length=64), nullable=True),
    sa.Column('reserved_bytes', sa.BigInteger(), nullable=False),
    sa.Column('idempotency_key', sa.String(length=128), nullable=True),
    sa.Column('failure_reason', sa.Text(), nullable=True),
    sa.Column('result_version_id', sa.Uuid(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("state IN ('initiated', 'uploaded', 'finalized', 'failed', 'cancelled', 'expired')", name=op.f('ck_upload_sessions_state')),
    sa.CheckConstraint('declared_size >= 0', name=op.f('ck_upload_sessions_declared_nonneg')),
    sa.CheckConstraint('reserved_bytes >= 0', name=op.f('ck_upload_sessions_reserved_nonneg')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_upload_sessions_created_by_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['document_id', 'organization_id'], ['dms.documents.id', 'dms.documents.organization_id'], name='fk_upload_sessions_document_org', ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['folder_id', 'organization_id'], ['dms.folders.id', 'dms.folders.organization_id'], name='fk_upload_sessions_folder_org', ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_upload_sessions_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['storage_location_id', 'organization_id'], ['dms.storage_locations.id', 'dms.storage_locations.organization_id'], name='fk_upload_sessions_location_org', ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_upload_sessions')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_upload_sessions_id_org'),
    sa.UniqueConstraint('storage_location_id', 'object_key', name='uq_upload_sessions_object'),
    schema='dms'
    )
    op.create_index('ix_upload_sessions_state_expiry', 'upload_sessions', ['state', 'expires_at'], unique=False, schema='dms')
    op.create_index('uq_upload_sessions_idem', 'upload_sessions', ['organization_id', 'created_by', 'idempotency_key'], unique=True, schema='dms', postgresql_where=sa.text('idempotency_key IS NOT NULL'))
    # circular reference (documents <-> document_versions) is added after both tables exist
    op.create_foreign_key(
        'fk_documents_current_version_org',
        'documents',
        'document_versions',
        ['current_version_id', 'organization_id'],
        ['id', 'organization_id'],
        source_schema='dms',
        referent_schema='dms',
        ondelete='RESTRICT',
    )


def downgrade() -> None:
    op.drop_constraint('fk_documents_current_version_org', 'documents', schema='dms', type_='foreignkey')
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('uq_upload_sessions_idem', table_name='upload_sessions', schema='dms', postgresql_where=sa.text('idempotency_key IS NOT NULL'))
    op.drop_index('ix_upload_sessions_state_expiry', table_name='upload_sessions', schema='dms')
    op.drop_table('upload_sessions', schema='dms')
    op.drop_index('ix_recent_user_time', table_name='recent_documents', schema='dms')
    op.drop_table('recent_documents', schema='dms')
    op.drop_index('ix_document_versions_org_scan', table_name='document_versions', schema='dms')
    op.drop_table('document_versions', schema='dms')
    op.drop_table('document_stars', schema='dms')
    op.drop_index('ix_share_recipients_lookup', table_name='share_recipients', schema='dms')
    op.drop_table('share_recipients', schema='dms')
    op.drop_index('ix_group_memberships_user_org', table_name='group_memberships', schema='dms')
    op.drop_table('group_memberships', schema='dms')
    op.drop_index('uq_documents_sibling_name', table_name='documents', schema='dms', postgresql_where=sa.text('deleted_at IS NULL'))
    op.drop_index('ix_documents_search', table_name='documents', schema='dms', postgresql_using='gin')
    op.drop_index('ix_documents_owner', table_name='documents', schema='dms')
    op.drop_index('ix_documents_folder', table_name='documents', schema='dms')
    op.drop_index('ix_documents_delete_batch', table_name='documents', schema='dms', postgresql_where=sa.text('delete_batch_id IS NOT NULL'))
    op.drop_table('documents', schema='dms')
    op.drop_index('uq_storage_locations_default', table_name='storage_locations', schema='dms', postgresql_where=sa.text('is_default'))
    op.drop_table('storage_locations', schema='dms')
    op.drop_index('ix_share_grants_resource', table_name='share_grants', schema='dms')
    op.drop_index('ix_share_grants_creator', table_name='share_grants', schema='dms')
    op.drop_index('ix_share_grants_active_expiry', table_name='share_grants', schema='dms', postgresql_where=sa.text('revoked_at IS NULL'))
    op.drop_table('share_grants', schema='dms')
    op.drop_index('ix_quota_ledger_session', table_name='quota_ledger_entries', schema='dms')
    op.drop_index('ix_quota_ledger_org_created', table_name='quota_ledger_entries', schema='dms')
    op.drop_table('quota_ledger_entries', schema='dms')
    op.drop_index('ix_permission_grants_subject', table_name='permission_grants', schema='dms')
    op.drop_index('ix_permission_grants_resource', table_name='permission_grants', schema='dms')
    op.drop_table('permission_grants', schema='dms')
    op.drop_index('ix_outbox_claimable', table_name='outbox_events', schema='dms', postgresql_where=sa.text("status IN ('pending', 'processing')"))
    op.drop_index('ix_outbox_aggregate', table_name='outbox_events', schema='dms')
    op.drop_table('outbox_events', schema='dms')
    op.drop_index('ix_notifications_user_created', table_name='notifications', schema='dms')
    op.drop_table('notifications', schema='dms')
    op.drop_index('ix_memberships_user', table_name='memberships', schema='dms')
    op.drop_table('memberships', schema='dms')
    op.drop_index('uq_groups_org_name', table_name='groups', schema='dms')
    op.drop_index('uq_groups_org_external', table_name='groups', schema='dms', postgresql_where=sa.text('external_id IS NOT NULL'))
    op.drop_table('groups', schema='dms')
    op.drop_index('uq_folders_sibling_name', table_name='folders', schema='dms', postgresql_where=sa.text('deleted_at IS NULL AND parent_folder_id IS NOT NULL'))
    op.drop_index('uq_folders_one_root', table_name='folders', schema='dms', postgresql_where=sa.text('parent_folder_id IS NULL'))
    op.drop_index('ix_folders_parent', table_name='folders', schema='dms')
    op.drop_index('ix_folders_delete_batch', table_name='folders', schema='dms', postgresql_where=sa.text('delete_batch_id IS NOT NULL'))
    op.drop_table('folders', schema='dms')
    op.drop_index('ix_audit_events_resource', table_name='audit_events', schema='dms')
    op.drop_index('ix_audit_events_org_created', table_name='audit_events', schema='dms')
    op.drop_index('ix_audit_events_org_action', table_name='audit_events', schema='dms')
    op.drop_index('ix_audit_events_actor', table_name='audit_events', schema='dms')
    op.drop_table('audit_events', schema='dms')
    op.drop_index('uq_users_identity', table_name='users', schema='dms', postgresql_where=sa.text('external_subject IS NOT NULL'))
    op.drop_index('uq_users_email', table_name='users', schema='dms')
    op.drop_table('users', schema='dms')
    op.drop_table('processed_events', schema='dms')
    op.drop_table('organizations', schema='dms')
