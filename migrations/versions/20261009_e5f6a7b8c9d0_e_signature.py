"""e-signature

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-10-09 15:01:26.291287
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('signature_events',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('provider_event_id', sa.String(length=200), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=True),
    sa.Column('request_id', sa.Uuid(), nullable=True),
    sa.Column('provider_request_id', sa.String(length=200), nullable=True),
    sa.Column('event_type', sa.String(length=80), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('error', sa.String(length=300), nullable=True),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status IN ('received', 'processed', 'ignored', 'failed')", name=op.f('ck_signature_events_status')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_signature_events')),
    sa.UniqueConstraint('provider', 'provider_event_id', name='uq_signature_events_dedupe'),
    schema='dms'
    )
    op.create_index('ix_signature_events_request', 'signature_events', ['request_id', 'received_at'], unique=False, schema='dms')
    op.create_table('signature_requests',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('source_version_id', sa.Uuid(), nullable=False),
    sa.Column('requested_by', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('provider_request_id', sa.String(length=200), nullable=True),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('failure_reason', sa.String(length=300), nullable=True),
    sa.Column('last_reconciled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("state IN ('creating', 'sent', 'completed', 'declined', 'cancelled', 'expired', 'failed')", name=op.f('ck_signature_requests_state')),
    sa.ForeignKeyConstraint(['document_id', 'organization_id'], ['dms.documents.id', 'dms.documents.organization_id'], name='fk_signature_requests_document_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_signature_requests_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['requested_by'], ['dms.users.id'], name=op.f('fk_signature_requests_requested_by_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['source_version_id', 'organization_id'], ['dms.document_versions.id', 'dms.document_versions.organization_id'], name='fk_signature_requests_version_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_signature_requests')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_signature_requests_id_org'),
    schema='dms'
    )
    op.create_index('ix_signature_requests_document', 'signature_requests', ['organization_id', 'document_id'], unique=False, schema='dms')
    op.create_index('ix_signature_requests_org_state', 'signature_requests', ['organization_id', 'state'], unique=False, schema='dms')
    op.create_index('uq_signature_requests_provider_id', 'signature_requests', ['provider', 'provider_request_id'], unique=True, schema='dms', postgresql_where=sa.text('provider_request_id IS NOT NULL'))
    op.create_table('signature_recipients',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('request_id', sa.Uuid(), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('order_index', sa.Integer(), nullable=False),
    sa.Column('provider_recipient_id', sa.String(length=200), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('signed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'signed', 'declined')", name=op.f('ck_signature_recipients_status')),
    sa.ForeignKeyConstraint(['request_id', 'organization_id'], ['dms.signature_requests.id', 'dms.signature_requests.organization_id'], name='fk_signature_recipients_request_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_signature_recipients_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_signature_recipients')),
    sa.UniqueConstraint('request_id', 'email', name='uq_signature_recipients_email'),
    schema='dms'
    )
    op.create_table('signed_artifacts',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('request_id', sa.Uuid(), nullable=False),
    sa.Column('version_id', sa.Uuid(), nullable=False),
    sa.Column('source_version_id', sa.Uuid(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['request_id', 'organization_id'], ['dms.signature_requests.id', 'dms.signature_requests.organization_id'], name='fk_signed_artifacts_request_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['version_id', 'organization_id'], ['dms.document_versions.id', 'dms.document_versions.organization_id'], name='fk_signed_artifacts_version_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_signed_artifacts')),
    sa.UniqueConstraint('request_id', name='uq_signed_artifacts_request'),
    schema='dms'
    )
    for table in ("signature_requests", "signature_recipients", "signature_events", "signed_artifacts"):
        op.execute(f"ALTER TABLE dms.{table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.drop_table('signed_artifacts', schema='dms')
    op.drop_table('signature_recipients', schema='dms')
    op.drop_index('uq_signature_requests_provider_id', table_name='signature_requests', schema='dms', postgresql_where=sa.text('provider_request_id IS NOT NULL'))
    op.drop_index('ix_signature_requests_org_state', table_name='signature_requests', schema='dms')
    op.drop_index('ix_signature_requests_document', table_name='signature_requests', schema='dms')
    op.drop_table('signature_requests', schema='dms')
    op.drop_index('ix_signature_events_request', table_name='signature_events', schema='dms')
    op.drop_table('signature_events', schema='dms')
