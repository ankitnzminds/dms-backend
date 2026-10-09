"""processing metadata and search

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-10-09 14:40:30.845298
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('metadata_definitions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('label', sa.String(length=200), nullable=False),
    sa.Column('field_type', sa.String(length=16), nullable=False),
    sa.Column('required', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('options', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('schema_version', sa.Integer(), server_default='1', nullable=False),
    sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("field_type IN ('text', 'number', 'date', 'boolean', 'select')", name=op.f('ck_metadata_definitions_type')),
    sa.CheckConstraint("key ~ '^[a-z][a-z0-9_]{0,63}$'", name=op.f('ck_metadata_definitions_key_format')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_metadata_definitions_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_metadata_definitions_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_metadata_definitions')),
    sa.UniqueConstraint('organization_id', 'key', name='uq_metadata_definitions_key'),
    schema='dms'
    )
    op.create_index('ix_metadata_definitions_org', 'metadata_definitions', ['organization_id', sa.literal_column('archived_at NULLS FIRST')], unique=False, schema='dms')
    op.create_table('document_derivatives',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('version_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=24), nullable=False),
    sa.Column('storage_location_id', sa.Uuid(), nullable=False),
    sa.Column('object_key', sa.String(length=512), nullable=False),
    sa.Column('content_type', sa.String(length=100), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("kind IN ('thumbnail')", name=op.f('ck_document_derivatives_kind')),
    sa.ForeignKeyConstraint(['version_id', 'organization_id'], ['dms.document_versions.id', 'dms.document_versions.organization_id'], name='fk_document_derivatives_version_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_document_derivatives')),
    sa.UniqueConstraint('version_id', 'kind', name='uq_document_derivatives_kind'),
    schema='dms'
    )
    op.create_table('document_texts',
    sa.Column('version_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('engine', sa.String(length=50), nullable=True),
    sa.Column('char_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('truncated', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('text', sa.Text(), nullable=True),
    sa.Column('error', sa.String(length=300), nullable=True),
    sa.Column('extracted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('search_vector', postgresql.TSVECTOR(), sa.Computed("to_tsvector('simple', left(coalesce(text, ''), 1000000))", persisted=True), nullable=True),
    sa.CheckConstraint("status IN ('extracted', 'empty', 'unsupported', 'failed', 'ocr_unavailable')", name=op.f('ck_document_texts_status')),
    sa.ForeignKeyConstraint(['version_id', 'organization_id'], ['dms.document_versions.id', 'dms.document_versions.organization_id'], name='fk_document_texts_version_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('version_id', name=op.f('pk_document_texts')),
    schema='dms'
    )
    op.create_index('ix_document_texts_document', 'document_texts', ['organization_id', 'document_id'], unique=False, schema='dms')
    op.create_index('ix_document_texts_search', 'document_texts', ['search_vector'], unique=False, schema='dms', postgresql_using='gin')
    for table in ("document_texts", "document_derivatives", "metadata_definitions"):
        op.execute(f"ALTER TABLE dms.{table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.drop_index('ix_document_texts_search', table_name='document_texts', schema='dms', postgresql_using='gin')
    op.drop_index('ix_document_texts_document', table_name='document_texts', schema='dms')
    op.drop_table('document_texts', schema='dms')
    op.drop_table('document_derivatives', schema='dms')
    op.drop_index('ix_metadata_definitions_org', table_name='metadata_definitions', schema='dms')
    op.drop_table('metadata_definitions', schema='dms')
