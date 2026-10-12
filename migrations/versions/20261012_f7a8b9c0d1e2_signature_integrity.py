"""e-signature: source checksum on requests and one active request per document (additive)

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-10-12 00:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'f7a8b9c0d1e2'
down_revision = 'e6f7a8b9c0d1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('signature_requests', sa.Column('source_sha256', sa.String(length=64), nullable=True), schema='dms')
    # Backfill from the immutable source version (no data is altered otherwise).
    op.execute(
        """
        UPDATE dms.signature_requests r
           SET source_sha256 = v.sha256
          FROM dms.document_versions v
         WHERE v.id = r.source_version_id AND v.organization_id = r.organization_id
           AND r.source_sha256 IS NULL
        """
    )
    # The unique index cannot be built while a document has several in-flight requests. Never resolve
    # that automatically (cancelling a signing request is a business decision): stop with instructions.
    dupes = op.get_bind().execute(
        sa.text(
            """
            SELECT count(*) FROM (
              SELECT 1 FROM dms.signature_requests
               WHERE state IN ('creating', 'sent')
               GROUP BY organization_id, document_id HAVING count(*) > 1
            ) d
            """
        )
    ).scalar()
    if dupes:
        raise RuntimeError(
            f"{dupes} document(s) have more than one in-flight signature request. Cancel the extra "
            "requests (state creating/sent) and run the migration again. Nothing was changed by this migration."
        )
    op.create_index(
        'uq_signature_requests_one_active',
        'signature_requests',
        ['organization_id', 'document_id'],
        unique=True,
        schema='dms',
        postgresql_where=sa.text("state IN ('creating', 'sent')"),
    )


def downgrade() -> None:
    op.drop_index('uq_signature_requests_one_active', table_name='signature_requests', schema='dms')
    op.drop_column('signature_requests', 'source_sha256', schema='dms')
