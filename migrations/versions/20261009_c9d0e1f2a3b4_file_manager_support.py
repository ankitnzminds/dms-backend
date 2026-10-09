"""file manager support

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-10-09 15:53:28.914667
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'c9d0e1f2a3b4'
down_revision = 'b8c9d0e1f2a3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('user_preferences',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("key ~ '^[a-z][a-z0-9_.-]{0,63}$'", name=op.f('ck_user_preferences_key_format')),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_user_preferences_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_user_preferences_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'organization_id', 'key', name=op.f('pk_user_preferences')),
    schema='dms'
    )
    op.create_table('folder_favorites',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('folder_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['folder_id', 'organization_id'], ['dms.folders.id', 'dms.folders.organization_id'], name='fk_folder_favorites_folder_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_folder_favorites_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'folder_id', name=op.f('pk_folder_favorites')),
    schema='dms'
    )
    op.add_column('documents', sa.Column('updated_by', sa.Uuid(), nullable=True), schema='dms')
    op.add_column('documents', sa.Column('locked_by', sa.Uuid(), nullable=True), schema='dms')
    op.add_column('documents', sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True), schema='dms')
    op.add_column('documents', sa.Column('lock_expires_at', sa.DateTime(timezone=True), nullable=True), schema='dms')
    op.create_foreign_key(op.f('fk_documents_locked_by_users'), 'documents', 'users', ['locked_by'], ['id'], source_schema='dms', referent_schema='dms', ondelete='SET NULL')
    op.create_foreign_key(op.f('fk_documents_updated_by_users'), 'documents', 'users', ['updated_by'], ['id'], source_schema='dms', referent_schema='dms', ondelete='SET NULL')
    op.add_column('folders', sa.Column('updated_by', sa.Uuid(), nullable=True), schema='dms')
    op.create_foreign_key(op.f('fk_folders_updated_by_users'), 'folders', 'users', ['updated_by'], ['id'], source_schema='dms', referent_schema='dms', ondelete='SET NULL')
    for table in ("folder_favorites", "user_preferences"):
        op.execute(f"ALTER TABLE dms.{table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.drop_constraint(op.f('fk_folders_updated_by_users'), 'folders', schema='dms', type_='foreignkey')
    op.drop_column('folders', 'updated_by', schema='dms')
    op.drop_constraint(op.f('fk_documents_updated_by_users'), 'documents', schema='dms', type_='foreignkey')
    op.drop_constraint(op.f('fk_documents_locked_by_users'), 'documents', schema='dms', type_='foreignkey')
    op.drop_column('documents', 'lock_expires_at', schema='dms')
    op.drop_column('documents', 'locked_at', schema='dms')
    op.drop_column('documents', 'locked_by', schema='dms')
    op.drop_column('documents', 'updated_by', schema='dms')
    op.drop_table('folder_favorites', schema='dms')
    op.drop_table('user_preferences', schema='dms')
