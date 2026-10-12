"""folder locks and lock download prevention

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-10-10 00:30:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'a2b3c4d5e6f7'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Folders get the same cooperative lock documents already have.
    op.add_column('folders', sa.Column('locked_by', sa.Uuid(), nullable=True), schema='dms')
    op.add_column('folders', sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True), schema='dms')
    op.add_column('folders', sa.Column('lock_expires_at', sa.DateTime(timezone=True), nullable=True), schema='dms')
    op.add_column(
        'folders',
        sa.Column('lock_prevents_download', sa.Boolean(), server_default='false', nullable=False),
        schema='dms',
    )
    op.create_foreign_key(
        op.f('fk_folders_locked_by_users'), 'folders', 'users', ['locked_by'], ['id'],
        source_schema='dms', referent_schema='dms', ondelete='SET NULL',
    )
    # "Prevent others from downloading while locked" applies to documents too.
    op.add_column(
        'documents',
        sa.Column('lock_prevents_download', sa.Boolean(), server_default='false', nullable=False),
        schema='dms',
    )


def downgrade() -> None:
    op.drop_column('documents', 'lock_prevents_download', schema='dms')
    op.drop_constraint(op.f('fk_folders_locked_by_users'), 'folders', schema='dms', type_='foreignkey')
    op.drop_column('folders', 'lock_prevents_download', schema='dms')
    op.drop_column('folders', 'lock_expires_at', schema='dms')
    op.drop_column('folders', 'locked_at', schema='dms')
    op.drop_column('folders', 'locked_by', schema='dms')
