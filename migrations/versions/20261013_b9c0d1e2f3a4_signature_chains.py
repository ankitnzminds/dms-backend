"""signature chains: per-folder chain steps and chain fields on recipients (additive)

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-10-13 00:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'b9c0d1e2f3a4'
down_revision = 'a8b9c0d1e2f3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'signature_chain_steps',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('folder_id', sa.Uuid(), nullable=False),
        sa.Column('level', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('optional', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('is_super_signer', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('created_by', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('level >= 1', name=op.f('ck_signature_chain_steps_level_positive')),
        sa.ForeignKeyConstraint(['folder_id', 'organization_id'], ['dms.folders.id', 'dms.folders.organization_id'], name='fk_signature_chain_steps_folder_org', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_signature_chain_steps_user_id_users'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_signature_chain_steps_created_by_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_signature_chain_steps')),
        sa.UniqueConstraint('folder_id', 'level', 'user_id', name='uq_signature_chain_steps_signer'),
        schema='dms',
    )
    op.create_index('ix_signature_chain_steps_folder', 'signature_chain_steps', ['organization_id', 'folder_id', 'level'], schema='dms')
    op.execute("ALTER TABLE dms.signature_chain_steps ENABLE ROW LEVEL SECURITY")

    op.add_column('signature_recipients', sa.Column('level', sa.Integer(), server_default='1', nullable=False), schema='dms')
    op.add_column('signature_recipients', sa.Column('optional', sa.Boolean(), server_default='false', nullable=False), schema='dms')
    op.add_column('signature_recipients', sa.Column('is_super_signer', sa.Boolean(), server_default='false', nullable=False), schema='dms')
    # two more recipient outcomes (existing rows keep their values)
    op.drop_constraint(op.f('ck_signature_recipients_status'), 'signature_recipients', schema='dms', type_='check')
    op.create_check_constraint(
        op.f('ck_signature_recipients_status'),
        'signature_recipients',
        "status IN ('pending', 'signed', 'declined', 'cancelled', 'bypassed')",
        schema='dms',
    )


def downgrade() -> None:
    # rows already 'cancelled'/'bypassed' would violate the old constraint: map them back first
    op.execute("UPDATE dms.signature_recipients SET status = 'declined' WHERE status IN ('cancelled', 'bypassed')")
    op.drop_constraint(op.f('ck_signature_recipients_status'), 'signature_recipients', schema='dms', type_='check')
    op.create_check_constraint(
        op.f('ck_signature_recipients_status'),
        'signature_recipients',
        "status IN ('pending', 'signed', 'declined')",
        schema='dms',
    )
    op.drop_column('signature_recipients', 'is_super_signer', schema='dms')
    op.drop_column('signature_recipients', 'optional', schema='dms')
    op.drop_column('signature_recipients', 'level', schema='dms')
    op.drop_index('ix_signature_chain_steps_folder', table_name='signature_chain_steps', schema='dms')
    op.drop_table('signature_chain_steps', schema='dms')
