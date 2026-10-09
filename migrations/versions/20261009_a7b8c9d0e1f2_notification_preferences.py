"""notification preferences

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-10-09 15:16:00.901544
"""
from alembic import op
import sqlalchemy as sa


revision = 'a7b8c9d0e1f2'
down_revision = 'f6a7b8c9d0e1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('notification_preferences',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('group', sa.String(length=24), nullable=False),
    sa.Column('in_app', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('email', sa.Boolean(), server_default='true', nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_notification_preferences_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['dms.users.id'], name=op.f('fk_notification_preferences_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'organization_id', 'group', name=op.f('pk_notification_preferences')),
    schema='dms'
    )
    op.execute("ALTER TABLE dms.notification_preferences ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.drop_table('notification_preferences', schema='dms')
