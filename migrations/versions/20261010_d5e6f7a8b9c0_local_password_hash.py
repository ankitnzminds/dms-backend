"""local development sign-in: optional per-user password hash

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-10-10 03:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'd5e6f7a8b9c0'
down_revision = 'c4d5e6f7a8b9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('local_password_hash', sa.String(length=255), nullable=True), schema='dms')


def downgrade() -> None:
    op.drop_column('users', 'local_password_hash', schema='dms')
