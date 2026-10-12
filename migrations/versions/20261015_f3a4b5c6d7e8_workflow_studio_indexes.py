"""workflow studio: indexed lookups for the user-side run lists and approval wake-ups (additive)

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-10-15 12:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = 'f3a4b5c6d7e8'
down_revision = 'e2f3a4b5c6d7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('automation_runs', sa.Column('resource_id', sa.Uuid(), nullable=True), schema='dms')
    op.add_column('automation_runs', sa.Column('starter_id', sa.Uuid(), nullable=True), schema='dms')
    # existing runs: copy the item and the person out of the stored trigger context
    op.execute(
        """
        UPDATE dms.automation_runs
           SET resource_id = (trigger_context->'resource'->>'id')::uuid
         WHERE trigger_context->'resource'->>'id' ~ '^[0-9a-fA-F-]{36}$'
        """
    )
    op.execute(
        """
        UPDATE dms.automation_runs
           SET starter_id = (trigger_context->>'actor_id')::uuid
         WHERE trigger_context->>'actor_id' ~ '^[0-9a-fA-F-]{36}$'
        """
    )
    op.create_index(
        'ix_automation_runs_resource',
        'automation_runs',
        ['organization_id', 'resource_id', sa.text('created_at DESC')],
        schema='dms',
    )
    op.create_index(
        'ix_automation_runs_starter',
        'automation_runs',
        ['organization_id', 'starter_id', sa.text('created_at DESC')],
        schema='dms',
        postgresql_where=sa.text("mode = 'live'"),
    )
    op.create_index(
        'ix_automation_node_runs_waiting',
        'automation_node_runs',
        ['organization_id', sa.text("(output->>'approval_run_id')")],
        schema='dms',
        postgresql_where=sa.text("status = 'waiting'"),
    )


def downgrade() -> None:
    op.drop_index('ix_automation_node_runs_waiting', table_name='automation_node_runs', schema='dms')
    op.drop_index('ix_automation_runs_starter', table_name='automation_runs', schema='dms')
    op.drop_index('ix_automation_runs_resource', table_name='automation_runs', schema='dms')
    op.drop_column('automation_runs', 'starter_id', schema='dms')
    op.drop_column('automation_runs', 'resource_id', schema='dms')
