"""approval workflows

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-10-09 14:50:10.590625
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('workflow_definitions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_workflow_definitions_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_workflow_definitions_organization_id_organizations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workflow_definitions')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_workflow_definitions_id_org'),
    schema='dms'
    )
    op.create_index('uq_workflow_definitions_name', 'workflow_definitions', ['organization_id', sa.literal_column('lower(name)')], unique=True, schema='dms')
    op.create_table('workflow_definition_versions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('definition_id', sa.Uuid(), nullable=False),
    sa.Column('version_number', sa.Integer(), nullable=False),
    sa.Column('steps', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("jsonb_typeof(steps) = 'array'", name=op.f('ck_workflow_definition_versions_steps_array')),
    sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_workflow_definition_versions_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['definition_id', 'organization_id'], ['dms.workflow_definitions.id', 'dms.workflow_definitions.organization_id'], name='fk_wf_def_versions_definition_org', ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workflow_definition_versions')),
    sa.UniqueConstraint('definition_id', 'version_number', name='uq_wf_def_versions_number'),
    sa.UniqueConstraint('id', 'organization_id', name='uq_wf_def_versions_id_org'),
    schema='dms'
    )
    op.create_table('workflow_runs',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('definition_version_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('document_version_id', sa.Uuid(), nullable=False),
    sa.Column('started_by', sa.Uuid(), nullable=False),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('current_step', sa.Integer(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('outcome_comment', sa.Text(), nullable=True),
    sa.Column('resubmitted_from_run_id', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("state IN ('in_progress', 'approved', 'rejected', 'cancelled')", name=op.f('ck_workflow_runs_state')),
    sa.ForeignKeyConstraint(['definition_version_id', 'organization_id'], ['dms.workflow_definition_versions.id', 'dms.workflow_definition_versions.organization_id'], name='fk_workflow_runs_def_version_org', ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['document_id', 'organization_id'], ['dms.documents.id', 'dms.documents.organization_id'], name='fk_workflow_runs_document_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['document_version_id', 'organization_id'], ['dms.document_versions.id', 'dms.document_versions.organization_id'], name='fk_workflow_runs_version_org', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_workflow_runs_organization_id_organizations'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['resubmitted_from_run_id'], ['dms.workflow_runs.id'], name=op.f('fk_workflow_runs_resubmitted_from_run_id_workflow_runs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['started_by'], ['dms.users.id'], name=op.f('fk_workflow_runs_started_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workflow_runs')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_workflow_runs_id_org'),
    schema='dms'
    )
    op.create_index('ix_workflow_runs_org_state', 'workflow_runs', ['organization_id', 'state'], unique=False, schema='dms')
    op.create_index('uq_workflow_runs_active_document', 'workflow_runs', ['document_id'], unique=True, schema='dms', postgresql_where=sa.text("state = 'in_progress'"))
    op.create_table('approval_actions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('run_id', sa.Uuid(), nullable=False),
    sa.Column('task_id', sa.Uuid(), nullable=True),
    sa.Column('action', sa.String(length=32), nullable=False),
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['dms.users.id'], name=op.f('fk_approval_actions_actor_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['run_id', 'organization_id'], ['dms.workflow_runs.id', 'dms.workflow_runs.organization_id'], name='fk_approval_actions_run_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_approval_actions')),
    schema='dms'
    )
    op.create_index('ix_approval_actions_run', 'approval_actions', ['run_id', 'created_at'], unique=False, schema='dms')
    op.create_table('workflow_tasks',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('run_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('step_index', sa.Integer(), nullable=False),
    sa.Column('step_name', sa.String(length=200), nullable=False),
    sa.Column('rule', sa.String(length=8), nullable=False),
    sa.Column('assignee_id', sa.Uuid(), nullable=False),
    sa.Column('delegated_from_id', sa.Uuid(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('decided_by', sa.Uuid(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('due_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('overdue_notified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('escalate_to_id', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("rule IN ('all', 'any')", name=op.f('ck_workflow_tasks_rule')),
    sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'cancelled', 'skipped')", name=op.f('ck_workflow_tasks_status')),
    sa.ForeignKeyConstraint(['assignee_id'], ['dms.users.id'], name=op.f('fk_workflow_tasks_assignee_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['decided_by'], ['dms.users.id'], name=op.f('fk_workflow_tasks_decided_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['delegated_from_id'], ['dms.users.id'], name=op.f('fk_workflow_tasks_delegated_from_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['escalate_to_id'], ['dms.users.id'], name=op.f('fk_workflow_tasks_escalate_to_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['run_id', 'organization_id'], ['dms.workflow_runs.id', 'dms.workflow_runs.organization_id'], name='fk_workflow_tasks_run_org', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workflow_tasks')),
    sa.UniqueConstraint('id', 'organization_id', name='uq_workflow_tasks_id_org'),
    schema='dms'
    )
    op.create_index('ix_workflow_tasks_assignee_pending', 'workflow_tasks', ['organization_id', 'assignee_id'], unique=False, schema='dms', postgresql_where=sa.text("status = 'pending'"))
    op.create_index('ix_workflow_tasks_due', 'workflow_tasks', ['due_at'], unique=False, schema='dms', postgresql_where=sa.text("status = 'pending'"))
    op.create_index('ix_workflow_tasks_run', 'workflow_tasks', ['run_id', 'step_index'], unique=False, schema='dms')
    for table in (
        "workflow_definitions",
        "workflow_definition_versions",
        "workflow_runs",
        "workflow_tasks",
        "approval_actions",
    ):
        op.execute(f"ALTER TABLE dms.{table} ENABLE ROW LEVEL SECURITY")
    # approval history is append-only (same guard as the audit trail)
    op.execute(
        """
        CREATE TRIGGER approval_actions_append_only
          BEFORE UPDATE OR DELETE ON dms.approval_actions
          FOR EACH ROW WHEN (pg_trigger_depth() = 0)
          EXECUTE FUNCTION dms.forbid_modification();
        """
    )


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.drop_index('ix_workflow_tasks_run', table_name='workflow_tasks', schema='dms')
    op.drop_index('ix_workflow_tasks_due', table_name='workflow_tasks', schema='dms', postgresql_where=sa.text("status = 'pending'"))
    op.drop_index('ix_workflow_tasks_assignee_pending', table_name='workflow_tasks', schema='dms', postgresql_where=sa.text("status = 'pending'"))
    op.drop_table('workflow_tasks', schema='dms')
    op.drop_index('ix_approval_actions_run', table_name='approval_actions', schema='dms')
    op.drop_table('approval_actions', schema='dms')
    op.drop_index('uq_workflow_runs_active_document', table_name='workflow_runs', schema='dms', postgresql_where=sa.text("state = 'in_progress'"))
    op.drop_index('ix_workflow_runs_org_state', table_name='workflow_runs', schema='dms')
    op.drop_table('workflow_runs', schema='dms')
    op.drop_table('workflow_definition_versions', schema='dms')
    op.drop_index('uq_workflow_definitions_name', table_name='workflow_definitions', schema='dms')
    op.drop_table('workflow_definitions', schema='dms')
