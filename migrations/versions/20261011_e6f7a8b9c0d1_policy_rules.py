"""policy engine: rule policies and immutable revisions (additive)

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-10-11 00:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = 'e6f7a8b9c0d1'
down_revision = 'd5e6f7a8b9c0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'policy_rules',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=40), server_default='custom', nullable=False),
        sa.Column('owner_kind', sa.String(length=16), server_default='organization', nullable=False),
        sa.Column('owner_user_id', sa.Uuid(), nullable=True),
        sa.Column('status', sa.String(length=16), server_default='draft', nullable=False),
        sa.Column('mode', sa.String(length=16), server_default='enforce', nullable=False),
        sa.Column('mandatory', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('published_revision_id', sa.Uuid(), nullable=True),
        sa.Column('template_key', sa.String(length=60), nullable=True),
        sa.Column('created_by', sa.Uuid(), nullable=True),
        sa.Column('updated_by', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("status IN ('draft', 'published', 'disabled', 'archived')", name=op.f('ck_policy_rules_status')),
        sa.CheckConstraint("mode IN ('enforce', 'observe')", name=op.f('ck_policy_rules_mode')),
        sa.CheckConstraint("owner_kind IN ('organization', 'user')", name=op.f('ck_policy_rules_owner_kind')),
        sa.ForeignKeyConstraint(['organization_id'], ['dms.organizations.id'], name=op.f('fk_policy_rules_organization_id_organizations'), ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['owner_user_id'], ['dms.users.id'], name=op.f('fk_policy_rules_owner_user_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_policy_rules_created_by_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['updated_by'], ['dms.users.id'], name=op.f('fk_policy_rules_updated_by_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_policy_rules')),
        sa.UniqueConstraint('id', 'organization_id', name='uq_policy_rules_id_org'),
        schema='dms',
    )
    op.create_index('ix_policy_rules_org_status', 'policy_rules', ['organization_id', 'status'], schema='dms')

    op.create_table(
        'policy_revisions',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('policy_id', sa.Uuid(), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('document', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('status', sa.String(length=16), server_default='draft', nullable=False),
        sa.Column('change_reason', sa.String(length=500), nullable=True),
        sa.Column('created_by', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('validated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('published_by', sa.Uuid(), nullable=True),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('draft', 'validated', 'published', 'superseded')", name=op.f('ck_policy_revisions_status')),
        sa.ForeignKeyConstraint(['policy_id', 'organization_id'], ['dms.policy_rules.id', 'dms.policy_rules.organization_id'], name='fk_policy_revisions_policy_org', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['created_by'], ['dms.users.id'], name=op.f('fk_policy_revisions_created_by_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['published_by'], ['dms.users.id'], name=op.f('fk_policy_revisions_published_by_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_policy_revisions')),
        sa.UniqueConstraint('policy_id', 'revision', name='uq_policy_revisions_policy_revision'),
        schema='dms',
    )
    op.create_index('ix_policy_revisions_org_policy', 'policy_revisions', ['organization_id', 'policy_id'], schema='dms')

    # Published and superseded revisions can never change content or be deleted (audit-grade history).
    op.execute(
        """
        CREATE FUNCTION dms.protect_policy_revision() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            IF OLD.status IN ('published', 'superseded') THEN
              RAISE EXCEPTION 'published policy revisions cannot be deleted'
                USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN OLD;
          END IF;
          IF OLD.status IN ('published', 'superseded') AND (
               NEW.document IS DISTINCT FROM OLD.document
            OR NEW.revision <> OLD.revision
            OR NEW.policy_id <> OLD.policy_id
            OR NEW.organization_id <> OLD.organization_id
          ) THEN
            RAISE EXCEPTION 'published policy revisions are immutable'
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER policy_revisions_immutable
          BEFORE UPDATE OR DELETE ON dms.policy_revisions
          FOR EACH ROW EXECUTE FUNCTION dms.protect_policy_revision();
        """
    )
    for t in ('policy_rules', 'policy_revisions'):
        op.execute(f"ALTER TABLE dms.{t} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Destructive downgrades are not safe on data-bearing environments; prefer a forward fix.
    op.execute("DROP TRIGGER IF EXISTS policy_revisions_immutable ON dms.policy_revisions")
    op.execute("DROP FUNCTION IF EXISTS dms.protect_policy_revision()")
    op.drop_index('ix_policy_revisions_org_policy', table_name='policy_revisions', schema='dms')
    op.drop_table('policy_revisions', schema='dms')
    op.drop_index('ix_policy_rules_org_status', table_name='policy_rules', schema='dms')
    op.drop_table('policy_rules', schema='dms')
