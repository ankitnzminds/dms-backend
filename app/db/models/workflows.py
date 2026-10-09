"""Approval workflows: versioned definitions, runs over an exact document version, tasks, actions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk

RUN_STATES = ["in_progress", "approved", "rejected", "cancelled"]
TASK_STATES = ["pending", "approved", "rejected", "cancelled", "skipped"]


class WorkflowDefinition(Base):
    __tablename__ = "workflow_definitions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_workflow_definitions_id_org"),
        Index("uq_workflow_definitions_name", "organization_id", func.lower(name), unique=True),
    )


class WorkflowDefinitionVersion(Base):
    """Immutable snapshot of the steps. Runs reference a version, never the mutable definition."""

    __tablename__ = "workflow_definition_versions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    definition_id: Mapped[uuid.UUID] = mapped_column()
    version_number: Mapped[int] = mapped_column(Integer)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["definition_id", "organization_id"],
            ["dms.workflow_definitions.id", "dms.workflow_definitions.organization_id"],
            ondelete="RESTRICT",
            name="fk_wf_def_versions_definition_org",
        ),
        UniqueConstraint("id", "organization_id", name="uq_wf_def_versions_id_org"),
        UniqueConstraint("definition_id", "version_number", name="uq_wf_def_versions_number"),
        CheckConstraint("jsonb_typeof(steps) = 'array'", name="steps_array"),
    )


class WorkflowRun(Base):
    __tablename__ = "workflow_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    definition_version_id: Mapped[uuid.UUID] = mapped_column()
    document_id: Mapped[uuid.UUID] = mapped_column()
    # the exact immutable content under review - later versions do not affect this run
    document_version_id: Mapped[uuid.UUID] = mapped_column()
    started_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="RESTRICT"))
    state: Mapped[str] = mapped_column(String(16), default="in_progress")
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str | None] = mapped_column(Text)
    outcome_comment: Mapped[str | None] = mapped_column(Text)
    resubmitted_from_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.workflow_runs.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_workflow_runs_id_org"),
        ForeignKeyConstraint(
            ["definition_version_id", "organization_id"],
            [
                "dms.workflow_definition_versions.id",
                "dms.workflow_definition_versions.organization_id",
            ],
            ondelete="RESTRICT",
            name="fk_workflow_runs_def_version_org",
        ),
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="CASCADE",
            name="fk_workflow_runs_document_org",
        ),
        ForeignKeyConstraint(
            ["document_version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="CASCADE",
            name="fk_workflow_runs_version_org",
        ),
        CheckConstraint(check_in("state", RUN_STATES, "state"), name="state"),
        # at most one active run per document
        Index(
            "uq_workflow_runs_active_document",
            "document_id",
            unique=True,
            postgresql_where=text("state = 'in_progress'"),
        ),
        Index("ix_workflow_runs_org_state", "organization_id", "state"),
    )


class WorkflowTask(Base):
    __tablename__ = "workflow_tasks"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    run_id: Mapped[uuid.UUID] = mapped_column()
    document_id: Mapped[uuid.UUID] = mapped_column()  # denormalized for access checks
    step_index: Mapped[int] = mapped_column(Integer)
    step_name: Mapped[str] = mapped_column(String(200))
    rule: Mapped[str] = mapped_column(String(8))  # all | any
    assignee_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="RESTRICT"))
    delegated_from_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(16), default="pending")
    decided_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    comment: Mapped[str | None] = mapped_column(Text)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    overdue_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    escalate_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_workflow_tasks_id_org"),
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["dms.workflow_runs.id", "dms.workflow_runs.organization_id"],
            ondelete="CASCADE",
            name="fk_workflow_tasks_run_org",
        ),
        CheckConstraint(check_in("status", TASK_STATES, "status"), name="status"),
        CheckConstraint(check_in("rule", ["all", "any"], "rule"), name="rule"),
        Index(
            "ix_workflow_tasks_assignee_pending",
            "organization_id",
            "assignee_id",
            postgresql_where=text("status = 'pending'"),
        ),
        Index("ix_workflow_tasks_run", "run_id", "step_index"),
        Index("ix_workflow_tasks_due", "due_at", postgresql_where=text("status = 'pending'")),
    )


class ApprovalAction(Base):
    """Append-only history of everything that happened in a run (separate from audit_events so
    it can be shown to participants; mirrored into the audit trail)."""

    __tablename__ = "approval_actions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    run_id: Mapped[uuid.UUID] = mapped_column()
    task_id: Mapped[uuid.UUID | None] = mapped_column()
    action: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    comment: Mapped[str | None] = mapped_column(Text)
    action_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["dms.workflow_runs.id", "dms.workflow_runs.organization_id"],
            ondelete="CASCADE",
            name="fk_approval_actions_run_org",
        ),
        Index("ix_approval_actions_run", "run_id", "created_at"),
    )
