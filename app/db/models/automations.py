"""Automation workflows (IF this THEN that): drafts, immutable published versions, durable runs.

Both authoring experiences (the admin wizard and the visual canvas) produce the same definition:
a trigger plus a small directed graph of typed nodes. Runs reference an immutable version.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
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

AUTOMATION_STATUSES = ["draft", "published", "archived"]
RUN_STATUSES = ["queued", "running", "waiting", "succeeded", "failed", "cancelled", "skipped"]
NODE_STATUSES = ["pending", "running", "waiting", "succeeded", "failed", "skipped"]


class Automation(Base):
    __tablename__ = "automations"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="draft", server_default="draft")
    # Only a published automation can be enabled; enabling is a separate, explicit act.
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    editor_mode: Mapped[str] = mapped_column(String(16), default="wizard", server_default="wizard")
    # The editable draft. Publishing snapshots it into automation_versions.
    draft_trigger: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    draft_graph: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    published_version_id: Mapped[uuid.UUID | None] = mapped_column()
    # When several workflows match the same event: additive ones all run; among the exclusive ones
    # only the most specific scope runs (priority breaks ties).
    binding_mode: Mapped[str] = mapped_column(
        String(16), default="additive", server_default="additive"
    )
    priority: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    row_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    # Real evaluation bookkeeping (never fabricated): when it last looked, and what last ran.
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_status: Mapped[str | None] = mapped_column(String(16))
    last_run_summary: Mapped[str | None] = mapped_column(String(300))
    attention_reason: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_automations_id_org"),
        Index("uq_automations_name", "organization_id", func.lower(name), unique=True),
        CheckConstraint(check_in("status", AUTOMATION_STATUSES, "status"), name="status"),
        CheckConstraint(
            check_in("binding_mode", ["additive", "exclusive"], "bm"), name="binding_mode"
        ),
        CheckConstraint("NOT enabled OR status = 'published'", name="enabled_requires_published"),
        Index("ix_automations_due", "organization_id", "enabled", "next_check_at"),
    )


class AutomationVersion(Base):
    """Immutable published snapshot. Runs always reference one of these."""

    __tablename__ = "automation_versions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    automation_id: Mapped[uuid.UUID] = mapped_column()
    version_number: Mapped[int] = mapped_column(Integer)
    schema_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    trigger: Mapped[dict[str, Any]] = mapped_column(JSONB)
    graph: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # Whoever publishes owns the execution identity: every run re-authorizes AS this user.
    published_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    high_risk_confirmed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    # {node id: approval workflow definition id} for the Human approval steps, generated at publish.
    approval_definitions: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["automation_id", "organization_id"],
            ["dms.automations.id", "dms.automations.organization_id"],
            ondelete="RESTRICT",
            name="fk_automation_versions_automation_org",
        ),
        UniqueConstraint("id", "organization_id", name="uq_automation_versions_id_org"),
        UniqueConstraint("automation_id", "version_number", name="uq_automation_versions_number"),
    )


class AutomationRun(Base):
    __tablename__ = "automation_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    automation_id: Mapped[uuid.UUID] = mapped_column()
    version_id: Mapped[uuid.UUID] = mapped_column()
    # Idempotency: one run per (automation, event). Redelivered events never start a second run.
    event_key: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default="queued", server_default="queued")
    mode: Mapped[str] = mapped_column(String(8), default="live", server_default="live")
    trigger_context: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    variables: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    # Dry runs execute an in-memory copy of the DRAFT (never a stored version): {trigger, graph, as_user}
    snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(String(500))
    # the item the run is about and who set it off, copied out of trigger_context for indexed lookups
    resource_id: Mapped[uuid.UUID | None] = mapped_column()
    starter_id: Mapped[uuid.UUID | None] = mapped_column()
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = created_at_col()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["automation_id", "organization_id"],
            ["dms.automations.id", "dms.automations.organization_id"],
            ondelete="RESTRICT",
            name="fk_automation_runs_automation_org",
        ),
        UniqueConstraint("id", "organization_id", name="uq_automation_runs_id_org"),
        UniqueConstraint("automation_id", "event_key", name="uq_automation_runs_event"),
        CheckConstraint(check_in("status", RUN_STATUSES, "status"), name="status"),
        Index(
            "ix_automation_runs_list", "organization_id", "automation_id", text("created_at DESC")
        ),
        Index("ix_automation_runs_active", "status", "created_at"),
        # "what ran on this file" and "what did I start" read plain columns, not JSON paths
        Index(
            "ix_automation_runs_resource", "organization_id", "resource_id", text("created_at DESC")
        ),
        Index(
            "ix_automation_runs_starter",
            "organization_id",
            "starter_id",
            text("created_at DESC"),
            postgresql_where=text("mode = 'live'"),
        ),
    )


class AutomationNodeRun(Base):
    __tablename__ = "automation_node_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    run_id: Mapped[uuid.UUID] = mapped_column()
    node_id: Mapped[str] = mapped_column(String(64))
    node_type: Mapped[str] = mapped_column(String(48))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Safe summary only: counts, ids, outcomes. Never content, tokens or addresses.
    output: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    error: Mapped[str | None] = mapped_column(String(500))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["dms.automation_runs.id", "dms.automation_runs.organization_id"],
            ondelete="CASCADE",
            name="fk_automation_node_runs_run_org",
        ),
        UniqueConstraint("run_id", "node_id", name="uq_automation_node_runs_node"),
        CheckConstraint(check_in("status", NODE_STATUSES, "status"), name="status"),
        # finding the runs parked on one approval when it finishes
        Index(
            "ix_automation_node_runs_waiting",
            "organization_id",
            text("(output->>'approval_run_id')"),
            postgresql_where=text("status = 'waiting'"),
        ),
    )
