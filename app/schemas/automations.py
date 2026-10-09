"""Schemas for automation workflows (IF this THEN that + visual canvas)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ApiModel

RunStatus = Literal["queued", "running", "waiting", "succeeded", "failed", "cancelled", "skipped"]
NodeStatus = Literal["pending", "running", "waiting", "succeeded", "failed", "skipped"]


class TriggerDef(ApiModel):
    key: str = Field(max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)


class NodeDef(ApiModel):
    id: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    type: str = Field(max_length=48)
    params: dict[str, Any] = Field(default_factory=dict)
    position: dict[str, float] | None = None


class EdgeDef(ApiModel):
    from_: str = Field(alias="from", pattern=r"^[a-z0-9_-]{1,32}$")
    to: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    branch: Literal["true", "false"] | None = None


class GraphDef(ApiModel):
    nodes: list[NodeDef] = Field(max_length=40)
    edges: list[EdgeDef] = Field(max_length=80)


class Issue(ApiModel):
    where: str = Field(description="'trigger', 'graph', or a node id.")
    field: str | None = None
    message: str


class ValidationReport(ApiModel):
    valid: bool
    issues: list[Issue]
    needs_high_risk_confirmation: bool = False


class AutomationCreate(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    editor_mode: Literal["wizard", "canvas"] = "wizard"
    trigger: TriggerDef
    graph: GraphDef
    activate: bool = Field(
        False,
        description="Publish and enable immediately. Default false: the workflow is saved as a draft.",
    )
    confirm_high_risk: bool = False
    allow_invalid: bool = Field(
        False,
        description="Canvas: create an empty/unfinished draft. Cannot be combined with activate.",
    )


class AutomationUpdate(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    trigger: TriggerDef | None = None
    graph: GraphDef | None = None
    expected_row_version: int | None = None
    allow_invalid: bool = Field(
        False, description="Canvas autosave: store the draft even if it does not validate yet."
    )


class PublishRequest(ApiModel):
    confirm_high_risk: bool = False


class TestRequest(ApiModel):
    resource_id: uuid.UUID | None = Field(
        None, description="A file, folder or user to evaluate against (dry run, no side effects)."
    )


class AutomationOut(ApiModel):
    id: uuid.UUID
    name: str
    description: str | None
    status: Literal["draft", "published", "archived"]
    enabled: bool
    editor_mode: Literal["wizard", "canvas"]
    state: Literal[
        "draft", "enabled", "disabled", "running", "failed", "needs_attention", "archived"
    ]
    if_this: str
    then_that: str
    trigger: TriggerDef
    graph: GraphDef
    published_version: int | None
    has_unpublished_changes: bool
    high_risk: bool
    row_version: int
    created_by_email: str | None
    created_at: datetime
    updated_at: datetime
    last_checked_at: datetime | None
    next_check_at: datetime | None
    last_run_at: datetime | None
    last_run_status: RunStatus | None
    last_run_summary: str | None
    attention_reason: str | None
    runs_running: int
    runs_succeeded: int
    runs_failed: int


class NodeRunOut(ApiModel):
    node_id: str
    node_type: str
    label: str
    status: NodeStatus
    attempts: int
    output: dict[str, Any]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class AutomationRunOut(ApiModel):
    id: uuid.UUID
    automation_id: uuid.UUID
    automation_name: str | None = None
    version_number: int | None
    status: RunStatus
    mode: Literal["live", "dry"]
    event_key: str
    trigger_context: dict[str, Any]
    error: str | None
    correlation_id: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    nodes: list[NodeRunOut] = []


class CatalogueEntry(ApiModel):
    key: str
    label: str
    description: str
    supported: bool
    unsupported_reason: str | None
    schema_: dict[str, Any] = Field(alias="schema")
    example: dict[str, Any]
    variables: dict[str, str] = {}
    kind: str | None = None
    observation: str | None = None
    risk: Literal["low", "high"] | None = None
    provides: Literal["file", "folder", "user", "none"] | None = Field(
        None, description="What a condition hands to the steps (conditions only)."
    )
    needs_resource: Literal["none", "file", "file_or_folder"] | None = None
    wizard: bool = True
    notes: list[str] = []


class CatalogueOut(ApiModel):
    schema_version: int
    conditions: list[CatalogueEntry]
    actions: list[CatalogueEntry]
    expression_help: list[str]
