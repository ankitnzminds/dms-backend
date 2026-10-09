"""Workflow schemas (definitions, runs, tasks)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from app.schemas.common import ApiModel, UserRef


class AssigneeSpec(ApiModel):
    type: Literal["user", "group", "role"]
    id: uuid.UUID | None = None
    role: Literal["owner", "admin", "member", "auditor"] | None = None

    @model_validator(mode="after")
    def _shape(self) -> AssigneeSpec:
        if self.type == "role":
            if self.role is None or self.id is not None:
                raise ValueError("role assignees need 'role' and no 'id'")
        elif self.id is None or self.role is not None:
            raise ValueError(f"{self.type} assignees need 'id' and no 'role'")
        return self


class StepCondition(ApiModel):
    """Step runs only if the condition holds for the document when the step is activated."""

    field: Literal["classification", "size_bytes", "content_type", "metadata"]
    key: str | None = Field(None, max_length=64, description="metadata key when field='metadata'")
    op: Literal["eq", "neq", "gt", "gte", "lt", "lte", "in"]
    value: Any

    @model_validator(mode="after")
    def _shape(self) -> StepCondition:
        if (self.field == "metadata") != (self.key is not None):
            raise ValueError("'key' is required exactly when field is 'metadata'")
        if self.op == "in" and not isinstance(self.value, list):
            raise ValueError("'in' needs a list value")
        if self.op in ("gt", "gte", "lt", "lte") and (
            isinstance(self.value, bool) or not isinstance(self.value, (int, float))
        ):
            raise ValueError("comparison operators need a number")
        return self


class StepSpec(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    assignees: list[AssigneeSpec] = Field(min_length=1, max_length=20)
    rule: Literal["all", "any"] = Field(
        "all", description="all = every assignee must approve; any = first approval wins"
    )
    due_days: int | None = Field(None, ge=1, le=365)
    escalate_to_user_id: uuid.UUID | None = None
    condition: StepCondition | None = None


class WorkflowDefinitionIn(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    steps: list[StepSpec] = Field(min_length=1, max_length=10)


class WorkflowVersionIn(ApiModel):
    steps: list[StepSpec] = Field(min_length=1, max_length=10)


class WorkflowDefinitionUpdate(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    archived: bool | None = None


class WorkflowDefinitionOut(ApiModel):
    id: uuid.UUID
    name: str
    description: str | None
    archived: bool
    latest_version: int
    steps: list[StepSpec]
    created_at: datetime


class StartRunIn(ApiModel):
    definition_id: uuid.UUID
    note: str | None = Field(None, max_length=2000)


class DecisionIn(ApiModel):
    decision: Literal["approve", "reject"]
    comment: str | None = Field(None, max_length=2000)


class DelegateIn(ApiModel):
    user_id: uuid.UUID | None = None
    email: str | None = Field(None, max_length=320)
    comment: str | None = Field(None, max_length=2000)

    @model_validator(mode="after")
    def _one(self) -> DelegateIn:
        if (self.user_id is None) == (self.email is None):
            raise ValueError("provide exactly one of user_id or email")
        return self


class CancelRunIn(ApiModel):
    comment: str | None = Field(None, max_length=2000)


class TaskOut(ApiModel):
    id: uuid.UUID
    run_id: uuid.UUID
    document_id: uuid.UUID
    document_name: str | None
    step_index: int
    step_name: str
    rule: Literal["all", "any"]
    assignee: UserRef
    delegated_from: UserRef | None = None
    status: Literal["pending", "approved", "rejected", "cancelled", "skipped"]
    due_at: datetime | None
    overdue: bool
    decided_at: datetime | None
    comment: str | None
    run_state: Literal["in_progress", "approved", "rejected", "cancelled"] | None = None
    document_version_number: int | None = None
    started_by: UserRef | None = None
    note: str | None = None


class ActionOut(ApiModel):
    id: uuid.UUID
    action: str
    actor: UserRef | None
    comment: str | None
    task_id: uuid.UUID | None
    created_at: datetime
    metadata: dict[str, Any]


class StepStatusOut(ApiModel):
    index: int
    name: str
    rule: Literal["all", "any"]
    status: Literal["upcoming", "active", "approved", "rejected", "skipped"]


class RunOut(ApiModel):
    id: uuid.UUID
    document_id: uuid.UUID
    document_name: str | None
    document_version_id: uuid.UUID
    document_version_number: int
    definition_name: str | None
    definition_version: int
    state: Literal["in_progress", "approved", "rejected", "cancelled"]
    current_step: int
    started_by: UserRef
    note: str | None
    outcome_comment: str | None
    created_at: datetime
    completed_at: datetime | None
    resubmitted_from_run_id: uuid.UUID | None
    steps: list[StepStatusOut]
    tasks: list[TaskOut]
    actions: list[ActionOut]
