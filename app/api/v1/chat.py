"""Agentic chat API. The assistant acts only through typed, authorized tools; every consequential
action is a pending action the user must confirm (hash-bound, single use, expiring)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, Response

from app.adapters.llm.factory import get_llm
from app.api.deps import Authz, CurrentPrincipal, DbSession, limited
from app.core.config import get_settings
from app.core.errors import ErrorResponse
from app.modules.chat import service as chat
from app.schemas.chat import (
    ConfirmIn,
    ConversationCreate,
    ConversationOut,
    FeedbackIn,
    MessageAccepted,
    MessageCreate,
    MessageOut,
    PendingActionOut,
    RunOut,
)
from app.schemas.common import ApiModel, Page

router = APIRouter(
    prefix="/chat",
    tags=["chat"],
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)


class ChatStatus(ApiModel):
    enabled: bool
    model: str | None = None
    max_steps: int
    max_bulk_items: int
    action_ttl_minutes: int
    streaming: str = "polling"


@router.get(
    "/status", response_model=ChatStatus, summary="Is the assistant available, and its limits"
)
def status(_principal: CurrentPrincipal) -> ChatStatus:
    s = get_settings()
    llm = get_llm()
    return ChatStatus(
        enabled=llm is not None,
        model=llm.model if llm else None,
        max_steps=s.agent_max_steps,
        max_bulk_items=s.agent_max_bulk_items,
        action_ttl_minutes=s.agent_action_ttl_minutes,
    )


@router.post(
    "/conversations",
    response_model=ConversationOut,
    status_code=201,
    summary="Start a conversation",
)
def create_conversation(
    body: ConversationCreate, db: DbSession, principal: CurrentPrincipal
) -> ConversationOut:
    return chat.create_conversation(db, principal, body)


@router.get("/conversations", response_model=Page[ConversationOut], summary="My conversations")
def list_conversations(
    db: DbSession,
    principal: CurrentPrincipal,
    include_archived: bool = False,
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[ConversationOut]:
    items, total = chat.list_conversations(
        db, principal, include_archived=include_archived, limit=limit, offset=offset
    )
    return Page[ConversationOut](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/conversations/{conversation_id}", response_model=ConversationOut, summary="One conversation"
)
def get_conversation(
    conversation_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> ConversationOut:
    return chat.get_conversation(db, principal, conversation_id)


class ConversationPatch(ApiModel):
    title: str | None = None
    status: str | None = None


@router.patch(
    "/conversations/{conversation_id}", response_model=ConversationOut, summary="Rename or archive"
)
def patch_conversation(
    conversation_id: uuid.UUID, body: ConversationPatch, db: DbSession, principal: CurrentPrincipal
) -> ConversationOut:
    return chat.update_conversation(db, principal, conversation_id, body.title, body.status)


@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=Page[MessageOut],
    summary="History (re-filtered against your CURRENT access)",
)
def list_messages(
    conversation_id: uuid.UUID,
    db: DbSession,
    authz: Authz,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[MessageOut]:
    items, total = chat.list_messages(db, authz, conversation_id, limit, offset)
    return Page[MessageOut](items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=MessageAccepted,
    status_code=202,
    summary="Send a message; poll the returned run for progress and the answer",
    dependencies=[limited("chat", sensitive=True)],
)
def post_message(
    conversation_id: uuid.UUID, body: MessageCreate, db: DbSession, authz: Authz
) -> MessageAccepted:
    return chat.post_message(db, authz, conversation_id, body)


@router.get("/runs/{run_id}", response_model=RunOut, summary="Status of an agent run")
def get_run(run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> RunOut:
    return chat.get_run(db, principal, run_id)


@router.post("/runs/{run_id}/cancel", response_model=RunOut, summary="Stop generating")
def cancel_run(run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> RunOut:
    return chat.cancel_run(db, principal, run_id)


@router.put("/messages/{message_id}/feedback", status_code=204, summary="Thumbs up/down (or clear)")
def feedback(
    message_id: uuid.UUID, body: FeedbackIn, db: DbSession, principal: CurrentPrincipal
) -> Response:
    chat.set_feedback(db, principal, message_id, body.feedback)
    return Response(status_code=204)


@router.get(
    "/actions/{action_id}",
    response_model=PendingActionOut,
    summary="A pending action and its preview",
)
def get_action(
    action_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> PendingActionOut:
    return chat.get_action(db, principal, action_id)


@router.post(
    "/actions/{action_id}/confirm",
    response_model=PendingActionOut,
    summary="Confirm exactly this previewed action (hash-bound, single use); re-authorized on execute",
    dependencies=[limited("chat_confirm", sensitive=True)],
)
def confirm(action_id: uuid.UUID, body: ConfirmIn, db: DbSession, authz: Authz) -> PendingActionOut:
    return chat.confirm_action(db, authz, action_id, body.payload_hash)


@router.post(
    "/actions/{action_id}/cancel",
    response_model=PendingActionOut,
    summary="Cancel a pending action",
)
def cancel(action_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> PendingActionOut:
    return chat.cancel_action(db, principal, action_id)
