"""Chat conversations, messages, runs and the pending-action confirm/cancel lifecycle."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.adapters.llm.factory import get_llm
from app.core.config import get_settings
from app.core.errors import AppError, ConflictError, NotFoundError
from app.db.enums import Action
from app.db.models import AgentRun, ChatConversation, ChatMessage, PendingAction
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.chat import actions as act
from app.modules.chat import orchestrator
from app.modules.chat.visibility import REDACTED_TEXT, blocks_out, citations_out, message_visible
from app.modules.identity.principal import Principal
from app.schemas.chat import (
    ConversationCreate,
    ConversationOut,
    MessageAccepted,
    MessageCreate,
    MessageOut,
    PendingActionOut,
    RunOut,
)


# ------------------------------------------------------------------ conversations
def _conv_out(c: ChatConversation) -> ConversationOut:
    return ConversationOut(
        id=c.id,
        title=c.title,
        status=c.status,
        created_at=c.created_at,
        updated_at=c.updated_at,  # type: ignore[arg-type]
    )


def _own_conversation(db: Session, p: Principal, conversation_id: uuid.UUID) -> ChatConversation:
    c = db.scalar(
        select(ChatConversation).where(
            ChatConversation.id == conversation_id,
            ChatConversation.organization_id == p.organization_id,
            ChatConversation.owner_user_id == p.user_id,
        )
    )
    if c is None:
        raise NotFoundError("Conversation not found.")  # same answer for 'not yours' and 'missing'
    return c


def create_conversation(db: Session, p: Principal, body: ConversationCreate) -> ConversationOut:
    c = ChatConversation(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        owner_user_id=p.user_id,
        title=(body.title or "New conversation").strip()[:200] or "New conversation",
    )
    db.add(c)
    db.commit()
    return _conv_out(c)


def list_conversations(
    db: Session, p: Principal, *, include_archived: bool, limit: int, offset: int
) -> tuple[list[ConversationOut], int]:
    stmt = select(ChatConversation).where(
        ChatConversation.organization_id == p.organization_id,
        ChatConversation.owner_user_id == p.user_id,
    )
    if not include_archived:
        stmt = stmt.where(ChatConversation.status == "active")
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(ChatConversation.updated_at.desc()).limit(limit).offset(offset))
    return [_conv_out(c) for c in rows], int(total)


def get_conversation(db: Session, p: Principal, conversation_id: uuid.UUID) -> ConversationOut:
    return _conv_out(_own_conversation(db, p, conversation_id))


def update_conversation(
    db: Session, p: Principal, conversation_id: uuid.UUID, title: str | None, status: str | None
) -> ConversationOut:
    c = _own_conversation(db, p, conversation_id)
    if title is not None:
        c.title = title.strip()[:200] or c.title
    if status in ("active", "archived"):
        c.status = status
    db.commit()
    return _conv_out(c)


# ------------------------------------------------------------------ messages
def message_out(authz: AuthorizationService, m: ChatMessage) -> MessageOut:
    visible = m.role == "user" or message_visible(authz.db, authz, m)
    return MessageOut(
        id=m.id,
        role=m.role,  # type: ignore[arg-type]
        content=m.content if visible else REDACTED_TEXT,
        redacted=not visible,
        citations=citations_out(authz, m) if visible else [],
        blocks=blocks_out(authz, m.blocks) if visible else [],
        run_id=m.run_id,
        model=m.model,
        feedback=m.feedback,  # type: ignore[arg-type]
        created_at=m.created_at,
    )


def list_messages(
    db: Session, authz: AuthorizationService, conversation_id: uuid.UUID, limit: int, offset: int
) -> tuple[list[MessageOut], int]:
    _own_conversation(db, authz.principal, conversation_id)
    base = select(ChatMessage).where(ChatMessage.conversation_id == conversation_id)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.scalars(base.order_by(ChatMessage.created_at).limit(limit).offset(offset))
    return [message_out(authz, m) for m in rows], int(total)


def _run_out(db: Session, run: AgentRun) -> RunOut:
    msg_id = db.scalar(
        select(ChatMessage.id)
        .where(ChatMessage.run_id == run.id, ChatMessage.role == "assistant")
        .order_by(ChatMessage.created_at.desc())
        .limit(1)
    )
    pending = list(
        db.scalars(
            select(PendingAction.id).where(
                PendingAction.run_id == run.id, PendingAction.status == "pending"
            )
        )
    )
    return RunOut(
        id=run.id,
        conversation_id=run.conversation_id,
        status=run.status,  # type: ignore[arg-type]
        current_step=run.current_step,
        steps=run.steps,
        tool_calls=run.tool_calls,
        error_code=run.error_code,
        started_at=run.started_at,
        finished_at=run.finished_at,
        assistant_message_id=msg_id,
        pending_action_ids=pending,
    )


def post_message(
    db: Session, authz: AuthorizationService, conversation_id: uuid.UUID, body: MessageCreate
) -> MessageAccepted:
    p = authz.principal
    c = _own_conversation(db, p, conversation_id)
    if c.status != "active":
        raise ConflictError("This conversation is archived.", code="conversation_archived")
    if get_llm() is None:
        raise AppError("The assistant is not configured.", code="ai_not_configured")
    busy = db.scalar(
        select(AgentRun.id).where(
            AgentRun.conversation_id == conversation_id, AgentRun.status.in_(("queued", "running"))
        )
    )
    if busy is not None:
        raise ConflictError(
            "The assistant is still answering the previous message.", code="run_in_progress"
        )

    context: dict[str, str] = {}
    for key, rid, fetch in (
        (
            "document_id",
            body.context_document_id,
            lambda i: authz.require_document(i, Action.DISCOVER),
        ),
        ("folder_id", body.context_folder_id, lambda i: authz.require_folder(i, Action.DISCOVER)),
    ):
        if rid is not None:
            try:
                fetch(rid)
                context[key] = str(rid)  # IDs only; they grant nothing and are re-checked per use
            except AppError:
                pass  # silently ignore a context the user cannot see
    user_msg = ChatMessage(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        conversation_id=conversation_id,
        role="user",
        content=body.content.strip(),
        blocks=[{"type": "context", **context}] if context else [],
    )
    db.add(user_msg)
    run = AgentRun(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        requester_id=p.user_id,
        conversation_id=conversation_id,
        status="queued",
    )
    db.add(run)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="chat.message_sent",
        resource_type="agent_run",
        resource_id=run.id,
        metadata={"conversation_id": str(conversation_id)},
    )
    db.commit()
    out = MessageAccepted(message=message_out(authz, user_msg), run=_run_out(db, run))
    orchestrator.schedule_run(run.id, p.organization_id, p.user_id)
    db.expire_all()
    run = db.get(AgentRun, run.id) or run
    return MessageAccepted(message=out.message, run=_run_out(db, run))


def _own_run(db: Session, p: Principal, run_id: uuid.UUID) -> AgentRun:
    run = db.scalar(
        select(AgentRun)
        .where(
            AgentRun.id == run_id,
            AgentRun.organization_id == p.organization_id,
            AgentRun.requester_id == p.user_id,
        )
        .execution_options(populate_existing=True)
    )
    if run is None:
        raise NotFoundError("Run not found.")
    return run


def get_run(db: Session, p: Principal, run_id: uuid.UUID) -> RunOut:
    run = _own_run(db, p, run_id)
    settings = get_settings()
    stale_after = timedelta(seconds=settings.agent_max_runtime_seconds + 60)
    if run.status in ("queued", "running") and datetime.now(UTC) - run.created_at > stale_after:
        run.status, run.error_code, run.finished_at = "failed", "timeout", datetime.now(UTC)
        db.commit()  # a crashed worker must not leave the UI spinning forever
    return _run_out(db, run)


def cancel_run(db: Session, p: Principal, run_id: uuid.UUID) -> RunOut:
    run = _own_run(db, p, run_id)
    if run.status in ("queued", "running"):
        run.status, run.finished_at, run.error_code = "cancelled", datetime.now(UTC), "cancelled"
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="chat.run_cancelled",
            resource_type="agent_run",
            resource_id=run.id,
        )
        db.commit()
    return _run_out(db, run)


def set_feedback(db: Session, p: Principal, message_id: uuid.UUID, feedback: str | None) -> None:
    m = db.scalar(
        select(ChatMessage)
        .join(ChatConversation, ChatConversation.id == ChatMessage.conversation_id)
        .where(
            ChatMessage.id == message_id,
            ChatMessage.role == "assistant",
            ChatConversation.owner_user_id == p.user_id,
            ChatConversation.organization_id == p.organization_id,
        )
    )
    if m is None:
        raise NotFoundError("Message not found.")
    m.feedback = feedback
    db.commit()


# ------------------------------------------------------------------ pending actions
def _action_out(a: PendingAction) -> PendingActionOut:
    return PendingActionOut(
        id=a.id,
        conversation_id=a.conversation_id,
        action_type=a.action_type,
        status=a.status,  # type: ignore[arg-type]
        preview=a.preview,
        payload_hash=a.payload_hash,
        expires_at=a.expires_at,
        result=a.result,
        error_code=a.error_code,
    )


def _lock_action(db: Session, p: Principal, action_id: uuid.UUID, *, lock: bool) -> PendingAction:
    stmt = select(PendingAction).where(
        PendingAction.id == action_id,
        PendingAction.organization_id == p.organization_id,
        PendingAction.requester_id == p.user_id,  # someone else's action looks like a missing one
    )
    if lock:
        stmt = stmt.with_for_update()
    a = db.scalar(stmt.execution_options(populate_existing=True))
    if a is None:
        raise NotFoundError("Action not found.")
    return a


def get_action(db: Session, p: Principal, action_id: uuid.UUID) -> PendingActionOut:
    a = _lock_action(db, p, action_id, lock=False)
    if a.status == "pending" and a.expires_at <= datetime.now(UTC):
        a.status = "expired"
        db.commit()
    return _action_out(a)


def _post_result(db: Session, a: PendingAction, text: str, status: str) -> None:
    db.add(
        ChatMessage(
            id=uuid.uuid4(),
            organization_id=a.organization_id,
            conversation_id=a.conversation_id,
            role="assistant",
            content=text,
            run_id=a.run_id,
            blocks=[{"type": "action_result", "action_id": str(a.id), "status": status}],
        )
    )


def cancel_action(db: Session, p: Principal, action_id: uuid.UUID) -> PendingActionOut:
    a = _lock_action(db, p, action_id, lock=True)
    if a.status != "pending":
        raise ConflictError("This action is no longer pending.", code="action_not_pending")
    a.status = "cancelled"
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="chat.action_cancelled",
        resource_type="pending_action",
        resource_id=a.id,
        metadata={"action_type": a.action_type},
    )
    _post_result(db, a, "Cancelled. Nothing was changed.", "cancelled")
    db.commit()
    return _action_out(a)


def confirm_action(
    db: Session, authz: AuthorizationService, action_id: uuid.UUID, payload_hash: str
) -> PendingActionOut:
    p = authz.principal
    a = _lock_action(db, p, action_id, lock=True)
    if a.status != "pending":  # single use: a replay (or a confirmed/cancelled action) is refused
        raise ConflictError("This action is no longer pending.", code="action_not_pending")
    if a.expires_at <= datetime.now(UTC):
        a.status = "expired"
        db.commit()
        raise ConflictError(
            "This confirmation expired. Ask again for a fresh preview.", code="action_expired"
        )
    # The confirmation must name the exact payload the user was shown...
    if payload_hash != a.payload_hash:
        raise ConflictError(
            "This does not match the action you were shown. Review the current preview.",
            code="action_mismatch",
        )
    # ...and the stored payload must still hash to it (tamper check).
    if act.canonical_hash(a.action_type, a.payload, p.user_id, p.organization_id) != a.payload_hash:
        a.status, a.error_code = "invalidated", "payload_tampered"
        db.commit()
        raise ConflictError("This action is no longer valid.", code="action_mismatch")
    payload = act.parse_payload(a.action_type, a.payload)
    try:
        act.check_fresh(db, authz, a.action_type, payload)
    except ConflictError:
        a.status, a.error_code = "invalidated", "action_stale"
        db.commit()
        raise
    a.status, a.confirmed_at = "confirmed", datetime.now(UTC)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="chat.action_confirmed",
        resource_type="pending_action",
        resource_id=a.id,
        metadata={"action_type": a.action_type},
    )
    db.commit()  # claim it: from here on this id can never execute again

    aid, atype = a.id, a.action_type
    try:
        summary, result, status = act.EXECUTORS[atype](db, authz, payload)  # re-authorizes inside
    except AppError as exc:
        db.rollback()
        db.execute(
            update(PendingAction)
            .where(PendingAction.id == aid)
            .values(status="failed", error_code=exc.code, result={"message": exc.message})
        )
        row = db.get(PendingAction, aid)
        assert row is not None
        _post_result(db, row, f"I could not do that: {exc.message}", "failed")
        db.commit()
        raise
    except Exception:
        db.rollback()
        db.execute(
            update(PendingAction)
            .where(PendingAction.id == aid)
            .values(status="failed", error_code="internal_error")
        )
        db.commit()
        raise
    db.execute(
        update(PendingAction)
        .where(PendingAction.id == aid)
        .values(status=status, result={"summary": summary, **result})
    )
    row = db.get(PendingAction, aid)
    assert row is not None
    db.refresh(row)
    _post_result(db, row, summary, status)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="chat.action_executed",
        resource_type="pending_action",
        resource_id=aid,
        metadata={"action_type": atype, "status": status},
    )
    db.commit()
    return _action_out(row)
