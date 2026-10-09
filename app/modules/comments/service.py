"""Comments on documents and folders.

Reading needs VIEW on the resource; writing needs COMMENT (owners/admins have it; shares and
grants can carry it, so a recipient the item was shared with 'comment' access can comment). Edit is
author-only; delete is author or someone who manages access (admins/owners). Comments are plain
text. Trashed/purged resources are unreachable (404), like everything else.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import Action
from app.db.models import Comment, Document, Folder
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.items.common import user_refs
from app.modules.notifications import service as notifications
from app.schemas.comments import CommentOut
from app.schemas.common import UserRef

MAX_REPLIES_PER_THREAD = 200
NOTIFY_LIMIT = 50


def _actions(authz: AuthorizationService, rtype: str, rid: uuid.UUID) -> frozenset[str]:
    """Held actions, or NotFound unless the resource is at least viewable (non-disclosing)."""
    if rtype == "document":
        doc = authz.load_document(rid)
        acts = authz.document_actions([doc]).get(doc.id, frozenset()) if doc else frozenset()
    else:
        folder = authz.load_folder(rid)
        acts = (
            authz.folder_actions([folder.id]).get(folder.id, frozenset()) if folder else frozenset()
        )
    if Action.DISCOVER.value not in acts or Action.VIEW.value not in acts:
        raise NotFoundError(f"{rtype.capitalize()} not found.")
    return acts


def _out(
    db: Session, authz: AuthorizationService, rows: list[Comment], held: frozenset[str]
) -> list[CommentOut]:
    p = authz.principal
    refs = user_refs(db, [c.author_id for c in rows])
    can_moderate = Action.MANAGE_ACCESS.value in held or p.is_admin
    out: list[CommentOut] = []
    for c in rows:
        deleted = c.deleted_at is not None
        mine = c.author_id == p.user_id
        out.append(
            CommentOut(
                id=c.id,
                resource_type=c.resource_type,  # type: ignore[arg-type]
                resource_id=c.resource_id,
                parent_id=c.parent_id,
                author=refs.get(c.author_id, UserRef(id=c.author_id)) if c.author_id else None,
                body="" if deleted else c.body,
                created_at=c.created_at,
                edited_at=c.edited_at,
                deleted=deleted,
                can_edit=mine and not deleted and Action.COMMENT.value in held,
                can_delete=(mine or can_moderate) and not deleted,
            )
        )
    return out


def list_comments(
    db: Session,
    authz: AuthorizationService,
    rtype: str,
    rid: uuid.UUID,
    *,
    limit: int,
    offset: int,
) -> tuple[list[CommentOut], int, bool]:
    held = _actions(authz, rtype, rid)
    org = authz.principal.organization_id
    base = select(Comment).where(
        Comment.organization_id == org,
        Comment.resource_type == rtype,
        Comment.resource_id == rid,
    )
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = list(db.scalars(base.order_by(Comment.created_at).limit(limit).offset(offset)))
    return _out(db, authz, rows, held), int(total), Action.COMMENT.value in held


def _participants(db: Session, org: uuid.UUID, rtype: str, rid: uuid.UUID) -> set[uuid.UUID]:
    owner = (
        db.scalar(select(Document.owner_id).where(Document.id == rid))
        if rtype == "document"
        else db.scalar(select(Folder.created_by).where(Folder.id == rid))
    )
    prior = set(
        db.scalars(
            select(Comment.author_id)
            .where(
                Comment.organization_id == org,
                Comment.resource_type == rtype,
                Comment.resource_id == rid,
                Comment.author_id.is_not(None),
            )
            .distinct()
            .limit(NOTIFY_LIMIT)
        )
    )
    return {u for u in prior | ({owner} if owner else set()) if u}


def _can_still_view(
    db: Session, org: uuid.UUID, user_id: uuid.UUID, rtype: str, rid: uuid.UUID
) -> bool:
    """Would this user (not the caller) still see the resource? Used so a notification never
    reaches someone who lost access."""
    from app.modules.identity.service import principal_for

    try:
        other = AuthorizationService(db, principal_for(db, user_id, org))
        _actions(other, rtype, rid)
        return True
    except (NotFoundError, ForbiddenError):
        return False


def add_comment(
    db: Session,
    authz: AuthorizationService,
    rtype: str,
    rid: uuid.UUID,
    body: str,
    parent_id: uuid.UUID | None,
) -> CommentOut:
    p = authz.principal
    held = _actions(authz, rtype, rid)
    if Action.COMMENT.value not in held:
        authz.deny(rtype, rid, Action.COMMENT, "action_not_granted")
        raise ForbiddenError("You do not have permission to comment here.")
    text = body.strip()
    if not text:
        raise ValidationFailed("A comment cannot be empty.")
    if parent_id is not None:
        parent = db.scalar(
            select(Comment).where(
                Comment.id == parent_id,
                Comment.organization_id == p.organization_id,
                Comment.resource_type == rtype,
                Comment.resource_id == rid,
            )
        )
        if parent is None:
            raise NotFoundError("Comment not found.")
        if parent.parent_id is not None:
            raise ValidationFailed("Replies can only be added to a top-level comment.")
        if parent.deleted_at is not None:
            raise ConflictError("That comment was deleted.", code="comment_deleted")
        replies = db.scalar(select(func.count()).where(Comment.parent_id == parent_id)) or 0
        if replies >= MAX_REPLIES_PER_THREAD:
            raise ConflictError("This thread is full.", code="thread_full")
    c = Comment(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        resource_type=rtype,
        resource_id=rid,
        parent_id=parent_id,
        author_id=p.user_id,
        body=text,
    )
    db.add(c)
    db.flush()
    name = p.display_name or p.email
    for uid in _participants(db, p.organization_id, rtype, rid) - {p.user_id}:
        if _can_still_view(db, p.organization_id, uid, rtype, rid):
            notifications.create(
                db,
                organization_id=p.organization_id,
                user_id=uid,
                type_="comment.created",
                title=f"{name} commented",
                body=None,  # never put comment text in notifications/e-mail
                resource_type=rtype,
                resource_id=rid,
                source_event_id=c.id,
            )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="comment.created",
        resource_type=rtype,
        resource_id=rid,
        metadata={"comment_id": str(c.id), "reply": parent_id is not None},
    )
    db.commit()
    return _out(db, authz, [c], held)[0]


def _own_comment(db: Session, p_org: uuid.UUID, comment_id: uuid.UUID) -> Comment:
    c = db.scalar(
        select(Comment)
        .where(Comment.id == comment_id, Comment.organization_id == p_org)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if c is None:
        raise NotFoundError("Comment not found.")
    return c


def edit_comment(
    db: Session, authz: AuthorizationService, comment_id: uuid.UUID, body: str
) -> CommentOut:
    p = authz.principal
    c = _own_comment(db, p.organization_id, comment_id)
    held = _actions(authz, c.resource_type, c.resource_id)  # 404 if the resource is hidden/gone
    if c.deleted_at is not None:
        raise ConflictError("That comment was deleted.", code="comment_deleted")
    if c.author_id != p.user_id:
        raise ForbiddenError("You can only edit your own comments.")
    if Action.COMMENT.value not in held:
        raise ForbiddenError("You do not have permission to comment here.")
    text = body.strip()
    if not text:
        raise ValidationFailed("A comment cannot be empty.")
    c.body, c.edited_at = text, datetime.now(UTC)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="comment.edited",
        resource_type=c.resource_type,
        resource_id=c.resource_id,
        metadata={"comment_id": str(c.id)},
    )
    db.commit()
    return _out(db, authz, [c], held)[0]


def delete_comment(db: Session, authz: AuthorizationService, comment_id: uuid.UUID) -> None:
    p = authz.principal
    c = _own_comment(db, p.organization_id, comment_id)
    held = _actions(authz, c.resource_type, c.resource_id)
    if c.deleted_at is not None:
        return
    if c.author_id != p.user_id and not (Action.MANAGE_ACCESS.value in held or p.is_admin):
        raise ForbiddenError("You can only delete your own comments.")
    c.deleted_at, c.body = datetime.now(UTC), "[deleted]"  # scrub the text, keep the thread shape
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="comment.deleted",
        resource_type=c.resource_type,
        resource_id=c.resource_id,
        metadata={"comment_id": str(c.id), "moderated": c.author_id != p.user_id},
    )
    db.commit()
