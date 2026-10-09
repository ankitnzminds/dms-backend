"""Access requests: a record awaiting a decision. Creating one never grants anything; only an
approver who holds MANAGE_ACCESS on the resource (and is not the requester) can approve, and the
grant is applied through the regular permission service (no escalation beyond what they hold)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import Action, ResourceType, Role
from app.db.models import AccessRequest, Document, Folder, Membership
from app.modules.audit import service as audit
from app.modules.authorization import acl
from app.modules.authorization.actions import ALL_ACTIONS
from app.modules.authorization.service import AuthorizationService
from app.modules.items.common import user_refs
from app.modules.notifications import service as notifications
from app.schemas.chat import AccessRequestCreate, AccessRequestDecision, AccessRequestOut
from app.schemas.common import UserRef
from app.schemas.sharing import PermissionGrantIn

_NOT_REQUESTABLE = {"administer", "discover"}


def _names(db: Session, rows: list[AccessRequest]) -> dict[uuid.UUID, str]:
    doc_ids = [r.resource_id for r in rows if r.resource_type == "document"]
    folder_ids = [r.resource_id for r in rows if r.resource_type == "folder"]
    out: dict[uuid.UUID, str] = {}
    if doc_ids:
        out.update(
            db.execute(select(Document.id, Document.name).where(Document.id.in_(doc_ids))).all()
        )
    if folder_ids:
        out.update(
            db.execute(select(Folder.id, Folder.name).where(Folder.id.in_(folder_ids))).all()
        )
    return out


def _can_decide(authz: AuthorizationService, r: AccessRequest) -> bool:
    if r.status != "pending" or r.requester_id == authz.principal.user_id:
        return False
    if r.resource_type == "document":
        doc = authz.load_document(r.resource_id)
        acts = authz.document_actions([doc]).get(doc.id, frozenset()) if doc else frozenset()
    else:
        folder = authz.load_folder(r.resource_id)
        acts = (
            authz.folder_actions([folder.id]).get(folder.id, frozenset()) if folder else frozenset()
        )
    return Action.MANAGE_ACCESS.value in acts


def _out(
    db: Session, authz: AuthorizationService, rows: list[AccessRequest]
) -> list[AccessRequestOut]:
    refs = user_refs(db, [x for r in rows for x in (r.requester_id, r.approver_id)])
    names = _names(db, rows)
    result: list[AccessRequestOut] = []
    for r in rows:
        can_decide = _can_decide(authz, r)
        # The resource name is disclosed to the requester, and to anyone allowed to decide.
        disclose = r.requester_id == authz.principal.user_id or can_decide
        result.append(
            AccessRequestOut(
                id=r.id,
                resource_type=r.resource_type,  # type: ignore[arg-type]
                resource_id=r.resource_id,
                resource_name=names.get(r.resource_id) if disclose else None,
                requester=refs.get(r.requester_id, UserRef(id=r.requester_id)),
                requested_actions=list(r.requested_actions),
                reason=r.reason,
                status=r.status,  # type: ignore[arg-type]
                approver=refs.get(r.approver_id) if r.approver_id else None,
                decision_reason=r.decision_reason,
                created_at=r.created_at,
                decided_at=r.decided_at,
                can_decide=can_decide,
            )
        )
    return result


def _held(authz: AuthorizationService, rtype: str, rid: uuid.UUID) -> frozenset[str]:
    """Actions the caller holds, or NotFound if the resource is not discoverable (non-disclosing)."""
    if rtype == "document":
        doc = authz.load_document(rid)
        acts = authz.document_actions([doc]).get(doc.id, frozenset()) if doc else frozenset()
    else:
        folder = authz.load_folder(rid)
        acts = (
            authz.folder_actions([folder.id]).get(folder.id, frozenset()) if folder else frozenset()
        )
    if Action.DISCOVER.value not in acts:
        raise NotFoundError(f"{rtype.capitalize()} not found.")
    return acts


def _approver_ids(db: Session, org_id: uuid.UUID, rtype: str, rid: uuid.UUID) -> set[uuid.UUID]:
    """Best-effort notification targets: the creator and organization admins. The decision itself
    is always authorized against MANAGE_ACCESS, so this list never confers authority."""
    created_by = (
        db.scalar(select(Document.owner_id).where(Document.id == rid))
        if rtype == "document"
        else db.scalar(select(Folder.created_by).where(Folder.id == rid))
    )
    admins = set(
        db.scalars(
            select(Membership.user_id).where(
                Membership.organization_id == org_id,
                Membership.status == "active",
                Membership.role.in_([Role.OWNER.value, Role.ADMIN.value]),
            )
        )
    )
    return admins | ({created_by} if created_by else set())


def create(db: Session, authz: AuthorizationService, body: AccessRequestCreate) -> AccessRequestOut:
    p = authz.principal
    held = _held(authz, body.resource_type, body.resource_id)
    actions = sorted(set(body.actions))
    bad = [a for a in actions if a not in ALL_ACTIONS or a in _NOT_REQUESTABLE]
    if bad:
        raise ValidationFailed(f"These actions cannot be requested: {', '.join(bad)}")
    missing = [a for a in actions if a not in held]
    if not missing:
        raise ConflictError("You already have this access.", code="already_has_access")

    existing = db.scalar(
        select(AccessRequest).where(
            AccessRequest.organization_id == p.organization_id,
            AccessRequest.requester_id == p.user_id,
            AccessRequest.resource_type == body.resource_type,
            AccessRequest.resource_id == body.resource_id,
            AccessRequest.status == "pending",
        )
    )
    if existing is not None:  # idempotent: one open request per requester and resource
        return _out(db, authz, [existing])[0]

    req = AccessRequest(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        requester_id=p.user_id,
        requested_actions=missing,
        reason=body.reason.strip(),
    )
    db.add(req)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        again = db.scalar(
            select(AccessRequest).where(
                AccessRequest.organization_id == p.organization_id,
                AccessRequest.requester_id == p.user_id,
                AccessRequest.resource_id == body.resource_id,
                AccessRequest.status == "pending",
            )
        )
        if again is None:
            raise
        return _out(db, authz, [again])[0]
    for uid in _approver_ids(db, p.organization_id, body.resource_type, body.resource_id) - {
        p.user_id
    }:
        notifications.create(
            db,
            organization_id=p.organization_id,
            user_id=uid,
            type_="access_request.created",
            title=f"{p.display_name or p.email} requested access",
            resource_type=body.resource_type,
            resource_id=body.resource_id,
            source_event_id=req.id,
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="access_request.created",
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        metadata={"request_id": str(req.id), "actions": missing},
    )
    db.commit()
    return _out(db, authz, [req])[0]


def list_requests(
    db: Session,
    authz: AuthorizationService,
    *,
    mine: bool,
    status: str | None,
    limit: int,
    offset: int,
) -> tuple[list[AccessRequestOut], int]:
    """``mine`` = my own requests; otherwise requests I may decide (admins: all in the org)."""
    p = authz.principal
    stmt = select(AccessRequest).where(AccessRequest.organization_id == p.organization_id)
    if status:
        stmt = stmt.where(AccessRequest.status == status)
    if mine:
        rows = list(
            db.scalars(
                stmt.where(AccessRequest.requester_id == p.user_id).order_by(
                    AccessRequest.created_at.desc()
                )
            )
        )
    else:
        candidates = list(
            db.scalars(
                stmt.where(AccessRequest.requester_id != p.user_id)
                .order_by(AccessRequest.created_at.desc())
                .limit(500)
            )
        )
        rows = [r for r in candidates if _can_decide(authz, r) or (r.approver_id == p.user_id)]
    page = rows[offset : offset + limit]
    return _out(db, authz, page), len(rows)


def get(db: Session, authz: AuthorizationService, request_id: uuid.UUID) -> AccessRequestOut:
    r = db.scalar(
        select(AccessRequest).where(
            AccessRequest.id == request_id,
            AccessRequest.organization_id == authz.principal.organization_id,
        )
    )
    if r is None:
        raise NotFoundError("Access request not found.")
    out = _out(db, authz, [r])[0]
    if (
        r.requester_id != authz.principal.user_id
        and not out.can_decide
        and r.approver_id != authz.principal.user_id
    ):
        raise NotFoundError("Access request not found.")  # non-disclosing
    return out


def cancel(db: Session, authz: AuthorizationService, request_id: uuid.UUID) -> AccessRequestOut:
    p = authz.principal
    r = db.scalar(
        select(AccessRequest)
        .where(AccessRequest.id == request_id, AccessRequest.organization_id == p.organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if r is None or r.requester_id != p.user_id:
        raise NotFoundError("Access request not found.")
    if r.status != "pending":
        raise ConflictError("This request has already been decided.", code="already_decided")
    r.status = "cancelled"
    r.decided_at = datetime.now(UTC)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="access_request.cancelled",
        resource_type=r.resource_type,
        resource_id=r.resource_id,
        metadata={"request_id": str(r.id)},
    )
    db.commit()
    return _out(db, authz, [r])[0]


def decide(
    db: Session, authz: AuthorizationService, request_id: uuid.UUID, body: AccessRequestDecision
) -> AccessRequestOut:
    p = authz.principal
    r = db.scalar(
        select(AccessRequest)
        .where(AccessRequest.id == request_id, AccessRequest.organization_id == p.organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if r is None:
        raise NotFoundError("Access request not found.")
    if r.requester_id == p.user_id:
        raise ForbiddenError("You cannot decide your own access request.", code="self_approval")
    if r.status != "pending":
        raise ConflictError("This request has already been decided.", code="already_decided")
    # Authoritative approver check (MANAGE_ACCESS on the resource); also yields non-disclosing 404.
    if r.resource_type == "document":
        authz.require_document(r.resource_id, Action.MANAGE_ACCESS)
    else:
        authz.require_folder(r.resource_id, Action.MANAGE_ACCESS)

    now = datetime.now(UTC)
    r.approver_id = p.user_id
    r.decided_at = now
    r.decision_reason = (body.reason or "").strip() or None
    if body.decision == "reject":
        r.status = "rejected"
        notify_type, title = "access_request.rejected", "Your access request was rejected"
    else:
        granted = sorted(set(body.actions or r.requested_actions))
        if not set(granted) <= set(r.requested_actions):
            raise ValidationFailed("You can only approve actions that were requested.")
        r.status = "approved"
        notify_type, title = "access_request.approved", "Your access request was approved"
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=f"access_request.{r.status}",
        resource_type=r.resource_type,
        resource_id=r.resource_id,
        metadata={"request_id": str(r.id), "requester_id": str(r.requester_id)},
    )
    notifications.create(
        db,
        organization_id=p.organization_id,
        user_id=r.requester_id,
        type_=notify_type,
        title=title,
        resource_type=r.resource_type,
        resource_id=r.resource_id,
        source_event_id=r.id,
    )
    if body.decision == "approve":
        # add_grant commits: the status change, notification and grant land in ONE transaction,
        # and it refuses to grant anything the approver does not hold themselves.
        acl.add_grant(
            db,
            authz,
            ResourceType.DOCUMENT if r.resource_type == "document" else ResourceType.FOLDER,
            r.resource_id,
            PermissionGrantIn(
                subject_type="user",
                subject_id=r.requester_id,
                actions=granted,  # type: ignore[arg-type]
                inherit=True,
                expires_at=body.expires_at,
            ),
        )
    else:
        db.commit()
    db.refresh(r)
    return _out(db, authz, [r])[0]
