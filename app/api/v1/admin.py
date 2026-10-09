"""Administration: members, groups, audit trail, quarantine."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Response
from sqlalchemy import select

from app.api.deps import CurrentPrincipal, DbSession
from app.core.errors import ForbiddenError
from app.db.enums import DocumentStatus, ScanStatus
from app.db.models import Document, DocumentVersion
from app.modules.audit import queries as audit_queries
from app.modules.groups import service as groups
from app.modules.users import service as users
from app.schemas.admin import (
    AuditEventOut,
    GroupIn,
    GroupMemberAdd,
    GroupOut,
    GroupUpdate,
    InviteRequest,
    MemberOut,
    MemberUpdate,
    QuarantineItem,
)
from app.schemas.common import Page

router = APIRouter(prefix="/admin", tags=["admin"])


# ---- members
@router.get("/members", response_model=Page[MemberOut], summary="Organization members (admin)")
def list_members(
    db: DbSession,
    principal: CurrentPrincipal,
    q: str | None = Query(None, max_length=200),
    status: Literal["invited", "active", "suspended", "removed"] | None = None,
    role: Literal["owner", "admin", "member", "auditor"] | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[MemberOut]:
    items, total = users.list_members(
        db, principal, q=q, status=status, role=role, limit=limit, offset=offset
    )
    return Page[MemberOut](items=items, total=total, limit=limit, offset=offset)


@router.post("/members", response_model=MemberOut, status_code=201, summary="Invite a member")
def invite_member(body: InviteRequest, db: DbSession, principal: CurrentPrincipal) -> MemberOut:
    return users.invite(
        db, principal, email=body.email, display_name=body.display_name, role=body.role
    )


@router.patch(
    "/members/{user_id}",
    response_model=MemberOut,
    summary="Change role / suspend / remove a member",
)
def update_member(
    user_id: uuid.UUID, body: MemberUpdate, db: DbSession, principal: CurrentPrincipal
) -> MemberOut:
    return users.update_member(
        db, principal, user_id, role=body.role, status=body.status, display_name=body.display_name
    )


@router.post(
    "/members/{user_id}/revoke-sessions",
    status_code=204,
    summary="Invalidate all existing sessions of a member",
)
def revoke_sessions(user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> Response:
    users.revoke_sessions(db, principal, user_id)
    return Response(status_code=204)


# ---- groups (listing is open to members so they can pick share recipients)
@router.get("/groups", response_model=Page[GroupOut], summary="Groups, departments and teams")
def list_groups(
    db: DbSession,
    principal: CurrentPrincipal,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[GroupOut]:
    items, total = groups.list_groups(db, principal, q=q, limit=limit, offset=offset)
    return Page[GroupOut](items=items, total=total, limit=limit, offset=offset)


@router.post("/groups", response_model=GroupOut, status_code=201, summary="Create a group")
def create_group(body: GroupIn, db: DbSession, principal: CurrentPrincipal) -> GroupOut:
    return groups.create_group(
        db, principal, name=body.name, kind=body.kind, description=body.description
    )


@router.patch("/groups/{group_id}", response_model=GroupOut, summary="Update a group")
def update_group(
    group_id: uuid.UUID, body: GroupUpdate, db: DbSession, principal: CurrentPrincipal
) -> GroupOut:
    return groups.update_group(
        db, principal, group_id, name=body.name, description=body.description
    )


@router.delete(
    "/groups/{group_id}", status_code=204, summary="Delete a group (access granted to it ends)"
)
def delete_group(group_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> Response:
    groups.delete_group(db, principal, group_id)
    return Response(status_code=204)


@router.get(
    "/groups/{group_id}/members", response_model=list[MemberOut], summary="Members of a group"
)
def group_members(
    group_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> list[MemberOut]:
    return groups.list_group_members(db, principal, group_id)


@router.post("/groups/{group_id}/members", status_code=204, summary="Add a member to a group")
def add_group_member(
    group_id: uuid.UUID, body: GroupMemberAdd, db: DbSession, principal: CurrentPrincipal
) -> Response:
    groups.add_member(db, principal, group_id, body.user_id)
    return Response(status_code=204)


@router.delete(
    "/groups/{group_id}/members/{user_id}", status_code=204, summary="Remove a member from a group"
)
def remove_group_member(
    group_id: uuid.UUID, user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> Response:
    groups.remove_member(db, principal, group_id, user_id)
    return Response(status_code=204)


# ---- audit
@router.get(
    "/audit-events", response_model=Page[AuditEventOut], summary="Audit trail (admins and auditors)"
)
def audit_events(
    db: DbSession,
    principal: CurrentPrincipal,
    action: str | None = Query(None, max_length=100),
    actor_user_id: uuid.UUID | None = None,
    resource_type: str | None = Query(None, max_length=50),
    resource_id: uuid.UUID | None = None,
    outcome: Literal["success", "denied", "failure"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[AuditEventOut]:
    items, total = audit_queries.list_events(
        db,
        principal,
        action=action,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return Page[AuditEventOut](items=items, total=total, limit=limit, offset=offset)


# ---- quarantine
@router.get(
    "/quarantine",
    response_model=Page[QuarantineItem],
    summary="Versions blocked by security checks (admin)",
)
def quarantine(
    db: DbSession,
    principal: CurrentPrincipal,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[QuarantineItem]:
    if not principal.is_admin:
        raise ForbiddenError("Administrator access is required.")
    stmt = (
        select(DocumentVersion, Document)
        .join(Document, Document.id == DocumentVersion.document_id)
        .where(
            DocumentVersion.organization_id == principal.organization_id,
            DocumentVersion.scan_status.in_([ScanStatus.INFECTED.value, ScanStatus.ERROR.value]),
        )
        .order_by(DocumentVersion.scanned_at.desc().nullslast())
    )
    rows = db.execute(stmt).all()
    items = [
        QuarantineItem(
            document_id=d.id,
            document_name=d.name,
            version_id=v.id,
            version_number=v.version_number,
            scan_status=v.scan_status,
            scan_detail=v.scan_detail,
            scan_engine=v.scan_engine,
            scanned_at=v.scanned_at,
            uploaded_by=v.created_by,
            size_bytes=v.size_bytes,
        )
        for v, d in rows
    ]
    return Page[QuarantineItem](
        items=items[offset : offset + limit], total=len(items), limit=limit, offset=offset
    )


__all__ = ["DocumentStatus", "router"]
