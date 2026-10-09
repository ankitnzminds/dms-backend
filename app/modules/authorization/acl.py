"""Administrative ACL: permission grants on folders/documents (team folders, delegated access)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import Action, ResourceType, SubjectType, UserStatus
from app.db.models import Group, Membership, PermissionGrant, User
from app.modules.audit import service as audit
from app.modules.authorization.actions import ALL_ACTIONS
from app.modules.authorization.matrix import ACL_LABELS, to_labels
from app.modules.authorization.service import AuthorizationService
from app.schemas.sharing import PermissionGrantIn, PermissionGrantOut

# Only org administrators may hand out the ADMINISTER capability (it is org-level, never per-resource).
_NOT_GRANTABLE = {Action.ADMINISTER.value}


def _held(authz: AuthorizationService, rtype: ResourceType, rid: uuid.UUID) -> frozenset[str]:
    if rtype == ResourceType.DOCUMENT:
        doc = authz.require_document(rid, Action.MANAGE_ACCESS)
        return authz.document_actions([doc])[doc.id]
    folder = authz.require_folder(rid, Action.MANAGE_ACCESS)
    return authz.folder_actions([folder.id])[folder.id]


def _out(db: Session, grants: list[PermissionGrant]) -> list[PermissionGrantOut]:
    user_ids = [
        g.subject_id for g in grants if g.subject_type == SubjectType.USER.value and g.subject_id
    ]
    group_ids = [
        g.subject_id for g in grants if g.subject_type == SubjectType.GROUP.value and g.subject_id
    ]
    users = (
        {u.id: u for u in db.scalars(select(User).where(User.id.in_(user_ids)))} if user_ids else {}
    )
    groups = (
        {g.id: g for g in db.scalars(select(Group).where(Group.id.in_(group_ids)))}
        if group_ids
        else {}
    )
    out = []
    for g in grants:
        if g.subject_type == SubjectType.USER.value and g.subject_id in users:
            u = users[g.subject_id]
            label: str | None = u.display_name or u.email
        elif g.subject_type == SubjectType.GROUP.value and g.subject_id in groups:
            label = groups[g.subject_id].name
        else:
            label = (
                "Everyone in the organization"
                if g.subject_type == SubjectType.ORGANIZATION.value
                else None
            )
        out.append(
            PermissionGrantOut(
                id=g.id,
                resource_type=g.resource_type,  # type: ignore[arg-type]
                resource_id=g.resource_id,
                subject_type=g.subject_type,  # type: ignore[arg-type]
                subject_id=g.subject_id,
                subject_name=label,
                actions=list(g.actions),
                permissions=to_labels(g.actions, ACL_LABELS),
                inherit=g.inherit,
                expires_at=g.expires_at,
                revoked_at=g.revoked_at,
                created_by=g.created_by,
                created_at=g.created_at,
            )
        )
    return out


def list_grants(
    db: Session, authz: AuthorizationService, rtype: ResourceType, rid: uuid.UUID
) -> list[PermissionGrantOut]:
    _held(authz, rtype, rid)
    grants = list(
        db.scalars(
            select(PermissionGrant)
            .where(
                PermissionGrant.organization_id == authz.principal.organization_id,
                PermissionGrant.resource_type == rtype.value,
                PermissionGrant.resource_id == rid,
                PermissionGrant.revoked_at.is_(None),
            )
            .order_by(PermissionGrant.created_at)
        )
    )
    return _out(db, grants)


def add_grant(
    db: Session,
    authz: AuthorizationService,
    rtype: ResourceType,
    rid: uuid.UUID,
    payload: PermissionGrantIn,
) -> PermissionGrantOut:
    p = authz.principal
    held = _held(authz, rtype, rid)
    requested = set(payload.actions)
    unknown = requested - ALL_ACTIONS
    if unknown:
        raise ValidationFailed(f"Unknown actions: {', '.join(sorted(unknown))}")
    if requested & _NOT_GRANTABLE:
        raise ValidationFailed(
            "The 'administer' capability is an organization role, not a resource grant."
        )
    if not requested <= held:  # no escalation beyond what the grantor holds
        raise ForbiddenError("You cannot grant actions you do not hold.")
    if payload.expires_at is not None and payload.expires_at <= datetime.now(UTC):
        raise ValidationFailed("expires_at must be in the future.")

    subject_id = payload.subject_id
    if payload.subject_type == "user":
        ok = db.scalar(
            select(User.id)
            .join(Membership, Membership.user_id == User.id)
            .where(
                User.id == subject_id,
                Membership.organization_id == p.organization_id,
                User.status != UserStatus.DISABLED.value,
            )
        )
        if ok is None:
            raise ValidationFailed("Unknown user.", code="unknown_subject")
    elif payload.subject_type == "group":
        ok = db.scalar(
            select(Group.id).where(
                Group.id == subject_id, Group.organization_id == p.organization_id
            )
        )
        if ok is None:
            raise ValidationFailed("Unknown group.", code="unknown_subject")

    grant = PermissionGrant(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        resource_type=rtype.value,
        resource_id=rid,
        subject_type=payload.subject_type,
        subject_id=subject_id,
        actions=sorted(requested),
        inherit=payload.inherit if rtype == ResourceType.FOLDER else False,
        expires_at=payload.expires_at,
        created_by=p.user_id,
    )
    db.add(grant)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="permission.granted",
        resource_type=rtype.value,
        resource_id=rid,
        metadata={
            "grant_id": str(grant.id),
            "subject_type": payload.subject_type,
            "subject_id": str(subject_id) if subject_id else None,
            "actions": sorted(requested),
            "inherit": grant.inherit,
        },
    )
    db.commit()
    return _out(db, [grant])[0]


def revoke_grant(
    db: Session,
    authz: AuthorizationService,
    rtype: ResourceType,
    rid: uuid.UUID,
    grant_id: uuid.UUID,
) -> None:
    p = authz.principal
    _held(authz, rtype, rid)
    grant = db.scalar(
        select(PermissionGrant).where(
            PermissionGrant.id == grant_id,
            PermissionGrant.organization_id == p.organization_id,
            PermissionGrant.resource_type == rtype.value,
            PermissionGrant.resource_id == rid,
        )
    )
    if grant is None:
        raise NotFoundError("Permission grant not found.")
    if grant.revoked_at is None:
        grant.revoked_at = datetime.now(UTC)
        grant.revoked_by = p.user_id
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="permission.revoked",
            resource_type=rtype.value,
            resource_id=rid,
            metadata={"grant_id": str(grant.id)},
        )
        db.commit()
