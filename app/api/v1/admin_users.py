"""Administration: user management, policies and activity monitoring (organization scoped)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Response
from sqlalchemy import func, select

from app.api.deps import CurrentPrincipal, DbSession, limited
from app.core.errors import NotFoundError
from app.db.enums import PolicyScope, ResourceType
from app.db.models import Document, Membership, ShareGrant, ShareRecipient
from app.modules.admin_users import service as users
from app.modules.admin_users import transfer
from app.modules.audit import activity
from app.modules.authorization import access_check
from app.modules.policies import service as policies
from app.modules.policies.schema import ENFORCED
from app.modules.users import service as members
from app.schemas.admin_users import (
    ActivityEventOut,
    ActivityPage,
    AdminOut,
    AdminUserCreate,
    AdminUserCreated,
    AdminUserOut,
    AdminUserUpdate,
    AuditPolicyOut,
    DeleteImpact,
    DeleteRequest,
    EffectivePolicyOut,
    ImportPreviewOut,
    ImportRequest,
    ImportResultOut,
    PolicyDocument,
    PolicyPut,
    QuotaOut,
    StatusFilter,
    UserGroupsPut,
    UserShareOut,
)
from app.schemas.common import ApiModel, Page

router = APIRouter(prefix="/admin", tags=["admin-users"])

SortField = Literal["email", "display_name", "last_login_at", "created_at", "username"]
SourceFilter = Literal["default", "invitation", "csv_import", "directory"]


# ---- users
@router.get("/users", response_model=Page[AdminUserOut], summary="Users with profile and state")
def list_users(
    db: DbSession,
    principal: CurrentPrincipal,
    q: str | None = Query(None, max_length=200),
    status: StatusFilter = "all",
    source: SourceFilter | None = None,
    sort: SortField = "email",
    descending: bool = False,
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[AdminUserOut]:
    items, total = users.list_users(
        db,
        principal,
        q=q,
        status=status,
        source=source,
        sort=sort,
        descending=descending,
        limit=limit,
        offset=offset,
    )
    return Page[AdminUserOut](items=items, total=total, limit=limit, offset=offset)


@router.post("/users", response_model=AdminUserCreated, status_code=201, summary="Add a user")
def create_user(
    body: AdminUserCreate, db: DbSession, principal: CurrentPrincipal
) -> AdminUserCreated:
    return AdminUserCreated(
        user=users.create_user(db, principal, body),
        # No email is sent unless a provider is configured; the person signs in through the
        # identity provider and accepts the pending invitation.
        invitation_email="not_configured",
    )


@router.get("/users/export", summary="Export users as CSV (formula-safe, no secrets)")
def export_users(
    db: DbSession,
    principal: CurrentPrincipal,
    q: str | None = Query(None, max_length=200),
    status: StatusFilter = "all",
    source: SourceFilter | None = None,
    _rl: None = limited("admin_export", sensitive=True),
) -> Response:
    data = transfer.export_csv(db, principal, q=q, status=status, source=source)
    return Response(
        data,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="users.csv"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/users/import/template", summary="CSV template for user import")
def import_template(principal: CurrentPrincipal) -> Response:
    members.require_admin(principal)
    return Response(
        transfer.template_csv(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="users-template.csv"'},
    )


@router.post(
    "/users/import/preview",
    response_model=ImportPreviewOut,
    summary="Validate a CSV without changing anything",
    dependencies=[limited("admin_import", sensitive=True)],
)
def import_preview(
    body: ImportRequest, db: DbSession, principal: CurrentPrincipal
) -> ImportPreviewOut:
    return transfer.preview(db, principal, body.csv)


@router.post(
    "/users/import",
    response_model=ImportResultOut,
    summary="Create the valid rows of a CSV (existing accounts are skipped, never overwritten)",
    dependencies=[limited("admin_import", sensitive=True)],
)
def import_users(
    body: ImportRequest, db: DbSession, principal: CurrentPrincipal
) -> ImportResultOut:
    return transfer.commit(db, principal, body.csv)


@router.get("/users/{user_id}", response_model=AdminUserOut, summary="User details")
def get_user(user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AdminUserOut:
    return users.get_user(db, principal, user_id)


@router.patch("/users/{user_id}", response_model=AdminUserOut, summary="Update user details")
def update_user(
    user_id: uuid.UUID, body: AdminUserUpdate, db: DbSession, principal: CurrentPrincipal
) -> AdminUserOut:
    return users.update_user(db, principal, user_id, body)


@router.post("/users/{user_id}/deactivate", response_model=AdminUserOut, summary="Deactivate")
def deactivate_user(user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AdminUserOut:
    return users.set_enabled(db, principal, user_id, False)


@router.post("/users/{user_id}/reactivate", response_model=AdminUserOut, summary="Reactivate")
def reactivate_user(user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AdminUserOut:
    return users.set_enabled(db, principal, user_id, True)


@router.get(
    "/users/{user_id}/delete-impact", response_model=DeleteImpact, summary="What deleting does"
)
def delete_impact(user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> DeleteImpact:
    return users.delete_impact(db, principal, user_id)


@router.post("/users/{user_id}/delete", status_code=204, summary="Remove the account (soft)")
def delete_user(
    user_id: uuid.UUID, body: DeleteRequest, db: DbSession, principal: CurrentPrincipal
) -> Response:
    users.delete_user(
        db, principal, user_id, confirm=body.confirm, confirm_email=body.confirm_email
    )
    return Response(status_code=204)


@router.get("/users/{user_id}/quota", response_model=QuotaOut, summary="Storage usage")
def user_quota(user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> QuotaOut:
    return users.quota(db, principal, user_id)


@router.put(
    "/users/{user_id}/groups", response_model=AdminUserOut, summary="Replace group memberships"
)
def put_user_groups(
    user_id: uuid.UUID, body: UserGroupsPut, db: DbSession, principal: CurrentPrincipal
) -> AdminUserOut:
    return users.replace_groups(db, principal, user_id, body.group_ids)


@router.get(
    "/users/{user_id}/shares", response_model=list[UserShareOut], summary="Shares created by a user"
)
def user_shares(
    user_id: uuid.UUID,
    db: DbSession,
    principal: CurrentPrincipal,
    limit: int = Query(100, ge=1, le=200),
) -> list[UserShareOut]:
    users.get_user(db, principal, user_id)  # existence + admin check, tenant scoped
    rows = db.scalars(
        select(ShareGrant)
        .where(
            ShareGrant.organization_id == principal.organization_id,
            ShareGrant.created_by == user_id,
        )
        .order_by(ShareGrant.created_at.desc())
        .limit(limit)
    ).all()
    counts = dict(
        db.execute(
            select(ShareRecipient.share_grant_id, func.count())
            .where(ShareRecipient.share_grant_id.in_([s.id for s in rows] or [uuid.UUID(int=0)]))
            .group_by(ShareRecipient.share_grant_id)
        ).all()
    )
    doc_names = dict(
        db.execute(
            select(Document.id, Document.name).where(
                Document.organization_id == principal.organization_id,
                Document.id.in_(
                    [s.resource_id for s in rows if s.resource_type == "document"]
                    or [uuid.UUID(int=0)]
                ),
            )
        ).all()
    )
    return [
        UserShareOut(
            id=s.id,
            resource_type=s.resource_type,  # type: ignore[arg-type]
            resource_id=s.resource_id,
            resource_name=doc_names.get(s.resource_id),
            actions=list(s.actions),
            recipient_count=int(counts.get(s.id, 0)),
            created_at=s.created_at,
            expires_at=s.expires_at,
            revoked_at=s.revoked_at,
        )
        for s in rows
    ]


# ---- administrators
@router.get("/admins", response_model=list[AdminOut], summary="Owners, administrators and auditors")
def list_admins(db: DbSession, principal: CurrentPrincipal) -> list[AdminOut]:
    return users.list_admins(db, principal)


# ---- policies
def _policy_doc(
    db: DbSession, principal: CurrentPrincipal, scope: str, scope_id: uuid.UUID | None
) -> PolicyDocument:
    overrides, version = policies.stored_overrides(db, principal.organization_id, scope, scope_id)
    return PolicyDocument(overrides=overrides, version=version)


@router.get("/policies/defaults", summary="Built-in policy values and which settings are enforced")
def policy_defaults(principal: CurrentPrincipal) -> dict[str, object]:
    members.require_admin(principal)
    return {"defaults": policies.defaults(), "enforced": sorted(ENFORCED)}


@router.get(
    "/policies/organization", response_model=PolicyDocument, summary="Organization default policy"
)
def get_org_policy(db: DbSession, principal: CurrentPrincipal) -> PolicyDocument:
    members.require_admin(principal)
    return _policy_doc(db, principal, PolicyScope.ORGANIZATION.value, None)


@router.put(
    "/policies/organization",
    response_model=PolicyDocument,
    summary="Replace the organization default policy",
)
def put_org_policy(body: PolicyPut, db: DbSession, principal: CurrentPrincipal) -> PolicyDocument:
    members.require_admin(principal)
    policies.save(
        db,
        principal,
        PolicyScope.ORGANIZATION.value,
        None,
        body.overrides,
        expected_version=body.expected_version,
    )
    db.commit()
    return _policy_doc(db, principal, PolicyScope.ORGANIZATION.value, None)


@router.get("/groups/{group_id}/policy", response_model=PolicyDocument, summary="Group policy")
def get_group_policy(
    group_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> PolicyDocument:
    members.require_admin(principal)
    policies.require_group(db, principal, group_id)
    return _policy_doc(db, principal, PolicyScope.GROUP.value, group_id)


@router.put(
    "/groups/{group_id}/policy", response_model=PolicyDocument, summary="Replace a group policy"
)
def put_group_policy(
    group_id: uuid.UUID, body: PolicyPut, db: DbSession, principal: CurrentPrincipal
) -> PolicyDocument:
    members.require_admin(principal)
    policies.require_group(db, principal, group_id)
    policies.save(
        db,
        principal,
        PolicyScope.GROUP.value,
        group_id,
        body.overrides,
        expected_version=body.expected_version,
    )
    db.commit()
    return _policy_doc(db, principal, PolicyScope.GROUP.value, group_id)


@router.get(
    "/users/{user_id}/policy", response_model=PolicyDocument, summary="User policy overrides"
)
def get_user_policy(
    user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> PolicyDocument:
    users.get_user(db, principal, user_id)
    return _policy_doc(db, principal, PolicyScope.USER.value, user_id)


@router.put(
    "/users/{user_id}/policy",
    response_model=PolicyDocument,
    summary="Replace user policy overrides",
)
def put_user_policy(
    user_id: uuid.UUID, body: PolicyPut, db: DbSession, principal: CurrentPrincipal
) -> PolicyDocument:
    users.get_user(db, principal, user_id)
    policies.save(
        db,
        principal,
        PolicyScope.USER.value,
        user_id,
        body.overrides,
        expected_version=body.expected_version,
    )
    db.commit()
    return _policy_doc(db, principal, PolicyScope.USER.value, user_id)


@router.post(
    "/users/{user_id}/policy/reset", response_model=PolicyDocument, summary="Remove user overrides"
)
def reset_user_policy(
    user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> PolicyDocument:
    users.get_user(db, principal, user_id)
    policies.reset(db, principal, PolicyScope.USER.value, user_id)
    db.commit()
    return _policy_doc(db, principal, PolicyScope.USER.value, user_id)


@router.get(
    "/users/{user_id}/policy/effective",
    response_model=EffectivePolicyOut,
    summary="Effective policy",
)
def effective_policy(
    user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> EffectivePolicyOut:
    users.get_user(db, principal, user_id)
    eff = policies.effective(db, principal.organization_id, user_id)
    base = policies.effective(db, principal.organization_id, user_id, include_user=False)
    sources = set(eff.provenance.values())
    applied = (
        "user"
        if "user" in sources
        else "group"
        if any(s.startswith("group:") for s in sources)
        else "organization"
        if "organization" in sources
        else "default"
    )
    return EffectivePolicyOut(
        values=eff.values,
        provenance=eff.provenance,
        inherited=base.values,
        inherited_provenance=base.provenance,
        enforced=sorted(ENFORCED),
        applied_from=applied,  # type: ignore[arg-type]
    )


# ---- activity monitoring
@router.get(
    "/activity", response_model=ActivityPage, summary="Organization activity (cursor paged)"
)
def activity_search(
    db: DbSession,
    principal: CurrentPrincipal,
    user_id: uuid.UUID | None = None,
    category: str | None = Query(None, max_length=32),
    action: str | None = Query(None, max_length=100),
    outcome: Literal["success", "denied", "failure"] | None = None,
    resource_type: str | None = Query(None, max_length=50),
    resource_id: uuid.UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    cursor: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    _rl: None = limited("admin_activity"),
) -> ActivityPage:
    return activity.search(
        db,
        principal,
        user_id=user_id,
        category=category,
        action=action,
        outcome=outcome,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since,
        until=until,
        cursor=cursor,
        limit=limit,
    )


@router.get("/activity/export", summary="Export activity as CSV (audited, row-limited)")
def activity_export(
    db: DbSession,
    principal: CurrentPrincipal,
    user_id: uuid.UUID | None = None,
    category: str | None = Query(None, max_length=32),
    action: str | None = Query(None, max_length=100),
    outcome: Literal["success", "denied", "failure"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    _rl: None = limited("admin_export", sensitive=True),
) -> Response:
    data = activity.export_csv(
        db,
        principal,
        user_id=user_id,
        category=category,
        action=action,
        outcome=outcome,
        since=since,
        until=until,
    )
    return Response(
        data,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="activity.csv"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/activity/{event_id}", response_model=ActivityEventOut, summary="One activity event")
def activity_event(
    event_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> ActivityEventOut:
    return activity.get_event(db, principal, event_id)


@router.get(
    "/users/{user_id}/activity", response_model=ActivityPage, summary="Activity timeline of a user"
)
def user_activity(
    user_id: uuid.UUID,
    db: DbSession,
    principal: CurrentPrincipal,
    category: str | None = Query(None, max_length=32),
    action: str | None = Query(None, max_length=100),
    outcome: Literal["success", "denied", "failure"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    cursor: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    _rl: None = limited("admin_activity"),
) -> ActivityPage:
    activity.require_reader(principal)
    # The subject must belong to this organization (also covers removed members, whose history stays readable).
    if (
        db.scalar(
            select(Membership.user_id).where(
                Membership.organization_id == principal.organization_id,
                Membership.user_id == user_id,
            )
        )
        is None
    ):
        raise NotFoundError("User not found.")
    return activity.search(
        db,
        principal,
        user_id=user_id,
        category=category,
        action=action,
        outcome=outcome,
        since=since,
        until=until,
        cursor=cursor,
        limit=limit,
    )


@router.get(
    "/audit-policy", response_model=AuditPolicyOut, summary="What is recorded and for how long"
)
def audit_policy(principal: CurrentPrincipal) -> AuditPolicyOut:
    return activity.audit_policy(principal)


# ---- access check / ACL impact
class AccessCheckRequest(ApiModel):
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    user_id: uuid.UUID


class ImpactRequest(ApiModel):
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    subject_type: Literal["user", "group", "organization"]
    subject_id: uuid.UUID | None = None
    inherit: bool = True


@router.post(
    "/access-check",
    response_model=access_check.AccessCheckOut,
    summary="What can this user do with this item, and why? (same engine as enforcement)",
    dependencies=[limited("access_check")],
)
def access_check_endpoint(
    body: AccessCheckRequest, db: DbSession, principal: CurrentPrincipal
) -> access_check.AccessCheckOut:
    return access_check.check(
        db, principal, ResourceType(body.resource_type), body.resource_id, body.user_id
    )


@router.post(
    "/acl-impact",
    response_model=access_check.ImpactOut,
    summary="Preview how far a grant would reach before making it",
)
def acl_impact(
    body: ImpactRequest, db: DbSession, principal: CurrentPrincipal
) -> access_check.ImpactOut:
    return access_check.impact(
        db,
        principal,
        ResourceType(body.resource_type),
        body.resource_id,
        body.subject_type,
        body.subject_id,
        body.inherit,
    )
