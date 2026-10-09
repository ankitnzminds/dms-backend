"""Current user, invitations, organization info."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy import func, or_, select

from app.adapters.identity.base import VerifiedIdentity
from app.api.deps import CurrentPrincipal, DbSession, get_verified_identity, limited
from app.core.errors import ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import UserStatus
from app.db.models import Membership, Organization, User
from app.modules.identity.service import assert_session_valid, find_or_bind_user
from app.modules.organizations import service as orgs
from app.modules.users import service as users
from app.schemas.admin import MeOut, OrganizationOut, OrganizationUpdate, UsageOut
from app.schemas.common import ApiModel, UserRef

router = APIRouter(tags=["identity"])

# Settings that change what a member can do (so forms can pre-validate); nothing sensitive.
_MEMBER_VISIBLE_SETTINGS = (
    "mask_shared_breadcrumbs",
    "max_share_days",
    "require_share_expiry",
    "signatures_enabled",
    "allow_external_signers",
)

_ADMIN_CAPS = [
    "administer",
    "manage_users",
    "manage_groups",
    "manage_permissions",
    "read_audit",
    "manage_organization",
]


def _capabilities(role: str) -> list[str]:
    if role in ("owner", "admin"):
        return _ADMIN_CAPS
    if role == "auditor":
        return ["read_audit"]
    return []


@router.get(
    "/me", response_model=MeOut, summary="Current user, memberships and pending invitations"
)
def me(
    db: DbSession,
    identity: VerifiedIdentity = Depends(get_verified_identity),
    x_organization_id: Annotated[str | None, Header()] = None,
) -> MeOut:
    """Works for any provisioned user, even before they have an active organization."""
    user = find_or_bind_user(db, identity)
    if user.status != UserStatus.ACTIVE.value:
        raise ForbiddenError("This account is not active.", code="account_inactive")
    assert_session_valid(user, identity)
    active, pending = users.membership_views(db, user)
    # Current org mirrors principal resolution: the selected (header) or only active membership.
    current = None
    if x_organization_id:
        current = next((m for m in active if str(m.organization_id) == x_organization_id), None)
    elif len(active) == 1:
        current = active[0]
    return MeOut(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        organization_id=current.organization_id if current else None,
        organization_name=current.organization_name if current else None,
        role=current.role if current else None,
        capabilities=_capabilities(current.role) if current else [],
        memberships=active,
        pending_invitations=pending,
    )


@router.post(
    "/me/invitations/{organization_id}/accept",
    status_code=204,
    summary="Accept an organization invitation",
)
def accept_invitation(
    organization_id: uuid.UUID,
    db: DbSession,
    identity: VerifiedIdentity = Depends(get_verified_identity),
) -> Response:
    user = find_or_bind_user(db, identity)
    if user.status != UserStatus.ACTIVE.value:
        raise ForbiddenError("This account is not active.", code="account_inactive")
    users.accept_invitation(db, user, organization_id)
    return Response(status_code=204)


@router.get("/organization", response_model=OrganizationOut, summary="The caller's organization")
def get_organization(db: DbSession, principal: CurrentPrincipal) -> OrganizationOut:
    org = orgs.get_org(db, principal.organization_id)
    settings = orgs.org_settings(org)
    return OrganizationOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        status=org.status,
        settings=settings
        if principal.is_admin
        else {k: settings[k] for k in _MEMBER_VISIBLE_SETTINGS},
        quota_bytes=org.quota_bytes,
        root_folder_id=orgs.root_folder_id(db, org.id),
    )


@router.patch(
    "/organization",
    response_model=OrganizationOut,
    summary="Update organization name/settings (admin)",
)
def update_organization(
    body: OrganizationUpdate, db: DbSession, principal: CurrentPrincipal
) -> OrganizationOut:
    users.require_admin(principal)
    if body.name is None and not body.settings:
        raise ValidationFailed("Nothing to update.")
    org = orgs.get_org(db, principal.organization_id)
    orgs.update_org(
        db, org, name=body.name, settings_patch=body.settings, actor_id=principal.user_id
    )
    return OrganizationOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        status=org.status,
        settings=orgs.org_settings(org),
        quota_bytes=org.quota_bytes,
        root_folder_id=orgs.root_folder_id(db, org.id),
    )


@router.get(
    "/organization/usage", response_model=UsageOut, summary="Storage and object counts (real data)"
)
def organization_usage(db: DbSession, principal: CurrentPrincipal) -> UsageOut:
    org = db.scalar(select(Organization).where(Organization.id == principal.organization_id))
    assert org is not None
    data = orgs.usage(db, org)
    if not principal.is_admin:
        # Members see their organization's quota usage only, not workforce/security counters.
        for key in ("users", "groups", "pending_scans", "quarantined_documents", "versions"):
            data[key] = None
    return UsageOut(**data)


@router.get(
    "/members/lookup",
    response_model=list[UserRef],
    summary="Find active members by name/e-mail (for choosing recipients; minimal fields)",
    dependencies=[limited("member_lookup")],
)
def lookup_members(
    db: DbSession, principal: CurrentPrincipal, q: str = Query(min_length=2, max_length=100)
) -> list[UserRef]:
    term = q.strip().lower().replace("%", "").replace("_", "")
    if len(term) < 2:  # wildcard-only queries must not enumerate the directory
        return []
    like = f"%{term}%"
    rows = db.execute(
        select(User.id, User.display_name, User.email)
        .join(Membership, Membership.user_id == User.id)
        .where(
            Membership.organization_id == principal.organization_id,
            Membership.status == "active",
            User.status == "active",
            User.id != principal.user_id,
            or_(
                func.lower(User.email).like(like),
                func.lower(func.coalesce(User.display_name, "")).like(like),
            ),
        )
        .order_by(User.email)
        .limit(10)
    ).all()
    return [UserRef(id=i, display_name=n, email=e) for i, n, e in rows]


@router.get(
    "/members/{user_id}",
    response_model=UserRef,
    summary="Name/e-mail of one active member of your organization (to label IDs)",
    dependencies=[limited("member_lookup")],
)
def get_member(user_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> UserRef:
    row = db.execute(
        select(User.id, User.display_name, User.email)
        .join(Membership, Membership.user_id == User.id)
        .where(
            User.id == user_id,
            Membership.organization_id == principal.organization_id,
            Membership.status == "active",
        )
    ).first()
    if row is None:
        raise NotFoundError("Member not found.")
    return UserRef(id=row[0], display_name=row[1], email=row[2])


class LogoutIn(ApiModel):
    everywhere: bool = False


@router.post(
    "/me/logout",
    status_code=204,
    summary="Record a sign-out; everywhere=true also invalidates every token issued so far",
)
def logout(db: DbSession, principal: CurrentPrincipal, body: LogoutIn | None = None) -> Response:
    """The client discards its token on sign-out. Tokens are stateless, so a single token cannot
    be revoked server-side; ``everywhere`` revokes all of this user's tokens issued before now
    (the same mechanism admins use for suspected compromise)."""
    from datetime import UTC, datetime

    from app.modules.audit import service as audit

    everywhere = bool(body and body.everywhere)
    if everywhere:
        user = db.get(User, principal.user_id)
        assert user is not None
        user.sessions_valid_after = datetime.now(UTC)
    audit.record(
        db,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.logout",
        resource_type="user",
        resource_id=principal.user_id,
        metadata={"everywhere": everywhere},
    )
    db.commit()
    return Response(status_code=204)
