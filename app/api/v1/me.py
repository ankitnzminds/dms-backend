"""Current user, invitations, organization info."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response
from sqlalchemy import select

from app.adapters.identity.base import VerifiedIdentity
from app.api.deps import CurrentPrincipal, DbSession, get_verified_identity
from app.core.errors import ForbiddenError, ValidationFailed
from app.db.enums import UserStatus
from app.db.models import Organization
from app.modules.identity.service import find_or_bind_user
from app.modules.organizations import service as orgs
from app.modules.users import service as users
from app.schemas.admin import MeOut, OrganizationOut, OrganizationUpdate, UsageOut

router = APIRouter(tags=["identity"])

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
        else {"mask_shared_breadcrumbs": settings["mask_shared_breadcrumbs"]},
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
            data[key] = 0
    return UsageOut(**data)
