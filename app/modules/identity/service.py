"""Turns a verified identity into a tenant-scoped Principal (authentication != authorization).

Rules enforced here (server side, every request):
  * the user must be provisioned (no self-sign-up) and ``active``
  * tokens issued before ``sessions_valid_after`` are rejected (session revocation)
  * the organization comes from *server-side memberships*; ``X-Organization-Id`` is only a
    selector among organizations the user is already an active member of
  * membership and organization must be active
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.identity.base import VerifiedIdentity
from app.core.errors import ForbiddenError, UnauthorizedError, ValidationFailed
from app.db.enums import AuditOutcome, MembershipStatus, OrgStatus, UserStatus
from app.db.models import GroupMembership, Membership, Organization, User
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal

_LAST_LOGIN_UPDATE_INTERVAL = timedelta(minutes=5)


def find_or_bind_user(db: Session, identity: VerifiedIdentity) -> User:
    user = db.scalar(
        select(User).where(
            User.identity_provider == identity.provider, User.external_subject == identity.subject
        )
    )
    if user is not None:
        return user

    # First login of an invited user: bind the external subject, but only through a
    # *verified* email (otherwise anyone could claim an invitation by typing an address).
    if identity.email and identity.email_verified:
        invited = db.scalar(
            select(User)
            .where(User.email == identity.email, User.external_subject.is_(None))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if invited is not None and invited.status != UserStatus.DISABLED.value:
            invited.identity_provider = identity.provider
            invited.external_subject = identity.subject
            invited.email_verified = True
            if invited.status == UserStatus.INVITED.value:
                invited.status = UserStatus.ACTIVE.value
            if identity.display_name and not invited.display_name:
                invited.display_name = identity.display_name
            for membership in db.scalars(
                select(Membership).where(
                    Membership.user_id == invited.id,
                    Membership.status == MembershipStatus.INVITED.value,
                )
            ):
                membership.status = MembershipStatus.ACTIVE.value
            audit.record(
                db,
                organization_id=None,
                actor_user_id=invited.id,
                action="auth.invitation_accepted",
                resource_type="user",
                resource_id=invited.id,
            )
            db.commit()
            return invited
    raise ForbiddenError("This account is not provisioned for the DMS.", code="not_provisioned")


def assert_session_valid(user: User, identity: VerifiedIdentity) -> None:
    """Tokens issued at/before the user's revocation moment are rejected (sign-out everywhere)."""
    if (
        user.sessions_valid_after is not None
        and identity.issued_at is not None
        and identity.issued_at.replace(microsecond=0)
        <= user.sessions_valid_after.replace(microsecond=0)
    ):
        raise UnauthorizedError(
            "Session has been revoked. Please sign in again.", code="session_revoked"
        )


def resolve_principal(
    db: Session, identity: VerifiedIdentity, requested_org: uuid.UUID | None
) -> Principal:
    user = find_or_bind_user(db, identity)

    if user.status != UserStatus.ACTIVE.value:
        audit.record_independent(
            organization_id=None,
            actor_user_id=user.id,
            action="auth.rejected_inactive_user",
            outcome=AuditOutcome.DENIED,
        )
        raise ForbiddenError("This account is not active.", code="account_inactive")

    assert_session_valid(user, identity)

    now = datetime.now(UTC)
    if user.last_login_at is None or now - user.last_login_at > _LAST_LOGIN_UPDATE_INTERVAL:
        user.last_login_at = now
        db.commit()

    rows = db.execute(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.user_id == user.id,
            Membership.status == MembershipStatus.ACTIVE.value,
            Organization.status == OrgStatus.ACTIVE.value,
        )
    ).all()
    blocked = [
        m
        for m, _ in rows
        if m.account_locked or (m.account_expires_at and m.account_expires_at <= now)
    ]
    rows = [r for r in rows if r[0] not in blocked]
    if blocked and not rows:
        audit.record_independent(
            organization_id=blocked[0].organization_id,
            actor_user_id=user.id,
            action="auth.rejected_locked_account",
            outcome=AuditOutcome.DENIED,
            metadata={"locked": blocked[0].account_locked},
        )
        raise ForbiddenError("This account is locked or has expired.", code="account_locked")
    if not rows:
        raise ForbiddenError("No active organization membership.", code="no_membership")

    memberships = {m.organization_id: m for m, _ in rows}
    if requested_org is not None:
        membership = memberships.get(requested_org)
        if membership is None:
            # Same response whether the org exists or not: no tenant enumeration.
            raise ForbiddenError(
                "No active membership in the requested organization.", code="no_membership"
            )
    elif len(memberships) == 1:
        membership = next(iter(memberships.values()))
    else:
        raise ValidationFailed(
            "Select an organization using the X-Organization-Id header.",
            code="organization_required",
            details={"organization_ids": [str(o) for o in memberships]},
        )

    group_ids = frozenset(
        db.scalars(
            select(GroupMembership.group_id).where(
                GroupMembership.user_id == user.id,
                GroupMembership.organization_id == membership.organization_id,
            )
        )
    )
    return Principal(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        organization_id=membership.organization_id,
        role=membership.role,
        group_ids=group_ids,
    )


def principal_for(db: Session, user_id: uuid.UUID, organization_id: uuid.UUID) -> Principal:
    """Rebuild a Principal from server-side state for background work (agent runs). Fails closed
    if the user, membership or organization is no longer active - access is never cached."""
    row = db.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            User.id == user_id,
            Membership.organization_id == organization_id,
            Membership.status == MembershipStatus.ACTIVE.value,
            Organization.status == OrgStatus.ACTIVE.value,
        )
    ).first()
    if row is None or row[0].status != UserStatus.ACTIVE.value:
        raise ForbiddenError("No active membership.", code="no_membership")
    user, membership = row
    group_ids = frozenset(
        db.scalars(
            select(GroupMembership.group_id).where(
                GroupMembership.user_id == user.id,
                GroupMembership.organization_id == organization_id,
            )
        )
    )
    return Principal(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        organization_id=organization_id,
        role=membership.role,
        group_ids=group_ids,
    )
