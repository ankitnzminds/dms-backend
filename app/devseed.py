"""Seed data for the LOCAL development stack only (never used in staging/production)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.enums import MembershipStatus, UserStatus
from app.db.models import Folder, Group, GroupMembership, Membership, Organization, User
from app.modules.organizations.service import bootstrap_organization, root_folder_id

DEV_ORG_SLUG = "acme-dev"
DEV_USERS = [
    ("alice@acme.test", "Alice Owner", "owner"),
    ("bob@acme.test", "Bob Member", "member"),
    ("carol@acme.test", "Carol Member", "member"),
    ("dave@acme.test", "Dave Auditor", "auditor"),
]


def seed_dev(db: Session) -> Organization:
    settings = get_settings()
    if settings.is_production_like or settings.auth_provider != "local":
        raise RuntimeError("seed_dev is for the local development stack only")
    org = db.scalar(select(Organization).where(Organization.slug == DEV_ORG_SLUG))
    if org is not None:
        return org
    org = bootstrap_organization(
        db,
        name="Acme Corp (dev)",
        slug=DEV_ORG_SLUG,
        owner_email=DEV_USERS[0][0],
        owner_display_name=DEV_USERS[0][1],
        quota_bytes=2 * 1024**3,
    )
    users: dict[str, User] = {}
    for email, name, role in DEV_USERS:
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(id=uuid.uuid4(), email=email, display_name=name)
            db.add(user)
            db.flush()
        user.status = UserStatus.ACTIVE.value
        user.identity_provider = "local"
        user.external_subject = f"local-{email.split('@')[0]}"
        user.email_verified = True
        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == user.id, Membership.organization_id == org.id
            )
        )
        if membership is None:
            membership = Membership(id=uuid.uuid4(), organization_id=org.id, user_id=user.id)
            db.add(membership)
        membership.role = role
        membership.status = MembershipStatus.ACTIVE.value
        users[email] = user
    db.flush()

    finance = Group(id=uuid.uuid4(), organization_id=org.id, name="Finance", kind="department")
    engineering = Group(
        id=uuid.uuid4(), organization_id=org.id, name="Engineering", kind="department"
    )
    db.add_all([finance, engineering])
    db.flush()
    db.add(
        GroupMembership(
            group_id=finance.id, user_id=users["carol@acme.test"].id, organization_id=org.id
        )
    )
    db.add(
        GroupMembership(
            group_id=engineering.id, user_id=users["bob@acme.test"].id, organization_id=org.id
        )
    )

    root = root_folder_id(db, org.id)
    alice = users["alice@acme.test"]
    for name in ("Contracts", "HR", "Engineering"):
        db.add(
            Folder(
                id=uuid.uuid4(),
                organization_id=org.id,
                parent_folder_id=root,
                name=name,
                created_by=alice.id,
            )
        )
    db.commit()
    return org
