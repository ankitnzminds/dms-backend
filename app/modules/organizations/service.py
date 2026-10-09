"""Organization settings, bootstrap and usage."""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters.storage.registry import default_provider_type
from app.core.config import get_settings
from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import (
    Action,
    AuditOutcome,
    DocumentStatus,
    MembershipStatus,
    OrgStatus,
    ResourceType,
    Role,
    ScanStatus,
    SubjectType,
    UserStatus,
)
from app.db.models import (
    Document,
    DocumentVersion,
    Folder,
    Group,
    Membership,
    Organization,
    PermissionGrant,
    StorageLocation,
    User,
)
from app.modules.audit import service as audit

ROOT_FOLDER_NAME = "Organization Files"
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

DEFAULT_ORG_SETTINGS: dict[str, Any] = {
    # Hide names of folders the viewer cannot open when showing a shared item's path.
    "mask_shared_breadcrumbs": False,
    # Upper bound for share lifetimes; shares without expiry are rejected when set to a number.
    "max_share_days": 365,
    "require_share_expiry": False,
    # Trashed items are permanently deleted after this many days (None = keep until purged).
    "trash_retention_days": 30,
    # Documents with these classifications cannot be reached through shares (DLP).
    "share_blocked_classifications": ["restricted"],
    # E-signature: off by default; external signers (outside the organization) need an opt-in.
    "signatures_enabled": False,
    "allow_external_signers": False,
}
_SETTING_VALIDATORS = {
    "mask_shared_breadcrumbs": lambda v: isinstance(v, bool),
    "max_share_days": lambda v: (
        v is None or (isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 3650)
    ),
    "require_share_expiry": lambda v: isinstance(v, bool),
    "trash_retention_days": lambda v: (
        v is None or (isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 3650)
    ),
    "signatures_enabled": lambda v: isinstance(v, bool),
    "allow_external_signers": lambda v: isinstance(v, bool),
    "share_blocked_classifications": lambda v: (
        isinstance(v, list)
        and all(x in {"public", "internal", "confidential", "restricted"} for x in v)
    ),
}


def get_org(db: Session, organization_id: uuid.UUID) -> Organization:
    org = db.get(Organization, organization_id)
    if org is None:
        raise NotFoundError("Organization not found.")
    return org


def org_settings(org: Organization) -> dict[str, Any]:
    return {**DEFAULT_ORG_SETTINGS, **(org.settings or {})}


def update_org(
    db: Session,
    org: Organization,
    *,
    name: str | None,
    settings_patch: dict[str, Any] | None,
    actor_id: uuid.UUID,
) -> Organization:
    if name is not None:
        name = name.strip()
        if not 1 <= len(name) <= 200:
            raise ValidationFailed("Organization name must be 1-200 characters.")
        org.name = name
    if settings_patch:
        unknown = set(settings_patch) - set(_SETTING_VALIDATORS)
        if unknown:
            raise ValidationFailed(f"Unknown settings: {', '.join(sorted(unknown))}")
        for key, value in settings_patch.items():
            if not _SETTING_VALIDATORS[key](value):
                raise ValidationFailed(f"Invalid value for setting '{key}'.")
        org.settings = {**(org.settings or {}), **settings_patch}
    audit.record(
        db,
        organization_id=org.id,
        actor_user_id=actor_id,
        action="org.updated",
        resource_type="organization",
        resource_id=org.id,
        metadata={
            "changed_settings": sorted((settings_patch or {}).keys()),
            "renamed": name is not None,
        },
    )
    db.commit()
    return org


def bootstrap_organization(
    db: Session,
    *,
    name: str,
    slug: str,
    owner_email: str,
    owner_display_name: str | None = None,
    quota_bytes: int | None = None,
    member_default_access: bool = True,
) -> Organization:
    """Create an organization with its root folder, default storage location and first owner.

    Only reachable from the operator CLI (``python -m app.cli``): there is deliberately no
    public endpoint that creates organizations or administrators.
    """
    if not _SLUG_RE.match(slug):
        raise ValidationFailed("Slug must be lowercase letters, digits and dashes (2-63 chars).")
    email = owner_email.strip().lower()
    if "@" not in email:
        raise ValidationFailed("Owner email is invalid.")
    settings = get_settings()
    try:
        org = Organization(id=uuid.uuid4(), name=name.strip(), slug=slug)
        if quota_bytes is not None:
            org.quota_bytes = quota_bytes
        db.add(org)
        db.flush()

        location = StorageLocation(
            id=uuid.uuid4(),
            organization_id=org.id,
            provider_type=default_provider_type(settings),
            bucket=settings.supabase_storage_bucket,
            is_default=True,
            secret_ref="env:SUPABASE_SERVICE_ROLE_KEY",  # noqa: S106  # a reference, never the value
        )
        db.add(location)

        root = Folder(id=uuid.uuid4(), organization_id=org.id, name=ROOT_FOLDER_NAME)
        db.add(root)

        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(
                id=uuid.uuid4(),
                email=email,
                display_name=owner_display_name,
                status=UserStatus.INVITED.value,
            )
            db.add(user)
            db.flush()
        db.add(
            Membership(
                id=uuid.uuid4(),
                organization_id=org.id,
                user_id=user.id,
                role=Role.OWNER.value,
                status=(
                    MembershipStatus.ACTIVE.value
                    if user.status == UserStatus.ACTIVE.value
                    else MembershipStatus.INVITED.value
                ),
            )
        )
        db.flush()

        if member_default_access:
            # Members can see the root listing (only what they are separately allowed to see)
            # and create their own folders/files at the top level. Admins can revoke this.
            db.add(
                PermissionGrant(
                    id=uuid.uuid4(),
                    organization_id=org.id,
                    resource_type=ResourceType.FOLDER.value,
                    resource_id=root.id,
                    subject_type=SubjectType.ORGANIZATION.value,
                    subject_id=None,
                    actions=[Action.DISCOVER.value, Action.CREATE_CHILD.value],
                    inherit=False,
                    created_by=user.id,
                )
            )
        audit.record(
            db,
            organization_id=org.id,
            actor_user_id=None,
            action="org.created",
            resource_type="organization",
            resource_id=org.id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"slug": slug, "via": "cli"},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("Organization slug already exists.") from exc
    return org


def root_folder_id(db: Session, organization_id: uuid.UUID) -> uuid.UUID:
    rid = db.scalar(
        select(Folder.id).where(
            Folder.organization_id == organization_id, Folder.parent_folder_id.is_(None)
        )
    )
    if rid is None:
        raise NotFoundError("Organization has no root folder.")
    return rid


def usage(db: Session, org: Organization) -> dict[str, Any]:
    oid = org.id

    def count(model: Any, *where: Any) -> int:
        return int(db.scalar(select(func.count()).select_from(model).where(*where)) or 0)

    return {
        "quota_bytes": org.quota_bytes,
        "used_bytes": org.quota_used_bytes,
        "reserved_bytes": org.quota_reserved_bytes,
        "documents": count(
            Document, Document.organization_id == oid, Document.deleted_at.is_(None)
        ),
        "folders": count(Folder, Folder.organization_id == oid, Folder.deleted_at.is_(None)),
        "versions": count(DocumentVersion, DocumentVersion.organization_id == oid),
        "pending_scans": count(
            DocumentVersion,
            DocumentVersion.organization_id == oid,
            DocumentVersion.scan_status == ScanStatus.PENDING.value,
        ),
        "quarantined_documents": count(
            Document,
            Document.organization_id == oid,
            Document.status == DocumentStatus.QUARANTINED.value,
        ),
        "users": count(
            Membership,
            Membership.organization_id == oid,
            Membership.status == MembershipStatus.ACTIVE.value,
        ),
        "groups": count(Group, Group.organization_id == oid),
        "organization_status": OrgStatus(org.status).value,
    }
