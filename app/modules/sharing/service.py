"""Sharing: grants over the ORIGINAL resource (no copies), Shared with Me / Shared by Me, revocation.

Security properties (release-blocking, covered by tests/security):
  * a share never duplicates bytes and never creates a second document identity
  * a document share confers rights on that document only - not its folder, siblings or
    ancestors; the breadcrumb shown to the recipient is context, never navigation rights
  * revocation/expiry take effect on the next request (authorization reads the grant each time)
  * a grantor can only share actions they hold themselves, limited to SHAREABLE_ACTIONS
  * recipients must be active members of the same organization (tenant isolation)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import (
    Action,
    DocumentStatus,
    MembershipStatus,
    RecipientType,
    ResourceType,
    UserStatus,
)
from app.db.models import (
    Document,
    DocumentVersion,
    Folder,
    Group,
    GroupMembership,
    Membership,
    ShareGrant,
    ShareRecipient,
    User,
)
from app.modules.audit import service as audit
from app.modules.authorization.actions import SHAREABLE_ACTIONS, expand_actions
from app.modules.authorization.matrix import SHARE_LABELS, to_labels
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import plain_path
from app.modules.folders.service import mask_policy, to_breadcrumb_out
from app.modules.organizations.service import get_org, org_settings
from app.modules.outbox import service as outbox
from app.modules.policies import service as policies
from app.modules.sharing import links
from app.schemas.common import UserRef
from app.schemas.sharing import (
    ReceivedShare,
    RecipientIn,
    RecipientOut,
    ShareCreate,
    ShareOut,
)

MAX_RECIPIENTS = 50


def share_status(share: ShareGrant, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    if share.revoked_at is not None:
        return "revoked"
    if share.expires_at is not None and share.expires_at <= now:
        return "expired"
    return "active"


def _resolve_recipients(
    db: Session, organization_id: uuid.UUID, self_id: uuid.UUID, items: list[RecipientIn]
) -> list[tuple[str, uuid.UUID]]:
    resolved: dict[tuple[str, uuid.UUID], None] = {}
    for item in items:
        if item.type == "group":
            assert item.id is not None
            found = db.scalar(
                select(Group.id).where(
                    Group.id == item.id, Group.organization_id == organization_id
                )
            )
            if found is None:
                raise ValidationFailed("Unknown recipient group.", code="unknown_recipient")
            resolved[(RecipientType.GROUP.value, found)] = None
            continue
        stmt = (
            select(User.id)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == organization_id,
                Membership.status == MembershipStatus.ACTIVE.value,
                User.status == UserStatus.ACTIVE.value,
            )
        )
        stmt = (
            stmt.where(User.id == item.id)
            if item.id
            else stmt.where(User.email == (item.email or "").strip().lower())
        )
        found_user = db.scalar(stmt)
        if found_user is None:
            # Same message whether the account is unknown, inactive or in another tenant.
            raise ValidationFailed(
                "Recipient must be an active member of this organization. External sharing is not enabled.",
                code="unknown_recipient",
            )
        if found_user == self_id:
            raise ValidationFailed("You cannot share with yourself.", code="invalid_recipient")
        resolved[(RecipientType.USER.value, found_user)] = None
    return list(resolved)


def create_share(
    db: Session,
    authz: AuthorizationService,
    resource_type: ResourceType,
    resource_id: uuid.UUID,
    payload: ShareCreate,
) -> ShareOut:
    p = authz.principal
    if len(payload.recipients) > MAX_RECIPIENTS:
        raise ValidationFailed(f"At most {MAX_RECIPIENTS} recipients per share.")

    if resource_type == ResourceType.DOCUMENT:
        doc = authz.require_document(resource_id, Action.SHARE)
        if doc.status != DocumentStatus.AVAILABLE.value:
            raise ConflictError("Only available documents can be shared.", code="not_available")
        if doc.classification in authz.share_blocked_classifications():
            raise ConflictError(
                f"Documents classified '{doc.classification}' cannot be shared.",
                code="policy_blocked",
            )
        held = authz.document_actions([doc])[doc.id]
        name, path = doc.name, f"{plain_path(db, p.organization_id, doc.folder_id)}/{doc.name}"
        # a file has no inside: nothing about creating or uploading below it
        allowed_pool = SHAREABLE_ACTIONS - {
            Action.CREATE_CHILD.value,
            Action.CREATE_FOLDER.value,
            Action.UPLOAD.value,
            Action.CREATE_FILE.value,
        }
    else:
        folder = authz.require_folder(resource_id, Action.SHARE)
        held = authz.folder_actions([folder.id])[folder.id]
        name, path = folder.name, plain_path(db, p.organization_id, folder.id)
        allowed_pool = SHAREABLE_ACTIONS

    requested = {a for a in payload.actions}
    unknown = requested - {a.value for a in Action}
    if unknown:
        raise ValidationFailed(f"Unknown actions: {', '.join(sorted(unknown))}")
    not_shareable = requested - allowed_pool
    if not_shareable:
        raise ValidationFailed(
            f"These actions cannot be shared: {', '.join(sorted(not_shareable))}",
            code="action_not_shareable",
        )
    # No privilege escalation: you can only hand out what you hold yourself.
    missing = requested - held
    if missing:
        authz.deny(resource_type.value, resource_id, Action.SHARE, "grantor_lacks_actions")
        raise ForbiddenError(
            f"You cannot grant actions you do not hold: {', '.join(sorted(missing))}"
        )
    granted = sorted(expand_actions(requested) - {Action.DISCOVER.value})

    now = datetime.now(UTC)
    settings = org_settings(get_org(db, p.organization_id))
    pol = policies.effective(db, p.organization_id, p.user_id).values["general"]
    if pol["share_mode"] == "no_shares":
        authz.deny(resource_type.value, resource_id, Action.SHARE, "policy_no_shares")
        raise ForbiddenError(
            "Sharing is turned off for your account by an administrator.", code="policy_no_shares"
        )
    expires_at = payload.expires_at
    if expires_at is None and pol["default_share_expiry_days"]:
        expires_at = now + timedelta(days=int(pol["default_share_expiry_days"]))
    if expires_at is not None:
        if expires_at.tzinfo is None:
            raise ValidationFailed("expires_at must include a timezone.")
        if expires_at <= now + timedelta(minutes=1):
            raise ValidationFailed("expires_at must be in the future.")
    if settings["max_share_days"] is not None and expires_at is not None:
        if expires_at > now + timedelta(days=settings["max_share_days"]):
            raise ValidationFailed(f"Shares may last at most {settings['max_share_days']} days.")
    if settings["require_share_expiry"] and expires_at is None:
        raise ValidationFailed("This organization requires shares to have an expiry.")

    recipients = _resolve_recipients(db, p.organization_id, p.user_id, payload.recipients)

    share = ShareGrant(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        resource_type=resource_type.value,
        resource_id=resource_id,
        created_by=p.user_id,
        actions=granted,
        expires_at=expires_at,
        message=payload.message,
    )
    db.add(share)
    db.flush()
    for rtype, rid in recipients:
        db.add(
            ShareRecipient(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                share_grant_id=share.id,
                recipient_type=rtype,
                recipient_id=rid,
            )
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="share.created",
        resource_type=resource_type.value,
        resource_id=resource_id,
        metadata={
            "share_id": str(share.id),
            "path": path,
            "actions": granted,
            "recipients": [{"type": t, "id": str(i)} for t, i in recipients],
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    outbox.enqueue(
        db,
        organization_id=p.organization_id,
        event_type="share.created",
        aggregate_type="share",
        aggregate_id=share.id,
        payload={
            "resource_type": resource_type.value,
            "resource_id": str(resource_id),
            "name": name,
        },
    )
    db.commit()
    return get_share_out(db, authz, share.id, _skip_check=True)


def _load_recipients(
    db: Session, share_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[RecipientOut]]:
    if not share_ids:
        return {}
    rows = db.scalars(
        select(ShareRecipient).where(ShareRecipient.share_grant_id.in_(share_ids))
    ).all()
    user_ids = [r.recipient_id for r in rows if r.recipient_type == RecipientType.USER.value]
    group_ids = [r.recipient_id for r in rows if r.recipient_type == RecipientType.GROUP.value]
    users = (
        {u.id: u for u in db.scalars(select(User).where(User.id.in_(user_ids)))} if user_ids else {}
    )
    groups = (
        {g.id: g for g in db.scalars(select(Group).where(Group.id.in_(group_ids)))}
        if group_ids
        else {}
    )
    defaults = {
        s.id: list(s.actions)
        for s in db.scalars(select(ShareGrant).where(ShareGrant.id.in_(share_ids)))
    }
    out: dict[uuid.UUID, list[RecipientOut]] = defaultdict(list)
    for r in rows:
        labels = to_labels(r.actions or defaults.get(r.share_grant_id, []), SHARE_LABELS)
        if r.recipient_type == RecipientType.USER.value:
            u = users.get(r.recipient_id)
            out[r.share_grant_id].append(
                RecipientOut(
                    type="user",
                    id=r.recipient_id,
                    name=u.display_name if u else None,
                    email=u.email if u else None,
                    permissions=labels,
                )
            )
        elif r.recipient_type == RecipientType.ORGANIZATION.value:
            out[r.share_grant_id].append(
                RecipientOut(
                    type="organization",
                    id=r.recipient_id,
                    name="EVERYONE (the whole organization)",
                    permissions=labels,
                )
            )
        else:
            g = groups.get(r.recipient_id)
            out[r.share_grant_id].append(
                RecipientOut(
                    type="group", id=r.recipient_id, name=g.name if g else None, permissions=labels
                )
            )
    return out


def _resource_names(
    db: Session, org_id: uuid.UUID, shares: list[ShareGrant]
) -> dict[uuid.UUID, str]:
    doc_ids = [s.resource_id for s in shares if s.resource_type == ResourceType.DOCUMENT.value]
    folder_ids = [s.resource_id for s in shares if s.resource_type == ResourceType.FOLDER.value]
    names: dict[uuid.UUID, str] = {}
    if doc_ids:
        names.update(
            db.execute(
                select(Document.id, Document.name).where(
                    Document.id.in_(doc_ids), Document.organization_id == org_id
                )
            ).all()
        )
    if folder_ids:
        names.update(
            db.execute(
                select(Folder.id, Folder.name).where(
                    Folder.id.in_(folder_ids), Folder.organization_id == org_id
                )
            ).all()
        )
    return names


def _user_ref(users: dict[uuid.UUID, User], uid: uuid.UUID) -> UserRef:
    u = users.get(uid)
    return UserRef(id=uid, display_name=u.display_name if u else None, email=u.email if u else None)


def _shares_out(
    db: Session,
    org_id: uuid.UUID,
    shares: list[ShareGrant],
    viewer: AuthorizationService | None = None,
) -> list[ShareOut]:
    users = {
        u.id: u
        for u in db.scalars(
            select(User).where(
                User.id.in_(
                    {s.created_by for s in shares} | {s.owner_id for s in shares if s.owner_id}
                    or {uuid.UUID(int=0)}
                )
            )
        )
    }
    recipients = _load_recipients(db, [s.id for s in shares])
    names = _resource_names(db, org_id, shares)
    now = datetime.now(UTC)
    return [
        ShareOut(
            id=s.id,
            resource_type=s.resource_type,  # type: ignore[arg-type]
            resource_id=s.resource_id,
            resource_name=names.get(s.resource_id),
            created_by=_user_ref(users, s.created_by),
            actions=list(s.actions),
            created_at=s.created_at,
            expires_at=s.expires_at,
            revoked_at=s.revoked_at,
            status=share_status(s, now),  # type: ignore[arg-type]
            message=s.message,
            recipients=recipients.get(s.id, []),
            name=s.name or names.get(s.resource_id),
            owner=_user_ref(users, s.owner_id or s.created_by),
            restricted=s.restricted,
            notify_email=s.notify_email,
            upload_quota_mb=(s.upload_quota_bytes // (1024 * 1024))
            if s.upload_quota_bytes
            else None,
            upload_used_bytes=s.upload_used_bytes,
            link_enabled=s.link_enabled,
            can_manage=bool(viewer and _can_manage(viewer, s)),
            link_url=(
                links.url_for(tok)
                if viewer
                and s.link_enabled
                and _can_manage(viewer, s)
                and (tok := links.decrypt(s.link_token_enc))
                else None
            ),
        )
        for s in shares
    ]


def _can_manage(authz: AuthorizationService, share: ShareGrant) -> bool:
    p = authz.principal
    if p.is_admin or share.created_by == p.user_id:
        return True
    try:
        if share.resource_type == ResourceType.DOCUMENT.value:
            doc = authz.load_document(share.resource_id, include_deleted=True)
            return (
                doc is not None
                and Action.MANAGE_ACCESS.value in authz.document_actions([doc])[doc.id]
            )
        folder = authz.load_folder(share.resource_id, include_deleted=True)
        return (
            folder is not None
            and Action.MANAGE_ACCESS.value in authz.folder_actions([folder.id])[folder.id]
        )
    except NotFoundError:
        return False


def _get_org_share(db: Session, org_id: uuid.UUID, share_id: uuid.UUID) -> ShareGrant | None:
    return db.scalar(
        select(ShareGrant).where(ShareGrant.id == share_id, ShareGrant.organization_id == org_id)
    )


def get_share_out(
    db: Session, authz: AuthorizationService, share_id: uuid.UUID, *, _skip_check: bool = False
) -> ShareOut:
    p = authz.principal
    share = _get_org_share(db, p.organization_id, share_id)
    if share is None:
        raise NotFoundError("Share not found.")
    if not _skip_check:
        is_recipient = db.scalar(
            select(ShareRecipient.id).where(
                ShareRecipient.share_grant_id == share.id,
                or_(
                    and_(
                        ShareRecipient.recipient_type == "user",
                        ShareRecipient.recipient_id == p.user_id,
                    ),
                    and_(
                        ShareRecipient.recipient_type == "group",
                        ShareRecipient.recipient_id.in_(list(p.group_ids) or [uuid.UUID(int=0)]),
                    ),
                ),
            )
        )
        if not (_can_manage(authz, share) or is_recipient):
            raise NotFoundError("Share not found.")
    return _shares_out(db, p.organization_id, [share], authz)[0]


def revoke_share(db: Session, authz: AuthorizationService, share_id: uuid.UUID) -> ShareOut:
    p = authz.principal
    share = _get_org_share(db, p.organization_id, share_id)
    if share is None or not _can_manage(authz, share):
        authz.deny("share", share_id, Action.MANAGE_ACCESS, "revoke_not_permitted")
        raise NotFoundError("Share not found.")
    if share.revoked_at is None:
        share.revoked_at = datetime.now(UTC)
        share.revoked_by = p.user_id
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="share.revoked",
            resource_type=share.resource_type,
            resource_id=share.resource_id,
            metadata={"share_id": str(share.id)},
        )
        outbox.enqueue(
            db,
            organization_id=p.organization_id,
            event_type="share.revoked",
            aggregate_type="share",
            aggregate_id=share.id,
            payload={"resource_type": share.resource_type, "resource_id": str(share.resource_id)},
        )
        db.commit()
    return _shares_out(db, p.organization_id, [share], authz)[0]


def list_sent(
    db: Session,
    authz: AuthorizationService,
    *,
    include_inactive: bool,
    scope_all: bool,
    limit: int,
    offset: int,
) -> tuple[list[ShareOut], int]:
    p = authz.principal
    stmt = select(ShareGrant).where(ShareGrant.organization_id == p.organization_id)
    if scope_all:
        if not p.is_admin:
            raise ForbiddenError("Only administrators can list all shares.")
    else:
        stmt = stmt.where(ShareGrant.created_by == p.user_id)
    shares = list(db.scalars(stmt.order_by(ShareGrant.created_at.desc())))
    now = datetime.now(UTC)
    if not include_inactive:
        shares = [s for s in shares if share_status(s, now) == "active"]
    # Hide shares whose resource has since been deleted.
    names = _resource_names(db, p.organization_id, shares)
    live_doc_ids = set(
        db.scalars(
            select(Document.id).where(
                Document.id.in_([s.resource_id for s in shares] or [uuid.UUID(int=0)]),
                Document.deleted_at.is_(None),
            )
        )
    )
    live_folder_ids = set(
        db.scalars(
            select(Folder.id).where(
                Folder.id.in_([s.resource_id for s in shares] or [uuid.UUID(int=0)]),
                Folder.deleted_at.is_(None),
            )
        )
    )
    shares = [
        s
        for s in shares
        if s.resource_id in names
        and s.resource_id in (live_doc_ids if s.resource_type == "document" else live_folder_ids)
    ]
    page = shares[offset : offset + limit]
    return _shares_out(db, p.organization_id, page, authz), len(shares)


def list_for_resource(
    db: Session, authz: AuthorizationService, resource_type: ResourceType, resource_id: uuid.UUID
) -> list[ShareOut]:
    p = authz.principal
    if resource_type == ResourceType.DOCUMENT:
        doc = authz.require_document(resource_id, Action.SHARE)
        rid = doc.id
    else:
        rid = authz.require_folder(resource_id, Action.SHARE).id
    shares = list(
        db.scalars(
            select(ShareGrant)
            .where(
                ShareGrant.organization_id == p.organization_id,
                ShareGrant.resource_type == resource_type.value,
                ShareGrant.resource_id == rid,
            )
            .order_by(ShareGrant.created_at.desc())
        )
    )
    # Non-managers only see shares they created.
    if not (p.is_admin):
        manage = Action.MANAGE_ACCESS.value in (
            authz.document_actions([doc])[doc.id]
            if resource_type == ResourceType.DOCUMENT
            else authz.folder_actions([rid])[rid]
        )
        if not manage:
            shares = [s for s in shares if s.created_by == p.user_id]
    return _shares_out(db, p.organization_id, shares, authz)


def list_received(
    db: Session, authz: AuthorizationService, *, include_inactive: bool, limit: int, offset: int
) -> tuple[list[ReceivedShare], int]:
    """Shared with Me. For each *active* grant: the original resource + canonical breadcrumb.

    Inactive (expired/revoked) grants are listed only on request and carry no location or
    content details - they exist so the UI can explain why access ended."""
    p = authz.principal
    groups = list(p.group_ids) or [uuid.UUID(int=0)]
    shares = list(
        db.scalars(
            select(ShareGrant)
            .join(
                ShareRecipient,
                and_(
                    ShareRecipient.share_grant_id == ShareGrant.id,
                    ShareRecipient.organization_id == ShareGrant.organization_id,
                ),
            )
            .where(
                ShareGrant.organization_id == p.organization_id,
                or_(
                    and_(
                        ShareRecipient.recipient_type == "user",
                        ShareRecipient.recipient_id == p.user_id,
                    ),
                    and_(
                        ShareRecipient.recipient_type == "group",
                        ShareRecipient.recipient_id.in_(groups),
                    ),
                ),
            )
            .order_by(ShareGrant.created_at.desc())
            .distinct()
        )
    )
    now = datetime.now(UTC)
    statuses = {s.id: share_status(s, now) for s in shares}
    shares = [s for s in shares if include_inactive or statuses[s.id] == "active"]

    doc_ids = [s.resource_id for s in shares if s.resource_type == "document"]
    folder_ids = [s.resource_id for s in shares if s.resource_type == "folder"]
    docs = {
        d.id: d
        for d in db.scalars(
            select(Document).where(
                Document.id.in_(doc_ids or [uuid.UUID(int=0)]),
                Document.organization_id == p.organization_id,
                Document.deleted_at.is_(None),
            )
        )
    }
    folders = {
        f.id: f
        for f in db.scalars(
            select(Folder).where(
                Folder.id.in_(folder_ids or [uuid.UUID(int=0)]),
                Folder.organization_id == p.organization_id,
                Folder.deleted_at.is_(None),
            )
        )
    }
    shares = [
        s for s in shares if s.resource_id in (docs if s.resource_type == "document" else folders)
    ]
    # Documents that are not available (quarantined/processing) are not surfaced.
    shares = [
        s
        for s in shares
        if s.resource_type == "folder"
        or docs[s.resource_id].status == DocumentStatus.AVAILABLE.value
    ]

    active_shares = [s for s in shares if statuses[s.id] == "active"]
    parent_ids = [
        docs[s.resource_id].folder_id for s in active_shares if s.resource_type == "document"
    ] + [
        folders[s.resource_id].parent_folder_id
        for s in active_shares
        if s.resource_type == "folder" and folders[s.resource_id].parent_folder_id
    ]
    crumbs = authz.breadcrumbs_for_folders(
        [pid for pid in parent_ids if pid is not None], mask_unauthorized=mask_policy(db, authz)
    )
    version_ids = [
        docs[s.resource_id].current_version_id
        for s in active_shares
        if s.resource_type == "document" and docs[s.resource_id].current_version_id
    ]
    versions = (
        {
            v.id: v
            for v in db.scalars(select(DocumentVersion).where(DocumentVersion.id.in_(version_ids)))
        }
        if version_ids
        else {}
    )
    users = {
        u.id: u
        for u in db.scalars(
            select(User).where(User.id.in_({s.created_by for s in shares} or {uuid.UUID(int=0)}))
        )
    }

    items: list[ReceivedShare] = []
    for s in shares:
        active = statuses[s.id] == "active"
        if s.resource_type == "document":
            d = docs[s.resource_id]
            v = versions.get(d.current_version_id) if (active and d.current_version_id) else None
            segs = crumbs.get(d.folder_id, []) if active else []
            name = d.name
        else:
            f = folders[s.resource_id]
            v = None
            segs = crumbs.get(f.parent_folder_id, []) if (active and f.parent_folder_id) else []
            name = f.name
        items.append(
            ReceivedShare(
                share_id=s.id,
                resource_type=s.resource_type,  # type: ignore[arg-type]
                resource_id=s.resource_id,
                name=name,
                status=statuses[s.id],  # type: ignore[arg-type]
                shared_by=_user_ref(users, s.created_by),
                actions=list(s.actions) if active else [],
                shared_at=s.created_at,
                expires_at=s.expires_at,
                message=s.message,
                breadcrumb=to_breadcrumb_out(segs),
                size_bytes=v.size_bytes if v else None,
                content_type=v.content_type if v else None,
            )
        )
    return items[offset : offset + limit], len(items)


def expand_group_members(
    db: Session, organization_id: uuid.UUID, share_id: uuid.UUID
) -> set[uuid.UUID]:
    """Concrete user ids addressed by a share right now (used by notification fan-out)."""
    recipients = db.scalars(
        select(ShareRecipient).where(
            ShareRecipient.share_grant_id == share_id,
            ShareRecipient.organization_id == organization_id,
        )
    ).all()
    users = {r.recipient_id for r in recipients if r.recipient_type == RecipientType.USER.value}
    group_ids = [
        r.recipient_id for r in recipients if r.recipient_type == RecipientType.GROUP.value
    ]
    if group_ids:
        users.update(
            db.scalars(
                select(GroupMembership.user_id).where(
                    GroupMembership.group_id.in_(group_ids),
                    GroupMembership.organization_id == organization_id,
                )
            )
        )
    return users
