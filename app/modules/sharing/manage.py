"""Share Link dialog operations: options, link, invitations, groups, per-principal permissions,
history and link resolution.

Rules this module enforces (and the tests check):
  * Only people who can manage a share (its creator, an admin, or someone holding manage on the
    resource) can read or change it; everybody else gets the same 404 as for a missing share.
  * A grant can never exceed what the acting person holds (no escalation); invitations and groups
    start with the minimum (view + preview); share/delete/manage are only ever added explicitly.
  * Expiry, revocation and removal are evaluated by the authorization service on every request.
  * Every change writes a server-side audit event with before/after values (never the link token).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import (
    Action,
    AuditOutcome,
    MembershipStatus,
    RecipientType,
    ResourceType,
    UserStatus,
)
from app.db.models import (
    AuditEvent,
    Document,
    Group,
    Membership,
    ShareGrant,
    ShareRecipient,
    User,
)
from app.modules.audit import service as audit
from app.modules.authorization.actions import SHAREABLE_ACTIONS, expand_actions
from app.modules.authorization.matrix import MINIMUM, SHARE_LABELS, to_actions, to_labels
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import plain_path
from app.modules.organizations.service import get_org, org_settings
from app.modules.outbox import service as outbox
from app.modules.policies import service as policies
from app.modules.sharing import links
from app.modules.sharing import service as base
from app.schemas.common import UserRef
from app.schemas.sharing import (
    InviteResult,
    LinkResolveOut,
    PrincipalPermissions,
    ShareHistoryItem,
    ShareOut,
    ShareUpdate,
)

A = Action
DELEGABLE = SHAREABLE_ACTIONS | {
    A.SHARE.value,
    A.MOVE.value,
    A.COPY.value,
    A.DELETE.value,
    A.RESTORE.value,
    A.MANAGE_ACCESS.value,
    A.SYNC.value,
    A.EXPORT.value,
}
MAX_QUOTA_MB = 10_000_000


# ------------------------------------------------------------------------------- helpers
def _manageable(db: Session, authz: AuthorizationService, share_id: uuid.UUID) -> ShareGrant:
    p = authz.principal
    share = base._get_org_share(db, p.organization_id, share_id)
    if share is None or not base._can_manage(authz, share):
        authz.deny("share", share_id, A.MANAGE_ACCESS, "share_not_manageable")
        raise NotFoundError("Share not found.")
    return share


def _held(db: Session, authz: AuthorizationService, share: ShareGrant) -> frozenset[str]:
    if share.resource_type == ResourceType.DOCUMENT.value:
        doc = authz.load_document(share.resource_id, include_deleted=True)
        if doc is None:
            raise NotFoundError("Share not found.")
        return authz.document_actions([doc])[doc.id]
    folder = authz.load_folder(share.resource_id, include_deleted=True)
    if folder is None:
        raise NotFoundError("Share not found.")
    return authz.folder_actions([folder.id])[folder.id]


def _log(
    db: Session,
    authz: AuthorizationService,
    share: ShareGrant,
    action: str,
    metadata: dict[str, Any] | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
) -> None:
    p = authz.principal
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=action,
        resource_type=share.resource_type,
        resource_id=share.resource_id,
        outcome=outcome,
        metadata={"share_id": str(share.id), **(metadata or {})},
    )


def _out(db: Session, authz: AuthorizationService, share: ShareGrant) -> ShareOut:
    out = base._shares_out(db, authz.principal.organization_id, [share], authz)[0]
    if out.can_manage:
        out.resource_path = _path(db, share)
    return out


def _path(db: Session, share: ShareGrant) -> str | None:
    org = share.organization_id
    if share.resource_type == ResourceType.FOLDER.value:
        return "/" + "/".join(plain_path(db, org, share.resource_id).split("/")[1:])
    doc = db.get(Document, share.resource_id)
    if doc is None:
        return None
    return "/" + "/".join(plain_path(db, org, doc.folder_id).split("/")[1:] + [doc.name])


def _recipient(db: Session, share: ShareGrant, rtype: str, rid: uuid.UUID) -> ShareRecipient | None:
    return db.scalar(
        select(ShareRecipient).where(
            ShareRecipient.share_grant_id == share.id,
            ShareRecipient.recipient_type == rtype,
            ShareRecipient.recipient_id == rid,
        )
    )


def _labels(share: ShareGrant, r: ShareRecipient) -> list[str]:
    return to_labels(r.actions or share.actions, SHARE_LABELS)


def _label_of(db: Session, rtype: str, rid: uuid.UUID) -> str:
    if rtype == RecipientType.USER.value:
        u = db.get(User, rid)
        return u.email if u else str(rid)
    if rtype == RecipientType.GROUP.value:
        g = db.get(Group, rid)
        return f"Group {g.name}" if g else str(rid)
    return "EVERYONE"


# --------------------------------------------------------------------- get or create a share
def share_for_resource(
    db: Session, authz: AuthorizationService, rtype: ResourceType, rid: uuid.UUID
) -> ShareOut:
    """What the Share Link dialog opens: my existing live share of this item, or a new private one
    (nobody but the creator has access until people are invited or the link is enabled)."""
    p = authz.principal
    if rtype == ResourceType.DOCUMENT:
        doc = authz.require_document(rid, A.SHARE)
        name = doc.name
        held = authz.document_actions([doc])[doc.id]
        if doc.classification in authz.share_blocked_classifications():
            raise ConflictError(
                f"Documents classified '{doc.classification}' cannot be shared.",
                code="policy_blocked",
            )
    else:
        folder = authz.require_folder(rid, A.SHARE)
        name = folder.name
        held = authz.folder_actions([folder.id])[folder.id]
    pol = policies.effective(db, p.organization_id, p.user_id).values["general"]
    if pol["share_mode"] == "no_shares":
        authz.deny(rtype.value, rid, A.SHARE, "policy_no_shares")
        raise ForbiddenError(
            "Sharing is turned off for your account by an administrator.", code="policy_no_shares"
        )
    now = datetime.now(UTC)
    existing = db.scalar(
        select(ShareGrant)
        .where(
            ShareGrant.organization_id == p.organization_id,
            ShareGrant.resource_type == rtype.value,
            ShareGrant.resource_id == rid,
            ShareGrant.revoked_at.is_(None),
            or_(ShareGrant.expires_at.is_(None), ShareGrant.expires_at > now),
            or_(ShareGrant.created_by == p.user_id, ShareGrant.owner_id == p.user_id),
        )
        .order_by(ShareGrant.created_at.desc())
    )
    if existing is not None:
        return _out(db, authz, existing)
    default_actions = sorted(expand_actions(set(MINIMUM)) - {A.DISCOVER.value})
    settings = org_settings(get_org(db, p.organization_id))
    expires_at = None
    if pol["default_share_expiry_days"]:
        expires_at = now + timedelta(days=int(pol["default_share_expiry_days"]))
    elif settings["require_share_expiry"] and settings["max_share_days"]:
        expires_at = now + timedelta(days=int(settings["max_share_days"]))
    share = ShareGrant(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        resource_type=rtype.value,
        resource_id=rid,
        created_by=p.user_id,
        owner_id=p.user_id,
        actions=default_actions,
        expires_at=expires_at,
        name=name,
    )
    db.add(share)
    db.flush()
    _log(
        db,
        authz,
        share,
        "share.created",
        {"private": True, "actions": default_actions, "recipients": []},
    )
    _ = held
    db.commit()
    return _out(db, authz, share)


def get_options(db: Session, authz: AuthorizationService, share_id: uuid.UUID) -> ShareOut:
    return _out(db, authz, _manageable(db, authz, share_id))


# ---------------------------------------------------------------------------------- update
def update(
    db: Session, authz: AuthorizationService, share_id: uuid.UUID, body: ShareUpdate
) -> ShareOut:
    p = authz.principal
    share = _manageable(db, authz, share_id)
    if share.revoked_at is not None:
        raise ConflictError("This share has been removed.", code="share_revoked")
    sent = body.model_fields_set
    settings = org_settings(get_org(db, p.organization_id))
    now = datetime.now(UTC)

    if "name" in sent and body.name is not None and body.name.strip() != (share.name or ""):
        old = share.name
        share.name = body.name.strip()
        _log(db, authz, share, "share.renamed", {"from": old, "to": share.name})

    if (
        "owner_id" in sent
        and body.owner_id
        and body.owner_id != (share.owner_id or share.created_by)
    ):
        if not (p.is_admin or p.user_id == (share.owner_id or share.created_by)):
            authz.deny("share", share.id, A.MANAGE_ACCESS, "owner_change_not_permitted")
            raise ForbiddenError(
                "Only an administrator or the current owner can change the share owner."
            )
        active = db.scalar(
            select(User.id)
            .join(Membership, Membership.user_id == User.id)
            .where(
                User.id == body.owner_id,
                User.status == UserStatus.ACTIVE.value,
                Membership.organization_id == p.organization_id,
                Membership.status == MembershipStatus.ACTIVE.value,
            )
        )
        if active is None:
            raise ValidationFailed(
                "The new owner must be an active member of this organization.", code="unknown_owner"
            )
        old_owner = share.owner_id or share.created_by
        share.owner_id = body.owner_id
        _log(
            db,
            authz,
            share,
            "share.owner_changed",
            {"from": str(old_owner), "to": str(body.owner_id)},
        )

    if body.never_expires or body.expires_at is not None:
        old_exp = share.expires_at
        if body.never_expires:
            if settings["require_share_expiry"]:
                raise ValidationFailed("This organization requires shares to have an expiry.")
            new_exp = None
        else:
            new_exp = body.expires_at
            assert new_exp is not None
            if new_exp.tzinfo is None:
                raise ValidationFailed("expires_at must include a timezone.")
            if new_exp <= now + timedelta(minutes=1):
                raise ValidationFailed("expires_at must be in the future.")
            if settings["max_share_days"] is not None and new_exp > now + timedelta(
                days=settings["max_share_days"]
            ):
                raise ValidationFailed(
                    f"Shares may last at most {settings['max_share_days']} days."
                )
        if new_exp != old_exp:
            share.expires_at = new_exp
            share.expiry_recorded_at = (
                None  # an extended share can be reported as expired again later
            )
            _log(
                db,
                authz,
                share,
                "share.expiry_changed",
                {
                    "from": old_exp.isoformat() if old_exp else None,
                    "to": new_exp.isoformat() if new_exp else None,
                },
            )

    if body.unlimited_quota or body.upload_quota_mb is not None:
        old_q = share.upload_quota_bytes
        new_q = None if body.unlimited_quota else int(body.upload_quota_mb or 0) * 1024 * 1024
        if new_q is not None and new_q <= 0:
            raise ValidationFailed("Upload quota must be at least 1 MB.")
        if share.resource_type == ResourceType.DOCUMENT.value and new_q is not None:
            raise ValidationFailed(
                "An upload quota only applies to shared folders.", code="quota_not_applicable"
            )
        if new_q != old_q:
            share.upload_quota_bytes = new_q
            _log(
                db,
                authz,
                share,
                "share.quota_changed",
                {
                    "from_mb": (old_q or 0) // (1024 * 1024) or None,
                    "to_mb": (new_q or 0) // (1024 * 1024) or None,
                },
            )

    if (
        "notify_email" in sent
        and body.notify_email is not None
        and body.notify_email != share.notify_email
    ):
        share.notify_email = body.notify_email
        _log(db, authz, share, "share.notifications_changed", {"to": body.notify_email})

    if "restricted" in sent and body.restricted is not None and body.restricted != share.restricted:
        share.restricted = body.restricted
        _log(db, authz, share, "share.visibility_changed", {"restricted": body.restricted})

    if (
        "link_enabled" in sent
        and body.link_enabled is not None
        and body.link_enabled != share.link_enabled
    ):
        if body.link_enabled and share.link_token_hash is None:
            _issue_token(share)
        share.link_enabled = body.link_enabled
        _log(db, authz, share, "share.link_enabled" if body.link_enabled else "share.link_disabled")
    db.commit()
    return _out(db, authz, share)


def _issue_token(share: ShareGrant) -> None:
    token = links.new_token()
    share.link_token_hash = links.token_hash(token)
    share.link_token_enc = links.encrypt(token)


def rotate_link(db: Session, authz: AuthorizationService, share_id: uuid.UUID) -> ShareOut:
    """New token; the previous link stops working immediately."""
    share = _manageable(db, authz, share_id)
    if share.revoked_at is not None:
        raise ConflictError("This share has been removed.", code="share_revoked")
    _issue_token(share)
    share.link_enabled = True
    _log(db, authz, share, "share.link_rotated")
    db.commit()
    return _out(db, authz, share)


def track_link(db: Session, authz: AuthorizationService, share_id: uuid.UUID, event: str) -> None:
    share = _manageable(db, authz, share_id)
    _log(db, authz, share, f"share.link_{event}")
    db.commit()


# ------------------------------------------------------------------------ invitations & groups
def invite(
    db: Session,
    authz: AuthorizationService,
    share_id: uuid.UUID,
    users: list[Any],
    send_email: bool,
) -> InviteResult:
    p = authz.principal
    share = _manageable(db, authz, share_id)
    if share.revoked_at is not None:
        raise ConflictError("This share has been removed.", code="share_revoked")
    pol = policies.effective(db, p.organization_id, p.user_id).values["user_policy"]
    if pol["disable_invitations"]:
        authz.deny("share", share.id, A.SHARE, "policy_invitations_disabled")
        raise ForbiddenError(
            "Inviting people is turned off for your account by an administrator.",
            code="policy_invitations_disabled",
        )
    resolved = base._resolve_recipients(db, p.organization_id, p.user_id, users)
    invited: list[str] = []
    skipped: list[str] = []
    for rtype, rid in resolved:
        label = _label_of(db, rtype, rid)
        if _recipient(db, share, rtype, rid) is not None:
            skipped.append(f"{label}: already has access through this share")
            continue
        db.add(
            ShareRecipient(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                share_grant_id=share.id,
                recipient_type=rtype,
                recipient_id=rid,
                actions=sorted(expand_actions(set(MINIMUM)) - {A.DISCOVER.value}),
                created_by=p.user_id,
            )
        )
        invited.append(label)
        _log(
            db,
            authz,
            share,
            "share.user_invited",
            {"user_id": str(rid), "permissions": ["view"], "send_email": send_email},
        )
    email = "off"
    if invited and send_email and share.notify_email:
        outbox.enqueue(
            db,
            organization_id=p.organization_id,
            event_type="share.created",
            aggregate_type="share",
            aggregate_id=share.id,
            payload={
                "resource_type": share.resource_type,
                "resource_id": str(share.resource_id),
                "name": share.name or "item",
            },
        )
        email = "queued" if get_settings().email_provider != "none" else "not_configured"
    db.commit()
    return InviteResult(share=_out(db, authz, share), invited=invited, skipped=skipped, email=email)  # type: ignore[arg-type]


def add_group(
    db: Session,
    authz: AuthorizationService,
    share_id: uuid.UUID,
    group_id: uuid.UUID | None,
    everyone: bool,
    confirm_broad: bool,
) -> ShareOut:
    p = authz.principal
    share = _manageable(db, authz, share_id)
    if share.revoked_at is not None:
        raise ConflictError("This share has been removed.", code="share_revoked")
    if everyone == (group_id is not None):
        raise ValidationFailed("Choose either a group or EVERYONE.")
    pol = policies.effective(db, p.organization_id, p.user_id).values["user_policy"]
    if everyone:
        if pol["disable_everyone_group_sharing"]:
            authz.deny("share", share.id, A.SHARE, "policy_everyone_disabled")
            raise ForbiddenError(
                "Sharing with EVERYONE is turned off for your account by an administrator.",
                code="policy_everyone_disabled",
            )
        if not confirm_broad:
            raise ValidationFailed(
                "EVERYONE gives every member of the organization access. Confirm to continue.",
                code="broad_confirmation",
            )
        rtype, rid, label = RecipientType.ORGANIZATION.value, p.organization_id, "EVERYONE"
    else:
        assert group_id is not None
        group = db.scalar(
            select(Group).where(Group.id == group_id, Group.organization_id == p.organization_id)
        )
        if group is None:
            raise ValidationFailed("Unknown group.", code="unknown_recipient")
        rtype, rid, label = RecipientType.GROUP.value, group.id, f"Group {group.name}"
    if _recipient(db, share, rtype, rid) is not None:
        raise ConflictError(
            "That group already has access through this share.", code="already_member"
        )
    db.add(
        ShareRecipient(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            share_grant_id=share.id,
            recipient_type=rtype,
            recipient_id=rid,
            actions=sorted(expand_actions(set(MINIMUM)) - {A.DISCOVER.value}),
            created_by=p.user_id,
        )
    )
    _log(
        db,
        authz,
        share,
        "share.group_added",
        {"principal": label, "type": rtype, "id": str(rid), "permissions": ["view"]},
    )
    db.commit()
    return _out(db, authz, share)


def remove_recipient(
    db: Session, authz: AuthorizationService, share_id: uuid.UUID, rtype: str, rid: uuid.UUID
) -> ShareOut:
    share = _manageable(db, authz, share_id)
    r = _recipient(db, share, rtype, rid)
    if r is None:
        raise NotFoundError("That person or group is not part of this share.")
    label = _label_of(db, rtype, rid)
    db.delete(r)
    _log(
        db,
        authz,
        share,
        "share.principal_removed" if rtype == "user" else "share.group_removed",
        {"principal": label, "type": rtype, "id": str(rid)},
    )
    db.commit()
    return _out(db, authz, share)


def set_permissions(
    db: Session, authz: AuthorizationService, share_id: uuid.UUID, items: list[PrincipalPermissions]
) -> ShareOut:
    share = _manageable(db, authz, share_id)
    if share.revoked_at is not None:
        raise ConflictError("This share has been removed.", code="share_revoked")
    held = _held(db, authz, share)
    for item in items:
        r = _recipient(db, share, item.type, item.id)
        if r is None:
            raise NotFoundError("That person or group is not part of this share.")
        wanted = set(to_actions(item.permissions, SHARE_LABELS))
        if not wanted <= DELEGABLE:
            raise ValidationFailed(
                "That permission cannot be given through a share.", code="action_not_shareable"
            )
        missing = wanted - set(held)
        if missing:
            authz.deny("share", share.id, A.MANAGE_ACCESS, "grantor_lacks_actions")
            raise ForbiddenError(
                f"You cannot grant permissions you do not hold: {', '.join(sorted(missing))}"
            )
        before = _labels(share, r)
        after = [x for x in SHARE_LABELS if x in item.permissions]
        if before != after:
            r.actions = sorted(expand_actions(wanted) - {A.DISCOVER.value})
            _log(
                db,
                authz,
                share,
                "share.permissions_changed",
                {
                    "principal": _label_of(db, item.type, item.id),
                    "type": item.type,
                    "id": str(item.id),
                    "from": before,
                    "to": after,
                },
            )
    db.commit()
    return _out(db, authz, share)


# ------------------------------------------------------------------------------ removal (revoke)
def remove_share(db: Session, authz: AuthorizationService, share_id: uuid.UUID) -> ShareOut:
    """Remove Share: revoke the share and its link. New requests are denied immediately because the
    authorization service reads ``revoked_at`` on every call."""
    share = _manageable(db, authz, share_id)
    if share.revoked_at is None:
        share.link_enabled = False
        out = base.revoke_share(db, authz, share_id)
        return out
    return _out(db, authz, share)


# ------------------------------------------------------------------------------------ history
def _join(v: Any) -> str:
    return ", ".join(v) if isinstance(v, list) and v else "—"


def _summary(action: str, m: dict[str, Any]) -> str:
    who = m.get("principal") or ""
    table = {
        "share.created": "Shared privately" if m.get("private") else "Share created",
        "share.user_invited": f"Invited {who or 'a person'}" if who else "Invited a person",
        "share.group_added": f"Added {who}",
        "share.group_removed": f"Removed {who}",
        "share.principal_removed": f"Removed {who}",
        "share.permissions_changed": f"Changed permissions of {who}: {_join(m.get('from'))} → {_join(m.get('to'))}",
        "share.expiry_changed": f"Expiry changed: {m.get('from') or 'never'} → {m.get('to') or 'never'}",
        "share.renamed": f"Renamed: {m.get('from')} → {m.get('to')}",
        "share.owner_changed": "Owner changed",
        "share.quota_changed": f"Upload quota changed: {m.get('from_mb') or 'unlimited'} → {m.get('to_mb') or 'unlimited'} MB",
        "share.notifications_changed": f"Email notifications {'on' if m.get('to') else 'off'}",
        "share.visibility_changed": "Restricted to selected people and groups"
        if m.get("restricted")
        else "Open to anyone with the link",
        "share.link_enabled": "Link enabled",
        "share.link_disabled": "Link disabled",
        "share.link_rotated": "Link reissued; the previous link stopped working",
        "share.link_copied": "Link copied",
        "share.link_opened": "Link opened",
        "share.link_emailed": "Link sent by email",
        "share.link_accepted": "Joined through the link",
        "share.revoked": "Share removed",
        "share.expired": "Share expired",
    }
    return table.get(action, action.replace("share.", "").replace("_", " ").capitalize())


def history(
    db: Session, authz: AuthorizationService, share_id: uuid.UUID, *, limit: int, offset: int
) -> tuple[list[ShareHistoryItem], int]:
    p = authz.principal
    share = _manageable(db, authz, share_id)
    stmt = select(AuditEvent).where(
        AuditEvent.organization_id == p.organization_id,
        AuditEvent.action.like("share.%"),
        AuditEvent.resource_id == share.resource_id,
        AuditEvent.event_metadata["share_id"].astext == str(share.id),
    )
    from sqlalchemy import func

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(
        db.scalars(
            stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    actors = {
        u.id: u
        for u in db.scalars(
            select(User).where(
                User.id.in_(
                    {r.actor_user_id for r in rows if r.actor_user_id} or {uuid.UUID(int=0)}
                )
            )
        )
    }
    out = []
    for e in rows:
        meta = {k: v for k, v in (e.event_metadata or {}).items() if k not in ("share_id",)}
        u = actors.get(e.actor_user_id) if e.actor_user_id else None
        out.append(
            ShareHistoryItem(
                id=e.id,
                occurred_at=e.created_at,
                action=e.action,
                summary=_summary(e.action, meta),
                actor=UserRef(id=u.id, display_name=u.display_name, email=u.email) if u else None,
                outcome=e.outcome,  # type: ignore[arg-type]
                details=meta,
                ip_address=e.ip_address if p.is_admin else None,
            )
        )
    return out, int(total)


# --------------------------------------------------------------------------- link resolution
def _share_by_token(db: Session, token: str) -> ShareGrant | None:
    return db.scalar(
        select(ShareGrant).where(ShareGrant.link_token_hash == links.token_hash(token))
    )


def link_is_live(share: ShareGrant | None) -> bool:
    now = datetime.now(UTC)
    return bool(
        share
        and share.link_enabled
        and share.revoked_at is None
        and (share.expires_at is None or share.expires_at > now)
    )


def resolve_link(db: Session, authz: AuthorizationService, token: str) -> LinkResolveOut:
    """A signed-in member opens a share link. Restricted shares open only for people already on
    the share; open shares add the member (their permissions are the share's defaults)."""
    p = authz.principal
    share = _share_by_token(db, token)
    if share is None or share.organization_id != p.organization_id or not link_is_live(share):
        raise NotFoundError(
            "This link is not valid."
        )  # same answer for wrong, expired, revoked, other tenant
    me = _recipient(db, share, RecipientType.USER.value, p.user_id)
    in_group = any(_recipient(db, share, RecipientType.GROUP.value, g) for g in p.group_ids)
    everyone = _recipient(db, share, RecipientType.ORGANIZATION.value, p.organization_id)
    allowed = bool(me or in_group or everyone or base._can_manage(authz, share))
    joined = False
    if not allowed:
        if share.restricted:
            raise NotFoundError("This link is not valid.")
        db.add(
            ShareRecipient(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                share_grant_id=share.id,
                recipient_type=RecipientType.USER.value,
                recipient_id=p.user_id,
                actions=None,
                created_by=None,
            )
        )
        _log(db, authz, share, "share.link_accepted", {"user_id": str(p.user_id)})
        joined = True
    else:
        _log(db, authz, share, "share.link_opened")
    names = base._resource_names(db, p.organization_id, [share])
    db.commit()
    return LinkResolveOut(
        resource_type=share.resource_type,  # type: ignore[arg-type]
        resource_id=share.resource_id,
        name=names.get(share.resource_id, "Shared item"),
        joined=joined,
    )
