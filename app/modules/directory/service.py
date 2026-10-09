"""Directory provisioning: sources and an idempotent, guarded sync engine (ADR-0012).

Principles
  * Identity is keyed by the directory's stable external id, never by display name/DN.
  * Authentication (SSO) is separate: provisioning creates *invited* accounts; a person binds
    their login by signing in with a verified e-mail (see app.modules.identity.service).
  * Deprovisioning (account disabled / removed from the directory) removes DMS access and
    invalidates existing sessions immediately.
  * Fail safe: an empty or implausibly shrunken directory response aborts the run instead of
    mass-removing people; administrators/owners are never auto-removed unless explicitly allowed;
    memberships changed manually by an admin are not overridden.
  * Only objects this source manages (linked by external id) are ever touched.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.adapters.directory.base import DirectoryError, DirSnapshot
from app.adapters.directory.providers import build_provider
from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import AuditOutcome, MembershipStatus, Role, UserStatus
from app.db.models import (
    DirectoryGroupLink,
    DirectorySource,
    DirectorySyncRun,
    DirectoryUserLink,
    Group,
    GroupMembership,
    Membership,
    PermissionGrant,
    ShareRecipient,
    User,
)
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.outbox import service as outbox
from app.modules.users.service import require_admin
from app.schemas.directory import (
    DirectorySourceIn,
    DirectorySourceOut,
    DirectorySourceUpdate,
    SnapshotIn,
    SyncRunOut,
)

_SECRET_REF = re.compile(r"^env:DMS_DIR_[A-Z0-9_]{1,80}$")
MAX_REMOVAL_FRACTION = 0.3
MIN_REMOVAL_GUARD = 5
MAX_SNAPSHOT_USERS = 20_000


class SyncAborted(Exception):
    """A safety guard stopped the run before any change was committed."""


@dataclass
class Stats:
    counters: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def inc(self, key: str, n: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + n


# ---------------------------------------------------------------- source CRUD
def _out(s: DirectorySource) -> DirectorySourceOut:
    cfg = dict(s.config or {})
    cfg.pop("users", None)  # never return the (possibly large / sensitive) uploaded snapshot
    cfg.pop("groups", None)
    return DirectorySourceOut(
        id=s.id,
        name=s.name,
        kind=s.kind,
        config=cfg,  # type: ignore[arg-type]
        secret_ref=s.secret_ref,
        enabled=s.enabled,
        sync_interval_minutes=s.sync_interval_minutes,
        last_sync_at=s.last_sync_at,
        has_snapshot=bool((s.config or {}).get("users")),
    )


def _validate_config(kind: str, config: dict[str, Any], secret_ref: str | None) -> None:
    if secret_ref is not None:
        if not _SECRET_REF.match(secret_ref):
            raise ValidationFailed(
                "secret_ref must look like env:DMS_DIR_<NAME>.", code="invalid_secret_ref"
            )
    if kind == "entra" and not (config.get("tenant_id") and config.get("client_id")):
        raise ValidationFailed("Entra sources need tenant_id and client_id.")
    if kind == "ldap":
        uri = str(config.get("server_uri", ""))
        if not (
            uri.startswith("ldaps://") or (uri.startswith("ldap://") and config.get("start_tls"))
        ):
            raise ValidationFailed(
                "LDAP sources must use ldaps:// (or ldap:// with start_tls=true).",
                code="insecure_ldap",
            )
        if not (config.get("bind_dn") and config.get("base_dn_users")):
            raise ValidationFailed("LDAP sources need bind_dn and base_dn_users.")


def list_sources(db: Session, p: Principal) -> list[DirectorySourceOut]:
    require_admin(p)
    return [
        _out(s)
        for s in db.scalars(
            select(DirectorySource)
            .where(DirectorySource.organization_id == p.organization_id)
            .order_by(DirectorySource.name)
        )
    ]


def create_source(db: Session, p: Principal, body: DirectorySourceIn) -> DirectorySourceOut:
    require_admin(p)
    _validate_config(body.kind, body.config, body.secret_ref)
    s = DirectorySource(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=body.name.strip(),
        kind=body.kind,
        config=body.config,
        secret_ref=body.secret_ref,
        sync_interval_minutes=body.sync_interval_minutes,
        created_by=p.user_id,
    )
    db.add(s)
    try:
        db.flush()
    except Exception as exc:
        db.rollback()
        raise ConflictError(
            "A source with this name already exists.", code="name_conflict"
        ) from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="directory_source.created",
        resource_type="directory_source",
        resource_id=s.id,
        metadata={"kind": s.kind, "name": s.name},
    )
    db.commit()
    return _out(s)


def _source(db: Session, p: Principal, source_id: uuid.UUID) -> DirectorySource:
    s = db.scalar(
        select(DirectorySource).where(
            DirectorySource.id == source_id, DirectorySource.organization_id == p.organization_id
        )
    )
    if s is None:
        raise NotFoundError("Directory source not found.")
    return s


def update_source(
    db: Session, p: Principal, source_id: uuid.UUID, body: DirectorySourceUpdate
) -> DirectorySourceOut:
    require_admin(p)
    s = _source(db, p, source_id)
    if body.config is not None:
        new_cfg = {**body.config}
        if (
            s.kind == "static"
        ):  # keep the uploaded snapshot unless replaced via the snapshot endpoint
            new_cfg.setdefault("users", (s.config or {}).get("users", []))
            new_cfg.setdefault("groups", (s.config or {}).get("groups", []))
        _validate_config(
            s.kind, new_cfg, body.secret_ref if body.secret_ref is not None else s.secret_ref
        )
        s.config = new_cfg
    if body.secret_ref is not None:
        _validate_config(s.kind, s.config or {}, body.secret_ref)
        s.secret_ref = body.secret_ref
    if body.enabled is not None:
        s.enabled = body.enabled
    if "sync_interval_minutes" in body.model_fields_set:
        s.sync_interval_minutes = body.sync_interval_minutes
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="directory_source.updated",
        resource_type="directory_source",
        resource_id=s.id,
    )
    db.commit()
    return _out(s)


def delete_source(db: Session, p: Principal, source_id: uuid.UUID) -> None:
    require_admin(p)
    s = _source(db, p, source_id)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="directory_source.deleted",
        resource_type="directory_source",
        resource_id=s.id,
        metadata={"name": s.name},
    )
    db.delete(s)  # links/runs cascade; users and groups already provisioned are left as they are
    db.commit()


def upload_snapshot(
    db: Session, p: Principal, source_id: uuid.UUID, body: SnapshotIn
) -> DirectorySourceOut:
    require_admin(p)
    s = _source(db, p, source_id)
    if s.kind != "static":
        raise ConflictError(
            "Snapshots can only be uploaded to 'static' sources.", code="invalid_state"
        )
    if len(body.users) > MAX_SNAPSHOT_USERS:
        raise ValidationFailed(f"At most {MAX_SNAPSHOT_USERS} users per snapshot.")
    s.config = {
        **(s.config or {}),
        "users": [u.model_dump() for u in body.users],
        "groups": [g.model_dump() for g in body.groups],
    }
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="directory_source.snapshot_uploaded",
        resource_type="directory_source",
        resource_id=s.id,
        metadata={"users": len(body.users), "groups": len(body.groups)},
    )
    db.commit()
    return _out(s)


# ------------------------------------------------------------------- running
def request_sync(db: Session, p: Principal, source_id: uuid.UUID, *, dry_run: bool) -> SyncRunOut:
    require_admin(p)
    s = _source(db, p, source_id)
    if not s.enabled:
        raise ConflictError("This source is disabled.", code="source_disabled")
    running = db.scalar(
        select(DirectorySyncRun.id).where(
            DirectorySyncRun.source_id == s.id, DirectorySyncRun.state == "running"
        )
    )
    if running:
        raise ConflictError("A sync is already running for this source.", code="sync_running")
    run = DirectorySyncRun(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        source_id=s.id,
        dry_run=dry_run,
        triggered_by=p.user_id,
    )
    db.add(run)
    outbox.enqueue(
        db,
        organization_id=p.organization_id,
        event_type="directory.sync",
        aggregate_type="directory_sync_run",
        aggregate_id=run.id,
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="directory.sync_requested",
        resource_type="directory_source",
        resource_id=s.id,
        metadata={"dry_run": dry_run, "run_id": str(run.id)},
    )
    db.commit()
    return _run_out(run, s.name)


def _run_out(r: DirectorySyncRun, source_name: str | None = None) -> SyncRunOut:
    return SyncRunOut(
        id=r.id,
        source_id=r.source_id,
        source_name=source_name,
        state=r.state,  # type: ignore[arg-type]
        dry_run=r.dry_run,
        stats=r.stats or {},
        error=r.error,
        started_at=r.started_at,
        finished_at=r.finished_at,
    )


def list_runs(db: Session, p: Principal, source_id: uuid.UUID, limit: int = 20) -> list[SyncRunOut]:
    require_admin(p)
    s = _source(db, p, source_id)
    runs = db.scalars(
        select(DirectorySyncRun)
        .where(DirectorySyncRun.source_id == s.id)
        .order_by(DirectorySyncRun.started_at.desc())
        .limit(limit)
    )
    return [_run_out(r, s.name) for r in runs]


def get_run(db: Session, p: Principal, run_id: uuid.UUID) -> SyncRunOut:
    require_admin(p)
    r = db.scalar(
        select(DirectorySyncRun).where(
            DirectorySyncRun.id == run_id, DirectorySyncRun.organization_id == p.organization_id
        )
    )
    if r is None:
        raise NotFoundError("Sync run not found.")
    return _run_out(r)


def execute_run(factory: sessionmaker[Session], run_id: uuid.UUID) -> str:
    """Worker side. Reads the directory with no locks held, then applies it in one transaction."""
    with factory() as db:
        run = db.get(DirectorySyncRun, run_id)
        if run is None or run.state != "running":
            return "skipped"
        source = db.get(DirectorySource, run.source_id)
        assert source is not None
        kind, config, secret_ref = source.kind, dict(source.config or {}), source.secret_ref
        org_id, dry_run, source_id = run.organization_id, run.dry_run, run.source_id

    def finish(state: str, stats: dict[str, Any] | None = None, error: str | None = None) -> str:
        with factory() as db:
            r = db.get(DirectorySyncRun, run_id)
            assert r is not None
            r.state, r.finished_at, r.error = state, datetime.now(UTC), error
            if stats is not None:
                r.stats = stats
            src = db.get(DirectorySource, r.source_id)
            if src is not None and state == "succeeded" and not dry_run:
                src.last_sync_at = datetime.now(UTC)
            audit.record(
                db,
                organization_id=org_id,
                actor_user_id=None,
                action=f"directory.sync_{state}",
                resource_type="directory_source",
                resource_id=r.source_id,
                outcome=AuditOutcome.SUCCESS if state == "succeeded" else AuditOutcome.FAILURE,
                metadata={
                    "run_id": str(run_id),
                    "dry_run": dry_run,
                    **(stats or {}),
                    **({"error": error[:200]} if error else {}),
                },
            )
            db.commit()
        return state

    try:
        snapshot = build_provider(kind, config, secret_ref).fetch()
    except DirectoryError as exc:
        return finish("failed", error=str(exc)[:500])
    except Exception as exc:  # defensive: provider bugs must not wedge the queue
        return finish("failed", error=f"{type(exc).__name__}: {str(exc)[:300]}")

    with factory() as db:
        try:
            stats = apply_snapshot(
                db,
                org_id,
                source_id=source_id,
                snapshot=snapshot,
                allow_admin_deprovision=bool(config.get("allow_admin_deprovision")),
            )
            if dry_run:
                db.rollback()
            else:
                db.commit()
        except SyncAborted as exc:
            db.rollback()
            return finish("aborted", error=str(exc))
        except Exception as exc:
            db.rollback()
            return finish("failed", error=f"{type(exc).__name__}: {str(exc)[:300]}")
    return finish("succeeded", {**stats.counters, "notes": stats.notes[:20]})


def schedule_due(db: Session) -> int:
    """Maintenance: queue syncs for sources whose interval elapsed."""
    now = datetime.now(UTC)
    queued = 0
    for s in db.scalars(
        select(DirectorySource).where(
            DirectorySource.enabled.is_(True), DirectorySource.sync_interval_minutes.is_not(None)
        )
    ):
        due = s.last_sync_at is None or s.last_sync_at < now - timedelta(
            minutes=s.sync_interval_minutes or 0
        )
        busy = db.scalar(
            select(DirectorySyncRun.id).where(
                DirectorySyncRun.source_id == s.id, DirectorySyncRun.state == "running"
            )
        )
        recent = db.scalar(
            select(DirectorySyncRun.id).where(
                DirectorySyncRun.source_id == s.id,
                DirectorySyncRun.started_at > now - timedelta(minutes=s.sync_interval_minutes or 0),
            )
        )
        if due and not busy and not recent:
            run = DirectorySyncRun(
                id=uuid.uuid4(), organization_id=s.organization_id, source_id=s.id
            )
            db.add(run)
            outbox.enqueue(
                db,
                organization_id=s.organization_id,
                event_type="directory.sync",
                aggregate_type="directory_sync_run",
                aggregate_id=run.id,
            )
            queued += 1
    db.commit()
    return queued


# --------------------------------------------------------------------- engine
def apply_snapshot(
    db: Session,
    org_id: uuid.UUID,
    *,
    source_id: uuid.UUID,
    snapshot: DirSnapshot,
    allow_admin_deprovision: bool,
) -> Stats:
    st = Stats()
    now = datetime.now(UTC)
    if not snapshot.users:
        raise SyncAborted("The directory returned no users; refusing to deprovision everyone.")

    links = {
        lk.external_id: lk
        for lk in db.scalars(
            select(DirectoryUserLink).where(DirectoryUserLink.source_id == source_id)
        )
    }
    in_dir_active = {u.external_id for u in snapshot.users if u.active}
    to_remove = [
        lk for ext, lk in links.items() if ext not in in_dir_active and lk.deprovisioned_at is None
    ]
    guard = max(MIN_REMOVAL_GUARD, int(MAX_REMOVAL_FRACTION * max(len(links), 1)))
    if len(to_remove) > guard:
        raise SyncAborted(
            f"Would deprovision {len(to_remove)} of {len(links)} linked users (limit {guard}); check the directory source before retrying."
        )

    user_by_ext: dict[str, uuid.UUID] = {}
    seen_emails: set[str] = set()
    for du in snapshot.users:
        email = du.email.strip().lower()
        if "@" not in email or email in seen_emails or len(email) > 320:
            st.inc("invalid_records")
            continue
        seen_emails.add(email)
        link = links.get(du.external_id)
        user = (
            db.get(User, link.user_id)
            if link
            else db.scalar(select(User).where(User.email == email))
        )
        if user is not None and user.status == UserStatus.DISABLED.value:
            st.inc("skipped_disabled_accounts")
            continue
        if link is None:
            if user is None:
                user = User(
                    id=uuid.uuid4(),
                    email=email,
                    display_name=du.display_name,
                    status=UserStatus.INVITED.value,
                )
                db.add(user)
                db.flush()
                st.inc("users_created")
                audit.record(
                    db,
                    organization_id=org_id,
                    actor_user_id=None,
                    action="member.provisioned",
                    resource_type="user",
                    resource_id=user.id,
                    metadata={"source": str(source_id)},
                )
            else:
                st.inc("users_linked")
            other = db.scalar(
                select(DirectoryUserLink.id).where(
                    DirectoryUserLink.source_id == source_id, DirectoryUserLink.user_id == user.id
                )
            )
            if other is not None:
                st.inc("duplicate_identities")  # same person appears twice in the directory
                continue
            link = DirectoryUserLink(
                id=uuid.uuid4(),
                organization_id=org_id,
                source_id=source_id,
                external_id=du.external_id,
                user_id=user.id,
            )
            db.add(link)
            links[du.external_id] = link
        elif user is not None and user.email != email:
            clash = db.scalar(select(User.id).where(User.email == email, User.id != user.id))
            if clash is None:
                user.email = email
                st.inc("emails_updated")
            else:
                st.inc("email_conflicts")
        if user is not None and du.display_name and not user.display_name:
            user.display_name = du.display_name
        assert user is not None
        user_by_ext[du.external_id] = user.id

        if not du.active:
            continue  # handled by the deprovision pass below
        membership = db.scalar(
            select(Membership).where(
                Membership.organization_id == org_id, Membership.user_id == user.id
            )
        )
        if membership is None:
            db.add(
                Membership(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    user_id=user.id,
                    role=Role.MEMBER.value,
                    status=MembershipStatus.ACTIVE.value
                    if user.status == UserStatus.ACTIVE.value
                    else MembershipStatus.INVITED.value,
                )
            )
            st.inc("memberships_created")
        elif (
            membership.status == MembershipStatus.REMOVED.value
            and link.deprovisioned_at is not None
        ):
            membership.status = (
                MembershipStatus.ACTIVE.value
                if user.status == UserStatus.ACTIVE.value
                else MembershipStatus.INVITED.value
            )
            link.deprovisioned_at = None
            st.inc("memberships_reactivated")
            audit.record(
                db,
                organization_id=org_id,
                actor_user_id=None,
                action="member.reprovisioned",
                resource_type="user",
                resource_id=user.id,
            )
        link.last_seen_at = now

    # ---- deprovision
    for link in to_remove:
        membership = db.scalar(
            select(Membership).where(
                Membership.organization_id == org_id, Membership.user_id == link.user_id
            )
        )
        user = db.get(User, link.user_id)
        if (
            membership is None
            or user is None
            or membership.status == MembershipStatus.REMOVED.value
        ):
            link.deprovisioned_at = link.deprovisioned_at or now
            continue
        if membership.role in (Role.OWNER.value, Role.ADMIN.value) and not allow_admin_deprovision:
            st.inc("protected_admins_skipped")
            st.notes.append(f"{user.email}: administrator not deprovisioned automatically")
            continue
        membership.status = MembershipStatus.REMOVED.value
        link.deprovisioned_at = now
        user.sessions_valid_after = now  # existing tokens stop working on their next request
        db.execute(
            delete(GroupMembership).where(
                GroupMembership.user_id == user.id, GroupMembership.organization_id == org_id
            )
        )
        st.inc("users_deprovisioned")
        audit.record(
            db,
            organization_id=org_id,
            actor_user_id=None,
            action="member.deprovisioned",
            resource_type="user",
            resource_id=user.id,
            metadata={"reason": "removed_or_disabled_in_directory", "source": str(source_id)},
        )

    # ---- groups
    glinks = {
        g.external_id: g
        for g in db.scalars(
            select(DirectoryGroupLink).where(DirectoryGroupLink.source_id == source_id)
        )
    }
    dir_group_ids = {g.external_id for g in snapshot.groups}
    stale = [gl for ext, gl in glinks.items() if ext not in dir_group_ids]
    if len(stale) > max(3, int(MAX_REMOVAL_FRACTION * max(len(glinks), 1))):
        raise SyncAborted(
            f"Would delete {len(stale)} of {len(glinks)} directory groups; check the directory source before retrying."
        )
    for dg in snapshot.groups:
        gl = glinks.get(dg.external_id)
        if gl is None:
            name = dg.name.strip()[:200] or dg.external_id
            taken = db.scalar(
                select(Group.id).where(Group.organization_id == org_id, Group.name.ilike(name))
            )
            if taken is not None:
                name = f"{name[:180]} (directory)"
            group = Group(
                id=uuid.uuid4(),
                organization_id=org_id,
                name=name,
                kind="group",
                external_id=dg.external_id,
            )
            db.add(group)
            db.flush()
            gl = DirectoryGroupLink(
                id=uuid.uuid4(),
                organization_id=org_id,
                source_id=source_id,
                external_id=dg.external_id,
                group_id=group.id,
            )
            db.add(gl)
            glinks[dg.external_id] = gl
            st.inc("groups_created")
        managed = db.get(Group, gl.group_id)
        assert managed is not None
        group = managed
        if group.name != dg.name.strip() and not db.scalar(
            select(Group.id).where(
                Group.organization_id == org_id,
                Group.name.ilike(dg.name.strip()),
                Group.id != group.id,
            )
        ):
            group.name = dg.name.strip()[:200]
            st.inc("groups_renamed")
        desired = {user_by_ext[m] for m in dg.member_ids if m in user_by_ext and m in in_dir_active}
        current = set(
            db.scalars(select(GroupMembership.user_id).where(GroupMembership.group_id == group.id))
        )
        for uid in desired - current:
            db.add(GroupMembership(group_id=group.id, user_id=uid, organization_id=org_id))
            st.inc("group_members_added")
        for uid in current - desired:
            db.execute(
                delete(GroupMembership).where(
                    GroupMembership.group_id == group.id, GroupMembership.user_id == uid
                )
            )
            st.inc("group_members_removed")
    for gl in stale:
        doomed = db.get(Group, gl.group_id)
        if doomed is not None:
            group = doomed
            db.execute(delete(GroupMembership).where(GroupMembership.group_id == group.id))
            db.execute(
                update(PermissionGrant)
                .where(
                    PermissionGrant.subject_type == "group",
                    PermissionGrant.subject_id == group.id,
                    PermissionGrant.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            db.execute(
                delete(ShareRecipient).where(
                    ShareRecipient.recipient_type == "group",
                    ShareRecipient.recipient_id == group.id,
                )
            )
            db.delete(group)
            st.inc("groups_deleted")
    db.flush()
    return st
