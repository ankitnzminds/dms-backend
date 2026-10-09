"""Handlers for every action key. Each runs AS the person who published the workflow, through the
same services (and therefore the same authorization) the UI uses; nothing here bypasses ACLs.

Handlers return a ``NodeResult`` with a *safe* output summary (ids, counts, outcomes, never file
content, tokens or addresses). Expected refusals raise ``ActionFailed`` (the node fails, no retry);
unexpected infrastructure errors propagate so the outbox retries with backoff.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.storage.base import StorageError
from app.adapters.storage.registry import get_storage_provider
from app.core.config import get_settings
from app.core.errors import AppError, ConflictError
from app.db.enums import AuditOutcome, ResourceType
from app.db.models import (
    Document,
    DocumentVersion,
    Folder,
    GroupMembership,
    Membership,
    StorageLocation,
    User,
    WorkflowRun,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.automations import expr
from app.modules.identity.principal import Principal
from app.modules.identity.service import principal_for
from app.schemas.sharing import PermissionGrantIn

_PLACEHOLDER = re.compile(r"\{([a-z_]+(?:\.[a-z_]+)*)\}")


class ActionFailed(Exception):
    """A deliberate, non-retryable failure of one node (permission, validation, conflict)."""


@dataclass
class NodeResult:
    status: str = "succeeded"  # succeeded | skipped | waiting
    output: dict[str, Any] = field(default_factory=dict)
    branch: str | None = None


@dataclass
class Ctx:
    db: Session
    run_id: uuid.UUID
    node_id: str
    org: uuid.UUID
    principal: Principal
    authz: AuthorizationService
    expr_ctx: dict[str, Any]
    variables: dict[str, Any]
    resource: dict[str, Any] | None
    actor_id: uuid.UUID | None
    prior_output: dict[str, Any]

    @property
    def resource_id(self) -> uuid.UUID | None:
        return uuid.UUID(self.resource["id"]) if self.resource else None


def render(text: str, ctx: dict[str, Any], *, hide_resource: bool = False) -> str:
    """{file.name} style placeholders only. Unknown names render empty; nothing is evaluated."""

    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if hide_resource and name.split(".")[0] in ("file", "folder"):
            return "a file"
        value: Any = ctx
        for part in name.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        return "" if value is None else str(value)

    return _PLACEHOLDER.sub(sub, text)[:1000]


def _recipient_ids(c: Ctx, params: dict[str, Any]) -> list[uuid.UUID]:
    ids = {uuid.UUID(x) for x in params.get("user_ids", [])}
    for gid in params.get("group_ids", []):
        ids |= set(
            c.db.scalars(
                select(GroupMembership.user_id).where(
                    GroupMembership.group_id == uuid.UUID(gid),
                    GroupMembership.organization_id == c.org,
                )
            )
        )
    if params.get("include_actor") and c.actor_id:
        ids.add(c.actor_id)
    if not ids:
        return []
    active = set(
        c.db.scalars(
            select(Membership.user_id)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == c.org,
                Membership.user_id.in_(ids),
                Membership.status == "active",
                User.status == "active",
            )
        )
    )
    return sorted(active)[:200]


def _can_view(c: Ctx, recipient: uuid.UUID) -> bool:
    """Would this recipient be allowed to see the triggering item? Decides what a notification may
    reveal (a person without access gets a generic message, not the file name)."""
    if not c.resource or c.resource["type"] not in ("document", "folder"):
        return True
    try:
        other = AuthorizationService(c.db, principal_for(c.db, recipient, c.org))
        rid = uuid.UUID(c.resource["id"])
        if c.resource["type"] == "document":
            return "view" in other.document_actions([c.db.get(Document, rid)]).get(rid, frozenset())  # type: ignore[list-item]
        return "view" in other.folder_actions([rid]).get(rid, frozenset())
    except Exception:
        return False


def _notify(c: Ctx, params: dict[str, Any], title: str, body: str, *, kind: str) -> NodeResult:
    from app.modules.notifications import service as notifications

    recipients = _recipient_ids(c, params)
    if not recipients:
        return NodeResult(
            status="skipped",
            output={"reason": "No active recipient could be resolved (for example the acting person is unknown)."},
        )
    sent = 0
    for rid in recipients:
        visible = _can_view(c, rid)
        created = notifications.create(
            c.db,
            organization_id=c.org,
            user_id=rid,
            type_=kind,
            title=render(title, c.expr_ctx, hide_resource=not visible),
            body=render(body, c.expr_ctx, hide_resource=not visible) or None,
            resource_type=c.resource["type"] if (c.resource and visible) else None,
            resource_id=c.resource_id if visible else None,
            source_event_id=uuid.uuid5(c.run_id, c.node_id),
        )
        sent += int(created)
    c.db.commit()
    return NodeResult(output={"recipients": len(recipients), "created": sent})


# ----------------------------------------------------------------------------- actions
def notify_users(c: Ctx, p: dict[str, Any]) -> NodeResult:
    return _notify(c, p, p["title"], p.get("message", ""), kind="automation.notice")


def send_email(c: Ctx, p: dict[str, Any]) -> NodeResult:
    if get_settings().email_provider == "none":
        return NodeResult(
            status="skipped",
            output={"reason": "No email provider is configured, so nothing was sent."},
        )
    result = _notify(c, p, p["subject"], p.get("body", ""), kind="automation.email")
    result.output["delivery"] = "queued per recipient preferences"
    return result


def _document(c: Ctx) -> Document:
    if not c.resource or c.resource["type"] != "document":
        raise ActionFailed("This step needs a file, but the trigger did not provide one.")
    doc = c.db.scalar(
        select(Document).where(Document.id == c.resource_id, Document.organization_id == c.org)
    )
    if doc is None:
        raise ActionFailed("The file no longer exists.")
    return doc


def _free_name(c: Ctx, folder_id: uuid.UUID, name: str) -> str:
    from app.modules.folders.common import name_taken

    if not name_taken(c.db, c.org, folder_id, name):
        return name
    stem, dot, ext = name.rpartition(".")
    stem, ext = (stem, f".{ext}") if dot else (name, "")
    for n in range(2, 100):
        cand = f"{stem} ({n}){ext}"
        if not name_taken(c.db, c.org, folder_id, cand):
            return cand
    raise ActionFailed("Could not find a free name in the destination.")


def _destination(c: Ctx, p: dict[str, Any], doc: Document) -> uuid.UUID:
    target = uuid.UUID(p["target_folder_id"])
    if p.get("keep_folder_structure"):
        from app.modules.folders import service as folders

        parent = c.db.get(Folder, doc.folder_id)
        if parent is not None and parent.parent_folder_id is not None:
            leaf, _ = folders.ensure_path(c.db, c.authz, target, [parent.name])
            return leaf.id
    return target


def copy_files(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.documents import service as documents
    from app.modules.folders.common import name_taken

    if c.prior_output.get("new_document_id"):
        return NodeResult(output=c.prior_output)  # redelivery after a crash: already copied
    doc = _document(c)
    target = _destination(c, p, doc)
    name: str | None = None
    if name_taken(c.db, c.org, target, doc.name):
        if p["on_conflict"] == "skip":
            return NodeResult(
                status="skipped", output={"reason": "A file with that name already exists."}
            )
        name = _free_name(c, target, doc.name)
    try:
        copy = documents.copy_document(c.db, c.authz, doc.id, target, name)
    except ConflictError as e:
        raise ActionFailed(e.message) from e
    except AppError as e:
        raise ActionFailed(e.message) from e
    return NodeResult(output={"new_document_id": str(copy.id), "renamed": name is not None})


def move_files(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.documents import service as documents

    doc = _document(c)
    target = _destination(c, p, doc)
    if doc.folder_id == target:
        return NodeResult(status="skipped", output={"reason": "The file is already there."})
    name: str | None = None
    from app.modules.folders.common import name_taken

    if name_taken(c.db, c.org, target, doc.name):
        if p["on_conflict"] == "skip":
            return NodeResult(
                status="skipped", output={"reason": "A file with that name already exists."}
            )
        name = _free_name(c, target, doc.name)
    try:
        documents.update_document(
            c.db,
            c.authz,
            doc.id,
            name=name,
            folder_id=target,
            metadata=None,
            classification=None,
            expected_row_version=None,
        )
    except AppError as e:
        raise ActionFailed(e.message) from e
    return NodeResult(output={"moved_to": str(target), "renamed": name is not None})


def delete_files(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.documents import service as documents

    doc = _document(c)
    if doc.deleted_at is not None:
        return NodeResult(status="skipped", output={"reason": "Already in the trash."})
    try:
        documents.delete_document(c.db, c.authz, doc.id)  # recycle bin; retention/legal hold apply
    except AppError as e:
        raise ActionFailed(e.message) from e
    return NodeResult(output={"moved_to_trash": True})


def _verify(c: Ctx, doc: Document) -> tuple[bool, str]:
    version = c.db.get(DocumentVersion, doc.current_version_id) if doc.current_version_id else None
    if version is None or version.organization_id != c.org:
        raise ActionFailed("The file has no current version to verify.")
    location = c.db.get(StorageLocation, version.storage_location_id)
    if location is None:
        raise ActionFailed("The storage location is unknown.")
    h = hashlib.sha256()
    try:
        for chunk in get_storage_provider(location.provider_type).stream_object(
            location.bucket, version.object_key
        ):
            h.update(chunk)
    except StorageError:
        return False, "missing_or_unreadable"
    return h.hexdigest() == version.sha256, "checksum_mismatch"


def _admins(c: Ctx, explicit: list[str]) -> dict[str, Any]:
    if explicit:
        return {"user_ids": explicit}
    ids = [
        str(u)
        for u in c.db.scalars(
            select(Membership.user_id).where(
                Membership.organization_id == c.org,
                Membership.role.in_(["owner", "admin"]),
                Membership.status == "active",
            )
        )
    ]
    return {"user_ids": ids}


def verify_integrity_alert(c: Ctx, p: dict[str, Any], *, delete: bool = False) -> NodeResult:
    doc = _document(c)
    ok, reason = _verify(c, doc)
    if ok:
        return NodeResult(output={"verified": True})
    audit.record(
        c.db,
        organization_id=c.org,
        actor_user_id=c.principal.user_id,
        action="integrity.mismatch",
        resource_type="document",
        resource_id=doc.id,
        outcome=AuditOutcome.FAILURE,
        metadata={"reason": reason, "run_id": str(c.run_id)},
    )
    c.db.commit()
    _notify(
        c,
        _admins(c, p.get("alert_user_ids", [])),
        "Integrity check failed for {file.name}",
        "The stored bytes do not match the checksum recorded at upload ({file.path}).",
        kind="automation.alert",
    )
    out: dict[str, Any] = {"verified": False, "reason": reason, "alerted": True}
    if delete:
        from app.modules.documents import service as documents

        try:
            documents.delete_document(c.db, c.authz, doc.id)
            out["moved_to_trash"] = True
        except AppError as e:
            raise ActionFailed(e.message) from e
    return NodeResult(output=out)


def verify_integrity_delete(c: Ctx, p: dict[str, Any]) -> NodeResult:
    return verify_integrity_alert(c, p, delete=True)


def run_report(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.reports import service as reports

    summary = reports.activity_summary(c.db, c.principal, int(p["days"]))
    shares = summary["shares"]
    body = (
        f"Last {summary['period_days']} days. Active shares: {shares['active']} "
        f"(revoked {shares['revoked']}, expired {shares['expired']}). "
        f"Audit events: {sum(summary['audit_events_by_outcome'].values())}."
    )
    result = _notify(c, p, "Activity summary", body, kind="automation.report")
    result.output["report"] = p["report"]
    return result


def release_locks(c: Ctx, p: dict[str, Any]) -> NodeResult:
    now = datetime.now(UTC)
    limit_at = now - timedelta(hours=int(p["older_than_hours"]))
    stmt = select(Document).where(
        Document.organization_id == c.org,
        Document.locked_by.is_not(None),
    )
    if c.resource and c.resource["type"] == "document":
        stmt = stmt.where(Document.id == c.resource_id)
    docs = [
        d
        for d in c.db.scalars(stmt.limit(500).with_for_update(skip_locked=True))
        if (d.lock_expires_at and d.lock_expires_at <= now)
        or (d.locked_at and d.locked_at <= limit_at)
    ][:200]
    owners: set[uuid.UUID] = set()
    for d in docs:
        if d.locked_by:
            owners.add(d.locked_by)
        audit.record(
            c.db,
            organization_id=c.org,
            actor_user_id=c.principal.user_id,
            action="document.lock_released_by_automation",
            resource_type="document",
            resource_id=d.id,
            metadata={"previous_holder": str(d.locked_by), "run_id": str(c.run_id)},
        )
        d.locked_by = d.locked_at = d.lock_expires_at = None
    c.db.commit()
    notified = 0
    if p.get("notify_owner") and owners:
        notified = _notify(
            c,
            {"user_ids": [str(o) for o in owners]},
            "A document you had checked out was released",
            "An automation released a stale checkout.",
            kind="automation.notice",
        ).output["created"]
    return NodeResult(output={"released": len(docs), "owners_notified": notified})


def create_directory(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.folders import service as folders

    name = render(p["name"], c.expr_ctx).strip().replace("/", "-")[:200] or "New folder"
    try:
        out = folders.create_folder(c.db, c.authz, uuid.UUID(p["parent_folder_id"]), name)
    except ConflictError:
        return NodeResult(status="skipped", output={"reason": "A folder with that name exists."})
    except AppError as e:
        raise ActionFailed(e.message) from e
    return NodeResult(output={"folder_id": str(out.id)})


def set_metadata(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.documents import service as documents

    doc = _document(c)
    merged = {**(doc.custom_metadata or {}), p["key"]: p["value"]}
    try:
        documents.update_document(
            c.db,
            c.authz,
            doc.id,
            name=None,
            folder_id=None,
            metadata=merged,
            classification=None,
            expected_row_version=None,
        )
    except AppError as e:
        raise ActionFailed(e.message) from e
    return NodeResult(output={"key": p["key"]})


def assign_acl(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.authorization import acl

    if not c.resource or c.resource["type"] not in ("document", "folder"):
        raise ActionFailed("This step needs a file or folder.")
    rtype = ResourceType.DOCUMENT if c.resource["type"] == "document" else ResourceType.FOLDER
    expires = (
        datetime.now(UTC) + timedelta(days=int(p["expires_in_days"]))
        if p.get("expires_in_days")
        else None
    )
    try:
        acl.add_grant(
            c.db,
            c.authz,
            rtype,
            c.resource_id,  # type: ignore[arg-type]
            PermissionGrantIn(
                subject_type=p["subject_type"],
                subject_id=uuid.UUID(p["subject_id"]),
                actions=p["actions"],
                inherit=True,
                expires_at=expires,
            ),
        )
    except AppError as e:  # includes "cannot grant what you do not hold"
        raise ActionFailed(e.message) from e
    return NodeResult(output={"granted": p["actions"]})


def wait_for_approval(c: Ctx, p: dict[str, Any]) -> NodeResult:
    from app.modules.workflows import service as workflows

    prior = c.prior_output.get("approval_run_id")
    if prior:
        run = c.db.get(WorkflowRun, uuid.UUID(prior))
        if run is None:
            raise ActionFailed("The approval run disappeared.")
        if run.state == "approved":
            return NodeResult(output={**c.prior_output, "decision": "approved"})
        if run.state in ("rejected", "cancelled"):
            raise ActionFailed(f"The approval was {run.state}.")
        return NodeResult(status="waiting", output=c.prior_output)
    doc = _document(c)
    try:
        started = workflows.start_run(
            c.db, c.authz, doc.id, uuid.UUID(p["approval_workflow_id"]), p.get("note") or None
        )
    except AppError as e:
        raise ActionFailed(e.message) from e
    return NodeResult(status="waiting", output={"approval_run_id": str(started.id)})


def assign_variable(c: Ctx, p: dict[str, Any]) -> NodeResult:
    names = _names(c)
    try:
        value = expr.evaluate(p["expression"], c.expr_ctx, names)
    except expr.ExprError as e:
        raise ActionFailed(str(e)) from e
    c.variables[p["name"]] = (
        value if isinstance(value, (bool, int, float, str, type(None))) else str(value)
    )
    c.expr_ctx.setdefault("vars", {})[p["name"]] = c.variables[p["name"]]
    return NodeResult(output={"name": p["name"], "value": c.variables[p["name"]]})


def condition(c: Ctx, p: dict[str, Any]) -> NodeResult:
    try:
        value = bool(expr.evaluate(p["expression"], c.expr_ctx, _names(c)))
    except expr.ExprError as e:
        raise ActionFailed(str(e)) from e
    return NodeResult(output={"result": value}, branch="true" if value else "false")


def _names(c: Ctx) -> frozenset[str]:
    return expr.names_in(c.expr_ctx) | {f"vars.{k}" for k in c.variables}


HANDLERS = {
    "notify_users": notify_users,
    "copy_files": copy_files,
    "delete_files": delete_files,
    "move_files": move_files,
    "verify_integrity_alert": verify_integrity_alert,
    "verify_integrity_delete": verify_integrity_delete,
    "run_report": run_report,
    "release_locks": release_locks,
    "send_email": send_email,
    "create_directory": create_directory,
    "set_metadata": set_metadata,
    "assign_acl": assign_acl,
    "wait_for_approval": wait_for_approval,
    "assign_variable": assign_variable,
    "condition": condition,
}
PURE = frozenset({"assign_variable", "condition"})  # no side effects: also run in dry runs
