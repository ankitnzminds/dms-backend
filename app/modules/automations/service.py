"""Definitions: validate, create, edit, publish, enable/disable, archive, list, catalogue.

Authorization: owners and administrators of the caller's organization only; every query is
scoped by ``p.organization_id``. Publishing snapshots the draft into an immutable version and
records *who published it*: runs re-authorize as that person every time.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import MembershipStatus, Role
from app.db.models import (
    Automation,
    AutomationRun,
    AutomationVersion,
    Folder,
    Group,
    Membership,
    User,
    WorkflowDefinition,
)
from app.modules.audit import service as audit
from app.modules.automations import expr
from app.modules.automations.registry import (
    ACTIONS,
    CONDITIONS,
    HIGH_RISK,
    SCHEMA_VERSION,
    ConditionSpec,
)
from app.modules.automations.schedule import next_fire
from app.modules.identity.principal import Principal
from app.schemas.automations import (
    AutomationCreate,
    AutomationOut,
    AutomationUpdate,
    CatalogueEntry,
    CatalogueOut,
    GraphDef,
    Issue,
    TriggerDef,
    ValidationReport,
)

MAX_NODES = 40
_PLACEHOLDER = re.compile(r"\{([a-z_]+(?:\.[a-z_]+)*)\}")
_PROVIDES = {
    "file": {
        "file_created",
        "file_updated",
        "file_deleted",
        "file_downloaded",
        "comment_added",
        "file_stale",
        "file_created_or_updated",
        "upload_size_threshold",
        "download_size_threshold",
    },
    "folder": {"folder_created", "folder_deleted"},
    "user": {"user_created", "account_age", "last_login_age", "account_expiring"},
}


def require_admin(p: Principal) -> None:
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required.")


def provides(trigger_key: str) -> str:
    for kind, keys in _PROVIDES.items():
        if trigger_key in keys:
            return kind
    return "none"


# ----------------------------------------------------------------------- validation
def _fmt_error(e: ValidationError) -> list[tuple[str | None, str]]:
    out = []
    for err in e.errors():
        loc = ".".join(str(x) for x in err["loc"]) or None
        out.append((loc, str(err["msg"]).removeprefix("Value error, ")))
    return out


def _check_placeholders(text: str, names: frozenset[str]) -> str | None:
    for m in _PLACEHOLDER.finditer(text):
        if m.group(1) not in names:
            return f"Unknown placeholder {{{m.group(1)}}}. Available: {', '.join(sorted(names)) or 'none'}."
    return None


def validate_definition(
    db: Session,
    p: Principal,
    trigger: TriggerDef,
    graph: GraphDef,
) -> ValidationReport:
    issues: list[Issue] = []

    def bad(where: str, message: str, field: str | None = None) -> None:
        issues.append(Issue(where=where, field=field, message=message))

    spec = CONDITIONS.get(trigger.key)
    names: frozenset[str] = frozenset()
    if spec is None:
        bad("trigger", f"Unknown condition '{trigger.key}'.", "key")
    elif not spec.supported:
        bad("trigger", spec.unsupported_reason or "This condition is not supported.", "key")
    else:
        names = frozenset(spec.variables)
        _validate_trigger_params(db, p, spec, trigger.params, names, bad)

    assigned = {
        str(n.params.get("name"))
        for n in graph.nodes
        if n.type == "assign_variable" and isinstance(n.params.get("name"), str)
    }
    action_names = names | {f"vars.{v}" for v in assigned}
    ids = [n.id for n in graph.nodes]
    if len(ids) != len(set(ids)):
        bad("graph", "Node ids must be unique.")
    if len(graph.nodes) > MAX_NODES:
        bad("graph", f"At most {MAX_NODES} nodes.")
    starts = [n for n in graph.nodes if n.type == "start"]
    if len(starts) != 1:
        bad("graph", "There must be exactly one Start node.")
    by_id = {n.id: n for n in graph.nodes}

    for n in graph.nodes:
        if n.type in ("start", "end"):
            continue
        aspec = ACTIONS.get(n.type)
        if aspec is None:
            bad(n.id, f"Unknown step type '{n.type}'.")
            continue
        if not aspec.supported:
            bad(n.id, aspec.unsupported_reason or "This step is not supported.")
            continue
        try:
            parsed = aspec.params.model_validate(n.params)
        except ValidationError as e:
            for loc, msg in _fmt_error(e):
                bad(n.id, msg, loc)
            continue
        if spec is not None:
            have = provides(trigger.key)
            if aspec.needs_resource == "file" and have != "file":
                bad(n.id, f"'{aspec.label}' needs a file, but this condition does not provide one.")
            if aspec.needs_resource == "file_or_folder" and have not in ("file", "folder"):
                bad(
                    n.id,
                    f"'{aspec.label}' needs a file or folder, but this condition does not provide one.",
                )
        _validate_action_refs(
            db, p, n.id, n.type, parsed.model_dump(mode="json"), action_names, bad
        )

    ends: dict[str, list[tuple[str, str | None]]] = {}
    for edge in graph.edges:
        if edge.from_ not in by_id or edge.to not in by_id:
            bad("graph", f"Edge {edge.from_} -> {edge.to} refers to a missing node.")
            continue
        if by_id[edge.to].type == "start":
            bad("graph", "Nothing may point at the Start node.")
        ends.setdefault(edge.from_, []).append((edge.to, edge.branch))
    for nid, outs in ends.items():
        node = by_id[nid]
        if node.type == "condition":
            branches = [b for _, b in outs]
            if None in branches or len(branches) != len(set(branches)):
                bad(nid, "Condition outputs must be labelled 'true' and/or 'false', once each.")
        elif node.type == "end":
            bad(nid, "The End node cannot have outgoing connections.")
        elif len(outs) > 1 or outs[0][1] is not None:
            bad(nid, "This step has one outgoing connection. Use a Condition to branch.")

    if len(starts) == 1:
        start = starts[0].id
        if not ends.get(start):
            bad(start, "Connect the Start node to a step.")
        seen: set[str] = set()
        stack = [start]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(t for t, _ in ends.get(cur, []))
        for n in graph.nodes:
            if n.id not in seen:
                bad(n.id, "This step is not connected to the Start node, so it would never run.")
        # cycles: iterative DFS with colors
        color: dict[str, int] = {}
        for root in by_id:
            if color.get(root):
                continue
            path = [(root, iter(ends.get(root, [])))]
            color[root] = 1
            while path:
                cur, it = path[-1]
                nxt = next(it, None)
                if nxt is None:
                    color[cur] = 2
                    path.pop()
                    continue
                tgt = nxt[0]
                if color.get(tgt) == 1:
                    bad(
                        "graph",
                        "Loops are not supported: a connection leads back to an earlier step.",
                    )
                    path.clear()
                    break
                if not color.get(tgt):
                    color[tgt] = 1
                    path.append((tgt, iter(ends.get(tgt, []))))

    actions_present = [n for n in graph.nodes if n.type not in ("start", "end")]
    if not actions_present:
        bad("graph", "Add at least one step after Start.")
    high = any(n.type in HIGH_RISK for n in graph.nodes)
    return ValidationReport(valid=not issues, issues=issues, needs_high_risk_confirmation=high)


def _validate_trigger_params(
    db: Session,
    p: Principal,
    spec: ConditionSpec,
    params: dict[str, Any],
    names: frozenset[str],
    bad: Any,
) -> None:
    try:
        parsed = spec.params.model_validate(params)
    except ValidationError as e:
        for loc, msg in _fmt_error(e):
            bad("trigger", msg, loc)
        return
    data = parsed.model_dump(mode="json")
    if data.get("expression"):
        try:
            expr.parse(data["expression"], names)
        except expr.ExprError as e:
            bad("trigger", str(e), "expression")
    for field in ("start_at", "end_at", "run_at"):
        raw = data.get(field)
        if raw:
            try:
                datetime.fromisoformat(raw)
            except ValueError:
                bad("trigger", "Use an ISO date-time such as 2027-01-31T09:00:00.", field)
    if spec.key == "specified_date" and data.get("run_at"):
        try:
            future = next_fire({"key": spec.key, "params": data}, datetime.now(UTC), first=True)
        except ValueError:
            return  # already reported as a bad date
        if future is None:
            bad("trigger", "Pick a date and time in the future.", "run_at")


def _validate_action_refs(
    db: Session,
    p: Principal,
    node_id: str,
    node_type: str,
    data: dict[str, Any],
    names: frozenset[str],
    bad: Any,
) -> None:
    org = p.organization_id
    for field in ("title", "message", "subject", "body", "name"):
        val = data.get(field)
        if isinstance(val, str):
            msg = _check_placeholders(val, names)
            if msg:
                bad(node_id, msg, field)
    for field in ("expression",):
        val = data.get(field)
        if isinstance(val, str):
            try:
                expr.parse(val, names)
            except expr.ExprError as e:
                bad(node_id, str(e), field)
    for field in ("target_folder_id", "parent_folder_id"):
        fid = data.get(field)
        if (
            fid
            and db.scalar(
                select(Folder.id).where(Folder.id == uuid.UUID(fid), Folder.organization_id == org)
            )
            is None
        ):
            bad(node_id, "That folder does not exist.", field)
    uids = [uuid.UUID(x) for x in data.get("user_ids", []) + data.get("alert_user_ids", [])]
    if data.get("subject_type") == "user" and data.get("subject_id"):
        uids.append(uuid.UUID(data["subject_id"]))
    if uids:
        found = set(
            db.scalars(
                select(Membership.user_id).where(
                    Membership.organization_id == org,
                    Membership.user_id.in_(uids),
                    Membership.status != MembershipStatus.REMOVED.value,
                )
            )
        )
        if found != set(uids):
            bad(node_id, "Recipients must be members of this organization.", "user_ids")
    gids = [uuid.UUID(x) for x in data.get("group_ids", [])]
    if data.get("subject_type") == "group" and data.get("subject_id"):
        gids.append(uuid.UUID(data["subject_id"]))
    if gids:
        found_g = set(
            db.scalars(select(Group.id).where(Group.organization_id == org, Group.id.in_(gids)))
        )
        if found_g != set(gids):
            bad(node_id, "One or more groups do not exist.", "group_ids")
    if (
        node_type == "wait_for_approval"
        and db.scalar(
            select(WorkflowDefinition.id).where(
                WorkflowDefinition.id == uuid.UUID(data["approval_workflow_id"]),
                WorkflowDefinition.organization_id == org,
                WorkflowDefinition.archived_at.is_(None),
            )
        )
        is None
    ):
        bad(node_id, "That approval workflow does not exist.", "approval_workflow_id")
    if node_type == "set_metadata":
        from app.modules.metadata.service import active_definitions

        defs = active_definitions(db, org)
        d = defs.get(data["key"])
        if d is None:
            bad(node_id, f"No metadata field '{data['key']}' is defined.", "key")


def require_valid(report: ValidationReport) -> None:
    if not report.valid:
        first = report.issues[0]
        raise ValidationFailed(
            first.message,
            code="invalid_workflow",
            details={"issues": [i.model_dump() for i in report.issues]},
        )


# ----------------------------------------------------------------------------- views
def describe_trigger(trigger: dict[str, Any]) -> str:
    spec = CONDITIONS.get(trigger.get("key", ""))
    if spec is None:
        return "(unknown condition)"
    params = trigger.get("params") or {}
    bits = []
    if params.get("path"):
        bits.append(f"in {params['path']}")
    for k, fmt in (
        ("days", "{} days"),
        ("within_days", "within {} days"),
        ("every_minutes", "every {} min"),
        ("greater_than_bytes", "> {} bytes"),
        ("frequency", "{}"),
        ("run_at", "at {}"),
    ):
        if params.get(k) is not None:
            bits.append(fmt.format(params[k]))
    return spec.label + (f" ({', '.join(bits)})" if bits else "")


def _ordered_actions(graph: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges: dict[str, list[str]] = {}
    for e in graph.get("edges", []):
        edges.setdefault(e["from"], []).append(e["to"])
    out, seen = [], set()
    stack = [n["id"] for n in graph.get("nodes", []) if n["type"] == "start"]
    while stack:
        cur = stack.pop(0)
        if cur in seen or cur not in nodes:
            continue
        seen.add(cur)
        if nodes[cur]["type"] not in ("start", "end"):
            out.append(nodes[cur])
        stack.extend(edges.get(cur, []))
    return out


def describe_actions(graph: dict[str, Any]) -> str:
    labels = [ACTIONS[n["type"]].label for n in _ordered_actions(graph) if n["type"] in ACTIONS]
    return " → ".join(labels) if labels else "(no steps)"


def _state(a: Automation, running: int, failed_recent: bool) -> str:
    if a.status == "archived":
        return "archived"
    if a.attention_reason:
        return "needs_attention"
    if a.status == "draft":
        return "draft"
    if running:
        return "running"
    if failed_recent and a.last_run_status == "failed":
        return "failed"
    return "enabled" if a.enabled else "disabled"


def to_out(db: Session, a: Automation) -> AutomationOut:
    version = db.get(AutomationVersion, a.published_version_id) if a.published_version_id else None
    counts = dict(
        db.execute(
            select(AutomationRun.status, func.count())
            .where(AutomationRun.automation_id == a.id, AutomationRun.mode == "live")
            .group_by(AutomationRun.status)
        ).all()
    )
    creator = db.get(User, a.created_by) if a.created_by else None
    unpublished = (
        version is None or version.trigger != a.draft_trigger or version.graph != a.draft_graph
    )
    running = (
        int(counts.get("running", 0)) + int(counts.get("queued", 0)) + int(counts.get("waiting", 0))
    )
    live_graph = version.graph if version else a.draft_graph
    return AutomationOut(
        id=a.id,
        name=a.name,
        description=a.description,
        status=a.status,  # type: ignore[arg-type]
        enabled=a.enabled,
        editor_mode=a.editor_mode,  # type: ignore[arg-type]
        state=_state(a, running, True),  # type: ignore[arg-type]
        if_this=describe_trigger(a.draft_trigger),
        then_that=describe_actions(a.draft_graph),
        trigger=TriggerDef.model_validate(a.draft_trigger or {"key": "", "params": {}}),
        graph=GraphDef.model_validate(a.draft_graph or {"nodes": [], "edges": []}),
        published_version=version.version_number if version else None,
        has_unpublished_changes=unpublished and a.status != "draft",
        high_risk=any(n.get("type") in HIGH_RISK for n in live_graph.get("nodes", [])),
        row_version=a.row_version,
        created_by_email=creator.email if creator else None,
        created_at=a.created_at,
        updated_at=a.updated_at,
        last_checked_at=a.last_checked_at,
        next_check_at=a.next_check_at,
        last_run_at=a.last_run_at,
        last_run_status=a.last_run_status,  # type: ignore[arg-type]
        last_run_summary=a.last_run_summary,
        attention_reason=a.attention_reason,
        runs_running=running,
        runs_succeeded=int(counts.get("succeeded", 0)),
        runs_failed=int(counts.get("failed", 0)),
    )


def get_or_404(
    db: Session, p: Principal, automation_id: uuid.UUID, *, lock: bool = False
) -> Automation:
    require_admin(p)
    stmt = select(Automation).where(
        Automation.id == automation_id, Automation.organization_id == p.organization_id
    )
    if lock:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    a = db.scalar(stmt)
    if a is None:
        raise NotFoundError("Workflow not found.")
    return a


def list_automations(
    db: Session,
    p: Principal,
    *,
    q: str | None,
    status: str | None,
    limit: int,
    offset: int,
) -> tuple[list[AutomationOut], int]:
    require_admin(p)
    stmt = select(Automation).where(Automation.organization_id == p.organization_id)
    stmt = (
        stmt.where(Automation.status != "archived")
        if status != "archived"
        else stmt.where(Automation.status == "archived")
    )
    if q and q.strip():
        stmt = stmt.where(
            func.lower(Automation.name).like("%" + re.sub(r"[%_\\]", "", q.strip().lower()) + "%")
        )
    if status in ("draft", "published"):
        stmt = stmt.where(Automation.status == status)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Automation.updated_at.desc()).limit(limit).offset(offset)).all()
    return [to_out(db, a) for a in rows], int(total)


def catalogue() -> CatalogueOut:
    return CatalogueOut(
        schema_version=SCHEMA_VERSION,
        conditions=[
            CatalogueEntry(
                key=c.key,
                label=c.label,
                description=c.description,
                supported=c.supported,
                unsupported_reason=c.unsupported_reason,
                schema_=c.params.model_json_schema(),
                example=c.example,
                variables=c.variables,
                kind=c.kind,
                observation=c.observation or None,
            )
            for c in CONDITIONS.values()
        ],
        actions=[
            CatalogueEntry(
                key=a.key,
                label=a.label,
                description=a.description,
                supported=a.supported,
                unsupported_reason=a.unsupported_reason,
                schema_=a.params.model_json_schema(),
                example=a.example,
                risk=a.risk,
                wizard=a.wizard,
                notes=a.notes,
            )
            for a in ACTIONS.values()
        ],
        expression_help=[
            "Comparisons: ==  !=  <  <=  >  >=",
            "Membership: in, not in (lists such as ['pdf','docx'])",
            "Text: contains, startswith, endswith, matches (regular expression, max 100 characters)",
            "Combine with and, or, not and parentheses",
            "Only the variables listed for the chosen condition exist; no functions, no code.",
        ],
    )


# ------------------------------------------------------------------------- mutations
def _clean_name(db: Session, p: Principal, name: str, except_id: uuid.UUID | None = None) -> str:
    name = name.strip()
    if not name:
        raise ValidationFailed("A workflow name is required.", code="name_required")
    stmt = select(Automation.id).where(
        Automation.organization_id == p.organization_id, func.lower(Automation.name) == name.lower()
    )
    if except_id:
        stmt = stmt.where(Automation.id != except_id)
    if db.scalar(stmt) is not None:
        raise ConflictError("A workflow with this name already exists.", code="name_conflict")
    return name


def _normalized(trigger: TriggerDef, graph: GraphDef) -> tuple[dict[str, Any], dict[str, Any]]:
    """Store parameters in their validated (defaulted, normalized) form where they validate."""
    t = trigger.model_dump(by_alias=True)
    spec = CONDITIONS.get(trigger.key)
    if spec:
        try:
            t["params"] = spec.params.model_validate(trigger.params).model_dump(mode="json")
        except ValidationError:
            pass
    g = graph.model_dump(by_alias=True, exclude_none=True)
    for n in g["nodes"]:
        aspec = ACTIONS.get(n["type"])
        if aspec:
            try:
                n["params"] = aspec.params.model_validate(n["params"]).model_dump(mode="json")
            except ValidationError:
                pass
    return t, g


def create(db: Session, p: Principal, body: AutomationCreate) -> AutomationOut:
    require_admin(p)
    name = _clean_name(db, p, body.name)
    report = validate_definition(db, p, body.trigger, body.graph)
    require_valid(report)
    trig, graph = _normalized(body.trigger, body.graph)
    a = Automation(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=name,
        description=(body.description or "").strip() or None,
        editor_mode=body.editor_mode,
        draft_trigger=trig,
        draft_graph=graph,
        created_by=p.user_id,
        updated_by=p.user_id,
    )
    db.add(a)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ConflictError(
            "A workflow with this name already exists.", code="name_conflict"
        ) from None
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.created",
        resource_type="automation",
        resource_id=a.id,
        metadata={"trigger": body.trigger.key, "mode": body.editor_mode},
    )
    if body.activate:
        _publish(db, p, a, report, confirm_high_risk=body.confirm_high_risk)
        _enable(db, p, a)
    db.commit()
    return to_out(db, a)


def update(
    db: Session, p: Principal, automation_id: uuid.UUID, body: AutomationUpdate
) -> AutomationOut:
    a = get_or_404(db, p, automation_id, lock=True)
    if a.status == "archived":
        raise ConflictError(
            "Archived workflows cannot be edited. Duplicate it instead.", code="archived"
        )
    if body.expected_row_version is not None and body.expected_row_version != a.row_version:
        raise ConflictError(
            "This workflow was changed elsewhere. Reload and try again.", code="stale_version"
        )
    if body.name is not None:
        a.name = _clean_name(db, p, body.name, a.id)
    if body.description is not None:
        a.description = body.description.strip() or None
    if body.trigger is not None or body.graph is not None:
        trigger = body.trigger or TriggerDef.model_validate(a.draft_trigger)
        graph = body.graph or GraphDef.model_validate(a.draft_graph)
        if not body.allow_invalid:
            require_valid(validate_definition(db, p, trigger, graph))
        a.draft_trigger, a.draft_graph = _normalized(trigger, graph)
    a.row_version += 1
    a.updated_by = p.user_id
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.updated",
        resource_type="automation",
        resource_id=a.id,
        metadata={
            "draft_only": True,
            "trigger_changed": body.trigger is not None,
            "graph_changed": body.graph is not None,
        },
    )
    db.commit()
    return to_out(db, a)


def _publish(
    db: Session, p: Principal, a: Automation, report: ValidationReport, *, confirm_high_risk: bool
) -> AutomationVersion:
    require_valid(report)
    if report.needs_high_risk_confirmation:
        if p.role != Role.OWNER.value:
            raise ForbiddenError(
                "Only an organization owner can publish a workflow with delete, ACL or email steps.",
                code="high_risk_owner_only",
            )
        if not confirm_high_risk:
            raise ValidationFailed(
                "This workflow contains high-risk steps. Confirm to publish.",
                code="high_risk_confirmation",
            )
    number = (
        db.scalar(
            select(func.coalesce(func.max(AutomationVersion.version_number), 0)).where(
                AutomationVersion.automation_id == a.id
            )
        )
        or 0
    ) + 1
    v = AutomationVersion(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        automation_id=a.id,
        version_number=number,
        schema_version=SCHEMA_VERSION,
        trigger=a.draft_trigger,
        graph=a.draft_graph,
        published_by=p.user_id,
        high_risk_confirmed=report.needs_high_risk_confirmation,
    )
    db.add(v)
    db.flush()
    a.published_version_id = v.id
    a.status = "published"
    a.attention_reason = None
    a.row_version += 1
    a.updated_by = p.user_id
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.published",
        resource_type="automation",
        resource_id=a.id,
        metadata={"version": number, "high_risk": report.needs_high_risk_confirmation},
    )
    if a.enabled:
        a.next_check_at = next_fire(a.draft_trigger, datetime.now(UTC), first=True)
    return v


def publish(
    db: Session, p: Principal, automation_id: uuid.UUID, *, confirm_high_risk: bool
) -> AutomationOut:
    a = get_or_404(db, p, automation_id, lock=True)
    if a.status == "archived":
        raise ConflictError("Archived workflows cannot be published.", code="archived")
    trigger = TriggerDef.model_validate(a.draft_trigger)
    graph = GraphDef.model_validate(a.draft_graph)
    report = validate_definition(db, p, trigger, graph)
    _publish(db, p, a, report, confirm_high_risk=confirm_high_risk)
    db.commit()
    return to_out(db, a)


def _enable(db: Session, p: Principal, a: Automation) -> None:
    if a.status != "published" or a.published_version_id is None:
        raise ConflictError("Publish the workflow before enabling it.", code="not_published")
    a.enabled = True
    a.attention_reason = None
    a.next_check_at = next_fire(a.draft_trigger, datetime.now(UTC), first=True)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.enabled",
        resource_type="automation",
        resource_id=a.id,
    )


def set_enabled(
    db: Session, p: Principal, automation_id: uuid.UUID, enabled: bool
) -> AutomationOut:
    a = get_or_404(db, p, automation_id, lock=True)
    if enabled:
        _enable(db, p, a)
    else:
        a.enabled = False
        a.next_check_at = None
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="automation.disabled",
            resource_type="automation",
            resource_id=a.id,
        )
    a.updated_by = p.user_id
    db.commit()
    return to_out(db, a)


def archive(db: Session, p: Principal, automation_id: uuid.UUID) -> AutomationOut:
    a = get_or_404(db, p, automation_id, lock=True)
    a.enabled = False
    a.status = "archived"
    a.next_check_at = None
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.archived",
        resource_type="automation",
        resource_id=a.id,
    )
    db.commit()
    return to_out(db, a)


def duplicate(db: Session, p: Principal, automation_id: uuid.UUID) -> AutomationOut:
    a = get_or_404(db, p, automation_id)
    base = f"{a.name} (copy)"
    name, n = base, 2
    while db.scalar(
        select(Automation.id).where(
            Automation.organization_id == p.organization_id,
            func.lower(Automation.name) == name.lower(),
        )
    ):
        name, n = f"{base} {n}", n + 1
    copy = Automation(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=name,
        description=a.description,
        editor_mode=a.editor_mode,
        draft_trigger=a.draft_trigger,
        draft_graph=a.draft_graph,
        created_by=p.user_id,
        updated_by=p.user_id,
    )
    db.add(copy)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.created",
        resource_type="automation",
        resource_id=copy.id,
        metadata={"duplicate_of": str(a.id)},
    )
    db.commit()
    return to_out(db, copy)


def validate_saved(db: Session, p: Principal, automation_id: uuid.UUID) -> ValidationReport:
    a = get_or_404(db, p, automation_id)
    return validate_definition(
        db, p, TriggerDef.model_validate(a.draft_trigger), GraphDef.model_validate(a.draft_graph)
    )
