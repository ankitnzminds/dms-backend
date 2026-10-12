"""Central, server-side authorization (deny by default).

Effective actions of a principal on a resource are the union of:

  * org owner/admin role                         -> every action in their own organization
  * ownership (document owner / folder creator)  -> OWNER_ACTIONS (folder ownership inherits down)
  * permission grants (user, group, org-wide)    -> on the resource itself; on ancestors only
                                                    when ``inherit`` is true
  * active share grants addressed to the user or one of their groups
                                                 -> a *document* share applies to that document
                                                    only; a *folder* share applies to the folder
                                                    and its descendants - never to ancestors or
                                                    siblings

Grants never flow *upwards*: sharing a child confers nothing on its parent folder or siblings.
Every query is scoped by ``organization_id`` taken from the Principal.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, NotFoundError
from app.core.metrics import AUTHZ_DENIALS
from app.db.enums import (
    Action,
    AuditOutcome,
    DocumentStatus,
    RecipientType,
    ResourceType,
    SubjectType,
)
from app.db.models import (
    Document,
    Folder,
    Organization,
    PermissionGrant,
    ShareGrant,
    ShareRecipient,
    WorkflowTask,
)
from app.modules.audit import service as audit
from app.modules.authorization.actions import ALL_ACTIONS, OWNER_ACTIONS, expand_actions
from app.modules.identity.principal import Principal
from app.modules.policy_engine.runtime import PolicyRuntime
from app.modules.policy_engine.runtime import refs as policy_refs

MAX_TREE_DEPTH = 100

_CHAIN_SQL = text(
    """
    WITH RECURSIVE chain(start_id, folder_id, parent_id, depth) AS (
      SELECT f.id, f.id, f.parent_folder_id, 0
        FROM dms.folders f
       WHERE f.id = ANY(:ids) AND f.organization_id = :org
      UNION ALL
      SELECT c.start_id, p.id, p.parent_folder_id, c.depth + 1
        FROM chain c
        JOIN dms.folders p ON p.id = c.parent_id AND p.organization_id = :org
       WHERE c.depth < :max_depth
    )
    SELECT start_id, folder_id, depth FROM chain ORDER BY start_id, depth
    """
)


@dataclass(frozen=True)
class BreadcrumbSegment:
    folder_id: uuid.UUID | None  # None when the viewer may not navigate there
    name: str | None  # None when masked by policy
    navigable: bool


class AuthorizationService:
    def __init__(self, db: Session, principal: Principal) -> None:
        self.db = db
        self.principal = principal
        self._share_blocked: frozenset[str] | None = None
        self._policy = PolicyRuntime(db, principal)

    def share_blocked_classifications(self) -> frozenset[str]:
        """Classifications that shares cannot grant access to (organization DLP setting)."""
        if self._share_blocked is None:
            settings = self.db.scalar(
                select(Organization.settings).where(
                    Organization.id == self.principal.organization_id
                )
            )
            value = (settings or {}).get("share_blocked_classifications", ["restricted"])
            self._share_blocked = frozenset(value)
        return self._share_blocked

    # ------------------------------------------------------------------ chains
    def folder_chains(
        self, folder_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, list[tuple[uuid.UUID, int]]]:
        """For each folder: [(folder_id, depth)] from itself (0) up to the root."""
        ids = list({*folder_ids})
        if not ids:
            return {}
        rows = self.db.execute(
            _CHAIN_SQL,
            {"ids": ids, "org": self.principal.organization_id, "max_depth": MAX_TREE_DEPTH},
        ).all()
        chains: dict[uuid.UUID, list[tuple[uuid.UUID, int]]] = defaultdict(list)
        for start_id, folder_id, depth in rows:
            chains[start_id].append((folder_id, depth))
        return chains

    # ------------------------------------------------------------ effective sets
    def folder_actions(self, folder_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, frozenset[str]]:
        return self._effective(folder_ids=list(folder_ids), documents=[])[0]

    def document_actions(self, documents: Sequence[Document]) -> dict[uuid.UUID, frozenset[str]]:
        return self._effective(folder_ids=[], documents=list(documents))[1]

    def _effective(
        self, *, folder_ids: list[uuid.UUID], documents: list[Document]
    ) -> tuple[dict[uuid.UUID, frozenset[str]], dict[uuid.UUID, frozenset[str]]]:
        """ACL/share result, then the policy layer, which can only take actions away."""
        folder_sets, doc_sets = self._effective_acl(folder_ids=folder_ids, documents=documents)
        if not self._policy.rules():
            return folder_sets, doc_sets
        chains: dict[uuid.UUID, frozenset[uuid.UUID]] = {}
        if any(ld.rule.doc.scope_type == "folder" for ld in self._policy.rules()):
            raw = self.folder_chains([*folder_ids, *(d.folder_id for d in documents)])
            chains = {start: frozenset(fid for fid, _ in chain) for start, chain in raw.items()}
        return self._policy.restrict(dict(folder_sets), dict(doc_sets), documents, chains)

    def _effective_acl(
        self, *, folder_ids: list[uuid.UUID], documents: list[Document]
    ) -> tuple[dict[uuid.UUID, frozenset[str]], dict[uuid.UUID, frozenset[str]]]:
        p = self.principal
        org = p.organization_id
        folder_result: dict[uuid.UUID, frozenset[str]] = {}
        doc_result: dict[uuid.UUID, frozenset[str]] = {}

        if p.is_admin:
            # Administrators hold every action on everything *inside their own organization*.
            # Callers always load resources through org-scoped queries first.
            return (
                {f: ALL_ACTIONS for f in folder_ids},
                {d.id: ALL_ACTIONS for d in documents},
            )

        chains = self.folder_chains([*folder_ids, *(d.folder_id for d in documents)])
        chain_folder_ids = {fid for chain in chains.values() for fid, _ in chain}
        doc_ids = [d.id for d in documents]
        if not chain_folder_ids and not doc_ids:
            return folder_result, doc_result

        # Ownership is full power only in the user's OWN SPACE: a folder they created directly under the
        # organization root (or inside such a folder). Something a person creates inside a folder that was
        # merely shared with them never grants more than the share did: creating, copying or moving
        # content must not be a way to raise your own rights.
        owned_folders: set[uuid.UUID] = set()
        root_ids: set[uuid.UUID] = set()
        if chain_folder_ids:
            rows = self.db.execute(
                select(Folder.id, Folder.parent_folder_id, Folder.created_by).where(
                    Folder.id.in_(chain_folder_ids), Folder.organization_id == org
                )
            ).all()
            root_ids = {fid for fid, parent, _ in rows if parent is None}
            made_by_me = {fid: parent for fid, parent, by in rows if by == p.user_id}
            changed = True
            while (
                changed
            ):  # parents first: a folder is own space if its parent is the root or own space
                changed = False
                for fid, parent in made_by_me.items():
                    if fid not in owned_folders and (parent in root_ids or parent in owned_folders):
                        owned_folders.add(fid)
                        changed = True

        now = datetime.now(UTC)
        subject_match = or_(
            and_(
                PermissionGrant.subject_type == SubjectType.USER.value,
                PermissionGrant.subject_id == p.user_id,
            ),
            and_(
                PermissionGrant.subject_type == SubjectType.GROUP.value,
                PermissionGrant.subject_id.in_(list(p.group_ids) or [uuid.UUID(int=0)]),
            ),
            PermissionGrant.subject_type == SubjectType.ORGANIZATION.value,
        )
        resource_match = or_(
            and_(
                PermissionGrant.resource_type == ResourceType.FOLDER.value,
                PermissionGrant.resource_id.in_(chain_folder_ids or [uuid.UUID(int=0)]),
            ),
            and_(
                PermissionGrant.resource_type == ResourceType.DOCUMENT.value,
                PermissionGrant.resource_id.in_(doc_ids or [uuid.UUID(int=0)]),
            ),
        )
        perm_grants = self.db.scalars(
            select(PermissionGrant).where(
                PermissionGrant.organization_id == org,
                PermissionGrant.revoked_at.is_(None),
                or_(PermissionGrant.expires_at.is_(None), PermissionGrant.expires_at > now),
                subject_match,
                resource_match,
            )
        ).all()

        recipient_match = or_(
            and_(
                ShareRecipient.recipient_type == RecipientType.USER.value,
                ShareRecipient.recipient_id == p.user_id,
            ),
            and_(
                ShareRecipient.recipient_type == RecipientType.GROUP.value,
                ShareRecipient.recipient_id.in_(list(p.group_ids) or [uuid.UUID(int=0)]),
            ),
            and_(  # "EVERYONE": a share addressed to the whole organization
                ShareRecipient.recipient_type == RecipientType.ORGANIZATION.value,
                ShareRecipient.recipient_id == org,
            ),
        )
        share_rows = self.db.execute(
            select(
                ShareGrant.resource_type,
                ShareGrant.resource_id,
                # per-principal permissions override the share's default set
                func.coalesce(ShareRecipient.actions, ShareGrant.actions),
            )
            .join(
                ShareRecipient,
                and_(
                    ShareRecipient.share_grant_id == ShareGrant.id,
                    ShareRecipient.organization_id == ShareGrant.organization_id,
                ),
            )
            .where(
                ShareGrant.organization_id == org,
                ShareGrant.revoked_at.is_(None),
                or_(ShareGrant.expires_at.is_(None), ShareGrant.expires_at > now),
                recipient_match,
                or_(
                    and_(
                        ShareGrant.resource_type == ResourceType.FOLDER.value,
                        ShareGrant.resource_id.in_(chain_folder_ids or [uuid.UUID(int=0)]),
                    ),
                    and_(
                        ShareGrant.resource_type == ResourceType.DOCUMENT.value,
                        ShareGrant.resource_id.in_(doc_ids or [uuid.UUID(int=0)]),
                    ),
                ),
            )
        ).all()

        task_docs: set[uuid.UUID] = set()
        if doc_ids:
            task_docs = set(
                self.db.scalars(
                    select(WorkflowTask.document_id).where(
                        WorkflowTask.organization_id == org,
                        WorkflowTask.assignee_id == p.user_id,
                        WorkflowTask.status == "pending",
                        WorkflowTask.document_id.in_(doc_ids),
                    )
                )
            )

        folder_perm: dict[uuid.UUID, list[PermissionGrant]] = defaultdict(list)
        doc_perm: dict[uuid.UUID, list[PermissionGrant]] = defaultdict(list)
        for g in perm_grants:
            (folder_perm if g.resource_type == ResourceType.FOLDER.value else doc_perm)[
                g.resource_id
            ].append(g)
        folder_share: dict[uuid.UUID, set[str]] = defaultdict(set)
        doc_share: dict[uuid.UUID, set[str]] = defaultdict(set)
        for rtype, rid, actions in share_rows:
            (folder_share if rtype == ResourceType.FOLDER.value else doc_share)[rid].update(actions)

        blocked_classes = self.share_blocked_classifications()
        # "Inherit Folder Level Security" off: nothing above such a folder reaches it or below it.
        no_inherit: set[uuid.UUID] = set()
        if chain_folder_ids:
            no_inherit = set(
                self.db.scalars(
                    select(Folder.id).where(
                        Folder.id.in_(chain_folder_ids),
                        Folder.organization_id == org,
                        Folder.inherit_acl.is_(False),
                    )
                )
            )

        def from_folder_chain(
            start: uuid.UUID, extra_depth: int, include_shares: bool = True
        ) -> set[str]:
            acc: set[str] = set()
            for fid, depth in chains.get(start, []):
                effective_depth = depth + extra_depth
                for g in folder_perm.get(fid, ()):
                    if effective_depth == 0 or g.inherit:
                        acc.update(g.actions)
                if include_shares:
                    acc.update(folder_share.get(fid, ()))  # folder shares cover the subtree
                if fid in owned_folders:
                    acc.update(OWNER_ACTIONS)
                if fid in no_inherit:
                    break  # the chain is cut here
            return acc

        for fid in folder_ids:
            folder_result[fid] = expand_actions(from_folder_chain(fid, 0))

        for doc in documents:
            shared_ok = doc.classification not in blocked_classes
            acc = from_folder_chain(doc.folder_id, 1, include_shares=shared_ok)
            for g in doc_perm.get(doc.id, ()):
                acc.update(g.actions)
            if shared_ok:
                acc.update(doc_share.get(doc.id, ()))
            if doc.owner_id == p.user_id and (
                doc.folder_id in owned_folders or doc.folder_id in root_ids
            ):
                acc.update(OWNER_ACTIONS)
            if doc.id in task_docs:  # reviewers may read what they were asked to approve
                acc.update((Action.VIEW.value, Action.PREVIEW.value, Action.DOWNLOAD.value))
            effective = expand_actions(acc)
            # Documents that have not passed required checks are visible to their owner only.
            if doc.status != DocumentStatus.AVAILABLE.value and doc.owner_id != p.user_id:
                effective = frozenset()
            doc_result[doc.id] = effective
        return folder_result, doc_result

    # ------------------------------------------------------------------ require_*
    def load_folder(self, folder_id: uuid.UUID, *, include_deleted: bool = False) -> Folder | None:
        folder = self.db.scalar(
            select(Folder).where(
                Folder.id == folder_id, Folder.organization_id == self.principal.organization_id
            )
        )
        if folder is None or (folder.deleted_at is not None and not include_deleted):
            return None
        return folder

    def load_document(
        self, document_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Document | None:
        doc = self.db.scalar(
            select(Document).where(
                Document.id == document_id,
                Document.organization_id == self.principal.organization_id,
            )
        )
        if doc is None or (doc.deleted_at is not None and not include_deleted):
            return None
        return doc

    def require_folder(
        self, folder_id: uuid.UUID, action: Action, *, include_deleted: bool = False
    ) -> Folder:
        folder = self.load_folder(folder_id, include_deleted=include_deleted)
        if folder is None:
            self.deny("folder", folder_id, action, "not_found")
            raise NotFoundError("Folder not found.")
        actions = self.folder_actions([folder.id]).get(folder.id, frozenset())
        self._check(actions, action, "folder", folder.id)
        return folder

    def require_document(
        self, document_id: uuid.UUID, action: Action, *, include_deleted: bool = False
    ) -> Document:
        doc = self.load_document(document_id, include_deleted=include_deleted)
        if doc is None:
            self.deny("document", document_id, action, "not_found")
            raise NotFoundError("Document not found.")
        actions = self.document_actions([doc]).get(doc.id, frozenset())
        self._check(actions, action, "document", doc.id)
        return doc

    def _check(self, actions: frozenset[str], action: Action, rtype: str, rid: uuid.UUID) -> None:
        if Action.DISCOVER.value not in actions:
            # Indistinguishable from "does not exist": no existence oracle for unauthorized ids.
            self.deny(rtype, rid, action, "not_visible")
            raise NotFoundError(f"{rtype.capitalize()} not found.")
        if action.value not in actions:
            blocked = self._policy.denial(rtype, rid, action.value)
            if blocked is not None:
                # Stable reason code + the policy revisions involved; the user is told only that a
                # policy applies, never which rule or its configuration.
                self.deny(rtype, rid, action, blocked.reason, policies=policy_refs(blocked))
                raise ForbiddenError(
                    "This action is blocked by an organization policy.", code="policy_denied"
                )
            self.deny(rtype, rid, action, "action_not_granted")
            raise ForbiddenError("You do not have permission to perform this action.")
        self._policy.observe(rtype, rid, action.value)

    def deny(
        self,
        rtype: str,
        rid: uuid.UUID,
        action: Action,
        reason: str,
        *,
        policies: list[dict[str, object]] | None = None,
    ) -> None:
        AUTHZ_DENIALS.labels(action.value).inc()
        extra = {"policies": policies} if policies else {}
        audit.record_independent(
            organization_id=self.principal.organization_id,
            actor_user_id=self.principal.user_id,
            action="authz.denied",
            resource_type=rtype,
            resource_id=rid,
            outcome=AuditOutcome.DENIED,
            metadata={"requested_action": action.value, "reason": reason, **extra},
        )

    # ---------------------------------------------------------------- breadcrumbs
    def breadcrumbs_for_folders(
        self, folder_ids: Iterable[uuid.UUID], *, mask_unauthorized: bool = False
    ) -> dict[uuid.UUID, list[BreadcrumbSegment]]:
        """Canonical path (root first) for each folder, computed in three queries.

        Names are display context only: a segment is ``navigable`` solely if the viewer is
        independently authorized to open that folder. Optionally mask names of segments the
        viewer cannot open (policy ``mask_shared_breadcrumbs``)."""
        wanted = list({*folder_ids})
        chains = self.folder_chains(wanted)
        all_ids = {fid for chain in chains.values() for fid, _ in chain}
        if not all_ids:
            return {}
        names = dict(
            self.db.execute(
                select(Folder.id, Folder.name).where(
                    Folder.id.in_(all_ids), Folder.organization_id == self.principal.organization_id
                )
            ).all()
        )
        authorised = self.folder_actions(list(all_ids))
        result: dict[uuid.UUID, list[BreadcrumbSegment]] = {}
        for start, chain in chains.items():
            segments: list[BreadcrumbSegment] = []
            for fid, _depth in sorted(chain, key=lambda t: -t[1]):  # root first
                if Action.DISCOVER.value in authorised.get(fid, frozenset()):
                    segments.append(BreadcrumbSegment(fid, names.get(fid), True))
                elif mask_unauthorized:
                    segments.append(BreadcrumbSegment(None, None, False))
                else:
                    segments.append(BreadcrumbSegment(None, names.get(fid), False))
            result[start] = segments
        return result

    def breadcrumb_for_folder(
        self, folder_id: uuid.UUID, *, mask_unauthorized: bool = False
    ) -> list[BreadcrumbSegment]:
        return self.breadcrumbs_for_folders([folder_id], mask_unauthorized=mask_unauthorized).get(
            folder_id, []
        )
