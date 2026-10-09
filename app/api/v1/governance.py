"""Governance: retention policies, legal holds, protection status and permanent purge."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Response

from app.api.deps import Authz, CurrentPrincipal, DbSession
from app.core.errors import ErrorResponse
from app.db.enums import ResourceType
from app.modules.governance import service as gov
from app.schemas.governance import (
    LegalHoldIn,
    LegalHoldItemIn,
    LegalHoldItemOut,
    LegalHoldOut,
    ProtectionOut,
    PurgeOut,
    ReleaseHoldIn,
    RetentionPolicyIn,
    RetentionPolicyOut,
    RetentionPolicyUpdate,
)

router = APIRouter(tags=["governance"], responses={404: {"model": ErrorResponse}})


def _hold_out(hold, count: int) -> LegalHoldOut:  # noqa: ANN001
    return LegalHoldOut(
        id=hold.id,
        name=hold.name,
        description=hold.description,
        status=hold.status,
        item_count=count,
        created_at=hold.created_at,
        released_at=hold.released_at,
        release_reason=hold.release_reason,
    )


# ---- permanent deletion
@router.delete(
    "/trash/{kind}/{resource_id}",
    response_model=PurgeOut,
    summary="Permanently delete a trashed item (irreversible; blocked by holds and retention)",
)
def purge(
    kind: Literal["documents", "folders"], resource_id: uuid.UUID, db: DbSession, authz: Authz
) -> PurgeOut:
    stats = gov.purge(db, authz, "document" if kind == "documents" else "folder", resource_id)
    return PurgeOut(**stats)


@router.get(
    "/documents/{document_id}/protection",
    response_model=ProtectionOut,
    summary="Holds/retention affecting a document",
)
def document_protection(document_id: uuid.UUID, db: DbSession, authz: Authz) -> ProtectionOut:
    return ProtectionOut(**gov.protection_summary(db, authz, "document", document_id))


@router.get(
    "/folders/{folder_id}/protection",
    response_model=ProtectionOut,
    summary="Holds/retention affecting a folder subtree",
)
def folder_protection(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> ProtectionOut:
    return ProtectionOut(**gov.protection_summary(db, authz, "folder", folder_id))


# ---- retention policies
@router.get(
    "/admin/retention-policies",
    response_model=list[RetentionPolicyOut],
    summary="Retention policies (admins, auditors)",
)
def list_policies(db: DbSession, principal: CurrentPrincipal) -> list[RetentionPolicyOut]:
    return [RetentionPolicyOut.model_validate(p) for p in gov.list_policies(db, principal)]


@router.post(
    "/admin/retention-policies",
    response_model=RetentionPolicyOut,
    status_code=201,
    summary="Create a retention policy",
)
def create_policy(
    body: RetentionPolicyIn, db: DbSession, principal: CurrentPrincipal
) -> RetentionPolicyOut:
    return RetentionPolicyOut.model_validate(
        gov.create_policy(
            db,
            principal,
            name=body.name,
            description=body.description,
            scope_folder_id=body.scope_folder_id,
            min_retention_days=body.min_retention_days,
        )
    )


@router.patch(
    "/admin/retention-policies/{policy_id}",
    response_model=RetentionPolicyOut,
    summary="Enable/disable or change duration",
)
def update_policy(
    policy_id: uuid.UUID, body: RetentionPolicyUpdate, db: DbSession, principal: CurrentPrincipal
) -> RetentionPolicyOut:
    return RetentionPolicyOut.model_validate(
        gov.update_policy(
            db,
            principal,
            policy_id,
            enabled=body.enabled,
            min_retention_days=body.min_retention_days,
        )
    )


@router.delete(
    "/admin/retention-policies/{policy_id}", status_code=204, summary="Delete a retention policy"
)
def delete_policy(policy_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> Response:
    gov.delete_policy(db, principal, policy_id)
    return Response(status_code=204)


# ---- legal holds
@router.get(
    "/admin/legal-holds",
    response_model=list[LegalHoldOut],
    summary="Legal holds (admins, auditors)",
)
def list_holds(db: DbSession, principal: CurrentPrincipal) -> list[LegalHoldOut]:
    return [_hold_out(h, n) for h, n in gov.list_holds(db, principal)]


@router.post(
    "/admin/legal-holds",
    response_model=LegalHoldOut,
    status_code=201,
    summary="Create a legal hold",
)
def create_hold(body: LegalHoldIn, db: DbSession, principal: CurrentPrincipal) -> LegalHoldOut:
    return _hold_out(
        gov.create_hold(db, principal, name=body.name, description=body.description), 0
    )


@router.get(
    "/admin/legal-holds/{hold_id}/items",
    response_model=list[LegalHoldItemOut],
    summary="Items under a hold",
)
def hold_items(
    hold_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> list[LegalHoldItemOut]:
    return [LegalHoldItemOut(**i) for i in gov.hold_items(db, principal, hold_id)]


@router.post(
    "/admin/legal-holds/{hold_id}/items",
    response_model=LegalHoldItemOut,
    status_code=201,
    summary="Place a document/folder on hold",
)
def add_hold_item(
    hold_id: uuid.UUID, body: LegalHoldItemIn, db: DbSession, principal: CurrentPrincipal
) -> LegalHoldItemOut:
    item = gov.add_hold_item(
        db, principal, hold_id, ResourceType(body.resource_type), body.resource_id
    )
    return LegalHoldItemOut(
        id=item.id,
        resource_type=item.resource_type,
        resource_id=item.resource_id,  # type: ignore[arg-type]
        resource_name=None,
        created_at=item.created_at,
    )


@router.delete(
    "/admin/legal-holds/{hold_id}/items/{item_id}",
    status_code=204,
    summary="Remove an item from a hold",
)
def remove_hold_item(
    hold_id: uuid.UUID, item_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> Response:
    gov.remove_hold_item(db, principal, hold_id, item_id)
    return Response(status_code=204)


@router.post(
    "/admin/legal-holds/{hold_id}/release",
    response_model=LegalHoldOut,
    summary="Release a hold (audited)",
)
def release_hold(
    hold_id: uuid.UUID, body: ReleaseHoldIn, db: DbSession, principal: CurrentPrincipal
) -> LegalHoldOut:
    hold = gov.release_hold(db, principal, hold_id, body.reason)
    return _hold_out(hold, len(gov.hold_items(db, principal, hold_id)))
