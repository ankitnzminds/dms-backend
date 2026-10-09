"""Custom metadata field definitions."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import CurrentPrincipal, DbSession
from app.modules.metadata import service as metadata
from app.schemas.metadata import (
    MetadataDefinitionIn,
    MetadataDefinitionOut,
    MetadataDefinitionUpdate,
)

router = APIRouter(prefix="/metadata-definitions", tags=["metadata"])


@router.get("", response_model=list[MetadataDefinitionOut], summary="Custom metadata fields")
def list_definitions(
    db: DbSession, principal: CurrentPrincipal, include_archived: bool = False
) -> list[MetadataDefinitionOut]:
    include = include_archived and principal.is_admin
    return metadata.list_definitions(db, principal, include_archived=include)


@router.post(
    "", response_model=MetadataDefinitionOut, status_code=201, summary="Define a field (admin)"
)
def create_definition(
    body: MetadataDefinitionIn, db: DbSession, principal: CurrentPrincipal
) -> MetadataDefinitionOut:
    return metadata.create_definition(db, principal, body)


@router.patch(
    "/{definition_id}",
    response_model=MetadataDefinitionOut,
    summary="Edit or archive a field (admin)",
)
def update_definition(
    definition_id: uuid.UUID,
    body: MetadataDefinitionUpdate,
    db: DbSession,
    principal: CurrentPrincipal,
) -> MetadataDefinitionOut:
    return metadata.update_definition(db, principal, definition_id, body)
