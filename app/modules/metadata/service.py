"""Typed custom metadata: definitions (admin managed) and validation of document metadata."""

from __future__ import annotations

import re
import uuid
from datetime import date
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.models import MetadataDefinition
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.users.service import require_admin
from app.schemas.metadata import (
    MetadataDefinitionIn,
    MetadataDefinitionOut,
    MetadataDefinitionUpdate,
)

_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_TEXT = 1000
MAX_OPTIONS = 100
MAX_TOTAL_BYTES = 16_000


def _out(d: MetadataDefinition) -> MetadataDefinitionOut:
    return MetadataDefinitionOut(
        id=d.id,
        key=d.key,
        label=d.label,
        field_type=d.field_type,  # type: ignore[arg-type]
        required=d.required,
        options=d.options,
        schema_version=d.schema_version,
        archived=d.archived_at is not None,
    )


def list_definitions(
    db: Session, p: Principal, *, include_archived: bool = False
) -> list[MetadataDefinitionOut]:
    stmt = select(MetadataDefinition).where(MetadataDefinition.organization_id == p.organization_id)
    if not include_archived:
        stmt = stmt.where(MetadataDefinition.archived_at.is_(None))
    return [_out(d) for d in db.scalars(stmt.order_by(MetadataDefinition.label))]


def active_definitions(db: Session, organization_id: uuid.UUID) -> dict[str, MetadataDefinition]:
    return {
        d.key: d
        for d in db.scalars(
            select(MetadataDefinition).where(
                MetadataDefinition.organization_id == organization_id,
                MetadataDefinition.archived_at.is_(None),
            )
        )
    }


def _clean_options(field_type: str, options: list[str] | None) -> list[str] | None:
    if field_type != "select":
        if options:
            raise ValidationFailed("options are only valid for select fields.")
        return None
    cleaned = [o.strip() for o in (options or []) if o and o.strip()]
    if not cleaned or len(set(cleaned)) != len(cleaned) or len(cleaned) > MAX_OPTIONS:
        raise ValidationFailed("select fields need 1-100 unique, non-empty options.")
    return cleaned


def create_definition(
    db: Session, p: Principal, body: MetadataDefinitionIn
) -> MetadataDefinitionOut:
    require_admin(p)
    if not _KEY_RE.match(body.key):
        raise ValidationFailed(
            "key must be lowercase letters, digits and underscores, starting with a letter."
        )
    definition = MetadataDefinition(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        key=body.key,
        label=body.label.strip(),
        field_type=body.field_type,
        required=body.required,
        options=_clean_options(body.field_type, body.options),
        created_by=p.user_id,
    )
    db.add(definition)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("A field with this key already exists.", code="name_conflict") from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="metadata_definition.created",
        resource_type="metadata_definition",
        resource_id=definition.id,
        metadata={"key": body.key, "type": body.field_type, "required": body.required},
    )
    db.commit()
    return _out(definition)


def update_definition(
    db: Session, p: Principal, definition_id: uuid.UUID, body: MetadataDefinitionUpdate
) -> MetadataDefinitionOut:
    require_admin(p)
    d = db.scalar(
        select(MetadataDefinition).where(
            MetadataDefinition.id == definition_id,
            MetadataDefinition.organization_id == p.organization_id,
        )
    )
    if d is None:
        raise NotFoundError("Field not found.")
    changes: dict[str, Any] = {}
    if body.label is not None and body.label.strip() != d.label:
        d.label = body.label.strip()
        changes["label"] = d.label
    if body.required is not None and body.required != d.required:
        d.required = body.required
        changes["required"] = body.required
    if body.options is not None:
        d.options = _clean_options(d.field_type, body.options)
        changes["options"] = "updated"
    if body.archived is not None and body.archived != (d.archived_at is not None):
        d.archived_at = func.now() if body.archived else None  # type: ignore[assignment]
        changes["archived"] = body.archived
    if changes:
        d.schema_version += 1
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="metadata_definition.updated",
            resource_type="metadata_definition",
            resource_id=d.id,
            metadata={"key": d.key, **changes},
        )
    db.commit()
    db.refresh(d)
    return _out(d)


def _check_value(d: MetadataDefinition, value: Any) -> Any:
    t = d.field_type
    if t == "text":
        if not isinstance(value, str) or len(value) > MAX_TEXT:
            raise ValueError(f"must be text up to {MAX_TEXT} characters")
        return value
    if t == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("must be a number")
        return value
    if t == "boolean":
        if not isinstance(value, bool):
            raise ValueError("must be true or false")
        return value
    if t == "date":
        try:
            date.fromisoformat(str(value))
        except ValueError as exc:
            raise ValueError("must be a date (YYYY-MM-DD)") from exc
        return str(value)
    if t == "select":
        if value not in (d.options or []):
            raise ValueError("must be one of the allowed options")
        return value
    raise ValueError("unsupported field type")


def validate_document_metadata(
    db: Session, organization_id: uuid.UUID, metadata: dict[str, Any]
) -> dict[str, Any]:
    """Validate against the organization's active definitions (strict once any exist)."""
    if len(str(metadata)) > MAX_TOTAL_BYTES:
        raise ValidationFailed("Metadata is too large.")
    definitions = active_definitions(db, organization_id)
    if not definitions:
        if not all(isinstance(k, str) and 0 < len(k) <= 100 for k in metadata):
            raise ValidationFailed("Metadata keys must be non-empty strings (max 100 chars).")
        return metadata
    errors: list[dict[str, str]] = []
    cleaned: dict[str, Any] = {}
    for key, value in metadata.items():
        d = definitions.get(key)
        if d is None:
            errors.append({"field": key, "msg": "unknown metadata field"})
            continue
        if value is None:
            continue
        try:
            cleaned[key] = _check_value(d, value)
        except ValueError as exc:
            errors.append({"field": key, "msg": str(exc)})
    for key, d in definitions.items():
        if d.required and key not in cleaned:
            errors.append({"field": key, "msg": "is required"})
    if errors:
        raise ValidationFailed(
            "Metadata validation failed.", code="metadata_invalid", details=errors
        )
    return cleaned


def parse_filters(db: Session, organization_id: uuid.UUID, raw: list[str]) -> dict[str, str]:
    """``meta=key:value`` query parameters -> validated {key: value}."""
    definitions = active_definitions(db, organization_id)
    out: dict[str, str] = {}
    for item in raw[:5]:
        key, _, value = item.partition(":")
        if key not in definitions or not value:
            raise ValidationFailed(
                f"Unknown or empty metadata filter '{key}'.", code="unknown_metadata_key"
            )
        out[key] = value
    return out
