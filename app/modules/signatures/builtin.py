"""Built-in e-signature: typed-name consent recorded inside the DMS (no external provider).

What this is, and is not
  * It is an **electronic-signature record**: who agreed, when, to which EXACT document version
    (id + SHA-256 captured at request time) under which consent statement version.
  * It is **not** a cryptographic PDF signature and produces no new document version. Whether it
    satisfies a particular legal requirement is for the organization/legal counsel to decide.

Rules (documented defaults, covered by tests)
  * Internal signers only (they authenticate with their own DMS account).
  * Signers act in parallel: any pending signer may sign at any time (no levels/chains yet).
  * The request completes when every signer has signed; any decline declines the request.
  * Only the assigned signer may act, only while the request is ``sent`` and their own status is
    ``pending``. Signing and declining are separate operations; both are final.
  * The signer must tick consent for the *current* statement version and type their name.
  * The state change runs under a row lock and goes through ``transition`` (terminal states are final).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.context import get_client_ip, get_user_agent
from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import ScanStatus
from app.db.models import DocumentVersion, SignatureRecipient, SignatureRequest, StorageLocation
from app.modules.audit import service as audit
from app.modules.documents.downloads import Servable
from app.modules.identity.principal import Principal
from app.modules.outbox import service as outbox
from app.modules.signatures import chain
from app.schemas.signatures import SignRequestIn

PROVIDER_NAME = "builtin"
CONSENT_VERSION = "2026-10-v1"
CONSENT_TEXT = (
    "I have reviewed this document and I agree that typing my name below is my electronic signature "
    "on it. I understand that this is an electronic-signature record kept by this system, with the "
    "time, the exact document version and its checksum, and that it is not a cryptographic "
    "digital-certificate signature."
)
CONSENT_SHA256 = hashlib.sha256(CONSENT_TEXT.encode()).hexdigest()


def _locked(
    db: Session, p: Principal, request_id: uuid.UUID
) -> tuple[SignatureRequest, SignatureRecipient]:
    """The request (row-locked) and the CALLER's own recipient row; anything else is a 404."""
    req = db.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.id == request_id,
            SignatureRequest.organization_id == p.organization_id,
            SignatureRequest.provider == PROVIDER_NAME,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    rec = (
        db.scalar(
            select(SignatureRecipient)
            .where(
                SignatureRecipient.request_id == request_id, SignatureRecipient.user_id == p.user_id
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if req
        else None
    )
    if req is None or rec is None:
        raise NotFoundError("Signature request not found.")
    return req, rec


def _all(db: Session, request_id: uuid.UUID) -> list[SignatureRecipient]:
    return list(
        db.scalars(
            select(SignatureRecipient)
            .where(SignatureRecipient.request_id == request_id)
            .order_by(SignatureRecipient.level, SignatureRecipient.order_index)
            .execution_options(populate_existing=True)
        )
    )


def _require_open(
    req: SignatureRequest, rec: SignatureRecipient, recs: list[SignatureRecipient]
) -> chain.ChainState:
    if req.state != "sent":
        raise ConflictError(f"The request is {req.state}.", code="invalid_state")
    if rec.status != "pending":
        raise ConflictError("You have already responded to this request.", code="already_responded")
    state = chain.evaluate(recs)
    if not chain.can_act(rec, state):
        raise ConflictError(
            "An earlier signing level has not finished yet. You will be able to sign after it does.",
            code="not_your_turn",
        )
    return state


def _complete(
    db: Session, req: SignatureRequest, recs: list[SignatureRecipient], now: datetime
) -> None:
    """Last level done: optional signers still pending are no longer needed; the request completes."""
    from app.modules.signatures.service import transition

    for r in recs:
        if r.status == "pending":
            r.status, r.decline_reason = "bypassed", chain.DONE_REASON
    transition(req, "completed")
    req.completed_at = now
    outbox.enqueue(
        db,
        organization_id=req.organization_id,
        event_type="signature.finished",
        aggregate_type="signature_request",
        aggregate_id=req.id,
        payload={"state": "completed"},
    )
    audit.record(
        db,
        organization_id=req.organization_id,
        actor_user_id=None,
        action="signature.completed",
        resource_type="document",
        resource_id=req.document_id,
        metadata={
            "request_id": str(req.id),
            "provider": PROVIDER_NAME,
            "source_version_id": str(req.source_version_id),
        },
    )


def sign(db: Session, p: Principal, request_id: uuid.UUID, body: SignRequestIn) -> None:
    req, rec = _locked(db, p, request_id)
    recs = _all(db, req.id)
    before = _require_open(req, rec, recs)
    if not body.agreed:
        raise ValidationFailed(
            "You must agree to the signature statement to sign.", code="consent_required"
        )
    if body.statement_version != CONSENT_VERSION:
        raise ValidationFailed(
            "The signature statement has changed; reload it and agree again.",
            code="statement_outdated",
        )
    name = body.typed_name.strip()
    if not name:
        raise ValidationFailed("Type your full name to sign.", code="typed_name_required")
    src = db.get(DocumentVersion, req.source_version_id)
    if src is None or (req.source_sha256 and src.sha256 != req.source_sha256):
        # versions are immutable; this can only mean tampering or data loss: refuse and say so
        audit.record_independent(
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="integrity.mismatch",
            resource_type="signature_request",
            resource_id=req.id,
            metadata={"where": "builtin_sign"},
        )
        raise ConflictError(
            "The document version being signed is no longer intact.", code="integrity_error"
        )

    now = datetime.now(UTC)
    evidence: dict[str, Any] = {
        "method": "builtin_typed_name_consent",
        "statement_version": CONSENT_VERSION,
        "statement_sha256": CONSENT_SHA256,
        "typed_name": name[:200],
        "signer_user_id": str(p.user_id),
        "signer_email": p.email,
        "request_id": str(req.id),
        "document_id": str(req.document_id),
        "source_version_id": str(req.source_version_id),
        "source_sha256": req.source_sha256 or src.sha256,
        "signed_at": now.isoformat(),
        "chain_level": rec.level,
        "super_signer": rec.is_super_signer,
    }
    if get_settings().signature_record_client_info:
        evidence["client"] = {"ip": get_client_ip(), "user_agent": (get_user_agent() or "")[:300]}
    rec.status, rec.signed_at, rec.evidence = "signed", now, evidence
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.recipient_signed",
        resource_type="document",
        resource_id=req.document_id,
        metadata={
            "request_id": str(req.id),
            "provider": PROVIDER_NAME,
            "statement_version": CONSENT_VERSION,
            "source_version_id": str(req.source_version_id),
            "level": rec.level,
            "optional": rec.optional,
        },
    )
    if rec.is_super_signer:
        skipped = chain.bypass_after_super(recs, rec)
        for r in skipped:
            r.status, r.decline_reason = "bypassed", chain.BYPASS_REASON
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="signature.chain_override",
            resource_type="document",
            resource_id=req.document_id,
            metadata={"request_id": str(req.id), "level": rec.level, "bypassed": len(skipped)},
        )
    after = chain.evaluate(recs)
    if after.complete:
        _complete(db, req, recs, now)
    elif after.active_level != before.active_level:
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=None,
            action="signature.chain_advanced",
            resource_type="document",
            resource_id=req.document_id,
            metadata={"request_id": str(req.id), "level": after.active_level},
        )
    db.commit()


def decline(db: Session, p: Principal, request_id: uuid.UUID, reason: str | None) -> None:
    from app.modules.signatures.service import transition

    req, rec = _locked(db, p, request_id)
    recs = _all(db, req.id)
    _require_open(req, rec, recs)
    now = datetime.now(UTC)
    rec.status, rec.signed_at = "declined", now
    rec.decline_reason = (reason or "").strip()[:500] or None
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.recipient_declined",
        resource_type="document",
        resource_id=req.document_id,
        metadata={
            "request_id": str(req.id),
            "provider": PROVIDER_NAME,
            "level": rec.level,
            "optional": rec.optional,
        },
    )
    if rec.optional:  # an optional decline halts nothing; the chain may even be complete now
        if chain.evaluate(recs).complete:
            _complete(db, req, recs, now)
        db.commit()
        return
    for r in chain.halt_targets(recs, rec):
        r.status, r.decline_reason = "cancelled", chain.HALT_REASON
    transition(req, "declined")
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=None,
        action="signature.declined",
        resource_type="document",
        resource_id=req.document_id,
        metadata={"request_id": str(req.id), "provider": PROVIDER_NAME},
    )
    outbox.enqueue(
        db,
        organization_id=req.organization_id,
        event_type="signature.finished",
        aggregate_type="signature_request",
        aggregate_id=req.id,
        payload={"state": "declined"},
    )
    db.commit()


def servable_source(db: Session, p: Principal, request_id: uuid.UUID) -> Servable:
    """The EXACT version being signed, for its signers to review (no DMS document rights needed)."""
    req = db.scalar(
        select(SignatureRequest).where(
            SignatureRequest.id == request_id,
            SignatureRequest.organization_id == p.organization_id,
            SignatureRequest.provider == PROVIDER_NAME,
        )
    )
    rec = (
        db.scalar(
            select(SignatureRecipient.id).where(
                SignatureRecipient.request_id == request_id, SignatureRecipient.user_id == p.user_id
            )
        )
        if req
        else None
    )
    if req is None or rec is None or req.state in ("cancelled", "failed", "expired"):
        raise NotFoundError("Signature request not found.")
    version = db.get(DocumentVersion, req.source_version_id)
    if version is None or version.scan_status != ScanStatus.CLEAN.value:
        raise NotFoundError("Signature request not found.")
    location = db.get(StorageLocation, version.storage_location_id)
    if location is None:
        raise NotFoundError("Signature request not found.")
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.document_viewed",
        resource_type="document",
        resource_id=req.document_id,
        metadata={"request_id": str(req.id), "source_version_id": str(version.id)},
    )
    db.commit()
    return Servable(
        location=location,
        object_key=version.object_key,
        size=version.size_bytes,
        content_type="application/octet-stream",
        disposition="attachment",
        filename=version.original_filename,
    )
