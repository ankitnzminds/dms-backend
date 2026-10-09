"""E-signature requests over an exact document version, webhook intake and reconciliation.

Security/integrity rules (ADR-0010):
  * Sending a document to a signature provider discloses it outside the DMS, so it needs the
    SHARE + DOWNLOAD rights, an organization opt-in, DLP clearance, and (unless explicitly
    allowed) internal signers only.
  * The request is bound to one immutable ``source_version``. The signed result is preserved as
    a NEW version (never an overwrite) and linked to that exact source version.
  * Webhooks are authenticated, deduplicated by provider event id, and treated only as a hint:
    the provider's own status API is the authority (``reconcile``), which also repairs lost,
    duplicated and out-of-order deliveries. Terminal states never regress.
  * No external call is made while holding a database lock.
"""

from __future__ import annotations

import hashlib
import tempfile
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, BinaryIO, cast

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.adapters.signatures.base import (
    InvalidWebhookError,
    SignatureProvider,
    SignatureProviderError,
    SignerSpec,
)
from app.adapters.signatures.factory import get_signature_provider
from app.adapters.storage.base import StorageError, new_object_key
from app.adapters.storage.registry import get_storage_provider
from app.core.config import get_settings
from app.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    NotFoundError,
    UnauthorizedError,
    ValidationFailed,
)
from app.db.enums import (
    Action,
    AuditOutcome,
    DocumentStatus,
    MembershipStatus,
    ScanStatus,
    UserStatus,
)
from app.db.models import (
    Document,
    DocumentVersion,
    Membership,
    SignatureEvent,
    SignatureRecipient,
    SignatureRequest,
    SignedArtifact,
    StorageLocation,
    User,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.modules.organizations.service import get_org, org_settings
from app.modules.outbox import service as outbox
from app.modules.quota import service as quota
from app.schemas.common import UserRef
from app.schemas.signatures import (
    SignatureArtifactOut,
    SignatureCapabilities,
    SignatureEventOut,
    SignatureRequestIn,
    SignatureRequestOut,
    SignerOut,
)

ACTIVE_STATES = ("creating", "sent")
TERMINAL_STATES = ("completed", "declined", "cancelled", "expired", "failed")
MAX_SIGNED_BYTES = 200 * 1024 * 1024


def capabilities(db: Session, p: Principal) -> SignatureCapabilities:
    provider = get_signature_provider()
    settings = org_settings(get_org(db, p.organization_id))
    return SignatureCapabilities(
        available=provider is not None,
        enabled=bool(settings["signatures_enabled"]),
        allow_external_signers=bool(settings["allow_external_signers"]),
        provider=provider.name if provider else None,
    )


def _require_provider() -> SignatureProvider:
    provider = get_signature_provider()
    if provider is None:
        raise ConflictError(
            "E-signature is not configured on this deployment.", code="signatures_unavailable"
        )
    return provider


# ------------------------------------------------------------------- create
def create_request(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, body: SignatureRequestIn
) -> SignatureRequestOut:
    p = authz.principal
    provider = _require_provider()
    settings = org_settings(get_org(db, p.organization_id))
    if not settings["signatures_enabled"]:
        raise ConflictError(
            "E-signature is not enabled for this organization.", code="feature_disabled"
        )

    doc = authz.require_document(document_id, Action.SHARE)
    authz.require_document(document_id, Action.DOWNLOAD)  # the bytes leave the DMS
    if doc.status != DocumentStatus.AVAILABLE.value or doc.current_version_id is None:
        raise ConflictError(
            "Only available documents can be sent for signature.", code="not_available"
        )
    if doc.classification in authz.share_blocked_classifications():
        raise ConflictError(
            f"Documents classified '{doc.classification}' cannot be sent for signature.",
            code="policy_blocked",
        )

    emails = [s.email.strip().lower() for s in body.signers]
    if len(set(emails)) != len(emails) or any(
        "@" not in e or e.startswith("@") or e.endswith("@") for e in emails
    ):
        raise ValidationFailed("Signers need unique, valid email addresses.")
    internal = {
        u.email: u
        for u in db.scalars(
            select(User)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == p.organization_id,
                Membership.status == MembershipStatus.ACTIVE.value,
                User.status == UserStatus.ACTIVE.value,
                User.email.in_(emails),
            )
        )
    }
    if not settings["allow_external_signers"] and set(emails) - set(internal):
        raise ValidationFailed(
            "External signers are not enabled; all signers must be members of this organization.",
            code="external_signers_disabled",
        )

    version = db.get(DocumentVersion, doc.current_version_id)
    assert version is not None and version.scan_status == ScanStatus.CLEAN.value
    if version.content_type != "application/pdf":
        raise ValidationFailed(
            "Only PDF documents can be sent for signature. Convert the file to PDF first.",
            code="pdf_required",
        )
    title = (body.title or doc.name)[:300]
    req = SignatureRequest(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        document_id=doc.id,
        source_version_id=version.id,
        requested_by=p.user_id,
        provider=provider.name,
        title=title,
        message=body.message,
        state="creating",
    )
    db.add(req)
    db.flush()
    for i, s in enumerate(body.signers):
        email = s.email.strip().lower()
        u = internal.get(email)
        db.add(
            SignatureRecipient(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                request_id=req.id,
                email=email,
                name=(s.name or (u.display_name if u else None) or email.split("@")[0])[:200],
                user_id=u.id if u else None,
                order_index=i,
            )
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.requested",
        resource_type="document",
        resource_id=doc.id,
        metadata={
            "request_id": str(req.id),
            "source_version": version.version_number,
            "signers": len(emails),
            "external": len(set(emails) - set(internal)),
        },
    )
    db.commit()

    # --- provider call happens OUTSIDE any transaction/lock
    location = db.get(StorageLocation, version.storage_location_id)
    assert location is not None
    storage = get_storage_provider(location.provider_type)
    signers = [SignerSpec(r.email, r.name, r.order_index) for r in _recipients(db, req.id)]
    try:
        created = provider.create_request(
            title=title,
            message=body.message,
            filename=version.original_filename,
            content=storage.stream_object(location.bucket, version.object_key),
            size=version.size_bytes,
            signers=signers,
            # External signers have no DMS account, so the provider e-mails them; internal-only
            # requests are signed inside the DMS (embedded signing page).
            send_email=bool(set(emails) - set(internal)),
        )
    except (SignatureProviderError, StorageError) as exc:
        req = db.get(SignatureRequest, req.id)  # type: ignore[assignment]
        assert req is not None
        req.state, req.failure_reason = "failed", str(exc)[:300]
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="signature.failed",
            resource_type="document",
            resource_id=doc.id,
            outcome=AuditOutcome.FAILURE,
            metadata={"request_id": str(req.id)},
        )
        db.commit()
        raise DependencyUnavailableError(
            "The signature provider is unavailable. Please try again later."
        ) from exc

    req = cast(SignatureRequest, db.get(SignatureRequest, req.id))
    req.state, req.provider_request_id = "sent", created.provider_request_id
    for r in _recipients(db, req.id):
        r.provider_recipient_id = created.recipient_ids.get(r.email)
        r.signing_url = created.signing_urls.get(r.email)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.sent",
        resource_type="document",
        resource_id=doc.id,
        metadata={"request_id": str(req.id), "provider": provider.name},
    )
    db.commit()
    return get_request(db, authz, req.id)


def _recipients(db: Session, request_id: uuid.UUID) -> list[SignatureRecipient]:
    return list(
        db.scalars(
            select(SignatureRecipient)
            .where(SignatureRecipient.request_id == request_id)
            .order_by(SignatureRecipient.order_index)
        )
    )


def cancel_request(db: Session, p: Principal, request_id: uuid.UUID) -> None:
    req = db.scalar(
        select(SignatureRequest).where(
            SignatureRequest.id == request_id, SignatureRequest.organization_id == p.organization_id
        )
    )
    if req is None or not (req.requested_by == p.user_id or p.is_admin):
        raise NotFoundError("Signature request not found.")
    if req.state not in ACTIVE_STATES:
        raise ConflictError(f"The request is already {req.state}.", code="invalid_state")
    provider = get_signature_provider()
    if req.provider_request_id and provider is not None:
        try:
            provider.cancel(req.provider_request_id)
        except SignatureProviderError as exc:
            raise DependencyUnavailableError(
                "The signature provider is unavailable; the request was not cancelled."
            ) from exc
    req.state = "cancelled"
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.cancelled",
        resource_type="document",
        resource_id=req.document_id,
        metadata={"request_id": str(req.id)},
    )
    db.commit()


# ------------------------------------------------------------------ webhooks
def receive_webhook(
    db: Session, provider_name: str, headers: Mapping[str, str], body: bytes
) -> str:
    """Authenticate, deduplicate and enqueue. Returns 'accepted' | 'duplicate' | 'ignored'."""
    provider = get_signature_provider()
    if provider is None or provider.name != provider_name:
        raise NotFoundError("Unknown provider.")
    try:
        event = provider.parse_webhook({k.lower(): v for k, v in headers.items()}, body)
    except InvalidWebhookError as exc:
        audit.record_independent(
            organization_id=None,
            actor_user_id=None,
            action="signature.webhook_rejected",
            outcome=AuditOutcome.DENIED,
            metadata={"provider": provider_name},
        )
        raise UnauthorizedError("Invalid webhook.", code="invalid_webhook") from exc

    req = db.scalar(
        select(SignatureRequest).where(
            SignatureRequest.provider == provider_name,
            SignatureRequest.provider_request_id == event.provider_request_id,
        )
    )
    row = (
        pg_insert(SignatureEvent)
        .values(
            id=uuid.uuid4(),
            provider=provider_name,
            provider_event_id=event.event_id,
            organization_id=req.organization_id if req else None,
            request_id=req.id if req else None,
            provider_request_id=event.provider_request_id,
            event_type=event.event_type[:80],
            status="received" if req else "ignored",
            payload={"event_type": event.event_type},
        )
        .on_conflict_do_nothing(constraint="uq_signature_events_dedupe")
        .returning(SignatureEvent.id)
    )
    event_id = db.execute(row).scalar()
    if event_id is None:
        db.commit()
        return "duplicate"
    if req is None:
        db.commit()
        return "ignored"
    outbox.enqueue(
        db,
        organization_id=req.organization_id,
        event_type="signature.event",
        aggregate_type="signature_event",
        aggregate_id=event_id,
        payload={"request_id": str(req.id)},
    )
    db.commit()
    return "accepted"


# --------------------------------------------------------------- reconciliation
def reconcile(
    factory: sessionmaker[Session], request_id: uuid.UUID, provider: SignatureProvider | None = None
) -> str:
    """Bring a request in line with the provider's authoritative state. Idempotent."""
    provider = provider or _require_provider()
    with factory() as db:
        req = db.get(SignatureRequest, request_id)
        if req is None or req.provider_request_id is None:
            return "skipped"
        if req.state in TERMINAL_STATES:
            return req.state
        pid = req.provider_request_id
    state = provider.get_state(pid)  # external call, no locks held

    with factory() as db:
        req = db.scalar(
            select(SignatureRequest)
            .where(SignatureRequest.id == request_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        assert req is not None
        if req.state in TERMINAL_STATES:
            return req.state
        req.last_reconciled_at = datetime.now(UTC)
        by_email = {r.email: r for r in _recipients(db, req.id)}
        for rs in state.recipients:
            r = by_email.get(rs.email.lower())
            if r is not None and r.status == "pending" and rs.status in ("signed", "declined"):
                r.status, r.signed_at = rs.status, rs.signed_at or datetime.now(UTC)
                audit.record(
                    db,
                    organization_id=req.organization_id,
                    actor_user_id=r.user_id,
                    action=f"signature.recipient_{rs.status}",
                    resource_type="document",
                    resource_id=req.document_id,
                    metadata={"request_id": str(req.id), "email": r.email},
                )
        if state.status in ("declined", "cancelled", "expired"):
            req.state = state.status
            if state.status != "cancelled":
                outbox.enqueue(
                    db,
                    organization_id=req.organization_id,
                    event_type="signature.finished",
                    aggregate_type="signature_request",
                    aggregate_id=req.id,
                    payload={"state": state.status},
                )
            audit.record(
                db,
                organization_id=req.organization_id,
                actor_user_id=None,
                action=f"signature.{state.status}",
                resource_type="document",
                resource_id=req.document_id,
                metadata={"request_id": str(req.id)},
            )
            db.commit()
            return req.state
        db.commit()
        if state.status != "completed":
            return "sent"
        source_version_id, doc_id, org_id, requested_by = (
            req.source_version_id,
            req.document_id,
            req.organization_id,
            req.requested_by,
        )

    return _store_signed_artifact(
        factory, provider, request_id, pid, source_version_id, doc_id, org_id, requested_by, state
    )


def _store_signed_artifact(  # noqa: PLR0913
    factory: sessionmaker[Session],
    provider: SignatureProvider,
    request_id: uuid.UUID,
    pid: str,
    source_version_id: uuid.UUID,
    doc_id: uuid.UUID,
    org_id: uuid.UUID,
    requested_by: uuid.UUID,
    state: Any,
) -> str:
    with factory() as db:
        if db.scalar(select(SignedArtifact.id).where(SignedArtifact.request_id == request_id)):
            return "completed"
        src = db.get(DocumentVersion, source_version_id)
        assert src is not None
        location = db.get(StorageLocation, src.storage_location_id)
        assert location is not None
        content_type, filename = src.content_type, src.original_filename
        bucket, provider_type, loc_id = location.bucket, location.provider_type, location.id

    storage = get_storage_provider(provider_type)
    key = new_object_key(org_id)
    hasher = hashlib.sha256()
    size = 0
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as spool:
        for chunk in provider.download_signed(pid):
            size += len(chunk)
            if size > MAX_SIGNED_BYTES:
                raise SignatureProviderError("signed document is unreasonably large")
            hasher.update(chunk)
            spool.write(chunk)
        if size == 0:
            raise SignatureProviderError("provider returned an empty signed document")
        spool.seek(0)
        storage.put_object(bucket, key, cast(BinaryIO, spool), size, content_type)
    digest = hasher.hexdigest()

    try:
        with factory() as db:
            req = db.scalar(
                select(SignatureRequest)
                .where(SignatureRequest.id == request_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            assert req is not None
            if req.state == "completed" or db.scalar(
                select(SignedArtifact.id).where(SignedArtifact.request_id == request_id)
            ):
                storage.delete_object(bucket, key)  # a concurrent reconcile won
                return "completed"
            doc = db.scalar(
                select(Document)
                .where(Document.id == doc_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            assert doc is not None
            doc.latest_version_number += 1
            doc.row_version += 1
            version = DocumentVersion(
                id=uuid.uuid4(),
                organization_id=org_id,
                document_id=doc_id,
                version_number=doc.latest_version_number,
                storage_location_id=loc_id,
                object_key=key,
                size_bytes=size,
                sha256=digest,
                content_type=content_type,
                original_filename=filename,
                created_by=requested_by,
                scan_status=ScanStatus.PENDING.value,
            )
            db.add(version)
            db.flush()
            quota.charge_direct(
                db,
                organization_id=org_id,
                reference_id=version.id,
                size_bytes=size,
                document_version_id=version.id,
            )
            evidence = {
                "provider": provider.name,
                "provider_request_id": pid,
                "status": state.status,
                "recipients": [
                    {
                        "email": r.email,
                        "status": r.status,
                        "signed_at": r.signed_at.isoformat() if r.signed_at else None,
                    }
                    for r in state.recipients
                ],
                "completed_at": (state.completed_at or datetime.now(UTC)).isoformat(),
                "signed_sha256": digest,
                "source_version_id": str(source_version_id),
            }
            db.add(
                SignedArtifact(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    request_id=request_id,
                    version_id=version.id,
                    source_version_id=source_version_id,
                    sha256=digest,
                    size_bytes=size,
                    evidence=evidence,
                )
            )
            req.state, req.completed_at = "completed", datetime.now(UTC)
            outbox.enqueue(
                db,
                organization_id=org_id,
                event_type="document_version.uploaded",
                aggregate_type="document_version",
                aggregate_id=version.id,
                payload={"document_id": str(doc_id), "version_number": version.version_number},
            )
            outbox.enqueue(
                db,
                organization_id=org_id,
                event_type="signature.finished",
                aggregate_type="signature_request",
                aggregate_id=request_id,
                payload={"state": "completed"},
            )
            audit.record(
                db,
                organization_id=org_id,
                actor_user_id=None,
                action="signature.completed",
                resource_type="document",
                resource_id=doc_id,
                metadata={
                    "request_id": str(request_id),
                    "source_version_id": str(source_version_id),
                    "signed_version_id": str(version.id),
                    "sha256": digest,
                },
            )
            db.commit()
    except Exception:
        storage.delete_object(bucket, key)
        raise
    return "completed"


def process_event(factory: sessionmaker[Session], event_id: uuid.UUID) -> str:
    """Worker side of a webhook: reconcile the request it refers to."""
    with factory() as db:
        ev = db.get(SignatureEvent, event_id)
        if ev is None or ev.status in ("processed", "ignored") or ev.request_id is None:
            return "skipped"
        request_id = ev.request_id
    try:
        result = reconcile(factory, request_id)
    except Exception as exc:
        with factory() as db:
            ev = db.get(SignatureEvent, event_id)
            if ev is not None:
                ev.error = f"{type(exc).__name__}: {str(exc)[:200]}"
                db.commit()
        raise
    with factory() as db:
        ev = db.get(SignatureEvent, event_id)
        if ev is not None:
            ev.status, ev.processed_at, ev.error = "processed", datetime.now(UTC), None
            db.commit()
    return result


def reconcile_stale(factory: sessionmaker[Session], limit: int = 50) -> dict[str, int]:
    """Maintenance: repair lost webhooks and clean up requests orphaned during creation."""
    minutes = get_settings().signature_reconcile_minutes
    cutoff = datetime.now(UTC) - timedelta(minutes=minutes)
    summary = {"reconciled": 0, "orphans_failed": 0, "errors": 0}
    with factory() as db:
        ids = list(
            db.scalars(
                select(SignatureRequest.id)
                .where(
                    SignatureRequest.state == "sent",
                    (SignatureRequest.last_reconciled_at.is_(None))
                    | (SignatureRequest.last_reconciled_at < cutoff),
                )
                .limit(limit)
            )
        )
        orphans = list(
            db.scalars(
                select(SignatureRequest).where(
                    SignatureRequest.state == "creating",
                    SignatureRequest.created_at < datetime.now(UTC) - timedelta(minutes=15),
                )
            )
        )
        for o in orphans:
            o.state, o.failure_reason = "failed", "creation did not complete"
            audit.record(
                db,
                organization_id=o.organization_id,
                actor_user_id=None,
                action="signature.failed",
                resource_type="document",
                resource_id=o.document_id,
                outcome=AuditOutcome.FAILURE,
                metadata={"request_id": str(o.id), "reason": "orphaned"},
            )
        db.commit()
        summary["orphans_failed"] = len(orphans)
    if get_signature_provider() is None:
        return summary
    for rid in ids:
        try:
            reconcile(factory, rid)
            summary["reconciled"] += 1
        except Exception:  # one bad request must not stop the sweep
            summary["errors"] += 1
    return summary


# ------------------------------------------------------------------ read models
def _out(
    db: Session, req: SignatureRequest, viewer_id: uuid.UUID | None = None
) -> SignatureRequestOut:
    users = {u.id: u for u in db.scalars(select(User).where(User.id == req.requested_by))}
    u = users.get(req.requested_by)
    doc = db.get(Document, req.document_id)
    src = db.get(DocumentVersion, req.source_version_id)
    art = db.scalar(select(SignedArtifact).where(SignedArtifact.request_id == req.id))
    art_version = db.get(DocumentVersion, art.version_id) if art else None
    events = list(
        db.scalars(
            select(SignatureEvent)
            .where(SignatureEvent.request_id == req.id)
            .order_by(SignatureEvent.received_at)
        )
    )
    return SignatureRequestOut(
        id=req.id,
        document_id=req.document_id,
        document_name=doc.name if doc else None,
        source_version_number=src.version_number if src else None,
        requested_by=UserRef(
            id=req.requested_by,
            display_name=u.display_name if u else None,
            email=u.email if u else None,
        ),
        provider=req.provider,
        state=req.state,
        title=req.title,
        message=req.message,  # type: ignore[arg-type]
        failure_reason=req.failure_reason,
        created_at=req.created_at,
        completed_at=req.completed_at,
        signers=[
            SignerOut(
                email=r.email,
                name=r.name,
                internal=r.user_id is not None,
                status=r.status,
                signed_at=r.signed_at,
            )
            for r in _recipients(db, req.id)
        ],  # type: ignore[arg-type]
        artifact=SignatureArtifactOut(
            version_id=art.version_id,
            version_number=art_version.version_number if art_version else None,
            sha256=art.sha256,
            size_bytes=art.size_bytes,
            created_at=art.created_at,
        )
        if art
        else None,
        my_signing_available=any(
            r.user_id == viewer_id and r.status == "pending" and bool(r.signing_url)
            for r in _recipients(db, req.id)
        )
        and req.state == "sent",
        events=[
            SignatureEventOut(event_type=e.event_type, status=e.status, received_at=e.received_at)
            for e in events
        ],
    )


def get_request(
    db: Session, authz: AuthorizationService, request_id: uuid.UUID
) -> SignatureRequestOut:
    p = authz.principal
    req = db.scalar(
        select(SignatureRequest).where(
            SignatureRequest.id == request_id, SignatureRequest.organization_id == p.organization_id
        )
    )
    if req is None:
        raise NotFoundError("Signature request not found.")
    is_signer = bool(
        db.scalar(
            select(SignatureRecipient.id).where(
                SignatureRecipient.request_id == req.id, SignatureRecipient.user_id == p.user_id
            )
        )
    )
    if not (p.is_admin or req.requested_by == p.user_id or is_signer):
        doc = authz.load_document(req.document_id, include_deleted=True)
        if doc is None or Action.VIEW.value not in authz.document_actions([doc])[doc.id]:
            raise NotFoundError("Signature request not found.")
    return _out(db, req, p.user_id)


def list_for_document(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID
) -> list[SignatureRequestOut]:
    doc = authz.require_document(document_id, Action.VIEW)
    reqs = db.scalars(
        select(SignatureRequest)
        .where(
            SignatureRequest.document_id == doc.id,
            SignatureRequest.organization_id == doc.organization_id,
        )
        .order_by(SignatureRequest.created_at.desc())
    )
    return [_out(db, r) for r in reqs]


def list_mine(
    db: Session, p: Principal, *, scope: str, limit: int, offset: int
) -> tuple[list[SignatureRequestOut], int]:
    stmt = select(SignatureRequest).where(SignatureRequest.organization_id == p.organization_id)
    if scope == "to_sign":  # requests where I am a signer ("My signatures")
        stmt = stmt.where(
            SignatureRequest.id.in_(
                select(SignatureRecipient.request_id).where(SignatureRecipient.user_id == p.user_id)
            )
        )
    elif not (scope == "all" and p.is_admin):
        stmt = stmt.where(SignatureRequest.requested_by == p.user_id)
    reqs = list(db.scalars(stmt.order_by(SignatureRequest.created_at.desc())))
    return [_out(db, r, p.user_id) for r in reqs[offset : offset + limit]], len(reqs)


def open_signing_session(db: Session, p: Principal, request_id: uuid.UUID) -> str:
    """The signing page URL for the CURRENT user, if they are a pending internal signer.

    The URL embeds the signer's secret token (document/documenso-guide.txt s.10): it is returned
    only to that user, only while the request is open, and is never logged or audited."""
    req = db.scalar(
        select(SignatureRequest).where(
            SignatureRequest.id == request_id, SignatureRequest.organization_id == p.organization_id
        )
    )
    rec = (
        db.scalar(
            select(SignatureRecipient).where(
                SignatureRecipient.request_id == request_id, SignatureRecipient.user_id == p.user_id
            )
        )
        if req
        else None
    )
    if req is None or rec is None:
        raise NotFoundError("Signature request not found.")
    if req.state != "sent":
        raise ConflictError(f"The request is {req.state}.", code="invalid_state")
    if rec.status != "pending":
        raise ConflictError("You have already responded to this request.", code="already_responded")
    if not rec.signing_url:
        raise ConflictError(
            "This request is signed through the link e-mailed to you.", code="no_signing_link"
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.signing_opened",
        resource_type="document",
        resource_id=req.document_id,
        metadata={"request_id": str(req.id)},
    )
    db.commit()
    return rec.signing_url


def refresh_request(
    factory: sessionmaker[Session], db: Session, authz: AuthorizationService, request_id: uuid.UUID
) -> SignatureRequestOut:
    """Ask the provider for the authoritative status now (the guide's 'I have finished signing')."""
    p = authz.principal
    req = db.scalar(
        select(SignatureRequest).where(
            SignatureRequest.id == request_id, SignatureRequest.organization_id == p.organization_id
        )
    )
    if req is None:
        raise NotFoundError("Signature request not found.")
    involved = (
        p.is_admin
        or req.requested_by == p.user_id
        or db.scalar(
            select(SignatureRecipient.id).where(
                SignatureRecipient.request_id == req.id, SignatureRecipient.user_id == p.user_id
            )
        )
    )
    if not involved:
        raise NotFoundError("Signature request not found.")
    try:
        reconcile(factory, request_id)
    except SignatureProviderError as exc:
        raise DependencyUnavailableError(
            "The signature provider is unavailable. Try again shortly."
        ) from exc
    db.expire_all()
    fresh = db.get(SignatureRequest, request_id)
    assert fresh is not None
    return _out(db, fresh, p.user_id)
