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
from app.modules.signatures import chain, chain_config, pdf_convert, url_crypto
from app.schemas.common import UserRef
from app.schemas.signatures import (
    SignatureArtifactOut,
    SignatureCapabilities,
    SignatureEventOut,
    SignatureRequestIn,
    SignatureRequestOut,
    SignerIn,
    SignerOut,
)

ACTIVE_STATES = ("creating", "sent")
TERMINAL_STATES = ("completed", "declined", "cancelled", "expired", "failed")
MAX_SIGNED_BYTES = 200 * 1024 * 1024

# The ONLY legal state changes. Terminal states have no way out, so a late or replayed event can never
# reopen or overwrite a finished request.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "creating": frozenset({"sent", "failed", "cancelled"}),
    "sent": frozenset({"completed", "declined", "cancelled", "expired", "failed"}),
}


def transition(req: SignatureRequest, new_state: str) -> None:
    """Move a request to ``new_state`` or refuse. Every writer of ``state`` goes through here."""
    if new_state not in ALLOWED_TRANSITIONS.get(req.state, frozenset()):
        raise ConflictError(
            f"A {req.state} signature request cannot become {new_state}.", code="invalid_transition"
        )
    req.state = new_state


def capabilities(db: Session, p: Principal) -> SignatureCapabilities:
    provider = get_signature_provider()
    settings = org_settings(get_org(db, p.organization_id))
    return SignatureCapabilities(
        builtin_available=True,
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
    builtin = body.provider == "builtin"
    provider = None if builtin else _require_provider()
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

    # A folder with a signature chain decides the signers (the body's list is ignored, as in the
    # reference app); otherwise the requester names them.
    steps = chain_config.steps_for_folder(db, p.organization_id, doc.folder_id)
    plan: dict[str, tuple[int, bool, bool]] = {}  # email -> (level, optional, super signer)
    signers_in = list(body.signers)
    if steps:
        chain_users = chain_config.chain_users(db, p.organization_id, steps)
        signers_in = []
        for st in steps:
            cu = chain_users[st.user_id]
            signers_in.append(SignerIn(email=cu.email, name=cu.display_name))
            plan[cu.email.lower()] = (st.level, st.optional, st.is_super_signer)
        if not builtin and any(opt or sup for _, opt, sup in plan.values()):
            raise ValidationFailed(
                "Optional and super signers need built-in signing: an external provider only finishes "
                "a document once every signer has signed.",
                code="chain_flags_builtin_only",
            )
    if not signers_in:
        raise ValidationFailed("Add at least one signer.")
    emails = [s.email.strip().lower() for s in signers_in]
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
    if builtin and set(emails) - set(internal):
        raise ValidationFailed(
            "Built-in signing needs every signer to be an active member of this organization.",
            code="builtin_internal_only",
        )
    if not settings["allow_external_signers"] and set(emails) - set(internal):
        raise ValidationFailed(
            "External signers are not enabled; all signers must be members of this organization.",
            code="external_signers_disabled",
        )

    version = db.get(DocumentVersion, doc.current_version_id)
    if version is None or version.scan_status != ScanStatus.CLEAN.value:
        raise ConflictError(
            "Only documents whose current version passed the malware scan can be sent for signature.",
            code="not_available",
        )
    # Serialize concurrent creators on the document row, then refuse a second active request.
    db.execute(select(Document.id).where(Document.id == doc.id).with_for_update())
    if db.scalar(
        select(SignatureRequest.id).where(
            SignatureRequest.organization_id == p.organization_id,
            SignatureRequest.document_id == doc.id,
            SignatureRequest.state.in_(ACTIVE_STATES),
        )
    ):
        raise ConflictError(
            "This document already has a signature request in progress. Cancel it or wait for it to finish.",
            code="signature_in_progress",
        )
    signing_pdf: bytes | None = None
    if builtin and body.placement is not None:
        raise ValidationFailed(
            "Signature placement is used with the external signing provider only.",
            code="placement_not_supported",
        )
    if not builtin:
        # The provider signs a PDF. Anything else is converted to a signing copy (the original is never
        # changed); a file that cannot be converted is refused with a clear reason, before any request exists.
        signing_pdf = _signing_pdf(db, version)
        if body.placement is not None and body.placement.page_number > pdf_convert.page_count(
            signing_pdf
        ):
            raise ValidationFailed(
                "The chosen page does not exist in this document.", code="placement_invalid"
            )
    title = (body.title or doc.name)[:300]
    req = SignatureRequest(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        document_id=doc.id,
        source_version_id=version.id,
        source_sha256=version.sha256,
        placement=body.placement.model_dump() if body.placement else None,
        requested_by=p.user_id,
        provider="builtin" if builtin else provider.name,  # type: ignore[union-attr]
        title=title,
        message=body.message,
        state="sent" if builtin else "creating",
    )
    db.add(req)
    db.flush()
    for i, s in enumerate(signers_in):
        email = s.email.strip().lower()
        u = internal.get(email)
        level, optional, super_signer = plan.get(email, (1, False, False))
        db.add(
            SignatureRecipient(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                request_id=req.id,
                email=email,
                name=(s.name or (u.display_name if u else None) or email.split("@")[0])[:200],
                user_id=u.id if u else None,
                order_index=i,
                level=level,
                optional=optional,
                is_super_signer=super_signer,
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
            "chain": bool(steps),
            "levels": len({lv for lv, _, _ in plan.values()}) if steps else 1,
            "external": len(set(emails) - set(internal)),
            "provider": req.provider,
        },
    )
    if builtin:
        outbox.enqueue(
            db,
            organization_id=p.organization_id,
            event_type="signature.requested",
            aggregate_type="signature_request",
            aggregate_id=req.id,
            payload={},
        )
    db.commit()
    if builtin:
        return get_request(db, authz, req.id)
    assert provider is not None

    # --- provider call happens OUTSIDE any transaction/lock
    assert signing_pdf is not None
    signers = [SignerSpec(r.email, r.name, r.order_index) for r in _recipients(db, req.id)]
    try:
        created = provider.create_request(
            title=title,
            message=body.message,
            filename=_signing_filename(version.original_filename),
            content=iter([signing_pdf]),
            size=len(signing_pdf),
            placement=body.placement.model_dump() if body.placement else None,
            signers=signers,
            # External signers have no DMS account, so the provider e-mails them; internal-only
            # requests are signed inside the DMS (embedded signing page).
            send_email=bool(set(emails) - set(internal)),
        )
    except (SignatureProviderError, StorageError) as exc:
        req = db.get(SignatureRequest, req.id)  # type: ignore[assignment]
        assert req is not None
        transition(req, "failed")
        req.failure_reason = str(exc)[:300]
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

    req = cast(
        SignatureRequest,
        db.scalar(
            select(SignatureRequest)
            .where(SignatureRequest.id == req.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ),
    )
    if req.state != "creating":  # cancelled while the provider call was in flight
        try:
            provider.cancel(created.provider_request_id)
        except SignatureProviderError:
            pass  # best effort; reconcile will see the provider state
        raise ConflictError(
            f"The request was {req.state} while it was being sent.", code="invalid_state"
        )
    transition(req, "sent")
    req.provider_request_id = created.provider_request_id
    for r in _recipients(db, req.id):
        r.provider_recipient_id = created.recipient_ids.get(r.email)
        url = created.signing_urls.get(r.email)
        r.signing_url = (
            url_crypto.encrypt(url) if url else None
        )  # secret-equivalent: encrypted at rest
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


def _signing_filename(name: str) -> str:
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return f"{stem}.pdf"


def _signing_pdf(db: Session, version: DocumentVersion) -> bytes:
    """The PDF sent for signing: the version itself if it is a PDF, otherwise a converted copy."""
    location = db.get(StorageLocation, version.storage_location_id)
    if location is None:
        raise ConflictError("The document's file is not available.", code="not_available")
    storage = get_storage_provider(location.provider_type)
    try:
        data = b"".join(storage.stream_object(location.bucket, version.object_key))
    except StorageError as exc:
        raise DependencyUnavailableError(
            "The document could not be read. Try again later."
        ) from exc
    try:
        return pdf_convert.convert_to_pdf(
            filename=version.original_filename, content_type=version.content_type, data=data
        )
    except pdf_convert.ConversionError as exc:
        raise ValidationFailed(str(exc), code="conversion_failed") from exc


def preview_signing_pdf(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID
) -> tuple[bytes, str]:
    """The exact PDF that would be sent for signing (for choosing where the signature goes)."""
    p = authz.principal
    doc = authz.require_document(document_id, Action.SHARE)
    authz.require_document(document_id, Action.DOWNLOAD)  # the bytes leave the DMS
    if doc.status != DocumentStatus.AVAILABLE.value or doc.current_version_id is None:
        raise ConflictError(
            "Only available documents can be sent for signature.", code="not_available"
        )
    version = db.get(DocumentVersion, doc.current_version_id)
    if version is None or version.scan_status != ScanStatus.CLEAN.value:
        raise ConflictError(
            "The document has not passed the malware scan yet.", code="not_available"
        )
    pdf = _signing_pdf(db, version)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="signature.preview_prepared",
        resource_type="document",
        resource_id=doc.id,
        metadata={
            "source_version": version.version_number,
            "converted": not version.content_type.endswith("pdf"),
        },
    )
    db.commit()
    return pdf, _signing_filename(version.original_filename)


def _recipients(db: Session, request_id: uuid.UUID) -> list[SignatureRecipient]:
    return list(
        db.scalars(
            select(SignatureRecipient)
            .where(SignatureRecipient.request_id == request_id)
            .order_by(SignatureRecipient.order_index)
        )
    )


def _locked_request(db: Session, p: Principal, request_id: uuid.UUID) -> SignatureRequest | None:
    req = db.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.id == request_id, SignatureRequest.organization_id == p.organization_id
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if req is None or not (req.requested_by == p.user_id or p.is_admin):
        return None
    return req


def cancel_request(db: Session, p: Principal, request_id: uuid.UUID) -> None:
    """Cancel in two short locked phases around the provider call, so it cannot race with a
    reconcile that completes the request in between (the second phase re-checks the state)."""
    req = _locked_request(db, p, request_id)
    if req is None:
        raise NotFoundError("Signature request not found.")
    if req.state not in ACTIVE_STATES:
        raise ConflictError(f"The request is already {req.state}.", code="invalid_state")
    provider_request_id = req.provider_request_id
    db.rollback()  # release the lock before the external call
    provider = get_signature_provider()
    if provider_request_id and provider is not None:
        try:
            provider.cancel(provider_request_id)
        except SignatureProviderError as exc:
            raise DependencyUnavailableError(
                "The signature provider is unavailable; the request was not cancelled."
            ) from exc
    req = _locked_request(db, p, request_id)
    if req is None:
        raise NotFoundError("Signature request not found.")
    if req.state not in ACTIVE_STATES:  # finished while we were talking to the provider
        raise ConflictError(f"The request is already {req.state}.", code="invalid_state")
    transition(req, "cancelled")
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
            transition(req, state.status)
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
        # the signed result is always a PDF; a converted source (docx, image, ...) keeps its name + " (signed)"
        content_type = "application/pdf"
        filename = (
            src.original_filename
            if src.content_type == "application/pdf"
            else f"{_signing_filename(src.original_filename)[:-4]} (signed).pdf"
        )
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
        if spool.read(5) != b"%PDF-":
            raise SignatureProviderError("the provider returned something that is not a PDF")
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
                "source_sha256": req.source_sha256,
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
            transition(req, "completed")
            req.completed_at = datetime.now(UTC)
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
            transition(o, "failed")
            o.failure_reason = "creation did not complete"
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
    recs = _recipients(db, req.id)
    state = chain.evaluate(recs)
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
                level=r.level,
                optional=r.optional,
                is_super_signer=r.is_super_signer,
                waiting=r.status == "pending"
                and req.state == "sent"
                and not chain.can_act(r, state),
            )
            for r in recs
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
            r.user_id == viewer_id
            and r.status == "pending"
            and (bool(r.signing_url) or req.provider == "builtin")
            and chain.can_act(r, state)
            for r in recs
        )
        and req.state == "sent",
        events=[
            SignatureEventOut(event_type=e.event_type, status=e.status, received_at=e.received_at)
            for e in events
        ],
        placement=req.placement,  # type: ignore[arg-type]
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
    db: Session, p: Principal, *, scope: str, limit: int, offset: int, status: str = "any"
) -> tuple[list[SignatureRequestOut], int]:
    stmt = select(SignatureRequest).where(SignatureRequest.organization_id == p.organization_id)
    if status == "active":  # still waiting for someone
        stmt = stmt.where(SignatureRequest.state.in_(ACTIVE_STATES))
    elif status == "finished":  # history: signed, declined, cancelled, expired, failed
        stmt = stmt.where(SignatureRequest.state.in_(TERMINAL_STATES))
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
    if not chain.can_act(rec, chain.evaluate(_recipients(db, req.id))):
        raise ConflictError(
            "An earlier signing level has not finished yet. You will be able to sign after it does.",
            code="not_your_turn",
        )
    if not rec.signing_url:
        raise ConflictError(
            "This request is signed through the link e-mailed to you.", code="no_signing_link"
        )
    url = url_crypto.read(rec.signing_url)
    if url is None:  # unreadable (key changed / corrupt): never hand out garbage
        raise ConflictError(
            "The signing link is no longer available. Ask the sender to send a new request.",
            code="no_signing_link",
        )
    if not url_crypto.is_encrypted(rec.signing_url):
        rec.signing_url = url_crypto.encrypt(url)  # upgrade a legacy plaintext row on first use
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
    return url


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
