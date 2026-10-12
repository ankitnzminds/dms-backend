"""E-signature requests and the provider webhook receiver."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from app.api.deps import Authz, CurrentPrincipal, DbSession, limited
from app.core.errors import ErrorResponse
from app.core.ratelimit import rate_limit
from app.modules.documents import downloads
from app.modules.signatures import builtin, chain_config
from app.modules.signatures import service as sig
from app.schemas.common import Page
from app.schemas.signatures import (
    ChainIn,
    ChainOut,
    DeclineIn,
    SignatureCapabilities,
    SignatureRequestIn,
    SignatureRequestOut,
    SignatureStatementOut,
    SigningSessionOut,
    SignRequestIn,
)

router = APIRouter(tags=["signatures"], responses={404: {"model": ErrorResponse}})


@router.get(
    "/signature-capabilities",
    response_model=SignatureCapabilities,
    summary="Is e-signature available and enabled?",
)
def capabilities(db: DbSession, principal: CurrentPrincipal) -> SignatureCapabilities:
    return sig.capabilities(db, principal)


@router.post(
    "/documents/{document_id}/signature-requests",
    response_model=SignatureRequestOut,
    status_code=201,
    summary="Send the current version to a signature provider (requires share + download)",
    dependencies=[limited("signature_create", sensitive=True)],
)
def create_request(
    document_id: uuid.UUID, body: SignatureRequestIn, db: DbSession, authz: Authz
) -> SignatureRequestOut:
    return sig.create_request(db, authz, document_id, body)


@router.get(
    "/documents/{document_id}/signature-requests",
    response_model=list[SignatureRequestOut],
    summary="Signature history of a document",
)
def document_requests(
    document_id: uuid.UUID, db: DbSession, authz: Authz
) -> list[SignatureRequestOut]:
    return sig.list_for_document(db, authz, document_id)


@router.get(
    "/signature-requests",
    response_model=Page[SignatureRequestOut],
    summary="My signature requests (admins: scope=all)",
)
def list_requests(
    db: DbSession,
    principal: CurrentPrincipal,
    scope: str = Query(
        "mine",
        pattern="^(mine|all|to_sign)$",
        description="mine = I requested; to_sign = I am a signer; all = admins",
    ),
    status: str = Query(
        "any",
        pattern="^(any|active|finished)$",
        description="active = still waiting; finished = history (signed, declined, cancelled, ...)",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[SignatureRequestOut]:
    items, total = sig.list_mine(
        db, principal, scope=scope, limit=limit, offset=offset, status=status
    )
    return Page[SignatureRequestOut](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/signature-requests/{request_id}",
    response_model=SignatureRequestOut,
    summary="Signature request with signers, events and signed artifact",
)
def get_request(request_id: uuid.UUID, db: DbSession, authz: Authz) -> SignatureRequestOut:
    return sig.get_request(db, authz, request_id)


@router.post(
    "/signature-requests/{request_id}/cancel", status_code=204, summary="Cancel a pending request"
)
def cancel_request(request_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> Response:
    sig.cancel_request(db, principal, request_id)
    return Response(status_code=204)


@router.post(
    "/signature-requests/{request_id}/signing-session",
    response_model=SigningSessionOut,
    summary="Open the signing page (embed in an iframe or new tab) - only for the pending signer",
    dependencies=[limited("signing_session", sensitive=True)],
)
def signing_session(
    request_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> SigningSessionOut:
    return SigningSessionOut(url=sig.open_signing_session(db, principal, request_id))


@router.get(
    "/documents/{document_id}/signature-preview-pdf",
    summary="The exact PDF that would be sent for signing (converted if needed) - to choose where the signature goes",
    dependencies=[limited("signature_preview", sensitive=True)],
    responses={422: {"model": ErrorResponse}},
)
def signature_preview_pdf(document_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    pdf, name = sig.preview_signing_pdf(db, authz, document_id)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": downloads.content_disposition("inline", name),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get(
    "/folders/{folder_id}/signature-chain",
    response_model=ChainOut,
    summary="The folder's signature chain (levels of signers); empty = manual signer selection",
)
def get_signature_chain(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> ChainOut:
    return chain_config.get_chain(db, authz, folder_id)


@router.put(
    "/folders/{folder_id}/signature-chain",
    response_model=ChainOut,
    summary="Replace the folder's signature chain (administrators); an empty chain removes it",
)
def set_signature_chain(
    folder_id: uuid.UUID, body: ChainIn, db: DbSession, principal: CurrentPrincipal
) -> ChainOut:
    return chain_config.set_chain(db, principal, folder_id, body)


@router.get(
    "/signature-statement",
    response_model=SignatureStatementOut,
    summary="The consent statement shown to built-in signers (versioned)",
)
def signature_statement(principal: CurrentPrincipal) -> SignatureStatementOut:
    return SignatureStatementOut(version=builtin.CONSENT_VERSION, text=builtin.CONSENT_TEXT)


@router.post(
    "/signature-requests/{request_id}/sign",
    status_code=204,
    summary="Built-in signing: agree to the statement and sign (the assigned signer only)",
    dependencies=[limited("signature_sign", sensitive=True)],
)
def sign_request(
    request_id: uuid.UUID, body: SignRequestIn, db: DbSession, principal: CurrentPrincipal
) -> Response:
    builtin.sign(db, principal, request_id, body)
    return Response(status_code=204)


@router.post(
    "/signature-requests/{request_id}/decline",
    status_code=204,
    summary="Built-in signing: decline (a separate, final operation)",
    dependencies=[limited("signature_sign", sensitive=True)],
)
def decline_request(
    request_id: uuid.UUID, body: DeclineIn, db: DbSession, principal: CurrentPrincipal
) -> Response:
    builtin.decline(db, principal, request_id, body.reason)
    return Response(status_code=204)


@router.get(
    "/signature-requests/{request_id}/document",
    summary="Built-in signing: download the exact version to be signed (signers only)",
    dependencies=[limited("signature_document", sensitive=True)],
)
def signing_document(
    request_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> StreamingResponse:
    s = builtin.servable_source(db, principal, request_id)
    return StreamingResponse(
        downloads.open_stream(s),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": downloads.content_disposition("attachment", s.filename),
            "Content-Length": str(s.size),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post(
    "/signature-requests/{request_id}/refresh",
    response_model=SignatureRequestOut,
    summary="Re-read the status from the provider now (after signing; webhook may be delayed)",
    dependencies=[limited("signature_refresh", sensitive=True)],
)
def refresh_request(request_id: uuid.UUID, db: DbSession, authz: Authz) -> SignatureRequestOut:
    from app.db.session import get_sessionmaker

    return sig.refresh_request(get_sessionmaker(), db, authz, request_id)


@router.post(
    "/webhooks/signatures/{provider}",
    status_code=202,
    summary="Provider webhook (authenticated by the provider's secret/signature; not for browsers)",
    responses={401: {"model": ErrorResponse}},
)
async def signature_webhook(provider: str, request: Request, db: DbSession) -> dict[str, str]:
    rate_limit("signature_webhook", sensitive=False)(request)
    body = await request.body()
    result = await run_in_threadpool(sig.receive_webhook, db, provider, dict(request.headers), body)
    return {"status": result}
