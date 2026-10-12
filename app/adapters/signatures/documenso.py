"""Documenso adapter (REST API v1) - follows document/documenso-guide.txt section 8.

Sequence per request (checked against the deployed instance's own OpenAPI document):
  1. POST /api/v1/documents            title + recipients (+ meta)    -> documentId, uploadUrl,
                                                                         recipients[{recipientId, token, signingUrl}]
  2. PUT  <uploadUrl>                  raw PDF bytes (application/pdf)
  3. POST /api/v1/documents/{id}/fields one SIGNATURE field per signer (percent coordinates);
                                       Documenso refuses to send a document without fields
  4. POST /api/v1/documents/{id}/send  {"sendEmail": bool}
  5. signer opens signingUrl (<DOCUMENSO_URL>/sign/<token>) - treat it like a password
  6. status via webhook (X-Documenso-Secret) or GET /api/v1/documents/{id}
  7. GET  /api/v1/documents/{id}/download -> {downloadUrl} (S3 storage transport)

The API token is sent as-is in the Authorization header (no "Bearer"). Only PDFs can be signed;
conversion of other formats is out of scope (the DMS rejects them up front).
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
from collections.abc import Iterator, Mapping
from datetime import datetime

import httpx

from app.adapters.signatures.base import (
    CreatedRequest,
    InvalidWebhookError,
    ProviderState,
    RecipientState,
    SignatureProviderError,
    SignerSpec,
    WebhookEvent,
)

_STATUS = {
    "PENDING": "pending",
    "DRAFT": "pending",
    "COMPLETED": "completed",
    "REJECTED": "declined",
    "CANCELLED": "cancelled",
}
_EVENT_TYPES = {
    "DOCUMENT_CREATED",
    "DOCUMENT_SENT",
    "DOCUMENT_OPENED",
    "DOCUMENT_SIGNED",
    "DOCUMENT_COMPLETED",
    "DOCUMENT_REJECTED",
    "DOCUMENT_CANCELLED",
}
# Signature box: 35% x 6% of the page, stacked from the lower part of the last page.
_FIELD_WIDTH, _FIELD_HEIGHT, _FIELD_X, _FIELD_Y0, _FIELD_STEP = 35.0, 6.0, 10.0, 62.0, 8.0


def _page_count(pdf: bytes) -> int:
    from pypdf import PdfReader

    try:
        return max(1, len(PdfReader(io.BytesIO(pdf), strict=False).pages))
    except Exception:  # noqa: BLE001 - malformed PDF: sign the first page rather than fail
        return 1


def _box(placement: dict[str, float] | None, index: int, pages: int) -> dict[str, float | int]:
    """The signature field of the ``index``-th signer. With a chosen placement the first signer gets exactly
    that box and the others are stacked directly below it (kept inside the page); without one the
    default spot on the last page is used, as before."""
    if placement is None:
        return {
            "pageNumber": pages,
            "pageX": _FIELD_X,
            "pageY": min(_FIELD_Y0 + index * _FIELD_STEP, 90.0),
            "pageWidth": _FIELD_WIDTH,
            "pageHeight": _FIELD_HEIGHT,
        }
    h = float(placement["page_height"])
    y = min(float(placement["page_y"]) + index * (h + 1.0), 100.0 - h)
    return {
        "pageNumber": min(int(placement["page_number"]), pages),
        "pageX": float(placement["page_x"]),
        "pageY": y,
        "pageWidth": float(placement["page_width"]),
        "pageHeight": h,
    }


class DocumensoProvider:
    name = "documenso"

    def __init__(
        self, base_url: str, api_key: str, webhook_secret: str, client: httpx.Client | None = None
    ) -> None:
        if not base_url or not api_key or not webhook_secret:
            raise RuntimeError(
                "DOCUMENSO_URL, DOCUMENSO_API_KEY and DOCUMENSO_WEBHOOK_SECRET are required"
            )
        if not base_url.startswith("https://") and "localhost" not in base_url:
            raise RuntimeError("DOCUMENSO_URL must be an https:// URL")
        self._root = base_url.rstrip("/")
        self._base = self._root + "/api/v1"
        self._headers = {"Authorization": api_key}
        self._secret = webhook_secret
        # Free-tier hosts can take a minute to wake up: generous read timeout, short connect.
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(90.0, connect=20.0), follow_redirects=False
        )

    def _call(self, method: str, path: str, **kw):  # noqa: ANN003, ANN202
        try:
            r = self._client.request(method, f"{self._base}{path}", headers=self._headers, **kw)
        except httpx.HTTPError as exc:
            raise SignatureProviderError("signature provider unreachable") from exc
        if r.status_code >= 400:
            # Never include the response body: it can echo request data.
            raise SignatureProviderError(f"signature provider returned HTTP {r.status_code}")
        return r

    def create_request(  # noqa: PLR0913
        self,
        *,
        title: str,
        message: str | None,
        filename: str,
        content: Iterator[bytes],
        size: int,
        signers: list[SignerSpec],
        send_email: bool = False,
        placement: dict[str, float] | None = None,
    ) -> CreatedRequest:
        pdf = b"".join(content)
        if not pdf.startswith(b"%PDF-"):
            raise SignatureProviderError("only PDF documents can be sent for signature")
        body = {
            "title": title[:200],
            "recipients": [
                {"name": s.name, "email": s.email, "role": "SIGNER", "signingOrder": s.order_index}
                for s in signers
            ],
            "meta": {
                "subject": f"Signature requested: {title[:150]}",
                "message": (message or "")[:2000],
            },
        }
        created = self._call("POST", "/documents", json=body).json()
        doc_id = str(created["documentId"])
        by_email = {r["email"].lower(): r for r in created.get("recipients", [])}
        try:
            self._upload(created["uploadUrl"], pdf)
            pages = _page_count(pdf)
            for i, s in enumerate(signers):
                rec = by_email.get(s.email.lower())
                if rec is None:
                    raise SignatureProviderError("recipient missing from provider response")
                self._call(
                    "POST",
                    f"/documents/{doc_id}/fields",
                    json={
                        "recipientId": rec["recipientId"],
                        "type": "SIGNATURE",
                        **_box(placement, i, pages),
                    },
                )
            self._call("POST", f"/documents/{doc_id}/send", json={"sendEmail": send_email})
        except SignatureProviderError:
            self._discard(doc_id)  # do not leave half-built documents on the provider
            raise
        return CreatedRequest(
            doc_id,
            {e: str(r.get("recipientId", "")) for e, r in by_email.items()},
            {e: str(r["signingUrl"]) for e, r in by_email.items() if r.get("signingUrl")},
        )

    def _upload(self, upload_url: str, pdf: bytes) -> None:
        try:
            r = self._client.put(
                upload_url, content=pdf, headers={"Content-Type": "application/pdf"}
            )
        except httpx.HTTPError as exc:
            raise SignatureProviderError("upload failed") from exc
        if r.status_code >= 400:
            raise SignatureProviderError(f"upload failed with HTTP {r.status_code}")

    def _discard(self, doc_id: str) -> None:
        try:
            self._call("DELETE", f"/documents/{doc_id}")
        except SignatureProviderError:
            pass

    def get_state(self, provider_request_id: str) -> ProviderState:
        data = self._call("GET", f"/documents/{provider_request_id}").json()
        recipients = []
        for r in data.get("recipients", []):
            signing = str(r.get("signingStatus", "")).upper()
            signed_at = r.get("signedAt")
            recipients.append(
                RecipientState(
                    email=str(r["email"]).lower(),
                    status="signed"
                    if signing == "SIGNED"
                    else "declined"
                    if signing in ("REJECTED", "DECLINED")
                    else "pending",
                    signed_at=datetime.fromisoformat(str(signed_at).replace("Z", "+00:00"))
                    if signed_at
                    else None,
                )
            )
        return ProviderState(
            status=_STATUS.get(str(data.get("status", "")).upper(), "pending"),
            recipients=recipients,
        )

    def download_signed(self, provider_request_id: str) -> Iterator[bytes]:
        link = (
            self._call("GET", f"/documents/{provider_request_id}/download")
            .json()
            .get("downloadUrl")
        )
        if not link:
            raise SignatureProviderError("provider returned no download url")
        try:
            with self._client.stream("GET", link) as r:
                if r.status_code >= 400:
                    raise SignatureProviderError(f"download failed with HTTP {r.status_code}")
                yield from r.iter_bytes(1024 * 1024)
        except httpx.HTTPError as exc:
            raise SignatureProviderError("download failed") from exc

    def cancel(self, provider_request_id: str) -> None:
        self._call("DELETE", f"/documents/{provider_request_id}")

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> WebhookEvent:
        # The shared secret arrives in X-Documenso-Secret and is checked on EVERY call.
        given = headers.get("x-documenso-secret", "")
        if not hmac.compare_digest(given.encode(), self._secret.encode()):
            raise InvalidWebhookError("bad secret")
        try:
            data = json.loads(body)
            event_type = str(data["event"])
            request_id = str(data["payload"]["id"])
        except (ValueError, KeyError, TypeError) as exc:
            raise InvalidWebhookError("malformed body") from exc
        if event_type not in _EVENT_TYPES:
            raise InvalidWebhookError("unsupported event")
        # No event id is provided: identical redeliveries dedupe on the body hash.
        return WebhookEvent(hashlib.sha256(body).hexdigest(), event_type, request_id)
