"""Documenso adapter (REST API v1).

VERIFICATION STATUS: written from Documenso's public API documentation and exercised against a
mocked transport only. It has NOT been run against a live Documenso instance - see
docs/implementation-status.md. Licensing (AGPL/commercial) must be reviewed before production
use (ADR-0010, open decision).
"""

from __future__ import annotations

import hashlib
import hmac
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
    WebhookEvent,
)

_STATUS = {
    "PENDING": "pending",
    "COMPLETED": "completed",
    "DRAFT": "pending",
    "REJECTED": "declined",
}
_EVENT_TYPES = {
    "DOCUMENT_SENT",
    "DOCUMENT_OPENED",
    "DOCUMENT_SIGNED",
    "DOCUMENT_COMPLETED",
    "DOCUMENT_REJECTED",
    "DOCUMENT_CANCELLED",
}


class DocumensoProvider:
    name = "documenso"

    def __init__(
        self, base_url: str, api_key: str, webhook_secret: str, client: httpx.Client | None = None
    ) -> None:
        if not base_url or not api_key or not webhook_secret:
            raise RuntimeError(
                "DOCUMENSO_BASE_URL, DOCUMENSO_API_KEY and SIGNATURE_WEBHOOK_SECRET are required"
            )
        self._base = base_url.rstrip("/") + "/api/v1"
        self._headers = {"Authorization": api_key}
        self._secret = webhook_secret
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False
        )

    def _call(self, method: str, path: str, **kw):  # noqa: ANN003, ANN202
        try:
            r = self._client.request(method, f"{self._base}{path}", headers=self._headers, **kw)
        except httpx.HTTPError as exc:
            raise SignatureProviderError("signature provider unreachable") from exc
        if r.status_code >= 400:
            raise SignatureProviderError(f"signature provider returned HTTP {r.status_code}")
        return r

    def create_request(self, *, title, message, filename, content, size, signers):  # noqa: ANN001, ANN201
        body = {
            "title": title[:200],
            "recipients": [{"name": s.name, "email": s.email, "role": "SIGNER"} for s in signers],
            "meta": {
                "subject": f"Signature requested: {title[:150]}",
                "message": (message or "")[:2000],
            },
        }
        created = self._call("POST", "/documents", json=body).json()
        doc_id = str(created["documentId"])
        try:
            upload = self._client.put(
                created["uploadUrl"],
                content=b"".join(content),
                headers={"Content-Type": "application/pdf"},
            )
            if upload.status_code >= 400:
                raise SignatureProviderError(f"upload failed with HTTP {upload.status_code}")
        except httpx.HTTPError as exc:
            raise SignatureProviderError("upload failed") from exc
        self._call("POST", f"/documents/{doc_id}/send", json={"sendEmail": True})
        ids = {
            r["email"].lower(): str(r.get("recipientId", "")) for r in created.get("recipients", [])
        }
        return CreatedRequest(doc_id, ids)

    def get_state(self, provider_request_id: str) -> ProviderState:
        data = self._call("GET", f"/documents/{provider_request_id}").json()
        recipients = [
            RecipientState(
                email=r["email"].lower(),
                status="signed"
                if r.get("signingStatus") == "SIGNED"
                else "declined"
                if r.get("signingStatus") == "REJECTED"
                else "pending",
                signed_at=datetime.fromisoformat(r["signedAt"].replace("Z", "+00:00"))
                if r.get("signedAt")
                else None,
            )
            for r in data.get("recipients", [])
        ]
        return ProviderState(
            status=_STATUS.get(str(data.get("status")), "pending"), recipients=recipients
        )

    def download_signed(self, provider_request_id: str) -> Iterator[bytes]:
        link = (
            self._call("GET", f"/documents/{provider_request_id}/download")
            .json()
            .get("downloadUrl")
        )
        if not link:
            raise SignatureProviderError("no download url")
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
        # Documenso sends the shared secret in X-Documenso-Secret.
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
