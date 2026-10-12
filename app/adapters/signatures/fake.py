"""In-memory signature provider for development and automated tests (refused in production).

It implements the same contract as a real provider, including an HMAC-signed webhook, so the
DMS-side verification, deduplication and reconciliation logic is exercised for real.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime

from app.adapters.signatures.base import (
    CreatedRequest,
    InvalidWebhookError,
    ProviderState,
    RecipientState,
    SignatureProviderError,
    SignerSpec,
    WebhookEvent,
)

SIGNATURE_HEADER = "x-fake-signature"


class _Doc:
    def __init__(self, content: bytes, signers: list[SignerSpec]) -> None:
        self.content = content
        self.send_email = False
        self.placement: dict[str, float] | None = None
        self.recipients: dict[str, tuple[str, datetime | None]] = {
            s.email: ("pending", None) for s in signers
        }
        self.status = "pending"
        self.completed_at: datetime | None = None


class FakeSignatureProvider:
    name = "fake"
    _docs: dict[str, _Doc] = {}  # shared so a separately constructed instance sees the same state
    _lock = threading.Lock()
    fail_next_create = False
    unavailable = False

    def __init__(self, webhook_secret: str) -> None:
        self._secret = webhook_secret.encode()

    # ---- provider contract
    def create_request(  # noqa: ANN201
        self,
        *,
        title,
        message,
        filename,
        content,
        size,
        signers,
        send_email=False,
        placement=None,  # noqa: ANN001
    ):
        if self.unavailable or FakeSignatureProvider.fail_next_create:
            FakeSignatureProvider.fail_next_create = False
            raise SignatureProviderError("provider unavailable")
        data = b"".join(content)
        rid = f"fake-{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._docs[rid] = _Doc(data, signers)
        self._docs[rid].send_email = send_email
        self._docs[rid].placement = placement
        return CreatedRequest(
            rid,
            {s.email: f"{rid}-{i}" for i, s in enumerate(signers)},
            {
                s.email: f"https://fake-sign.example/sign/{rid}-{i}-token"
                for i, s in enumerate(signers)
            },
        )

    def get_state(self, provider_request_id: str) -> ProviderState:
        if self.unavailable:
            raise SignatureProviderError("provider unavailable")
        doc = self._docs.get(provider_request_id)
        if doc is None:
            raise SignatureProviderError("unknown request")
        return ProviderState(
            status=doc.status,
            recipients=[RecipientState(e, s, at) for e, (s, at) in doc.recipients.items()],
            completed_at=doc.completed_at,
        )

    def download_signed(self, provider_request_id: str) -> Iterator[bytes]:
        doc = self._docs[provider_request_id]
        if doc.status != "completed":
            raise SignatureProviderError("not completed")
        yield doc.content
        yield b"\n%% signed by fake provider %%\n"

    def cancel(self, provider_request_id: str) -> None:
        doc = self._docs.get(provider_request_id)
        if doc and doc.status == "pending":
            doc.status = "cancelled"

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> WebhookEvent:
        given = headers.get(SIGNATURE_HEADER, "")
        expected = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(given, expected):
            raise InvalidWebhookError("bad signature")
        try:
            data = json.loads(body)
            return WebhookEvent(
                str(data["event_id"]), str(data["event_type"]), str(data["provider_request_id"])
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise InvalidWebhookError("malformed body") from exc

    # ---- test / dev helpers (act as "the signer clicked sign")
    @classmethod
    def sign(cls, provider_request_id: str, email: str) -> None:
        doc = cls._docs[provider_request_id]
        doc.recipients[email] = ("signed", datetime.now(UTC))
        if all(s == "signed" for s, _ in doc.recipients.values()):
            doc.status, doc.completed_at = "completed", datetime.now(UTC)

    @classmethod
    def decline(cls, provider_request_id: str, email: str) -> None:
        doc = cls._docs[provider_request_id]
        doc.recipients[email] = ("declined", datetime.now(UTC))
        doc.status = "declined"

    def build_webhook(
        self, event_type: str, provider_request_id: str, event_id: str | None = None
    ) -> tuple[bytes, dict[str, str]]:
        body = json.dumps(
            {
                "event_id": event_id or uuid.uuid4().hex,
                "event_type": event_type,
                "provider_request_id": provider_request_id,
            }
        ).encode()
        return body, {
            SIGNATURE_HEADER: hmac.new(self._secret, body, hashlib.sha256).hexdigest(),
            "content-type": "application/json",
        }

    @classmethod
    def reset(cls) -> None:
        cls._docs.clear()
        cls.fail_next_create = False
        cls.unavailable = False
