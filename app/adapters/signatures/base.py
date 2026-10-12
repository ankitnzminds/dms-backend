"""Provider-neutral e-signature interface (ADR-0010).

The DMS never depends on a vendor's payload shapes: adapters translate to these types. Webhooks
are treated as *hints*; the authoritative status always comes from ``get_state``.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


class SignatureProviderError(Exception):
    """Provider unreachable / rejected the request (retryable or not, never a security verdict)."""


class InvalidWebhookError(Exception):
    """Signature/secret verification failed or the body is malformed."""


@dataclass(frozen=True)
class SignerSpec:
    email: str
    name: str
    order_index: int = 0


@dataclass(frozen=True)
class CreatedRequest:
    provider_request_id: str
    recipient_ids: dict[str, str] = field(default_factory=dict)  # email -> provider recipient id
    # email -> URL the signer opens. Secret-equivalent: never logged, audited or listed.
    signing_urls: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RecipientState:
    email: str
    status: str  # pending | signed | declined
    signed_at: datetime | None = None


@dataclass(frozen=True)
class ProviderState:
    status: str  # pending | completed | declined | cancelled | expired
    recipients: list[RecipientState] = field(default_factory=list)
    completed_at: datetime | None = None


@dataclass(frozen=True)
class WebhookEvent:
    event_id: str
    event_type: str
    provider_request_id: str


class SignatureProvider(Protocol):
    name: str

    def create_request(
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
    ) -> CreatedRequest: ...

    def get_state(self, provider_request_id: str) -> ProviderState: ...

    def download_signed(self, provider_request_id: str) -> Iterator[bytes]: ...

    def cancel(self, provider_request_id: str) -> None: ...

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> WebhookEvent:
        """Verify authenticity and extract the event. Raises InvalidWebhookError."""
