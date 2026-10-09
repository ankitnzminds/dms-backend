"""Email adapter interface. Messages never carry document content or access tokens."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class EmailMessage:
    to: str
    subject: str
    body_text: str
    idempotency_key: str


class EmailSender(Protocol):
    def send(self, message: EmailMessage) -> None: ...


class LogEmailSender:
    """Development sender: records that an email *would* be sent (no body, no addresses in logs)."""

    def send(self, message: EmailMessage) -> None:
        from app.core.logging import get_logger

        get_logger(__name__).info(
            "email_suppressed", extra={"idempotency_key": message.idempotency_key}
        )
