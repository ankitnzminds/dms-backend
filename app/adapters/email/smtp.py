"""SMTP sender (STARTTLS or implicit TLS). Credentials come from server-side settings only."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage as MimeMessage
from email.utils import formatdate, make_msgid

from app.adapters.email.base import EmailMessage


class EmailDeliveryError(Exception):
    pass


class SmtpEmailSender:
    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        username: str | None = None,
        password: str | None = None,
        starttls: bool = True,
        implicit_tls: bool = False,
        timeout: float = 20.0,
    ) -> None:
        if not host or not sender:
            raise RuntimeError("SMTP_HOST and SMTP_FROM are required")
        self.host, self.port, self.sender = host, port, sender
        self.username, self.password = username, password
        self.starttls, self.implicit_tls, self.timeout = starttls, implicit_tls, timeout

    def send(self, message: EmailMessage) -> None:
        mime = MimeMessage()
        mime["From"] = self.sender
        mime["To"] = message.to
        mime["Subject"] = message.subject.replace("\r", " ").replace("\n", " ")[:200]
        mime["Date"] = formatdate(localtime=False)
        mime["Message-ID"] = make_msgid(domain=self.sender.split("@")[-1])
        mime["X-DMS-Idempotency-Key"] = message.idempotency_key
        mime.set_content(message.body_text)
        context = ssl.create_default_context()
        try:
            if self.implicit_tls:
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                    self.host, self.port, timeout=self.timeout, context=context
                )
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            with smtp:
                if self.starttls and not self.implicit_tls:
                    smtp.starttls(context=context)
                if self.username and self.password:
                    smtp.login(self.username, self.password)
                smtp.send_message(mime)
        except (smtplib.SMTPException, OSError) as exc:
            raise EmailDeliveryError(f"email delivery failed: {type(exc).__name__}") from exc
