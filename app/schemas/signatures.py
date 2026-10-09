"""E-signature schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.common import ApiModel, UserRef


class SignerIn(ApiModel):
    email: str = Field(min_length=3, max_length=320)
    name: str | None = Field(None, max_length=200)


class SignatureRequestIn(ApiModel):
    signers: list[SignerIn] = Field(min_length=1, max_length=10)
    title: str | None = Field(None, max_length=300)
    message: str | None = Field(None, max_length=2000)


class SignerOut(ApiModel):
    email: str
    name: str
    internal: bool
    status: Literal["pending", "signed", "declined"]
    signed_at: datetime | None


class SignatureArtifactOut(ApiModel):
    version_id: uuid.UUID
    version_number: int | None
    sha256: str
    size_bytes: int
    created_at: datetime


class SignatureEventOut(ApiModel):
    event_type: str
    status: str
    received_at: datetime


class SignatureRequestOut(ApiModel):
    id: uuid.UUID
    document_id: uuid.UUID
    document_name: str | None
    source_version_number: int | None
    requested_by: UserRef
    provider: str
    state: Literal["creating", "sent", "completed", "declined", "cancelled", "expired", "failed"]
    title: str
    message: str | None
    failure_reason: str | None
    created_at: datetime
    completed_at: datetime | None
    signers: list[SignerOut]
    artifact: SignatureArtifactOut | None
    my_signing_available: bool = Field(
        False, description="The caller is a pending internal signer and can open the signing page."
    )
    events: list[SignatureEventOut]


class SigningSessionOut(ApiModel):
    url: str = Field(
        description="Signing page for the caller only. Treat like a password; do not store or log."
    )


class SignatureCapabilities(ApiModel):
    available: bool = Field(description="A provider is configured on this deployment.")
    enabled: bool = Field(description="The organization has enabled e-signature.")
    allow_external_signers: bool
    provider: str | None
