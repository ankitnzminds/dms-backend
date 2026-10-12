"""E-signature schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ApiModel, UserRef


class SignerIn(ApiModel):
    email: str = Field(min_length=3, max_length=320)
    name: str | None = Field(None, max_length=200)


class PlacementIn(ApiModel):
    """Where the signature goes on the signing PDF, as percentages of the page (0-100)."""

    page_number: int = Field(ge=1, le=10_000)
    page_x: float = Field(ge=0, le=100)
    page_y: float = Field(ge=0, le=100)
    page_width: float = Field(gt=0, le=100)
    page_height: float = Field(gt=0, le=100)

    @model_validator(mode="after")
    def _inside(self) -> PlacementIn:
        if self.page_x + self.page_width > 100.0001 or self.page_y + self.page_height > 100.0001:
            raise ValueError("the signature box must stay inside the page")
        return self


class SignatureRequestIn(ApiModel):
    # Ignored when the document's folder has a signature chain (the chain decides the signers).
    signers: list[SignerIn] = Field(default_factory=list, max_length=10)
    title: str | None = Field(None, max_length=300)
    message: str | None = Field(None, max_length=2000)
    placement: PlacementIn | None = Field(
        None,
        description="Signature box for the external provider (other signers' boxes are stacked below it).",
    )
    provider: Literal["default", "builtin"] = Field(
        "default",
        description="default = the configured external provider (PDF only); builtin = typed-name "
        "consent inside the DMS (internal signers, any file type).",
    )


class SignRequestIn(ApiModel):
    agreed: bool = Field(description="The signer ticked the consent statement.")
    statement_version: str = Field(
        max_length=40, description="Version of the statement shown to the signer."
    )
    typed_name: str = Field(min_length=1, max_length=200)


class DeclineIn(ApiModel):
    reason: str | None = Field(None, max_length=500)


class SignatureStatementOut(ApiModel):
    version: str
    text: str


class SignerOut(ApiModel):
    email: str
    name: str
    internal: bool
    status: Literal["pending", "signed", "declined", "cancelled", "bypassed"]
    signed_at: datetime | None
    level: int = 1
    optional: bool = False
    is_super_signer: bool = False
    waiting: bool = Field(
        False, description="Pending, but an earlier signing level has not finished yet."
    )


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
    placement: PlacementIn | None = None
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
    builtin_available: bool = Field(
        True,
        description="Built-in typed-name consent is available (internal signers, any file type).",
    )


class ChainEntryIn(ApiModel):
    user_id: uuid.UUID
    optional: bool = False
    is_super_signer: bool = False


class ChainIn(ApiModel):
    """Levels run in order; signers inside a level are parallel. An empty list clears the chain."""

    levels: list[list[ChainEntryIn]] = Field(default_factory=list, max_length=20)
    # groups per level (same index); members are expanded when saved
    group_ids: list[list[uuid.UUID]] = Field(default_factory=list, max_length=20)


class ChainSignerOut(ApiModel):
    user_id: uuid.UUID
    name: str
    email: str
    optional: bool
    is_super_signer: bool


class ChainOut(ApiModel):
    folder_id: uuid.UUID
    levels: list[list[ChainSignerOut]]
