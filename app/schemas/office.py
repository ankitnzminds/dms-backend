"""Office-suite integration schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.schemas.common import ApiModel


class OfficeStatus(ApiModel):
    available: bool
    provider: str | None = None
    viewable_extensions: list[str] = Field(default_factory=list)
    editable_extensions: list[str] = Field(default_factory=list)


class OfficeSessionIn(ApiModel):
    mode: Literal["view", "edit"] = "view"


class OfficeSessionOut(ApiModel):
    editor_url: str = Field(
        description="Office server URL for the iframe. POST access_token to it (form post, "
        "target=iframe) - never put the token in a URL."
    )
    access_token: str = Field(
        description="Scoped to this document and mode, short-lived, re-authorized on every call."
    )
    access_token_ttl: int = Field(description="Expiry as epoch milliseconds (WOPI convention).")
    mode: Literal["view", "edit"]
    can_edit: bool
    reason: str | None = Field(None, description="Why you were given view instead of edit.")
    can_download: bool = Field(
        description="Print/export/copy are disabled in the editor when false."
    )
