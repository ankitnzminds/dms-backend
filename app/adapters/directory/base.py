"""Directory (identity provisioning) interface. SSO/authentication is a separate concern: a
directory only tells the DMS *who exists, whether they are enabled, and who is in which group*,
keyed by stable external ids - never by mutable display names."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Protocol


class DirectoryError(Exception):
    """The directory could not be read (network, auth, malformed response)."""


@dataclass(frozen=True)
class DirUser:
    external_id: str
    email: str
    display_name: str | None = None
    active: bool = True


@dataclass(frozen=True)
class DirGroup:
    external_id: str
    name: str
    member_ids: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class DirSnapshot:
    users: list[DirUser]
    groups: list[DirGroup]


class DirectoryProvider(Protocol):
    def fetch(self) -> DirSnapshot: ...


_SECRET_REF = re.compile(r"^env:(DMS_DIR_[A-Z0-9_]{1,80})$")


def resolve_secret(ref: str | None) -> str | None:
    """``env:DMS_DIR_<NAME>`` only. The prefix stops an administrator from pointing a source at
    an arbitrary server secret (DATABASE_URL, service-role key, ...) and exfiltrating it."""
    if not ref:
        return None
    m = _SECRET_REF.match(ref)
    if not m:
        raise DirectoryError("secret_ref must look like env:DMS_DIR_<NAME>")
    value = os.environ.get(m.group(1))
    if not value:
        raise DirectoryError(f"environment variable {m.group(1)} is not set")
    return value
