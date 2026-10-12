"""Closed vocabularies stored as constrained text (no PG enum types, easier migrations)."""

from __future__ import annotations

from enum import StrEnum


class OrgStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    OFFBOARDING = "offboarding"
    DELETION_REQUESTED = "deletion_requested"


class UserStatus(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    DISABLED = "disabled"


class MembershipStatus(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REMOVED = "removed"


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    AUDITOR = "auditor"


class AccessLevel(StrEnum):
    FULL = "full"  # licensed account with storage
    GUEST = "guest"  # licensed account, no storage
    EXTERNAL = "external"  # free account, no storage


class CreationSource(StrEnum):
    DEFAULT = "default"
    INVITATION = "invitation"
    CSV_IMPORT = "csv_import"
    DIRECTORY = "directory"


class PolicyScope(StrEnum):
    ORGANIZATION = "organization"
    GROUP = "group"
    USER = "user"


class GroupKind(StrEnum):
    GROUP = "group"
    DEPARTMENT = "department"
    TEAM = "team"


class DocumentStatus(StrEnum):
    PROCESSING = "processing"  # no version has passed required checks yet
    AVAILABLE = "available"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class ScanStatus(StrEnum):
    PENDING = "pending"
    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"


class UploadState(StrEnum):
    INITIATED = "initiated"
    UPLOADED = "uploaded"  # bytes verified in staging, awaiting finalize
    FINALIZED = "finalized"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ResourceType(StrEnum):
    FOLDER = "folder"
    DOCUMENT = "document"


class SubjectType(StrEnum):
    USER = "user"
    GROUP = "group"
    ORGANIZATION = "organization"


class RecipientType(StrEnum):
    USER = "user"
    GROUP = "group"
    ORGANIZATION = "organization"  # "EVERYONE": every active member of the organization


class LedgerEntryType(StrEnum):
    RESERVE = "reserve"
    COMMIT = "commit"
    RELEASE = "release"
    ADJUST = "adjust"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class OutboxStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    DONE = "done"
    DEAD = "dead"


class Action(StrEnum):
    """Capability vocabulary used by roles, grants and shares."""

    DISCOVER = "discover"  # list / know the resource exists
    VIEW = "view"  # metadata
    PREVIEW = "preview"
    DOWNLOAD = "download"
    UPLOAD_VERSION = "upload_version"
    CREATE_CHILD = "create_child"
    EDIT_METADATA = "edit_metadata"
    RENAME = "rename"
    MOVE = "move"
    COPY = "copy"
    SHARE = "share"
    MANAGE_ACCESS = "manage_access"
    DELETE = "delete"
    RESTORE = "restore"
    COMMENT = "comment"
    EXPORT = "export"
    SYNC = "sync"  # permitted to be synchronized by approved clients (stored; no sync client exists yet)
    ADMINISTER = "administer"
    # Granular create/version/lock rights (create_child is the older "create anything" umbrella).
    CREATE_FOLDER = "create_folder"
    UPLOAD = "upload"  # upload files into a folder
    CREATE_FILE = "create_file"  # create a new file in a folder
    VIEW_VERSIONS = "view_versions"
    RESTORE_VERSION = "restore_version"
    LOCK = "lock"  # lock / unlock (check out / in)


def values(enum_cls: type[StrEnum]) -> list[str]:
    return [e.value for e in enum_cls]
