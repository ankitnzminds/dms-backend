"""Import every model so Base.metadata is complete for Alembic and tests."""

from app.db.models.access import PermissionGrant, ShareGrant, ShareRecipient
from app.db.models.identity import Group, GroupMembership, Membership, Organization, User
from app.db.models.platform import (
    AuditEvent,
    DocumentStar,
    Notification,
    OutboxEvent,
    ProcessedEvent,
    RecentDocument,
)
from app.db.models.tree import Document, DocumentVersion, Folder, StorageLocation
from app.db.models.uploads import QuotaLedgerEntry, UploadSession

__all__ = [
    "AuditEvent",
    "Document",
    "DocumentStar",
    "DocumentVersion",
    "Folder",
    "Group",
    "GroupMembership",
    "Membership",
    "Notification",
    "Organization",
    "OutboxEvent",
    "PermissionGrant",
    "ProcessedEvent",
    "QuotaLedgerEntry",
    "RecentDocument",
    "ShareGrant",
    "ShareRecipient",
    "StorageLocation",
    "UploadSession",
    "User",
]
