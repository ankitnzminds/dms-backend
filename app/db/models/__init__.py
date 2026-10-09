"""Import every model so Base.metadata is complete for Alembic and tests."""

from app.db.models.access import PermissionGrant, ShareGrant, ShareRecipient
from app.db.models.chat import (
    AccessRequest,
    AgentRun,
    ChatConversation,
    ChatMessage,
    PendingAction,
    ToolExecution,
)
from app.db.models.comments import Comment
from app.db.models.directory import (
    DirectoryGroupLink,
    DirectorySource,
    DirectorySyncRun,
    DirectoryUserLink,
)
from app.db.models.governance import LegalHold, LegalHoldItem, RetentionPolicy
from app.db.models.identity import Group, GroupMembership, Membership, Organization, User
from app.db.models.platform import (
    AuditEvent,
    DocumentStar,
    FolderFavorite,
    Notification,
    NotificationPreference,
    OutboxEvent,
    ProcessedEvent,
    RecentDocument,
    UserPreference,
)
from app.db.models.processing import DocumentDerivative, DocumentText, MetadataDefinition
from app.db.models.signatures import (
    SignatureEvent,
    SignatureRecipient,
    SignatureRequest,
    SignedArtifact,
)
from app.db.models.tree import Document, DocumentVersion, Folder, StorageLocation
from app.db.models.uploads import QuotaLedgerEntry, UploadSession
from app.db.models.workflows import (
    ApprovalAction,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    WorkflowRun,
    WorkflowTask,
)

__all__ = [
    "Comment",
    "AccessRequest",
    "AgentRun",
    "ChatConversation",
    "ChatMessage",
    "PendingAction",
    "ToolExecution",
    "DirectoryGroupLink",
    "DirectorySource",
    "DirectorySyncRun",
    "DirectoryUserLink",
    "SignatureEvent",
    "SignatureRecipient",
    "SignatureRequest",
    "SignedArtifact",
    "ApprovalAction",
    "WorkflowDefinition",
    "WorkflowDefinitionVersion",
    "WorkflowRun",
    "WorkflowTask",
    "AuditEvent",
    "Document",
    "DocumentDerivative",
    "DocumentText",
    "MetadataDefinition",
    "DocumentStar",
    "DocumentVersion",
    "Folder",
    "FolderFavorite",
    "Group",
    "LegalHold",
    "LegalHoldItem",
    "RetentionPolicy",
    "GroupMembership",
    "Membership",
    "Notification",
    "NotificationPreference",
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
    "UserPreference",
]
