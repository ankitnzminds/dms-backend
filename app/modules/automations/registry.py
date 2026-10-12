"""The allowlisted catalogue of conditions (IF) and actions (THEN).

Nothing outside this registry can run: a workflow stores only a *key* and typed parameters, and
the key is looked up here. Each entry has a Pydantic model (unknown fields rejected), bounds,
help text and an example, so the UI can render a typed form and the server validates the same
schema. ``supported=False`` entries are listed (so the catalogue is honest about the reference
flow) but cannot be selected, with the reason.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 1

ConditionKind = Literal["event", "timer", "scan", "manual"]
Days = Annotated[int, Field(ge=1, le=3650)]
Pattern = Annotated[str, Field(min_length=1, max_length=200)]


def _tz(v: str) -> str:
    try:
        ZoneInfo(v)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(
            f"Unknown timezone '{v}'. Use an IANA name such as Europe/Berlin."
        ) from None
    return v


def _norm_path(v: str | None) -> str | None:
    if v is None or v.strip() in ("", "/"):
        return None
    parts = [p for p in v.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError("Paths may not contain '..'.")
    return "/" + "/".join(parts)


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Scope(_Params):
    path: str | None = Field(None, description="Only items under this folder path, e.g. /Finance.")
    recursive: bool = Field(True, description="Include sub-folders.")
    exclude: list[Pattern] = Field(
        default_factory=list,
        max_length=20,
        description="Case-insensitive patterns; * matches any characters (e.g. *.tmp).",
    )
    expression: str | None = Field(
        None, max_length=500, description="Extra filter, e.g. file.size_bytes > 1000000."
    )

    @field_validator("path")
    @classmethod
    def _path(cls, v: str | None) -> str | None:
        return _norm_path(v)


class FileEvent(Scope):
    extensions: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9]{1,10}$")]] = Field(
        default_factory=list, max_length=30, description="Only these file extensions (no dot)."
    )


class FolderEvent(Scope):
    pass


class NoParams(_Params):
    pass


WhoCanStart = Literal["editors", "admins"]
_WHO = "Who may start it: anyone who can edit the item, or administrators only."
_INSTRUCTIONS = "Shown to the person who starts it (what will happen, what to prepare)."


class ManualFile(FileEvent):
    who_can_start: WhoCanStart = Field("editors", description=_WHO)
    instructions: str | None = Field(None, max_length=300, description=_INSTRUCTIONS)


class ManualFolder(FolderEvent):
    who_can_start: WhoCanStart = Field("editors", description=_WHO)
    instructions: str | None = Field(None, max_length=300, description=_INSTRUCTIONS)


class SizeThreshold(FileEvent):
    greater_than_bytes: Annotated[int, Field(ge=1, le=10**13)] = Field(
        ..., description="Fires when the file is larger than this many bytes."
    )


class StaleFiles(FileEvent):
    days: Days = Field(..., description="Not modified or created for this many days.")


class StaleShares(_Params):
    days: Days = Field(..., description="Not accessed for this many days.")
    expression: str | None = Field(None, max_length=500)


class PeriodicInterval(_Params):
    every_minutes: Annotated[int, Field(ge=15, le=60 * 24 * 31)] = Field(
        ..., description="Minimum 15 minutes."
    )
    timezone: str = "UTC"
    start_at: str | None = Field(None, description="ISO date-time; do not fire before this.")
    end_at: str | None = Field(None, description="ISO date-time; stop firing after this.")

    _t = field_validator("timezone")(_tz)


class PeriodicSchedule(_Params):
    frequency: Literal["hourly", "daily", "weekly", "monthly"]
    time: str = Field(
        "09:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$", description="HH:MM local time."
    )
    weekday: Annotated[int, Field(ge=0, le=6)] = Field(0, description="0 = Monday (weekly).")
    day_of_month: Annotated[int, Field(ge=1, le=28)] = Field(1, description="1-28 (monthly).")
    timezone: str = "UTC"

    _t = field_validator("timezone")(_tz)


class SpecifiedDate(_Params):
    run_at: str = Field(..., description="ISO date-time, e.g. 2027-01-31T09:00:00.")
    timezone: str = "UTC"

    _t = field_validator("timezone")(_tz)


class AccountAge(_Params):
    days: Days
    exclude_disabled: bool = True
    expression: str | None = Field(None, max_length=500)


class LastLoginAge(_Params):
    days: Days
    include_never_logged_in: bool = Field(
        False,
        description="Also match accounts that have never signed in (older than the threshold).",
    )
    exclude_disabled: bool = True
    expression: str | None = Field(None, max_length=500)


class AccountExpiring(_Params):
    within_days: Annotated[int, Field(ge=1, le=365)]
    expression: str | None = Field(None, max_length=500)


class UserCreated(_Params):
    expression: str | None = Field(None, max_length=500)


FILE_VARS = {
    "file.name": "File name",
    "file.path": "Full path, e.g. /Finance/report.pdf",
    "file.extension": "Lower-case extension without the dot",
    "file.size_bytes": "Size of the current version in bytes",
    "file.classification": "public | internal | confidential | restricted",
    "file.version_number": "Version number that triggered this",
    "actor.email": "Who did it (empty for system events)",
    "event.action": "The audit action name",
}
REQUEST_VARS = {
    **FILE_VARS,
    "request.id": "The access request",
    "request.actions": "What was asked for, comma-separated (e.g. view, download)",
}
FOLDER_VARS = {
    "folder.name": "Folder name",
    "folder.path": "Full path",
    "actor.email": "Who did it",
    "event.action": "The audit action name",
}
USER_VARS = {
    "user.email": "Account email",
    "user.display_name": "Display name",
    "user.role": "owner | admin | member | auditor",
    "user.age_days": "Days since the account was created",
    "user.days_since_login": "Days since the last login (empty if never)",
    "user.days_to_expiry": "Days until the account expires (empty if none)",
    "event.action": "The audit action name",
}
SHARE_VARS = {
    "share.days_since_access": "Days without access",
    "share.resource_type": "document | folder",
    "event.action": "The event name",
}
TIMER_VARS = {"event.action": "Always 'timer'"}


@dataclass(frozen=True)
class ConditionSpec:
    key: str
    label: str
    kind: ConditionKind
    params: type[BaseModel]
    variables: dict[str, str]
    description: str
    example: dict[str, Any]
    audit_actions: tuple[str, ...] = ()  # events that fire it (kind == "event")
    supported: bool = True
    unsupported_reason: str | None = None
    # how the event is observed, shown to the admin so nothing is overpromised
    observation: str = ""


CONDITIONS: dict[str, ConditionSpec] = {
    c.key: c
    for c in [
        ConditionSpec(
            "client_app_connected",
            "If any new client app connects",
            "event",
            NoParams,
            {},
            "A new desktop or mobile client registers with the organization.",
            {},
            supported=False,
            unsupported_reason="There are no desktop or mobile clients and no device registry yet.",
        ),
        ConditionSpec(
            "manual_file",
            "Started by a user on a file",
            "manual",
            ManualFile,
            FILE_VARS,
            "A person starts this workflow from a file's menu. Nothing runs by itself.",
            {"path": "/Contracts", "who_can_start": "editors"},
            observation="Appears under 'Start workflow' on files the person can edit and that "
            "match the scope. Steps run as the person who published the workflow.",
        ),
        ConditionSpec(
            "manual_folder",
            "Started by a user on a folder",
            "manual",
            ManualFolder,
            FOLDER_VARS,
            "A person starts this workflow from a folder's menu. Nothing runs by itself.",
            {"path": "/Projects", "who_can_start": "editors"},
            observation="Appears under 'Start workflow' on folders the person can add to and "
            "that match the scope. Steps run as the person who published the workflow.",
        ),
        ConditionSpec(
            "access_request_created",
            "If someone requests access to a file",
            "event",
            FileEvent,
            REQUEST_VARS,
            "Fires when a person asks for more access to a file (for example to download or edit "
            "it). Use Grant access or Deny access to answer it, or Human approval to ask "
            "someone first.",
            {"path": "/Finance"},
            ("access_request.created",),
            observation="Files only: requests for folders do not start workflows yet. "
            "Grant/Deny act as the person who published the workflow and need Manage access.",
        ),
        ConditionSpec(
            "file_metadata_updated",
            "If a file's details are edited",
            "event",
            FileEvent,
            FILE_VARS,
            "Fires when someone changes a file's metadata or classification.",
            {"path": "/Contracts"},
            ("document.metadata_updated",),
        ),
        ConditionSpec(
            "file_created",
            "If a file is created",
            "event",
            FileEvent,
            FILE_VARS,
            "Fires when the first version of a file has passed the security scan and is available.",
            {"path": "/Finance", "extensions": ["pdf"]},
            ("document.scan_clean",),
            observation="Fires after the malware scan, not at upload time. Version 1 only.",
        ),
        ConditionSpec(
            "folder_created",
            "If a folder is created",
            "event",
            FolderEvent,
            FOLDER_VARS,
            "Fires when a folder is created.",
            {"path": "/Projects"},
            ("folder.created",),
        ),
        ConditionSpec(
            "file_updated",
            "If a file is updated",
            "event",
            FileEvent,
            FILE_VARS,
            "Fires when a new version (version 2 or later) of a file becomes available.",
            {"path": "/Contracts"},
            ("document.scan_clean",),
            observation="Fires after the malware scan. Edits saved from the Office editor count.",
        ),
        ConditionSpec(
            "file_deleted",
            "If a file is deleted",
            "event",
            FileEvent,
            FILE_VARS,
            "Fires when a file is moved to the trash. Permanent purges are a different event.",
            {"path": "/HR"},
            ("document.deleted",),
        ),
        ConditionSpec(
            "folder_deleted",
            "If a folder is deleted",
            "event",
            FolderEvent,
            FOLDER_VARS,
            "Fires when a folder is moved to the trash.",
            {"path": "/Projects"},
            ("folder.deleted",),
        ),
        ConditionSpec(
            "file_downloaded",
            "If file is downloaded",
            "event",
            FileEvent,
            FILE_VARS,
            "Fires when a download link is issued for a file.",
            {"path": "/Finance"},
            ("document.download_url_issued",),
            observation="DMS sees the authorized request for the link, not the byte transfer itself. "
            "Previews are not downloads.",
        ),
        ConditionSpec(
            "comment_added",
            "If a comment is added",
            "event",
            FileEvent,
            FILE_VARS,
            "Fires when someone comments on a file. The comment text is never exposed to the workflow.",
            {},
            ("comment.created",),
        ),
        ConditionSpec(
            "file_stale",
            "If file was not modified/created in specified days",
            "scan",
            StaleFiles,
            FILE_VARS,
            "Checks daily for files whose latest version is older than the threshold.",
            {"days": 365, "path": "/Archive"},
            observation="Checked once a day; each file fires once per day at most.",
        ),
        ConditionSpec(
            "file_created_or_updated",
            "If a file is added or updated",
            "event",
            FileEvent,
            FILE_VARS,
            "Fires for every new available version, including the first.",
            {"extensions": ["docx"]},
            ("document.scan_clean",),
            observation="Fires after the malware scan.",
        ),
        ConditionSpec(
            "upload_size_threshold",
            "If file uploaded is bigger than expected size",
            "event",
            SizeThreshold,
            FILE_VARS,
            "A new version larger than the threshold became available.",
            {"greater_than_bytes": 104857600},
            ("document.scan_clean",),
        ),
        ConditionSpec(
            "download_size_threshold",
            "If file downloaded is bigger than expected size",
            "event",
            SizeThreshold,
            FILE_VARS,
            "A download link was issued for a file larger than the threshold.",
            {"greater_than_bytes": 52428800},
            ("document.download_url_issued",),
            observation="Size is the stored size of the current version.",
        ),
        ConditionSpec(
            "periodic_interval",
            "Perform an action periodically at specified time and interval",
            "timer",
            PeriodicInterval,
            TIMER_VARS,
            "Fires every N minutes (minimum 15).",
            {"every_minutes": 1440, "timezone": "UTC"},
        ),
        ConditionSpec(
            "specified_date",
            "Perform an action on the specified date",
            "timer",
            SpecifiedDate,
            TIMER_VARS,
            "Fires once at the given date and time.",
            {"run_at": "2027-01-31T09:00:00", "timezone": "Europe/Berlin"},
        ),
        ConditionSpec(
            "periodic_schedule",
            "Perform an action periodically",
            "timer",
            PeriodicSchedule,
            TIMER_VARS,
            "Fires hourly, daily, weekly or monthly at a local time.",
            {"frequency": "weekly", "weekday": 0, "time": "08:30", "timezone": "UTC"},
        ),
        ConditionSpec(
            "share_stale",
            "If share has not been accessed for specified days",
            "scan",
            StaleShares,
            SHARE_VARS,
            "Checks daily for active shares that nobody has opened.",
            {"days": 90},
            supported=False,
            unsupported_reason="Share access is not recorded per share yet, so staleness cannot be measured.",
        ),
        ConditionSpec(
            "user_created",
            "If a new user is created",
            "event",
            UserCreated,
            USER_VARS,
            "Fires when an account is added or invited.",
            {},
            ("member.invited",),
        ),
        ConditionSpec(
            "account_age",
            "If a user's account is older than",
            "scan",
            AccountAge,
            USER_VARS,
            "Checks daily for accounts older than the threshold.",
            {"days": 365},
        ),
        ConditionSpec(
            "last_login_age",
            "If a user's last login is older than",
            "scan",
            LastLoginAge,
            USER_VARS,
            "Checks daily for accounts that have not signed in for the threshold.",
            {"days": 90, "include_never_logged_in": False},
            observation="Last login is the first authenticated request after sign-in at the identity provider.",
        ),
        ConditionSpec(
            "account_expiring",
            "If a user's account is near its expiration date",
            "scan",
            AccountExpiring,
            USER_VARS,
            "Checks daily for accounts expiring within the lead time.",
            {"within_days": 14},
        ),
    ]
}


# ----------------------------------------------------------------------------- actions
class Recipients(_Params):
    user_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    include_actor: bool = Field(False, description="Also the person whose action triggered this.")

    @model_validator(mode="after")
    def _some(self) -> Recipients:
        if not (self.user_ids or self.group_ids or self.include_actor):
            raise ValueError("Choose at least one user, group, or the acting person.")
        return self


class NotifyUsers(Recipients):
    title: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Placeholders: {file.name} {file.path} {event.action}",
    )
    message: str = Field("", max_length=1000)


class SendEmail(Recipients):
    subject: str = Field(..., min_length=1, max_length=200)
    body: str = Field("", max_length=2000)


class Destination(_Params):
    target_folder_id: uuid.UUID = Field(..., description="Destination folder.")
    on_conflict: Literal["skip", "rename"] = Field(
        "skip", description="If a file with that name exists: skip it, or add a numeric suffix."
    )
    keep_folder_structure: bool = Field(
        False, description="Recreate the source's parent folder name under the destination."
    )


class DeleteFiles(_Params):
    confirm_move_to_trash: Literal[True] = Field(
        ..., description="Must be true. Files go to the recycle bin; nothing is purged."
    )


class VerifyAlert(_Params):
    alert_user_ids: list[uuid.UUID] = Field(
        default_factory=list, max_length=50, description="Default: all organization admins."
    )


class VerifyDelete(VerifyAlert):
    confirm_move_to_trash: Literal[True] = Field(
        ..., description="Must be true. A mismatching file goes to the recycle bin, never purged."
    )


class RunReport(Recipients):
    report: Literal["activity_summary"] = "activity_summary"
    days: Annotated[int, Field(ge=1, le=365)] = 30


class ReleaseLocks(_Params):
    older_than_hours: Annotated[int, Field(ge=1, le=24 * 90)] = 24
    notify_owner: bool = True


class CreateDirectory(_Params):
    parent_folder_id: uuid.UUID
    name: str = Field(..., min_length=1, max_length=200, description="Placeholders allowed.")


class SetMetadata(_Params):
    key: str = Field(..., pattern=r"^[a-z][a-z0-9_]{0,63}$")
    value: str | int | float | bool = Field(
        ..., description="Validated against the field definition."
    )


class AssignAcl(_Params):
    subject_type: Literal["user", "group"]
    subject_id: uuid.UUID
    actions: list[Literal["view", "preview", "download", "comment"]] = Field(
        ...,
        min_length=1,
        description="Limited to read-level actions; broader grants need a person.",
    )
    expires_in_days: Annotated[int, Field(ge=1, le=365)] | None = 30


class WaitForApproval(_Params):
    approval_workflow_id: uuid.UUID = Field(..., description="An existing approval workflow.")
    note: str = Field("", max_length=500)


class HumanApproval(_Params):
    user_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10)
    completion: Literal["any", "all", "sequence"] = Field(
        "any",
        description="any = the first approval decides; all = everyone must approve; "
        "sequence = asked one after another.",
    )
    title: str = Field(
        "Approve {file.name}", min_length=1, max_length=200, description="Placeholders allowed."
    )
    instructions: str = Field("", max_length=500)
    timeout_days: Annotated[int, Field(ge=1, le=365)] | None = Field(
        None, description="No decision by then: take the 'timed out' exit."
    )

    @model_validator(mode="after")
    def _some(self) -> HumanApproval:
        if not (self.user_ids or self.group_ids):
            raise ValueError("Choose at least one person or group to ask.")
        return self


class GrantAccess(_Params):
    actions: list[Literal["view", "preview", "download", "comment"]] = Field(
        default_factory=list,
        description="Leave empty to grant everything that was asked for.",
    )
    expires_in_days: Annotated[int, Field(ge=1, le=365)] | None = 30
    reason: str = Field("", max_length=500)


class DenyAccess(_Params):
    reason: str = Field("", max_length=500, description="Told to the person who asked.")


class AssignVariable(_Params):
    name: str = Field(..., pattern=r"^[a-z][a-z0-9_]{0,31}$")
    expression: str = Field(..., min_length=1, max_length=500)


class Condition(_Params):
    expression: str = Field(..., min_length=1, max_length=500)


@dataclass(frozen=True)
class ActionSpec:
    key: str
    label: str
    params: type[BaseModel]
    description: str
    example: dict[str, Any]
    risk: Literal["low", "high"] = "low"
    wizard: bool = True  # offered in the IF/THEN wizard
    needs_resource: Literal["none", "file", "file_or_folder", "access_request"] = "none"
    supported: bool = True
    unsupported_reason: str | None = None
    notes: list[str] = field(default_factory=list)
    # Named exits for a branching step (edges are labelled with these). Empty = one plain exit.
    outputs: tuple[str, ...] = ()


ACTIONS: dict[str, ActionSpec] = {
    a.key: a
    for a in [
        ActionSpec(
            "notify_users",
            "Notify user(s)",
            NotifyUsers,
            "Sends an in-app notification (and an email if the recipient and the server allow it).",
            {
                "user_ids": [],
                "include_actor": True,
                "title": "Review {file.name}",
                "message": "{file.path}",
            },
            notes=["Honors each recipient's notification preferences and administrator policy."],
        ),
        ActionSpec(
            "copy_files",
            "Copy the file(s) to some location",
            Destination,
            "Copies the file that triggered the workflow into another folder.",
            {"target_folder_id": "00000000-0000-0000-0000-000000000000", "on_conflict": "rename"},
            needs_resource="file",
            notes=[
                "Runs as the person who published the workflow and needs read access to the source and create access at the destination."
            ],
        ),
        ActionSpec(
            "delete_files",
            "Delete the file(s)",
            DeleteFiles,
            "Moves the file to the recycle bin. Nothing is permanently deleted.",
            {"confirm_move_to_trash": True},
            risk="high",
            needs_resource="file",
        ),
        ActionSpec(
            "move_files",
            "Move the file(s) to some location",
            Destination,
            "Moves the file that triggered the workflow into another folder.",
            {"target_folder_id": "00000000-0000-0000-0000-000000000000", "on_conflict": "skip"},
            needs_resource="file",
        ),
        ActionSpec(
            "verify_integrity_alert",
            "Verify file integrity and generate admin alert on mismatch",
            VerifyAlert,
            "Re-reads the stored bytes, recomputes the checksum and compares it with the one recorded at upload. "
            "A mismatch raises an audit alert and notifies administrators. The file is not changed.",
            {"alert_user_ids": []},
            needs_resource="file",
        ),
        ActionSpec(
            "verify_integrity_delete",
            "Verify file integrity and delete on mismatch",
            VerifyDelete,
            "Like the alert variant, and also moves a mismatching file to the recycle bin.",
            {"confirm_move_to_trash": True, "alert_user_ids": []},
            risk="high",
            needs_resource="file",
        ),
        ActionSpec(
            "run_report",
            "Run a report",
            RunReport,
            "Builds the activity summary and delivers it as a notification.",
            {"report": "activity_summary", "days": 30, "include_actor": True},
            notes=["Only allowlisted reports; no free-form queries."],
        ),
        ActionSpec(
            "release_locks",
            "Release locks",
            ReleaseLocks,
            "Clears checkout locks older than the limit (or already expired) on the triggering file, "
            "or across the organization for timer and scan triggers.",
            {"older_than_hours": 24, "notify_owner": True},
        ),
        ActionSpec(
            "send_email",
            "Send an email",
            SendEmail,
            "Emails organization members. Recipients are always members: no arbitrary addresses.",
            {
                "user_ids": [],
                "include_actor": True,
                "subject": "Heads up",
                "body": "{file.path} changed.",
            },
            risk="high",
            notes=["Skipped (and recorded as skipped) when no email provider is configured."],
        ),
        # ---- canvas-only nodes
        ActionSpec(
            "create_directory",
            "Create Directory",
            CreateDirectory,
            "Creates a folder (placeholders allowed in the name).",
            {
                "parent_folder_id": "00000000-0000-0000-0000-000000000000",
                "name": "Review {file.name}",
            },
            wizard=False,
        ),
        ActionSpec(
            "set_metadata",
            "Set Metadata Attribute Value",
            SetMetadata,
            "Sets one custom metadata field on the file.",
            {"key": "status", "value": "reviewed"},
            wizard=False,
            needs_resource="file",
        ),
        ActionSpec(
            "assign_acl",
            "Assign ACL Permissions",
            AssignAcl,
            "Grants read-level access on the file to a user or group, expiring by default.",
            {
                "subject_type": "group",
                "subject_id": "00000000-0000-0000-0000-000000000000",
                "actions": ["view"],
                "expires_in_days": 30,
            },
            risk="high",
            wizard=False,
            needs_resource="file_or_folder",
            notes=["Cannot grant more than the publisher holds, nor anything beyond read/comment."],
        ),
        ActionSpec(
            "wait_for_approval",
            "Wait for File Approval",
            WaitForApproval,
            "Starts an approval workflow for the file and pauses this run until it is decided. "
            "A rejection stops the run.",
            {"approval_workflow_id": "00000000-0000-0000-0000-000000000000"},
            wizard=False,
            needs_resource="file",
        ),
        ActionSpec(
            "human_approval",
            "Human approval",
            HumanApproval,
            "Asks people to approve the file and pauses this run. The run continues down the "
            "approved, rejected or timed-out exit, so each outcome can do something different.",
            {
                "user_ids": [],
                "completion": "any",
                "title": "Approve {file.name}",
                "timeout_days": 7,
            },
            wizard=False,
            needs_resource="file",
            outputs=("approved", "rejected", "timeout"),
            notes=[
                "The asked people see it under My approvals and can approve, reject or delegate.",
                "Only one approval can be open on a file at a time.",
            ],
        ),
        ActionSpec(
            "grant_access",
            "Grant access",
            GrantAccess,
            "Approves the access request that started this run and gives the person the "
            "access they asked for (read-level only, expiring by default).",
            {"actions": [], "expires_in_days": 30},
            risk="high",
            wizard=False,
            needs_resource="access_request",
            notes=["Runs as the publisher: they need Manage access on the file."],
        ),
        ActionSpec(
            "deny_access",
            "Deny access",
            DenyAccess,
            "Rejects the access request that started this run and tells the person why.",
            {"reason": "This file is not shared outside the team."},
            wizard=False,
            needs_resource="access_request",
        ),
        ActionSpec(
            "assign_variable",
            "Assign Variable Value",
            AssignVariable,
            "Stores the value of an expression in vars.<name> for later nodes.",
            {"name": "big", "expression": "file.size_bytes > 1000000"},
            wizard=False,
        ),
        ActionSpec(
            "condition",
            "Condition",
            Condition,
            "Branches on an expression: edges labelled true / false.",
            {"expression": "file.extension == 'pdf'"},
            wizard=False,
            outputs=("true", "false"),
        ),
    ]
}

HIGH_RISK = frozenset(k for k, a in ACTIONS.items() if a.risk == "high")


def condition_names(spec: ConditionSpec, extra_vars: set[str] | None = None) -> frozenset[str]:
    names = set(spec.variables)
    names |= {f"vars.{v}" for v in (extra_vars or set())}
    return frozenset(names)
