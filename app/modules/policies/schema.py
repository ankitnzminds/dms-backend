"""The policy catalogue: every setting is typed, validated and documented in one place.

``ENFORCED`` lists the settings that backend code actually acts on. The API returns it next to the
values so the UI can say honestly which controls are enforced today and which are stored only
(they become enforceable when the feature they govern exists, e.g. mobile clients or MFA).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

NonNeg = Annotated[int, Field(ge=0, le=10_000_000_000_000)]
Days = Annotated[int, Field(ge=0, le=3650)]


class GeneralPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    share_mode: Literal["allow_all", "no_shares"] = "allow_all"
    default_share_expiry_days: Days = 0  # 0 = no default expiry
    default_max_downloads: NonNeg = 0  # 0 = unlimited
    user_storage_quota_bytes: NonNeg = 0  # 0 = unlimited
    privacy_settings_enabled: bool = False
    recycle_bin_enabled: bool = True
    recycle_bin_auto_delete_days: Days = 0  # 0 = never
    recycle_bin_max_file_bytes: NonNeg = 0  # 0 = no limit


class MfaPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    require_mfa: bool = False


class UserPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disable_invitations: bool = False
    create_account_on_share: bool = False
    code_device_auth: bool = False
    code_device_auth_requires_approval: bool = False
    enforce_device_session_timeout: bool = False
    allow_folder_level_security: bool = True
    enable_web_edit: bool = True
    enable_recycle_bin_clearing: bool = True
    disallow_default_share_change: bool = False
    disable_send_for_approval: bool = False
    disable_everyone_group_sharing: bool = False
    allow_group_creation: bool = False
    allow_group_management: bool = False
    allow_group_deletion: bool = False
    allow_workflow_sharing: bool = False
    disable_workflow_automation: bool = False
    require_share_approval: bool = False
    esignature_enabled: bool = True
    max_upload_bytes: NonNeg = 0  # 0 = platform maximum
    save_zip_session_password: bool = False


class ClientAppPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    require_passcode_lock: bool = False
    disable_mobile_apps: bool = False
    disable_mobile_edit: bool = False
    disable_print: bool = False
    disable_download: bool = False
    disable_open_with: bool = False
    disable_share: bool = False
    disable_favorites: bool = False
    disable_screenshots: bool = False


class DeviceConfigPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_configuration_xml: Annotated[str, Field(max_length=100_000)] = ""

    @field_validator("client_configuration_xml")
    @classmethod
    def well_formed(cls, v: str) -> str:
        if v.strip():
            validate_xml(v)
        return v


class NotificationsPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disable_all: bool = False
    disable_user_override: bool = False
    disable_new_file: bool = False
    disable_update: bool = False
    disable_delete: bool = False
    disable_download: bool = False
    disable_preview: bool = False
    disable_lock: bool = False
    disable_share: bool = False
    disable_rename: bool = False
    disable_self: bool = False


TABS: dict[str, type[BaseModel]] = {
    "general": GeneralPolicy,
    "mfa": MfaPolicy,
    "user_policy": UserPolicy,
    "client_app": ClientAppPolicy,
    "device_config": DeviceConfigPolicy,
    "notifications": NotificationsPolicy,
}

# Settings the backend acts on today ("tab.key"). Everything else is stored, versioned and audited
# but not yet enforced; the API says so.
ENFORCED = frozenset(
    {
        "general.share_mode",
        "general.default_share_expiry_days",
        "general.user_storage_quota_bytes",
        "user_policy.max_upload_bytes",
        "user_policy.enable_web_edit",
        "user_policy.disable_invitations",
        "user_policy.disable_everyone_group_sharing",
        "notifications.disable_all",
        "notifications.disable_share",
    }
)


def validate_xml(text: str) -> None:
    """Reject malformed XML with line/column; defusedxml also refuses DTD/entity-expansion tricks."""
    from defusedxml import ElementTree as SafeET
    from defusedxml.common import DefusedXmlException

    try:
        SafeET.fromstring(text)
    except SafeET.ParseError as e:
        line, col = e.position
        raise ValueError(f"XML is not well-formed (line {line}, column {col}).") from None
    except DefusedXmlException:
        raise ValueError("XML uses forbidden constructs (DTD or entities).") from None
