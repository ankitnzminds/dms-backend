"""Activity feed schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from app.schemas.common import ApiModel, UserRef


class ActivityItem(ApiModel):
    id: uuid.UUID
    action: str
    label: str
    actor: UserRef | None
    at: datetime
    you: bool


class MyActivityItem(ApiModel):
    """One thing the signed-in user did, phrased for a feed: "You <verb> <target_name>"."""

    id: uuid.UUID
    action: str
    verb: str
    target_type: str
    target_id: uuid.UUID
    #: Null when the item is gone or the user can no longer see it (names are never leaked).
    target_name: str | None
    at: datetime
