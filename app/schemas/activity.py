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
