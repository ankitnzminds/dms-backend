"""Search, recents, starred, trash and notifications."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Response
from pydantic import Field

from app.api.deps import Authz, CurrentPrincipal, DbSession, limited
from app.modules.documents import service as documents
from app.modules.folders import service as folders
from app.modules.notifications import service as notifications
from app.modules.search import service as search_service
from app.modules.search.service import SearchResult
from app.schemas.admin import NotificationOut
from app.schemas.common import ApiModel, Page
from app.schemas.tree import TrashItem, TreeItem

router = APIRouter(tags=["library"])


@router.get(
    "/search",
    response_model=Page[SearchResult],
    summary="Search names; results, totals and paths are authorization-filtered",
    dependencies=[limited("search")],
)
def search(
    db: DbSession,
    authz: Authz,
    q: str = Query(min_length=1, max_length=200),
    scope: Literal["all", "name", "content"] = "all",
    meta: list[str] = Query(
        default_factory=list, max_length=5, description="key:value metadata filters"
    ),
    folder_id: uuid.UUID | None = None,
    kind: Literal["folder", "document"] | None = None,
    owner_id: uuid.UUID | None = None,
    content_type: str | None = Query(None, max_length=127),
    modified_after: datetime | None = None,
    modified_before: datetime | None = None,
    color_tag: Literal["red", "orange", "yellow", "green", "blue", "purple", "pink", "gray"]
    | None = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[SearchResult]:
    items, total = search_service.search(
        db,
        authz,
        q=q,
        scope=scope,
        meta=meta,
        folder_id=folder_id,
        kind=kind,
        owner_id=owner_id,
        content_type=content_type,
        modified_after=modified_after,
        modified_before=modified_before,
        color_tag=color_tag,
        limit=limit,
        offset=offset,
    )
    return Page[SearchResult](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/recent", response_model=Page[TreeItem], summary="Recently accessed documents (server-side)"
)
def recent(
    db: DbSession, authz: Authz, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)
) -> Page[TreeItem]:
    items, total = documents.list_recent(db, authz, limit, offset)
    return Page[TreeItem](items=items, total=total, limit=limit, offset=offset)


@router.get("/starred", response_model=Page[TreeItem], summary="Starred documents")
def starred(
    db: DbSession, authz: Authz, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)
) -> Page[TreeItem]:
    items, total = documents.list_starred(db, authz, limit, offset)
    return Page[TreeItem](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/trash", response_model=Page[TrashItem], summary="Trashed items the caller may restore"
)
def trash(
    db: DbSession, authz: Authz, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)
) -> Page[TrashItem]:
    items, total = folders.list_trash(db, authz, limit=limit, offset=offset)
    return Page[TrashItem](items=items, total=total, limit=limit, offset=offset)


class NotificationPage(Page[NotificationOut]):
    unread_count: int


@router.get("/notifications", response_model=NotificationPage, summary="In-app notifications")
def list_notifications(
    db: DbSession,
    principal: CurrentPrincipal,
    unread_only: bool = False,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> NotificationPage:
    items, total, unread = notifications.list_for(
        db, principal, unread_only=unread_only, limit=limit, offset=offset
    )
    return NotificationPage(
        items=items, total=total, limit=limit, offset=offset, unread_count=unread
    )


@router.post(
    "/notifications/{notification_id}/read", status_code=204, summary="Mark a notification read"
)
def read_notification(
    notification_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> Response:
    notifications.mark_read(db, principal, notification_id)
    return Response(status_code=204)


class ReadAllOut(ApiModel):
    updated: int


@router.post(
    "/notifications/read-all", response_model=ReadAllOut, summary="Mark all notifications read"
)
def read_all_notifications(db: DbSession, principal: CurrentPrincipal) -> ReadAllOut:
    return ReadAllOut(updated=notifications.mark_all_read(db, principal))


class NotificationPreferenceModel(ApiModel):
    group: Literal["sharing", "workflow", "signature", "document", "other"]
    in_app: bool
    email: bool


class NotificationPreferencesOut(ApiModel):
    email_available: bool = Field(description="An e-mail sender is configured on this deployment.")
    preferences: list[NotificationPreferenceModel]


@router.get(
    "/notification-preferences",
    response_model=NotificationPreferencesOut,
    summary="My notification delivery preferences",
)
def get_preferences(db: DbSession, principal: CurrentPrincipal) -> NotificationPreferencesOut:
    from app.core.config import get_settings

    return NotificationPreferencesOut(
        email_available=get_settings().email_provider != "none",
        preferences=[
            NotificationPreferenceModel(**p) for p in notifications.get_preferences(db, principal)
        ],  # type: ignore[arg-type]
    )


@router.put(
    "/notification-preferences",
    response_model=NotificationPreferencesOut,
    summary="Update my notification preferences",
)
def put_preferences(
    body: list[NotificationPreferenceModel], db: DbSession, principal: CurrentPrincipal
) -> NotificationPreferencesOut:
    from app.core.config import get_settings

    updated = notifications.set_preferences(db, principal, [m.model_dump() for m in body])
    return NotificationPreferencesOut(
        email_available=get_settings().email_provider != "none",
        preferences=[NotificationPreferenceModel(**p) for p in updated],  # type: ignore[arg-type]
    )
