"""Shared with Me / Shared by Me and share management."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query, Response

from app.api.deps import Authz, DbSession, limited
from app.core.errors import ErrorResponse
from app.db.enums import ResourceType
from app.modules.sharing import manage
from app.modules.sharing import service as sharing
from app.schemas.common import Page
from app.schemas.sharing import (
    InviteResult,
    LinkResolveIn,
    LinkResolveOut,
    LinkTrack,
    ReceivedShare,
    ShareGroupAdd,
    ShareHistoryItem,
    ShareInvite,
    ShareOut,
    SharePermissionsUpdate,
    ShareUpdate,
)

router = APIRouter(prefix="/shares", tags=["sharing"], responses={404: {"model": ErrorResponse}})


@router.get(
    "/received",
    response_model=Page[ReceivedShare],
    summary="Shared with Me - original documents with their canonical breadcrumb",
)
def received(
    db: DbSession,
    authz: Authz,
    include_inactive: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[ReceivedShare]:
    items, total = sharing.list_received(
        db, authz, include_inactive=include_inactive, limit=limit, offset=offset
    )
    return Page[ReceivedShare](items=items, total=total, limit=limit, offset=offset)


@router.get("/sent", response_model=Page[ShareOut], summary="Shared by Me")
def sent(
    db: DbSession,
    authz: Authz,
    include_inactive: bool = False,
    scope: Literal["mine", "all"] = "mine",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[ShareOut]:
    items, total = sharing.list_sent(
        db,
        authz,
        include_inactive=include_inactive,
        scope_all=scope == "all",
        limit=limit,
        offset=offset,
    )
    return Page[ShareOut](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/{share_id}",
    response_model=ShareOut,
    summary="Share details (creator, managers and recipients)",
)
def get_share(share_id: uuid.UUID, db: DbSession, authz: Authz) -> ShareOut:
    return sharing.get_share_out(db, authz, share_id)


@router.post(
    "/{share_id}/revoke",
    response_model=ShareOut,
    summary="Revoke a share (takes effect immediately)",
)
def revoke(share_id: uuid.UUID, db: DbSession, authz: Authz) -> ShareOut:
    return sharing.revoke_share(db, authz, share_id)


# ---- Share Link dialog
@router.post(
    "/for/{resource_type}/{resource_id}",
    response_model=ShareOut,
    summary="Open the share of this item (creates a private one if you have none yet)",
)
def share_for_resource(
    resource_type: Literal["document", "folder"],
    resource_id: uuid.UUID,
    db: DbSession,
    authz: Authz,
) -> ShareOut:
    return manage.share_for_resource(db, authz, ResourceType(resource_type), resource_id)


@router.patch(
    "/{share_id}",
    response_model=ShareOut,
    summary="Update name, owner, expiry, upload quota, notifications, visibility and link",
)
def update_share(share_id: uuid.UUID, body: ShareUpdate, db: DbSession, authz: Authz) -> ShareOut:
    return manage.update(db, authz, share_id, body)


@router.delete("/{share_id}", response_model=ShareOut, summary="Remove the share and its link")
def remove_share(share_id: uuid.UUID, db: DbSession, authz: Authz) -> ShareOut:
    return manage.remove_share(db, authz, share_id)


@router.post(
    "/{share_id}/link/rotate",
    response_model=ShareOut,
    summary="Issue a new link; the previous one stops working at once",
    dependencies=[limited("share_link", sensitive=True)],
)
def rotate_link(share_id: uuid.UUID, db: DbSession, authz: Authz) -> ShareOut:
    return manage.rotate_link(db, authz, share_id)


@router.post(
    "/{share_id}/link/track",
    status_code=204,
    summary="Record that the link was copied/opened/emailed",
)
def track_link(share_id: uuid.UUID, body: LinkTrack, db: DbSession, authz: Authz) -> Response:
    manage.track_link(db, authz, share_id, body.event)
    return Response(status_code=204)


@router.post(
    "/{share_id}/invite",
    response_model=InviteResult,
    summary="Invite people (minimum permissions: view + preview)",
    dependencies=[limited("share_invite", sensitive=True)],
)
def invite(share_id: uuid.UUID, body: ShareInvite, db: DbSession, authz: Authz) -> InviteResult:
    return manage.invite(db, authz, share_id, body.users, body.send_email)


@router.post(
    "/{share_id}/groups", response_model=ShareOut, summary="Add a group (or EVERYONE) to the share"
)
def add_group(share_id: uuid.UUID, body: ShareGroupAdd, db: DbSession, authz: Authz) -> ShareOut:
    return manage.add_group(db, authz, share_id, body.group_id, body.everyone, body.confirm_broad)


@router.patch(
    "/{share_id}/permissions",
    response_model=ShareOut,
    summary="Set per-person/group permissions (View, Download, Upload, Share, Sync, Delete, Manage)",
)
def set_permissions(
    share_id: uuid.UUID, body: SharePermissionsUpdate, db: DbSession, authz: Authz
) -> ShareOut:
    return manage.set_permissions(db, authz, share_id, body.principals)


@router.delete(
    "/{share_id}/recipients/{recipient_type}/{recipient_id}",
    response_model=ShareOut,
    summary="Remove a person or group from the share",
)
def remove_recipient(
    share_id: uuid.UUID,
    recipient_type: Literal["user", "group", "organization"],
    recipient_id: uuid.UUID,
    db: DbSession,
    authz: Authz,
) -> ShareOut:
    return manage.remove_recipient(db, authz, share_id, recipient_type, recipient_id)


@router.get("/{share_id}/history", response_model=Page[ShareHistoryItem], summary="Share History")
def share_history(
    share_id: uuid.UUID,
    db: DbSession,
    authz: Authz,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[ShareHistoryItem]:
    items, total = manage.history(db, authz, share_id, limit=limit, offset=offset)
    return Page[ShareHistoryItem](items=items, total=total, limit=limit, offset=offset)


links_router = APIRouter(prefix="/share-links", tags=["sharing"])


@links_router.post(
    "/resolve",
    response_model=LinkResolveOut,
    summary="Open a share link as a signed-in member",
    dependencies=[limited("share_link_resolve", sensitive=True)],
)
def resolve_link(body: LinkResolveIn, db: DbSession, authz: Authz) -> LinkResolveOut:
    return manage.resolve_link(db, authz, body.token)
