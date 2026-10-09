"""Team Folders listing and (admin) marking."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response
from pydantic import BaseModel

from app.api.deps import Authz, DbSession
from app.modules.folders import team

router = APIRouter(tags=["team-folders"])


class TeamFolderPut(BaseModel):
    enabled: bool


@router.get("/team-folders", response_model=list[team.TeamFolderOut], summary="Team Folders")
def list_team_folders(db: DbSession, authz: Authz) -> list[team.TeamFolderOut]:
    return team.list_team_folders(db, authz)


@router.put(
    "/admin/team-folders/{folder_id}",
    status_code=204,
    summary="Mark or unmark a top-level folder as a team folder (administrators)",
)
def put_team_folder(
    folder_id: uuid.UUID, body: TeamFolderPut, db: DbSession, authz: Authz
) -> Response:
    team.set_team_folder(db, authz, folder_id, body.enabled)
    return Response(status_code=204)
