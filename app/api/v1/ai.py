"""AI assistance (Gemini/Groq): summary, Q&A and metadata suggestions for one document."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import Authz, CurrentPrincipal, DbSession, limited
from app.core.errors import ErrorResponse
from app.modules.ai import service as ai
from app.schemas.ai import (
    AiAnswerOut,
    AiMetadataSuggestion,
    AiQuestionIn,
    AiStatus,
    AiSummaryOut,
)

router = APIRouter(
    tags=["ai"],
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)


@router.get("/ai/status", response_model=AiStatus, summary="Is AI assistance configured?")
def ai_status(_principal: CurrentPrincipal) -> AiStatus:
    return ai.status()


@router.post(
    "/documents/{document_id}/ai/summary",
    response_model=AiSummaryOut,
    summary="Summarize the current version (needs PREVIEW)",
    dependencies=[limited("ai", sensitive=True)],
)
def summary(document_id: uuid.UUID, db: DbSession, authz: Authz) -> AiSummaryOut:
    return ai.summarize(db, authz, document_id)


@router.post(
    "/documents/{document_id}/ai/ask",
    response_model=AiAnswerOut,
    summary="Ask a question about the current version (needs PREVIEW)",
    dependencies=[limited("ai", sensitive=True)],
)
def ask(document_id: uuid.UUID, body: AiQuestionIn, db: DbSession, authz: Authz) -> AiAnswerOut:
    return ai.ask(db, authz, document_id, body.question)


@router.post(
    "/documents/{document_id}/ai/suggest-metadata",
    response_model=AiMetadataSuggestion,
    summary="Suggest classification/metadata (needs EDIT_METADATA); never applied automatically",
    dependencies=[limited("ai", sensitive=True)],
)
def suggest_metadata(document_id: uuid.UUID, db: DbSession, authz: Authz) -> AiMetadataSuggestion:
    return ai.suggest_metadata(db, authz, document_id)
