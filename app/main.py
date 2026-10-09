"""FastAPI application factory."""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from app import __version__
from app.api.v1 import admin, documents, folders, library, me, shares, uploads
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestContextMiddleware
from app.db.session import get_engine

log = get_logger("app")

API_DESCRIPTION = """
Enterprise DMS REST API. The backend owns this contract; clients (web today, desktop/mobile
later) consume it. Every protected operation is authorized server-side: authentication proves
who you are, **authorization decides what you may do with each folder/document**.

Errors always use `{"error": {"code", "message", "request_id", "details"}}`.
"""


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(_: FastAPI):  # noqa: ANN202
        log.info(
            "startup",
            extra={
                "env": settings.app_env,
                "auth_provider": settings.auth_provider,
                "storage_provider": settings.storage_provider,
            },
        )
        yield

    app = FastAPI(
        title="Enterprise DMS API",
        version=__version__,
        description=API_DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production_like else None,
        redoc_url=None,
        openapi_url="/openapi.json" if not settings.is_production_like else None,
    )
    register_exception_handlers(app)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Organization-Id",
            "Idempotency-Key",
            "X-Request-ID",
        ],
        expose_headers=["X-Request-ID", "Content-Disposition", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(RequestContextMiddleware)  # outermost: wraps CORS and handlers

    v1 = APIRouter(prefix=settings.api_v1_prefix)
    for module in (me, folders, documents, uploads, shares, library, admin):
        v1.include_router(module.router)
    if settings.auth_provider == "local" and settings.app_env in ("development", "test"):
        from app.api.v1 import dev

        v1.include_router(dev.router)
    app.include_router(v1)

    @app.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def ready() -> JSONResponse:
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.get("/metrics", include_in_schema=False)
    def metrics(request: Request) -> Response:
        token = settings.metrics_token
        supplied = request.headers.get("authorization", "")
        if token is None or not hmac.compare_digest(supplied, f"Bearer {token.get_secret_value()}"):
            return Response(status_code=404)  # disabled or unauthorized: do not advertise
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
