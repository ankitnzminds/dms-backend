"""Uniform error contract: ``{"error": {"code", "message", "request_id", "details"}}``."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import get_request_id
from app.core.logging import get_logger

log = get_logger(__name__)


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: Any | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(
        self, message: str | None = None, *, details: Any | None = None, code: str | None = None
    ):
        super().__init__(message or self.__class__.__name__)
        self.message = message or "Request could not be processed."
        self.details = details
        if code:
            self.code = code


class UnauthorizedError(AppError):
    status_code = 401
    code = "unauthenticated"


class ForbiddenError(AppError):
    status_code = 403
    code = "forbidden"


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_error"


class PayloadTooLargeError(AppError):
    status_code = 413
    code = "payload_too_large"


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"


class QuotaExceededError(AppError):
    status_code = 409
    code = "quota_exceeded"


class DependencyUnavailableError(AppError):
    status_code = 503
    code = "dependency_unavailable"


def _body(code: str, message: str, details: Any | None = None) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": get_request_id(),
            "details": details,
        }
    }


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        headers = {"Retry-After": "30"} if isinstance(exc, RateLimitedError) else None
        return JSONResponse(
            status_code=exc.status_code,
            content=_body(exc.code, exc.message, exc.details),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo request input back (may contain secrets): keep location, message and type.
        details = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg"), "type": e.get("type")}
            for e in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=_body("validation_error", "Request validation failed.", details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return JSONResponse(
            status_code=exc.status_code,
            content=_body(code, str(exc.detail) if exc.status_code < 500 else "Server error."),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        # Log full detail server-side only; the client gets a safe generic message.
        log.exception("unhandled_exception", extra={"error_type": type(exc).__name__})
        return JSONResponse(
            status_code=500,
            content=_body("internal_error", "An unexpected error occurred."),
        )
