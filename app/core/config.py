"""Application settings (12-factor, environment driven).

Secrets are ``SecretStr`` so they never appear in ``repr``/logs. Production
start-up fails fast when unsafe development-only providers are selected.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # --- application ---
    app_env: Environment = "development"
    app_name: str = "EnterpriseDMS"
    api_v1_prefix: str = "/api/v1"
    public_api_base_url: str = "http://localhost:8000"
    cors_allowed_origins: str = "http://localhost:3000"
    log_level: str = "INFO"
    # Origins allowed to embed inline previews (CSP frame-ancestors). Empty = CORS origins.
    frame_ancestors: str = ""
    metrics_token: SecretStr | None = None  # when unset, /metrics is disabled

    # --- database (server side only) ---
    database_url: str = ""
    db_pool_size: int = 10
    db_max_overflow: int = 10

    # --- authentication ---
    auth_provider: Literal["supabase", "local"] = "supabase"
    supabase_url: str = ""
    supabase_jwt_secret: SecretStr | None = None  # legacy HS256 projects only
    supabase_jwt_audience: str = "authenticated"
    local_jwt_secret: SecretStr | None = None  # development/test only
    auth_clock_skew_seconds: int = 30

    # --- storage ---
    storage_provider: Literal["supabase", "local"] = "supabase"
    supabase_service_role_key: SecretStr | None = None  # SERVER ONLY
    supabase_storage_bucket: str = "dms-private"
    local_storage_path: str = ".local-storage"  # development/test only
    max_upload_bytes: int = 100 * 1024 * 1024
    upload_session_ttl_seconds: int = 3600
    blocked_extensions: str = "exe,dll,bat,cmd,com,scr,msi,vbs,ps1,jar,sh,apk"
    download_signing_secret: SecretStr | None = None
    download_url_ttl_seconds: int = 60

    # --- malware scanning ---
    malware_scanner: Literal["clamd", "eicar", "none"] = "none"
    clamd_host: str = "localhost"
    clamd_port: int = 3310
    clamd_timeout_seconds: float = 30.0

    # --- content processing (text extraction / thumbnails / optional OCR) ---
    extract_max_bytes: int = 25 * 1024 * 1024
    extract_max_chars: int = 1_000_000
    extract_max_pages: int = 300
    extract_timeout_seconds: int = 60
    ocr_command: str = ""  # path to a tesseract binary; empty = OCR disabled

    # --- e-signature (provider adapter; 'none' disables the feature) ---
    # "auto" = Documenso when DOCUMENSO_URL and DOCUMENSO_API_KEY are set, otherwise disabled.
    signature_provider: Literal["auto", "none", "fake", "documenso"] = "auto"
    documenso_url: str = ""
    documenso_api_key: SecretStr | None = None
    documenso_webhook_secret: SecretStr | None = None
    signature_webhook_secret: SecretStr | None = None  # fake provider only

    # --- AI assistance (Groq, OpenAI-compatible chat API) ---
    ai_provider: Literal["auto", "none", "fake", "groq"] = "auto"
    groq_api_key: SecretStr | None = None
    groq_model: str = "openai/gpt-oss-20b"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    ai_max_input_chars: int = 40_000
    ai_timeout_seconds: int = 60
    signature_reconcile_minutes: int = 15

    # --- rate limiting (per process; see docs/security) ---
    rate_limit_enabled: bool = True
    rate_limit_default_per_minute: int = 600
    rate_limit_sensitive_per_minute: int = 60

    # --- workers ---
    worker_poll_interval_seconds: float = 2.0
    worker_batch_size: int = 10
    outbox_max_attempts: int = 8
    outbox_lock_seconds: int = 300

    # --- email (adapter; no provider configured by default) ---
    email_provider: Literal["none", "log", "smtp"] = "none"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: SecretStr | None = None
    smtp_from: str = ""
    smtp_starttls: bool = True
    smtp_implicit_tls: bool = False
    web_base_url: str = "http://localhost:3000"  # used for links in e-mails (no tokens)

    @property
    def is_production_like(self) -> bool:
        return self.app_env in ("staging", "production")

    @property
    def effective_signature_provider(self) -> str:
        if self.signature_provider != "auto":
            return self.signature_provider
        return "documenso" if self.documenso_url and self.documenso_api_key else "none"

    @property
    def effective_ai_provider(self) -> str:
        if self.ai_provider != "auto":
            return self.ai_provider
        return "groq" if self.groq_api_key else "none"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def preview_frame_ancestors(self) -> list[str]:
        raw = [o.strip() for o in self.frame_ancestors.split(",") if o.strip()]
        return raw or self.cors_origins

    @property
    def blocked_extension_set(self) -> frozenset[str]:
        return frozenset(e.strip().lower().lstrip(".") for e in self.blocked_extensions.split(","))

    @model_validator(mode="after")
    def _validate_environment(self) -> Settings:
        if self.is_production_like:
            problems: list[str] = []
            if self.auth_provider == "local":
                problems.append("AUTH_PROVIDER=local is development/test only")
            if self.storage_provider == "local":
                problems.append("STORAGE_PROVIDER=local is development/test only")
            if self.malware_scanner in ("eicar", "none"):
                problems.append(
                    "MALWARE_SCANNER must be a real scanner (clamd) in staging/production"
                )
            if self.ai_provider == "fake":
                problems.append("AI_PROVIDER=fake is development/test only")
            if self.signature_provider == "fake":
                problems.append("SIGNATURE_PROVIDER=fake is development/test only")
            if (
                self.effective_signature_provider == "documenso"
                and self.documenso_webhook_secret is None
            ):
                problems.append("DOCUMENSO_WEBHOOK_SECRET is required when Documenso is enabled")
            if "*" in self.cors_origins:
                problems.append("CORS_ALLOWED_ORIGINS must not contain '*'")
            if (
                self.download_signing_secret is None
                or len(self.download_signing_secret.get_secret_value()) < 32
            ):
                problems.append("DOWNLOAD_SIGNING_SECRET (>= 32 chars) is required")
            if problems:
                raise ValueError("Unsafe configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
