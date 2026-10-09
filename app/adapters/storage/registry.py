"""Resolve a StorageProvider for a storage_location row."""

from __future__ import annotations

from functools import lru_cache

from app.adapters.storage.base import StorageProvider
from app.adapters.storage.local import LocalStorageProvider
from app.adapters.storage.supabase import SupabaseStorageProvider
from app.core.config import Settings, get_settings


@lru_cache
def _build(provider_type: str, settings_id: int) -> StorageProvider:
    settings = get_settings()
    if provider_type == "supabase":
        return SupabaseStorageProvider(settings)
    if provider_type == "local":
        if settings.is_production_like:
            raise RuntimeError("local storage is not allowed in staging/production")
        return LocalStorageProvider(settings.local_storage_path)
    raise RuntimeError(f"Unsupported storage provider: {provider_type}")


def get_storage_provider(provider_type: str) -> StorageProvider:
    return _build(provider_type, id(get_settings()))


def default_provider_type(settings: Settings | None = None) -> str:
    return (settings or get_settings()).storage_provider


def reset_storage_registry() -> None:
    _build.cache_clear()
