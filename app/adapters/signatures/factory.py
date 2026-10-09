from __future__ import annotations

from functools import lru_cache

from app.adapters.signatures.base import SignatureProvider
from app.adapters.signatures.documenso import DocumensoProvider
from app.adapters.signatures.fake import FakeSignatureProvider
from app.core.config import get_settings


@lru_cache
def _build(name: str, _settings_id: int) -> SignatureProvider | None:
    s = get_settings()
    if name == "fake":
        secret = s.signature_webhook_secret.get_secret_value() if s.signature_webhook_secret else ""
        if s.is_production_like:
            raise RuntimeError("the fake signature provider is not allowed in staging/production")
        return FakeSignatureProvider(secret or "fake-dev-webhook-secret")
    if name == "documenso":
        return DocumensoProvider(
            s.documenso_url,
            s.documenso_api_key.get_secret_value() if s.documenso_api_key else "",
            s.documenso_webhook_secret.get_secret_value() if s.documenso_webhook_secret else "",
        )
    return None


def get_signature_provider() -> SignatureProvider | None:
    """The configured provider, or None when e-signature is not configured."""
    s = get_settings()
    return _build(s.effective_signature_provider, id(s))


def reset_signature_provider() -> None:
    _build.cache_clear()
