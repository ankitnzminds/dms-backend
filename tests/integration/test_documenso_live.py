"""OPT-IN live test against the deployed Documenso configured in .env.

    RUN_LIVE_DOCUMENSO=1 uv run pytest tests/integration/test_documenso_live.py

Creates one throwaway document (sendEmail=false) and deletes it again. Skipped by default so CI
and offline runs never touch an external service.
"""

from __future__ import annotations

import io
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_DOCUMENSO") != "1",
    reason="set RUN_LIVE_DOCUMENSO=1 to run against the deployed instance",
)


def test_live_create_send_status_cancel():  # noqa: ANN201
    from pypdf import PdfWriter

    from app.adapters.signatures.base import SignerSpec
    from app.adapters.signatures.documenso import DocumensoProvider
    from app.core.config import Settings

    s = Settings()  # reads .env
    assert s.documenso_url and s.documenso_api_key and s.documenso_webhook_secret
    provider = DocumensoProvider(
        s.documenso_url,
        s.documenso_api_key.get_secret_value(),
        s.documenso_webhook_secret.get_secret_value(),
    )
    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    buf = io.BytesIO()
    writer.write(buf)
    pdf = buf.getvalue()
    created = provider.create_request(
        title="DMS live test (auto-deleted)",
        message=None,
        filename="t.pdf",
        content=iter([pdf]),
        size=len(pdf),
        signers=[SignerSpec("dms-live-test@example.com", "Live Test")],
        send_email=False,
    )
    try:
        assert created.signing_urls and next(iter(created.signing_urls.values())).startswith(
            s.documenso_url.rstrip("/") + "/sign/"
        )
        state = provider.get_state(created.provider_request_id)
        assert state.status == "pending" and [r.status for r in state.recipients] == ["pending"]
    finally:
        provider.cancel(created.provider_request_id)
