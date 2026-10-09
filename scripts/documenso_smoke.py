"""Smoke-test the DEPLOYED Documenso instance configured in .env (DOCUMENSO_URL/API_KEY/...).

    uv run python scripts/documenso_smoke.py

It uses the real adapter: creates a 1-page PDF document with one signer (sendEmail=false, so
nobody is e-mailed), adds the signature field, sends it, reads the status back, then deletes the
document again. Secrets and signing links are never printed.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pypdf import PdfWriter  # noqa: E402

from app.adapters.signatures.base import SignatureProviderError, SignerSpec  # noqa: E402
from app.adapters.signatures.factory import get_signature_provider  # noqa: E402
from app.core.config import get_settings  # noqa: E402


def make_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def finish() -> int:
    """After a human/browser completed the signing page: check status, download, delete."""
    import json

    info = json.loads(Path(".dev/smoke.json").read_text())
    provider = get_signature_provider()
    assert provider is not None
    state = provider.get_state(info["id"])
    print(f"status: {state.status}; recipients: {[(r.email, r.status) for r in state.recipients]}")
    if state.status == "completed":
        data = b"".join(provider.download_signed(info["id"]))
        print(f"signed download: {len(data)} bytes, starts with {data[:5]!r}")
    provider.cancel(info["id"])
    print("cleanup: smoke document deleted")
    Path(".dev/smoke.json").unlink(missing_ok=True)
    return 0


def main() -> int:
    if "--finish" in sys.argv:
        return finish()
    keep = "--keep" in sys.argv
    settings = get_settings()
    print(f"provider selected: {settings.effective_signature_provider}")
    provider = get_signature_provider()
    if provider is None or provider.name != "documenso":
        print("Documenso is not configured (DOCUMENSO_URL / DOCUMENSO_API_KEY / DOCUMENSO_WEBHOOK_SECRET).")
        return 2
    print(f"instance: {urlparse(settings.documenso_url).netloc}")
    pdf = make_pdf()
    created = None
    try:
        created = provider.create_request(
            title="DMS smoke test (safe to delete)",
            message=None,
            filename="smoke.pdf",
            content=iter([pdf]),
            size=len(pdf),
            signers=[SignerSpec("dms-smoke-signer@example.com", "DMS Smoke Signer", 0)],
            send_email=False,
        )
        print(f"create+upload+field+send: OK (document id {created.provider_request_id})")
        link = next(iter(created.signing_urls.values()), "")
        print(f"signing link returned: {'yes' if link else 'NO'} (host {urlparse(link).netloc or '-'}, path /sign/<token>: {urlparse(link).path.startswith('/sign/')})")
        state = provider.get_state(created.provider_request_id)
        print(f"status: {state.status}; recipients: {[(r.email, r.status) for r in state.recipients]}")
        if keep:
            import json

            Path(".dev").mkdir(exist_ok=True)
            Path(".dev/smoke.json").write_text(json.dumps({"id": created.provider_request_id, "link": link}))
            print("kept for browser signing (link stored in .dev/smoke.json, not printed)")
            created = None
        return 0
    except SignatureProviderError as exc:
        print(f"FAILED: {exc}")
        return 1
    finally:
        if created is not None:
            try:
                provider.cancel(created.provider_request_id)
                print("cleanup: smoke document deleted")
            except SignatureProviderError as exc:
                print(f"cleanup FAILED ({exc}) - delete 'DMS smoke test' manually in Documenso")


if __name__ == "__main__":
    raise SystemExit(main())
