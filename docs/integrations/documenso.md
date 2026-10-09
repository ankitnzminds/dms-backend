# Documenso integration

Implemented from `docs/integrations/documenso-guide-original.txt` against the deployed instance in
`DOCUMENSO_URL` (no local Docker).

Flow (`adapters/signatures/documenso.py`): create document → upload the PDF to the presigned URL →
add SIGNATURE fields (percentage coordinates on the last page) → send (`sendEmail` flag from the
request) → state via GET → on completion download the signed PDF → store it as a **new version**.
Cancel = DELETE. Authorization header is the raw API token; webhook secret header is
`x-documenso-secret`.

Verified live (via `scripts/documenso_smoke.py`, `test_documenso_live.py`, and the frontend's
`signing-live` E2E): create → sign in the browser → completed → signed download → cleanup.

Not verified: webhook delivery (needs a public callback URL). Reconciliation
(`SIGNATURE_RECONCILE_MINUTES`) is authoritative and covers missed webhooks; the signing UI polls
`POST /signature-requests/{id}/refresh`.

Security: the signing link is secret-equivalent (not logged, not in notifications); embedded
signing needs `FRAME_ANCESTORS`/CSP `frame-src` set for the Documenso origin; production requires
`DOCUMENSO_WEBHOOK_SECRET`.
