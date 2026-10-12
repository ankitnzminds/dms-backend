# E-signature: what exists today (audit)

Source: read-only inspection; **no test was run for this audit**. "Test exists" ≠ "passes".
Classes: A implemented+verified · B implemented, not verified · C partial · D missing · E broken.

**Key finding: the request assumes a built-in signing flow, chains, optional signers, a Super Signer, consent
and a decline endpoint. None of these exist in the code** (searched `app/`, `migrations/`, frontend). Only a
Documenso-adapter flow (plus a fake provider for tests) exists. Those items are new features, not enhancements.

## Backend
| Area | Class | Evidence |
|---|---|---|
| Tables `signature_requests/recipients/events/signed_artifacts` (RLS on) | B | migration 20261009_e5f6a7b8c9d0, b8c9d0e1f2a3 (signing_url); models/signatures.py |
| Request states `creating, sent, completed, declined, cancelled, expired, failed` | B | CHECK constraint; `TERMINAL_STATES`/`ACTIVE_STATES` in modules/signatures/service.py. No transition table |
| Document-version binding | C | `source_version_id` composite FK (tenant-safe); no checksum of the source version stored |
| Documenso REST v1 create/send/status/download/cancel | B | adapters/signatures/documenso.py; mocked-transport tests; live test opt-in only |
| Webhook `POST /webhooks/signatures/{provider}` | B | shared secret header (`hmac.compare_digest`), allow-listed events, body-hash dedupe, only a *hint*: enqueues `signature.event` → `reconcile()` asks the provider (authority). Tests: forged, duplicate, out-of-order, lying, unknown id |
| "I've finished signing" = `POST /refresh` | A/B | does not trust client; calls `reconcile()` → provider state; participants only, rate limited |
| Completion: download, sha256 (self-computed), NEW version, `signed_artifacts` row | B | `_store_signed_artifact` (lock re-check, orphan cleanup, 200 MB cap). Promotion of the new version to current: not traced |
| `reconcile_stale` sweep | B | workers/maintenance.py (sent requests older than 15 min; fails stuck `creating`). Never expires old `sent` |
| Cancel | C | requester/admin; provider DELETE then `cancelled`; **no row lock / re-check after the provider call** |
| Expiry | D (unreachable) | state exists; Documenso map has no expiry; no DMS timer |
| Built-in signing flow, consent text, DMS decline endpoint | **D** | none; decline only happens inside Documenso |
| Signature chains, levels, optional, Super Signer, per-folder/provider config | **D** | none; recipients have `order_index` passed as Documenso `signingOrder` only |
| Evidence (IP, user-agent, consent, statement version) | **D** | only provider `signedAt` |
| One active request per document | D | no constraint; a test name suggests otherwise but duplicates are allowed |
| Field placement | C | one SIGNATURE field per signer on the **last page**, fixed % coordinates; overlaps beyond ~4 signers; page-1 fallback on malformed PDF |
| Non-PDF signing | D | rejected (`pdf_required`); no convert-then-sign path |
| Authorization | B | create: SHARE+DOWNLOAD, org opt-in, DLP classification, external-signer policy; view: requester/admin/signer/doc VIEW else 404; cancel: requester/admin; signing-session: recipient only; all queries org-scoped |
| Audit events | B | requested, sent, failed, cancelled, recipient_signed/declined, declined, expired, completed, webhook_rejected, signing_opened. Missing: consent, denied signing-session attempts, webhook received/duplicate |
| Signing URL storage | C | plaintext in `signature_recipients.signing_url` (secret-equivalent) |

## Conversion (office)
Collabora Online only (`OFFICE_PROVIDER`, `COLLABORA_URL`); `modules/office/convert.py::to_pdf` powers "Download as PDF"
only (checks DOWNLOAD, lock, scan gate, 50 MB cap, hard 90 s timeout, `%PDF` check, in-memory, synchronous, failures audited).
It is **not** wired into signing. Format registry (`office/formats.py`) is extension-based; no OOXML/ODF magic validation.
LibreOffice is not used directly. No convert-specific tests were confirmed.

## Frontend
| Area | Class | Evidence |
|---|---|---|
| Document-details Signatures panel + request dialog (member picker, free email, title, message) | B | components/file-browser/document-panels.tsx, components/signatures/request-dialog.tsx; PDF-only gate message |
| My Signatures `/signatures` + detail card (sign, refresh, cancel, signer list, timeline, signed link) | C | features/signatures; one list with scope select; **no pending/history split** |
| Sign flow | B | `POST /signing-session` → iframe overlay of Documenso's own page (consent/sign happen there) |
| Consent checkbox, decline dialog, provider selector, chain admin UI, field-placement UI | **D** | none |
| Tests | B | tests/components/signing.test.tsx (6); e2e signing-live (skipped unless `RUN_LIVE_SIGNING=1`) |

Backend tests: tests/integration/test_signatures.py (24–28, fake provider + mocked Documenso adapter), test_documenso_live.py (1, opt-in).
Docs claim a live create→sign→complete→download run; webhook delivery from Documenso is stated as **not verified**.
