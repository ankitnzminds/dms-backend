# E-signature: integrity fixes and built-in signing (implemented)

Companion to the audit documents in this folder. Everything here is additive and covered by executed tests
(see "Evidence"). Chains, optional signers and the Super Signer are **not** implemented (see "Not done").

## 1. Integrity fixes to the existing flow
| Gap | Change |
|---|---|
| S1 duplicate active requests | One in-flight (`creating`/`sent`) request per document: service check under a document row lock (`409 signature_in_progress`) **and** a partial unique index `uq_signature_requests_one_active`. The migration refuses to run if duplicates already exist and tells you to cancel the extras (it never cancels anything itself) |
| S2 cancel race | `cancel_request` is two short locked phases around the provider call; the second phase re-checks the state, so a request that completed in between stays completed |
| S3 state machine | `ALLOWED_TRANSITIONS` + `transition()`; every writer of `state` uses it. Terminal states have no exits (`409 invalid_transition`) |
| S5 signing URLs | Stored encrypted (Fernet, key derived from the server signing secret, purpose-specific). Legacy plaintext rows keep working and are re-encrypted on first use; unreadable values are never handed out |
| S6/S7 artifact + binding | `signature_requests.source_sha256` recorded at request time (migration backfills from the immutable source version) and repeated in the artifact evidence; a provider download that is not a `%PDF-` file is never stored (request stays `sent`, the sweep retries) |
| S9 | The scan-status `assert` became a typed `409 not_available` |

## 2. Built-in signing (provider `builtin`)
**What it is:** an electronic-signature *record*: who agreed, when, to which **exact version** (id + SHA-256 at request time),
under which **versioned consent statement**. **What it is not:** a cryptographic/certificate PDF signature; it creates no new
document version. Whether it satisfies a given legal requirement is a decision for the organization and its counsel.

API (all org-scoped, rate limited, audited):
`POST /documents/{id}/signature-requests` with `"provider": "builtin"` · `GET /signature-statement` ·
`POST /signature-requests/{id}/sign` `{agreed, statement_version, typed_name}` ·
`POST /signature-requests/{id}/decline` `{reason?}` · `GET /signature-requests/{id}/document` (exact version, signers only) ·
`GET /signature-requests?status=active|finished|any`. Omitting `provider` keeps the previous behaviour (configured external
provider, PDF only). `GET /signature-capabilities` gained `builtin_available`.

Rules implemented (documented defaults, tested): internal signers only · any file type · signers act in **parallel** (no order) ·
complete when **every** signer has signed · **any decline declines the request** · only the assigned signer may act, only while the
request is `sent` and their status is `pending` · sign and decline are separate and final · consent for the *current* statement
version and a typed name are required · row lock + `transition()` · checksum re-verified at signing (`409 integrity_error` and an
`integrity.mismatch` audit event if it ever differs) · signers read the exact version through the request (no DMS document rights needed).

Evidence per signer (`signature_recipients.evidence`): method, statement version + SHA-256, typed name, signer id/email,
request/document/source-version ids, source SHA-256, signed-at and — only if `SIGNATURE_RECORD_CLIENT_INFO=true` (default) — IP and
user-agent. Set the variable to `false` where recording them is not justified. Decline reasons are stored but not shown to other users.

Audit events: `signature.requested`, `signature.recipient_signed`, `signature.completed`, `signature.recipient_declined`,
`signature.declined`, `signature.document_viewed`, `signature.cancelled`; notifications to signers on request and to the requester
on completion/decline.

UI: request dialog offers Built-in vs the external provider (non-PDF files can only use Built-in); the signature card shows
"Review and sign" (download the exact version → versioned statement → checkbox → typed name → Sign, with Decline as a separate
step); a completed built-in request says plainly that it is an electronic record and not a certificate-based PDF signature;
My Signatures has Active / History / All.

## 3. Deployment and rollback
Migrations (additive, in order): `f7a8b9c0d1e2` (source checksum, one-active index; **aborts if duplicate in-flight requests exist**),
`a8b9c0d1e2f3` (recipient `evidence`, `decline_reason`). Config: optional `SIGNATURE_RECORD_CLIENT_INFO` (default true).
Rollback: deploy the previous image (new columns/index are ignored by old code); migrations downgrade drops only what they added.
Signing-URL encryption needs `DOWNLOAD_SIGNING_SECRET` to stay stable: rotating it makes stored provider signing links
unreadable (signers then ask the sender for a new request).

## 4. Evidence (executed tests)
tests/integration/test_signature_integrity.py (22), test_signature_builtin.py (18), test_signatures.py (existing, updated for
`builtin_available`), frontend tests/components/builtin-signing.test.tsx (5), signing.test.tsx, phase2-logic.test.ts.
Full-suite results are recorded in IMPLEMENTATION_ROADMAP (docs/audit).

## 5. Not done (needs decisions or external services)
Signature chains / levels / optional signers / Super Signer (semantics undefined), convert-then-sign for the external provider,
field-placement UI, Documenso webhook delivery verified live, expiry timer, native decline for the external provider,
cryptographic PDF signing for built-in.
