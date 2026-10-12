# E-signature test plan

Status key: ✔ test exists today (not re-run in this audit) · ◻ to write · ⛔ needs an external service.

## Existing (tests/integration/test_signatures.py, ~24–28; tests/components/signing.test.tsx, 6)
✔ capabilities/org opt-in/external policy/permissions/DLP · full lifecycle (webhook → reconcile → signed artifact) ·
declined (no artifact) · cancel · provider outage on create · forged/malformed/duplicate/out-of-order/lying webhooks ·
lost-webhook repair · orphaned `creating` failed · visibility/tenancy · Documenso adapter (mocked) create sequence,
mid-failure cleanup, non-PDF refused, https required · signing session only for signer · refresh authoritative ·
overlay behaviour in the UI.
⛔ test_documenso_live.py (create/send/status/cancel) and e2e signing-live: opt-in only.

## Phase 2 – characterization before changes (◻)
Pin current behaviour so refactors cannot regress it: terminal-state immutability, one signed artifact per request,
original version unchanged after completion, My Signatures scopes, audit actions list, API response shapes (OpenAPI diff).

## Phase 3 – state machine / idempotency (◻)
Allowed/forbidden transitions table-driven · cancel vs reconcile race (two threads, row lock) · duplicate sign/decline ·
stale event cannot revert completed · cancelled/expired/declined cannot be signed · second active request per document → 409.

## Phase 4 – Documenso / webhook (◻, plus ⛔ live)
Genuine completed/declined payloads (recorded fixtures) · invalid secret · replay of an old body · forged provider id ·
event for another tenant's request ignored · download failure leaves `sent` and is retried · storage failure rolls back ·
completion re-check before download · checksum + `%PDF` + page-count validation · signed version scan/promotion.

## Phase 5 – conversion (◻ + ⛔ Collabora)
Registry-driven matrix: PDF, DOCX, DOC, XLSX, XLS, PPTX, PPT, TXT, CSV, MD, JPEG, PNG, TIFF. **Only formats with a passing
conversion test are listed as supported.** Representative fixtures (tables, images, charts, headers/footers, multi-page,
landscape sheets); visual comparison where practical; magic-byte vs extension mismatch rejected; timeout, oversize,
malformed file, converter down → clear error, original untouched, retry works; temp files cleaned.

## Phase 6/7 – built-in signing and chains (◻; after semantics are decided)
Built-in: create, assignee-only, consent required, signing records version id + checksum + statement version, decline,
duplicate sign, cancelled/expired request, audit events, evidence not visible to unauthorized users.
Chains: single signer, several signers per level, sequential levels (cannot skip a level), optional signer, Super Signer,
decline policy, cancellation, provider failure mid-chain, duplicate completion event cannot advance twice, unauthorized
chain edits, retries after worker crash.

## Security (◻)
Cross-tenant request/artifact access, IDOR on request/recipient/artifact ids, signed-artifact download authorization and
revocation, webhook forgery, privilege escalation on chain config, access after share revocation.

## Regression gate
Full backend suite + frontend vitest + OpenAPI diff + migration model-diff test; results recorded in the roadmap before release.
