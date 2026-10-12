# E-signature architecture (current) and the proposed extension

## Current
```
UI (document panel / My Signatures) --> /documents/{id}/signature-requests (create)
   create_request: authz (SHARE+DOWNLOAD), org opt-in, DLP, PDF + CLEAN scan -> row `creating`
   -> adapter.create_and_send (Documenso REST v1) -> `sent`, provider_request_id stored
signer -> POST /signing-session -> Documenso page in an iframe overlay (consent/sign/decline happen THERE)
Documenso -> POST /webhooks/signatures/documenso (secret header) -> signature_events (dedupe) -> outbox
worker/refresh -> reconcile(): GET provider state (authority) -> row lock -> recipients/state -> on completed:
   download -> sha256 -> NEW DocumentVersion (+ signed_artifacts row, source_version_id) -> audit + notify
maintenance -> reconcile_stale (sent > N min), fail stuck `creating`
```
Principles already in place and kept: provider state is authoritative; webhook and "finished" button only
trigger verification; terminal states do not regress; artifact creation is idempotent (unique request id);
original versions are never overwritten (signed PDF = new version); every query is org-scoped.

## Proposed (backward compatible; only after the open questions in the gap analysis are answered)
1. **State machine**: single `transition()` with an explicit map; reuse existing states
   (`creating`≈PREPARING, `sent`≈AWAITING/IN_PROGRESS, terminal: completed/declined/cancelled/expired/failed);
   progress is derived from recipients. Add a state only if needed (e.g. `converting`).
2. **Provider adapter** gains `builtin` (same interface): `create` records recipients; signing is a DMS endpoint
   `POST /signature-requests/{id}/sign` (consent statement id + exact version id + checksum, assignee only,
   locks the row, rejects terminal states, writes evidence + audit) and `POST .../decline`.
   Evidence is a record of electronic-signature consent, **not** a cryptographic PDF signature, and is labelled so.
3. **Chains**: new tables `signature_chains` (folder scope, provider) and `signature_chain_levels/signers`
   (level index, `required`, `super`), executed by a single `advance_chain()` that runs under the request row lock
   and is keyed by the recipient-completion event so duplicates cannot advance twice. Semantics per the answers.
4. **Convert-then-sign**: outbox job `signature.prepare` → `office.to_pdf` with timeout + size cap → store the
   signing PDF as an *artifact* (checksum recorded with the source checksum) → create the provider request from it.
   Failure keeps the original, records `signature.conversion_failed`, and is retryable.
5. **Placement**: request carries `fields[{signer, page, x, y, w, h}]` validated against the PDF page count and bounds;
   default stays last-page placement.
6. **Security**: unique active request per document; encrypted/non-persisted signing URLs; completion re-check;
   cancel under lock; audit `received/duplicate/prepared/conversion_failed/consent/chain_advanced`.

Deployment requirements (unchanged): Documenso URL/API key/webhook secret; Collabora URL for conversion (both external).
Migrations must be additive (nullable columns, partial unique index created after a duplicate check).
