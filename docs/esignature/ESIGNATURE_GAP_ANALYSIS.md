# E-signature gap analysis

Priority: P0 critical security/integrity · P1 required capability or integrity gap · P2 important · P3 minor.
Evidence is from the audit in ESIGNATURE_EXISTING_IMPLEMENTATION.md.

## Security / integrity gaps in what exists
| # | Pri | Gap | Smallest backward-compatible fix |
|---|---|---|---|
| S1 | P1 | No "one active request per document" rule; duplicates allowed (incl. concurrent) | Partial unique index on `(organization_id, document_id)` where state in (`creating`,`sent`); return 409 `signature_in_progress`. Existing rows: check for duplicates before the migration and cancel/mark nothing automatically (report them) |
| S2 | P1 | `cancel_request` has no row lock and no re-check after the provider call (race with reconcile) | `SELECT … FOR UPDATE`, re-read state after the provider call, then transition |
| S3 | P2 | No state-transition table; terminal protection exists only in `reconcile` | One `transition(request, new_state)` helper with an allowed-transitions map, used by every writer; DB trigger optional |
| S4 | P2 | Webhook: static shared secret, dedupe by body hash with no replay window | Keep (provider contract gives no HMAC/event id); treat webhook strictly as a hint (already true); add rate/size limit + audit `webhook_received/duplicate`; verify against provider's documented signing option if the deployed Documenso version supports it (to confirm) |
| S5 | P2 | Signing URLs stored in plaintext | Encrypt at rest with the same mechanism as share link tokens (`link_token_enc`) or stop persisting and re-fetch per session |
| S6 | P2 | Signed artifact checksum is self-computed; no validation that the file is a PDF with provider-verified completion | Re-verify `get_state()==completed` immediately before download; validate `%PDF`, size > 0, page count via pypdf; store sha256 (already) and source-version sha256 on the request |
| S7 | P2 | Source-version checksum not stored on the request | Add nullable `source_sha256` (backfill from `document_versions`) |
| S8 | P2 | Signed version scan_status starts PENDING; promotion to current unverified | Trace and test; document |
| S9 | P3 | `assert` for scan status in `create_request` (500 / stripped under -O) | Replace by a typed 409/422 error |
| S10 | P3 | Expiry unreachable; old `sent` requests never expire | Optional `expires_at` on the request + maintenance sweep (needs product decision on default) |
| S11 | P3 | Field overlap beyond ~4 signers; silent page-1 fallback | Distribute fields in a grid; reject malformed PDFs |
| S12 | P3 | ADR number mismatch; no signature runbook | Docs |

## Missing capabilities (not in the code at all)
| # | Pri | Capability | Note |
|---|---|---|---|
| M1 | P1 | Built-in (typed-name/consent) signing: consent statement, explicit confirm, evidence (statement version, version id + checksum, timestamp, optional IP/UA), separate decline endpoint, My Signatures sign/decline dialogs | New provider `builtin` behind the existing provider adapter; reuse requests/recipients/events tables; new evidence table or JSONB on recipients |
| M2 | P1 | Signature chains: folder-specific chains, levels (sequential), several signers per level, optional signers, Super Signer, decline policy, cancellation, provider per chain | **Semantics are not defined anywhere in the repo.** Must be decided with the product owner before any code (see Open questions) |
| M3 | P1 | Convert-then-sign for DOCX/XLSX/PPTX/etc. | Reuse Collabora `to_pdf`; store the signing PDF as an artifact (not a version replacement); register source+PDF checksums; background job with timeout/retry |
| M4 | P1 | Field-placement UI / explicit page + coordinates | Provider supports field positions; need a placement step and validation against page count |
| M5 | P2 | My Signatures: pending vs history split, Ready/In progress states, expiry display | UI + list filter; no new backend states needed except if PREPARING is added |
| M6 | P2 | Provider selection UI | Backend selects by env today; only meaningful once `builtin` exists |
| M7 | P2 | Documenso webhook delivery verified live; conversion tests; image/TXT/CSV/MD → PDF without Collabora (images/text) | Needs a Documenso instance and Collabora; cannot be proven locally without them |
| M8 | P3 | Dedicated signature audit view; format registry with MIME + magic validation for OOXML/ODF | |

## Ambiguities that block implementation (Open questions)
1. **Optional signer:** may the request complete without them? Do they receive a request? Can they block a level?
2. **Super Signer:** a signer who can sign for any level / override a stuck level / sign on behalf of others / who must always sign last? Is their signature required for completion?
3. **Level completion:** all required signers of a level, or any N? What does a decline do (fail the chain, skip, restart)?
4. **Providers per chain:** may a chain mix built-in and Documenso signers? (Not recommended: different evidence strengths.)
5. **Legal status** of built-in signatures (typed-name consent is an electronic-signature record, **not** a cryptographic PDF signature) and jurisdiction review: owner/legal decision, not an engineering one.
