# Complete user flow plan (v2 + admin workflow addendum): gap matrix

Source: *Enterprise DMS: Complete User Flow, Workflows, Permissions, Version Control Implementation Plan v2*.
This is the requirement-to-code gap matrix the plan asks for. **Implemented** = works end to end and is
tested; **Partial** = works with the stated limits; **Deferred** = feasible, not built; **Not supported** =
no backing system or deliberately excluded. Parity with the reference screenshots was not measured, so
nothing here claims it.

## 1. Authorization, roles, revocation (plan §2, §6)

| Requirement | Status | Notes |
|---|---|---|
| Owner / Admin / Auditor / Member roles; tenant isolation | Implemented | Every query is scoped by the verified principal; cross-tenant ids return 404 (tests across admin, automations, diffs, access check). |
| Delegated roles (Group/Policy/Workflow admin, scoped audit) | Deferred | Needs a role+scope model. Today: owner/admin manage everything in the org, auditor reads audit. |
| Admin revokes access; effective on next check | Implemented | Authorization is recomputed on every call (no cached grants). WOPI tokens, download tickets and automation runs re-authorize each time. Tested: grant revoked → next access check and API call denied. |
| Direct, group, inherited (folder chain), share grants; expiry | Implemented | Existing engine; "inherit: false" grants do not reach children (tested). |
| Explicit deny | Not supported | The model is a union of grants (documented precedence: any grant, within expiry and account state, wins). |
| **Check Access** (what can X do here and why) | Implemented | `POST /admin/access-check`: same engine as enforcement, run as the target; provenance lists direct/group/organization/share/role/ownership and the inherited-from folder. Audited (`access.checked`). UI: Manage access → Check access. |
| **ACL impact preview** before a broad grant | Implemented | `POST /admin/acl-impact` + inline text in the grant form. |
| Bulk ACL change preview/apply | Deferred | Single-resource grants only. |
| Guest / External | Partial | Access level exists; no storage for them; they use shares. No link/OTP/password shares (see §6). |

## 2. Navigation and context menu (plan §3, §4)

| Item | Status | Notes |
|---|---|---|
| My Files, Recent, Starred, Shared by me/with me, Trash | Implemented | Existing. |
| Team Folders | Partial | `is_team_folder` exists on folders; no dedicated navigation entry. |
| Workflows | Implemented | Approval workflows (people) and **Automations** (IF/THEN + visual) are separate admin entries. |
| File Operations (job center, bulk jobs, conversions) | Deferred | No `operation_jobs` table; PDF export is synchronous. |
| USERS / GROUPS → Users, Groups, Admins | Implemented | Previous change. |
| Preview, Download, Open, Rename (F2), Share, Delete (recycle bin), Copy/Cut/Paste, Move to/Copy to, Properties, Quick Access | Implemented | Existing, backend-enforced. |
| Copy Direct Link | Partial | Copies the app URL; it works only for signed-in people with access. No public/token links. |
| Previous Versions (list, restore as new version, **compare**) | Implemented | Right-click → Version history & compare. |
| Lock (check out) | Implemented | Lease with expiry; admins can break; the *Release locks* automation clears stale ones. |
| Comment (C) | Partial | Threaded comments work from the details pane; no `C` shortcut from the list. |
| **Download as PDF** | Implemented | Office files only; converted by the office server (`/cool/convert-to/pdf`), needs download permission, nothing stored, `Cache-Control: no-store`, audited. Synchronous with a 90 s timeout; unavailable if no office server. |
| **Apply Color Tag** | Implemented | Eight colors on files and folders; shown as a dot; filterable in search (`color_tag`); audited. |
| Send for Approval | Partial | Available on the document page (existing), not in the right-click menu. |
| Start Workflow (manual, on a file) | Deferred | Manual-start automations are not built. |
| Notifications per resource | Deferred | User-level preferences and admin policy only. |
| Export Secure Doc (watermark/restrictions) | Not supported | No watermark engine. |

## 3. Office viewing/editing (plan §7)

Implemented in the earlier Office change (Collabora over WOPI, PDF.js, new immutable version per save,
per-call re-authorization). PDF export was verified against a real Collabora container (a 58 KB PDF from the complex DOCX sample).

## 4. Version control and diffs (plan §8)

| Item | Status | Notes |
|---|---|---|
| Immutable snapshots; restore = new version | Implemented | Existing (database triggers prevent changing stored bytes' metadata). |
| Compare any two clean versions (inline and side by side) | Implemented | `GET /documents/{id}/versions/compare?from=&to=`; needs DOWNLOAD; unreleased/quarantined versions refused; audited (`document.versions_compared`). |
| Text/Markdown/code | Implemented | Exact line diff with word-level highlights and collapsed context. |
| CSV | Implemented | Line diff + cell changes (rows matched by position). |
| JSON | Implemented | Line diff + structural diff by path. |
| DOCX | Implemented | Paragraphs, tables (per cell), headers/footers, run formatting flags; tracked changes are *counted and reported*. Not compared: images, floating objects, fields, comments, layout. |
| XLSX | Implemented | Sheets by name; value/formula changes; merged ranges; style ids. Formulas are not recalculated; charts/pivots/macros/external links are not compared. |
| PPTX | Implemented | Slide order (moves recognised), shape text, shape set, animation presence. Not compared: animation details, transitions, embedded objects, visual rendering. |
| PDF | Partial | Extracted text by page. No visual page diff (no server-side renderer); scanned pages give no text. |
| Images/other | Partial | Properties only (size, checksum, type); the result says no content diff exists. |
| Cached results, parser version, failure recorded | Implemented | `version_diffs` table; failures are shown as failures, never as "no differences". Hostile packages (zip bombs, DTD/entities) are refused with a message. |
| Asynchronous diff generation for big files | Deferred | Inline up to 25 MB per version; larger → "too large". |
| Version record: parent, save source, comment, workflow link | Partial | Has number, checksum, size, author, time, restored-from, scan state. No save-source/comment/workflow link fields. |

## 5. Sharing (plan §9)

Shares to users and groups with permission set, expiry, revoke, recipients and a permission summary exist.
**Not built:** link shares, password/OTP, download caps, and a share-approval step (the
`require_share_approval` policy is stored but not enforced). The new policy `default_share_expiry_days`
and `share_mode` *are* enforced (previous change).

## 6. Automation workflows (plan §10 and the Admin addendum)

One definition model, two editors: a trigger plus a validated graph of typed nodes, saved as a **draft**,
published into an **immutable version** (recording who published it), then explicitly **enabled**.

| Item | Status | Notes |
|---|---|---|
| Manage Workflows table (Name, IF THIS, THEN THAT, Last Check, Last Action, Enabled, Actions), Add Workflow, "No results found" | Implemented | Last Check / Last Action come from real run records ("Never" until one happens). Scheduled workflows show the next check time. |
| Wizard: condition → parameters → action → parameters → name → Finish | Implemented | Previous/Next/Cancel/close keep input; every Next is validated by the server; Cancel warns when dirty; Finish persists as a **draft** unless "Publish and enable now" is ticked. |
| Typed forms from JSON Schema + advanced JSON editor | Implemented | Forms are generated from the same Pydantic models the server validates with; malformed JSON/unknown keys are rejected with field-level messages. |
| Constrained expressions | Implemented | `== != < <= > >= in, not in, contains, startswith, endswith, matches, and/or/not`; no calls/attributes/eval; unknown variables are errors; regex length and nested quantifiers restricted. |
| Conditions (20) | 18 Implemented, 2 Not supported | Not supported: *client app connects* (no device registry), *share not accessed* (share access is not recorded). Each condition states what DMS actually observes (e.g. *file created* fires after the malware scan; *downloaded* means a link was issued). |
| Actions (9 wizard + 6 canvas-only) | Implemented | notify, copy, move, delete (**recycle bin only**), verify integrity (alert / delete→recycle bin), run report (activity summary as a notification), release locks, send email (**skipped and recorded as skipped** when no email provider is configured; recipients are members only). Canvas adds create directory, set metadata, assign ACL (read-level, expiring, cannot exceed the publisher's own rights), wait for approval, assign variable, condition. |
| Visual canvas (palette, drag/drop, connect, zoom/pan/fit, undo/redo, autosave draft, validation, list view) | Implemented | Built on `@xyflow/react`. A **List (keyboard)** tab edits the same definition without a pointer. Folder picker has no "New folder" button. |
| Trigger kinds | Partial | Event, timer, daily scan. Not built: manual "started by a user on a file", "share activity", "metadata activity" triggers. |
| Durable runs, node states, attempts, errors, correlation ids | Implemented | `automation_runs` / `automation_node_runs`; executed from the transactional outbox (retry with backoff, dead-letter). |
| Idempotency | Implemented | One run per (workflow, event key); finished nodes are never redone; redelivery and a second scheduler cannot duplicate runs (tested). |
| Re-authorization before every step | Implemented | Runs act **as the person who published** the version: the principal is rebuilt from current state before each node. A suspended publisher or a disabled workflow stops the next step (tested). |
| Notifications do not leak | Implemented | A recipient who cannot view the file gets a generic message without its name/path/link (tested). |
| High-risk steps (delete, ACL, email) | Implemented | Publishing needs an **owner** and an explicit confirmation; recorded on the version. |
| Dry-run test | Implemented | Evaluates conditions/variables for real; other steps only report what they would do; not recorded as a real run. |
| Retry failed steps / cancel / archive / duplicate / enable / disable | Implemented | |
| Circuit breaker | Implemented | >200 runs in 10 minutes disables the workflow with "needs attention" (protects against self-triggering loops, e.g. a copy into a watched folder). |
| Pause/resume mid-run, per-node timeouts, concurrency limits | Deferred | Disable cancels at the next step boundary. |
| Approval gates for risky steps beyond owner confirmation | Partial | Owner confirmation only; no per-run approval. |
| Audit | Implemented | created/updated/published/enabled/disabled/archived/run finished/retried/cancelled/circuit open, integrity mismatch, forced lock release; shown under the Workflow category in Activity. |

Operational notes: timers and scans are evaluated by the worker's maintenance loop (about once a minute;
intervals have a 15-minute minimum); event workflows depend on the worker, and events queue durably while
it is down; waiting approvals are re-checked on the same cadence.

## 7. Audit (plan §5, §13)

Implemented in the previous change (Activity page, user timeline, cursor paging, export, append-only,
viewing audited). New events from this change: `access.checked`, `document.versions_compared`,
`document.exported_pdf`, `document.color_tagged`, `folder.color_tagged`, `automation.*`,
`integrity.mismatch`, `document.lock_released_by_automation`.

## 8. Not covered by this change

Admin Portal items from the addendum's navigation list that are separate products (Smart DLP, Smart
Classification, Compliance Center, Federated Search, Watermark, Alert, Device Management, Customization)
were not built. Existing Governance, Quarantine, Reports and Directory sync pages remain.

## Tests added

`tests/integration/test_automations.py` (49), `tests/unit/test_automation_expr.py` (27),
`tests/integration/test_version_diffs.py` (12), `tests/integration/test_flow_extras.py` (12);
frontend `tests/unit/automations-definition.test.ts`.

## Deployment notes

New migrations (additive): `c8d9e0f1a2b3` automations, `d9e0f1a2b3c4` version diffs, `e0f1a2b3c4d5` color
tags. Run the worker (it executes automations). PDF export needs the Collabora container to accept
conversion requests from the backend (its `net.post_allow` must include the backend's address). Frontend
adds the `@xyflow/react` dependency.
