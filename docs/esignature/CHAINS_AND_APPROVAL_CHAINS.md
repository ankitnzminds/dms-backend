# Signature chains and approval chains (ported from the reference DMS)

Source of the behaviour: `C:\ANKIT\DMS\dms-app` (read-only inspection). Implemented here on top of the existing
architecture (no second engine, no second group system). Where this DMS differs, the reason is stated.

## 1. Signature chains (per folder)
Admin page **Administration > Signature chains**; API `GET/PUT /folders/{id}/signature-chain` (PUT = administrators; full
replace; empty = remove). Table `signature_chain_steps` (folder, level, user, optional, is_super_signer); the chain is copied onto
the request's recipients (`level`, `optional`, `is_super_signer`) when it is created, so editing the chain never changes a running request.

Rules (module `signatures/chain.py`, pure and unit-tested; request row lock + `transition()` around it)
- Levels run in order; signers inside a level are parallel. A level is complete when every **required** signer has signed (a level of only
  optional signers needs one signature).
- A signer can act only when their level is the active level or an earlier one (`409 not_your_turn` otherwise; the UI shows "Waiting for an earlier level").
- A required decline halts the chain: pending signers at that level and later levels become `cancelled`, the request is `declined`.
  An optional decline changes nothing else.
- A **super signer**'s signature makes every other pending signer at their level and later levels `bypassed` and completes the request
  (confirmation dialog: "…immediately bypass every other pending signer at this level and every signer at every level below…").
- When the last level completes, optional signers still pending become `bypassed`.
- Progress is computed from the recipients' statuses each time (no "create the next level" step), so repeated or concurrent actions cannot advance a
  chain twice (the reference app has no lock and can create duplicate next-level requests).
- Starting: if the document's folder has a chain the request uses it (the body's signer list is ignored; button "Start signature chain"); otherwise the
  requester names the signers as before.
- Audit: `folder.signature_chain.set`, `signature.chain_advanced`, `signature.chain_override`, plus the existing signed/declined/completed events.

Differences from the reference, deliberately
- **One request with many recipients** (the reference creates one request per signer, level by level). Needed for the single-document evidence model.
- **Groups are the existing DMS groups** (members expanded when the chain is saved); there is no separate "Signature groups" system.
- **A person can be in one level only** (recipient rows are unique per person per request).
- **External provider (Documenso):** one Documenso document holds all signers (signing order), so levels are enforced inside the DMS (the signing page opens only
  on the signer's turn) but **optional and super signers are refused (`422 chain_flags_builtin_only`)**: Documenso only completes once every recipient has signed. Use built-in signing for those.
- Reference quirks not copied: consent text is now sent and stored (statement version + hash); the "I've finished signing" action never changes state on its own;
  built-in signing records the exact version checksum.

## 2. Approval chains (per folder) on the existing workflow engine
Admin page **Administration > Approval chains**; API `GET/PUT /folders/{id}/approval-chain`; file action **Submit for approval**
(`POST /documents/{id}/submit-for-approval`, no approver to choose when the folder has a chain; otherwise the existing "choose a workflow" flow is unchanged).

Saving compiles the levels into a **versioned workflow definition** ("Folder approval chain: <folder>") and binds it to the folder (`folder_approval_chains`);
editing creates a new version, so approvals in flight keep the chain they started with. Everything else (My approvals, delegation, resubmission, due dates,
notifications, audit, reviewer access to the exact version) is the engine's own.

Engine extension (additive; existing definitions behave exactly as before): assignee entries and tasks carry `optional` and `is_super_approver`.
- A step ("level") is done when every **required** approver approved; a step of only optional approvers needs one approval; remaining optional tasks are skipped.
- A **required** rejection halts the chain and rejects the document; an **optional** rejection is recorded only.
- A **super approver's** approval approves the document immediately and skips every pending task (confirmation: "…immediately bypass every other pending approver at this level and every approver at every level below…"). A super approver can act only once their level has started.
- Audit: `folder.approval_chain.set`, `workflow.chain_override` (+ the usual `workflow.*`).

Not ported (and why): the reference's **graph workflow engine** (React Flow builder, 14+ node types, trigger bindings, upload-hold in a "Drafts" folder) is a separate,
large subsystem; this DMS already has its own versioned workflow engine, so only the folder approval chain (the "workflow creation for a file and for a folder" flow) was ported.
Folder chains are not inherited by subfolders (same as the reference).

## 3. Migrations (additive)
`b9c0d1e2f3a4` (signature_chain_steps; recipient level/optional/is_super_signer; recipient status adds `cancelled`, `bypassed`),
`c0d1e2f3a4b5` (workflow_tasks optional/is_super_approver; folder_approval_chains). Downgrades map the new recipient statuses back to `declined`.

## 4. Evidence (executed tests)
Backend: tests/unit/test_signature_chain.py (7), tests/integration/test_signature_chains.py (19), tests/integration/test_approval_chains.py (16).
Frontend: tests/components/signature-chains.test.tsx (4), approval-chains.test.tsx (4). Full-suite results: see docs/audit/IMPLEMENTATION_ROADMAP.md.
