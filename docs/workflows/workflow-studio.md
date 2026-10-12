# Workflow studio

One designer, one engine, for everything that should happen "when something happens", "on a schedule" or
"when a person asks for it". It extends the existing automation engine (`app/modules/automations`); the
approval engine (`app/modules/workflows`) is reused for the human steps. Nothing was duplicated and the
existing workflows, approval chains and signature chains behave exactly as before.

## Who uses what

| Person | Where | What they do |
|---|---|---|
| Administrator | Admin → Workflow studio | Designs workflows (wizard or visual canvas), sets *Bindings*, checks, tests (dry run), publishes, enables. |
| Administrator | Admin → Workflow runs | Sees every run, filters by status or workflow, opens a run to see each step, retries or cancels. |
| Anyone who can edit a file/folder | File or folder → **Start workflow**, and the file's **Workflows** tab | Starts a workflow an administrator made available, adds a note, follows it live. |
| Anyone | Workflows (left menu) | Sees the workflows they started and where each one is now. |
| Anyone asked to approve | My approvals | Decides, delegates (the existing approvals inbox). |

## Triggers (the Start node)

Grouped in the editor as *A person starts it* / *When something happens* / *On a schedule*.

New in the studio:

* `manual_file` / `manual_folder` – started by a person. Scope (folder path, file types, exclude, expression)
  decides where "Start workflow" is offered; `who_can_start` is `editors` (anyone who can edit the file, or
  add to the folder) or `admins`.
* `access_request_created` – someone asks for more access to a **file** (folder requests do not start
  workflows). Variables: `request.id`, `request.actions` plus the usual file variables.
* `file_metadata_updated` – a file's details or classification were edited.

Existing: file/folder created, updated, deleted, downloaded, comment added, size thresholds, timers,
daily scans and user events. `client_app_connected` and `share_stale` stay listed as *not supported* with
the reason.

## Steps

New: **Human approval**, **Grant access**, **Deny access**. Existing steps are unchanged.

### Branching is now data-driven

`ActionSpec.outputs` names a step's exits. `condition` has `true`/`false`; `human_approval` has
`approved`/`rejected`/`timeout`. The catalogue returns `outputs`, the canvas draws one handle per exit, the
list editor shows one selector per exit, and validation checks edge labels against the same list (every
exit at most once; the first exit of a non-condition branching step must be connected). Plain steps still
have a single unlabelled exit.

### Human approval

Asks people (users and/or groups) to approve the file and parks the run (`waiting`).

* Completion: `any` (first answer decides), `all`, or `sequence` (one after another).
* **Compiled onto the existing approval engine** at publish time (`_compile_approvals`): one approval
  workflow definition per (workflow, step) with a stable name `Workflow studio: <id>/<node>`, versioned
  on republish, so approvals already in flight keep the people they started with. Tasks therefore show up
  in *My approvals* with delegation, due dates, audit and notifications for free. The mapping is stored on
  the immutable version (`automation_versions.approval_definitions`).
* Exits: **approved**, **rejected** (also taken when the approval is cancelled), **timeout** (no decision
  within `timeout_days`; the open approval is cancelled so nobody can answer a closed question).
  Rejection is a normal outcome, not a failure; a missing exit simply ends the run.
* The run resumes **immediately** when the approval finishes (`workflow.finished` wakes the parked run);
  the maintenance pass remains as the safety net and is what notices timeouts.
* Needs a file. One open approval per file (the approval engine's rule) – a second one fails the step with
  a clear message.
* The task title/instructions support placeholders (`{file.name}`), and the starter's note is appended.

### Grant access / Deny access

Answer the access request that started the run through `access_requests.decide`, i.e. with the same
checks as a person deciding: the publisher must hold *Manage access* on the file and cannot be the
requester. Grant is limited to read-level actions (`view`, `preview`, `download`, `comment`) and only what
was asked for; expiry defaults to 30 days. `grant_access` is **high risk** (owner + confirmation to
publish). An already-decided request makes the step *skipped*, never an error.

## Manual start

`GET /automations/startable?resource_type&resource_id` lists what the caller may start;
`POST /automations/{id}/start` starts it. The starter must hold `edit_metadata` on the file (or
`create_child` on the folder), the workflow must be published, enabled, of the right item type and in
scope. A run is created like any other (`event_key = manual:<uuid>`, same circuit breaker) and audited as
`automation.manual_started`.

**Execution identity is unchanged: runs execute as the person who published the workflow** and re-check
that person's rights at every step. Starting a workflow therefore never gives the starter more power than
the administrator chose to hand out; the publish dialog says so for manual workflows.

## Bindings (exclusive vs additive)

`automations.binding_mode` (`additive` default, `exclusive`) and `priority` (0–1000).

When one event matches several workflows: all **additive** ones run; of the **exclusive** ones only the most
specific scope runs (deeper folder path, then file-type and expression filters), priority then age break a
tie. Scope itself stays in the trigger settings (folder path, file types, expression); it is path-based,
so renaming or moving a folder changes what it covers.

## Seeing what happened

* Admin: `GET /admin/automation-runs` (every live run; filters `status`, `automation_id`) and the existing
  run detail with retry/cancel.
* Everyone else gets a **summary only** (`RunSummaryOut`): workflow name, status, who started it, item,
  step names with outcome/exit and errors – never step parameters or raw output.
  `GET /automation-runs/mine`, `GET /automation-runs/mine/{id}` (the starter, or an admin) and
  `GET /documents/{id}/automation-runs` (anyone who can view the file).
* Dry runs preview a branching step's first exit (the happy path) so the rest of the flow is visible;
  nothing is asked, sent or changed.

## Data model (additive migration `e2f3a4b5c6d7`)

* `automations.binding_mode`, `automations.priority`
* `automation_versions.approval_definitions` (JSONB)

## Honest limits

* Run steps execute as the publisher; per-starter execution identity is not offered on purpose.
* Share-activity and "started on timer" visual workflows from other products are not included
  (share events are not tied to a file/folder resource yet; timers already exist as triggers).
* Access-request workflows cover files only.
* Timeouts and the safety-net resume are noticed on the maintenance pass (minute-level), not to the second.
* The visual canvas still runs one linear path with branches; there is no parallel fan-out.
