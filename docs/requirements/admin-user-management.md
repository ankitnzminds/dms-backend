# Admin user management and activity monitoring

Source specifications: *Admin User Management COMPLETE Specification v2* and *v3 (Audit / Activity)*.
This page is the feature matrix the specifications ask for. It states what is implemented, what is
partial, and what is deferred or unsupported **and why**. Nothing listed as implemented is mocked.
It is **not** a claim of parity with the reference product: the reference screenshots were not
available to compare against pixel-for-pixel, and several reference features depend on systems this
DMS does not have (mobile clients, email, backup, MFA).

## Design decisions

| Topic | Decision |
|---|---|
| Where profile fields live | Per-organization columns on `memberships` (`username`, `access_level`, `secondary_email`, `phone`, `notes`, `account_expires_at`, `account_locked`, `creation_source`). A person can belong to several organizations with different profiles. `users` stays global identity. |
| Passwords | DMS holds none: sign-in is the identity provider's (Supabase / SSO). The Add-user password fields, "generate password and email it", reset password, password expiry, and "change password on login" are therefore **Not supported**, deliberately. |
| Deleting an account | **Soft**. Membership becomes `removed`, sessions end, group memberships are dropped. Files, versions, shares and audit history are **kept** (retention first). The dialog says so; the reference text ("deletes all files") is intentionally not followed. Needs a checkbox and the typed email. Self-delete and last-owner delete are refused. |
| Policies | One versioned JSONB document per scope (`organization`, `group`, `user`) holding only the overridden keys. Precedence: built-in default < organization < groups (name order) < user. The API returns the value and where each value came from. Optimistic concurrency via `version`. |
| Enforcement honesty | `ENFORCED` in `app/modules/policies/schema.py` lists the settings backend code acts on. Everything else is stored, versioned and audited, and the UI labels it "Stored, not enforced yet". |
| Roles | Existing four roles: owner, admin, member, auditor. The spec's finer delegated roles (Group Admin, Policy Admin, …) are **not** modelled; see Deferred. |

## Feature matrix

Legend: **Implemented**, **Partial**, **Deferred** (not built, feasible), **Not supported** (no backing system).

### Navigation and users

| Feature | Status | Notes |
|---|---|---|
| Collapsible `USERS / GROUPS` group with Users, Groups, Admins | Implemented | State remembered per browser; the group stays open on its own pages. Server-side authorization on every route. |
| Users list: search, status filter (All/Guest/Full/External/Disabled), source filter, sort allow-list, page size, pagination, empty/loading/error | Implemented | Search covers user name, email, secondary email, display name, notes. Access level and disabled/locked state are separate. |
| Row actions: expand, edit, manage policy, delete | Implemented | |
| Add user (access level, user name, display name, email, role) | Implemented | Creates a pending invitation. "AD/LDAP" authentication is disabled in the form: directory accounts come from directory sync. |
| Welcome / invitation email | Not supported | No email provider is configured; the API returns `invitation_email: "not_configured"` and the UI says no email was sent. |
| CSV import: template, dry-run preview, validation, duplicate policy, results | Implemented | Max 1000 rows / 1 MB, runs in the request. Existing accounts are **skipped, never overwritten**. A Password column is ignored and never stored. Group names are mapped explicitly. |
| CSV import as a background job with progress and error-report download | Deferred | Needs a job table and worker handler; bounded in-request import is used instead. |
| Directory import | Partial | Existing Directory sync (preview, stable ids, explicit group mapping) is linked from the dialog; it is not re-implemented. |
| Export users (CSV) | Implemented | Honors filters, formula-injection safe, excludes phone, notes and secrets; audited as `member.exported`. |
| User details: summary and quota card | Implemented | Used bytes are summed from stored versions the user uploaded (trash counts until purged, ADR-0007). Total quota comes from the effective policy. |
| Details fields: display name, user name, secondary email, phone (E.164), access level, account expiry, account locked, notes, creation source, email verified (read-only), authentication (read-only) | Implemented | Field-level errors; unsaved-changes prompt. |
| Profile image, TOS date, disable sync, backup path, password expiry, change-password-on-login | Not supported | Listed in the dialog under "Not available in this DMS" with the reason. |
| Quick actions: Manage Policy, Manage Shares, Notifications, Delete Account | Implemented | |
| Quick actions: Manage Files, Mobile Devices, Reset Password, Send Email, Manage Backups | Not supported / Deferred | Shown disabled with a reason. Manage Files (browsing another person's files) is deferred by design: use Shares and Activity. |
| Group membership of a user (replace set) | Implemented | Directory-synchronized groups are read-only here (409). Membership never changes anyone's role. |
| Manage shares of a user | Partial | Lists shares the user created. Revoking another person's share from here is deferred (the owner/manager revokes via the share). |
| Lock / unlock, expiry | Implemented and enforced | Locking ends sessions; locked or expired accounts cannot start a session (`account_locked`). |
| Access level enforced | Implemented | Guest and External accounts have no storage: uploads are refused (`no_storage_access`). |

### Policies

| Tab | Status | Enforced today |
|---|---|---|
| General | Implemented (stored, versioned, validated) | Share mode (`no_shares`), default share expiry, per-user storage quota |
| MFA | Stored only | Nothing: MFA belongs to the identity provider. UI says so. |
| User policy | Implemented (stored) | Max upload size, Enable web edit |
| Client application | Stored only | Nothing: there is no mobile client |
| Device configuration | Implemented (XML validated with line/column, DTD/entities rejected, versioned) | Not delivered to any device: no device channel |
| Notifications | Implemented (stored) | `disable_all`, `disable_share` |
| Watermark | Not supported | Honest empty state; there is no watermark feature |
| Cancel / Reset / Save, dirty prompt, provenance, effective view | Implemented | Reset removes overrides at that scope only, after confirmation |
| Group policies and organization default policy | Implemented | Group policy from the Groups page; organization default API (`/admin/policies/organization`) has no dedicated page yet |

### Groups and admins

| Feature | Status | Notes |
|---|---|---|
| Groups CRUD, membership, policy | Implemented | Existing Groups page + group policy. |
| Group source/provenance column, protected system groups | Deferred | `external_id` exists on groups; the list does not show it yet. |
| Admins page: list, add, change role, suspend, reactivate, revoke sessions | Implemented | Reuses member rules: rank checks, no self-changes, **last active owner protected**; role changes are audited. |
| Delegated admin roles (User/Group/Policy admin, scoped audit) | Deferred | Needs a role/scope model beyond the four roles. |

### Folder permissions / Check Access

Not part of this change: the existing share and permission APIs (grants, effective actions) remain. A
dedicated admin folder-ACL dialog with "Check Access" is **Deferred**.

### Activity and audit (v3)

| Feature | Status | Notes |
|---|---|---|
| Organization activity page and **user Activity tab** | Implemented | Filters: category, result, action, date range; user via the user timeline. |
| Keyset (cursor) pagination, newest first | Implemented | Stable while new events arrive. |
| Event detail drawer | Implemented | Actor, target, result, request id, safe metadata. |
| CSV export | Implemented (synchronous, 50 000 rows) | Audited as `audit.exported`; rate limited; formula-safe. Async export jobs: Deferred. |
| Viewing is audited | Implemented | `audit.viewed` once per opened view (not per page of results). |
| Role scoping | Partial | Owner, admin and auditor read the organization's activity; **only owner and auditor see IP address and user agent**. A user cannot read activity (403). Finer scopes: Deferred. |
| Tenant isolation | Implemented | Every query filters by the caller's organization; another tenant's event id returns 404; tested. |
| Immutability | Implemented | Database triggers block UPDATE, DELETE and TRUNCATE on `audit_events` (tested). |
| Retention policy / purge process, tamper-evident hashes, alerts, live updates | Deferred | Events are kept indefinitely; `GET /admin/audit-policy` says so. |
| Redaction | Implemented | Metadata keys containing token/secret/password/url/signature are dropped; profile changes record field **names** only; search text is not recorded. |

#### Event coverage (what actually emits an event)

Instrumented: member invite/accept/update/lock/unlock/deactivate/reactivate/delete/groups/profile/
import/export; group create/update/delete/membership; policy updated/reset; share create/revoke/
expire; permission grant/revoke; access requests; document and folder create/move/copy/delete/restore/
version restore/lock; upload initiate/expire; scan clean/quarantine; preview/download URL issued;
Office opened/saved; comments; workflows; signatures; retention and legal hold; metadata
definitions; directory sync; AI chat and agent tool actions; logout; denied authorization;
rejected inactive/locked accounts; audit view/export.

**Not observable by this application** (so not in the log): the sign-in itself (done at the identity
provider; `last_login_at` is updated at the first authenticated request), actual byte transfers after
a ticket is issued, edits made *inside* the office server before they are saved, devices, backups,
email delivery.

## API surface

`/api/v1/admin/`: `users` (GET, POST), `users/export`, `users/import/template`, `users/import/preview`,
`users/import`, `users/{id}` (GET, PATCH), `users/{id}/deactivate|reactivate|delete-impact|delete|quota|
groups|shares|policy|policy/reset|policy/effective|activity`, `admins`, `policies/defaults`,
`policies/organization`, `groups/{id}/policy`, `activity`, `activity/export`, `activity/{id}`,
`audit-policy`. All are tenant-scoped from the verified principal; none accepts an organization id.

## Tests

`tests/integration/test_admin_users.py` (29 tests): listing/filters/sort, tenant isolation (IDOR on
every sub-resource), create/validation/uniqueness, lock/expiry blocking sign-in, rank and self
protection, deletion confirmation and file retention, last owner, policy validation/versioning/
precedence/provenance, enforcement (upload limit, personal quota, guest storage, share mode and
default expiry), CSV preview/commit/duplicates/limits/formula-safe export, activity roles/privacy/
cursor/audit-of-viewing/immutability/no-secrets.

## Deployment notes

- New migration `b7c8d9e0f1a2` (additive; RLS enabled on `policies`). Apply with the normal Alembic flow; do not run against production without approval.
- New dependency declared: `defusedxml` (XML validation).
- No new environment variables.
