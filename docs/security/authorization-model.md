# Authorization model

Backend authorization is the only authority. The frontend hides actions for usability; the
chatbot's model never decides access.

## Effective actions

For a principal and a resource, the allowed actions are the **union** of:

1. organization role (`owner`/`admin` administer everything in their organization; `auditor` reads
   audit/compliance data),
2. ownership,
3. permission grants (user / group / organization-wide) with optional expiry, on the resource or
   inherited **downward** from an ancestor folder (`inherit=true`),
4. active shares (user / group recipients, with expiry; revocation is immediate),
5. approver access to a document with a pending workflow task.

Action vocabulary: `discover, view, preview, download, upload_version, create_child, edit_metadata,
rename, move, copy, share, manage_access, delete, restore, comment, export, administer`.

## Rules

* **Deny by default.** No grant, no action. `discover` is required to learn a resource exists.
* **Non-disclosure:** a resource the caller cannot discover returns the same 404 as a missing one;
  a discoverable resource without the action returns 403. Names in breadcrumbs the caller cannot
  open are marked `navigable=false` and can be masked by org policy.
* **Folder grants inherit downward only.** A document share never grants access to its parent or
  siblings. A share does not authorize browsing the original location.
* **No escalation:** a grantor can only grant actions they hold themselves (`acl.add_grant`).
  `administer` is a role, not a resource grant.
* **DLP:** documents whose classification is in the organization's `share_blocked_classifications`
  (default `restricted`) ignore share-derived access, cannot be shared, and are never sent to an
  external AI provider.
* **Holds and locks:** legal holds block deletion/purge; retention minimums block purge; a
  check-out lock blocks other users' rename/delete/new versions (admins can break it).
* **Tenant boundary:** every query filters by `organization_id`; composite foreign keys enforce it
  in the database; cross-tenant IDs behave as missing.

## Where it is enforced

`app/modules/authorization/service.py` (`folder_actions`, `document_actions`, `require_*`),
`acl.py` (grants), `sharing/service.py`, and the item/file-manager services. Router-level
dependencies only resolve identity and rate limits.

## Tests

`tests/security/test_authorization_matrix.py`, `test_tenant_isolation.py`,
`test_sharing_acceptance.py` (the mandatory sharing acceptance test), `test_input_and_http.py` (all in `tests/security/`).
