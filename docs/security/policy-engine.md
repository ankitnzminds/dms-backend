# Policy engine

Typed, declarative, versioned rules that can **restrict** what the ACL/share model would otherwise allow.
Code: `app/modules/policy_engine/` (schema, evaluator, runtime, service, simulator, templates). API:
`/api/v1/admin/policy-rules`. Tables: `policy_rules`, `policy_revisions` (migration `e6f7a8b9c0d1`).

The older `policies` table (flat per-scope settings such as upload limits) is unchanged; it is the
*settings* layer. This is the *rule* layer.

## 1. Where it sits in authorization

```
request -> Principal (active user, membership, org, groups; rebuilt every request)
        -> AuthorizationService._effective_acl   (owner / grants / shares / inheritance / admin)
        -> PolicyRuntime.restrict                (this engine: can only REMOVE actions)
        -> require_* / list filtering / search / AI / hover hints
```

`AuthorizationService._effective()` is the single choke point, so every caller sees the same answer.
A policy can never add an action, so a policy (or a bug in one) cannot grant access.

Invariants enforced in code, not configurable: authenticated + active user, active membership/org,
session validity, tenant scoping on every query, `requested <= held` on every grant (no self-escalation),
legal hold / retention on delete and purge, quarantine/scan gates, lock download-prevention.

## 2. Policy document (schema v1)

```json
{ "schema_version": 1,
  "effect": "DENY",                      // ALLOW | DENY | REQUIRE_APPROVAL
  "mandatory": false,
  "scope": {"type": "organization" | "folder" | "file", "id": "<uuid>"},
  "subjects": {"users": [], "groups": [], "roles": [], "access_levels": []},   // empty = everyone
  "resource_types": ["document", "folder"],
  "actions": ["download"],               // values of the existing Action enum
  "condition": {"attribute": "resource.classification", "operator": "EQUALS", "value": "confidential"} }
```

Conditions: leaf `{attribute, operator, value}` or `{op: AND|OR, conditions: [...]}` (max depth 4, 25 nodes).
Operators: `EQUALS NOT_EQUALS IN NOT_IN EXISTS NOT_EXISTS`. Attributes (allow-list, all filled from trusted
server state): `resource.classification`, `resource.file_extension`, `resource.owner_is_subject`,
`subject.role`, `subject.access_level`, `subject.is_external`. Nothing is executed; unknown keys,
attributes, operators, actions, effects and mistyped values are rejected with a path. An attribute must
exist for **every** targeted resource type (classification is document-only).

`REQUIRE_STEP_UP_AUTHENTICATION` is **not accepted**: the application has no step-up flow.

Subject targeting is a **union** (user OR group OR role OR access level). Scope `folder` covers that folder
and its whole subtree; `file` one document. Policy inheritance (folder scope) is separate from ACL
inheritance.

## 3. Precedence (one place: `evaluator.evaluate`)

1. matching **mandatory** DENY -> deny `POLICY_MANDATORY_DENY`
2. matching DENY -> deny `POLICY_DENY`
3. a rule whose context is incomplete -> deny `POLICY_CONTEXT_MISSING` (fail closed; unknown is never "equal" or "not equal")
4. matching REQUIRE_APPROVAL -> `require_approval`
5. otherwise `no_opinion` (adds no restriction; **never a grant**)

ALLOW rules are matched and reported (explanations, simulator) but cannot lift a DENY or approval and
cannot create a missing permission. Every match is reported, rules are visited in a stable order, and
the same inputs + revisions always give the same result. Numeric priority is not used.

**Administrators** (owner/admin) are exempt from ordinary rules but **bound by mandatory ones**
(managed by owners only), so an ordinary DENY can't lock out the people administering the tenant.

## 4. Groups

Membership is read from `group_memberships` for the authenticated user on **every request** (no cache),
so removing someone from a group ends group-derived restrictions/access on the next request. A user in
several groups is matched against all of them; conflicts resolve by "deny wins". Nested groups are not
supported by the identity model; a policy can only reference a group that exists in the same
organization (checked at validation and again at publish). A deleted group simply matches nobody.

## 5. Lifecycle

`draft -> validated -> published -> disabled -> archived` (policy status; revisions are
`draft / validated / published / superseded`). Editing a published policy opens a **new draft revision**
while the old one stays enforced. Published/superseded revisions are immutable (DB trigger). Rollback =
new draft copied from an old revision (needs validate + publish again). Publishing is transactional and
re-validates; `mode` is `enforce` or `observe` (shadow: decisions are only written to the audit log as
`policy.observed`, never applied and never able to authorize anything). Audit actions: `policy.created
updated validated published disabled enabled archived rolled_back mode_changed simulated observed`.

Capabilities use existing roles: view = owner/admin/auditor; manage/publish = owner/admin; **mandatory
policies = owner only**.

## 6. Enforcement points

Because enforcement is inside `_effective`, these all honour policies: folder listing, preview, download
tickets (re-authorised at redemption), upload / create folder / create file / version upload,
rename, move (source MOVE + destination UPLOAD/CREATE_FOLDER), copy, delete, restore, version
restore, share create/manage (SHARE), permission grants (MANAGE_ACCESS), search results and previews,
AI retrieval and AI tool actions, hover-action hints, and background principals (`principal_for`).
Anonymous **public links** have no Principal; they are evaluated as an external, role-less visitor
(`runtime.anonymous_blocked`) **and** now honour the organization's `share_blocked_classifications`
(previously a folder link could serve a "restricted" file).

## 7. Known limitations (honest)

- **REQUIRE_APPROVAL cannot be enforced**: nothing can hold an operation until approved. It may only be
  published in observe mode; enforce is refused (`approval_not_available`).
- No step-up/MFA effect (no MFA flow exists). No nested groups.
- Moving a file does not compare source and destination classification; use a folder-scoped DENY on the
  destination (upload/create) to keep content out.
- Attribute set is deliberately small (see §2). IP, device, time-of-day, auth strength are not available.
- Policies on groups that are later deleted stop matching silently.
- Retention / legal hold remain separate governance controls; policies do not weaken them.
- Observe mode logs only on single-resource operations (not bulk listings) to avoid audit flooding.

## 8. Rollout and rollback

1. Create from a template (always a draft). 2. Validate (references, impact count, overlap warnings).
3. Simulate for real users/resources, optionally including the draft. 4. Publish in **observe** mode and
review `policy.observed` events. 5. Switch to **enforce**. Rollback: set mode back to observe, or
**disable** (effective on the next request), or roll back to an older revision (new revision). Migration is
additive; downgrade drops only the two new tables.
