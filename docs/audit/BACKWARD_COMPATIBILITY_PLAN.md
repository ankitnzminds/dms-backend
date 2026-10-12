# Backward-compatibility plan

Principle: additive changes only; any behavior change is a documented security fix.

## Already changed (all additive)
- Tables `policy_rules`, `policy_revisions` (migration `e6f7a8b9c0d1`); `local_password_hash`, recycle
  `purge_requested_*` columns (earlier). No table/column dropped, no identifier changed.
- New endpoints only: `/admin/policy-rules*`, `/admin/permissions/access`, `/me/access`,
  `/resources/{kind}/{id}/{effective-access,permission-history}`. Existing contracts untouched.
- `AuthorizationService._effective` now wraps `_effective_acl` (the former body, unchanged). With **no
  published policy** the result is identical to before (one extra query per request, memoized).

## Documented behavior changes (security fixes)
1. Public links now hide `share_blocked_classifications` (default `restricted`) documents and honour
   enforcing policies. Anyone relying on anonymous access to restricted files loses it (intended).
2. Admin permission endpoints answer 404 for foreign-tenant resources.
3. A published, enforcing DENY policy removes actions for matching users (new capability, opt-in).

## Rules for upcoming work
- Migrations: nullable columns / safe defaults, no drops, tested by `tests/integration/test_database.py`
  (model-vs-migration diff) and applied to a copy first; forward-recovery steps in each PR.
- API: add fields/endpoints, never rename; regenerate `docs/api/openapi.json` and the frontend types in the same
  change (CI has an OpenAPI diff).
- Governance fixes (G1) tighten move/rename/restore: ship behind a documented release note, default ON because it
  is a security fix, with an audit event naming the blocking hold/retention so support can explain denials.
- Rate limiting and config guards fail closed only in production-like environments; development defaults unchanged.
- Feature flags may gate new UI/effects, never an existing protection.
- Policy engine rollout: drafts never enforce; new policies publish in **observe** first; disable is instant.

## Rollback
Application: redeploy previous image (new tables are ignored by old code). Policies: disable or set to observe.
Migrations: downgrade drops only additive tables; prefer forward fix on data-bearing environments.
