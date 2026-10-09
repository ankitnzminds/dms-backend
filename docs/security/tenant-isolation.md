# Tenant isolation

* **Identity → tenant:** the tenant comes from server-side memberships. `X-Organization-Id` can only
  select among organizations the user is already an active member of; any other value returns the
  same "no membership" response whether or not the organization exists (no tenant enumeration).
* **Query scoping:** every service query includes `organization_id == principal.organization_id`.
* **Database enforcement:** tenant tables have composite foreign keys on `(id, organization_id)`, so
  a row cannot reference a row of another tenant even by mistake.
* **Row-level security:** enabled (deny-all) on every `dms.*` table, including those added by
  later migrations. The API role is the owner and enforces authorization in code; RLS is
  defense-in-depth against direct Supabase client/PostgREST access with an anon/authenticated key.
  Never expose the `dms` schema through PostgREST.
* **Object storage:** private bucket; keys are opaque (`<org>/<yyyy>/<mm>/<random>`), never derived
  from user input; the browser never receives a storage URL or key.
* **Chat:** conversations, runs, tool executions and pending actions are scoped by organization and
  owner; another user's conversation or action is indistinguishable from a missing one.
* **Verification:** `tests/security/test_tenant_isolation.py` plus per-feature cross-tenant
  assertions (file manager, chat, access requests, contract gaps).

Known limit: RLS policies for non-owner roles are not defined because no non-owner role is used;
if one is introduced, policies must be written and tested first.
