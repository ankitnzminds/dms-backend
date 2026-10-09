# ADR 0001: Modular monolith, single `dms` schema, owner connection + RLS deny-all

**Status:** accepted

**Context.** Two repositories (frontend/backend) are required; the backend must be operable by a
small team on Supabase Postgres. Strong tenant consistency matters more than independent scaling.

**Decision.** One FastAPI process and one worker over a single PostgreSQL schema (`dms`). Modules
are packages with explicit service functions. The API connects as the table owner and enforces
authorization in code; RLS is enabled with no permissive policies so Supabase client/PostgREST
access with anon or authenticated keys cannot read anything. Tenant consistency is enforced with
composite foreign keys.

**Consequences.** Simple transactions across modules (e.g. share + audit + outbox). A bug in the
service layer is the only barrier for API access, so authorization tests are broad (matrix,
tenant isolation, sharing acceptance, mutation checks). Splitting into services later is possible
along module lines. If a non-owner DB role is ever used, RLS policies must be written and tested.
