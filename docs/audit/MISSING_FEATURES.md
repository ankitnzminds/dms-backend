# Missing or incomplete features (verified gaps only)

Everything not listed here was found implemented. See EXISTING_FEATURE_INVENTORY.md.

| Capability | State | Needed |
|---|---|---|
| Hold/retention on rename, move, version restore | Missing | Call governance checks on those paths (G1) |
| Storage reconciliation + dead-letter alerting | Missing | Orphan/missing-object sweep, alert on dead events, replay tool (G2) |
| Distributed login/request rate limiting | Weak | Shared store (Postgres/Redis) and IP-keyed pre-auth limits (G3) |
| Authentication audit | Missing | `auth.login_failed`, token failure events, throttled (G4) |
| Production config guard | Partial | Fail startup when production-like markers present but required env missing (G5) |
| Upload allowlist / per-type limits | Missing | Configurable allowlist + type-specific caps (G6) |
| REQUIRE_APPROVAL execution | Missing | Reuse workflows engine with a new subject type (access request / share) — approvals hold the operation, re-evaluate policy at grant time |
| Multi-step / parallel access-request approval | Missing | Same as above (existing workflow engine is document-bound) |
| External/guest user identity + invitations | Missing | Guest model + invitation flow (only an access level enum and public links exist) |
| MFA / step-up | Delegated | Document Supabase MFA, add `aal` claim check for admin actions (G9) |
| Audit retention/archival | Missing | Partitioning or export-then-archive job (G10) |
| Alerting, SLOs, incident runbook | Missing | Alert rules on denials, auth failures, dead events, scan backlog (G16) |
| Backups against the real hosting (Supabase DB + bucket) | Unverified | Procedure + a restore actually tested there (G7) |
| Policy: user-created (personal) policies, file picker, nested groups | Not built | Deliberately deferred; see roadmap |
| OCR out of the box | Optional | Configure an OCR binary in deployment |
| Semantic/vector search | Missing (P3) | Optional; lexical search works |
