# Implementation roadmap

## Baseline (executed, this machine)
- Backend full suite after the policy-engine tables and enforcement hook: **681 passed, 2 skipped** (live-service
  tests), run before the last small additions (templates, grammar endpoint, schema renames). A re-run was started
  afterwards; its result must be recorded before release.
- Targeted: policy unit tests 40 passed; policy lifecycle + enforcement + simulator integration 29 passed.
- Frontend: tsc and eslint clean; vitest had 1 failing test (Trash dialog text) caused by the earlier admin-controlled
  Recycle Bin change; the test was updated and its file passes (11/11). A complete vitest run after the latest changes
  was interrupted and is **not yet recorded**.

## Done
Permission dashboards (admin + My access) · policy engine (typed rules, lifecycle, immutability trigger, enforcement hook,
public-link fix, simulator, templates, builder UI) · docs/security/policy-engine.md.

## Next (ordered by priority, each: test first, smallest change, regression run)
| Order | Pri | Work | Depends on |
|---|---|---|---|
| 1 ✅ | P1 | G1 (done): enforce legal hold/retention on move, rename, version restore (+ tests, + clear denial reason) | – |
| 2 ✅ | P1 | G5 (done): production config guard (fail startup if production markers present but env incomplete) | – |
| 3 ✅ | P1 | G4 (done): audit failed logins / token failures (throttled) + metrics alerts doc | – |
| 4 | P1 | G3: shared-store, IP-keyed pre-auth rate limit | infra choice (Postgres table vs Redis) — needs approval |
| 5 ✅ | P1 | G2 (done, orphan detection excluded): reconciliation job + dead-letter alert + replay command | – |
| 6 | P2 | Approval execution: generalize workflow runs to a subject type; REQUIRE_APPROVAL for sharing and access requests (sequential/parallel) | design review |
| 7 | P2 | G6: upload allowlist + per-type caps (configurable, default = current behavior) | – |
| 8 | P2 | Backups on real hosting: bucket backup procedure + restore test | hosting access |
| 9 | P2 | External/guest users + invitations | product decision |
| 10 | P2 | G9/G10: admin step-up (`aal`), audit retention/archival | Supabase config |
| 11 | P3 | G13–G18 housekeeping; user-created policies; thumbnails check; DLP snippet masking in `/search` | – |

Gate for each item: unit/integration tests added, full backend suite and frontend vitest run and recorded,
migration diff test green, docs updated, no deployment or push without approval.
