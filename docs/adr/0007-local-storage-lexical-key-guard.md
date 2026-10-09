# ADR 0007: Lexical object-key guard in the local storage provider

**Status:** accepted (bug fix)

**Context.** The development storage provider guarded against path traversal by comparing
`resolve()`d paths. Under concurrent uploads on Windows, resolving a not-yet-created path could
yield a different (short vs long name) prefix than the already-created bucket directory, so valid
keys were rejected intermittently ("invalid object key", surfaced as HTTP 503). Found when the
concurrent-upload regression test failed in full-suite runs.

**Decision.** Validate keys lexically (no empty/`.`/`..` segments, no absolute paths or drive
colons, no backslashes) and join under the resolved root. Keys are server-generated and opaque
anyway (`<org>/<yyyy>/<mm>/<random>`).

**Consequences.** Deterministic behaviour; traversal tests still pass (`tests/unit/test_adapters.py`).
Supabase storage is unaffected.
