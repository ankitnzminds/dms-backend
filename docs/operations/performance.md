# Performance

Measured with `scripts/load_test.py` on a laptop with the embedded PostgreSQL (not representative
of production hardware): concurrent upload → finalize → download cycles in one organization, plus
mixed listing/search traffic. The first run found an org-row lock-upgrade deadlock (HTTP 500s);
fixed with `FOR NO KEY UPDATE` and covered by
`test_uploads_versions::TestConcurrentUploadsDoNotDeadlock`.

Design points that matter at scale:

* Listings paginate server-side and compute permissions in batches; breadcrumbs for a page are
  computed in a fixed number of queries.
* Search uses PostgreSQL `tsvector` indexes (names and extracted text); the chatbot adds passage
  scoring in Python over at most 10 candidate documents.
* Uploads and downloads stream through the API; large files cost API bandwidth (ADR 0003).
* Agent runs call an external LLM (seconds to tens of seconds); they run in a small thread pool
  (4) so they do not block request workers. For load, move runs onto the outbox worker.

Not done: sustained soak test, production-sized dataset benchmarks, query plans under realistic
cardinalities. Re-run `scripts/load_test.py` after any change to locking or listing code.
