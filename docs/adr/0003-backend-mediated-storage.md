# ADR 0003: Backend-mediated uploads and downloads

**Status:** accepted

**Decision.** The browser never receives storage URLs or keys. Uploads are initiate → PUT bytes to
the API → finalize, with size/SHA-256 verification, magic-byte sniffing, blocked extensions and an
idempotent quota ledger. Downloads are short-lived signed tickets (JWT) that are re-authorized on
redemption and streamed through the API. Versions are immutable (trigger) and promoted only after a
clean malware scan.

**Consequences.** Every byte passes through the API (bandwidth/latency cost; see
`docs/operations/performance.md`), in exchange for uniform authorization, DLP and audit. Large-file
direct-to-storage uploads are a possible future optimization behind the same adapter interface.
