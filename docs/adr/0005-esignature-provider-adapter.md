# ADR 0005: E-signature through a provider adapter (Documenso)

**Status:** accepted

**Decision.** A `SignatureProvider` interface with a Documenso implementation (per
`docs/integrations/documenso-guide-original.txt`) and a fake provider with an HMAC-signed webhook
for tests. Reconciliation (polling provider state) is authoritative; webhooks only accelerate it.
The signed artifact is stored as a **new version** of the document. The signing link is
secret-equivalent: held in server state, returned only to the signer, never logged or put in
notifications. Production configuration rejects the fake provider and requires the webhook secret.

**Consequences.** Verified live against the deployed Documenso for create → sign → complete →
download; the webhook path on a public URL is **not** verified (no public callback in dev), which is
why reconciliation exists.
