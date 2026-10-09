# ADR 0002: Union-of-sources authorization with non-disclosing 404

**Status:** accepted

**Context.** Access comes from roles, ownership, folder grants, shares and approver tasks. Shares
must never leak the surrounding tree, and unauthorized users must not learn what exists.

**Decision.** Effective actions are the union of all sources, computed server-side per request
(`AuthorizationService`). Folder grants inherit downward only; document shares are leaf-scoped.
Resources without `discover` return 404 (identical to missing); discoverable resources without the
requested action return 403. Breadcrumb segments carry `navigable`. Classifications listed in
`share_blocked_classifications` ignore share-derived access (DLP).

**Consequences.** Predictable, testable rules (see `authorization-model.md`). Every new feature must
call `require_*` rather than checking roles; the chatbot reuses exactly the same calls.
