# Chatbot security

Implements the controls in the *Advanced Agentic Chatbot* guide. Every statement below names the
code that enforces it and the test that proves it (`tests/integration/test_chat.py` unless noted).

| Control | Enforcement | Test |
|---|---|---|
| The model never authorizes | tools call the normal services (`AuthorizationService`); the model supplies only typed arguments | `test_prompt_injection_in_a_document_cannot_trigger_actions` |
| Authorize **before** content reaches the model | `chat/retrieval.py`: candidates from permission-filtered search, `PREVIEW` + DLP classification checked, only then text is loaded | `test_unauthorized_document_text_never_reaches_the_model`, `test_dlp_classified_documents_are_not_sent_to_the_model` (the fake model records everything it is sent) |
| Search snippets filtered | snippets only for documents with `PREVIEW`; blocked classifications dropped | `test_search_snippets_are_permission_filtered` |
| Untrusted text | system prompt + `<document>` data framing; tool output flagged as untrusted; no tool takes free-form instructions | injection test above |
| Typed, allowlisted tools only | `chat/tools.py` registry, Pydantic `extra="forbid"`, unknown tools rejected, no SQL/shell/HTTP tool | `test_tool_argument_tampering_and_unknown_tools_are_rejected` |
| Identity never from the model | tool args cannot carry user/org; principal rebuilt from the database for each run (`identity.principal_for`) | tampering test |
| Writes are proposals | write tools create a `pending_actions` row and return "awaiting confirmation"; nothing executes | `test_even_permitted_writes_are_only_proposals` |
| Confirmation bound to the exact payload | confirm requires the preview's SHA-256 over `{type, payload, user, org}`; mismatch → `action_mismatch`; stored payload re-hashed | `test_confirmation_is_hash_bound_single_use_and_executes_via_real_services` |
| Single use, expiring | row lock + status transition `pending→confirmed` before executing; TTL `AGENT_ACTION_TTL_MINUTES` | same + `test_expired_cancelled_and_stale_actions_cannot_run` |
| Stale targets | row-version fingerprints captured in the preview; changed/removed targets → `action_stale`, status `invalidated` | stale case in the test above |
| Re-authorization at execution | executors call the same services (which check permissions again); failure marks the action `failed` and returns 403/404 | `test_authorization_is_rechecked_at_execution_time` |
| Access requests grant nothing | `access_requests` records only; decision needs `MANAGE_ACCESS`, never the requester; grant via `acl.add_grant` (no escalation) | `test_access_request_via_chat_...`, `test_access_request_rules`, `test_approver_cannot_grant_what_they_do_not_hold` |
| Sharing intelligence is disclosure-controlled | `get_sharing_summary` needs `SHARE` (and `MANAGE_ACCESS` for ACL); otherwise "withheld" | `test_sharing_details_are_disclosed_only_to_those_allowed` |
| Revocation | history is re-filtered against *current* access (`chat/visibility.py`): guarded messages become `redacted`, citations lose names/routes, and redacted messages are never replayed to the model | `test_revocation_hides_history_and_it_is_never_replayed_to_the_model` |
| Citations are real | only `[S#]` refs retrieved in the same run survive; others are stripped; no storage keys | `test_fabricated_citations_are_stripped` |
| Conversation privacy | owner + tenant scoping; 404 otherwise | `test_conversations_are_private_to_their_owner_and_tenant` |
| Bounded agent | max steps / tool calls / runtime / bulk items; one active run per conversation | `test_step_budget_is_enforced`, `test_item_limit_is_enforced`, `test_only_one_run_at_a_time_and_cancel_is_safe` |
| Fail closed on outage | model error → run `failed`, no pending action, no side effect | `test_model_outage_fails_closed_without_side_effects` |
| Admin insights scoped | tool listed and allowed only for admins/auditors | `test_admin_insights_are_scoped_to_privileged_roles` |
| Audit | `tool_executions` (args **hash** only, decision, reason), `chat.*` audit events; no prompts/answers/document text logged | assertions in lifecycle tests |

## Known limits (be honest about them)

* A model can still write a misleading *sentence* about permitted data; citations and server-built
  cards (not model prose) are the source of truth. The system prompt forbids claiming unconfirmed
  actions, but that is a mitigation, not a guarantee; the action card status is authoritative.
* Retrieval is keyword/full-text (PostgreSQL) plus passage scoring. **Semantic/vector search is not
  implemented**; no embeddings are stored.
* Page-level citations are not available: citations point to document, version and chunk number.
* "Streaming" is run polling (status steps), not token streaming.
* Text sent to the model leaves the system boundary (Groq). DLP-blocked classifications are
  excluded; an org-level opt-out switch for AI is **not** implemented yet.
* Groq free-tier token limits (8k TPM observed) make multi-step runs slow (bounded retry on 429).
* Evaluation of model quality (tool selection, hallucination rate) has only a smoke test
  (`test_chat_live.py`); there is no systematic eval suite yet.
