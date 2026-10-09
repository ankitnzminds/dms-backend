# Entity relationships (core)

Columns are in the generated `data-dictionary.md`; this shows how the main tables relate. Every
tenant table also has `organization_id` with a composite FK back to the owning row.

```mermaid
erDiagram
  organizations ||--o{ memberships : has
  users ||--o{ memberships : joins
  organizations ||--o{ folders : owns
  folders ||--o{ folders : parent_of
  folders ||--o{ documents : contains
  documents ||--o{ document_versions : has
  document_versions ||--o| document_texts : extracted
  documents ||--o{ share_grants : shared_by
  share_grants ||--o{ share_recipients : to
  folders ||--o{ permission_grants : granted_on
  documents ||--o{ workflow_runs : reviewed_in
  workflow_definitions ||--o{ workflow_definition_versions : versions
  workflow_runs ||--o{ workflow_tasks : has
  documents ||--o{ signature_requests : signed_via
  chat_conversations ||--o{ chat_messages : has
  chat_conversations ||--o{ agent_runs : runs
  agent_runs ||--o{ tool_executions : audited
  chat_conversations ||--o{ pending_actions : proposes
  users ||--o{ access_requests : requests
  organizations ||--o{ outbox_events : queues
  organizations ||--o{ audit_events : records
```
