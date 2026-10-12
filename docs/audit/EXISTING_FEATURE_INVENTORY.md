# Existing feature inventory (audit of 2026-10-11)

Method: read-only source inspection (module, route, frontend page, test file). **"Test file exists" is not
"test passes".** The only executed baseline is in `IMPLEMENTATION_ROADMAP.md` §Baseline. Classes:
A implemented + test file · B implemented, incomplete/thinly tested · C partial · D frontend-only ·
E backend-only · F missing · G not verified. No feature was found in classes C–F; every inspected
frontend page has a backend module (judged by file presence, not by exercising each page).

Paths: BE `enterprise-dms-backend/app`, FE `enterprise-dms-frontend/src`, T backend `tests/`.

| Feature | Class | Evidence |
|---|---|---|
| Login, forgot/reset password | A | BE modules/identity, adapters/identity · FE (auth)/login, forgot-password, reset-password · T unit/test_local_password.py |
| Users / admin users | A | modules/users, admin_users · FE admin/users · T integration/test_admin_users.py |
| Organization management | B | modules/organizations · FE admin/settings · only security/test_tenant_isolation.py |
| RBAC + permission matrix | A | modules/authorization, permission_admin · T security/test_authorization_matrix.py, integration/test_permission_dashboards.py |
| Files / folders CRUD | A | modules/items, folders, documents · T test_file_manager.py, test_create_folder_permissions.py |
| Team folders | A | modules/folders/team.py · FE team-folders (no dedicated test name) |
| Uploads (chunked, scan gate) | A | modules/uploads · T test_uploads_versions.py |
| Downloads, zip | A | documents/downloads.py, folders/archive.py |
| Preview PDF / Office (WOPI) | A | modules/office · T test_office.py |
| Thumbnails | G | only a `has_thumbnail` flag found; generator not located |
| Versioning, diffs, restore version | A | modules/documents, diffs · T test_uploads_versions.py, test_version_diffs.py |
| File/folder permissions, inheritance | A | authorization/acl.py · T test_authorization_matrix.py |
| Groups | A | modules/groups · only indirectly tested (test_directory.py) |
| Internal sharing, invite, notifications | A | modules/sharing · T test_sharing_v3.py |
| External / public links | A | sharing/public.py · T test_sharing_v3.py |
| Shared with me / by me | A | api/v1/shares.py, library.py |
| Favorites / recent | B | api/v1/library.py · no dedicated favorites test |
| Recycle bin (user + admin) | A | modules/recycle · T test_recycle_bin.py, test_trash_search.py |
| Locking | A | documents/locks.py · T test_locks.py |
| Search | A | modules/search · T test_activity_auth_search.py |
| OCR / text extraction | B | modules/processing · OCR optional (`ocr_unavailable` when no binary) |
| Audit log + UI | A | modules/audit · FE admin/audit |
| Approval workflows | A | modules/workflows · T test_workflows.py |
| E-signatures (Documenso) | A | modules/signatures · live test needs external service |
| AI chat + retrieval | A | modules/chat, ai · T test_chat.py (~30), test_ai.py |
| Dashboards | B | FE dashboard, admin overview · no dedicated test |
| Notifications | B | modules/notifications · no dedicated backend test |
| Access requests | A | modules/access_requests · single-approver only |
| Settings policies (old `policies`) | B | modules/policies · 9 keys enforced, rest stored only |
| Rule policy engine (new) | A | modules/policy_engine · T test_policy_lifecycle.py, test_policy_enforcement.py, unit/test_policy_engine.py |
| Governance (retention, legal hold) | B | modules/governance · enforced on delete/purge only (see gap analysis) |
| Directory sync | A | modules/directory · T test_directory.py |
| Automations, metadata | A | modules/automations, metadata |
| Quarantine | B | adapters/malware · no backend test file |
| Storage / quota admin, reports | B | modules/quota, reports · no dedicated tests |
| Comments | A | modules/comments · T test_comments.py |
| Permission dashboards (admin + My access) | A | permission_admin, FE admin/permissions, my-access |
