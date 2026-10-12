# v3 addendum: folder hover, context menu, Team Folders, sharing and permissions

Source: `Enterprise_DMS_Complete_Implementation_Plan_v3_Folder_Hover_Context_Menu_Sharing_Permissions.docx`.

**Parity statement.** Behaviour and information architecture follow the addendum. Pixel-identical visual
parity is **not** claimed: no reference screenshots were available, so layout, spacing and icons follow this
product's existing design system.

Status values: **Done** (implemented and exercised), **Partial** (works with a stated limit), **Not possible** (needs
something this deployment does not have).

| Requirement | Status | Where / notes |
| --- | --- | --- |
| Hover toolbar (Share, Download, Rename, Copy, Move, Delete, Permissions, overflow); no layout shift; keyboard reachable | Done | `components/explorer/hover-toolbar.tsx`; absolutely positioned, same handlers as the context menu, disabled buttons keep a reason tooltip |
| Existing actions/menu items not removed or renamed | Done | `buildMenu` kept; entries only added (colour tag, Download as PDF, folder ZIP) |
| Team Folders page (breadcrumb, count, Add Files and Folders, refresh, filter, sortable columns, row actions) | Done | `/team-folders`, `features/team-folders/*`; backend `GET /team-folders`, `PUT /admin/team-folders/{id}` (administrators, top-level folders only, audited) |
| Team Folders grant nothing | Done | listing is filtered by `discover`; marking changes only where a folder is listed |
| Share Link dialog: link field, Modify Link (on/off/new link), copy, open, email | Done | `components/sharing/share-link-dialog.tsx`; token stored as SHA-256 hash plus encrypted copy so managers can re-display it |
| Share Options: name, owner, expiry, upload quota, email notifications, who can use it | Done | `share_grants` columns + `PATCH /shares/{id}`; owner change, quota enforced at upload initiate and charged at finalize |
| Share History tab | Done | `GET /shares/{id}/history` from the audit trail; link copy/open/email events are client-reported by managers |
| Invite Users / Add Group / per-recipient matrix (view, download, upload, share, sync, delete, manage) | Done | recipient `actions` override the share default (`coalesce(recipient.actions, share.actions)`) |
| Sync permission | Partial | stored and returned; no sync client exists, so it has no runtime effect |
| Everyone / organization-wide link | Done | recipient type `organization`; signed-in members who open the link are added |
| External identities (EXTERNALS group) | Not possible | no external identity model; not offered |
| Anonymous public link | Partial | off by default; enabled per organization by `allow_public_links`; read-only, IP rate limited, never upload/change/delete |
| Email with link | Partial | sent only when an email provider is configured; the email carries no link token by design |
| `/s/{token}` landing | Done | signed-in: resolve then open the item; otherwise public read-only page or one neutral "not valid" message |
| Manage Folder Permissions: Security tab (read, write, share, delete, manage), Add Users / Add Group | Done | `components/sharing/folder-permissions-dialog.tsx`; label matrix maps to the real action sets |
| Inherit Folder Level Security + inherited permissions preview | Done | `folders.inherit_acl`; turning it off stops ancestor grants applying (preview endpoint shows what would be lost) |
| Check Access tab | Done | `POST /resources/{kind}/{id}/check-access`; same evaluation as request authorization, shows the contributing grants |
| ACL model: union of grants, no explicit deny, non-disclosing 404 | Done | unchanged core authorization; new matrix is a view over it |
| Folder Download as ZIP | Done | per-file authorization, 2000 file / 500 MB cap, audited |
| Audit for every change | Done | `share.*`, `permission.granted/updated/revoked/inheritance_changed`, `access.checked`, `folder.team_folder_changed` |
| Copy of a folder from the legacy item menu | Partial | still disabled there with a reason; Explorer copy-to uses the bulk API |

## Verification

- Backend: `tests/integration/test_sharing_v3.py` plus the full suite (see `implementation-status.md`).
- Browser (development stack, alice owner): Team Folders add/list; Share dialog open, invite Bob, toggle Download, turn
  link on, `/s/<token>` as a signed-in user opens the folder and as an anonymous user shows the neutral message
  (public links off); Permissions dialog add Carol, toggle Write, Check Access reports Carol's grants; hover toolbar
  lists all actions. Screenshots under the frontend `docs/screenshots/`.
- Not verified: any other browser than Chromium, mobile layout of the new dialogs, email delivery.
