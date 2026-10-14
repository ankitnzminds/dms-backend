# Deploying the backend on Render

[`render.yaml`](../../render.yaml) defines everything the backend needs. Every service tracks `main`
and **redeploys automatically on each push or merge to `main`** (`autoDeploy: true`).

| Resource | Type | Purpose | Plan (approx.) |
|---|---|---|---|
| `dms-db` | Postgres 17 | application database, private (no public access) | basic-256mb (~$6/mo) |
| `dms-clamav` | private service | ClamAV virus scanner (`deploy/clamav/Dockerfile`) | standard, 2 GB (~$25/mo) |
| `dms-api` | web service | FastAPI; runs `python -m app.cli migrate` before each release | starter (~$7/mo) |
| `dms-worker` | background worker | scans, text extraction / OCR, notifications, workflows | starter (~$7/mo) |

Total about **$45/month**. There is no free tier path: workers and private services are not free, a free
Postgres expires after 30 days, and the free web tier sleeps. Plans are in `render.yaml`; change them there.

## Why Supabase and ClamAV are required

The app refuses to start in `APP_ENV=production` with development settings (`app/core/config.py`):
local sign-in, local file storage, fake providers and a missing malware scanner are all rejected. So a
public deployment needs:

- a **Supabase project** for sign-in and a **private** storage bucket (`dms-private`), and
- **ClamAV**, which the Blueprint provisions for you.

The Supabase live paths are described as not yet verified in `docs/requirements/implementation-status.md`:
test sign-in, upload, download and delete on a staging deployment before relying on it.

## One-time setup

1. **Supabase:** create a project; create a **private** Storage bucket named `dms-private`; note the project
   URL, the publishable key and the service-role key (server only). Under Authentication > URL
   configuration, add the web app URL once you have it.
2. **GitHub:** push this repo (Render needs GitHub, GitLab.com or Bitbucket; a self-hosted GitLab is not
   supported).
3. Render dashboard > **New > Blueprint** > this repo > branch `main`. Render asks for the `sync: false` values:

   | Variable | Value |
   |---|---|
   | `SUPABASE_URL` | `https://<project-ref>.supabase.co` |
   | `SUPABASE_SERVICE_ROLE_KEY` | service-role key (**secret**) |
   | `GEMINI_API_KEY` | your Gemini key (**secret**); chat and OCR of scanned files |
   | `PUBLIC_API_BASE_URL` | the API's public URL, e.g. `https://dms-api.onrender.com` (no `/api/v1`) |
   | `CORS_ALLOWED_ORIGINS` | the web app URL, e.g. `https://dms-web.onrender.com` (no trailing slash) |
   | `WEB_BASE_URL` | the same web app URL |

   The API and the worker both ask for these; enter the same values for each. If you do not know the final
   URLs yet, put the expected ones and fix them after the first deploy, then redeploy.
4. **Apply.** The first run builds three images, the scanner downloads its signatures (a few minutes), and
   the API applies the database migrations before going live.
5. **Create the first organization** (Render shell on `dms-api`):

   ```
   python -m app.cli bootstrap-org --name "Your Company" --slug your-company --owner-email you@company.com
   ```

   The owner must also exist as a user in your Supabase project (same e-mail).
6. Deploy the web app Blueprint from the frontend repo (`docs/deploy-render.md` there).

## How releases work

- Merge or push to `main` on GitHub: Render rebuilds the changed services and redeploys them.
- Before the API switches over, `preDeployCommand` runs the Alembic migrations. If a migration fails, the
  deploy fails and the previous version keeps serving. Remove `preDeployCommand` from `render.yaml` if you
  prefer to apply migrations by hand (the README treats applying migrations to a database as a reviewed
  step).
- To deploy only after CI passes, change `autoDeploy: true` to `autoDeployTrigger: checksPass`.
- Pushing only to GitLab does not trigger Render. Mirror GitLab to GitHub, or call each service's
  *Deploy Hook* URL from a GitLab CI job on `main`.

## Not included

- **Office viewer/editor (Collabora):** off (`COLLABORA_URL` empty). PDFs, images and text work without it.
- **E-signature (Documenso)** and **e-mail:** off by default; set the variables in `.env.example` to enable.
- A **custom domain** and TLS: add them on the `dms-api` / `dms-web` services, then update the URL variables.
