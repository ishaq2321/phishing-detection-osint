# Deployment Setup Guide — Controlling When Deployments Trigger

Both **Vercel** (frontend) and **Render** (backend) are configured by
default to auto-deploy on every push to `main`. This means that editing
documentation in `docs/`, updating the `README.md`, or any other
non-code commit would still trigger a rebuild — wasting build minutes
and producing noisy deploy logs.

This guide explains how to guarantee that deployments only happen **when
you want them to**.

---

## Render (backend) — `render.yaml`

The repository now contains a top-level `render.yaml` blueprint with
`autoDeploy: false`. This means Render will **not** deploy
automatically on any git push. Deployments must be triggered manually
from one of the following:

### Option A — Manual trigger from Render dashboard

1. Open <https://dashboard.render.com/>
2. Select the `phishguard-api` service
3. Click **Manual Deploy → Deploy latest commit**

Use this when you want to ship a backend change.

### Option B — Render Deploy Hook (optional)

1. In Render dashboard → `phishguard-api` → **Settings → Deploy Hook**
2. Copy the unique URL
3. Trigger a deploy with `curl -X POST <deploy-hook-url>` from your
   terminal or CI pipeline

### Option C — Re-enable auto-deploy temporarily

If you want auto-deploys back *just for this branch*, edit `render.yaml`:

```yaml
autoDeploy: true
```

and commit. Or set it per-branch in the Render dashboard under
**Settings → Auto-Deploy**.

### First-time setup

If this is the first time you are connecting Render to the repo:

1. Render dashboard → **New → Blueprint**
2. Connect the GitHub repo
3. Render will read `render.yaml` and create the `phishguard-api` service
4. Set secrets in **Environment**:
   - `VIRUSTOTAL_API_KEY` (optional)
   - `ABUSEIPDB_API_KEY` (optional)
   - `CORS_ORIGINS` → `https://<your-vercel-domain>.vercel.app`
5. Confirm that **Auto-Deploy** is **off** (the blueprint sets it to
   false automatically)

---

## Vercel (frontend) — `should-build.sh`

Because "frontend/" is the Vercel project root directory, changes to
files outside that directory (such as `backend/`, `docs/`, or
`README.md`) **do not** trigger a frontend rebuild in the standard
configuration. However, to make this guarantee explicit and to cover any
future configuration changes, a `frontend/should-build.sh` script is
provided.

### One-time Vercel dashboard configuration

1. Open <https://vercel.com/dashboard>
2. Select the PhishGuard frontend project
3. **Settings → Git → Ignored Build Step**
4. Set the field to:

   ```text
   bash ./should-build.sh
   ```

5. Save

### What the script does

`should-build.sh` inspects the files changed between the previous and
current commit SHAs (provided by Vercel as environment variables). If
**every** changed file falls *outside* the frontend project — e.g.
`docs/`, `backend/`, `*.md` at repo root, `render.yaml` — the script
exits `0`, causing Vercel to **skip the build**. If **any** changed
file falls inside the frontend project (`frontend/src/*`,
`frontend/package.json`, etc.), the script exits `1` and Vercel
proceeds normally.

### Customizing paths

If you add a new directory under `frontend/` that should also count as
a frontend change, edit the `FRONTEND_PATHS` array in
`should-build.sh`.

---

## `.vercelignore`

The `.vercelignore` file already excludes:

- `e2e/` (Playwright tests — slow and not needed at build time)

Do **not** add `docs/` to `.vercelignore` — Vercel only looks inside the
configured project root (`frontend/`), so `docs/` is already excluded
in practice.

---

## Summary

| Action | Frontend (Vercel) | Backend (Render) |
|--------|-------------------|------------------|
| Edit `docs/` only | **No rebuild** (script exits 0) | **No rebuild** (autoDeploy: false) |
| Edit `README.md` only | **No rebuild** | **No rebuild** |
| Edit `frontend/` code | Rebuilds normally | n/a |
| Edit `backend/` code | n/a | Auto-deploy OFF — trigger manually |
| Edit `render.yaml` | No rebuild | **No rebuild** — applied next manual deploy |
| Edit `frontend/vercel.json` | Rebuilds normally | No rebuild |

This gives you total control: code changes to backend never auto-deploy,
code changes to frontend only deploy when files inside `frontend/`
changed, and explicitly pure-docs commits are entirely silent.
