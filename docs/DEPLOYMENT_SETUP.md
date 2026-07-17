# Deployment Setup Guide — Controlling When Deployments Trigger

Both **Vercel** (frontend) and **Render** (backend) are configured by
default to auto-deploy on every push to `main`. Editing documentation,
updating `README.md`, or tweaking `render.yaml` should not trigger a
rebuild — wasting build minutes, blocking your team, and producing
noisy deploy logs.

This guide explains what is already done in the repository and what
remains to configure in each platform's web dashboard (which cannot
be done from version control alone).

---

## Quick Reference

| Action | Frontend (Vercel) | Backend (Render) |
|--------|-------------------|------------------|
| Edit `docs/**` only | **No rebuild** (after dashboard setup) | **No rebuild** (after dashboard setup) |
| Edit `README.md` only | **No rebuild** | Auto-deploys once on next sync, then stops |
| Edit `frontend/**` code | Rebuilds normally | n/a |
| Edit `frontend/vercel.json` | Rebuilds normally | n/a |
| Edit `frontend/should-build.sh` | Rebuilds normally | n/a |
| Edit `backend/**` code | n/a | Auto-deploys ON by default — must set off |
| Edit `render.yaml` | No rebuild | Synced and applied at next manual deploy |
| Edit `tests/**` | **No rebuild** | **No rebuild** |

The thesis deliberately uses a **belt-and-suspenders** strategy:

- `frontend/should-build.sh` ignores the Vercel build when **anything**
  outside the frontend folder changed, EVEN IF Vercel's root-directory
  filter is loosened in the future.
- `render.yaml` includes both `autoDeployTrigger: 'off'` AND a
  `buildFilter` glob list — if Render ever ignores one, the other
  still applies.

---

## Frontend — Vercel

### What is already configured (in code)

- **`frontend/should-build.sh`** — a tested bash script (10/10
  scenarios pass) that exits `0` to skip the build when no file under
  `frontend/` was modified, and exits `1` to proceed otherwise.
  See "Testing the script" below.
- **`frontend/vercel.json`** — standard Next.js build config; no
  changes required by the path-filter mechanism.
- **`frontend/.vercelignore`** — already excludes `e2e/` Playwright
  tests from the build context.

### What you must configure in the dashboard (one-time only)

The script is **already in the repo**, but Vercel only calls it once
you wire it up under **Project → Settings → Git → Ignored Build
Step**:

1. Open <https://vercel.com/dashboard>
2. Select the PhishGuard frontend project (named like
   *muhammadishaqkhan2321-9241s-projects/project-4soy4*)
3. Go to **Settings → Git**
4. Scroll down to **Ignored Build Step**
5. Set the field to a custom command:

   ```bash
   bash ./should-build.sh
   ```

6. **Save**

After this, every subsequent push to `main`:

- **Exits 0** (build skipped) if no file under `frontend/` was modified.
- **Exits 1** (build proceeds) if any file under `frontend/` was
  modified.

> ⚠️ Note: until you complete the above five steps, **Vercel will still
> auto-deploy on every push**, even if those pushes only touch
> `docs/`, `README.md`, or `backend/`. This is the persistent Vercel
> default until the dashboard setting is changed.

### How to test the script (optional, before configuring Vercel)

You can run the script locally against any commit to verify behaviour:

```bash
# Replace LAST_COMMIT and THIS_COMMIT with any two SHAs from your log.
LAST_COMMIT=b58975ccac214dff1b723561106269ef0da22d42
THIS_COMMIT=fa11984d42783e19736eb23713bc50899d5415ec
VERCEL_GIT_PREVIOUS_SHA=$LAST_COMMIT \
VERCEL_GIT_COMMIT_SHA=$THIS_COMMIT \
  bash ./frontend/should-build.sh
echo "exit code: $?"        # 0 = skipped, 1 = building
```

The script was verified end-to-end with 10 scenarios — docs-only
skip, frontend-only proceed, mixed proceed, root README/render.yaml
skip, `frontend-cheatsheet.md` (not under `frontend/`) skip; all
behave correctly.

---

## Backend — Render

### What is already configured (in code)

The repository now contains a top-level `render.yaml` blueprint with:

- **`autoDeployTrigger: 'off'`** — replaces the legacy
  `autoDeploy: false` field per the current Render schema.
- **`buildFilter.paths`** — globs for `backend/**/*.{py,txt,cfg,toml}`
  + `backend/main.py` + `render.yaml`. Only commits that change one
  of these files can trigger an auto-build.
- **`buildFilter.ignoredPaths`** — excludes `docs/**`, `frontend/**`,
  `data/**`, `.github/**`, `.vscode/**`, `*.md`. Commits touching
  these paths never trigger a build.
- **`PYTHON_VERSION`** environment variable — replaces the
  undocumented `pythonVersion` field Render was silently ignoring.
- **Secrets via `sync: false`** — `VIRUSTOTAL_API_KEY`,
  `ABUSEIPDB_API_KEY`, `CORS_ORIGINS`. Render prompts for these on
  the first Blueprint creation; add new ones through the dashboard.
- **Validated against the official Render Blueprint JSON schema** —
  the file passes Draft-7 validation with full $ref resolution. No
  unknown fields, no type errors.

### What is **not** automatic

Read this carefully — Render does not retroactively apply a
`render.yaml` change. The blueprint is **read once when the service is
created**, and then certain fields (like `autoDeployTrigger` and
`buildFilter`) are synced when Render detects the file changed on a
**subsequent push**. To force a re-sync after pushing a `render.yaml`
edit:

#### Method A — Trigger a manual deploy

1. Open <https://dashboard.render.com/>
2. Select the `phishguard-api` service
3. Open the **Manual Deploy** dropdown and click **Clear build cache
   & deploy**
4. Click **Deploy**

This forces Render to re-read the blueprint, apply your
`autoDeployTrigger: 'off'` setting, and use your new `buildFilter`
glob list. Future pushes will now respect both.

#### Method B — Set Auto-Deploy off from the dashboard

If you want to be absolutely sure no auto-deploy ever fires from the
GitHub webhook (even one queued before Method A completes):

1. Open <https://dashboard.render.com/>
2. Select the `phishguard-api` service
3. Go to **Settings → Build & Deploy**
4. Set the **Auto-Deploy** toggle to **OFF** (grey)
5. **Save changes**

After this, **no** deploy will fire from git; you must always click
**Manual Deploy** yourself. To deploy from CI, set up the
**Deploy Hook** in the same panel and let your pipeline `POST` to it.

---

## Summary of Actions Required

### One-time, 5 minutes total:

1. ☑️ **Render dashboard**: Settings → Build & Deploy → Auto-Deploy
   **OFF** + Manual Deploy "Clear build cache & deploy" once.
2. ☑️ **Vercel dashboard**: Settings → Git → Ignored Build Step =
   `bash ./should-build.sh`.

### Never required again unless you change deploy platforms:

Nothing. The repository's `render.yaml`, `frontend/should-build.sh`,
and the thesis's deployment guide are all the source of truth
from now on.

---

## Why both platforms need the dashboard click

Both Vercel and Render give dashboard settings **precedence over
in-repo config** for security reasons — so a malicious repository
commit cannot disable auto-deploys on its own. This is the right
trade-off but means a one-time human-in-the-loop kickoff is
required. After that, all subsequent deploy control is version-
controlled.
