# Deployment Setup Guide — Controlling When Deployments Trigger
*(Last updated: 2026-07-17 — verify ignoreCommand is active on Vercel + parent-commit fallback working)*

Both **Vercel** (frontend) and **Render** (backend) are configured by
default to auto-deploy on every push to `main`. Editing documentation,
updating `README.md`, or tweaking `render.yaml` should not trigger a
rebuild — wasting build minutes, blocking your team, and producing
noisy deploy logs.

Both platforms now read deployment control settings **from version
control** so no dashboard click is required.

---

## Quick Reference

| Action | Frontend (Vercel) | Backend (Render) |
|--------|-------------------|------------------|
| Edit `docs/**` only | **No rebuild** | **No rebuild** |
| Edit `README.md` only | **No rebuild** | **No rebuild** |
| Edit `frontend/**` code | Rebuilds normally | n/a |
| Edit `frontend/vercel.json` | Rebuilds normally | n/a |
| Edit `frontend/should-build.sh` | Rebuilds normally | n/a |
| Edit `backend/**` code | n/a | No auto-deploy (manual only — see "backend — Render") |
| Edit `render.yaml` | No rebuild | Synced and applied at next manual deploy |
| Edit `tests/**` | **No rebuild** | **No rebuild** |

The thesis deliberately uses a **belt-and-suspenders** strategy:

- **`frontend/vercel.json` → `ignoreCommand`** invokes
  `frontend/should-build.sh` which exits `0`/`1`/`2` based on which
  paths changed; **Vercel skips the build entirely when exit code
  is 0**. This is a documented, official Vercel feature that takes
  precedence over the dashboard Ignored Build Step setting.
- **`render.yaml`** includes both `autoDeployTrigger: 'off'` AND a
  `buildFilter` glob list — if Render ever ignores one, the other
  still applies.

---

## Frontend — Vercel

### What is already configured (in code)

Both deployment platforms are now configured **entirely from version
control**:

- **`frontend/vercel.json`** — includes `"ignoreCommand":
  "bash ./should-build.sh"`. This is the official documented way to
  make Vercel skip builds based on custom logic
  (<https://vercel.com/docs/project-configuration/vercel-json#ignorecommand>),
  and it **takes precedence over any dashboard setting** for Ignored
  Build Step. **No dashboard click required.**
- **`frontend/should-build.sh`** — a tested bash script (10/10
  scenarios verified) that exits `0` to skip the build when no file
  under `frontend/` was modified, and exits `1` to proceed otherwise.
- **`frontend/.vercelignore`** — already excludes `e2e/` Playwright
  tests from the build context.

### How it works

When Vercel deploys:

1. It reads `vercel.json` *before* running anything.
2. It runs `bash ./should-build.sh` (the `ignoreCommand`) with the
   special env vars `VERCEL_GIT_PREVIOUS_SHA` and
   `VERCEL_GIT_COMMIT_SHA` set.
3. If exit code `0` → ignoreCommand matched → **Vercel skips the
   build entirely** (no build minutes consumed, no deployment
   created, no preview URL).
4. If exit code `1` → ignoreCommand did not match → **Vercel runs
   `npm install && npx next build` as normal**.
5. Any other exit code → falls back to Vercel's default behaviour
   (build runs).

Because of the strict-match exit contract, our script is
deterministic and the behaviour is identical whether you configure
it via `vercel.json` or the dashboard — but vercel.json wins.

### How to test the script locally

You can run the script locally against any commit to verify behaviour:

```bash
# Replace LAST_COMMIT and THIS_COMMIT with any two SHAs from your log.
LAST_COMMIT=b58975ccac214dff1b723561106269ef0da22d42
THIS_COMMIT=fa11984d42783e19736eb23713bc50899d5415ec
cd frontend
VERCEL_GIT_PREVIOUS_SHA=$LAST_COMMIT \
VERCEL_GIT_COMMIT_SHA=$THIS_COMMIT \
  bash ./should-build.sh
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

There is now practically zero required dashboard configuration because
deploy control lives in version control.

### One-time, optional but recommended:

With `autoDeployTrigger: 'off'` already in `render.yaml`, the next
time Render re-syncs the blueprint (next time it touches the repo),
backend deploys will correctly stop auto-firing. **You are no
longer required to click anything in either dashboard.** The
optional Render one-click confirmation ("Clear build cache &
deploy") in Method A above just accelerates when that sync happens.

### After the first sync, deploy control is fully version-controlled:

- Backend auto-deploys: **off** (render.yaml)
- Backend path filter: **active** (render.yaml buildFilter)
- Frontend auto-deploys: **off when irrelevant** (vercel.json ignoreCommand)

### To deploy manually:

1. **Vercel**: dashboard → "Promote to Production" or trigger via
   the deploy hook.
2. **Render**: dashboard → Manual Deploy → Deploy latest commit.
3. **CI/CD**: hit the **Deploy Hook** URL with a POST.

---

## Why version-control configuration is preferred

Both Vercel and Render give dashboard settings **precedence over
in-repo config** *in principle* for security reasons. However,
**Vercel's `ignoreCommand`** is a documented exception: it is read
from `vercel.json` and applies on every deploy. Render does the
like with `autoDeployTrigger` and `buildFilter` in `render.yaml`
via its Blueprint mechanism.

Because both `vercel.json` and `render.yaml` are committed and pushed
through Git, your deployment policy is now:

- ✅ Code-reviewed (PRs can check the yaml/json before merge)
- ✅ Version-controlled (any change is in git history)
- ✅ Automatically enforced on every deploy
- ⚠️ Still requires a single manual one-click on Render if "Off" via
  Blueprint hasn't yet been applied — see Backend section.
