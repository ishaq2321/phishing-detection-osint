#!/usr/bin/env bash
# =============================================================================
# should-build.sh
# =============================================================================
# Used by Vercel's "Ignored Build Step" (vercel.json → ignoreCommand).
#
# Exit contract (Vercel-mandated):
#   0 → SKIP the build
#   1 → PROCEED with the build
#
# HISTORY / LESSONS LEARNED (2026-08):
#   The original version fell back to HEAD~1 when VERCEL_GIT_PREVIOUS_SHA
#   was unset. That made every multi-commit push whose TIP commit touched
#   only non-frontend files look skippable — even when an earlier commit in
#   the same push had modified frontend/ — so frontend features silently
#   never deployed and production drifted months behind main.
#
#   New contract, correctness over build-minutes:
#     1. If VERCEL_GIT_PREVIOUS_SHA is set AND is a true ancestor of the
#        current commit → build iff the whole range touched frontend/.
#     2. In EVERY other case (missing SHA, shallow clone, force-push,
#        anything unexpected) → BUILD. Fail-safe means "build".
#
#   SECOND INCIDENT (2026-08, later same day): the range diff used the
#   pathspec `-- frontend/`, but Vercel executes ignoreCommand with CWD
#   set to the project Root Directory (frontend/). Git pathspecs are
#   CWD-relative, so the script was really diffing frontend/frontend/
#   — always empty — and silently skipping EVERY push. The fail-safe
#   never fired because `git diff` itself succeeded. Lesson: the
#   pathspec must be CWD-aware, and a failing diff must BUILD, never
#   skip. Both fixed below; verified against all four real push ranges.
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Current commit (Vercel-provided, local-debug fallback)
# ---------------------------------------------------------------------------
if [ -n "${VERCEL_GIT_COMMIT_SHA:-}" ]; then
  CURR_SHA="${VERCEL_GIT_COMMIT_SHA}"
elif git rev-parse HEAD > /dev/null 2>&1; then
  CURR_SHA="$(git rev-parse HEAD)"
else
  echo "No commit SHA determinable. Fail-safe: build."
  exit 1
fi

# ---------------------------------------------------------------------------
# Baseline: ONLY trust VERCEL_GIT_PREVIOUS_SHA when it is genuinely an
# ancestor of the current commit. No parent-commit fallback — see header.
# ---------------------------------------------------------------------------
BASE_VALID=0
if [ -n "${VERCEL_GIT_PREVIOUS_SHA:-}" ]; then
  if git merge-base --is-ancestor "${VERCEL_GIT_PREVIOUS_SHA}" "${CURR_SHA}" > /dev/null 2>&1 \
     && [ "${VERCEL_GIT_PREVIOUS_SHA}" != "${CURR_SHA}" ]; then
    BASE="${VERCEL_GIT_PREVIOUS_SHA}"
    BASE_VALID=1
  else
    echo "VERCEL_GIT_PREVIOUS_SHA '${VERCEL_GIT_PREVIOUS_SHA}' is not a proper ancestor. Fail-safe: build."
  fi
else
  echo "VERCEL_GIT_PREVIOUS_SHA not set. Fail-safe: build."
fi

if [ "${BASE_VALID}" -ne 1 ]; then
  exit 1
fi

# ---------------------------------------------------------------------------
# Range diff limited to the frontend project. A path-limited diff over the
# full range captures frontend changes from ALL commits in the push, not
# just the tip — the flaw that caused the stale-production incident.
#
# CWD-awareness: Vercel runs this script from the project Root Directory
# (frontend/), and git pathspecs are relative to CWD. From frontend/ the
# correct pathspec is "."; from the repo root it is "frontend/".
# ---------------------------------------------------------------------------
if [ "$(basename "$PWD")" = "frontend" ]; then
  PATHSPEC="."
else
  PATHSPEC="frontend/"
fi

CHANGED="$(git diff --name-only "${BASE}" "${CURR_SHA}" -- "${PATHSPEC}" 2>/dev/null)"
if [ $? -ne 0 ]; then
  echo "git diff failed for range ${BASE}..${CURR_SHA}. Fail-safe: build."
  exit 1
fi

if [ -n "${CHANGED}" ]; then
  echo "Frontend files changed between ${BASE} and ${CURR_SHA}:"
  printf '  - %s\n' ${CHANGED} | head -20
  echo "Proceeding with build."
  exit 1
fi

echo "No frontend changes in range ${BASE}..${CURR_SHA}. Skipping build."
exit 0
