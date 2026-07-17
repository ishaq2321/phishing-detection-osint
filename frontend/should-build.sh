#!/usr/bin/env bash
# =============================================================================
# should-build.sh
# =============================================================================
# Used by Vercel's "Ignored Build Step" feature (configurable via the
# ignoreCommand field in vercel.json).
#
# This script determines whether a Vercel build should proceed based on
# which files changed in the latest commit. By default, Vercel builds on
# every push to the configured branch. This script suppresses builds when
# only non-frontend files (backend, docs/, README.md, render.yaml) changed.
#
# Configure via vercel.json's ignoreCommand:
#     "ignoreCommand": "bash ./should-build.sh"
#
# Exit contract (Vercel-mandated):
#   - 0  → SKIP the build (matched the ignore rule)
#   - 1  → PROCEED with the build (no rule matched)
#   - 2  → ALSO PROCEED (Vercel falls back to building too)
#
# Reference:
#   https://vercel.com/docs/project-configuration/vercel-json#ignorecommand
# =============================================================================

set -uo pipefail  # note: no -e, because we use grep -q which exits 1 on miss

# ---------------------------------------------------------------------------
# Step 1: Identify the "current" commit SHA.
#
# We prefer VERCEL_GIT_COMMIT_SHA when set (Vercel-provided), but fall back to
# HEAD if not — for local debugging.
# ---------------------------------------------------------------------------
if [ -n "${VERCEL_GIT_COMMIT_SHA:-}" ]; then
  CURR_SHA="${VERCEL_GIT_COMMIT_SHA}"
elif git rev-parse HEAD > /dev/null 2>&1; then
  CURR_SHA=$(git rev-parse HEAD)
else
  echo "Cannot determine current commit SHA. Proceeding with build (fail-safe)."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Identify the "previous" commit SHA.
#
# VERCEL_GIT_PREVIOUS_SHA is the documented way, but it has known issues
# (https://community.vercel.com/t/vercel-git-previous-sha-is-always-empty/39835).
# We therefore fall back to git's own notion of the parent commit. This means
# we always know what the "previous" commit is, even if Vercel's variable is
# blank.
#
# As an extra safeguard: if VERCEL_GIT_PREVIOUS_SHA is set we use it
# (because that is the SHA Vercel considers "previously deployed",
# which may not be HEAD~1 if there were force-pushes), but if it's
# missing we fall back to HEAD~1.
# ---------------------------------------------------------------------------
if [ -n "${VERCEL_GIT_PREVIOUS_SHA:-}" ]; then
  PREV_SHA="${VERCEL_GIT_PREVIOUS_SHA}"
elif git rev-parse "${CURR_SHA}^" > /dev/null 2>&1; then
  PREV_SHA="${CURR_SHA}^"
  echo "VERCEL_GIT_PREVIOUS_SHA not set; using parent commit ${PREV_SHA} as fallback."
else
  echo "Cannot determine previous commit SHA (no VERCEL_GIT_PREVIOUS_SHA and no parent). Proceeding with build (fail-safe)."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: List the paths that SHOULD trigger a build.
#
# If any changed file matches one of these patterns, we build. Otherwise we
# skip. The patterns cover the 'frontend/' project at the repo root, which
# is the directory Vercel is configured to deploy from.
# ---------------------------------------------------------------------------
FRONTEND_PATHS=(
  '^frontend/?$'        # a `.` or empty inside frontend/
  '^frontend/'           # anything nested inside frontend/
)

# ---------------------------------------------------------------------------
# Step 4: Collect changed files via git diff.
# ---------------------------------------------------------------------------
mapfile -t CHANGED_FILES < <(git diff --name-only "$PREV_SHA" "$CURR_SHA" 2>/dev/null || true)

if [ "${#CHANGED_FILES[@]}" -eq 0 ]; then
  # No changes detected (very rare in production). Build anyway to be safe.
  echo "No changed files detected between $PREV_SHA..$CURR_SHA. Proceeding with build."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 5: Decide.
# ---------------------------------------------------------------------------
for file in "${CHANGED_FILES[@]}"; do
  for pattern in "${FRONTEND_PATHS[@]}"; do
    if [[ "${file}" =~ ${pattern} ]]; then
      echo "Changed file '${file}' is inside the frontend project. Proceeding with build."
      exit 1
    fi
  done
done

# Only non-frontend files were changed — skip the build entirely.
PRETTY=$(printf '  - %s\n' "${CHANGED_FILES[@]}")
echo "No frontend files changed between $PREV_SHA and $CURR_SHA. The following files were modified:"
echo "$PRETTY"
echo "Skipping Vercel build (exit 0)."
exit 0
