#!/usr/bin/env bash
# =============================================================================
# should-build.sh
# =============================================================================
# Used by Vercel's "Ignored Build Step" feature.
#
# This script determines whether a Vercel build should proceed based on
# which files changed in the latest commit(s). By default, Vercel builds on
# every push to the configured branch. This script lets us suppress builds
# when only non-frontend files (backend, docs, README) have changed.
#
# Usage in Vercel dashboard:
#   Project Settings → Git → Ignored Build Step → Custom:
#     bash ./should-build.sh
#
# The script must exit:
#   - 0  → SKIP the build
#   - 1  → PROCEED with the build
#
# Key insight: Because "frontend/" is the Vercel project root, Vercel only
# sees files inside this directory. Changes to backend/, docs/, or root files
# never trigger a build in the first place. This script is therefore a
# belt-and-suspenders safety net for any future configuration where the root
# changes or build triggers widen.
#
# Reference: https://vercel.com/docs/concepts/projects/environment-variables/ignored-build-step
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# If the required git environment variables are not present (e.g. we are
# running outside Vercel), default to building (exit 1).
# ---------------------------------------------------------------------------
if [ -z "${VERCEL_GIT_PREVIOUS_SHA:-}" ] || [ -z "${VERCEL_GIT_COMMIT_SHA:-}" ]; then
  echo "Not running inside a Vercel build environment. Proceeding with build."
  exit 1
fi

# ---------------------------------------------------------------------------
# List of regex patterns for paths that SHOULD trigger a build.
# Any change inside these paths will proceed with the build (exit 1).
# Any change ONLY outside these paths will skip the build (exit 0).
# ---------------------------------------------------------------------------
FRONTEND_PATHS=(
  # The directory itself (e.g. an inadvertent `frontend` change)
  '^frontend/?$'
  # Anything nested inside the frontend project
  '^frontend/'
)

# ---------------------------------------------------------------------------
# Inspect changed files using git diff between the previous and current SHA.
# Use a newline-separated list (passed through 'git diff -z' would be cleaner,
# but -z output uses NUL separators which are awkward in bash). We rely on
# `git diff --name-only` which emits one file per line.
# ---------------------------------------------------------------------------
mapfile -t CHANGED_FILES < <(git diff --name-only "${VERCEL_GIT_PREVIOUS_SHA}" "${VERCEL_GIT_COMMIT_SHA}" 2>/dev/null || true)

if [ "${#CHANGED_FILES[@]}" -eq 0 ]; then
  # No changes detected (very rare). Build anyway to be safe.
  echo "No changed files detected. Proceeding with build."
  exit 1
fi

# Check whether any changed file matches one of the FRONTEND_PATHS.
for file in "${CHANGED_FILES[@]}"; do
  for pattern in "${FRONTEND_PATHS[@]}"; do
    if [[ "${file}" =~ ${pattern} ]]; then
      echo "Changed file '${file}' is inside the frontend project. Proceeding with build."
      exit 1
    fi
  done
done

# Build a human-readable list of changed files for logging.
PRETTY_FILES=$(printf '  - %s\n' "${CHANGED_FILES[@]}")

# Only non-frontend files were changed — skip the build to save time/resources.
echo "No frontend files changed in this commit. The following files were modified:"
echo "${PRETTY_FILES}"
echo "Skipping Vercel build."
exit 0
