#!/usr/bin/env bash
# Only four kinds of path under .cortexkit/ may be tracked: release notes,
# skills, rules and the worker guide. Everything else there is private (internal
# documents, scripts, agent state) and must never reach a commit.
#
# This lists every tracked path rather than asking git for tracked-and-ignored
# files: a stray `!` line in any .gitignore un-ignores a private file, and a
# tracked file that is no longer ignored would pass that narrower check. A
# failing `git ls-files` must fail the check, not read as an empty list.
#
# Usage: check-cortexkit-layout.sh [repository]   (default: current directory)
set -euo pipefail

repo="${1:-.}"
if ! all="$(git -C "$repo" ls-files -- .cortexkit)"; then
  echo "BLIND: git ls-files failed in $repo" >&2
  exit 2
fi
bad="$(printf '%s\n' "$all" | grep -vE '^\.cortexkit/(release-notes/|skills/|rules/|WORKER\.md$)' | grep -v '^$' || true)"
if [ -n "$bad" ]; then
  printf 'tracked outside the .cortexkit allowlist:\n%s\n' "$bad" >&2
  exit 1
fi
