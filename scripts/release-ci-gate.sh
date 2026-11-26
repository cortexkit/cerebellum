#!/usr/bin/env bash
# Require a successful push CI run on main or a train/ branch for the tagged commit.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 1 ]]; then
  echo 'usage: scripts/release-ci-gate.sh <commit-ish>' >&2
  exit 2
fi
sha=$(git rev-parse --verify "$1^{commit}") || { echo 'release-ci-gate: REFUSED: cannot resolve commit' >&2; exit 2; }
git merge-base --is-ancestor "$sha" origin/main || {
  echo "release-ci-gate: REFUSED: $sha is not landed on origin/main (fetch main first)" >&2
  exit 2
}
exec python3 scripts/lib/release_ci.py "$sha"
