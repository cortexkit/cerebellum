#!/usr/bin/env bash
# SIGKILL can leave ckdev-mutate's guard edits in the checkout. Refuse to compile
# those edits as ordinary source in a verification gate.
set -euo pipefail
cd "$(dirname "$0")/.."
for python in python3 python3.14 python3.13 python3.12 python3.11; do
  if command -v "$python" >/dev/null && "$python" -c 'import tomllib' 2>/dev/null; then
    "$python" scripts/lib/check-mutation-tree.test.py
    exec "$python" scripts/lib/check-mutation-tree.py "$@"
  fi
done
echo 'mutation tree check: Python 3.11+ is required' >&2
exit 2
