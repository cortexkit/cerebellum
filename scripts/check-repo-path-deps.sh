#!/usr/bin/env bash
# TOML parsing needs Python 3.11+. macOS may ship an older python3, while
# Windows may only provide the python command.
set -euo pipefail
cd "$(dirname "$0")/.."
for python in python3 python3.14 python3.13 python3.12 python3.11 python; do
  if command -v "$python" >/dev/null && "$python" -c 'import tomllib' 2>/dev/null; then
    exec "$python" scripts/lib/repo-path-deps.py "$@"
  fi
done
echo 'repository-contained path dependencies: Python 3.11+ is required' >&2
exit 2
