#!/usr/bin/env bash
# Keep the target lease in Cargo, but never in a test binary or its descendants.
set -euo pipefail

if [ "${1:-}" = --run ]; then
  shift
  exec 9>&-
  exec "$@"
fi

runner="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
config="$(python3 - "$runner" <<'PY'
import json
import sys

print("target.'cfg(all())'.runner = " + json.dumps(["bash", sys.argv[1], "--run"]))
PY
)"
exec cargo --config "$config" test "$@"
