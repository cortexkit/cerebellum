#!/usr/bin/env bash
# Replay the named guard proofs, optionally narrowed to rows touched since a base.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

base="${MUTATION_BASE:-origin/main}"
narrow=1
full=1
only_mode=""
usage() {
  echo "usage: $0 [--diff REF] [--narrow-only | --full-only]"
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --diff)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      base="$2"
      shift 2
      ;;
    --narrow-only)
      [ "$only_mode" != "full" ] || { echo "choose only one of --narrow-only and --full-only" >&2; exit 2; }
      only_mode="narrow"
      full=0
      shift
      ;;
    --full-only)
      [ "$only_mode" != "narrow" ] || { echo "choose only one of --narrow-only and --full-only" >&2; exit 2; }
      only_mode="full"
      narrow=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# Cargo's install record distinguishes the reviewed source revision from another
# binary that happens to report the same semantic version.
expected_version="0.12.3"
expected_revision="649d5f126c3b7da49e3019407ea1a94652d32eea"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
mutate="$cargo_home/bin/ckdev-mutate"
if [ ! -x "$mutate" ]; then
  echo "mutations: ckdev-mutate is missing from $cargo_home/bin" >&2
  exit 2
fi
actual_version="$("$mutate" --version)"
if [ "$actual_version" != "ckdev-mutate $expected_version" ]; then
  echo "mutations: expected ckdev-mutate $expected_version from revision $expected_revision; found '$actual_version'" >&2
  exit 2
fi
python3 - "$cargo_home/.crates2.json" "$expected_version" "$expected_revision" <<'PY'
import json
from pathlib import Path
import sys

metadata_path, version, revision = sys.argv[1:]
expected = (
    f"cortexkit-mutate {version} "
    f"(git+https://github.com/cortexkit/commons?rev={revision}#{revision})"
)
try:
    installs = json.loads(Path(metadata_path).read_text())['installs']
except (OSError, KeyError, json.JSONDecodeError) as error:
    print(f"mutations: cannot verify ckdev-mutate install revision: {error}", file=sys.stderr)
    sys.exit(2)
install = installs.get(expected)
if install is None or "ckdev-mutate" not in install.get("bins", []):
    print(
        f"mutations: ckdev-mutate must be installed from commons revision {revision}",
        file=sys.stderr,
    )
    sys.exit(2)
PY

if [ ! -d mutations.d ]; then
  echo "mutations: missing mutations.d catalogue" >&2
  exit 2
fi

# Keep temporary test-run files on the same worktree filesystem, not in a shared
# system temp directory where another build can collide with them.
tmpdir="$(mktemp -d "$repo_root/.ckdev-mutate.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM HUP QUIT
export TMPDIR="$tmpdir"

"$mutate" check --catalogue mutations.d --strict

if [ "$narrow" -eq 1 ]; then
  if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
    echo "mutations: base ref '$base' does not resolve to a commit" >&2
    exit 2
  fi
  if [ -z "$(git ls-tree -d --name-only "$base" -- mutations.d)" ]; then
    echo "narrow replay: base $base has no catalogue, running the full replay"
    narrow=0
    full=1
  else
    echo "==> narrow mutation replay: changes since $base"
    "$mutate" run --catalogue mutations.d --diff "$base" --narrow
  fi
fi

if [ "$full" -eq 1 ]; then
  echo "==> full mutation replay: every catalogue row"
  started=$SECONDS
  "$mutate" run --catalogue mutations.d --all
  echo "FULL MUTATION REPLAY WALL TIME: $((SECONDS - started))s"
fi
