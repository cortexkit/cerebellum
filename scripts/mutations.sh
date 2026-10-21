#!/usr/bin/env bash
# Replay the named guard proofs, optionally narrowed to rows touched since a base.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

./scripts/check-mutation-tree.sh

base="${MUTATION_BASE:-origin/main}"
narrow=1
full=1
only_mode=""
check_only=0
usage() {
  echo "usage: $0 [--diff REF] [--narrow-only | --full-only | --check-only]"
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
    --check-only)
      check_only=1
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
if [ "$check_only" -eq 1 ] && [ -n "$only_mode" ]; then
  echo "--check-only replays nothing, so it takes no replay mode" >&2
  exit 2
fi

# The runner lives in this checkout's own install root. ~/.cargo/bin is shared
# by every repository on the machine, so another repository installing a
# different ckdev-mutate there would silently change, or block, this replay.
# The script never looks on PATH or in ~/.cargo/bin, and never installs on its
# own: it names the exact install command and stops.
# Cargo's install record distinguishes the reviewed source revision from another
# binary that happens to report the same semantic version.
expected_version="0.12.3"
expected_revision="649d5f126c3b7da49e3019407ea1a94652d32eea"
tools_root="$repo_root/target/tools"
mutate="$tools_root/bin/ckdev-mutate"
refuse_runner() {
  echo "mutations: $1" >&2
  echo "mutations: install the pinned runner into this checkout with:" >&2
  echo "  cargo install --locked --root \"$tools_root\" --git https://github.com/cortexkit/commons --rev $expected_revision cortexkit-mutate" >&2
  exit 2
}
if [ ! -x "$mutate" ]; then
  refuse_runner "ckdev-mutate is missing from $tools_root/bin"
fi
actual_version="$("$mutate" --version)" || refuse_runner "$mutate --version failed"
if [ "$actual_version" != "ckdev-mutate $expected_version" ]; then
  refuse_runner "expected ckdev-mutate $expected_version from revision $expected_revision in $tools_root; found '$actual_version'"
fi
python3 - "$tools_root/.crates2.json" "$expected_version" "$expected_revision" <<'PY' || refuse_runner "$tools_root does not record ckdev-mutate from commons revision $expected_revision"
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

# Validating the catalogue alone is what a landing gate needs when a change
# touches it: a row the runner refuses under --strict stops every later replay,
# and nothing else would notice until someone ran one.
if [ "$check_only" -eq 1 ]; then
  echo "mutations: the catalogue is valid under --strict"
  exit 0
fi

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
