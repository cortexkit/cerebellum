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
anchors_only=0
platform=""
diff_given=0
usage() {
  echo "usage: $0 [--diff REF] [--narrow-only | --full-only | --check-only [--anchors-only | --platform OS]]"
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --diff)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      base="$2"
      diff_given=1
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
    --anchors-only)
      anchors_only=1
      shift
      ;;
    --platform)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      case "$2" in linux|macos|windows) platform="$2" ;; *) usage >&2; exit 2 ;; esac
      shift 2
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
if [ "$check_only" -eq 0 ] && { [ "$anchors_only" -eq 1 ] || [ -n "$platform" ]; }; then
  echo "--anchors-only and --platform require --check-only" >&2
  exit 2
fi
if [ "$anchors_only" -eq 1 ] && [ -n "$platform" ]; then
  echo "--anchors-only cannot be combined with --platform" >&2
  exit 2
fi

# Keep the check's scratch catalogue outside the installed tools and source tree.
scratch_root="${CARGO_TARGET_DIR:-$repo_root/target}/scratch"
mkdir -p "$scratch_root"
tmpdir="$(mktemp -d "$scratch_root/mutation-check.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP QUIT
# The runner's own temporary files stay out of the per-user temp directory too,
# but in a directory this script never deletes. A compiler cache server started
# by the runner's first build would keep this TMPDIR for its whole life and serve
# every later build on the machine, so start it first, with the caller's TMPDIR.
if command -v sccache >/dev/null 2>&1; then
  sccache --start-server >/dev/null 2>&1 || true
fi
export TMPDIR="$scratch_root/tmp"
mkdir -p "$TMPDIR"
catalogue=mutations.d
if [ "$check_only" -eq 1 ]; then
  planner_python=""
  for python in python3 python3.14 python3.13 python3.12 python3.11; do
    if command -v "$python" >/dev/null && "$python" -c 'import tomllib' 2>/dev/null; then
      planner_python="$python"
      break
    fi
  done
  [ -n "$planner_python" ] || { echo 'mutation check planner: Python 3.11+ is required' >&2; exit 2; }
  "$planner_python" scripts/lib/mutation-catalogue.py coverage mutations.d
fi
if [ "$check_only" -eq 1 ] && [ "$diff_given" -eq 1 ]; then
  selection="$("$planner_python" scripts/lib/mutation-check-plan.py "$base" "$tmpdir/selected.toml")"
  echo "mutations: strict check selection: $selection"
  case "$selection" in
    'scoped 0') echo "mutations: no changed or anchored catalogue rows"; exit 0 ;;
    scoped*) catalogue="$tmpdir/selected.toml" ;;
    full) ;;
    *) echo "mutations: invalid check plan: $selection" >&2; exit 2 ;;
  esac
fi

# The runner lives in this checkout's Cargo target directory. ~/.cargo/bin is shared
# by every repository on the machine, so another repository installing a
# different ckdev-mutate there would silently change, or block, this replay.
# The script never looks on PATH or in ~/.cargo/bin, and never installs on its
# own: it names the exact install command and stops.
# Cargo's install record distinguishes the reviewed source revision from another
# binary that happens to report the same semantic version.
expected_version="0.12.10"
expected_revision="73af60d143d64fe874606ce73f22e02cb356a4bb"
tools_root="${CARGO_TARGET_DIR:-$repo_root/target}/tools"
case "$tools_root" in /*) ;; *) tools_root="$repo_root/$tools_root" ;; esac
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

check_options=(--strict)
if [ "$anchors_only" -eq 1 ]; then
  check_options=(--anchors-only)
elif [ -n "$platform" ]; then
  check_options+=(--platform "$platform")
fi
"$mutate" check --catalogue "$catalogue" "${check_options[@]}"

# Validating the catalogue alone is what a landing gate needs when a change
# touches it: a row the runner refuses under --strict stops every later replay,
# and nothing else would notice until someone ran one.
if [ "$check_only" -eq 1 ]; then
  echo "mutations: the catalogue is valid (${check_options[*]})"
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
