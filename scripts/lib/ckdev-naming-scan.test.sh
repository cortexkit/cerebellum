#!/usr/bin/env bash
# Planted controls for per-spawn ckdev naming checks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$SCRIPT_DIR/ckdev-naming-scan.py"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ckdev-naming-scan.XXXXXX")"
source "$SCRIPT_DIR/fail-closed-exit.sh"
trap 'fail_closed_exit rm -rf "$TMP_DIR"' EXIT

failures=0
checks=0

fresh_tree() {
  local tree="$TMP_DIR/$1"
  mkdir -p "$tree/crates/demo/tests" "$tree/crates/demo/src" "$tree/crates/demo/examples" "$tree/scripts/lib"
  cat >"$tree/crates/demo/tests/process.rs" <<'RUST'
#[test]
fn run_module() {
    let binary = support::ckdev_binary(env!("CARGO_BIN_EXE_ck-cerebellum"), scratch());
    Command::new(&binary).status();
    // DIRECT_SPAWN_CONTROL
}
RUST
  cat >"$tree/scripts/check.sh" <<'SH'
#!/usr/bin/env bash
DEPLOYED_NAME="ck-cerebellum"
STAGE="/tmp/stage"
DEV_NAME="ckdev-cerebellum"
reported="$("$STAGE/$DEV_NAME" --version)"
SH
  printf '%s' "$tree"
}

expect() {
  local name="$1" want="$2" needle="$3" tree="$4" got output
  checks=$((checks + 1))
  set +e
  output="$(python3 "$SCAN" "$tree" 2>&1)"
  got=$?
  set -e
  if [ "$got" -ne "$want" ]; then
    echo "FAIL $name: exit $got, wanted $want" >&2
    printf '%s\n' "$output" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  elif [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$output"; then
    echo "FAIL $name: report does not name $needle" >&2
    printf '%s\n' "$output" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  else
    echo "ok   $name"
  fi
}

tree="$(fresh_tree clean)"
expect "helper-wrapped Rust spawn and ckdev shell link pass" 0 "scanned 1 Rust test-code files and 1 shell scripts" "$tree"

tree="$(fresh_tree direct-rust)"
python3 - "$tree/crates/demo/tests/process.rs" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().replace(
    "    // DIRECT_SPAWN_CONTROL",
    '    Command::new(env!("CARGO_BIN_EXE_ck-cerebellum")).status();',
))
PY
expect "direct spawn immediately after wrapped spawn is rejected" 1 \
  "crates/demo/tests/process.rs:5: process constructor executes a ck-* binary without ckdev_binary" "$tree"

tree="$(fresh_tree direct-shell)"
cat >>"$tree/scripts/check.sh" <<'SH'
smoke="$("$STAGE/$DEPLOYED_NAME" --version)"
SH
expect "production-named script execution is rejected" 1 \
  "scripts/check.sh:6: shell command executes ck-cerebellum without a ckdev- name" "$tree"

if [ "$failures" -ne 0 ]; then
  echo "ckdev-naming-scan.test.sh: $failures of $checks checks failed" >&2
  exit 1
fi
echo "ckdev-naming-scan.test.sh: $checks checks passed"
finished=1
