#!/usr/bin/env bash
# Planted-offender proofs for the macOS permission request source scan.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$SCRIPT_DIR/mac-permission-request-scan.py"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mac-permission-request-scan.XXXXXX")"
source "$SCRIPT_DIR/fail-closed-exit.sh"
trap 'fail_closed_exit rm -rf "$TMP_DIR"' EXIT

failures=0
checks=0

fresh_tree() {
  local tree="$TMP_DIR/$1"
  mkdir -p "$tree/crates/demo/src" "$tree/crates/demo/tests" "$tree/crates/demo/examples"
  cat >"$tree/crates/demo/src/lib.rs" <<'RUST'
pub fn production() {
    CGRequestScreenCaptureAccess();
}

#[cfg(test)]
mod tests;
RUST
  cat >"$tree/crates/demo/src/tests.rs" <<'RUST'
// CGRequestScreenCaptureAccess() in a comment is not a call.
const DOC: &str = "AXIsProcessTrustedWithOptions(options)";

#[test]
fn safe() {
    CGPreflightScreenCaptureAccess();
}
RUST
  cat >"$tree/crates/demo/tests/wire.rs" <<'RUST'
#[test]
fn safe_integration_test() {
    check_only();
}
RUST
  cat >"$tree/crates/demo/examples/probe.rs" <<'RUST'
fn production_example() {
    CGRequestListenEventAccess();
}

#[cfg(test)]
mod tests {
    #[test]
    fn safe_example_test() {}
}
RUST
  printf '%s' "$tree"
}

expect() {
  local name="$1" want="$2" needle="${3:-}" tree="$4" got output
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
expect "production calls and comments and strings are outside test code" 0 "scanned 4" "$tree"

tree="$(fresh_tree planted)"
cat >>"$tree/crates/demo/src/tests.rs" <<'RUST'

#[cfg(all(test, unix))]
fn requests_permission() {
    unsafe { AXIsProcessTrustedWithOptions(std::ptr::null()) };
}
RUST
expect "requesting API in an out-of-line cfg(test) module is detected" 1 \
  "crates/demo/src/tests.rs:11: test code calls requesting API AXIsProcessTrustedWithOptions(" "$tree"

tree="$(fresh_tree integration)"
cat >>"$tree/crates/demo/tests/wire.rs" <<'RUST'

#[test]
fn requests_permission() {
    CGRequestScreenCaptureAccess();
}
RUST
expect "requesting API in an integration test is detected" 1 \
  "crates/demo/tests/wire.rs:8: test code calls requesting API CGRequestScreenCaptureAccess(" "$tree"

tree="$(fresh_tree example)"
cat >>"$tree/crates/demo/examples/probe.rs" <<'RUST'

#[cfg(test)]
mod more_tests {
    #[test]
    fn requests_permission() {
        IOHIDRequestAccess(1);
    }
}
RUST
expect "requesting API in an example test is detected" 1 \
  "crates/demo/examples/probe.rs:15: test code calls requesting API IOHIDRequestAccess(" "$tree"

if [ "$failures" -ne 0 ]; then
  echo "mac-permission-request-scan.test.sh: $failures of $checks checks failed" >&2
  exit 1
fi
echo "mac-permission-request-scan.test.sh: $checks checks passed"
finished=1
