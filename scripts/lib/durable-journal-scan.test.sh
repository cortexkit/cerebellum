#!/usr/bin/env bash
# Planted-offender proofs for durable-journal-scan.py, run by the test gate
# before the scan itself.
#
# A scan that reports nothing looks the same whether the tree is clean or the
# scan is blind, so each shape of test code it claims to cover gets an offender
# planted in a scratch tree and must be reported, and each shape it must NOT
# report (comments, strings, non-test code, `cfg(not(test))`) must pass.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$SCRIPT_DIR/durable-journal-scan.py"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/durable-journal-scan-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

failures=0
checks=0

# A fresh tree holding one integration test and one library source, both
# clean, which each case then plants into.
fresh_tree() {
  local tree="$TMP_DIR/$1"
  mkdir -p "$tree/crates/demo/src" "$tree/crates/demo/tests"
  cat >"$tree/crates/demo/tests/wire.rs" <<'RUST'
#[test]
fn isolated() {
    let _ = Planes::with_browser_config_journaling(health(), None, JournalPersistence::Isolated);
}
RUST
  cat >"$tree/crates/demo/src/lib.rs" <<'RUST'
pub fn production() -> Planes {
    // Production code may journal durably; only test code is checked.
    Planes::new(health())
}

#[cfg(not(test))]
fn not_a_test() {
    let _ = Planes::with_browser_config(health(), None);
}

#[cfg(test)]
mod tests {
    // Planes::new( in a comment is not a call.
    const NOTE: &str = "Planes::new(";
    /* nor JournalPersistence::Durable in a block comment */

    #[test]
    fn isolated() {
        let _ = Planes::with_browser_config_journaling(health(), None, JournalPersistence::Isolated);
    }
}
RUST
  printf '%s' "$tree"
}

# expect <case> <exit status> [text the report must contain]
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
  elif [ -n "$needle" ] && ! printf '%s' "$output" | grep -qF -- "$needle"; then
    echo "FAIL $name: report does not name $needle" >&2
    printf '%s\n' "$output" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  else
    echo "ok   $name"
  fi
}

tree="$(fresh_tree clean)"
expect "a clean tree passes, with comments, strings and non-test code" 0 "scanned 1 integration-test files" "$tree"

tree="$(fresh_tree split)"
cat >>"$tree/crates/demo/src/lib.rs" <<'RUST'

#[cfg(test)]
mod split {
    #[test]
    fn durable() {
        let _ = Planes
            ::
            new (health());
    }
}
RUST
expect "an offender split across lines in a cfg(test) module" 1 "crates/demo/src/lib.rs:27: Planes::new(" "$tree"

tree="$(fresh_tree out_of_line)"
cat >>"$tree/crates/demo/src/lib.rs" <<'RUST'

#[cfg(test)]
mod more_tests;
RUST
cat >"$tree/crates/demo/src/more_tests.rs" <<'RUST'
fn helper() {
    let _ = computer_capability::production_audit();
}
RUST
expect "an offender in an out-of-line cfg(test) module file" 1 "crates/demo/src/more_tests.rs:2: production_audit(" "$tree"

tree="$(fresh_tree nested_cfg)"
cat >>"$tree/crates/demo/src/lib.rs" <<'RUST'

#[cfg(all(test, unix))]
fn durable() {
    let _ = JournalPersistence :: Durable;
}
RUST
expect "an offender under cfg(all(test, ..))" 1 "JournalPersistence::Durable" "$tree"

tree="$(fresh_tree test_attribute)"
cat >>"$tree/crates/demo/src/lib.rs" <<'RUST'

#[tokio::test(flavor = "current_thread")]
async fn durable() {
    let _ = DurableLaunchJournal::open_filesystem(config());
}
RUST
expect "an offender in a #[tokio::test] outside any test module" 1 "DurableLaunchJournal::open_filesystem(" "$tree"

tree="$(fresh_tree for_test)"
cat >>"$tree/crates/demo/src/lib.rs" <<'RUST'

pub fn drive_for_test() -> Planes {
    Planes::new(health())
}
RUST
expect "an offender in a function named for tests" 1 "crates/demo/src/lib.rs:24: Planes::new(" "$tree"

tree="$(fresh_tree integration)"
cat >>"$tree/crates/demo/tests/wire.rs" <<'RUST'

#[test]
fn profiles() {
    let _ = production_profile_lifecycle();
}
RUST
expect "an offender in an integration test" 1 "crates/demo/tests/wire.rs:8: production_profile_lifecycle(" "$tree"

tree="$(fresh_tree missing_module)"
cat >>"$tree/crates/demo/src/lib.rs" <<'RUST'

#[cfg(test)]
mod nowhere;
RUST
expect "a test module with no file refuses rather than skipping it" 2 "test module \`nowhere\` has no file" "$tree"

mkdir -p "$TMP_DIR/empty"
expect "an empty tree refuses rather than passing" 2 "nothing was scanned" "$TMP_DIR/empty"

tree="$(fresh_tree no_tests)"
cat >"$tree/crates/demo/src/lib.rs" <<'RUST'
pub fn production() {}
RUST
expect "a source tree with no test code refuses rather than passing" 2 "nothing was scanned" "$tree"

if [ "$failures" -ne 0 ]; then
  echo "durable-journal-scan.test.sh: $failures of $checks checks failed" >&2
  exit 1
fi
echo "durable-journal-scan.test.sh: $checks checks passed"
