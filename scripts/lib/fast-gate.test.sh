#!/usr/bin/env bash
# Exercise the live phase runner without compiling or using operator state.
set -uo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/scripts/lib/fast-gate-phases.sh"
scratch_root="${CARGO_TARGET_DIR:-$repo_root/target}/scratch"
mkdir -p "$scratch_root"
scratch="$(mktemp -d "$scratch_root/fast-gate-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
failures=0
checks=0

check() {
  if [ -n "${FAST_GATE_PHASE_CASE:-}" ] && [ "$1" != "$FAST_GATE_PHASE_CASE" ]; then
    return
  fi
  checks=$((checks + 1))
  if ( "$2" ) >"$scratch/output" 2>&1; then
    echo "SELF-TEST PASSED: $1"
  else
    echo "SELF-TEST FAILED: $1"
    cat "$scratch/output"
    failures=$((failures + 1))
  fi
}

setup_phases() {
  static_dir="$scratch"
  static_pids=()
  static_logs=()
  phase_failed=0
  not_verified=()
}

failing_concurrent_phase() {
  setup_phases
  fail() { echo 'whole failing output'; return 19; }
  pass() { echo 'whole passing output'; }
  start_static_phase 'planted failing concurrent phase' fail
  start_static_phase 'passing concurrent control' pass
  run_serial_phase 'passing serial control' pass
  wait_static_phases >"$scratch/joined"
  if finish_gate >"$scratch/verdict" 2>&1; then return 1; fi
  grep -Fxq '==> FAIL: planted failing concurrent phase (exit 19)' "$scratch/joined" &&
    grep -Fxq 'whole failing output' "$scratch/joined" &&
    grep -Fq '==> PASS: passing concurrent control' "$scratch/joined" &&
    grep -Fq 'FAST GATE FAILED:' "$scratch/verdict"
}

concurrent_order() {
  setup_phases
  mkfifo "$scratch/ready" "$scratch/ack"
  static_work() {
    echo ready >"$scratch/ready"
    read -r reply <"$scratch/ack"
    echo "static $reply"
  }
  serial_work() {
    read -r ready <"$scratch/ready"
    echo "$ready" >"$scratch/ack"
    echo 'serial complete'
  }
  start_static_phase 'static rendezvous' static_work
  run_serial_phase 'serial rendezvous' serial_work >"$scratch/serial"
  wait_static_phases >"$scratch/joined"
  grep -Fxq 'serial complete' "$scratch/serial" &&
    grep -Fxq 'static ready' "$scratch/joined" &&
    ! grep -q 'static rendezvous' "$scratch/serial" &&
    finish_gate
}

unreadable_process_table() {
  setup_phases
  uname() { echo Darwin; }
  process_table_readable() { return 1; }
  configure_lib_tests
  [ "${lib_test_options[*]}" = '-- --skip launch_recovery_clear' ] || return 1
  finish_gate >"$scratch/verdict"
  [ "$(head -n 1 "$scratch/verdict")" = 'NOT VERIFIED: launch_recovery_clear (process table unreadable here)' ] &&
    [ "$(tail -n 1 "$scratch/verdict")" = 'FAST GATE PASSED: every selected phase that ran is green; see the NOT VERIFIED lines above' ]
}

readable_process_table() {
  setup_phases
  uname() { echo Darwin; }
  process_table_readable() { return 0; }
  configure_lib_tests
  [ "${#lib_test_options[@]}" -eq 0 ] && [ "${#not_verified[@]}" -eq 0 ]
}

linux_mode() {
  uname() { echo Linux; }
  require_part_host linux && ! require_part_host mac || return 1
  base=fixture
  replay_options=()
  ck() { printf '%s\n' "$@" >"$scratch/argv"; }
  run_linux_part
  grep -Fxq linux "$scratch/argv" && grep -Fxq -- --part "$scratch/argv" &&
    grep -Fxq fixture "$scratch/argv"
}

mac_mode() {
  uname() { echo Darwin; }
  require_part_host mac && ! require_part_host linux || return 1
  packages=(cerebellum cerebellum-core cerebellum-computer cerebellum-macos cerebellum-native-host)
  lib_packages=(cerebellum cerebellum-core cerebellum-computer cerebellum-macos)
  suites=(cerebellum-core:it cerebellum:it cerebellum-macos:preview_hide)
  select_mac_plan
  [ "${packages[*]}" = 'cerebellum cerebellum-computer cerebellum-macos cerebellum-native-host' ] || return 1
  [ "${lib_packages[*]}" = 'cerebellum cerebellum-computer cerebellum-macos' ] || return 1
  [ "${suites[*]}" = 'cerebellum:it cerebellum-macos:preview_hide' ] || return 1
  packages=(cerebellum-linux)
  lib_packages=(cerebellum-core)
  suites=(cerebellum-core:it)
  select_mac_plan
  [ "${#packages[@]}" -eq 0 ] && [ "${#lib_packages[@]}" -eq 0 ] && [ "${#suites[@]}" -eq 0 ] &&
    catalogue_check_needed mac mutations.d/rows.toml &&
    ! catalogue_check_needed linux mutations.d/rows.toml &&
    ! catalogue_check_needed mac scripts/fast-gate.sh
}

combined_mode() {
  uname() { echo Darwin; }
  base=HEAD
  mutations=0
  run_linux_part() { echo 'linux whole log'; return 200; }
  run_mac_part() { echo 'mac whole log'; }
  if run_combined_gate >"$scratch/combined" 2>&1; then return 1; fi
  python3 - "$scratch/combined" <<'PY'
from pathlib import Path
import sys
log = Path(sys.argv[1]).read_text()
assert log.index('linux whole log') < log.index('mac whole log')
assert '==> FAIL: Linux half (ck motor run) (exit 200)' in log
assert '==> PASS: macOS half (local)' in log
assert "git rev-parse origin/main" in log and "--part linux --base <commit>" in log
assert 'FAST GATE FAILED:' in log
PY
}

combined_skip() {
  uname() { echo Darwin; }
  base=HEAD
  mutations=0
  run_linux_part() { fixture_fingerprint a; echo linux; }
  run_mac_part() { fixture_fingerprint a; echo 'NOT VERIFIED: launch_recovery_clear (process table unreadable here)'; }
  run_combined_gate >"$scratch/combined" 2>&1 || return 1
  [ "$(tail -n 1 "$scratch/combined")" = 'FAST GATE PASSED: every selected phase that ran is green; see the NOT VERIFIED lines above' ]
}

fixture_fingerprint() {
  python3 - "$1" <<'PY'
import sys
print('FAST GATE FINGERPRINT: head=' + '0' * 40 + ' base=' + '1' * 40 +
      ' diff=' + sys.argv[1] * 64 + ' untracked=' + '2' * 64)
PY
}

mac_clippy_pipeline() {
  local fixture="$scratch/mac-fixture" calls="$scratch/mac-cargo.calls" status
  mkdir -p "$fixture/scripts/lib" "$fixture/bin" \
    "$fixture/crates/cerebellum/src" "$fixture/crates/cerebellum-linux/src"
  cp "$repo_root/scripts/fast-gate.sh" "$fixture/scripts/"
  cp "$repo_root/scripts/lib/fast-gate-phases.sh" \
    "$repo_root/scripts/lib/fast-gate-fingerprint.py" \
    "$repo_root/scripts/lib/process-table-probe.py" "$fixture/scripts/lib/"
  printf '#!/usr/bin/env bash\necho Darwin\n' >"$fixture/bin/uname"
  cat >"$fixture/bin/cargo" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$CALL_LOG"
case "$1" in
  metadata) printf '%s\n' "$FIXTURE_METADATA" ;;
  clippy) exit "${FIXTURE_CLIPPY_STATUS:-0}" ;;
  test) echo 'test result: ok. 1 passed; 0 failed' ;;
esac
SH
  chmod +x "$fixture/bin/cargo" "$fixture/bin/uname"
  printf 'fixture\n' >"$fixture/crates/cerebellum/src/lib.rs"
  printf 'fixture\n' >"$fixture/crates/cerebellum-linux/src/lib.rs"
  (
    cd "$fixture" || exit 1
    git init -q && git config user.email fixture@example.invalid && git config user.name fixture || exit 1
    git add . && git -c commit.gpgsign=false commit -qm fixture || exit 1
    export CALL_LOG="$calls" PATH="$fixture/bin:$PATH" CARGO_TARGET_DIR="$scratch/mac-fixture-target"
    FIXTURE_METADATA="$(python3 - <<'PY'
from pathlib import Path
import json
print(json.dumps({'packages': [
    {'name': name, 'manifest_path': str(Path('crates', name, 'Cargo.toml').resolve()),
     'targets': [{'name': name, 'kind': ['lib']}, {'name': 'it', 'kind': ['test']}]}
    for name in ('cerebellum', 'cerebellum-linux')]}))
PY
)"
    export FIXTURE_METADATA
    printf 'changed\n' >crates/cerebellum/src/lib.rs
    : >"$CALL_LOG"
    ./scripts/fast-gate.sh --part mac --base HEAD >"$scratch/mac-pipeline" 2>&1 || exit 1
    python3 - "$CALL_LOG" <<'PY'
from pathlib import Path
import sys
calls = Path(sys.argv[1]).read_text().splitlines()
lint = calls.index('clippy --locked -p cerebellum --all-targets -- -D warnings')
tests = next(i for i, line in enumerate(calls) if line.startswith('test --locked -p cerebellum --lib'))
assert lint < tests
PY
    [ "$?" -eq 0 ] || exit 1
    printf 'fixture\n' >crates/cerebellum/src/lib.rs
    printf 'changed\n' >crates/cerebellum-linux/src/lib.rs
    : >"$CALL_LOG"
    ./scripts/fast-gate.sh --part mac --base HEAD >"$scratch/mac-linux-only" 2>&1 || exit 1
    [ "$(wc -l <"$CALL_LOG" | tr -d ' ')" = 1 ] || exit 1
    printf 'fixture\n' >crates/cerebellum-linux/src/lib.rs
    printf 'changed\n' >crates/cerebellum/src/lib.rs
    : >"$CALL_LOG"
    FIXTURE_CLIPPY_STATUS=31 ./scripts/fast-gate.sh --part mac --base HEAD >"$scratch/mac-lint-failure" 2>&1
    status=$?
    [ "$status" -ne 0 ] && ! grep -q '^test ' "$CALL_LOG" &&
      grep -Fq '(macOS) (exit 31)' "$scratch/mac-lint-failure"
  )
}

combined_mismatch() {
  uname() { echo Darwin; }
  base=HEAD
  mutations=0
  run_linux_part() { fixture_fingerprint a; }
  run_mac_part() { fixture_fingerprint b; }
  if run_combined_gate >"$scratch/mismatch" 2>&1; then return 1; fi
  grep -Fq 'mismatched tree fingerprints' "$scratch/mismatch" &&
    grep -Fq 'Linux fingerprint: FAST GATE FINGERPRINT:' "$scratch/mismatch" &&
    grep -Fq 'Mac fingerprint: FAST GATE FINGERPRINT:' "$scratch/mismatch" &&
    [ "$(tail -n 1 "$scratch/mismatch")" = 'FAST GATE FAILED: one or more selected phases failed' ]
}

combined_missing() {
  uname() { echo Darwin; }
  base=HEAD
  mutations=0
  run_linux_part() { echo 'no fingerprint'; }
  run_mac_part() { fixture_fingerprint a; }
  if run_combined_gate >"$scratch/missing" 2>&1; then return 1; fi
  grep -Fxq 'Linux fingerprint: <missing>' "$scratch/missing"
}

check 'a failing concurrent phase still fails the gate' failing_concurrent_phase
check 'source checks overlap serial work with whole, ordered logs' concurrent_order
check 'the sandbox skip prints NOT VERIFIED before the verdict' unreadable_process_table
check 'a readable process table leaves library tests unchanged' readable_process_table
check '--part linux selects the remote Linux lane' linux_mode
check '--part mac keeps platform binaries and excludes Linux-only checks' mac_mode
check 'Mac clippy precedes tests, fails fast, and excludes Linux-only changes' mac_clippy_pipeline
check 'default mode collects both halves and reports a runner connection failure' combined_mode
check 'default mode preserves NOT VERIFIED from the Mac half' combined_skip
check 'default mode refuses mismatched tree fingerprints and names both' combined_mismatch
check 'default mode refuses a missing tree fingerprint' combined_missing
echo "fast-gate phase tests: $checks checks, $failures failures"
[ "$failures" -eq 0 ]
