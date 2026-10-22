#!/usr/bin/env bash
# Exercise the live phase runner without compiling or using operator state.
set -uo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/scripts/lib/fast-gate-phases.sh"
mkdir -p "$repo_root/target/scratch"
scratch="$(mktemp -d "$repo_root/target/scratch/fast-gate-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
failures=0
checks=0

check() {
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

check 'a failing concurrent phase still fails the gate' failing_concurrent_phase
check 'source checks overlap serial work with whole, ordered logs' concurrent_order
check 'the sandbox skip prints NOT VERIFIED before the verdict' unreadable_process_table
check 'a readable process table leaves library tests unchanged' readable_process_table
echo "fast-gate phase tests: $checks checks, $failures failures"
[ "$failures" -eq 0 ]
