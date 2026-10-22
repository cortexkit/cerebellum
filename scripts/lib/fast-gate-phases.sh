#!/usr/bin/env bash
# Sourced by fast-gate.sh; Cargo phases stay serial while source scans run.
run_phase() {
  local label="$1"
  shift
  local started=$SECONDS
  echo "==> RUN: $label"
  if "$@"; then
    echo "==> PASS: $label ($((SECONDS - started))s)"
  else
    local status=$?
    echo "==> FAIL: $label (exit $status)" >&2
    return "$status"
  fi
}

run_serial_phase() {
  run_phase "$@" || phase_failed=1
}

start_static_phase() {
  local label="$1"
  shift
  local log="$static_dir/${#static_pids[@]}.log"
  static_logs+=("$log")
  ( run_phase "$label" "$@" ) >"$log" 2>&1 &
  static_pids+=("$!")
}

wait_static_phases() {
  local index
  for index in "${!static_pids[@]}"; do
    if ! wait "${static_pids[$index]}"; then
      phase_failed=1
    fi
    cat "${static_logs[$index]}"
  done
  static_pids=()
  static_logs=()
}

process_table_readable() {
  python3 "$repo_root/scripts/lib/process-start-time-probe.py"
}

configure_lib_tests() {
  lib_test_options=()
  if [ "$(uname -s)" = Darwin ] && ! process_table_readable; then
    lib_test_options=(-- --skip launch_recovery_clear)
    not_verified+=("launch_recovery_clear (process table unreadable here)")
  fi
}

finish_gate() {
  local item
  for item in "${not_verified[@]+${not_verified[@]}}"; do
    echo "NOT VERIFIED: $item"
  done
  if [ "$phase_failed" -ne 0 ]; then
    echo "FAST GATE FAILED: one or more selected phases failed" >&2
    return 1
  elif [ "${#not_verified[@]}" -eq 0 ]; then
    echo "FAST GATE PASSED: all selected phases are green"
  else
    echo "FAST GATE PASSED: every selected phase that ran is green; see the NOT VERIFIED lines above"
  fi
}
