#!/usr/bin/env bash
# Sourced by fast-gate.sh; Cargo phases stay serial while source scans run.
require_part_host() {
  local system
  system="$(uname -s)"
  case "$1:$system" in linux:Linux|mac:Darwin) return 0 ;; esac
  echo "fast gate: --part $1 cannot run on $system" >&2
  return 2
}

mac_package() {
  case "$1" in
    cerebellum|cerebellum-computer|cerebellum-macos|cerebellum-native-host) return 0 ;;
    *) return 1 ;;
  esac
}

select_mac_plan() {
  # These binaries contain platform-gated tests that Linux cannot execute.
  # Keep the original diff scope; script-only changes need no native rebuild.
  local package suite
  local mac_libs=() mac_suites=()
  for package in "${lib_packages[@]+${lib_packages[@]}}"; do
    if mac_package "$package"; then
      mac_libs+=("$package")
    fi
  done
  lib_packages=("${mac_libs[@]+${mac_libs[@]}}")
  for suite in "${suites[@]+${suites[@]}}"; do
    if mac_package "${suite%%:*}"; then mac_suites+=("$suite"); fi
  done
  suites=("${mac_suites[@]+${mac_suites[@]}}")
}

catalogue_check_needed() {
  [ "$1" = mac ] && grep -q '^mutations\.d/' <<<"$2"
}

run_linux_part() {
  ck motor run --vcpus 8 --cwd "$repo_root" -- \
    ./scripts/fast-gate.sh --part linux --base "$base" "${replay_options[@]+${replay_options[@]}}"
}

run_mac_part() {
  ./scripts/fast-gate.sh --part mac --base "$base" "${replay_options[@]+${replay_options[@]}}"
}

run_combined_gate() (
  require_part_host mac || exit $?
  local scratch_root="${CARGO_TARGET_DIR:-$repo_root/target}/scratch"
  mkdir -p "$scratch_root"
  static_dir="$(mktemp -d "$scratch_root/fast-gate-parts.XXXXXX")"
  static_pids=()
  static_logs=()
  phase_failed=0
  not_verified=()
  replay_options=()
  [ "$mutations" -eq 0 ] || replay_options=(--mutations)
  cleanup_parts() {
    local pid
    for pid in "${static_pids[@]+${static_pids[@]}}"; do
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    done
    rm -rf "$static_dir"
  }
  trap cleanup_parts EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP QUIT
  start_static_phase 'Linux half (ck motor run)' run_linux_part
  start_static_phase 'macOS half (local)' run_mac_part
  wait_static_phases
  if [ "$phase_failed" -ne 0 ]; then
    echo 'fast gate: both halves are required. In a worker sandbox, run scripts/fast-gate.sh --part linux with bash runon: "linux,8c", and scripts/fast-gate.sh --part mac locally (with the same --base).' >&2
  fi
  finish_gate
)

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
  local index line
  for index in "${!static_pids[@]}"; do
    if ! wait "${static_pids[$index]}"; then
      phase_failed=1
    fi
    cat "${static_logs[$index]}"
    while IFS= read -r line; do
      case "$line" in 'NOT VERIFIED: '*) not_verified+=("${line#NOT VERIFIED: }") ;; esac
    done <"${static_logs[$index]}"
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
