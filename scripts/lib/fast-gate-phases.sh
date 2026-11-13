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
    cerebellum|cerebellum-ability|cerebellum-computer|cerebellum-macos|cerebellum-native-host) return 0 ;;
    *) return 1 ;;
  esac
}

select_mac_plan() {
  # Keep native platform tests and the shared ability contract on macOS.
  # Keep the original diff scope; script-only changes need no native rebuild.
  local package suite
  local mac_packages=() mac_libs=() mac_suites=()
  for package in "${packages[@]+${packages[@]}}"; do
    if mac_package "$package"; then mac_packages+=("$package"); fi
  done
  packages=("${mac_packages[@]+${mac_packages[@]}}")
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

run_mac_clippy() {
  if [ "${#packages[@]}" -eq 0 ]; then
    echo '==> SKIP: macOS clippy (no touched macOS package)'
    return 0
  fi
  local package probe=0
  local args=(--locked)
  for package in "${packages[@]}"; do
    args+=(-p "$package")
    case "$package" in cerebellum|cerebellum-computer|cerebellum-macos) probe=1 ;; esac
  done
  args+=(--all-targets -- -D warnings)
  run_phase "cargo clippy --locked ${packages[*]} --all-targets -- -D warnings (macOS)" \
    cargo clippy "${args[@]}" || return 1
  [ "$probe" -eq 1 ] || return 0
  if [ "${vm:-0}" -eq 1 ]; then
    # The desk probe is a hand-run, person-present flow: build the helper,
    # sign it with the operator's Apple Development identity, and run it on
    # an unlocked desk. The VM has none of that, so its build is verified
    # where it runs, never here, and the skip is named rather than silent.
    echo '==> SKIP: desk-probe example clippy in the macOS VM (local only)'
    not_verified+=("desk-probe example clippy not run in the macOS VM (needs the operator signing identity and a desk; run it locally: bash scripts/fast-gate.sh --part mac --base ${base:-<commit>})")
    return 0
  fi
  # The hand-run desk probe and its screen-capture check build only with the
  # desk-probe feature, which no other phase enables. The probe uses much of
  # the library, so any change to these packages can break it.
  run_phase "cargo clippy --locked -p cerebellum --example app_use_desk_probe --features desk-probe -- -D warnings (macOS)" \
    cargo clippy --locked -p cerebellum --example app_use_desk_probe --features desk-probe -- -D warnings
}

run_linux_part() {
  # Exit 200 means the build server refused the job before starting it (for
  # example when it is full): nothing ran, so asking again is safe. Any other
  # exit, including ck's own codes for a lost or timed-out job, is the verdict.
  local attempt status
  # 8 CPUs measured faster end to end than 4 once queue time is counted.
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    ck motor run --vcpus 8 --timeout 1800 --cwd "$repo_root" -- \
      ./scripts/fast-gate.sh --part linux --base "$base"
    status=$?
    [ "$status" -eq 200 ] || return "$status"
    echo "==> Linux half refused before it started (attempt $attempt of 12); asking again in 15 s"
    sleep 15
  done
  return 200
}

run_mac_part() {
  ./scripts/fast-gate.sh --part mac --base "$base"
}

run_mac_remote_part() {
  # Opt-in remote Mac half: the heavy work runs on MOTOR's macOS VM and this
  # host only streams its log. Exit 200 means MOTOR refused the job before
  # starting it (for example the runner was unreachable or busy): nothing ran,
  # so asking again is safe. Any other exit, including ck's own codes for a
  # lost or timed-out job, is the verdict. The VM is a fixed-size offline
  # macOS worker, so neither --vcpus nor --net is passed.
  #
  # Measured 2026-10-27 on a branch of this gate: a scripts-only diff passed
  # the remote half in 48 s end to end (job 01a17e6a), while a Rust diff hit
  # the 30 min job timeout with the lib tests still running (job 01a17e6b;
  # clippy alone took 83 s where the local Mac half takes about 200 s for a
  # similar diff). A cold 4-vCPU VM builds roughly ten times slower, so the
  # combined gate keeps the local Mac half by default and this stays opt-in
  # until the VM builds warm. The 60 min timeout fits a cold full-half run.
  local attempt status
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    ck motor run --platform macos --timeout 3600 --cwd "$repo_root" -- \
      ./scripts/fast-gate.sh --part mac --vm --base "$base"
    status=$?
    [ "$status" -eq 200 ] || return "$status"
    echo "==> macOS VM half refused before it started (attempt $attempt of 12); asking again in 15 s"
    sleep 15
  done
  return 200
}

# Every phase of --part mac, and where the macOS-VM form (--vm) runs it. The
# VM is a headless macOS worker: it has the toolchain, ad-hoc codesign and
# FSEvents, but no desktop session, no TCC grants (Transparency, Consent, and
# Control: the macOS privacy permissions covering Accessibility, Screen
# Recording, and Input Monitoring), no launchd agents, and no Apple
# Development signing identity.
#
# - tree fingerprint: runs in VM (pure python over the snapshot).
# - macOS clippy on the touched macOS packages: runs in VM (pure compilation;
#   --all-targets also compiles the desk test targets below, so skipping their
#   execution loses no compile coverage).
# - desk-probe example clippy: LOCAL ONLY (needs the operator signing
#   identity and a desk; the VM form reports NOT VERIFIED, never a silent skip).
# - touched --lib tests: run in VM. The launch_recovery_clear subtests read the
#   process table; where that table is unreadable the gate already skips them
#   with a NOT VERIFIED line (see configure_lib_tests).
# - touched integration suites: run in VM, EXCEPT the window-server desk tests
#   below, which are LOCAL ONLY: without a window-server session they cannot
#   check what they promise (the preview and cursor hide, cursor motion
#   framing, and the source-rect capture), so the VM form reports each as NOT
#   VERIFIED with the local command instead of running it.
vm_local_only_suites=(
  cerebellum-macos:preview_hide
  cerebellum-macos:cursor_hide
  cerebellum-macos:cursor_motion
  cerebellum-macos:source_rect_pattern
)

is_vm_local_only_suite() {
  local wanted="$1" suite
  for suite in "${vm_local_only_suites[@]}"; do
    [ "$suite" = "$wanted" ] && return 0
  done
  return 1
}

run_combined_gate() (
  require_part_host mac || exit $?
  base="$(GIT_OPTIONAL_LOCKS=0 git rev-parse --verify "${base}^{commit}")" || exit 2
  local scratch_root="${CARGO_TARGET_DIR:-$repo_root/target}/scratch"
  mkdir -p "$scratch_root"
  static_dir="$(mktemp -d "$scratch_root/fast-gate-parts.XXXXXX")"
  static_pids=()
  static_logs=()
  phase_failed=0
  not_verified=()
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
  local part_logs=("${static_logs[@]}")
  wait_static_phases
  if ! python3 "$repo_root/scripts/lib/fast-gate-fingerprint.py" --compare "${part_logs[@]}"; then
    phase_failed=1
  fi
  if [ "$phase_failed" -ne 0 ]; then
    echo "fast gate: both halves are required. In a worker sandbox, take the base commit with 'git rev-parse origin/main', then run scripts/fast-gate.sh --part linux --base <commit> with bash runon, and scripts/fast-gate.sh --part mac --base <commit> locally." >&2
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

check_shell_exit_traps() {
  bash "$repo_root/scripts/lib/fail-closed-exit.test.sh" &&
    python3 "$repo_root/scripts/lib/fail-closed-exit-scan.py" "$repo_root"
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
  python3 "$repo_root/scripts/lib/process-table-probe.py"
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
