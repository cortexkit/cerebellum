#!/usr/bin/env bash
# Narrow landing checks for the files changed since a base revision.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

base="${FAST_GATE_BASE:-origin/main}"
self_test=0
part=""
remote=0
vm=0
usage() {
  echo "usage: $0 [--base REF] [--part linux|mac] [--remote] [--vm] [--self-test]"
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      base="$2"
      shift 2
      ;;
    --part)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      case "$2" in linux|mac) part="$2" ;; *) usage >&2; exit 2 ;; esac
      shift 2
      ;;
    --remote)
      remote=1
      shift
      ;;
    --vm)
      vm=1
      shift
      ;;
    --self-test)
      self_test=1
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

# Live desk operations are enabled only by the explicit desk commands below.
# In particular, an inherited shell variable must not enable them in lib tests.
unset CEREBELLUM_DESK_TESTS

source "$repo_root/scripts/lib/fast-gate-phases.sh"
source "$repo_root/scripts/lib/desk-test-report.sh"
if [ "$self_test" -eq 0 ]; then
  # --remote and --vm select the macOS-VM form of --part mac: --remote sends
  # it to the VM from here, --vm executes it inside the VM. Anything else with
  # either flag is a usage error, reported before anything is verified.
  if [ "$remote" -eq 1 ] && [ "$vm" -eq 1 ]; then
    echo "fast gate: --remote and --vm cannot be combined" >&2
    usage >&2
    exit 2
  fi
  if { [ "$remote" -eq 1 ] || [ "$vm" -eq 1 ]; } && [ "$part" != mac ]; then
    echo "fast gate: --remote and --vm select the macOS-VM form of --part mac" >&2
    usage >&2
    exit 2
  fi
  if [ "$remote" -eq 1 ]; then
    # The VM's snapshot carries commits but no branch or remote refs, so
    # resolve the base to a commit where the ref exists: here.
    if ! base="$(GIT_OPTIONAL_LOCKS=0 git rev-parse --verify "${base}^{commit}" 2>/dev/null)"; then
      echo "fast gate: base does not resolve here; nothing has been verified." >&2
      echo "Take the base commit with 'git rev-parse origin/main', then pass '--part mac --remote --base <that commit>'." >&2
      exit 2
    fi
    echo "==> FAST GATE PART: mac (remote macOS VM dispatch)"
    run_mac_remote_part
    exit $?
  fi
  if [ -z "$part" ]; then
    run_combined_gate
    exit $?
  fi
  require_part_host "$part"
  echo "==> FAST GATE PART: $part"
  # A build-server snapshot carries the commits but no branch or remote refs,
  # so a ref name such as origin/main resolves only where the gate was
  # started. The combined gate passes the base as a commit for that reason.
  if ! GIT_OPTIONAL_LOCKS=0 git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
    echo "fast gate: base '$base' does not resolve here; nothing has been verified." >&2
    echo "On the build server, pass the base as a commit taken on the Mac: run 'git rev-parse origin/main' locally, then '--part $part --base <that commit>'." >&2
    exit 2
  fi
  python3 "$repo_root/scripts/lib/fast-gate-fingerprint.py" "$base"
fi
metadata="$(cargo metadata --locked --format-version 1 --no-deps)"

source "$repo_root/scripts/lib/fast-gate-plan.sh"

# A harness-less desk test (one that opens AppKit windows on the main thread)
# prints "test NAME ... SKIPPED: reason", or "SKIPPED (what it did check):
# reason", when this host could not check what it promises, for example
# because the screen is locked. CEREBELLUM_DESK_TESTS=1 explicitly enables its
# live operation. With CEREBELLUM_DESK_TEST_SKIP_OK=1 it then exits 0 instead
# of 2, so a locked screen does not turn this gate red; the gate reads the
# reason back from the output and names it in the summary, so a skip is never
# silent.
desk_suites=(
  "cerebellum-macos:preview_hide"
  "cerebellum-macos:cursor_motion"
  "cerebellum-macos:cursor_hide"
  "cerebellum-macos:source_rect_pattern"
)

record_skipped_tests() {
  local log="$1" scope="$2" line
  while IFS= read -r line; do
    not_verified+=("$scope: $line")
  done < <(desk_skip_lines < "$log")
}

if [ "$self_test" -eq 1 ]; then
  scripts/lib/fast-gate.test.sh
  python3 scripts/lib/fast-gate-fingerprint.py --self-test
  python3 scripts/lib/process-table-probe.py --self-test
  planted_skip="test a_preview_test ... SKIPPED (the window's kind was checked and is right): the screen is locked, so no window is realised"
  if [ "$(printf '%s\n' "$planted_skip" | desk_skip_reason)" != "the screen is locked, so no window is realised" ] || \
     [ "$(printf 'test a_preview_test ... SKIPPED: no display is readable\n' | desk_skip_reason)" != "no display is readable" ]; then
    echo "SELF-TEST FAILED: a planted desk-test skip line did not yield its reason" >&2
    exit 1
  fi
  if [ -n "$(printf 'test a_preview_test ... ok\n' | desk_skip_reason)" ]; then
    echo "SELF-TEST FAILED: a passing desk test was read as a skip" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a desk-test skip yields its reason and a pass yields none"

  skip_lines="$(printf '%s\n' \
    'test one ... SKIPPED: desk test not enabled' \
    'test two ... ok' \
    'test three ... SKIPPED: no display' | desk_skip_lines)"
  if [ "$skip_lines" != $'test one ... SKIPPED: desk test not enabled\ntest three ... SKIPPED: no display' ]; then
    echo "SELF-TEST FAILED: the skip reporter did not preserve every and only the skipped tests" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: every skipped test is retained for NOT VERIFIED reporting"

  suite_plan="$(plan_for_files 'crates/cerebellum/tests/it/tool_catalog.rs' "$metadata")"
  if ! printf '%s\n' "$suite_plan" | grep -Fxq 'T|cerebellum|it'; then
    echo "SELF-TEST FAILED: a planted tests/it source path did not select suite it" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a planted tests/it source path selects suite it"

  cursor_plan="$(plan_for_files 'crates/cerebellum-macos/src/cursor_geometry.rs' "$metadata")"
  if ! printf '%s\n' "$cursor_plan" | grep -Fxq 'T|cerebellum-macos|cursor_motion' || \
     ! printf '%s\n' "$cursor_plan" | grep -Fxq 'T|cerebellum-macos|cursor_hide'; then
    echo "SELF-TEST FAILED: a planted cursor source path did not select the cursor desk tests" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a planted cursor source path selects the cursor desk tests"

  permission_plan="$(plan_for_files 'crates/cerebellum-macos/src/test_support.rs' "$metadata")"
  if ! printf '%s\n' "$permission_plan" | grep -Fxq 'T|cerebellum-macos|source_rect_pattern'; then
    echo "SELF-TEST FAILED: the shared permission gate did not select its source-rect desk test" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: the shared permission gate selects the source-rect desk test"

  flat_plan="$(plan_for_files 'crates/cerebellum/src/flat_tools.rs' "$metadata")"
  if ! printf '%s\n' "$flat_plan" | grep -Fxq 'P|cerebellum' || \
     ! printf '%s\n' "$flat_plan" | grep -Fxq 'A|tool-catalog-and-schema-bytes' || \
     ! printf '%s\n' "$flat_plan" | grep -Fxq 'A|flat-tools-fingerprints'; then
    echo "SELF-TEST FAILED: flat_tools.rs did not select its package and catalog checks" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a planted flat_tools.rs change keeps catalog and fingerprint checks"

  catalog_plan="$(plan_for_files 'engram-catalog.json' "$metadata")"
  if ! printf '%s\n' "$catalog_plan" | grep -Fxq 'P|cerebellum-core' || \
     ! printf '%s\n' "$catalog_plan" | grep -Fxq 'L|cerebellum-core'; then
    echo "SELF-TEST FAILED: engram-catalog.json did not select cerebellum-core --lib" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a root engram-catalog.json change runs cerebellum-core --lib"

  # A shipped-source change with no test file in the diff must still run every
  # source scan in cerebellum's `it` target, which reads src/ directly.
  scan_plan="$(plan_for_files 'crates/cerebellum/src/browser_session.rs' "$metadata")"
  if ! printf '%s\n' "$scan_plan" | grep -Fxq 'T|cerebellum|it'; then
    echo "SELF-TEST FAILED: a cerebellum src change did not select the whole it target" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a cerebellum src change runs every source scan in suite it"

  # The same holds for every crate with an `it` target: cerebellum-core's keeps
  # the crate free of plane identifiers, and once missed a test renamed in src/.
  core_scan_plan="$(plan_for_files 'crates/cerebellum-core/src/engram_catalog.rs' "$metadata")"
  if ! printf '%s\n' "$core_scan_plan" | grep -Fxq 'T|cerebellum-core|it'; then
    echo "SELF-TEST FAILED: a cerebellum-core src change did not select its it target" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a cerebellum-core src change runs its it target"

  # The control: a change outside cerebellum must not schedule cerebellum's `it`
  # target, which shows the rule above follows package selection and is not a
  # blanket run.
  core_plan="$(plan_for_files 'crates/cerebellum-core/src/private_fs.rs' "$metadata")"
  if printf '%s\n' "$core_plan" | grep -Fxq 'T|cerebellum|it'; then
    echo "SELF-TEST FAILED: a cerebellum-core-only change scheduled cerebellum's it target" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a change outside cerebellum leaves its it target to the mandatory modules"

  if plan_for_files '' "$metadata" >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: an empty diff was accepted" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: an empty diff is refused"
  exit 0
fi

if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
  echo "fast gate: base ref '$base' does not resolve to a commit" >&2
  exit 2
fi
changed_files="$(
  {
    git diff --name-only --no-renames "$base"
    git ls-files --others --exclude-standard
  } | sort -u
)"
if [ -z "$changed_files" ]; then
  echo "fast gate: refusing to pass an empty diff against '$base'" >&2
  exit 2
fi

plan="$(plan_for_files "$changed_files" "$metadata")"
packages=()
lib_packages=()
suites=()
all_suites=()
while IFS='|' read -r kind first second; do
  case "$kind" in
    P) packages+=("$first") ;;
    L) lib_packages+=("$first") ;;
    T) suites+=("$first:$second") ;;
    S) all_suites+=("$first:$second") ;;
  esac
done <<< "$plan"

if [ "$part" = mac ]; then
  select_mac_plan
fi

# Share the full gate's lock: Cargo test binaries and build artifacts are not
# safe to drive from two gates against the same target directory at once.
gate_target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
mkdir -p "$gate_target_dir"
gate_lock="$gate_target_dir/rust-test-gate.lock"
source "$repo_root/scripts/lib/gate-lock.sh"
acquire_gate_lock "$gate_lock"
static_dir="$(mktemp -d "$gate_target_dir/fast-gate.XXXXXX")"
static_pids=()
static_logs=()
phase_failed=0
not_verified=()
lib_test_options=()
for package in "${lib_packages[@]-}"; do
  if [ "$package" = cerebellum ]; then
    configure_lib_tests
  fi
done
release_lock() {
  local pid
  for pid in "${static_pids[@]+${static_pids[@]}}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$static_dir"
}
source "$repo_root/scripts/lib/fail-closed-exit.sh"
trap 'fail_closed_exit release_lock' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP QUIT

if printf '%s\n' "$plan" | grep -Fxq 'A|shell-exit-traps'; then
  start_static_phase "nounset scripts fail closed on EXIT" check_shell_exit_traps
fi

if [ "$part" = mac ]; then
  start_static_phase "source file size limit" \
    bash -c 'scripts/file-size-check.test.sh && scripts/file-size-check.sh'
fi

if [ "$part" = linux ]; then
start_static_phase "module wiring: scripts/module-wiring-gate.sh" ./scripts/module-wiring-gate.sh
# The full gate's test-code source scans take seconds and catch defects no
# compiler or test sees (a ck-* spawn from a test went unnoticed for days
# because only the full gate ran this). Each scan first proves it detects its
# planted offenders, then scans the tree.
start_static_phase "no test journals to the operator's disk" \
  bash -c 'scripts/lib/durable-journal-scan.test.sh >/dev/null && python3 scripts/lib/durable-journal-scan.py .'
start_static_phase "no test requests macOS permissions" \
  bash -c 'scripts/lib/mac-permission-request-scan.test.sh >/dev/null && python3 scripts/lib/mac-permission-request-scan.py .'
start_static_phase "test and script ck-* executions use ckdev names" \
  bash -c 'scripts/lib/ckdev-naming-scan.test.sh >/dev/null && python3 scripts/lib/ckdev-naming-scan.py .'
start_static_phase "only allowlisted .cortexkit paths are tracked" \
  bash -c 'scripts/check-cortexkit-layout.test.sh >/dev/null && scripts/check-cortexkit-layout.sh'
# This proof builds format_versions, so it must not overlap another Cargo phase.
run_serial_phase "format-floor gate proofs: scripts/lib/format-floor-gate.test.sh" scripts/lib/format-floor-gate.test.sh

run_serial_phase "cargo fmt --all -- --check" cargo fmt --all -- --check

if [ "${#packages[@]}" -gt 0 ]; then
  clippy_args=(--locked)
  for package in "${packages[@]}"; do clippy_args+=(-p "$package"); done
  clippy_args+=(--all-targets --quiet -- -D warnings)
  run_serial_phase "cargo clippy --locked ${packages[*]} --all-targets -- -D warnings" cargo clippy "${clippy_args[@]}"
else
  run_serial_phase "cargo clippy --locked --workspace --all-targets -- -D warnings" \
    cargo clippy --locked --workspace --all-targets --quiet -- -D warnings
fi

# Cross-check x86_64 Windows tests and examples too: the Linux build server can
# compile ring using its Windows GNU C toolchain. ARM64 stays default-only.
run_serial_phase "cargo clippy --locked --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings" \
  cargo clippy --locked --workspace --all-targets --target x86_64-pc-windows-gnu --quiet -- -D warnings
if [ -d "$(rustc --print target-libdir --target aarch64-pc-windows-gnullvm 2>/dev/null)" ]; then
  run_serial_phase "cargo clippy --locked --workspace --target aarch64-pc-windows-gnullvm -- -D warnings" \
    cargo clippy --locked --workspace --target aarch64-pc-windows-gnullvm --quiet -- -D warnings
else
  echo "NOT VERIFIED: aarch64-pc-windows-gnullvm not installed"
  not_verified+=("aarch64-pc-windows-gnullvm not installed")
fi
fi

if [ "$part" = mac ] && ! run_mac_clippy; then
  phase_failed=1
  finish_gate
  exit 1
fi

if [ "${#lib_packages[@]}" -gt 0 ]; then
  test_args=(--locked)
  for package in "${lib_packages[@]}"; do test_args+=(-p "$package"); done
  test_args+=(--lib "${lib_test_options[@]+${lib_test_options[@]}}")
  lib_log="$static_dir/lib-tests.log"
  run_serial_phase "cargo test --locked ${lib_packages[*]} --lib" \
    run_teed "$lib_log" "$repo_root/scripts/lib/gate-cargo-test.sh" "${test_args[@]}"
  record_skipped_tests "$lib_log" "library tests"
else
  echo "==> SKIP: touched-package --lib tests (no changed package with a library target)"
fi

is_desk_suite() {
  local wanted="$1" suite
  for suite in "${desk_suites[@]}"; do
    [ "$suite" = "$wanted" ] && return 0
  done
  return 1
}

# Run a command with its standard output also copied to a log, keeping the
# command's own exit status.
run_teed() {
  local log="$1"
  shift
  "$@" | tee "$log"
  return "${PIPESTATUS[0]}"
}

suite_will_run() {
  local wanted="$1" suite
  if [ "${#suites[@]}" -eq 0 ]; then
    return 1
  fi
  for suite in "${suites[@]}"; do
    [ "$suite" = "$wanted" ] && return 0
  done
  return 1
}

if [ "$part" = linux ]; then
# The `it` target contains catalog/schema checks, a source scan enforcing that
# only launch_nonce.rs reads the launch secret, and a scan that rejects shipped
# code which writes runtime output to stdout or stderr. Run it even when the diff
# is elsewhere; if the touched-suite plan includes it, avoid scheduling it twice.
if suite_will_run "cerebellum:it"; then
  run_serial_phase "cargo test --locked -p cerebellum --test it (changed suite)" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --test it
  echo "==> RUN COVERAGE: mandatory catalog, launch-secret, and zero-prints checks are included in touched suite cerebellum:it"
else
  run_serial_phase "cargo test --locked -p cerebellum --test it tool_catalog::" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --test it tool_catalog::
  run_serial_phase "cargo test --locked -p cerebellum --test it one_launch_nonce_reader::" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --test it one_launch_nonce_reader::
  run_serial_phase "cargo test --locked -p cerebellum --test it no_runtime_output::" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --test it no_runtime_output::
  echo "==> SKIP: remaining tests in cerebellum:it (no source/module path changed; the mandatory modules above ran)"
fi

if suite_will_run "cerebellum:format_floor"; then
  run_serial_phase "cargo test --locked -p cerebellum --test format_floor (changed suite)" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --test format_floor
  echo "==> RUN COVERAGE: mandatory format_floor integration tests are included in touched suite cerebellum:format_floor"
else
  run_serial_phase "cargo test --locked -p cerebellum --test format_floor" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --test format_floor
fi

# If cerebellum was not touched, run its schema-contract tests and the frozen
# catalog-byte fingerprint separately. A full cerebellum --lib run above already
# includes both when that package changed.
cerebellum_touched=0
for package in "${packages[@]-}"; do
  [ "$package" = cerebellum ] && cerebellum_touched=1
done
if [ "$cerebellum_touched" -eq 1 ]; then
  echo "==> RUN COVERAGE: mandatory flat-tools fingerprint tests are included in cerebellum --lib tests"
else
  run_serial_phase "cargo test --locked -p cerebellum --lib flat_tools" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --lib flat_tools
  run_serial_phase "cargo test --locked -p cerebellum --lib catalog_preserves_flat_definition_bytes" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum --lib catalog_preserves_flat_definition_bytes
  echo "==> SKIP: remaining cerebellum --lib tests (the package was unchanged)"
fi
# If cerebellum-core was not touched, the format_floor and journal filters below
# still exercise rollback floors and the journal's on-disk format checks.
core_touched=0
for package in "${lib_packages[@]-}"; do
  [ "$package" = cerebellum-core ] && core_touched=1
done
if [ "$core_touched" -eq 1 ]; then
  echo "==> RUN COVERAGE: format-floor and journal-format unit tests are included in touched cerebellum-core --lib tests"
else
  run_serial_phase "cargo test --locked -p cerebellum-core --lib format_floor" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum-core --lib format_floor
  run_serial_phase "cargo test --locked -p cerebellum-core --lib journal" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p cerebellum-core --lib journal
  echo "==> SKIP: remaining cerebellum-core --lib tests (the package was unchanged)"
fi
fi

if [ "${#suites[@]}" -gt 0 ]; then
  for suite in "${suites[@]}"; do
    if [ "$part" = linux ] && { [ "$suite" = "cerebellum:it" ] || [ "$suite" = "cerebellum:format_floor" ]; }; then
      continue
    fi
    package="${suite%%:*}"
    target="${suite#*:}"
    if [ "$part" = linux ] && [ "$package" = cerebellum-macos ]; then
      echo "==> SKIP: $suite (macOS-only; belongs to --part mac)"
      continue
    fi
    if [ "${vm:-0}" -eq 1 ] && is_vm_local_only_suite "$suite"; then
      echo "==> SKIP: $suite (no window-server session in the macOS VM; local only)"
      not_verified+=("$suite not executed in the macOS VM (no window-server session; run it locally: bash scripts/fast-gate.sh --part mac --base $base)")
      continue
    fi
    if is_desk_suite "$suite"; then
      log="$static_dir/desk-$package-$target.log"
      run_serial_phase "CEREBELLUM_DESK_TESTS=1 CEREBELLUM_DESK_TEST_SKIP_OK=1 cargo test --locked -p $package --test $target" \
        run_teed "$log" env CEREBELLUM_DESK_TESTS=1 CEREBELLUM_DESK_TEST_SKIP_OK=1 "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p "$package" --test "$target"
      reason="$(desk_skip_reason < "$log")"
      if [ "$(uname -s)" != Darwin ]; then
        # Off macOS the target builds to an empty program that prints nothing.
        reason="AppKit exists only on macOS, so no preview panel was shown"
      fi
      if [ -n "$reason" ]; then
        not_verified+=("$target skipped ($reason)")
      fi
    else
      log="$static_dir/test-$package-$target.log"
      run_serial_phase "cargo test --locked -p $package --test $target" \
        run_teed "$log" "$repo_root/scripts/lib/gate-cargo-test.sh" --locked -p "$package" --test "$target"
      record_skipped_tests "$log" "$package:$target"
    fi
  done
fi

if [ "${#all_suites[@]}" -gt 0 ]; then
  skipped_suites=()
  for suite in "${all_suites[@]}"; do
    if [ "$suite" = "cerebellum:it" ] || [ "$suite" = "cerebellum:format_floor" ] || suite_will_run "$suite"; then
      continue
    fi
    skipped_suites+=("$suite")
  done
  if [ "${#skipped_suites[@]}" -gt 0 ]; then
    echo "==> SKIP: integration suites without changed source/module paths: ${skipped_suites[*]}"
  fi
fi

# Source-check logs are replayed in launch order, never interleaved with Cargo.
wait_static_phases
finish_gate
finished=1
