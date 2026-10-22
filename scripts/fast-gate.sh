#!/usr/bin/env bash
# Narrow landing checks for the files changed since a base revision.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

base="${FAST_GATE_BASE:-origin/main}"
self_test=0
mutations=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base)
      [ "$#" -ge 2 ] || { echo "usage: $0 [--base REF] [--self-test] [--mutations]" >&2; exit 2; }
      base="$2"
      shift 2
      ;;
    --self-test)
      self_test=1
      shift
      ;;
    --mutations)
      mutations=1
      shift
      ;;
    -h|--help)
      echo "usage: $0 [--base REF] [--self-test] [--mutations]"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      echo "usage: $0 [--base REF] [--self-test] [--mutations]" >&2
      exit 2
      ;;
  esac
done

./scripts/check-mutation-tree.sh

metadata="$(cargo metadata --locked --format-version 1 --no-deps)"

plan_for_files() {
  FAST_GATE_METADATA="$metadata" FAST_GATE_FILES="$1" python3 - <<'PY'
import json
import os
from pathlib import Path
import sys

metadata = json.loads(os.environ["FAST_GATE_METADATA"])
files = [line for line in os.environ["FAST_GATE_FILES"].splitlines() if line]
if not files:
    print("refusing to plan an empty diff", file=sys.stderr)
    sys.exit(2)

root = Path.cwd().resolve()
packages = metadata["packages"]
workspace_wide = any(
    path in {"Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml"}
    or path.startswith(".cargo/")
    for path in files
)
selected_packages = set()
selected_suites = set()

# Some sources live at the repo root but are compiled into a crate with
# include_str!, so a path-containment match never selects that crate. Map them
# explicitly, or a change to the data slips past the test that parses it.
root_file_packages = {"engram-catalog.json": "cerebellum-core"}
for path in files:
    owner = root_file_packages.get(path)
    if owner:
        selected_packages.add(owner)

for package in packages:
    manifest = Path(package["manifest_path"]).resolve()
    package_root = manifest.parent
    if workspace_wide:
        selected_packages.add(package["name"])
        continue
    for relative in files:
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(package_root)
        except ValueError:
            continue
        selected_packages.add(package["name"])
        if not candidate.is_relative_to(package_root / "tests"):
            continue
        test_targets = [target for target in package["targets"] if "test" in target["kind"]]
        mapped = set()
        for target in test_targets:
            source = Path(target["src_path"]).resolve()
            if candidate == source:
                mapped.add(target["name"])
            elif source.name == "main.rs" and candidate.is_relative_to(source.parent):
                mapped.add(target["name"])
        if not mapped:
            # An unrecognized helper, fixture, or module path may be shared by
            # several test targets, so run every integration suite in its crate.
            mapped.update(target["name"] for target in test_targets)
        selected_suites.update((package["name"], suite) for suite in mapped)

# Each crate's consolidated `it` target holds the source scans over that crate's
# shipped code. cerebellum's covers the single launch-secret reader, zero
# runtime prints, declared launch-path outcome words, the one lease clock,
# private file writes and more; cerebellum-core's keeps the crate free of plane
# identifiers. Each scan reads files under src/, so a change there can break one
# while no test file changed, and a hand-picked subset of modules misses
# whichever scan reads the changed file. So whenever a package is selected, run
# its whole `it` target. cerebellum's takes about 15 s once built, and the gate
# builds it either way.
for name in selected_packages:
    package = next(package for package in packages if package["name"] == name)
    if any(
        target["name"] == "it" and "test" in target["kind"]
        for target in package["targets"]
    ):
        selected_suites.add((name, "it"))

for name in sorted(selected_packages):
    print(f"P|{name}")
    package = next(package for package in packages if package["name"] == name)
    if any("lib" in target["kind"] for target in package["targets"]):
        print(f"L|{name}")
for package, suite in sorted(selected_suites):
    print(f"T|{package}|{suite}")
for package in packages:
    for target in package["targets"]:
        if "test" in target["kind"]:
            print(f"S|{package['name']}|{target['name']}")
for required in (
    "tool-catalog-and-schema-bytes",
    "flat-tools-fingerprints",
    "format-floor-and-journal-formats",
    "launch-secret-single-reader",
    "zero-prints",
    "module-wiring",
):
    print(f"A|{required}")
PY
}

if [ "$self_test" -eq 1 ]; then
  suite_plan="$(plan_for_files 'crates/cerebellum/tests/it/tool_catalog.rs')"
  if ! printf '%s\n' "$suite_plan" | grep -Fxq 'T|cerebellum|it'; then
    echo "SELF-TEST FAILED: a planted tests/it source path did not select suite it" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a planted tests/it source path selects suite it"

  flat_plan="$(plan_for_files 'crates/cerebellum/src/flat_tools.rs')"
  if ! printf '%s\n' "$flat_plan" | grep -Fxq 'P|cerebellum' || \
     ! printf '%s\n' "$flat_plan" | grep -Fxq 'A|tool-catalog-and-schema-bytes' || \
     ! printf '%s\n' "$flat_plan" | grep -Fxq 'A|flat-tools-fingerprints'; then
    echo "SELF-TEST FAILED: flat_tools.rs did not select its package and catalog checks" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a planted flat_tools.rs change keeps catalog and fingerprint checks"

  catalog_plan="$(plan_for_files 'engram-catalog.json')"
  if ! printf '%s\n' "$catalog_plan" | grep -Fxq 'P|cerebellum-core' || \
     ! printf '%s\n' "$catalog_plan" | grep -Fxq 'L|cerebellum-core'; then
    echo "SELF-TEST FAILED: engram-catalog.json did not select cerebellum-core --lib" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a root engram-catalog.json change runs cerebellum-core --lib"

  # A shipped-source change with no test file in the diff must still run every
  # source scan in cerebellum's `it` target, which reads src/ directly.
  scan_plan="$(plan_for_files 'crates/cerebellum/src/browser_session.rs')"
  if ! printf '%s\n' "$scan_plan" | grep -Fxq 'T|cerebellum|it'; then
    echo "SELF-TEST FAILED: a cerebellum src change did not select the whole it target" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a cerebellum src change runs every source scan in suite it"

  # The same holds for every crate with an `it` target: cerebellum-core's keeps
  # the crate free of plane identifiers, and once missed a test renamed in src/.
  core_scan_plan="$(plan_for_files 'crates/cerebellum-core/src/engram_catalog.rs')"
  if ! printf '%s\n' "$core_scan_plan" | grep -Fxq 'T|cerebellum-core|it'; then
    echo "SELF-TEST FAILED: a cerebellum-core src change did not select its it target" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a cerebellum-core src change runs its it target"

  # The control: a change outside cerebellum must not schedule cerebellum's `it`
  # target, which shows the rule above follows package selection and is not a
  # blanket run.
  core_plan="$(plan_for_files 'crates/cerebellum-core/src/private_fs.rs')"
  if printf '%s\n' "$core_plan" | grep -Fxq 'T|cerebellum|it'; then
    echo "SELF-TEST FAILED: a cerebellum-core-only change scheduled cerebellum's it target" >&2
    exit 1
  fi
  echo "SELF-TEST PASSED: a change outside cerebellum leaves its it target to the mandatory modules"

  if plan_for_files '' >/dev/null 2>&1; then
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
    git diff --name-only --diff-filter=ACMR "$base"
    git ls-files --others --exclude-standard
  } | sort -u
)"
if [ -z "$changed_files" ]; then
  echo "fast gate: refusing to pass an empty diff against '$base'" >&2
  exit 2
fi

plan="$(plan_for_files "$changed_files")"
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

# Share the full gate's lock: Cargo test binaries and build artifacts are not
# safe to drive from two gates against the same target directory at once.
gate_target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
mkdir -p "$gate_target_dir"
gate_lock="$gate_target_dir/rust-test-gate.lock"
if ! mkdir "$gate_lock" 2>/dev/null; then
  holder="$(cat "$gate_lock/holder" 2>/dev/null || true)"
  echo "fast gate: another gate owns the shared Cargo target lock${holder:+ (pid $holder)}" >&2
  echo "nothing has been verified" >&2
  exit 2
fi
printf '%s\n' "$$" > "$gate_lock/holder"
static_dir="$(mktemp -d "$gate_target_dir/fast-gate.XXXXXX")"
static_pids=()
static_logs=()
release_lock() {
  rm -rf "$static_dir" "$gate_lock"
}
trap release_lock EXIT INT TERM HUP QUIT

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

start_static_phase() {
  local label="$1"
  shift
  local log="$static_dir/${#static_pids[@]}.log"
  static_logs+=("$log")
  ( run_phase "$label" "$@" ) >"$log" 2>&1 &
  static_pids+=("$!")
}

wait_static_phases() {
  local failed=0 index
  for index in "${!static_pids[@]}"; do
    if wait "${static_pids[$index]}"; then
      :
    else
      failed=1
    fi
    cat "${static_logs[$index]}"
  done
  if [ "$failed" -ne 0 ]; then
    echo "FAST GATE FAILED: one or more independent source checks failed" >&2
    return 1
  fi
}

start_static_phase "module wiring: scripts/module-wiring-gate.sh" ./scripts/module-wiring-gate.sh
start_static_phase "format-floor gate proofs: scripts/lib/format-floor-gate.test.sh" scripts/lib/format-floor-gate.test.sh
wait_static_phases

run_phase "cargo fmt --all -- --check" cargo fmt --all -- --check

if [ "${#packages[@]}" -gt 0 ]; then
  clippy_args=(--locked)
  for package in "${packages[@]}"; do clippy_args+=(-p "$package"); done
  clippy_args+=(--all-targets --quiet -- -D warnings)
  run_phase "cargo clippy --locked ${packages[*]} --all-targets -- -D warnings" cargo clippy "${clippy_args[@]}"
else
  echo "==> SKIP: package clippy (no changed file maps to a Cargo package)"
fi

if [ "${#lib_packages[@]}" -gt 0 ]; then
  test_args=(--locked)
  for package in "${lib_packages[@]}"; do test_args+=(-p "$package"); done
  test_args+=(--lib)
  run_phase "cargo test --locked ${lib_packages[*]} --lib" cargo test "${test_args[@]}"
else
  echo "==> SKIP: touched-package --lib tests (no changed package with a library target)"
fi

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

# The `it` target contains catalog/schema checks, a source scan enforcing that
# only launch_nonce.rs reads the launch secret, and a scan that rejects shipped
# code which writes runtime output to stdout or stderr. Run it even when the diff
# is elsewhere; if the touched-suite plan includes it, avoid scheduling it twice.
if suite_will_run "cerebellum:it"; then
  run_phase "cargo test --locked -p cerebellum --test it (changed suite)" cargo test --locked -p cerebellum --test it
  echo "==> RUN COVERAGE: mandatory catalog, launch-secret, and zero-prints checks are included in touched suite cerebellum:it"
else
  run_phase "cargo test --locked -p cerebellum --test it tool_catalog::" cargo test --locked -p cerebellum --test it tool_catalog::
  run_phase "cargo test --locked -p cerebellum --test it one_launch_nonce_reader::" cargo test --locked -p cerebellum --test it one_launch_nonce_reader::
  run_phase "cargo test --locked -p cerebellum --test it no_runtime_output::" cargo test --locked -p cerebellum --test it no_runtime_output::
  echo "==> SKIP: remaining tests in cerebellum:it (no source/module path changed; the mandatory modules above ran)"
fi

if suite_will_run "cerebellum:format_floor"; then
  run_phase "cargo test --locked -p cerebellum --test format_floor (changed suite)" cargo test --locked -p cerebellum --test format_floor
  echo "==> RUN COVERAGE: mandatory format_floor integration tests are included in touched suite cerebellum:format_floor"
else
  run_phase "cargo test --locked -p cerebellum --test format_floor" cargo test --locked -p cerebellum --test format_floor
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
  run_phase "cargo test --locked -p cerebellum --lib flat_tools" cargo test --locked -p cerebellum --lib flat_tools
  run_phase "cargo test --locked -p cerebellum --lib catalog_preserves_flat_definition_bytes" cargo test --locked -p cerebellum --lib catalog_preserves_flat_definition_bytes
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
  run_phase "cargo test --locked -p cerebellum-core --lib format_floor" cargo test --locked -p cerebellum-core --lib format_floor
  run_phase "cargo test --locked -p cerebellum-core --lib journal" cargo test --locked -p cerebellum-core --lib journal
  echo "==> SKIP: remaining cerebellum-core --lib tests (the package was unchanged)"
fi

if [ "${#suites[@]}" -gt 0 ]; then
  for suite in "${suites[@]}"; do
    if [ "$suite" = "cerebellum:it" ] || [ "$suite" = "cerebellum:format_floor" ]; then
      continue
    fi
    package="${suite%%:*}"
    target="${suite#*:}"
    run_phase "cargo test --locked -p $package --test $target" cargo test --locked -p "$package" --test "$target"
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

if [ "$mutations" -eq 1 ]; then
  run_phase "narrow mutation replay against $base" ./scripts/mutations.sh --diff "$base" --narrow-only
elif grep -q '^mutations\.d/' <<< "$changed_files"; then
  # A catalogue row the runner refuses under --strict would stop every later
  # replay, and the anchor check above does not parse rows that strictly.
  run_phase "mutation catalogue --strict check (a catalogue file changed)" ./scripts/mutations.sh --check-only
else
  echo "==> SKIP: mutation catalogue --strict check (no catalogue file changed)"
fi

echo "FAST GATE PASSED: all selected phases are green"
