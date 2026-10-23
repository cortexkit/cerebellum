#!/usr/bin/env bash
# mutations.sh must run only the ckdev-mutate installed in this checkout's own
# target/tools root. ~/.cargo/bin and PATH are shared with every other
# repository on the machine, so a runner found there must never decide the
# replay, even when it claims the pinned version. Drives a copy of the real
# script in a scratch checkout with fake runners; nothing is compiled.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch_root="${CARGO_TARGET_DIR:-$root/target}/scratch"
real_mutate="${CARGO_TARGET_DIR:-$root/target}/tools/bin/ckdev-mutate"
mkdir -p "$scratch_root"
scratch="$(mktemp -d "$scratch_root/mutations-test.XXXXXX")"
# Fixtures have their own install roots, independent of the caller's build cache.
unset CARGO_TARGET_DIR
trap 'rm -rf "$scratch"' EXIT
failures=0
checks=14

pinned_version="0.12.10"
pinned_revision="73af60d143d64fe874606ce73f22e02cb356a4bb"
other_revision="0000000000000000000000000000000000000000"

# write_runner DIR NAME VERSION: a fake ckdev-mutate that reports VERSION and
# appends "NAME ARGS" to the shared call log for every other invocation.
write_runner() {
  mkdir -p "$1"
  cat > "$1/ckdev-mutate" <<FAKE
#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then
  echo "ckdev-mutate $3"
  exit 0
fi
echo "$2 \$*" >> "\$CALL_LOG"
FAKE
  chmod +x "$1/ckdev-mutate"
}

# write_record ROOT VERSION REVISION: the .crates2.json cargo install --root
# leaves behind for cortexkit-mutate built from REVISION.
write_record() {
  mkdir -p "$1"
  cat > "$1/.crates2.json" <<JSON
{"installs":{"cortexkit-mutate $2 (git+https://github.com/cortexkit/commons?rev=$3#$3)":{"bins":["ckdev-mutate"]}}}
JSON
}

# run_case NAME EXPECTED_STATUS SETUP [ARGS...]: build a fresh scratch checkout
# holding a copy of mutations.sh, let SETUP install runners into it, then run
# mutations.sh with ARGS (default --full-only) with a decoy runner first on PATH
# and in CARGO_HOME.
run_case() {
  local name="$1" expected="$2" setup="$3"
  shift 3
  [ "$#" -gt 0 ] || set -- --full-only
  local mode="$1" check_args="--strict"
  case "$*" in
    *--anchors-only*) check_args="--anchors-only" ;;
    *--platform*) check_args="--strict --platform ${@: -1}" ;;
  esac
  local case_dir="$scratch/$name"
  local repo="$case_dir/repo"
  mkdir -p "$repo/scripts/lib" "$repo/mutations.d"
  cp "$root/scripts/mutations.sh" "$repo/scripts/mutations.sh"
  cp "$root/scripts/lib/mutation-catalogue.py" "$repo/scripts/lib/"
  printf '[[control]]\nid = "fixture"\n' >"$repo/mutations.d/rows.toml"
  # The tree check guards the real checkout; this scratch copy has nothing to check.
  printf '#!/usr/bin/env bash\nexit 0\n' > "$repo/scripts/check-mutation-tree.sh"
  chmod +x "$repo/scripts/check-mutation-tree.sh"
  : > "$case_dir/calls"
  "$setup" "$case_dir" "$repo"
  env CALL_LOG="$case_dir/calls" CARGO_HOME="$case_dir/cargo-home" \
    PATH="$case_dir/path-bin:$PATH" \
    "$repo/scripts/mutations.sh" "$@" >"$case_dir/out" 2>&1
  local status=$?
  local problem=""
  [ "$status" = "$expected" ] || problem="exit $status, expected $expected"
  if grep -Eq '^(path|cargo-home) ' "$case_dir/calls"; then
    problem="${problem:+$problem; }a shared runner was invoked"
  fi
  if [ "$expected" = 0 ]; then
    if ! grep -qx "private check --catalogue mutations.d $check_args" "$case_dir/calls"; then
      problem="${problem:+$problem; }the private runner did not check the catalogue"
    fi
    if [ "$mode" = "--check-only" ]; then
      if grep -q '^private run ' "$case_dir/calls"; then
        problem="${problem:+$problem; }a check-only run replayed rows"
      fi
    elif ! grep -qx 'private run --catalogue mutations.d --all' "$case_dir/calls"; then
      problem="${problem:+$problem; }the private runner did not run the replay"
    fi
  elif [ "$setup" = setup_uncovered ]; then
    grep -qF 'rows not covered by linux or macos: windows-only' "$case_dir/out" || problem="coverage refusal missing"
    [ ! -s "$case_dir/calls" ] || problem="uncovered row reached runner"
  elif [ "$setup" = setup_private_pinned ] && [ "$expected" = 2 ]; then
    [ ! -s "$case_dir/calls" ] || problem="invalid options reached runner"
  elif ! grep -qF "cargo install --locked --root \"$repo/target/tools\" --git https://github.com/cortexkit/commons --rev $pinned_revision cortexkit-mutate" "$case_dir/out"; then
    problem="${problem:+$problem; }the refusal did not name the install command"
  fi
  if [ -z "$problem" ]; then
    echo "ok $name"
  else
    echo "FAIL $name: $problem"
    sed 's/^/    /' "$case_dir/out" "$case_dir/calls"
    failures=$((failures + 1))
  fi
}

# Decoys every case gets: an unpinned runner first on PATH, and a runner in
# CARGO_HOME whose install record matches the pin exactly, as a shared
# ~/.cargo would after the right install.
decoys() {
  write_runner "$1/path-bin" path 0.12.4
  write_runner "$1/cargo-home/bin" cargo-home "$pinned_version"
  write_record "$1/cargo-home" "$pinned_version" "$pinned_revision"
}
setup_private_missing() {
  decoys "$1"
}
setup_private_pinned() {
  decoys "$1"
  write_runner "$2/target/tools/bin" private "$pinned_version"
  write_record "$2/target/tools" "$pinned_version" "$pinned_revision"
}
setup_private_wrong_version() {
  decoys "$1"
  write_runner "$2/target/tools/bin" private 0.12.4
  write_record "$2/target/tools" 0.12.4 "$pinned_revision"
}
setup_private_wrong_revision() {
  decoys "$1"
  write_runner "$2/target/tools/bin" private "$pinned_version"
  write_record "$2/target/tools" "$pinned_version" "$other_revision"
}
setup_private_unrecorded() {
  decoys "$1"
  write_runner "$2/target/tools/bin" private "$pinned_version"
}
setup_uncovered() {
  setup_private_pinned "$@"
  printf '[[control]]\nid = "windows-only"\nplatforms = ["windows"]\n' >"$2/mutations.d/rows.toml"
}

# Without a private runner the replay refuses, even though PATH and CARGO_HOME
# both offer one; it never falls back to either.
run_case private_missing_ignores_shared_runners 2 setup_private_missing
# The private pinned runner decides: the wrong-version runner on PATH is never
# consulted, and the replay runs through the private one.
run_case private_pinned_runs_despite_wrong_path_runner 0 setup_private_pinned
# The private root's own version and install record still gate the runner.
run_case private_wrong_version_refuses 2 setup_private_wrong_version
run_case private_wrong_revision_refuses 2 setup_private_wrong_revision
run_case private_without_install_record_refuses 2 setup_private_unrecorded
# A landing gate validates the catalogue without replaying any row, and still
# only through the private pinned runner.
run_case check_only_validates_without_replaying 0 setup_private_pinned --check-only
run_case check_only_still_refuses_a_missing_private_runner 2 setup_private_missing --check-only
run_case anchors_only_checks_without_strict_or_replay 0 setup_private_pinned --check-only --anchors-only
run_case platform_checks_strictly_without_replay 0 setup_private_pinned --check-only --platform linux
run_case macos_platform_is_forwarded 0 setup_private_pinned --check-only --platform macos
run_case anchors_only_requires_check_only 2 setup_private_pinned --anchors-only
run_case platform_requires_check_only 2 setup_private_pinned --platform linux
run_case anchors_only_conflicts_with_platform 2 setup_private_pinned --check-only --anchors-only --platform linux

scoped_invalid_row() {
  local repo="$scratch/scoped/repo" status
  mkdir -p "$repo/scripts/lib" "$repo/mutations.d"
  cp "$root/scripts/mutations.sh" "$repo/scripts/"
  cp "$root/scripts/lib/mutation-check-plan.py" "$repo/scripts/lib/"
  cp "$root/scripts/lib/mutation-catalogue.py" "$repo/scripts/lib/"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$repo/scripts/check-mutation-tree.sh"
  chmod +x "$repo/scripts/check-mutation-tree.sh"
  setup_private_pinned "$scratch/scoped" "$repo"
  cat >>"$repo/target/tools/bin/ckdev-mutate" <<'FAKE'
if [ "$1" = check ] && [ "$2" = --catalogue ]; then
  if grep -q 'planted-invalid' "$3"; then
    echo 'strict check refused planted-invalid' >&2
    exit 7
  fi
fi
FAKE
  (
    cd "$repo" || exit 1
    git init -q
    git config user.email fast-gate-test@example.invalid
    git config user.name fast-gate-test
    printf '[[control]]\nid = "unchanged"\nfile = "guard.rs"\nold = "before"\nnew = "after"\n' >mutations.d/rows.toml
    git add mutations.d
    git commit -qm fixture
    cat >>mutations.d/rows.toml <<'ROW'

[[control]]
id = "planted-invalid"
guards = "a malformed row is rejected after diff selection"
file = "scripts/mutations.sh"
old = "set -euo pipefail"
new = "set -euo pipefail; :"
test_file = "scripts/mutations.sh"
runner = "command"
command = ["echo", "Ran 1 test", "{test}"]
test_count_pattern = "Ran {count} test"
expect_red = ["missing_test"]
ROW
    CALL_LOG="$scratch/scoped/calls" ./scripts/mutations.sh --check-only --diff HEAD >"$scratch/scoped/out" 2>&1
  )
  status=$?
  if [ "$status" -eq 7 ] &&
     grep -Fxq 'mutations: strict check selection: scoped 1' "$scratch/scoped/out" &&
     grep -Fxq 'strict check refused planted-invalid' "$scratch/scoped/out"; then
    echo 'ok scoped_check_refuses_a_planted_invalid_row'
  else
    echo "FAIL scoped_check_refuses_a_planted_invalid_row: exit $status, expected 7 and a scoped refusal"
    cat "$scratch/scoped/out"
    failures=$((failures + 1))
  fi
  if [ -x "$real_mutate" ]; then
    checks=$((checks + 1))
    cp "$real_mutate" "$repo/target/tools/bin/ckdev-mutate"
    (cd "$repo" && ./scripts/mutations.sh --check-only --diff HEAD) >"$scratch/scoped/real-out" 2>&1
    status=$?
    # This row deliberately lacks list_command. The real runner, not a schema
    # imitation in the planner, must still reject it under --strict after selection.
    if [ "$status" -eq 2 ] &&
       grep -Fxq 'mutations: strict check selection: scoped 1' "$scratch/scoped/real-out" &&
       grep -Fq 'command row has no list_command: planted-invalid' "$scratch/scoped/real-out"; then
      echo 'ok scoped_real_strict_check_refuses_a_planted_invalid_row'
    else
      echo "FAIL scoped_real_strict_check_refuses_a_planted_invalid_row: exit $status, expected a strict schema refusal"
      cat "$scratch/scoped/real-out"
      failures=$((failures + 1))
    fi
  else
    echo 'SKIP: real pinned strict-check fixture (private runner is not installed)'
  fi
}
scoped_invalid_row

# Coverage is catalogue-wide, including when diff selection would find no rows.
checks=$((checks + 1))
run_case windows_only_is_not_covered 2 setup_uncovered --check-only --anchors-only
checks=$((checks + 1))
run_case coverage_precedes_diff_selection 2 setup_uncovered --check-only --platform linux --diff nonexistent-base

echo "mutations wrapper tests: $checks checks, $failures failures"
[ "$failures" = 0 ]
