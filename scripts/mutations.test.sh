#!/usr/bin/env bash
# mutations.sh must run only the ckdev-mutate installed in this checkout's own
# target/tools root. ~/.cargo/bin and PATH are shared with every other
# repository on the machine, so a runner found there must never decide the
# replay, even when it claims the pinned version. Drives a copy of the real
# script in a scratch checkout with fake runners; nothing is compiled.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# macOS's TMPDIR ends in a slash, so the joined path holds "//". mutations.sh
# prints its root as `pwd` spells it, with single slashes, so spell the scratch
# root the same way or the refusal cases never find the path they expect.
scratch="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/mutations-test.XXXXXX")" && pwd)"
trap 'rm -rf "$scratch"' EXIT
failures=0

pinned_version="0.12.3"
pinned_revision="649d5f126c3b7da49e3019407ea1a94652d32eea"
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

# run_case NAME EXPECTED_STATUS SETUP [MODE]: build a fresh scratch checkout
# holding a copy of mutations.sh, let SETUP install runners into it, then run
# mutations.sh in MODE (default --full-only) with a decoy runner first on PATH
# and in CARGO_HOME.
run_case() {
  local name="$1" expected="$2" setup="$3" mode="${4:---full-only}"
  local case_dir="$scratch/$name"
  local repo="$case_dir/repo"
  mkdir -p "$repo/scripts" "$repo/mutations.d"
  cp "$root/scripts/mutations.sh" "$repo/scripts/mutations.sh"
  # The tree check guards the real checkout; this scratch copy has nothing to check.
  printf '#!/usr/bin/env bash\nexit 0\n' > "$repo/scripts/check-mutation-tree.sh"
  chmod +x "$repo/scripts/check-mutation-tree.sh"
  : > "$case_dir/calls"
  "$setup" "$case_dir" "$repo"
  env CALL_LOG="$case_dir/calls" CARGO_HOME="$case_dir/cargo-home" \
    PATH="$case_dir/path-bin:/usr/bin:/bin" \
    "$repo/scripts/mutations.sh" "$mode" >"$case_dir/out" 2>&1
  local status=$?
  local problem=""
  [ "$status" = "$expected" ] || problem="exit $status, expected $expected"
  if grep -Eq '^(path|cargo-home) ' "$case_dir/calls"; then
    problem="${problem:+$problem; }a shared runner was invoked"
  fi
  if [ "$expected" = 0 ]; then
    if ! grep -qx 'private check --catalogue mutations.d --strict' "$case_dir/calls"; then
      problem="${problem:+$problem; }the private runner did not check the catalogue"
    fi
    if [ "$mode" = "--check-only" ]; then
      if grep -q '^private run ' "$case_dir/calls"; then
        problem="${problem:+$problem; }a check-only run replayed rows"
      fi
    elif ! grep -qx 'private run --catalogue mutations.d --all' "$case_dir/calls"; then
      problem="${problem:+$problem; }the private runner did not run the replay"
    fi
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

[ "$failures" = 0 ]
