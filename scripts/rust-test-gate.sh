#!/usr/bin/env bash
# ck-cerebellum Rust test gate.
#
# This script is the definition of "verified" for this repository: CI runs it
# verbatim rather than restating its phases, so the desk and the runner cannot
# drift apart. Anything that belongs in the verification contract belongs here
# rather than in the workflow.
#
# Run from the repo root after any code change. The first phase is
# `cargo fmt -p <each member> -- --check`, so an unformatted commit fails the gate.
# Serialize cargo invocations (never parallel cargo): other workers share this
# machine and concurrent workspace builds have saturated it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Snapshot the tree before anything builds, so the final phase can attribute a
# change to the build rather than to uncommitted work the author already had.
tree_before_build="$(git status --porcelain)"

# Only one gate at a time on this checkout, enforced rather than requested.
#
# The header above used to ASK for serialized cargo invocations. A neighbouring
# project learned what a request is worth: three of its gates ran concurrently
# on one checkout and the losers blocked forever inside store opens, leaving
# test binaries alive for eight and a half hours and holding this machine at
# load 12-21 for a working day. Its per-test bound did not help, because the
# bound sat on one runner's lanes and the wedged children ran under the other.
#
# The lock is a directory because mkdir is atomic: two gates racing cannot both
# believe they hold it. A holder that died without cleaning up leaves a pid
# nobody can signal, so that case is reclaimed rather than blocking a machine
# on a corpse -- but a LIVE holder is refused by name, because waiting silently
# is how the eight-hour version began.
# Resolved rather than assumed to be "$repo_root/.git": IN A GIT WORKTREE THAT
# PATH IS A FILE, not a directory, so mkdir under it fails with "Not a
# directory" and the gate refuses to start. Every mason runs in a worktree, so
# the first version of this lock broke the gate for every worker while working
# perfectly here -- they fell back to running the phases by hand, which is
# honest and is not the gate. `--git-dir` resolves to the real directory in
# both layouts, and it is per-checkout in both, which is what the lock wants:
# a worktree has its own target directory, so it may hold its own gate.
GATE_LOCK="$(git -C "$repo_root" rev-parse --git-dir)/gate.lock"

acquire_gate_lock() {
  if mkdir "$GATE_LOCK" 2>/dev/null; then
    echo $$ > "$GATE_LOCK/holder"
    return 0
  fi
  local holder
  holder="$(cat "$GATE_LOCK/holder" 2>/dev/null || true)"
  if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
    echo "A gate is already running on this checkout (pid $holder)." >&2
    echo "Two gates on one checkout share a target directory and the same" >&2
    echo "single-writer test leases, so the second one can block indefinitely" >&2
    echo "rather than finish. Wait for that run, or stop it deliberately." >&2
    echo "Nothing has been verified." >&2
    exit 2
  fi
  echo "Reclaiming a gate lock left by pid ${holder:-unknown}, which is gone." >&2
  rm -rf "$GATE_LOCK"
  mkdir "$GATE_LOCK" || {
    echo "Could not take the gate lock after reclaiming it." >&2
    exit 2
  }
  echo $$ > "$GATE_LOCK/holder"
}

release_gate_lock() {
  [ -n "${GATE_LOCK:-}" ] && rm -rf "$GATE_LOCK"
}

acquire_gate_lock
trap release_gate_lock EXIT INT TERM HUP QUIT

# An upper bound on a single phase, so a test that waits on something which
# never arrives fails loudly instead of holding the machine until someone
# notices. Generous on purpose: the workspace suite has legitimately taken 39
# minutes on a saturated machine, and a bound that fires on a slow run teaches
# people to raise it rather than to read it.
GATE_PHASE_TIMEOUT_S="${GATE_PHASE_TIMEOUT_S:-3600}"

# Job control, so each phase becomes its own process group and the whole tree
# can be signalled. Killing only the direct child would leave cargo's test
# binaries running -- which is precisely the state this bound exists to end.
set -m

run_phase() {
  local label="$1"
  shift
  local started=$SECONDS
  echo "==> $label"

  "$@" &
  local phase_pid=$!
  local waited=0
  while kill -0 "$phase_pid" 2>/dev/null; do
    if [ "$waited" -ge "$GATE_PHASE_TIMEOUT_S" ]; then
      echo "" >&2
      echo "PHASE EXCEEDED ITS BOUND: $label" >&2
      echo "Ran for ${waited}s without finishing. A phase that does not end is" >&2
      echo "usually a test waiting on something that will never arrive, and it" >&2
      echo "holds this machine until someone notices by hand." >&2
      kill -TERM "-$phase_pid" 2>/dev/null || kill -TERM "$phase_pid" 2>/dev/null || true
      sleep 5
      kill -KILL "-$phase_pid" 2>/dev/null || kill -KILL "$phase_pid" 2>/dev/null || true
      echo "GATE FAILED: $label did not finish within ${GATE_PHASE_TIMEOUT_S}s" >&2
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  # `wait` on a finished job reports its exit status, which `set -e` cannot see
  # for a background child. Without this a failing phase would be reported ok.
  if ! wait "$phase_pid"; then
    echo "GATE FAILED: $label" >&2
    exit 1
  fi
  echo "    ok ($((SECONDS - started))s)"
}

# Phase 0: refuse to certify a tree in which a guard may still be deliberately
# broken. `scripts/mutate.sh` weakens a mechanism on purpose to see whether any
# test notices, and restores it afterwards -- but a hard kill runs no restore and
# prints nothing, leaving a broken guard in a file that still looks like source. The marker survives that kill, so the break announces itself here
# rather than passing review as ordinary code. This runs first because every
# later phase would be reporting on the mutated tree.
check_no_mutation_in_progress() {
  local marker
  marker="$(git rev-parse --git-dir)/mutation-in-progress"
  if [ -e "$marker" ]; then
    echo "    a mutation run did not confirm its restore:" >&2
    sed 's/^/    /' "$marker" >&2
    return 1
  fi
}

run_phase "no mutation left in the working tree" \
  check_no_mutation_in_progress

# Registry checksums and git revisions in Cargo.lock replace sibling source pins.
# Check every manifest, including target-specific and test dependencies, before
# Cargo runs so an external checkout can never become an implicit build input.
run_phase "path dependency guard planted-violation self-tests" \
  scripts/check-repo-path-deps.sh --self-test
run_phase "repository-contained path dependencies" \
  scripts/check-repo-path-deps.sh

# Phase 0c: no test may build a plane that journals to the operator's disk.
#
# The journal path derives from HOME, which is process-global, so a test cannot
# be isolated by pointing it somewhere else without affecting every test running
# beside it. Isolation is therefore opt-in at construction -- and an opt-in that
# a test can forget is one that will be forgotten.
#
# This is not hypothetical. Wiring the journal with a durable DEFAULT sent the
# wire tests at real audit data: a gate run left three genuine records in a
# directory enrolled for fleet backup, and every test passed. Nothing in the
# suite could notice, because the suite does not look outside the repository.
#
# Test code is found structurally by scripts/lib/durable-journal-scan.py:
# every file under crates/*/tests/, and under crates/*/src/ every item behind
# a test-enabling attribute (`#[cfg(test)]` modules, including out-of-line
# ones, `#[test]` and `#[tokio::test]` functions) plus functions named for
# tests. Source is tokenized, so comments and strings never match and line
# breaks cannot hide a call. What it looks for: the durable plane
# constructors, naming `JournalPersistence::Durable` outright, and the openers
# that always take the operator's own files -- the computer audit, the launch
# journal (whose startup recovery can kill a live browser and move profile
# custody) and the profile registry of real browser profiles -- and the format
# floor chosen from the process's data home, which is the operator's floor
# file for any store under it.
#
# Its planted-offender proofs run first: a scan that reports nothing looks the
# same whether the tree is clean or the scan is blind. The scan prints how many
# files it read and refuses when that is none, for the same reason.
#
# An allowlist, if one is ever needed, lives in the scanner and carries its
# reason per entry, so an entry that stops being justified reads as wrong
# rather than as precedent.
check_tests_do_not_journal_durably() {
  scripts/lib/durable-journal-scan.test.sh >/dev/null || {
    echo "    the scanner's planted-offender proofs failed, so its verdict means nothing:" >&2
    scripts/lib/durable-journal-scan.test.sh 2>&1 | grep -v '^ok ' | sed 's/^/      /' >&2
    return 1
  }
  local status=0
  python3 scripts/lib/durable-journal-scan.py . || status=$?
  if [ "$status" -eq 1 ]; then
    echo "    the test code above builds something that journals to the operator's disk." >&2
    echo "    use Planes::with_browser_config_journaling(.., JournalPersistence::Isolated)" >&2
    echo "    (or an in-memory journal where a test opens one directly)" >&2
    echo "    or allow the file in durable-journal-scan.py with the reason it must be durable." >&2
  fi
  return "$status"
}

run_phase "no test journals to the operator's disk" \
  check_tests_do_not_journal_durably

# A preflight is a reading, not a request. A test that calls one of the
# requesting APIs can put a system dialog on the desk running the gate, so the
# source guard uses the same Rust-aware test-code regions as the journal scan
# and proves it sees planted requests before scanning this workspace.
check_tests_do_not_request_macOS_permissions() {
  scripts/lib/mac-permission-request-scan.test.sh >/dev/null || {
    echo "    the permission scanner's planted-request proofs failed:" >&2
    scripts/lib/mac-permission-request-scan.test.sh 2>&1 | grep -v '^ok ' | sed 's/^/      /' >&2
    return 1
  }
  python3 scripts/lib/mac-permission-request-scan.py .
}

run_phase "no test requests macOS permissions" \
  check_tests_do_not_request_macOS_permissions

# A real daemon execs a test module through the privacy trampoline, so both the
# smoke launch and the configured module path must be ckdev links. Check each
# spawn or configured program independently so a helper on a neighboring line
# cannot hide a direct production-named execution.
check_test_binaries_use_ckdev_names() {
  scripts/lib/ckdev-naming-scan.test.sh >/dev/null || {
    echo "    the ckdev naming scan's planted controls failed:" >&2
    scripts/lib/ckdev-naming-scan.test.sh 2>&1 | grep -v '^ok ' | sed 's/^/      /' >&2
    return 1
  }
  python3 scripts/lib/ckdev-naming-scan.py .
}

run_phase "test and script ck-* executions use ckdev names" \
  check_test_binaries_use_ckdev_names

# Phase 1: format workspace members. Keep the scope explicit so only this
# repository's source is checked, and refuse an empty member list.
check_members_formatted() {
  local members
  members="$(cargo metadata --locked --format-version 1 --no-deps \
    | python3 -c 'import json,sys; print(" ".join("-p " + p["name"] for p in json.load(sys.stdin)["packages"]))')"
  if [ -z "$members" ]; then
    echo "    cargo metadata listed no workspace members; refusing to check nothing" >&2
    return 1
  fi
  # shellcheck disable=SC2086
  cargo fmt $members -- --check
}
run_phase "workspace members are formatted" \
  check_members_formatted

# Phase 2: structural wiring. A module that exists on disk but is not declared
# in its crate root compiles only where a test includes it explicitly, so dead
# code inside it is never reported and nothing outside a test can call it. That
# state is indistinguishable from a module nobody remembered to wire up.
run_phase "scripts/module-wiring-gate.sh" \
  ./scripts/module-wiring-gate.sh

# Phase 3: clippy with warnings as errors, across all targets.
run_phase "cargo clippy --locked --workspace --all-targets --quiet -- -D warnings" \
  cargo clippy --locked --workspace --all-targets --quiet -- -D warnings

# The same lint against the platform CI actually runs on. A macOS-only gate
# cannot see code that stops compiling when the macOS seam disappears, and this
# repository has now been red on Linux twice while every local run was green --
# both times found by someone else reading our CI rather than by us.
#
# Skipped rather than failed when the target is absent, because a developer
# without it installed should not be blocked; CI has it, and CI is where the
# verdict binds.
#
# Two dependencies in our tree compile C -- ring and libsqlite3-sys, both via
# subc-core -- so this needs a C compiler that emits Linux objects, not just the
# Rust target. zig ships one, and using it means no separate toolchain to
# install or keep in step. An operator who already has a real cross-gcc
# configured keeps it: these are only set when unset.
# Directory probe, not exit status -- see the Windows loop below for why.
#
# A MISSING CROSS COMPILER IS NAMED HERE, NOT DISCOVERED INSIDE A BUILD SCRIPT.
# Without one, cargo runs anyway and libsqlite3-sys's build script dies looking
# for `x86_64-linux-gnu-gcc`, twenty lines into its own environment dump: a red
# gate whose subject is a third-party crate when the actual fault is this
# host's toolchain. So the absence gets the same treatment as an absent target
# (skipped, named, with the remedy), because CI builds Linux natively and is
# where this verdict binds either way.
# Every phase this host could not run, collected for the verdict line. A skip
# printed only mid-log is invisible to anyone who reads the last line, which is
# the line this script tells them to read.
not_verified=

# Ubuntu CI runs this gate natively, where the host clippy phase checks Linux.
# On macOS the same CI run supplies that signal; on Linux the host phase already
# supplies it locally. Keep the cross lane available for operators who explicitly
# request it, but do not spend a second build on a signal CI already provides.
host_os="$(uname -s)"
if [ "${CEREBELLUM_GATE_LINUX_LINT:-}" != 1 ] &&
  { [ "$host_os" = Darwin ] || [ "$host_os" = Linux ]; }; then
  printf '==> SKIPPED: linux lint (delegated to CI)\n'
  not_verified="$not_verified; linux lint (delegated to CI)"
else
  linux_cc_ready=
  if [ -n "${CC_x86_64_unknown_linux_gnu:-}" ]; then
    linux_cc_ready=1
  elif command -v zig >/dev/null 2>&1; then
    CC_x86_64_unknown_linux_gnu="$repo_root/scripts/zig-cross-cc.sh"
    AR_x86_64_unknown_linux_gnu="$repo_root/scripts/zig-cross-ar.sh"
    export CC_x86_64_unknown_linux_gnu AR_x86_64_unknown_linux_gnu
    linux_cc_ready=1
  fi
  if [ ! -d "$(rustc --print target-libdir --target x86_64-unknown-linux-gnu 2>/dev/null)" ]; then
    printf '==> SKIPPED: the linux target is not installed, so cross-platform lint did not run\n'
    printf '    install it with: rustup target add x86_64-unknown-linux-gnu\n'
    not_verified="$not_verified; linux lint (target not installed)"
  elif [ -z "$linux_cc_ready" ]; then
    printf '==> SKIPPED: no C compiler for x86_64-unknown-linux-gnu, so cross-platform lint did not run\n'
    printf '    ring and libsqlite3-sys compile C; install zig, or set CC_x86_64_unknown_linux_gnu\n'
    not_verified="$not_verified; linux lint (no C cross-compiler)"
  else
    run_phase "cargo clippy --locked --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings" \
      cargo clippy --locked --workspace --all-targets --target x86_64-unknown-linux-gnu --quiet -- -D warnings
  fi
fi

# Windows: LIBRARY targets only, deliberately.
#
# The workspace gained Windows support before the Windows plane exists, so
# nothing here exercises it -- this phase exists to stop it rotting. Portability
# claimed and unenforced survives about as long as the next unix-only import.
#
# Not --all-targets: a dev-dependency compiles C and needs a Windows toolchain
# this host does not have, so the test targets cannot be cross-checked from
# macOS at all. Asking for them would make this phase fail for a reason that has
# nothing to do with our code, and a phase that always fails teaches you to
# ignore it. The VM covers what this cannot.
# Both Windows architectures, and aarch64 is not the exotic one. Every Windows
# machine reachable from an Apple Silicon host is ARM64, so that is the target
# any measurement will actually run on -- checking only x86_64 verified the
# hypothetical build and left the real one unchecked, which is how I came to
# build the wrong architecture for a VM I was about to test against.
# The probe is the DIRECTORY, not the command's exit status. `rustc --print
# target-libdir` computes a path from the triple and exits 0 for any triple
# rustc recognises, installed or not -- so testing its exit status made the
# skip branch unreachable, and on a host without the Windows targets (CI) the
# phase ran and failed the whole gate, 25 runs in a row, for a toolchain
# reason that says nothing about the code. Reported by iceteaSA in #18.
# A runner can execute both Windows targets, so keep the local lanes as the
# default but allow both to be delegated together when requested.
if [ "${CEREBELLUM_GATE_WINDOWS_LINT:-}" = remote ]; then
  for windows_target in x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
    printf '==> SKIPPED: run remotely instead: cargo clippy --locked --workspace --target %s -- -D warnings\n' "$windows_target"
  done
  not_verified="$not_verified; windows lint x86_64+aarch64 (run remotely)"
else
  for windows_target in x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
    if [ -d "$(rustc --print target-libdir --target "$windows_target" 2>/dev/null)" ]; then
      run_phase "cargo clippy --locked --workspace --target $windows_target -- -D warnings" \
        cargo clippy --locked --workspace --target "$windows_target" --quiet -- -D warnings
    else
      printf '==> SKIPPED: %s is not installed, so that windows build was not checked\n' "$windows_target"
      not_verified="$not_verified; $windows_target build (target not installed)"
      printf '    install it with: rustup target add %s\n' "$windows_target"
    fi
  done
fi

# Phase 4: compile + all tests (lib, bins, integration).
run_phase "cargo test --locked --workspace --quiet" \
  cargo test --locked --workspace --quiet

# Phase 5: the identity-resolution observer seam is feature-gated so production
# builds emit no observer code. A plain `cargo test` therefore skips the
# conformance test that exercises it, so run that feature explicitly — otherwise
# the seam could rot unnoticed.
run_phase "cargo test --locked -p cerebellum --features test-observer --test conformance -- --exact feature_gated_identity_observer_records_resolved_facts" \
  scripts/lib/observer-conformance-gate.sh feature_gated_identity_observer_records_resolved_facts

# Phase 5b: staging refuses a build below the format floor. The gate lives in a
# script rather than a test, so a test run never exercises it; its proofs point
# it at scratch floor files, one version above what this tree reads, equal to
# it, and missing, and never at the operator's data home.
run_phase "scripts/lib/format-floor-gate.test.sh" \
  scripts/lib/format-floor-gate.test.sh

# Phase 5b2: the CI watcher that decides whether a train lands must never read
# a failed GitHub call as a green run. Driven against a fake gh, no network.
run_phase "scripts/watch-ci.test.sh" \
  scripts/watch-ci.test.sh
# Phase 5b3: the train lock's stale-owner recovery never takes a lock another
# train acquired meanwhile. Drives the real script in a scratch repository.
run_phase "scripts/train-push-lock.test.sh" \
  scripts/train-push-lock.test.sh

# Phase 5c: staging and placement refuse a binary without hardened runtime or
# with get-task-allow, since either lets a same-user debugger read the module.
# Like the floor gate, the check is a script a test run never reaches, so its
# proofs run here against ad hoc signed scratch binaries under /tmp. codesign
# and lipo exist only on macOS, so elsewhere the phase is named as not run
# rather than passed.
if [ "$(uname -s)" = Darwin ]; then
  run_phase "scripts/check-placed-hardening.test.sh" \
    scripts/check-placed-hardening.test.sh
else
  printf '==> SKIPPED: the hardening check needs macOS codesign, so it did not run\n'
  not_verified="$not_verified; hardening check (macOS only)"
fi

# Phase 6: a generated file must be committed in the form its generator emits.
# An entry that is semantically right but textually different -- a hand-written
# Cargo.lock line with the wrong indent, say -- is rewritten by the next build,
# so the tree goes dirty again however often it is restored. Every test still
# passes, because the only observable is repository state rather than behaviour,
# and worker dispatch refuses to launch against a dirty parent checkout.
#
# This compares against a snapshot taken before the first build rather than
# requiring a clean tree, because the normal caller is an author or worker with
# uncommitted work in progress. Only a file the BUILD itself changed is a
# finding.
check_build_rewrote_nothing() {
  local after rewritten
  after="$(git status --porcelain)"
  rewritten="$(comm -13 <(printf '%s\n' "$tree_before_build" | sort) \
                        <(printf '%s\n' "$after" | sort))"
  if [ -n "$rewritten" ]; then
    echo "    building rewrote these tracked files:" >&2
    echo "$rewritten" >&2
    echo "    they are committed in a form their generator does not emit;" >&2
    echo "    regenerate and commit the result rather than editing by hand." >&2
    return 1
  fi
}

# Named for what is being checked, not for the healthy outcome: the runner
# prints "GATE FAILED: <label>", and a label stating the healthy outcome reads
# as its own negation on the failing path ("GATE FAILED: the build rewrote no
# generated file" was read as a pass twice).
run_phase "generated files untouched by the build" \
  check_build_rewrote_nothing

# A single line naming the outcome, so a caller reading a filtered view of this
# output can find it by looking for one fixed word rather than by anticipating
# every way a phase can fail.
#
# The exit status is the real contract and this changes nothing about it. It
# exists because the output is routinely read through a filter, and a filter
# that greps for the failures its author expected reports the ones they did not
# as success: `cargo fmt` announces a problem with a diff and no error word at
# all. A phase that fails never reaches this line, so its ABSENCE is as
# meaningful as its presence.
# "All phases green" is only true when every phase RAN. A skipped phase is not a
# green one, and the one-line verdict is where a reader decides whether they are
# done, so it names what this host did not check rather than rounding it away.
# The "GATE PASSED" prefix is unchanged: callers match on it.
if [ -z "$not_verified" ]; then
  echo "GATE PASSED: all phases green"
else
  echo "GATE PASSED: every phase that ran is green; NOT VERIFIED on this host: ${not_verified#; }"
fi

# WHAT THIS GATE DID NOT DO, printed on success because that is when it is
# forgotten. It runs TESTS on this host only, and lints the Linux target without
# executing anything there. So a test behind #[cfg(target_os = "linux")] is
# compiled here at best and never run, and its result is unknown to every green
# run of this script.
#
# That is not hypothetical: main stayed red on Linux CI for seven commits while
# this line printed each time. Two fixtures assumed /bin/sh was bash, which is
# true on Fedora and Arch and false on Debian and Ubuntu, and no local run could
# have seen either one.
echo "        (host tests + cross-lint only; Linux-gated tests run in CI, not here)"
