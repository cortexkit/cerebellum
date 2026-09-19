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

# Phase 0a: say so, loudly, if Cargo.lock already differs from HEAD before any
# cargo command in this gate runs. NOT a refusal -- a deliberate absorb is
# exactly this state -- but a statement made while the operator is still
# looking. Measured against this repo's history: eleven commits carry a subc
# version bump under a message about something else, every one the same
# mechanism (an unflagged cargo run rewrote the lock, `git add -A` took it).
# Phase 6 cannot see those: it compares the tree before the BUILD to after,
# and a lock rewritten by an earlier cargo run is already in the "before".
# Only a comparison against HEAD is anchored to something the operator
# decided. Every cargo command below carries --locked, so this gate itself
# is a reader; the rewrite, if any, happened before it started.
report_lock_drift_from_head() {
  local drift
  drift="$(git diff --stat HEAD -- Cargo.lock 2>/dev/null)"
  if [ -n "$drift" ]; then
    echo "    NOTE: Cargo.lock differs from HEAD before this gate ran anything:" >&2
    git diff HEAD -- Cargo.lock | grep -E '^[-+]version|^[-+]name' | paste - - - - 2>/dev/null | sed 's/^/      /' >&2
    echo "    Commit it as its own lock change, or restore it --" >&2
    echo "    do NOT let it ride in a commit about something else (git add by path)." >&2
  fi
}
report_lock_drift_from_head

# Phase 0b: refuse to certify against a sibling that is not the one this commit
# declares. The workspace takes subc-* by PATH, so the crates compiled here come
# from whatever ../subconscious currently holds -- and if that disagrees with the
# committed Cargo.lock, cargo silently RESOLVES rather than failing: it rewrites
# the lock to match what the sibling supplies and carries on.
#
# The rewrite can PRUNE as easily as it can bump. A contributor whose sibling was
# behind saw entries removed (ahash, base64, cc) and got a full green run with an
# identical test count -- a true number obtained against a downgraded dependency
# graph. That is the shape worth refusing: an alarming rewrite gets investigated,
# a pruning one reads as tidying.
#
# Checked against the same content-addressed subtree hashes scripts/release-build.sh
# pins, so a gate run and a release build cannot disagree about which sibling is
# the right one.
check_sibling_matches_declaration() {
  local drift=0
  check_one_sibling subconscious "$(dirname "$0")/../subconscious-source.txt" || drift=1
  check_one_sibling commons "$(dirname "$0")/../commons-source.txt" || drift=1
  if [ "$drift" -ne 0 ]; then
    echo "    move the sibling to the declared revisions, or repin its" >&2
    echo "    *-source.txt if the move is intended. Building against a" >&2
    echo "    different sibling silently rewrites Cargo.lock and reports a" >&2
    echo "    true test count for a dependency graph nobody chose." >&2
    return 1
  fi
}

# One sibling, one declaration file. Same format for every sibling so a new
# one is a line in the caller above, never a second copy of this loop.
#
# The pin is compared against the sibling's PUBLISHED head as well as its
# working tree, because those answer different questions and only one of them
# is what CI will clone. A subtree that exists only in the producer's working
# tree passes a HEAD comparison and fails on the runner, and the failure that
# arrives there is `generated files untouched by the build` -- a message about
# our own lock being rewritten, naming nothing about the sibling. That cost two
# separate investigations on 2026-09-19, one here and one at the producer, for
# a bump held unpushed for about an hour.
#
# So the two mismatches get different words, because the remedy differs: a pin
# matching an unpushed subtree means WAIT for the producer to push (repinning
# would pin content no consumer can fetch), while matching neither means repin.
check_one_sibling() {
  local name="$1" declaration="$2" sibling drift=0
  sibling="$(dirname "$0")/../../$name"
  [ -f "$declaration" ] || { echo "    no $name declaration to check against" >&2; return 1; }
  [ -d "$sibling" ] || { echo "    sibling checkout missing at $sibling" >&2; return 1; }
  local upstream
  upstream="$(sibling_published_ref "$sibling")"
  while read -r declared crate; do
    case "$declared" in ""|\#*) continue ;; esac
    [ -z "$crate" ] && continue
    local actual published
    actual="$(git -C "$sibling" rev-parse "HEAD:crates/$crate" 2>/dev/null || echo missing)"
    published="$(git -C "$sibling" rev-parse "$upstream:crates/$crate" 2>/dev/null || echo unknown)"
    if [ "$actual" != "$declared" ]; then
      echo "    $name/$crate: declared $declared, sibling has $actual" >&2
      drift=1
    elif [ "$published" != "$declared" ] && [ "$published" != unknown ]; then
      echo "    $name/$crate: declared $declared matches the sibling's working tree" >&2
      echo "      but $upstream has $published -- the subtree is UNPUSHED, so CI" >&2
      echo "      cannot fetch what this pin names. Wait for the producer to push;" >&2
      echo "      do not repin." >&2
      drift=1
    fi
  done < "$declaration"
  return "$drift"
}

# The remote-tracking ref to compare against, or the sibling's own HEAD when
# there is none. An offline or remoteless checkout must not fail this phase for
# a reason that has nothing to do with the pins: with no upstream to read, the
# published question is unanswerable rather than answered no.
sibling_published_ref() {
  local sibling="$1" upstream
  upstream="$(git -C "$sibling" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
  if [ -n "$upstream" ] && git -C "$sibling" rev-parse --verify --quiet "$upstream" >/dev/null; then
    printf '%s' "$upstream"
  else
    printf 'HEAD'
  fi
}

run_phase "sibling matches the declared revisions" \
  check_sibling_matches_declaration

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
# The allowlist carries its reason per entry rather than a bare filename, so an
# entry that stops being justified reads as wrong rather than as precedent.
check_tests_do_not_journal_durably() {
  local offenders
  # Deliberate: b1_s3_browser.rs asserts that the PRODUCTION constructor
  # installs a journal, which is the defect that started this -- production had
  # none from the day the plane shipped. It builds the plane and never
  # dispatches, and the store opens lazily on first reservation, so it observes
  # the setting without opening anything.
  offenders="$(grep -rln "Planes::new(\|Planes::with_browser_config(" \
    crates/*/tests/ 2>/dev/null | grep -v "tests/b1_s3_browser.rs" || true)"
  if [ -n "$offenders" ]; then
    echo "    these tests build a durably-journaling plane:" >&2
    echo "$offenders" | sed 's/^/      /' >&2
    echo "    use Planes::with_browser_config_journaling(.., JournalPersistence::Isolated)" >&2
    echo "    or add the file here with the reason it must be durable." >&2
    return 1
  fi
}

run_phase "no test journals to the operator's disk" \
  check_tests_do_not_journal_durably

# Phase 1: formatting check, over THIS workspace's members only.
#
# Not `--all`: cargo fmt's --all follows path dependencies out of the
# workspace, so it reaches every crate in ../subconscious and ../commons.
# Measured here: `cargo fmt --all -- --check -v` listed both siblings' crates.
# As a check that makes this gate fail on a sibling's formatting; as a write
# (`cargo fmt --all` before a commit) it rewrites files in another
# repository's checkout. The member list comes from cargo metadata rather
# than a hand-kept string, and an empty list refuses rather than checking
# nothing and passing.
check_members_formatted() {
  local members
  members="$(cargo metadata --format-version 1 --no-deps \
    | python3 -c 'import json,sys; print(" ".join("-p " + p["name"] for p in json.load(sys.stdin)["packages"]))')"
  if [ -z "$members" ]; then
    echo "    cargo metadata listed no workspace members; refusing to check nothing" >&2
    return 1
  fi
  # shellcheck disable=SC2086
  cargo fmt $members -- --check
}
run_phase "workspace members are formatted (not --all: that reaches the siblings)" \
  check_members_formatted

# Phase 2: structural wiring. A module that exists on disk but is not declared
# in its crate root compiles only where a test includes it explicitly, so dead
# code inside it is never reported and nothing outside a test can call it. That
# state is indistinguishable from a module nobody remembered to wire up.
run_phase "scripts/module-wiring-gate.sh" \
  ./scripts/module-wiring-gate.sh

# Phase 3: clippy with warnings as errors, across all targets.
run_phase "cargo clippy --workspace --all-targets --quiet -- -D warnings" \
  cargo clippy --workspace --all-targets --quiet -- -D warnings

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
if [ -d "$(rustc --print target-libdir --target x86_64-unknown-linux-gnu 2>/dev/null)" ]; then
  if [ -z "${CC_x86_64_unknown_linux_gnu:-}" ] && command -v zig >/dev/null 2>&1; then
    CC_x86_64_unknown_linux_gnu="$repo_root/scripts/zig-cross-cc.sh"
    AR_x86_64_unknown_linux_gnu="$repo_root/scripts/zig-cross-ar.sh"
    export CC_x86_64_unknown_linux_gnu AR_x86_64_unknown_linux_gnu
  fi
  run_phase "cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings" \
    cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu --quiet -- -D warnings
else
  printf '==> SKIPPED: the linux target is not installed, so cross-platform lint did not run\n'
  printf '    install it with: rustup target add x86_64-unknown-linux-gnu\n'
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
for windows_target in x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
  if [ -d "$(rustc --print target-libdir --target "$windows_target" 2>/dev/null)" ]; then
    run_phase "cargo clippy --workspace --target $windows_target -- -D warnings" \
      cargo clippy --workspace --target "$windows_target" --quiet -- -D warnings
  else
    printf '==> SKIPPED: %s is not installed, so that windows build was not checked\n' "$windows_target"
    printf '    install it with: rustup target add %s\n' "$windows_target"
  fi
done

# Phase 4: compile + all tests (lib, bins, integration).
run_phase "cargo test --workspace --quiet" \
  cargo test --workspace --quiet

# Phase 5: the identity-resolution observer seam is feature-gated so production
# builds emit no observer code. A plain `cargo test` therefore skips the
# conformance test that exercises it, so run that feature explicitly — otherwise
# the seam could rot unnoticed.
run_phase "cargo test -p cerebellum --features test-observer --test conformance --quiet" \
  cargo test -p cerebellum --features test-observer --test conformance --quiet

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
echo "GATE PASSED: all phases green"

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