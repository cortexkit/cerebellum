#!/usr/bin/env bash
# ck-cerebellum Rust test gate.
#
# This script is the definition of "verified" for this repository: CI runs it
# verbatim rather than restating its phases, so the desk and the runner cannot
# drift apart. Anything that belongs in the verification contract belongs here
# rather than in the workflow.
#
# Run from the repo root after any code change. The first phase is
# `cargo fmt --all -- --check`, so an unformatted commit fails the gate.
# Serialize cargo invocations (never parallel cargo): other workers share this
# machine and concurrent workspace builds have saturated it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Snapshot the tree before anything builds, so the final phase can attribute a
# change to the build rather than to uncommitted work the author already had.
tree_before_build="$(git status --porcelain)"

run_phase() {
  local label="$1"
  shift
  local started=$SECONDS
  echo "==> $label"
  "$@"
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

# Phase 1: formatting check. `cargo fmt --all` must be run before committing;
# this check fails the gate on an unformatted commit.
run_phase "cargo fmt --all -- --check" \
  cargo fmt --all -- --check

# Phase 2: structural wiring. A module that exists on disk but is not declared
# in its crate root compiles only where a test includes it explicitly, so dead
# code inside it is never reported and nothing outside a test can call it. That
# state is indistinguishable from a module nobody remembered to wire up.
run_phase "scripts/module-wiring-gate.sh" \
  ./scripts/module-wiring-gate.sh

# Phase 3: clippy with warnings as errors, across all targets.
run_phase "cargo clippy --workspace --all-targets --quiet -- -D warnings" \
  cargo clippy --workspace --all-targets --quiet -- -D warnings

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

run_phase "the build rewrote no generated file" \
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