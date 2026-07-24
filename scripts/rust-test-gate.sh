#!/usr/bin/env bash
# ck-cerebellum Rust test gate.
#
# Run from the repo root after any code change. The first phase is
# `cargo fmt --all -- --check`, so an unformatted commit fails the gate.
# Serialize cargo invocations (never parallel cargo): other workers share this
# machine and concurrent workspace builds have saturated it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_phase() {
  local label="$1"
  shift
  local started=$SECONDS
  echo "==> $label"
  "$@"
  echo "    ok ($((SECONDS - started))s)"
}

# Phase 1: formatting check. `cargo fmt --all` must be run before committing;
# this check fails the gate on an unformatted commit.
run_phase "cargo fmt --all -- --check" \
  cargo fmt --all -- --check

# Phase 2: clippy with warnings as errors, across all targets.
run_phase "cargo clippy --workspace --all-targets --quiet -- -D warnings" \
  cargo clippy --workspace --all-targets --quiet -- -D warnings

# Phase 3: compile + all tests (lib, bins, integration).
run_phase "cargo test --workspace --quiet" \
  cargo test --workspace --quiet

# Phase 4: the identity-resolution observer seam is feature-gated so production
# builds emit no observer code. A plain `cargo test` therefore skips the
# conformance test that exercises it, so run that feature explicitly — otherwise
# the seam could rot unnoticed.
run_phase "cargo test -p cerebellum --features test-observer --test conformance --quiet" \
  cargo test -p cerebellum --features test-observer --test conformance --quiet