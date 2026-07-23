#!/usr/bin/env bash
# Rust test gate for ck-cerebellum.
#
# Phase 1: cargo fmt --all -- --check (unformatted code fails the gate).
# Phase 2: cargo test (all crates).
#
# Serialize cargo invocations (never parallel cargo) — the shared build machine
# saturates under concurrent workspace builds.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Phase 1: cargo fmt --all -- --check ==="
cargo fmt --all -- --check

echo "=== Phase 2: cargo test ==="
cargo test

echo "=== Gate passed ==="