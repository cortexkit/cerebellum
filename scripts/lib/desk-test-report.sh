#!/usr/bin/env bash
# Shared output handling for tests whose live desk operation was not verified.

desk_skip_reason() {
  sed -n 's/^test [^ ]* \.\.\. SKIPPED[^:]*: //p' | head -n 1
}

desk_skip_lines() {
  sed -n '/^test [^ ]* \.\.\. SKIPPED/p'
}

# Keep the command's exit status and retain stderr as well as stdout: the Rust
# test helpers write SKIPPED directly to stderr so libtest cannot hide it.
run_teed() {
  local log="$1"
  shift
  "$@" 2>&1 | tee "$log"
  return "${PIPESTATUS[0]}"
}
