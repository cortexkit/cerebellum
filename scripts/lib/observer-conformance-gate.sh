#!/usr/bin/env bash
# The observer seam is feature-gated, so require its one conformance test to run.
set -euo pipefail

test_name="${1:-feature_gated_identity_observer_records_resolved_facts}"
output=
if output="$(cargo test --locked -p cerebellum --features test-observer --test conformance --quiet -- --exact "$test_name" 2>&1)"; then
  printf '%s\n' "$output"
else
  status=$?
  printf '%s\n' "$output"
  exit "$status"
fi

# Cargo exits successfully when an exact filter matches nothing, so only a
# harness summary reporting exactly one passing test verifies this seam.
passed_summaries="$(grep -Ec '^test result: ok\. 1 passed;' <<<"$output" || true)"
if [ "$passed_summaries" -ne 1 ]; then
  echo "GATE FAILED: observer conformance filter '$test_name' did not run exactly one test" >&2
  exit 1
fi
