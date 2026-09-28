#!/usr/bin/env bash
# Proofs for format-floor-gate.sh, run by the test gate.
#
# Every case points the gate at a floor file in a scratch directory, never at
# the operator's data home. The refusing case is built from what THIS tree
# reports it can read, one version above it, so the case keeps meaning "a
# floor this build falls short of" as the formats move.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/format-floor-gate.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/format-floor-gate-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

failures=0
checks=0

# expect <case> <exit status> <floor file> [text the output must contain]
expect() {
  local name="$1" want="$2" floor="$3" needle="${4:-}" got output
  checks=$((checks + 1))
  set +e
  output="$("$GATE" "$floor" "$TMP_DIR/versions.json" 2>&1)"
  got=$?
  set -e
  if [ "$got" -ne "$want" ]; then
    echo "FAIL $name: exit $got, wanted $want" >&2
    printf '%s\n' "$output" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  elif [ -n "$needle" ] && ! printf '%s' "$output" | grep -qF -- "$needle"; then
    echo "FAIL $name: output does not name $needle" >&2
    printf '%s\n' "$output" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  else
    echo "ok   $name"
  fi
}

# A missing floor file is floor zero, and the run also yields what the tree
# reads, which every later case is built from.
expect "a missing floor file passes" 0 "$TMP_DIR/absent/format-floor.json"
if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d and all(v > 0 for v in d.values())' \
  "$TMP_DIR/versions.json"; then
  echo "FAIL the gate wrote no usable supported versions for the staging card" >&2
  exit 1
fi

# Floors equal to what the tree reads, for every format it reads.
python3 - "$TMP_DIR/versions.json" "$TMP_DIR/equal.json" <<'PY'
import json, sys
supported = json.load(open(sys.argv[1]))
json.dump({"version": 1, "floors": supported}, open(sys.argv[2], "w"))
PY
expect "a floor equal to what the build reads passes" 0 "$TMP_DIR/equal.json"

# One format one version above what the tree reads; the others equal.
format="$(python3 -c 'import json,sys; print(sorted(json.load(open(sys.argv[1])))[0])' "$TMP_DIR/versions.json")"
python3 - "$TMP_DIR/versions.json" "$TMP_DIR/above.json" "$format" <<'PY'
import json, sys
supported = json.load(open(sys.argv[1]))
floors = dict(supported)
floors[sys.argv[3]] = supported[sys.argv[3]] + 1
json.dump({"version": 1, "floors": floors}, open(sys.argv[2], "w"))
PY
expect "a floor one version above the build refuses, naming the format" 1 "$TMP_DIR/above.json" \
  "  $format: on disk at version"
# Only that format: the others are at what the build reads.
if "$GATE" "$TMP_DIR/above.json" "$TMP_DIR/versions.json" 2>&1 | grep -F ': on disk at version' | grep -vqF "  $format:"; then
  echo "FAIL the refusal named a format that is not short" >&2
  failures=$((failures + 1))
fi

# A format on disk that this build has no reader for at all.
printf '{"version": 1, "floors": {"a-format-no-build-reads": 1}}' >"$TMP_DIR/unknown.json"
expect "a floor naming a format the build does not read refuses" 1 "$TMP_DIR/unknown.json" \
  "a-format-no-build-reads: on disk at version 1, this build reads up to 0"

# A floor file from a newer build is refused by name, not compared.
printf '{"version": 2, "floors": {}, "added_later": true}' >"$TMP_DIR/newer.json"
expect "a newer floor file is refused by name" 1 "$TMP_DIR/newer.json" "newer_writer"

printf 'not json' >"$TMP_DIR/corrupt.json"
expect "an unreadable floor file stops the gate" 2 "$TMP_DIR/corrupt.json" "cannot be read"

echo "$checks checks, $failures failed"
[ "$failures" -eq 0 ]
