#!/usr/bin/env bash
# Proofs for format-floor-gate.sh, run by the test gate.
#
# Every case runs the gate with XDG_DATA_HOME pointed at a scratch data home,
# so the floors it reads are the scratch ones -- located by the module's own
# resolver, as they would be in production -- and never the operator's. The
# refusing cases are built from what THIS tree reports it can read, one
# version above it, so they keep meaning "a floor this build falls short of"
# as the formats move.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/format-floor-gate.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/format-floor-gate-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

failures=0
checks=0
case_number=0

# A fresh scratch data home for one case, in $home. Not a command
# substitution: that runs in a subshell, whose counter never reaches this one,
# and every case would share (and inherit the floors of) the first home.
new_data_home() {
  case_number=$((case_number + 1))
  home="$TMP_DIR/home-$case_number"
  mkdir -p "$home/cortexkit/cerebellum/journal" "$home/cortexkit/cerebellum/browser"
}

# expect <case> <exit status> <data home> [text the output must contain]
expect() {
  local name="$1" want="$2" home="$3" needle="${4:-}" got output
  checks=$((checks + 1))
  set +e
  output="$(XDG_DATA_HOME="$home" "$GATE" "$TMP_DIR/versions.json" 2>&1)"
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

# Missing floor files are floor zero. The run also shows the floors were
# located under the scratch data home by the module's resolver, and yields
# what the tree reads, which every later case is built from.
new_data_home
expect "missing floor files pass, located under the data home given" 0 "$home" \
  "journal=$home/cortexkit/cerebellum/journal/format-floor.json"
if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d and all(v > 0 for v in d.values())' \
  "$TMP_DIR/versions.json"; then
  echo "FAIL the gate wrote no usable supported versions for the staging card" >&2
  exit 1
fi
cp "$TMP_DIR/versions.json" "$TMP_DIR/supported.json"

# floor <file> <python expression over `supported`, giving the floors map>
floor() {
  python3 - "$TMP_DIR/supported.json" "$1" "$2" <<'PY'
import json, sys
supported = json.load(open(sys.argv[1]))
first = sorted(supported)[0]
floors = eval(sys.argv[3])
json.dump({"version": 1, "floors": floors}, open(sys.argv[2], "w"))
PY
}
first="$(python3 -c 'import json,sys; print(sorted(json.load(open(sys.argv[1])))[0])' "$TMP_DIR/supported.json")"

new_data_home
floor "$home/cortexkit/cerebellum/journal/format-floor.json" 'dict(supported)'
floor "$home/cortexkit/cerebellum/browser/format-floor.json" 'dict(supported)'
expect "floors equal to what the build reads pass" 0 "$home"

new_data_home
floor "$home/cortexkit/cerebellum/journal/format-floor.json" 'dict(supported)'
expect "one floor file present and the other missing passes" 0 "$home"

new_data_home
floor "$home/cortexkit/cerebellum/journal/format-floor.json" 'dict(supported)'
floor "$home/cortexkit/cerebellum/browser/format-floor.json" '{first: supported[first] + 1}'
expect "a browser floor one version above the build refuses, naming the format and file" 1 "$home" \
  "  $first: on disk at version"
if XDG_DATA_HOME="$home" "$GATE" "$TMP_DIR/versions.json" 2>&1 | grep -F ': on disk at version' |
  grep -vqF "  $first: on disk at version $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]] + 1)' "$TMP_DIR/supported.json" "$first"), this build reads up to"; then
  echo "FAIL the refusal named a format that is not short" >&2
  failures=$((failures + 1))
fi
expect "the refusal names the floor file it came from" 1 "$home" \
  "($home/cortexkit/cerebellum/browser/format-floor.json)"

new_data_home
floor "$home/cortexkit/cerebellum/journal/format-floor.json" '{first: supported[first] + 1}'
expect "a journal floor one version above the build refuses" 1 "$home" "  $first: on disk at version"

new_data_home
printf '{"version": 1, "floors": {"a-format-no-build-reads": 1}}' \
  >"$home/cortexkit/cerebellum/journal/format-floor.json"
expect "a floor naming a format the build does not read refuses" 1 "$home" \
  "a-format-no-build-reads: on disk at version 1, this build reads up to 0"

new_data_home
printf '{"version": 2, "floors": {}, "added_later": true}' \
  >"$home/cortexkit/cerebellum/browser/format-floor.json"
expect "a newer floor file is refused by name" 1 "$home" "newer_writer"

new_data_home
printf 'not json' >"$home/cortexkit/cerebellum/journal/format-floor.json"
expect "an unreadable floor file stops the gate" 2 "$home" "cannot be read"

echo "$checks checks, $failures failed"
[ "$failures" -eq 0 ]
