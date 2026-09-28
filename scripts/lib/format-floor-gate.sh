#!/usr/bin/env bash
# Refuse a build that cannot read the durable records already on disk.
#
# Every durable reader in this module refuses a record newer than it knows,
# which is right, but on its own that is discovered only when a build meets
# such a record -- after a rollback, on the live desk, with a browser profile
# locked until someone deletes the lock by hand. So each writer raises a floor
# in `<data home>/cortexkit/cerebellum/format-floor.json` before it first
# writes a format, and this gate compares that floor with what the build
# being staged can read, before the build is handed over.
#
# Usage:
#   scripts/lib/format-floor-gate.sh <floor-file> <versions-out>
#
# Builds and runs the `format_versions` example from THIS tree, which prints
# the highest version of each format the tree reads, taken from the constants
# its readers check. Writes that JSON to <versions-out> for the staging card,
# so a placer can compare it with the floor on the machine it places onto.
#
# A missing floor file is floor zero for every format: nothing that raises a
# floor has written there yet. A format named in the floor that this build does
# not list at all reads as version zero, so it refuses too: the build has no
# reader for records that are on disk.
#
# Exit 0: the build reads everything the floor names. Exit 1: refused, with
# each format the build falls short on named. Exit 2: the gate could not run.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  sed -n '12,14p' "$0" >&2
  exit 2
fi

floor_file="$1"
versions_out="$2"

cd "$(dirname "$0")/../.."

# Unfiltered: a build failure must reach the terminal with its own words.
# `--locked` so the build cannot rewrite Cargo.lock on its way to an answer.
if ! versions="$(cargo run --quiet --locked -p cerebellum --example format_versions)"; then
  echo "REFUSING: could not build or run the format_versions example," >&2
  echo "so what this tree can read is unknown." >&2
  exit 2
fi

printf '%s\n' "$versions" >"$versions_out"

python3 - "$floor_file" "$versions_out" <<'PY'
import json
import sys

floor_path, versions_path = sys.argv[1], sys.argv[2]

# The floor file's own format this gate reads. A newer floor file is refused
# by name like any other newer record: its floors may mean something this
# gate does not know how to compare.
FLOOR_FILE_VERSION = 1

with open(versions_path) as handle:
    supported = json.load(handle)
if not isinstance(supported, dict) or not supported or not all(
    isinstance(name, str) and isinstance(version, int) and version > 0
    for name, version in supported.items()
):
    # An empty list would pass every floor, which is the failure this whole
    # gate exists to prevent, so it is refused rather than compared.
    print(f"REFUSING: format_versions printed no usable versions: {supported!r}", file=sys.stderr)
    sys.exit(2)

try:
    with open(floor_path) as handle:
        document = json.load(handle)
except FileNotFoundError:
    document = {"version": FLOOR_FILE_VERSION, "floors": {}}
except (OSError, ValueError) as error:
    print(f"REFUSING: the format floor {floor_path} cannot be read: {error}", file=sys.stderr)
    sys.exit(2)

version = document.get("version") if isinstance(document, dict) else None
if not isinstance(version, int):
    print(f"REFUSING: the format floor {floor_path} has no version", file=sys.stderr)
    sys.exit(2)
if version > FLOOR_FILE_VERSION:
    print(
        f"REFUSING TO STAGE: newer_writer: the format floor {floor_path} is version "
        f"{version}; this gate reads up to version {FLOOR_FILE_VERSION}",
        file=sys.stderr,
    )
    sys.exit(1)
floors = document.get("floors")
if version != FLOOR_FILE_VERSION or not isinstance(floors, dict):
    print(f"REFUSING: the format floor {floor_path} is not a floor file", file=sys.stderr)
    sys.exit(2)

short = sorted(
    (name, floor, supported.get(name, 0))
    for name, floor in floors.items()
    if not isinstance(floor, int) or supported.get(name, 0) < floor
)
if short:
    print("REFUSING TO STAGE: this build cannot read records already on disk.", file=sys.stderr)
    print(f"  floor: {floor_path}", file=sys.stderr)
    for name, floor, reads in short:
        print(f"  {name}: on disk at version {floor}, this build reads up to {reads}", file=sys.stderr)
    print(
        "Placing it would refuse those records on the live desk. Stage a build\n"
        "that reads them, or move the records aside deliberately first.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"format floor ok: {len(floors)} floor(s) at {floor_path}, build reads {json.dumps(supported, sort_keys=True)}")
PY
