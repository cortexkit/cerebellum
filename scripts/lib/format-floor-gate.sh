#!/usr/bin/env bash
# Refuse a build that cannot read the durable records already on disk.
#
# Every durable reader in this module refuses a record newer than it knows,
# which is right, but on its own that is discovered only when a build meets
# such a record -- after a rollback, in production, with a browser profile
# locked until someone deletes the lock by hand. So each writer raises a floor
# before it first writes a format, in the floor file of the data tree it
# writes into (`journal/format-floor.json`, `browser/format-floor.json` under
# the module's data directory), and this gate compares those floors with what
# the build being staged can read, before the build is handed over.
#
# Usage:
#   scripts/lib/format-floor-gate.sh <versions-out>
#
# Builds and runs the `format_versions` example from THIS tree. It prints the
# highest version of each format the tree reads, taken from the constants its
# readers check, and the path of each floor file, resolved by the same
# data-home resolver the module uses -- so this script resolves no path of its
# own, and the environment it runs in (XDG_DATA_HOME and the rest) decides
# which floors it reads, exactly as it would for the module. Writes the
# supported versions to <versions-out>; stage.sh copies them beside the staged
# binary, so whoever places that binary can compare them with the floors on
# the machine it lands on.
#
# A missing floor file is floor zero for every format in that tree: nothing
# that raises a floor has written there yet. A format named in a floor that
# this build does not list at all reads as version zero, so it refuses too:
# the build has no reader for records that are on disk.
#
# Exit 0: the build reads everything the floors name. Exit 1: refused, with
# each format the build falls short on named. Exit 2: the gate could not run.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  sed -n '13,14p' "$0" >&2
  exit 2
fi

versions_out="$1"

cd "$(dirname "$0")/../.."

# Unfiltered: a build failure must reach the terminal with its own words.
# `--locked` so the build cannot rewrite Cargo.lock on its way to an answer.
if ! report="$(cargo run --quiet --locked -p cerebellum --example format_versions)"; then
  echo "REFUSING: could not build or run the format_versions example," >&2
  echo "so what this tree can read, or where its floors are, is unknown." >&2
  exit 2
fi

python3 - "$versions_out" "$report" <<'PY'
import json
import sys

versions_out, report = sys.argv[1], sys.argv[2]

# The floor file's own format this gate reads. A newer floor file is refused
# by name like any other newer record: its floors may mean something this
# gate does not know how to compare.
FLOOR_FILE_VERSION = 1

try:
    report = json.loads(report)
    supported = report["supported"]
    floor_paths = report["floor_paths"]
except (ValueError, KeyError, TypeError) as error:
    print(f"REFUSING: format_versions printed no usable report: {error}", file=sys.stderr)
    sys.exit(2)
if not isinstance(supported, dict) or not supported or not all(
    isinstance(name, str) and isinstance(version, int) and version > 0
    for name, version in supported.items()
):
    # An empty list would pass every floor, which is the failure this whole
    # gate exists to prevent, so it is refused rather than compared.
    print(f"REFUSING: format_versions printed no usable versions: {supported!r}", file=sys.stderr)
    sys.exit(2)
if not isinstance(floor_paths, dict) or not floor_paths or not all(
    isinstance(path, str) and path.startswith("/") for path in floor_paths.values()
):
    print(f"REFUSING: format_versions printed no usable floor paths: {floor_paths!r}", file=sys.stderr)
    sys.exit(2)

with open(versions_out, "w") as handle:
    json.dump(supported, handle, sort_keys=True)
    handle.write("\n")


def read_floors(path):
    """The floors in one file; a missing file is floor zero."""
    try:
        with open(path) as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as error:
        print(f"REFUSING: the format floor {path} cannot be read: {error}", file=sys.stderr)
        sys.exit(2)
    version = document.get("version") if isinstance(document, dict) else None
    if not isinstance(version, int):
        print(f"REFUSING: the format floor {path} has no version", file=sys.stderr)
        sys.exit(2)
    if version > FLOOR_FILE_VERSION:
        print(
            f"REFUSING TO STAGE: newer_writer: the format floor {path} is version "
            f"{version}; this gate reads up to version {FLOOR_FILE_VERSION}",
            file=sys.stderr,
        )
        sys.exit(1)
    floors = document.get("floors")
    if version != FLOOR_FILE_VERSION or not isinstance(floors, dict):
        print(f"REFUSING: the format floor {path} is not a floor file", file=sys.stderr)
        sys.exit(2)
    return floors


short = []
read = 0
for tree, path in sorted(floor_paths.items()):
    floors = read_floors(path)
    read += len(floors)
    for name, floor in sorted(floors.items()):
        reads = supported.get(name, 0)
        if not isinstance(floor, int) or reads < floor:
            short.append((tree, path, name, floor, reads))

if short:
    print("REFUSING TO STAGE: this build cannot read records already on disk.", file=sys.stderr)
    for tree, path, name, floor, reads in short:
        print(
            f"  {name}: on disk at version {floor}, this build reads up to {reads}  ({path})",
            file=sys.stderr,
        )
    print(
        "Placed, it would refuse those records in production. Stage a build\n"
        "that reads them, or move the records aside deliberately first.",
        file=sys.stderr,
    )
    sys.exit(1)

paths = ", ".join(f"{tree}={path}" for tree, path in sorted(floor_paths.items()))
print(f"format floors ok: {read} floor(s) in {paths}; build reads {json.dumps(supported, sort_keys=True)}")
PY
