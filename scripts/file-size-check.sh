#!/usr/bin/env bash
# Enforce the source-file line limit against the tracked baseline.
# No tracked Rust files under crates/ were identified as generated or vendored;
# generated bindings are dependencies, and vendored test vectors are not Rust.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/lib/fail-closed-exit.sh"
trap 'fail_closed_exit :' EXIT
cd "$repo_root"

python3 - <<'PY'
from pathlib import Path
import subprocess
import sys

limit = 5000
minimum_files = 100
baseline_path = Path("scripts/file-size-baseline.txt")
baseline = {}
try:
    for line in baseline_path.read_text().splitlines():
        count, path = line.split(" ", 1)
        if not count.isascii() or not count.isdigit() or int(count) <= limit or not path.startswith("crates/") or path in baseline:
            raise ValueError(f"invalid baseline entry: {line!r}")
        baseline[path] = int(count)
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "crates/*.rs"],
        check=True, stdout=subprocess.PIPE,
    ).stdout.split(b"\0")
    files = []
    for raw in tracked:
        if not raw:
            continue
        path = Path(raw.decode("utf-8"))
        if "tests" in path.parts or path.name == "tests.rs" or path.name.endswith("_tests.rs"):
            continue
        files.append(path)
    print(f"file-size check: scanned {len(files)} files", flush=True)
    if len(files) < minimum_files:
        raise ValueError(f"implausibly small scan: expected at least {minimum_files} files")
    failed = False
    for path in files:
        data = path.read_bytes()
        lines = data.count(b"\n") + bool(data and not data.endswith(b"\n"))
        previous = baseline.get(path.as_posix())
        if previous is None and lines > limit:
            print(f"FAIL {path}: {lines} lines exceeds {limit}", file=sys.stderr)
            failed = True
        elif previous is not None and lines > previous:
            print(f"FAIL {path}: {lines} lines exceeds baseline {previous}", file=sys.stderr)
            failed = True
        elif previous is not None and lines < previous:
            if lines <= limit:
                print(f"HINT {path}: {lines} lines; remove its baseline entry")
            else:
                print(f"HINT {path}: {lines} lines; lower its baseline from {previous}")
    if failed:
        sys.exit(1)
except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as error:
    print(f"file-size check: {error}", file=sys.stderr)
    sys.exit(1)
PY
finished=1
