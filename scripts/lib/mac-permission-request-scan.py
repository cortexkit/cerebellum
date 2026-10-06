#!/usr/bin/env python3
"""Reject test code that can ask macOS to grant a privacy permission.

The test-code regions come from durable-journal-scan.py's Rust-aware scanner,
so inline tests, out-of-line test modules, integration tests, examples compiled
as tests, comments, and strings are classified the same way as the other
source scan in the test gate.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import List, Set, Tuple

SCANNER_PATH = Path(__file__).with_name("durable-journal-scan.py")
SPEC = importlib.util.spec_from_file_location("durable_journal_scan", SCANNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load shared Rust test-code scanner at {SCANNER_PATH}")
SHARED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARED)

# Ban the requesting APIs outright in tests. Their check-only counterparts are
# CGPreflightScreenCaptureAccess, CGPreflightListenEventAccess/IOHIDCheckAccess,
# and AXIsProcessTrusted.
REQUESTING_APIS = {
    "AXIsProcessTrustedWithOptions",
    "CGRequestListenEventAccess",
    "CGRequestScreenCaptureAccess",
    "IOHIDRequestAccess",
}


def request_calls(tokens: List[Tuple[str, str, int]], ranges: List[Tuple[int, int]]):
    found = []
    for start, end in ranges:
        for index in range(start, min(end, len(tokens)) - 1):
            kind, name, line = tokens[index]
            following = tokens[index + 1]
            if kind == "ident" and name in REQUESTING_APIS and following[1] == "(":
                found.append((line, name))
    return sorted(set(found))


def scan(root: Path):
    test_files = sorted(root.glob("crates/*/tests/**/*.rs"))
    sources = sorted(root.glob("crates/*/src/**/*.rs"))
    examples = sorted(root.glob("crates/*/examples/**/*.rs"))
    scans = {path: SHARED.scan_structure(path) for path in sources + examples}

    whole_test_files: Set[Path] = set()
    pending = []
    for result in scans.values():
        for name, explicit, in_test in result.modules:
            if in_test:
                pending.append((result.path, name, explicit))
    while pending:
        parent, name, explicit = pending.pop()
        child = SHARED.module_file(parent, name, explicit)
        if child is None:
            continue
        child = child.resolve()
        matched = next((path for path in scans if path.resolve() == child), None)
        if matched is None or matched in whole_test_files:
            continue
        whole_test_files.add(matched)
        pending.extend(
            (matched, child_name, child_path)
            for child_name, child_path, _ in scans[matched].modules
        )

    found = []
    scanned = 0

    def check(path: Path, tokens, ranges) -> None:
        nonlocal scanned
        if not ranges:
            return
        scanned += 1
        relative = path.relative_to(root).as_posix()
        for line, api in request_calls(tokens, ranges):
            found.append(f"{relative}:{line}: test code calls requesting API {api}(")

    for path in test_files:
        tokens = SHARED.tokenize(path.read_text(encoding="utf-8", errors="replace"))
        check(path, tokens, [(0, len(tokens))])

    for path, result in scans.items():
        ranges = [(0, len(result.tokens))] if path in whole_test_files else result.regions
        check(path, result.tokens, ranges)

    for item in sorted(found):
        print(item, file=sys.stderr)
    print(f"scanned {scanned} Rust test-code files for requesting macOS permission APIs")
    if not scanned:
        print("nothing was scanned, so no permission requests were checked", file=sys.stderr)
        return 2
    return 1 if found else 0


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    sys.exit(scan(root))
