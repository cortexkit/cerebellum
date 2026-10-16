#!/usr/bin/env python3
"""Print every module file declared by a crate's source tree, one per line.

Used by module-wiring-gate.sh for the case its plain file-layout check cannot
see: `mod y;` written inside an inline `mod x { ... }` lives at `x/y.rs`, whose
parent is a block inside another file rather than a file of its own. The
Rust-aware scanner in durable-journal-scan.py already tracks those enclosing
inline modules, so this reuses it instead of a second parser.

Usage: declared-modules.py SRC_DIR
"""

import importlib.util
import sys
from pathlib import Path

SCANNER_PATH = Path(__file__).with_name("durable-journal-scan.py")
SPEC = importlib.util.spec_from_file_location("durable_journal_scan", SCANNER_PATH)
SHARED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARED)


def main(argv):
    src = Path(argv[1])
    declared = set()
    for path in sorted(src.rglob("*.rs")):
        scan = SHARED.scan_structure(path)
        for name, explicit, _in_test, enclosing in scan.modules:
            child = SHARED.module_file(path, name, explicit, enclosing)
            if child is not None:
                declared.add(child.resolve())
    for path in sorted(declared):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
