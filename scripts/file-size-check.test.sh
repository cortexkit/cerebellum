#!/usr/bin/env bash
# Exercise the checker against tracked files in isolated repositories.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$root/target/scratch"
scratch="$(mktemp -d "$root/target/scratch/file-size-test.XXXXXX")"
source "$root/scripts/lib/fail-closed-exit.sh"
trap 'fail_closed_exit rm -rf "$scratch"' EXIT

fixture="$scratch/repo"
mkdir -p "$fixture/scripts/lib" "$fixture/crates/example/src" "$fixture/crates/example/tests"
cp "$root/scripts/file-size-check.sh" "$fixture/scripts/"
cp "$root/scripts/lib/fail-closed-exit.sh" "$fixture/scripts/lib/"
git -C "$fixture" init -q
python3 - "$fixture" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
for n in range(100):
    (root / f"crates/example/src/file{n}.rs").write_text("source\n")
(root / "crates/example/tests/large.rs").write_text("test\n" * 5001)
(root / "crates/example/src/unit_tests.rs").write_text("test\n" * 5001)
(root / "scripts/file-size-baseline.txt").write_text("")
PY
git -C "$fixture" add crates

checks=0
expect() {
  local name="$1" want="$2" needle="$3" output status
  checks=$((checks + 1))
  if output="$(bash "$fixture/scripts/file-size-check.sh" 2>&1)"; then status=0; else status=$?; fi
  if [ "$status" -ne "$want" ] || [[ "$output" != *"$needle"* ]]; then
    printf 'FAIL %s: exit %s, expected %s and %s\n%s\n' "$name" "$status" "$want" "$needle" "$output" >&2
    exit 1
  fi
  echo "ok   $name"
}
lines() {
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_text("line\n" * int(sys.argv[2]))
PY
}

file="$fixture/crates/example/src/file0.rs"
expect 'test files excluded from denominator' 0 'scanned 100 files'
lines "$file" 5001
expect 'new oversized source fails' 1 'file0.rs: 5001 lines exceeds 5000'
printf '5001 crates/example/src/file0.rs\n' > "$fixture/scripts/file-size-baseline.txt"
expect 'baseline permits its recorded size' 0 'scanned 100 files'
lines "$file" 5002
expect 'baseline growth fails' 1 'file0.rs: 5002 lines exceeds baseline 5001'
printf '5002 crates/example/src/file0.rs\n' > "$fixture/scripts/file-size-baseline.txt"
lines "$file" 5001
expect 'shrink above limit suggests lowering baseline' 0 '5001 lines; lower its baseline from 5002'
lines "$file" 5000
expect 'shrink to limit suggests removing baseline' 0 '5000 lines; remove its baseline entry'
git -C "$fixture" rm -qrf --cached crates
expect 'empty scan fails' 1 'scanned 0 files'
echo "file-size-check: all $checks cases passed"
finished=1
