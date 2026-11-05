#!/usr/bin/env bash
# Check guarded and unguarded script fixtures, then exercise EXIT cleanup in Bash.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
mkdir -p "$REPO_ROOT/target/scratch"
python3 - "$SCRIPT_DIR" "$BASH" "$REPO_ROOT/target/scratch" <<'PY'
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

lib = Path(sys.argv[1])
bash = sys.argv[2]
checks = 0


def expect(label, run, status, diagnostic=""):
    global checks
    checks += 1
    assert run.returncode == status, (label, run.returncode, run.stdout, run.stderr)
    assert diagnostic in run.stdout + run.stderr, (label, run.stdout, run.stderr)
    print(f"ok: {label}")


with tempfile.TemporaryDirectory(prefix="fail-closed-exit.", dir=sys.argv[3]) as tmp:
    root = Path(tmp)
    scripts = root / "scripts"
    (scripts / "lib").mkdir(parents=True)
    good = scripts / "lib/good.sh"
    good.write_text("\n".join([
        "#!/usr/bin/env bash", "set -euo pipefail",
        'source "$root/scripts/lib/fail-closed-exit.sh"',
        "trap 'fail_closed_exit cleanup' EXIT", "finished=1", "",
    ]))

    def scan():
        return subprocess.run([sys.executable, str(lib / "fail-closed-exit-scan.py"), str(root)],
                              text=True, capture_output=True)

    expect("a nested guarded script is accepted", scan(), 0, "1 nounset/EXIT scripts")
    bad = scripts / "lib/bad.sh"
    bad.write_text("set -u\ntrap 'echo cleanup' EXIT\n")
    expect("a nested unguarded script is refused", scan(), 1, "scripts/lib/bad.sh:")
    bad.write_text("set -e -u\ntrap 'echo cleanup' 0\n")
    expect("separate nounset flags and numeric EXIT are checked", scan(), 1, "scripts/lib/bad.sh:")
    bad.write_text("set -u; trap 'echo cleanup' EXIT\n")
    expect("a one-line unguarded script is refused", scan(), 1, "scripts/lib/bad.sh:")
    bad.write_text("set -o nounset\ntrap 'echo cleanup' EXIT\n"
                   "# source scripts/lib/fail-closed-exit.sh\n# trap 'fail_closed_exit cleanup' EXIT\n")
    expect("comments cannot supply the protection marker", scan(), 1, "scripts/lib/bad.sh:")
    bad.write_text("set -u\nsource scripts/lib/fail-closed-exit.sh\ntrap 'echo cleanup' EXIT\n")
    expect("sourcing alone is not a protected handler", scan(), 1, "scripts/lib/bad.sh:")
    bad.write_text("set -u\ntrap 'fail_closed_exit cleanup' EXIT\n")
    expect("a protected handler must source its definition", scan(), 1, "scripts/lib/bad.sh:")
    bad.unlink()
    for name in ("train-push.sh", "train-push-lock.test.sh"):
        (scripts / name).write_text("set -u\ntrap 'echo cleanup' EXIT\n")
    expect("unused train-push scripts are excluded", scan(), 0)
    good.unlink()
    bad.write_text("set -u\ntrap - EXIT INT TERM\n")
    expect("trap removal does not satisfy the denominator", scan(), 1, "no nounset/EXIT scripts found")
    bad.unlink()
    expect("an empty candidate set is refused", scan(), 1, "no nounset/EXIT scripts found")

    fixture = root / "runtime.sh"
    cleaned = root / "cleaned"

    def runtime(body):
        cleaned.unlink(missing_ok=True)
        fixture.write_text("\n".join([
            "set -euo pipefail",
            f"source {shlex.quote(str(lib / 'fail-closed-exit.sh'))}",
            f"cleanup() {{ echo cleaned > {shlex.quote(str(cleaned))}; }}",
            "trap 'fail_closed_exit cleanup' EXIT", body, "",
        ]))
        run = subprocess.run([bash, str(fixture)], text=True, capture_output=True)
        assert cleaned.read_text() == "cleaned\n", (body, run.stderr)
        return run

    expect("intended success exits zero after cleanup", runtime("finished=1"), 0)
    expect("an unfinished explicit exit zero is refused", runtime("exit 0"), 1)
    expect("an unfinished fallthrough is refused", runtime(":"), 1)
    expect("an intended early success exits zero", runtime("finished=1\nexit 0"), 0)
    expect("a nonzero exit keeps its status after cleanup", runtime("exit 23"), 23)
    expect("errexit keeps its status after cleanup", runtime("false"), 1)
    expect("an unbound scalar cannot exit zero", runtime('echo "${__cereb_probe_unbound}"'), 1,
           "unbound variable")
    version = subprocess.check_output([bash, "-c", 'echo "$BASH_VERSINFO"'], text=True).strip()
    array_run = runtime('array=()\nprintf "%s\\n" "${array[@]}"\nfinished=1')
    expect("empty arrays fail closed on Bash 3 and succeed on newer Bash", array_run,
           1 if int(version) < 4 else 0)

print(f"fail-closed-exit: {checks} checks passed")
PY
