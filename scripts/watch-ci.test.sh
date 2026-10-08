#!/usr/bin/env bash
# watch-ci.sh must never report success from a GitHub read that failed. Drives
# the real script against a fake `gh` first in PATH, with no network.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/watch-ci-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"
failures=0

# The fake answers `run view` by the JSON field asked for. The conclusion and
# jobs reads each fail on their first call when FAIL_FIRST=1, then answer with
# the run as CONCLUSION and FAILED_JOBS describe it.
cat > "$scratch/bin/gh" <<'FAKE'
#!/usr/bin/env bash
state="$FAKE_STATE"
count() { local n; n=$(( $(cat "$state/$1" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$state/$1"; echo "$n"; }
case "$*" in
  *"--json status"*) echo completed ;;
  *"--json url"*) echo "https://example.invalid/run/1" ;;
  *"--json conclusion"*)
    n=$(count conclusion)
    [ "${FAIL_FIRST:-0}" = 1 ] && [ "$n" = 1 ] && exit 1
    echo "$CONCLUSION" ;;
  *"select(.conclusion==\"failure\")"*) echo "" ;;
  *"--json jobs"*)
    n=$(count jobs)
    [ "${FAIL_FIRST:-0}" = 1 ] && [ "$n" = 1 ] && exit 1
    echo "$FAILED_JOBS" ;;
  *) exit 1 ;;
esac
FAKE
chmod +x "$scratch/bin/gh"

run_case() {
  local name="$1" expected="$2"
  shift 2
  local state="$scratch/state-$name"
  mkdir -p "$state"
  env "$@" FAKE_STATE="$state" PATH="$scratch/bin:/usr/bin:/bin" REPO=owner/name \
    WATCH_CI_POLL_SLEEP=0 "$root/scripts/watch-ci.sh" 12345 >"$scratch/$name.out" 2>&1
  local status=$?
  if [ "$status" = "$expected" ]; then
    echo "ok $name"
  else
    echo "FAIL $name: exit $status, expected $expected"
    sed 's/^/    /' "$scratch/$name.out"
    failures=$((failures + 1))
  fi
}

# A failed run whose verdict reads fail once must still end as a failure. The
# fail-open version read both failures as "no gating job failed" and exited 0.
run_case failed_reads_retry_to_failure 1 FAIL_FIRST=1 CONCLUSION=failure FAILED_JOBS="tests (linux)"
# Controls: a clean success, and a failure read without errors.
run_case success 0 CONCLUSION=success FAILED_JOBS=""
run_case failure 1 CONCLUSION=failure FAILED_JOBS="tests (linux)"
# An advisory-only failure stays landable, read after one failed attempt.
run_case advisory_only_after_retry 0 FAIL_FIRST=1 CONCLUSION=cancelled FAILED_JOBS=""

[ "$failures" = 0 ]
