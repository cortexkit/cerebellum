#!/usr/bin/env bash
# Break a guard on purpose, see whether anything notices, and put it back.
#
# A passing test suite cannot distinguish a guard that is watched from one that
# is merely present: a rule no traffic reaches, a refusal nobody asserts, and a
# correctly enforced invariant all produce the same evidence, which is nothing
# failing. The only way to tell them apart is to remove the mechanism and watch a
# named test go red.
#
# THE RESTORE IS THE HARD PART, because a deliberate break left behind looks
# exactly like source and the next commit ships it. Three endings have to be
# handled, and only the first is obvious:
#   - normal exit          -- restore, then verify the file matches the index
#   - interrupt or SIGTERM -- same, from a trap; this is why the verify command
#                             runs in the background and is waited on, since bash
#                             defers a trap until the current FOREGROUND child
#                             finishes, and a long test run is precisely the
#                             window where the break would otherwise survive
#   - SIGKILL              -- no code runs at all, so nothing here can help; a
#                             marker file is written up front instead, and the
#                             test gate refuses while it exists
#
# Usage:
#   scripts/mutate.sh <file> <mutate-command> <verify-command>
#
# <mutate-command> edits <file> in place and may name it as $MUTANT.
# <verify-command> is normally a test invocation.
#
# Read the result the opposite way round from a normal test run: the verify
# command FAILING is the good outcome, because something caught the break. The
# verify command passing is the finding.
set -uo pipefail

if [ "$#" -ne 3 ]; then
  sed -n '2,31p' "$0" >&2
  exit 2
fi

MUTANT="$1"
mutate_command="$2"
verify_command="$3"
export MUTANT

if [ ! -f "$MUTANT" ]; then
  echo "mutate: no such file: $MUTANT" >&2
  exit 2
fi

# The restore check compares against the index, so an untracked file could be
# "restored" to nothing and the check would still pass.
if ! git ls-files --error-unmatch "$MUTANT" >/dev/null 2>&1; then
  echo "mutate: $MUTANT is not tracked by git, so a restore cannot be verified" >&2
  exit 2
fi

# Refuse to run against a file that is already modified: the backup would
# capture the uncommitted work, and a failed restore would be indistinguishable
# from the state the caller started in.
if ! git diff --quiet -- "$MUTANT"; then
  echo "mutate: $MUTANT has uncommitted changes; commit or stash them first," >&2
  echo "        so that a failed restore is distinguishable from your own edits." >&2
  exit 2
fi

backup="$(mktemp)"
cp "$MUTANT" "$backup"

# A marker on disk, because the restore cannot defend against every ending: a
# SIGKILL runs no trap and prints nothing, so a mutation would survive in a file
# that still looks like source. The marker survives the same kill, and the test
# gate refuses to pass while one exists -- which turns a silent broken guard into
# a loud refusal. Removed only after the restore is verified.
marker_dir="$(git rev-parse --git-dir)"
marker="$marker_dir/mutation-in-progress"
cat >"$marker" <<MARKER
A mutation run started and did not confirm its restore.

file:   $MUTANT
backup: $backup

If $MUTANT still contains a deliberate break, restore it:
    cp $backup $MUTANT
Then remove this marker:
    rm $marker
MARKER

restore() {
  local status=$?
  # Stop the verify command first. It is a child of this shell, so leaving it
  # running would let a build keep reading the file while it is restored.
  if [ -n "${verify_pid:-}" ]; then
    kill -TERM "$verify_pid" 2>/dev/null
  fi
  cp "$backup" "$MUTANT" 2>/dev/null
  if git diff --quiet -- "$MUTANT" 2>/dev/null; then
    rm -f "$backup" "$marker"
  else
    # Loudly, and on every stream a caller might be reading: a surviving
    # mutation is a broken guard that looks like source, and the next commit
    # ships it.
    echo "" >&2
    echo "!!! MUTATION SURVIVED IN THE WORKING TREE: $MUTANT" >&2
    echo "!!! restore it with: cp $backup $MUTANT" >&2
    echo "!!! the backup is deliberately left in place until you do." >&2
    status=3
  fi
  exit "$status"
}
trap restore EXIT INT TERM

if ! eval "$mutate_command"; then
  echo "mutate: the mutate command failed; nothing was tested" >&2
  exit 2
fi

if git diff --quiet -- "$MUTANT"; then
  echo "mutate: the mutate command changed nothing, so the run proves nothing" >&2
  echo "        (check that the text it edits still appears in $MUTANT)" >&2
  exit 2
fi

echo "=== mutated $MUTANT ==="
git --no-pager diff --unified=0 -- "$MUTANT" | sed -n '5,$p'
echo "=== running: $verify_command ==="

# The verify command runs in the BACKGROUND and is waited on, rather than in the
# foreground, because bash defers a trap until the current foreground child
# exits. A foreground verify command means a SIGTERM arriving mid-run does not
# restore the file until that command finishes on its own -- which for a long
# test run is exactly the window where the mutation gets left behind. `wait` is
# interruptible by traps, so the restore happens immediately.
verify_output_file="$(mktemp)"
eval "$verify_command" >"$verify_output_file" 2>&1 &
verify_pid=$!
wait "$verify_pid"
verify_status=$?
verify_pid=""
verify_output="$(cat "$verify_output_file")"
rm -f "$verify_output_file"
printf '%s\n' "$verify_output"

echo "=== result ==="
if [ "$verify_status" -eq 0 ]; then
  echo "NOT CAUGHT: the guard was removed and the check still passed."
  echo "            Nothing is watching this mechanism."
else
  # Count individual test failures, not the suite's own summary line, which
  # also begins with "test " and ends in "FAILED".
  red="$(printf '%s\n' "$verify_output" | grep -cE '^test .* \.\.\. FAILED' || true)"
  echo "CAUGHT: the check failed with the guard removed ($red named failures)."
  echo "        Confirm the failures name the property you meant to test -- a"
  echo "        compile error or a timeout also exits nonzero."
fi

# The verify command's status is deliberately not the script's: it inverts, and
# a caller reading the exit code alone would draw the opposite conclusion. This
# exits 0 whenever the experiment RAN, and the report above says what it found.
exit 0
