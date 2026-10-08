#!/usr/bin/env bash
# train-push.sh's lock: recovering a stale owner must never take a lock a live
# train acquired in the meantime. Drives the real script in a scratch repo up
# to the lock; nothing reaches the network, because the lock comes first.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/train-push-lock-test.XXXXXX")"
live_owner=""
cleanup() {
  [ -n "$live_owner" ] && kill "$live_owner" 2>/dev/null
  rm -rf "$scratch"
}
trap cleanup EXIT
failures=0

repo="$scratch/repo"
git init -q "$repo"
git -C "$repo" commit -q --allow-empty -m init
mkdir -p "$repo/scripts"
cp "$root/scripts/train-push.sh" "$repo/scripts/train-push.sh"
locks="$repo/.git/train-push-locks"
mkdir -p "$locks/held"

start_of() { ps -p "$1" -o lstart= 2>/dev/null | awk '{$1=$1; print}'; }

# A finished process leaves the stale owner: its pid is gone.
sh -c 'exit 0' &
dead=$!
wait "$dead"
printf '%s stale\n%s\n' "$dead" "Thu Jan  1 00:00:00 1970" > "$locks/held/owner"

# The hook runs after this train read the stale owner and before it recovers.
# It plays the other train that won recovery first and now holds a FRESH lock
# with a live owner.
sleep 60 &
live_owner=$!
disown "$live_owner"
cat > "$scratch/winner.sh" <<HOOK
#!/usr/bin/env bash
rm -rf "$locks/held"
mkdir "$locks/held"
printf '%s winner\n%s\n' "$live_owner" "$(start_of "$live_owner")" > "$locks/held/owner"
HOOK
chmod +x "$scratch/winner.sh"

out="$scratch/out"
( cd "$repo" && TRAIN_PUSH_TEST_LOCK_RACE_HOOK="$scratch/winner.sh" \
    bash scripts/train-push.sh racer ) >"$out" 2>&1
status=$?
owner_after="$(awk 'NR==1{print $2}' "$locks/held/owner" 2>/dev/null)"

if [ "$status" = 2 ] && grep -q "is RUNNING as pid $live_owner" "$out" && [ "$owner_after" = winner ]; then
  echo "ok a recovering train leaves a winner's fresh lock alone and refuses"
else
  echo "FAIL recovery took the winner's lock (exit $status, owner now '${owner_after:-none}')"
  sed 's/^/    /' "$out"
  failures=$((failures + 1))
fi

[ "$failures" = 0 ]
