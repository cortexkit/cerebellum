#!/usr/bin/env bash
# Shared Cargo-target lock for the full and fast gates. The directory and lease
# file must stay in place: unlinking a locked inode would let a new gate lock a
# different inode while the old gate or its Cargo children still use the target.

acquire_gate_lock() {
  local lock="$1" holder status
  mkdir -p "$lock" || return 2
  # Keep fd 9 open in the gate and its children. The kernel releases the lock
  # only after the last inherited copy closes, even if the gate itself is killed.
  exec 9<>"$lock/lease" || return 2
  if python3 - <<'PY'
import fcntl
import sys

try:
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(2)
PY
  then
    # The pid is diagnostic text, never evidence that a process owns the lock.
    printf '%s\n' "$$" > "$lock/holder"
    return 0
  else
    status=$?
    exec 9>&-
  fi
  if [ "$status" -ne 2 ]; then
    echo "gate: cannot take the shared Cargo target lock; nothing has been verified" >&2
    return 2
  fi
  holder="$(cat "$lock/holder" 2>/dev/null || true)"
  echo "gate: another gate owns the shared Cargo target lock${holder:+ (pid $holder)}" >&2
  echo "nothing has been verified" >&2
  return 2
}
