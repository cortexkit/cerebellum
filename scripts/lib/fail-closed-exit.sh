#!/usr/bin/env bash
# Source before installing an EXIT trap; mark only intended success with finished=1.
finished=0

fail_closed_exit() {
  local status=$?
  # Bash 3.2 exits 0 from an EXIT trap after an unbound-variable error.
  "$@"
  if [ "$status" -eq 0 ] && [ "${finished:-0}" -ne 1 ]; then
    exit 1
  fi
  exit "$status"
}
