#!/usr/bin/env bash
# Refuse a ck-cerebellum binary that is not signed with hardened runtime, or
# that carries com.apple.security.get-task-allow.
#
# Usage: scripts/check-placed-hardening.sh <path to binary>
#
# WHY. Without hardened runtime, or with get-task-allow, any other program
# running as the same user can attach a debugger to the module and read its
# memory -- including the launch secret it holds. This was measured: `lldb -p`
# attached without a prompt to an unhardened module and was refused on a
# hardened copy of the same bytes. The module needs no entitlements under
# hardened runtime, so a hardened signature with an empty entitlement set is
# the only acceptable result.
#
# WHO RUNS IT. scripts/stage.sh runs it on the file it has just signed, and
# the placement gate runs it on the PLACED file, because placement is a plain
# copy made by the daemon owner and the placed bytes are the ones that execute.
# It only reads the signature; it never signs anything.
#
# Every architecture slice is checked on its own. `codesign -dv` without
# `--arch` describes only the slice this host would run, so a universal binary
# with one unhardened slice passes that reading and runs unhardened on the
# other kind of Mac.
#
# Exit status: 0 hardened, 1 not hardened (each problem named on stderr),
# 2 the check could not run (no argument, or no codesign on this host).
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <path to binary>" >&2
  exit 2
fi
binary="$1"

if ! command -v codesign >/dev/null 2>&1 || ! command -v lipo >/dev/null 2>&1; then
  echo "CANNOT CHECK HARDENING: codesign and lipo are macOS tools and are not on this host." >&2
  exit 2
fi

if [ ! -f "$binary" ]; then
  echo "NOT HARDENED: $binary does not exist or is not a regular file." >&2
  exit 1
fi

if ! archs="$(lipo -archs "$binary" 2>/dev/null)" || [ -z "$archs" ]; then
  echo "NOT HARDENED: $binary is not a Mach-O binary, so it carries no code signature." >&2
  exit 1
fi

problems=0
for arch in $archs; do
  where="$binary [$arch]"

  if ! info="$(codesign -dv --arch "$arch" "$binary" 2>&1)"; then
    echo "NOT HARDENED: $where is not signed: $(printf '%s\n' "$info" | sed -n 1p)" >&2
    problems=$((problems + 1))
    continue
  fi

  # The flag list comes from the CodeDirectory line, e.g.
  #   CodeDirectory v=20500 size=270 flags=0x10002(adhoc,runtime) hashes=...
  # and is matched as a whole comma-separated word. Matching "runtime"
  # anywhere in the output would also match the `Executable=` line of a file
  # whose path happens to contain the word, and pass an unhardened binary.
  # No early-closing reader (head, grep -q) sits in these pipelines: under
  # pipefail the writer's SIGPIPE would turn a match into a failure.
  flags="$(printf '%s\n' "$info" |
    sed -n 's/^CodeDirectory .*flags=0x[0-9a-fA-F]*(\([^)]*\)).*/\1/p')"
  if [ -z "$flags" ]; then
    # Named as a parse failure rather than as a missing flag, so a change in
    # codesign's output format reads as this script's problem and not as a
    # signing problem.
    echo "NOT HARDENED: $where: could not read the CodeDirectory flags from codesign -dv:" >&2
    printf '%s\n' "$info" | sed -n '1,5s/^/    /p' >&2
    problems=$((problems + 1))
  else
    case ",$flags," in
      *,runtime,*) ;;
      *)
        echo "NOT HARDENED: $where is signed without hardened runtime (flags: $flags); sign with --options runtime." >&2
        problems=$((problems + 1))
        ;;
    esac
  fi

  # Any appearance of the key refuses, whatever its value: the module needs no
  # entitlements at all, so there is no legitimate reason for the key to exist.
  if ! entitlements="$(codesign -d --entitlements - --xml --arch "$arch" "$binary" 2>/dev/null)"; then
    echo "NOT HARDENED: $where: could not read the entitlements with codesign -d --entitlements -." >&2
    problems=$((problems + 1))
  else
    case "$entitlements" in
      *com.apple.security.get-task-allow*)
        echo "NOT HARDENED: $where carries com.apple.security.get-task-allow, which lets any same-user process attach a debugger." >&2
        problems=$((problems + 1))
        ;;
    esac
  fi
done

if [ "$problems" -ne 0 ]; then
  exit 1
fi

echo "hardened: $binary (slices: $(printf '%s' "$archs" | tr '\n' ' '); runtime flag set, no get-task-allow)"
