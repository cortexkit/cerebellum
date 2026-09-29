#!/usr/bin/env bash
# Proofs for check-placed-hardening.sh and for stage.sh's hardening refusal,
# run by the test gate on macOS.
#
# The fixtures are ad hoc signed copies of /usr/bin/true: small, present on
# every Mac, and universal, so the per-slice check has more than one slice to
# read. Ad hoc signing sets the same CodeDirectory flags and entitlements as
# the real identity does, and needs no keychain, so these proofs run anywhere.
#
# The scratch directory is under /tmp, NEVER under $TMPDIR: codesign on a file
# under the per-user $TMPDIR (/var/folders/...) hangs forever on macOS 27, and
# a hung codesign here would hold the gate until its phase bound fires.
#
# stage.sh is exercised through its --check-hardening-only dry path, which
# runs the refusal it applies after signing and nothing else, so no case here
# builds, signs with the fleet identity, or stages anything.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-placed-hardening.sh"
STAGE="$SCRIPT_DIR/stage.sh"
SOURCE_BINARY=/usr/bin/true

TMP_DIR="$(mktemp -d /tmp/ck-placed-hardening-test.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

failures=0
checks=0

# expect <case> <exit status> <text the output must contain> <command...>
expect() {
  local name="$1" want="$2" needle="$3" got output
  shift 3
  checks=$((checks + 1))
  set +e
  output="$("$@" 2>&1)"
  got=$?
  set -e
  if [ "$got" -ne "$want" ]; then
    echo "FAIL $name: exit $got, wanted $want" >&2
    printf '%s\n' "$output" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  else
    case "$output" in
      *"$needle"*) echo "ok   $name" ;;
      *)
        echo "FAIL $name: output does not name '$needle'" >&2
        printf '%s\n' "$output" | sed 's/^/    /' >&2
        failures=$((failures + 1))
        ;;
    esac
  fi
}

# A fresh copy of the source binary at <path>, signed with the remaining
# codesign options (none means an ad hoc signature without hardened runtime).
signed_copy() {
  local path="$1"
  shift
  mkdir -p "$(dirname "$path")"
  cp "$SOURCE_BINARY" "$path"
  codesign --force --sign - "$@" "$path" 2>/dev/null
}

cat > "$TMP_DIR/get-task-allow.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
EOF

signed_copy "$TMP_DIR/hardened" --options runtime
signed_copy "$TMP_DIR/unhardened"
signed_copy "$TMP_DIR/debuggable" --options runtime --entitlements "$TMP_DIR/get-task-allow.plist"
cp "$SOURCE_BINARY" "$TMP_DIR/unsigned"
codesign --remove-signature "$TMP_DIR/unsigned"
# The word "runtime" in the path, on an unhardened binary. codesign -dv
# prints the path on its Executable= line, so a check that looks for the word
# anywhere in that output instead of in the flags would pass this one.
signed_copy "$TMP_DIR/runtime/runtime"

expect "a binary signed with --options runtime passes" 0 \
  "hardened: $TMP_DIR/hardened" "$CHECK" "$TMP_DIR/hardened"
expect "a binary signed without --options runtime fails, named" 1 \
  "is signed without hardened runtime" "$CHECK" "$TMP_DIR/unhardened"
expect "a hardened binary carrying get-task-allow fails, named" 1 \
  "carries com.apple.security.get-task-allow" "$CHECK" "$TMP_DIR/debuggable"
expect "an unsigned binary fails, named" 1 \
  "is not signed" "$CHECK" "$TMP_DIR/unsigned"
expect "the word runtime in the path does not pass an unhardened binary" 1 \
  "is signed without hardened runtime" "$CHECK" "$TMP_DIR/runtime/runtime"
expect "a missing file fails, named" 1 \
  "does not exist" "$CHECK" "$TMP_DIR/absent"
expect "no argument is a usage error, not a verdict" 2 \
  "usage:" "$CHECK"

# One hardened slice and one unhardened slice in one universal file. The host
# runs only one of them, and codesign -dv without --arch describes only that
# one, so this is the case a whole-file reading would pass.
first_arch="$(lipo -archs "$SOURCE_BINARY" | tr ' ' '\n' | sed -n 1p)"
second_arch="$(lipo -archs "$SOURCE_BINARY" | tr ' ' '\n' | sed -n 2p)"
if [ -n "$second_arch" ]; then
  lipo "$SOURCE_BINARY" -thin "$first_arch" -output "$TMP_DIR/slice-unhardened"
  lipo "$SOURCE_BINARY" -thin "$second_arch" -output "$TMP_DIR/slice-hardened"
  codesign --force --sign - "$TMP_DIR/slice-unhardened" 2>/dev/null
  codesign --force --sign - --options runtime "$TMP_DIR/slice-hardened" 2>/dev/null
  lipo -create "$TMP_DIR/slice-unhardened" "$TMP_DIR/slice-hardened" -output "$TMP_DIR/mixed"
  expect "one unhardened slice in a universal binary fails, naming the slice" 1 \
    "[$first_arch] is signed without hardened runtime" "$CHECK" "$TMP_DIR/mixed"
else
  echo "skip one unhardened slice in a universal binary: $SOURCE_BINARY has one slice here"
fi

# stage.sh's own refusal, through the dry path.
expect "stage.sh refuses an unhardened result, naming the reason" 1 \
  "REFUSING TO STAGE: the signed binary is not hardened." \
  "$STAGE" --check-hardening-only "$TMP_DIR/unhardened"
expect "stage.sh's refusal carries the check's named reason" 1 \
  "is signed without hardened runtime" \
  "$STAGE" --check-hardening-only "$TMP_DIR/unhardened"
expect "stage.sh accepts a hardened result" 0 \
  "hardening gate passed: $TMP_DIR/hardened" \
  "$STAGE" --check-hardening-only "$TMP_DIR/hardened"

# A run that checked nothing prints nothing alarming, so the count is part of
# the verdict.
if [ "$failures" -ne 0 ]; then
  echo "check-placed-hardening: $failures of $checks cases failed" >&2
  exit 1
fi
echo "check-placed-hardening: all $checks cases passed"
