#!/usr/bin/env bash
# Proofs for install-extension.sh, run by the test gate.
#
# Every case installs into a scratch directory and runs with HOME pointed at
# scratch too, so neither an explicit nor a defaulted destination can reach
# the person's real installed extension.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="$SCRIPT_DIR/install-extension.sh"
SOURCE="$SCRIPT_DIR/../extension"

TMP_DIR="$(mktemp -d /tmp/ck-install-extension-test.XXXXXX)"
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

# check <case> <command...>: the command must succeed.
check() {
  local name="$1"
  shift
  checks=$((checks + 1))
  if "$@"; then
    echo "ok   $name"
  else
    echo "FAIL $name" >&2
    failures=$((failures + 1))
  fi
}

run() {
  HOME="$TMP_DIR/home" CEREBELLUM_EXTENSION_DIR="$1" "$INSTALL" "${@:2}"
}

revision="$(sed -n 's/^export const EXTENSION_REVISION = \([0-9][0-9]*\);$/\1/p' "$SOURCE/revision.mjs")"
dest="$TMP_DIR/installed/cerebellum-extension"

expect "a fresh install names the revision it copied" 0 "contract revision $revision" run "$dest"
check "the installed files are the source's bytes" cmp -s "$SOURCE/native.mjs" "$dest/native.mjs"
check "the installed revision is the source's" cmp -s "$SOURCE/revision.mjs" "$dest/revision.mjs"
check "the installed manifest is the source's" cmp -s "$SOURCE/manifest.json" "$dest/manifest.json"
check "tests are not installed" test ! -e "$dest/tests"

# A stale copy, as Chrome last loaded it: an old file the source no longer
# has, and an old version of one it does.
echo 'export const EXTENSION_REVISION = 0;' > "$dest/revision.mjs"
echo 'stale' > "$dest/removed-upstream.mjs"
expect "a reinstall replaces a stale copy" 0 "Installed" run "$dest"
check "the stale revision is replaced" cmp -s "$SOURCE/revision.mjs" "$dest/revision.mjs"
check "files removed from the source are removed" test ! -e "$dest/removed-upstream.mjs"
check "no staging or retired copy is left behind" \
  test -z "$(find "$TMP_DIR/installed" -maxdepth 1 -name '.cerebellum-extension.*' -print)"

mkdir -p "$TMP_DIR/elsewhere"
echo 'keep' > "$TMP_DIR/elsewhere/keep"
ln -s "$TMP_DIR/elsewhere" "$TMP_DIR/linked"
expect "a symlinked destination is refused" 1 "is a symlink" run "$TMP_DIR/linked"
check "the symlink's target is untouched" test "$(cat "$TMP_DIR/elsewhere/keep")" = keep
check "the symlink's target gained no files" test ! -e "$TMP_DIR/elsewhere/manifest.json"

mkdir -p "$TMP_DIR/not-an-extension"
echo '{}' > "$TMP_DIR/not-an-extension/manifest.json"
expect "a source without revision.mjs is refused" 1 "has no revision.mjs" \
  run "$TMP_DIR/never-written" "$TMP_DIR/not-an-extension"
check "a refused source writes nothing" test ! -e "$TMP_DIR/never-written"

expect "a relative destination is refused" 1 "not an absolute path" run "relative/path"

expect "the default destination is under HOME" 0 \
  "$TMP_DIR/home/.local/share/cortexkit/cerebellum-extension" \
  env -u CEREBELLUM_EXTENSION_DIR HOME="$TMP_DIR/home" "$INSTALL"
check "the default install has the source's revision" \
  cmp -s "$SOURCE/revision.mjs" "$TMP_DIR/home/.local/share/cortexkit/cerebellum-extension/revision.mjs"

echo "install-extension.sh: $checks checks, $failures failed"
[ "$failures" -eq 0 ]
