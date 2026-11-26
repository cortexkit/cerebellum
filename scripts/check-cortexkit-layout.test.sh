#!/usr/bin/env bash
# Proves check-cortexkit-layout.sh catches what it exists for before the gate
# trusts its silence: a private file tracked through a `!` un-ignore line, a
# private file force-added past the ignore rule, and a directory git can't read.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check-cortexkit-layout.sh"
scratch="$(mktemp -d)"
source "$here/lib/fail-closed-exit.sh"
trap 'fail_closed_exit rm -rf "$scratch"' EXIT

new_repo() {
  local dir="$scratch/$1"
  git init -q "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name test
  printf '.cortexkit/*\n!.cortexkit/WORKER.md\n!.cortexkit/release-notes/\n!.cortexkit/example.jsonc\n' > "$dir/.gitignore"
  mkdir -p "$dir/.cortexkit/release-notes"
  echo guide > "$dir/.cortexkit/WORKER.md"
  echo notes > "$dir/.cortexkit/release-notes/v0.1.0.md"
  echo "{}" > "$dir/.cortexkit/example.jsonc"
  printf '%s\n' "$dir"
}

expect() {
  local want="$1" name="$2"
  shift 2
  set +e
  "$@" >/dev/null 2>&1
  local got=$?
  set -e
  if [ "$got" != "$want" ]; then
    echo "not ok $name: exit $got, expected $want" >&2
    exit 1
  fi
  echo "ok $name"
}

clean="$(new_repo clean)"
git -C "$clean" add -A && git -C "$clean" commit -qm init
expect 0 "allowlisted paths, including a project settings file, pass" "$check" "$clean"

unignored="$(new_repo unignored)"
printf '!.cortexkit/notes.md\n' >> "$unignored/.gitignore"
echo private > "$unignored/.cortexkit/notes.md"
git -C "$unignored" add -A && git -C "$unignored" commit -qm init
expect 1 "a private file un-ignored by a ! line fails" "$check" "$unignored"

forced="$(new_repo forced)"
mkdir -p "$forced/.cortexkit/internal-docs"
echo private > "$forced/.cortexkit/internal-docs/design.md"
git -C "$forced" add -A && git -C "$forced" add -f .cortexkit/internal-docs/design.md
git -C "$forced" commit -qm init
expect 1 "a force-added private file fails" "$check" "$forced"

mkdir "$scratch/not-a-repo"
expect 2 "an unreadable repository fails closed" "$check" "$scratch/not-a-repo"
finished=1
