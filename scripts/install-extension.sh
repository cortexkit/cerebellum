#!/usr/bin/env bash
# Install the unpacked Chrome extension that browser:"user" talks to, so the
# copy Chrome loads matches the cerebellum build being placed.
#
# WHY THIS EXISTS. Chrome runs whatever unpacked copy it was pointed at, from
# that copy's own directory, and neither building nor placing cerebellum
# touches it. On 2026-10-19 the installed copy at
# ~/.local/share/cortexkit/cerebellum-extension was older than the placed
# cerebellum and sent replies without fields cerebellum required, so every
# user-browser action refused. Cerebellum now names that case
# (extension_outdated / extension_newer, from the contract revision in
# extension/revision.mjs), and this script is how the copy is brought back in
# step.
#
# WHEN TO RUN IT. Right after placing a cerebellum binary, with the extension
# directory scripts/stage.sh staged beside that build (stage.sh prints the
# exact command). Not at staging time: Chrome restarts the extension's service
# worker from these files whenever it idles out, so installing early can put a
# newer extension in front of the cerebellum that is still running. Then ask
# the person to reload the extension in chrome://extensions, which also picks
# up manifest changes.
#
# Usage: install-extension.sh [SOURCE_DIR]
#   SOURCE_DIR   an extension directory; defaults to this checkout's extension/.
#   CEREBELLUM_EXTENSION_DIR   destination; defaults to
#                ~/.local/share/cortexkit/cerebellum-extension.
#
# The destination is replaced as a whole (files removed from the source are
# removed there too), never merged, and never followed through a symlink. The
# source's tests/ directory is not installed: Chrome does not need it.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -gt 1 ]]; then
  printf 'Usage: %s [SOURCE_DIR]\n' "$0" >&2
  exit 2
fi
source_dir="${1:-$root/extension}"
if [[ ! -d "$source_dir" ]]; then
  printf 'refused: %s is not a directory. Nothing was written.\n' "$source_dir" >&2
  exit 1
fi
source_dir="$(cd -- "$source_dir" && pwd -P)"
for required in manifest.json revision.mjs native.mjs service-worker.mjs; do
  if [[ ! -f "$source_dir/$required" ]]; then
    printf 'refused: %s has no %s, so it is not a CortexKit extension directory. Nothing was written.\n' "$source_dir" "$required" >&2
    exit 1
  fi
done

# Read what is being installed from the files themselves, so the report below
# describes the bytes copied rather than what the caller meant to copy.
revision="$(sed -n 's/^export const EXTENSION_REVISION = \([0-9][0-9]*\);$/\1/p' "$source_dir/revision.mjs")"
version="$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$source_dir/manifest.json")"
if [[ -z "$revision" || -z "$version" ]]; then
  printf 'refused: could not read EXTENSION_REVISION from revision.mjs or "version" from manifest.json in %s. Nothing was written.\n' "$source_dir" >&2
  exit 1
fi

if [[ -z "${HOME:-}" && -z "${CEREBELLUM_EXTENSION_DIR:-}" ]]; then
  printf 'refused: HOME is unset and CEREBELLUM_EXTENSION_DIR is not given. Nothing was written.\n' >&2
  exit 1
fi
dest="${CEREBELLUM_EXTENSION_DIR:-$HOME/.local/share/cortexkit/cerebellum-extension}"
if [[ "$dest" != /* ]]; then
  printf 'refused: the destination %s is not an absolute path. Nothing was written.\n' "$dest" >&2
  exit 1
fi
dest="${dest%/}"
# A symlinked destination would replace whatever it points at, which is not
# this script's to replace.
if [[ -L "$dest" ]]; then
  printf 'refused: the destination %s is a symlink. Nothing was written.\n' "$dest" >&2
  exit 1
fi
if [[ -e "$dest" && ! -d "$dest" ]]; then
  printf 'refused: the destination %s exists and is not a directory. Nothing was written.\n' "$dest" >&2
  exit 1
fi
parent="$(dirname -- "$dest")"
mkdir -p "$parent"
case "$(cd -- "$parent" && pwd -P)/$(basename -- "$dest")/" in
  "$source_dir"/*)
    printf 'refused: the destination %s is inside the source %s. Nothing was written.\n' "$dest" "$source_dir" >&2
    exit 1
    ;;
esac

# Build the new copy beside the destination, then swap it in with renames, so
# Chrome never reads a half-copied directory.
staging="$(mktemp -d "$parent/.cerebellum-extension.new.XXXXXX")"
retired=""
cleanup() {
  rm -rf "$staging"
  if [[ -n "$retired" ]]; then rm -rf "$retired"; fi
}
trap cleanup EXIT
cp -R "$source_dir/." "$staging/"
rm -rf "$staging/tests"
chmod 755 "$staging"
if [[ -d "$dest" ]]; then
  retired="$(mktemp -d "$parent/.cerebellum-extension.old.XXXXXX")"
  mv "$dest" "$retired/previous"
fi
if ! mv "$staging" "$dest"; then
  # Put the previous copy back rather than leaving Chrome with nothing.
  if [[ -n "$retired" ]]; then mv "$retired/previous" "$dest"; fi
  printf 'refused: could not move the new copy into %s; the previous copy is unchanged.\n' "$dest" >&2
  exit 1
fi

printf 'Installed CortexKit extension %s (contract revision %s) into %s.\n' "$version" "$revision" "$dest"
printf 'Ask the person to reload it in chrome://extensions (Load unpacked from this directory the first time).\n'
