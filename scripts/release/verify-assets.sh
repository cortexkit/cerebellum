#!/usr/bin/env bash
# Check the exact release inventory and verify each ZIP against its .sha256 file.
set -euo pipefail

assets=$(cd "${1:?usage: $0 <assets-dir> <expected-manifest>}" && pwd)
manifest="${2:?usage: $0 <assets-dir> <expected-manifest>}"
cmp "$manifest" "$assets/release-manifest.json"
cd "$assets"

archives=(ck-cerebellum-darwin-arm64.zip ck-cerebellum-native-host-darwin-arm64.zip ck-cerebellum-extension.zip ck-cerebellum-linux-x64.zip)
shopt -s nullglob dotglob
files=(*)
if [[ ${#files[@]} != $((2 * ${#archives[@]} + 1)) ]]; then
  echo 'Unexpected asset count: expected exactly the four ZIPs, their sidecars, and release-manifest.json.' >&2
  exit 1
fi

for archive in "${archives[@]}"; do
  actual=$(shasum -a 256 "$archive")
  if ! cmp -s "$archive.sha256" <(printf '%s\n' "$actual"); then
    echo "Missing or incorrect checksum: $archive.sha256" >&2
    exit 1
  fi
  echo "Verified: $archive"
done
