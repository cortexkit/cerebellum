#!/usr/bin/env bash
# Use the prebuilt development example so manifest writes use private_fs.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
probe="${USER_BROWSER_PROBE:-$root/target/debug/examples/user_browser_probe}"

if [[ $# != 1 || "$1" != /* ]]; then
  printf 'Usage: %s /absolute/path/to/ck-cerebellum-native-host\n' "$0" >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  printf 'The Chrome native host is supported on macOS only.\n' >&2
  exit 2
fi
if [[ ! -x "$probe" ]]; then
  printf 'Build the installer first: cargo build -p cerebellum --example user_browser_probe\n' >&2
  printf 'Or set USER_BROWSER_PROBE to its prebuilt executable. No files were written.\n' >&2
  exit 2
fi
exec "$probe" --install-native-host "$1" --extension-dir "$root/extension"
