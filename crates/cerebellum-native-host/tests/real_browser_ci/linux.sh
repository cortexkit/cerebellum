#!/usr/bin/env bash
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ]]; then
  echo 'Run the browser image suite on a disposable GitHub-hosted runner.' >&2
  exit 2
fi

. /etc/os-release
case "$ID" in
  ubuntu) skip=linux::refusals::debian_ ;;
  debian) skip=linux::refusals::ubuntu_; export CK_IMAGE_TEST_DPKG_DISPOSABLE=1 ;;
  *) echo "Unexpected browser fixture distribution: $ID" >&2; exit 2 ;;
esac
export CK_IMAGE_TEST_DISTRO="$ID"

artifact=$(dirname "$0")/cargo-executable.py
CK_IMAGE_TEST_TRAILER=$(cargo build --locked --release -p cerebellum-bridge-protocol \
  --bin peer-trailer --message-format=json | python3 "$artifact" peer-trailer)
export CK_IMAGE_TEST_TRAILER
cargo test --locked --release -p cerebellum-native-host --features bridge-test-identities \
  --test real_browser_ci linux:: -- --ignored --skip linux::fixture_entry --skip "$skip" --nocapture --test-threads=1
