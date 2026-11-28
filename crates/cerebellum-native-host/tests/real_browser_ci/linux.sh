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

chrome_path_stat() {
  stat -c 'mode=%a (%A) uid=%u gid=%g %N' -- \
    / /opt /opt/google /opt/google/chrome /opt/google/chrome/chrome \
    /var /var/lib /var/lib/dpkg /var/lib/dpkg/status /var/lib/dpkg/info \
    /var/lib/dpkg/info/google-chrome-stable*.list
  # These launcher links are not part of the product's executable path walk.
  namei -l -- /usr/bin/google-chrome /usr/bin/google-chrome-stable || true
}

if [[ $ID == ubuntu ]]; then
  echo 'Chrome path on the unmodified runner after package install:'
  chrome_path_stat
fi

artifact=$(dirname "$0")/cargo-executable.py
CK_IMAGE_TEST_TRAILER=$(cargo build --locked --release -p cerebellum-bridge-protocol \
  --bin peer-trailer --message-format=json | python3 "$artifact" peer-trailer)
export CK_IMAGE_TEST_TRAILER

test_command=(cargo test --locked --release -p cerebellum-native-host --features bridge-test-identities
  --test real_browser_ci)
unprotected_test=linux::refusals::ubuntu_unprotected_opt_is_refused
if [[ $ID == ubuntu ]]; then
  opt_mode=$(stat -c '%a' -- /opt)
  if (( 8#$opt_mode & 8#022 )); then
    "${test_command[@]}" "$unprotected_test" -- --ignored --exact --nocapture
  else
    echo '/opt is already protected against group/other writes; no unrepaired layout to test.'
  fi

  # The hosted image makes /opt writable. Keep Chrome at its real dpkg path,
  # but restore the ancestor directory modes required for browser attestation.
  sudo chmod go-w -- /opt /opt/google /opt/google/chrome
  writable_file=$(find /opt/google/chrome -type f -perm /022 -print -quit)
  if [[ -n $writable_file ]]; then
    echo "Reinstalling Chrome to restore package file modes (found writable file: $writable_file)"
    sudo apt-get install -y --reinstall "$RUNNER_TEMP/google-chrome-stable.deb"
  fi
  echo 'Chrome path before testing the protected layout:'
  chrome_path_stat
fi

"${test_command[@]}" linux:: -- --ignored --skip linux::fixture_entry --skip "$skip" \
  --skip "$unprotected_test" --nocapture --test-threads=1
