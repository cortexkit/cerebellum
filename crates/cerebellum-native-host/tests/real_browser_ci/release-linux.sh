#!/usr/bin/env bash
set -euo pipefail

coord=$(mktemp -d /tmp/ckbridge-ci.XXXXXXXX)
export CK_BRIDGE_CI_COORD="$coord"
export CK_BRIDGE_CI_SERVER="$coord/ck-cerebellum"
daemon_pid=
cleanup() {
  touch "$coord/stop"
  if [[ -n $daemon_pid ]]; then wait "$daemon_pid" || true; fi
  rm -rf "$coord"
}
trap cleanup EXIT
artifact=$(dirname "$0")/cargo-executable.py
CK_IMAGE_TEST_TRAILER=$(cargo build --locked --release -p cerebellum-bridge-protocol \
  --bin peer-trailer --message-format=json | python3 "$artifact" peer-trailer)
export CK_IMAGE_TEST_TRAILER
cargo test --locked --release -p cerebellum-native-host --features bridge-test-identities \
  --test real_browser_ci --no-run
cargo test --locked --release -p cerebellum --features bridge-test-identities \
  --test bridge_peer_ci --no-run --message-format=json > "$coord/cargo.json"
daemon=$(python3 "$artifact" bridge_peer_ci < "$coord/cargo.json")
server=$(python3 "$artifact" ck-cerebellum < "$coord/cargo.json")
cp "$server" "$CK_BRIDGE_CI_SERVER"
"$CK_IMAGE_TEST_TRAILER" sign --test-key "$CK_BRIDGE_CI_SERVER" cerebellum x86_64-unknown-linux-gnu ci
"$daemon" --exact scratch_subc_serves_the_signed_bridge --nocapture &
daemon_pid=$!
filter=()
# The Debian container runs as root. Prove the procfs denial in the Ubuntu
# leg, where the runner has no ptrace capability over a non-dumpable parent.
if [[ $(id -u) == 0 ]]; then filter+=(--skip rejects_a_non_dumpable_parent); fi
cargo test --locked --release -p cerebellum-native-host --features bridge-test-identities \
  --test real_browser_ci release_sessions::signed_release -- --ignored --nocapture --test-threads=1 "${filter[@]}"
touch "$coord/stop"
wait "$daemon_pid"
daemon_pid=
