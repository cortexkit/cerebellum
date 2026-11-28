#!/usr/bin/env bash
# The test uses only displays this script starts. Never reuse an inherited DISPLAY.
set -euo pipefail
if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ]]; then
    if [[ ${CK_X11_FIXTURE_LOCAL:-} != 1 ]]; then
        echo 'X11 pictures require the private fixture runner.' >&2
        exit 2
    fi
fi
work=$(mktemp -d /tmp/ck-x11-picture.XXXXXXXX)
pids=()
cleanup() {
    local pid
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

start_display() {
    local name=$1
    shift
    local auth="$work/$name.authority" number="$work/$name.display" cookie pid
    touch "$auth"
    chmod 600 "$auth"
    cookie=$(timeout 5s mcookie)
    timeout 5s xauth -f "$auth" add :0 MIT-MAGIC-COOKIE-1 "$cookie"
    timeout -k 5s 330s Xvfb -screen 0 800x600x24 -nolisten tcp -auth "$auth" \
        -displayfd 9 "$@" 9>"$number" >"$work/$name.log" 2>&1 &
    pid=$!
    pids+=("$pid")
    local i display_number
    for ((i = 0; i < 100; i++)); do
        [[ ! -s "$number" ]] || break
        kill -0 "$pid"
        sleep 0.05
    done
    if ! read -r display_number <"$number" || [[ ! $display_number =~ ^[0-9]+$ ]]; then
        echo "Private Xvfb failed to start ($name)." >&2
        exit 1
    fi
    timeout 5s xauth -f "$auth" add ":$display_number" MIT-MAGIC-COOKIE-1 "$cookie"
    display=":$display_number"
    authority="$auth"
}

here=$(dirname -- "${BASH_SOURCE[0]}")
timeout 20s cc -Wall -Werror "$here/decode-picture.c" -ljpeg -o "$work/decode-picture"
start_display capture
export CK_X11_FIXTURE_DISPLAY="$display" CK_X11_FIXTURE_AUTHORITY="$authority"
start_display no-composite -extension COMPOSITE
export CK_X11_NO_COMPOSITE_DISPLAY="$display" CK_X11_NO_COMPOSITE_AUTHORITY="$authority"
export CK_X11_DECODE_PICTURE="$work/decode-picture"
# Fixture clients read only the explicit fixture DISPLAY. Auth is inherited by
# the fixture clients, while the production seam reads the selected session.
export XAUTHORITY="$CK_X11_FIXTURE_AUTHORITY"
unset DISPLAY WAYLAND_DISPLAY

timeout -k 5s 300s cargo test --locked -p cerebellum --lib \
    computer_capability::linux::semantic_tests::picture_tests::native_x11_picture_matrix -- --ignored --exact --nocapture
