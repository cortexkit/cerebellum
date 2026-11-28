#!/usr/bin/env bash
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ]]; then
    printf '%s\n' 'These fixtures require a GitHub-hosted Linux runner.' >&2
    exit 2
fi

fixture_dir=crates/cerebellum-computer/src/platform/linux/fixtures
root=$(mktemp -d /tmp/cereb-semantic.XXXXXXXX)
children=()
cleanup_children() {
    local i pid
    for ((i=${#children[@]} - 1; i >= 0; i--)); do
        pid=${children[i]}
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    children=()
}
finish() {
    local status=$?
    trap - EXIT
    cleanup_children
    if ((status != 0)); then
        for log in "$root"/*/*.log; do
            [[ ! -f $log ]] || { printf '\n%s\n' "$log"; tail -n 25 "$log"; }
        done
    fi
    rm -rf -- "$root"
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start() {
    local log=$1
    shift
    timeout --kill-after=2s 7m "$@" >"$log" 2>&1 &
    children+=("$!")
}

await() {
    for _ in {1..100}; do
        if "$@"; then return 0; fi
        sleep 0.1
    done
    printf 'Fixture did not become ready: %s\n' "$*" >&2
    return 1
}

owns_focus() {
    local active rest
    [[ -s $1 ]] || return 1
    IFS=$'\t' read -r active rest < "$1"
    [[ $active == 1 ]]
}

wm_ready() {
    local reply
    reply=$(timeout 1s xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null) || return 1
    [[ $reply == *'window id # 0x'* ]]
}

gtk_flags=$(pkg-config --cflags --libs gtk4)
# pkg-config emits shell words for the fixed install under /usr.
# shellcheck disable=SC2086
timeout 45s cc -Wall -Wextra -Werror "$fixture_dir/semantic.c" $gtk_flags -o "$root/editor"
cp -- "$root/editor" "$root/pinentry-semantic-fixture"

for kind in x11 wayland; do
    dir=$root/$kind
    mkdir -m 0700 "$dir"
    export XDG_RUNTIME_DIR="$dir"
    export XDG_CONFIG_HOME="$dir/config" XDG_DATA_HOME="$dir/data" GSETTINGS_BACKEND=memory
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$dir/user-bus"
    export AT_SPI_BUS_ADDRESS="unix:path=$dir/a11y-bus"
    start "$dir/user-bus.log" dbus-daemon --session --nofork --address="$DBUS_SESSION_BUS_ADDRESS"
    start "$dir/a11y-bus.log" dbus-daemon --session --nofork --address="$AT_SPI_BUS_ADDRESS"
    await test -S "$dir/user-bus"
    await test -S "$dir/a11y-bus"
    start "$dir/registry.log" /usr/libexec/at-spi2-registryd
    unset WAYLAND_DISPLAY
    start "$dir/xvfb.log" bash -c 'exec Xvfb -displayfd 3 -screen 0 1024x768x24 -nolisten tcp 3>"$1"' _ "$dir/display"
    await test -s "$dir/display"
    IFS= read -r display < "$dir/display"
    [[ $display =~ ^[0-9]+$ ]]
    export DISPLAY=:$display
    start "$dir/wm.log" openbox --sm-disable
    await wm_ready
    if [[ $kind == wayland ]]; then
        # Weston's headless backend creates no seat. Nest it on Xvfb for a
        # virtual keyboard seat; the GTK clients use only native Wayland.
        export WAYLAND_DISPLAY=wayland-semantic
        start "$dir/weston.log" weston --backend=x11-backend.so --use-pixman --socket="$WAYLAND_DISPLAY" --idle-time=0
        await test -S "$dir/$WAYLAND_DISPLAY"
        unset DISPLAY
    fi
    export GDK_BACKEND=$kind GTK_A11Y=atspi
    export CK_SEMANTIC_KIND=$kind CK_SEMANTIC_TARGET="$dir/target" CK_SEMANTIC_OTHER="$dir/other"
    start "$dir/no-tree.log" env GTK_A11Y=none "$root/editor" 'Semantic Hidden Tree' "$dir/no-tree"
    await owns_focus "$dir/no-tree"
    start "$dir/operator.log" "$root/pinentry-semantic-fixture" 'Semantic Operator' "$dir/operator"
    await owns_focus "$dir/operator"
    start "$dir/target.log" "$root/editor" 'Semantic Target' "$dir/target"
    await owns_focus "$dir/target"
    start "$dir/other.log" "$root/editor" 'Semantic Other' "$dir/other"
    await owns_focus "$dir/other"
    timeout --kill-after=10s 6m cargo test --locked -p cerebellum --lib \
        computer_capability::linux::semantic_tests::native_gtk_semantic_actions -- --ignored --exact
    cleanup_children
done
