# Using your own Chrome

`browser_use` defaults to the agent's own browser. To work in your signed-in
Chrome, explicitly use `browser: "user"`. The `browser: "user"` target is available
only when the existing own-browser configuration is valid; loading the extension alone does
not enable the tool.

The extension controls only tabs in its coloured **Agent** group and tabs you
hand over through its UI. An agent opens a background tab with `open_tab`, or
claims a handed-over tab with `claim_tab`. Page actions must name the returned
opaque `tab` handle. Tabs outside the group are not visible to the agent. Closing
a route releases its claims and detaches the debugger; it does not close your
tabs or quit Chrome.

## Permission and freshness

The first visit to each site asks for permission to use **your own Chrome, signed
in as you**. Choose allow once, always on this site, or decline. There is no
all-sites grant. Grants for the agent's own browser do not authorize the user
browser, and vice versa. Redirects and cross-origin frames require their own site
permission. Embedded frames currently fail closed (`embedded_frame_unsupported`);
the user-browser implementation currently drives top-level pages only. Credential and payment
fields still refuse typing.

Chrome shows a debugging bar during an action. The debugger detaches between
actions. If you interact with or activate a controlled tab, an old snapshot can
no longer authorize input: the agent must read again. A worker reconnect also
invalidates old snapshots; commands are never replayed.

## Development installation in normal Chrome

Use an unpacked extension for development. Branded Chrome 137 and later ignores
`--load-extension`; do not use that switch to install into your normal browser.

1. Build and sign the native messaging host and cerebellum using the fleet
   certificate (Team ID `5R5846NBPW`), not ad-hoc signing. See
   [`crates/cerebellum-native-host/README.md`](../crates/cerebellum-native-host/README.md)
   for `sign-host.sh` and the deployed identifiers. Build the small development
   installer once: `cargo build --locked -p cerebellum --example user_browser_probe`.
   Keep the signed host binary in a stable location.
2. Run `scripts/install-native-host.sh` with the absolute path to the signed host.
   It writes only Chrome's native-host manifest, under
   `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`.
3. Open **`chrome://extensions`** in your normal Google Chrome.
4. Turn **Developer mode** on, click **Load unpacked**, and select this
   repository's `extension/` directory. Do not regenerate its manifest key: the
   key pins the extension id accepted by the native host.
5. Start your configured cerebellum instance. The extension connects its native
   host automatically; use its toolbar button to hand over a tab when desired.

Only Google Chrome is supported for this feature. The helper does not install
into Brave, Edge or Arc, modify browser profiles, launch a browser, or install
binaries. Its unpacked extension key is public: the bridge excludes unsigned
local impostors, but does not exclude same-user code that launches its own
signed Chrome with a lookalike extension. Web Store distribution is a separate
future boundary.

## Isolated real-browser probe

The opt-in example `user_browser_probe` is for **Chrome for Testing**, not your
normal Chrome. It must run only with the operator's approval and against its
loopback fixtures. Never point it at a live Chrome profile or a live journal.

### Preparation (no live browser run)

The installer uses the prebuilt example's `--install-native-host` mode to write
through `private_fs`; it does not invoke Cargo, sign or copy binaries, write
backups, or edit the extension. If a custom Cargo target directory is used, set
`USER_BROWSER_PROBE=/absolute/path/to/examples/user_browser_probe` when invoking
the shell helper. The manifest name is `com.cortexkit.cerebellum.json`, type is
`stdio`, and its sole allowed origin is
`chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/`. Redirected (symlinked)
manifest paths are refused.

The real probe needs **Chrome for Testing 155.0.8059.39, mac-arm64**, the version
pinned by the `chrome-for-testing-parent-probe` development feature. Stock CfT
has an ad-hoc loader signature, so the production host does not admit it. This
feature is weaker than Google's production certificate check: it pins the
loader cdhash, not dynamically loaded frameworks. Do not use it in a shipped
build; see
[`PEER_ATTESTATION.md`](../crates/cerebellum-macos/PEER_ATTESTATION.md).

Build the two probe artifacts, then sign them with the fleet development
certificate. The example acts as the scratch cerebellum server, so it must be
signed with the **`ck-cerebellum`** identifier, not its example filename:

```sh
cargo build --locked -p cerebellum --example user_browser_probe \
  --features chrome-for-testing-parent-probe
cargo build --locked -p cerebellum-native-host \
  --features chrome-for-testing-parent-probe
bash crates/cerebellum-native-host/sign-host.sh \
  target/debug/ck-cerebellum-native-host '<fleet signing identity>'
codesign --force --options runtime --timestamp \
  --identifier ck-cerebellum --sign '<fleet signing identity>' \
  target/debug/examples/user_browser_probe
```

No installation into normal Chrome is needed for the probe. It writes manifests
only beneath its scratch user-data directory and scratch HOME (including CfT's
`Google/ChromeForTesting/NativeMessagingHosts` location). The socket is selected
by the inherited `XDG_DATA_HOME`, not `XDG_RUNTIME_DIR`: the probe verifies the
resolved `data/cortexkit/run/cerebellum/user-browser.sock` stays beneath the
scratch root before binding. It uses an isolated in-process `Planes` instance,
not a running daemon or the operator's journal. No profile or journal path is
accepted as an argument.

### One-command approved run

**Ask the operator before this command.** Budget: **180 seconds plus up to
3 seconds of cleanup**. It is a headed browser, launched with
`--no-startup-window`; the harness never activates Chrome, a tab or a window,
and never restores focus. **Chrome/macOS startup might still front a window;
this harness cannot guarantee it will not. Such a change fails the probe.**
Keep your current app and focus unchanged during the run. Foreground pid is
sampled every 10 ms, so this is sampled evidence, not proof against an arbitrarily
short transient. The probe also watches Chrome tab/window activation events.

```sh
target/debug/examples/user_browser_probe --approve-local-probe \
  --chrome '/absolute/path/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing' \
  --native-host "$PWD/target/debug/ck-cerebellum-native-host" \
  --extension-dir "$PWD/extension"
```

All generated directories are private and under `/tmp` (on macOS,
`/private/tmp`). Only loopback fixtures are navigated; no external URLs or
operator tabs are used. A scratch consent relay validates the production card's
browser target, exact fixture origin, wording and `allow_once` choice before
answering. No phone, live consent channel or standing permission is needed.
It prints a **PASS/FAIL line per check** and exits nonzero on a failed check.

Checks cover opening an Agent tab, per-site consent, allow-once expiration,
snapshot, click and type with independent fixture beacons, an unrelated
outside-group tab's invisibility/refused read/survival, no activation, and
`chrome.debugger.getTargets()` showing no attached Agent page between actions.
The independent observer attaches only to the extension worker and unrelated
fixture; it does not drive Agent pages or stand in for `browser_use`.

For worker loss, the observer uses CDP `ServiceWorker.stopWorker`, verifies the
old worker/connection disappeared, and explicitly wakes the registration with
`ServiceWorker.startWorker`. The production native connection must acquire a
new epoch; old handles must refuse and fixture readback must show no replay.
This tests kill-and-wake reconnection, **not automatic alarm timing**. After a
reconnect, agents need new handles and fresh authorized reads.

The supervisor owns only the process group it spawned. It terminates/reaps that
group and also checks for detached helpers carrying the run's random scratch
path, with a kernel process-generation recheck before signalling. It removes
scratch state on success, failure, timeout, Ctrl-C and SIGTERM. SIGKILL of the
supervisor or a machine failure cannot execute cleanup. Cleanup failures are
reported rather than silently accepted.

The local fixtures deliberately do not open popups. Script-created popups are
not a no-focus guarantee in the current extension: its narrow recovery can
restore remembered tab/window focus after a transient activation. That known
limitation is outside this probe's top-level click/type checks.

### Offline verification without Chrome

```sh
cargo run --locked -p cerebellum --example user_browser_probe -- --self-test
bash -n scripts/install-native-host.sh
bash scripts/rust-test-gate.sh
```

The explicit self-test runs 11 portable checks (12 on macOS, including process-
group and directory cleanup) with driver doubles and scratch manifest
fixtures, without Chrome, a socket, a durable journal or any live profile. Its
negative controls deliberately fail named acceptance checks; the final named
self-test results distinguish these expected refusals from a test failure.
It does not substitute for the operator-approved real run. Passing doubles must
not be reported as a passing real-Chrome probe.

Primary references: [native host locations and framing](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging),
[user-data directory overrides](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md),
[`chrome.debugger` targets and attachment](https://developer.chrome.com/docs/extensions/reference/api/debugger),
and [CDP ServiceWorker control](https://chromedevtools.github.io/devtools-protocol/tot/ServiceWorker/).
The headed launch, native-manifest discovery and worker-control sequence still
need validation on the pinned CfT build; the harness fails closed if any is
unavailable, with no fallback to the person's profile or socket.
