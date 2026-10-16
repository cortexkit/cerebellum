# CortexKit Agent Tabs (development extension)

An unpacked, plain-ES-module Manifest V3 extension for the **user** browser target.
It keeps automation in its recorded blue **Agent** tab group and attaches Chrome's
debugger only for each CDP plan (an ordered, bounded batch of Chrome DevTools
Protocol commands for one claimed tab). There is no bundler, package install, telemetry,
logging, page-text persistence or background debugger attachment.

## Load and hand over tabs

1. Install the signed native host and its Chrome NativeMessagingHosts manifest
   using cerebellum's native-host installation command when available (the installer
   is not included in this directory). Its name must be
   `com.cortexkit.cerebellum`, allowed origin
   `chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/`.
2. In normal Chrome 137+, open `chrome://extensions`, enable **Developer mode**,
   choose **Load unpacked**, and select this `extension/` directory. Branded Chrome
   ignores `--load-extension`; only the approved scratch-profile Chrome for Testing
   acceptance probe should use that switch.
3. Click the extension's toolbar button (pin it if needed), or use the page context
   menu's **Hand tab to Agent / take it back**. The named tab joins the blue Agent
   group. Click again to take it back. Moving it out of the group also withdraws it
   immediately; stale handles/input refuse. Hand-over never activates another tab.

Only the recorded group id is trusted; renaming another group to Agent does not
make it eligible. The extension does not list/read/drive outside tab contents.
It remembers only active tab/window **ids** for the popup exception below. It
refuses hand-over across windows rather than moving the person's active tab;
move a tab into the Agent group's window first. Agent-created tabs open with
`active:false` and are not eligible until grouped. Close/Goodbye never closes any
tab: handed tabs return to the person, agent-created tabs stay for them to close.

The native port sustains the worker on supported Chrome. A lost port schedules
reconnect with a Chrome alarm; a restarted worker also connects anew. Old commands
are never replayed, handles rotate on worker restart, claims/baselines are cleared,
and a new authorized read is required before input. Every CDP plan detaches on
completion, error, withdrawal, Cancel or disconnect. DevTools/other debugger
ownership refuses rather than being taken over.

## Popup limitation (explicit owner-approved exception)

For a known new-tab link, cerebellum's user-browser adapter should issue `open_tab` with `url` and
`opener_tab`, not click the link: `tabs.create({active:false,openerTabId})` followed
by `tabs.group` keeps it background-only. `tabs.create` has no `groupId` property.

A script-created `window.open`/native popup **may briefly activate** before Chrome
notifies the extension. For an Agent-group opener only, the extension groups that
popup, restores the remembered tab/window ids if they still exist, and marks the
opener's CDP reply `popup_activated_briefly:true`. This recovery is a narrow exception
to the otherwise strict no-focus-change rule, **not** a guarantee of zero transient
activation. Popups from non-Agent openers are never touched. Recovery cannot restore
a remembered tab/window that the person closed, and Chrome's event timing still
needs an operator-approved real-Chrome probe observing activation throughout both
explicit-open and script-popup fixtures. No after-the-fact repair is used for ordinary
agent actions.

## Adapter boundaries and current limits

Read [`PROTOCOL.md`](PROTOCOL.md) for exact wire/plan/result schemas, native host
name, epoch semantics, method allowlist, chunk limits, deadlines and cancellation.
The extension is a bounded CDP adapter, not a second snapshot renderer or permission
store. The cerebellum user-target adapter must enforce per-site permission and
recheck the landing site's permission after every navigation/redirect,
filter unauthorized frame contributions before returning content, classify live
input targets and enforce credential/payment floors. Raw CDP plans must never be
exposed as an unadmitted public tool.

The allowlist supports an explicit subset of the current driver's AX/DOM traversal,
geometry, navigation, screenshots and classified input. Runtime function calls are
fail-closed behind three SHA-256 pins for the browser adapter's exact selection,
append-caret and focus-check declarations. Tests independently hash each declaration
and reject a one-byte change. It intentionally refuses browser-wide
Target bootstrap/activation, downloads, Runtime.evaluate and arbitrary JavaScript.
OOPIF child sessions are discovered only beneath the claimed tab's per-action
attachment. Protocol v2 maps CDP frames to webNavigation by parent chain and URL,
with document ids when exposed. Ambiguous or stale child reads are omitted with
a marker and a partial-snapshot flag; the rest of the page remains readable.
Input through an unverified frame still refuses. Reads
include embedded frames under the top site's grant; child input needs that
frame's origin grant. Missing sentinel/frame coverage also refuses input. These limits must remain visible to the
adapter and real-Chrome acceptance probes; a test double does not establish actual
Chrome compatibility or frame/site authorization.

## Offline extension harness

Run from the repository root:

```sh
node --version
node extension/test-gate.mjs
```

The shared gate runs `node --test --test-reporter=tap` with its working directory
set to `extension/tests/`, propagates any test failure, and refuses a missing or
zero test count. It is a phase of
`scripts/rust-test-gate.sh` and an explicit step of the Linux CI job, using the
runner's existing Node. The harness uses only Node's built-ins and Chrome doubles: no network, real browser,
operator profile, consent dialogs or durable journal. It tests membership races,
route-bound handles, detached and mid-action human input, click/activation (not
cursor movement alone), worker loss,
per-plan detachment, Cancel/chunks/reconnect, SHA-256 Runtime function-pin rejection and both popup
paths. `node --check` on shipped JS modules supplies syntax checking; this plain-JS
slice has no TypeScript package/typecheck. The Rust repository gate is still required
alongside these extension tests. Real Chrome probes require operator approval and
local fixtures in a scratch Chrome for Testing profile.
