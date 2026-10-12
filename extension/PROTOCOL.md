# Extension bridge protocol v1

This is the inner command contract consumed by the user-browser adapter. The
extension does not render snapshots or decide site grants: cerebellum authorizes
the route, site, landing site, frames and classified target before creating a
plan, and renders its existing text/ref snapshots from the returned Chrome
DevTools Protocol (CDP) accessibility and DOM data. Grants for
other browser targets must not authorize these plans.

## Native connection and action lifecycle

Native host name: **`com.cortexkit.cerebellum`**. The fixed unpacked extension id is
`bfmlflnlaflnibiellpjjifdbcifciei`; the public manifest key is pinned by
`cerebellum-bridge-protocol`. The native host, not the extension, constructs and
attests `host_hello`. Chrome's native messaging API performs stdio length framing;
the extension never writes length prefixes itself.

The host forwards the shared socket frame objects unchanged through native
messaging: `{type:"host_accepted", protocol:1, epoch:<positive safe integer>}`,
`{type:"host_refused", reason:<string>}`, and `{type:"relay", message:<message>}`.
The extension sends only `relay` frames. A fresh port needs `host_accepted` before
any invocation. `tests/native-host-wire.json` holds a first `open_tab` exchange in
this exact shape; the extension's and the native host's tests both check it. Server-assigned ids/epochs must be JavaScript-safe integers
(1 through 9007199254740991); unsupported larger values are not rounded.

Messages are `{id, epoch, body}`. Invocation ids are positive; the bridge's route-wide
Goodbye uses `id:0`. Bodies follow `user_browser_bridge.rs`:

1. `attach`: `{type:"attach", route:{channel,epoch}, command:<plan>}`.
   Route channel is u16; route epoch is u32. The extension validates the **whole**
   plan, checks that the named tab is claimed by the route and belongs to the
   recorded Agent group, and attaches a debugger for CDP plans only. It
   does not run any CDP commands or input in this phase.
2. `attached`: `{type:"attached"}`.
3. `dispatch`: `{type:"dispatch"}`. Exactly one dispatch is accepted.
4. `dispatched`: `{type:"dispatched", input_dispatched:false}` immediately
   acknowledges dispatch admission; it is not a promise that subsequent input
   will not happen. Terminal replies report whether a modifying step was sent.
5. One terminal result: `completed`, `refused`, `cancelled`, or chunked completion.
   Each terminal acknowledgement has `input_dispatched` and `detached:true`.

`cancel` stops attaching, further commands/input and chunk production; it never
undoes input. A late attach is detached, not replayed. If detachment cannot be
established (including an unresolved attach), the port is closed rather than
acknowledging a false `detached:true`. `goodbye` has `{type:"goodbye",route}` and
releases that route's claims without closing any tab. Connection loss clears
claims/baselines and stops old work before reconnect. New connections never
replay commands. Ignore stale epochs, ended invocation ids and duplicate dispatch.

Fixed deadlines: hello/attach/dispatch 5 seconds, whole reply 30 seconds, each
chunk 5 seconds, detach/cancellation 2 seconds. The bridge owns its FIFO queue;
overlapping extension invocations refuse as `action_busy` rather than forming a
second hidden queue.

## Closed plans

All plans have `version:1`. Unknown plan/command fields refuse. Optional fields
are omitted, not null.

| action | fields besides version/action | result |
| --- | --- | --- |
| `status` | none | `{tabs:[{tab, claimed, handed, interaction_epoch}], connection_epoch}` |
| `open_tab` | optional `url` (HTTP(S), default `about:blank`), optional `opener_tab` (claimed handle from this route) | `{tab, interaction_epoch, connection_epoch}` |
| `claim_tab` | required `tab` (unclaimed handed handle, or already claimed by this route) | `{tab, interaction_epoch, connection_epoch}` |
| `close` | none | `{connection_epoch}` |
| `cdp` | required `tab`, required nonempty `commands` (maximum 256), optional `interaction_epoch` (required for every input/modifying plan) | `{tab, results:[...], interaction_epoch, connection_epoch, popup_activated_briefly?:true}` |

`tab` is an opaque string, never a Chrome tab id. Status lists only this route's
claims and unclaimed handed tabs, not another route's claims or unclaimed
agent-opened tabs. Closing drops/rotates old handles. Agent-opened tabs remain in
the group; handed tabs are ungrouped. No close path closes Chrome or a tab.

Each command is `{method:<string>, params:<object>, frame_id?:<nonnegative Chrome
webNavigation frame id>}`. `frame_id` selects only the input sentinel, **not** a CDP
execution context or another target. Flat child sessions (`session_id`) are
currently refused: the adapter must not assume OOPIF transport/authorization is
implemented. Same-process CDP frame/context parameters retain their CDP meanings.

Results are exactly `{result:<CDP result>}` or
`{error:{code:<int>, message:<string>}}`, in command order. Stop the plan at the
first CDP error; later commands are absent. The error is Chrome's own CDP code
and fixed protocol message (for example `-32000`, "DOM agent hasn't been
enabled"), which name the failure and carry no page content. Chrome's `data`
field is dropped. A message over 200 characters or containing control
characters, and any rejection that is not a CDP error object, becomes "Chrome
debugger command failed". Cerebellum reports the failing method, code and
message as the `detail` of its `cdp_error` refusal. Group/claim,
stale interaction, method allowlist and debugger-busy failures are **plan-level
refusals**, never a successful result containing an error entry.

### Result references within one attachment

To use a node/object resolved by an earlier command without keeping the debugger
attached between plans, a parameter value may be
`{"$result":<earlier zero-based command index>,"path":[<string or integer>,...]}`.
It is substituted from that entry's `result` before dispatch. It cannot refer
forward, traverse a prototype, or include other fields. For example:

```json
{"version":1,"action":"cdp","tab":"opaque-handle","commands":[
  {"method":"DOM.getFlattenedDocument","params":{"depth":1}},
  {"method":"DOM.resolveNode","params":{
    "backendNodeId":{"$result":0,"path":["nodes",0,"backendNodeId"]}}}
]}
```

Result references do not authorize input or arbitrary JavaScript.

### Vetted CDP methods

`commands.mjs` allows **exactly**:

- `Page.getNavigationHistory`, `Page.getFrameTree`, `Page.navigate`, `Page.captureScreenshot`, `Page.getLayoutMetrics`
- `Accessibility.enable`, `Accessibility.getFullAXTree`
- `DOM.enable`, `DOM.getFlattenedDocument`, `DOM.getOuterHTML`, `DOM.getContentQuads`,
  `DOM.getNodeForLocation`, `DOM.focus`, `DOM.resolveNode`
- `Runtime.enable`, `Runtime.callFunctionOn` (hash-pinned only, below)
- `Input.dispatchMouseEvent`, `Input.dispatchKeyEvent`, `Input.insertText`
- `Emulation.setFocusEmulationEnabled` (only `{enabled:true}`)

Everything else refuses before attaching, including `Runtime.evaluate`, all
`Browser.*`/`Target.*`, `Page.bringToFront`, downloads, arbitrary JavaScript and
commands reaching another tab. CDP node resolution is **DOM.resolveNode**, not
Runtime.resolveNode. The [CDP gap list](../docs/user-browser-gap-list.md) identifies the current driver's broader AX/DOM,
geometry/navigation/screenshot/typing vocabulary; this adapter's admitted subset
is deliberately narrower. The pipe driver's Target bootstrap and presentation
commands are not reusable here. The driver also uses a fixed devicePixelRatio
Runtime.evaluate and isolated-world geometry helpers; those are **not admitted**
by this contract and cannot be sent unchanged.

### Pinned Runtime function list

`Runtime.callFunctionOn` requires a nonempty string `objectId` (or a result reference
resolving to one), a string `functionDeclaration`, and `returnByValue:true`, with
no other parameters. SHA-256 is computed over the exact UTF-8 declaration, without
whitespace normalization. The digest must occur in `RUNTIME_FUNCTION_SHA256` in
`runtime-functions.mjs` and in the list below. A test compares the executable and
documented lists, independently hashes all three declarations, and refuses a
one-byte change. The browser adapter uses the matching declarations in
`crates/cerebellum/src/user_browser/functions.rs`. All admitted function calls are
conservatively modifying steps and require a fresh input baseline.

| Function | SHA-256 |
| --- | --- |
| SELECT | `5642611a1b2f6289d347bf6b0182feca100bb1cd024a91730bf48236a9924689` |
| APPEND_CARET | `ac62bcd9e6db95e84a42a90a37f286117b8ce6d3b0760ae1d1083c084d96bba7` |
| HAS_FOCUS | `2cd006d8e531e4e1c03b2e4bfebec513fe642134af0ddc6d7fb602ca9c835ffe` |

<!-- runtime-function-sha256 -->
```json
[
  "5642611a1b2f6289d347bf6b0182feca100bb1cd024a91730bf48236a9924689",
  "ac62bcd9e6db95e84a42a90a37f286117b8ce6d3b0760ae1d1083c084d96bba7",
  "2cd006d8e531e4e1c03b2e4bfebec513fe642134af0ddc6d7fb602ca9c835ffe"
]
```
<!-- /runtime-function-sha256 -->

Exact function declarations (also independently hash-tested in
`tests/functions-fixture.mjs`):

```js
const SELECT = "function() { if (typeof this.select === 'function') { this.select(); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } }";
const APPEND_CARET = "function() { if (typeof this.setSelectionRange === 'function') { const end = this.value.length; this.setSelectionRange(end, end); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); range.collapse(false); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } return true; }";
const HAS_FOCUS = "function() { return this.ownerDocument.hasFocus() && this.getRootNode().activeElement === this; }";
```

`Emulation.setFocusEmulationEnabled` and `DOM.focus` emulate document/element focus
for typing, not tab/window activation; both are input-guarded. The stricter user-
frame filter, site/redirect authorization and risk classifier remain the adapter's
responsibility, not raw-CDP permission conferred by a plan.

## Group and interaction boundaries

Membership is the extension's recorded **group id**, not a matching title. A
new background tab remains ineligible until `tabs.group` succeeds. The extension
rechecks group and route before attach, before every modifying step, after every
command, before returning content, and before every reply chunk. Withdrawal
cancels active work and invalidates its handle.

An isolated-world sentinel is injected only into group members. It reads no page
text, URLs or field values, and persists between debugger attachments. Trusted
click/key/wheel/input/touch events increment the interaction epoch unless they match the
one-shot, exact ticket for the currently dispatched agent input. Ambiguous,
unmatched or expired events count as the person's input. Cursor movement alone
(`pointermove`/`mousemove`) is not interaction and is neither observed nor attributed.
Text-producing key events are intentionally not attributed: they count as the
person's input. The browser adapter must type text with `Input.insertText` and use
`Input.dispatchKeyEvent` only for non-text keys. Human activation and
non-agent navigation also invalidate freshness; agent Page navigation is excluded.
Missing observer/frame coverage and changed document identity invalidate input.

Successful AX/DOM content reads or screenshots with live observer coverage establish
an input baseline. Input plans must supply that read's `interaction_epoch`; status/open/claim, a
refused input, and reconnect do not create a baseline. Epochs are checked before
**each** modifying step. Reconnect clears baselines even if numeric interaction
epochs happen to coincide. Snapshot/ref scoping must also include route, tab,
user-browser target and `connection_epoch` in cerebellum's user-browser adapter.

Plan refusals use the bridge's `refused` message. Its `reason` string encodes JSON
`{"reason":<machine reason>,"remedy":<human remedy>,...}`; stale/continuity failures
say `read again`. The enclosing terminal frame carries prior-input and detach
metadata; partial results are never returned on a plan refusal.

## Popup disposition and explicit limitation

Prefer `open_tab` with `url` and `opener_tab` for links known to open a new tab.
It uses `tabs.create({active:false,openerTabId,windowId})` followed by
`tabs.group({groupId,tabIds})`; `groupId` is not a tabs.create property. This path
does not activate a tab/window.

Script-created popups from an eligible opener are caught through
`tabs.onCreated`/`webNavigation.onCreatedNavigationTarget`, grouped immediately,
and inherit the opener's claim. If a popup activates, the extension restores the
remembered active **tab/window ids only** and returns
`popup_activated_briefly:true` on the opener's next CDP reply. It remembers the
initial active ids and subsequent activation/focus events, never retaining or
returning outside-tab content or handles. This is a narrow owner-approved exception
to strict no-focus-change: transient activation **can happen**, and focus restoration
is best effort if the remembered tab/window was closed. It is not the original
G10 guarantee of zero transient focus changes. Popups from outside openers are
never grouped, read, driven or restored by the extension.

## Bounded replies

The complete escaped native JSON envelope must fit 1 MiB. Larger results use
`reply_start {bytes,input_dispatched}`, zero-based ordered
`reply_chunk {sequence,data}` strings, then
`reply_end {input_dispatched,detached:true}`. Chunks contain at most 128 KiB of
UTF-8 data, are split at Unicode scalar boundaries, and their **escaped envelope**
is checked against 1 MiB too. Aggregate result JSON is at most 16 MiB. Transfer
yields between chunks so Cancel/withdrawal can stop it; no partial reply is valid
without reply_end. The debugger is detached before reply transfer.
