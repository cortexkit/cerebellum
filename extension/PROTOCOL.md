# Extension bridge protocol v2

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
undoes input. A dispatched mouse press has a release-only cleanup exception:
while its debugger attachment is still held, refusal or cancellation sends only
the matching release at the original point and button, never another press or
the rest of the plan. Prior input remains disclosed even when cleanup succeeds.
A late attach is detached, not replayed. If detachment cannot be
established (including an unresolved attach), the port is closed rather than
acknowledging a false `detached:true`. `goodbye` has `{type:"goodbye",route}` and
releases that route's claims without closing any tab. Connection loss clears
claims/baselines and stops old work before reconnect. New connections never
replay commands. Ignore stale epochs, ended invocation ids and duplicate dispatch.

Fixed deadlines: hello/attach/dispatch 5 seconds, whole reply 30 seconds, each
chunk 5 seconds, detach/cancellation 2 seconds. The bridge owns its FIFO queue;
overlapping extension invocations refuse as `action_busy` rather than forming a
second hidden queue.

Attach rejections retain the `debugger_busy` machine code for compatibility;
their `remedy` distinguishes another debugger, a missing tab, a restricted page,
and an unknown Chrome rejection. An unknown rejection quotes at most 200
characters of Chrome's message. The attach deadline remains `attach_deadline`,
and its remedy names the 5-second deadline rather than suggesting DevTools is
open. Refusal JSON also carries `attach_failure` (`rejection` or `deadline`) and
`attach_reason`; cerebellum currently forwards only the reason and remedy.
An existing pending attach refuses before contacting Chrome, with the separate
remedy to wait for debugger cleanup.

On Chrome's already-attached rejection, another attached active plan on the tab
is never disturbed. Otherwise the extension probes with `debugger.detach`,
which can detach only its own session. A successful probe permits one attach
retry; a rejected probe identifies another holder and permits no retry. The
probe and retry share the attach deadline, and cancellation prevents a late
probe from starting a new attach.

## Closed plans

All plans have `version:2` (the native socket envelope remains protocol 1). Unknown plan/command fields refuse. Optional fields
are omitted, not null.

### Contract revision

Every `completed` result (including a chunked one) carries
`extension_revision:<positive integer>` beside the fields below, and every
`refused` reason JSON carries it beside `reason` and `remedy`. The value is
`EXTENSION_REVISION` in `revision.mjs`; cerebellum requires exactly its own
`EXTENSION_REVISION` (in `crates/cerebellum/src/user_browser.rs`) and checks it
before decoding anything else. A missing or lower revision refuses as
`extension_outdated` and a higher one as `extension_newer`, both with a remedy
asking the person to reload the extension in `chrome://extensions`, for every
action including `status`. Raise both constants together whenever a plan, reply
or refusal shape in this document changes; a test compares them. The manifest
`version` is not this revision: Chrome keeps running whichever unpacked copy it
loaded, and that copy's `version` says nothing about the reply shapes it sends.
The result tables below omit `extension_revision`.

| action | fields besides version/action | result |
| --- | --- | --- |
| `status` | none | `{tabs:[{tab, claimed, handed, interaction_epoch}], connection_epoch}` |
| `open_tab` | optional `url` (HTTP(S), default `about:blank`), optional `opener_tab` (claimed handle from this route) | `{tab, interaction_epoch, connection_epoch}` |
| `claim_tab` | required `tab` (unclaimed handed handle, or already claimed by this route) | `{tab, interaction_epoch, connection_epoch}` |
| `close` | none | `{connection_epoch}` |
| `cdp` | required `tab`, required nonempty `commands` (maximum 256), optional `interaction_epoch` and `observer_continuity` (both required for input and observed navigation) | `{tab, results:[...], interaction_epoch, interaction_cause?, observer_available, observer_continuity, connection_epoch, popup_activated_briefly?:true}` |

`tab` is an opaque string, never a Chrome tab id. Status lists only this route's
claims and unclaimed handed tabs, not another route's claims or unclaimed
agent-opened tabs. Closing drops/rotates old handles. Agent-opened tabs remain in
the group; handed tabs are ungrouped. No close path closes Chrome or a tab.

CDP replies pair `interaction_epoch`, the counter of observed interactions and
unattributed navigation, with `observer_available`, which is true only after all
live frames answered the observer sample. `interaction_cause`, present once the
counter has moved, is a short code for the last thing that moved it:
`input.<event>.<main|subframe>`, naming one of the sentinel's event types and
whether it happened in the main frame or a child frame, or `navigation.main`
for a main-frame navigation the agent did not start. It never carries page
text, URLs or field values; cerebellum passes on only codes from this
vocabulary and names them in a `state_changed_by_person` refusal's `detail`.
`observer_available:false` never means no interaction occurred; its numeric counter
cannot authorize input. `observer_continuity` fences snapshots across observer loss
and replacement independently of the human-input counter. Unknown observation
refuses as `observer_unavailable`, not as a person-change accusation. This reply
shape requires matching current extension and Cerebellum builds.
Modifying plans carry the saved snapshot's continuity, not a newer baseline from
an internal classification read; a repaired observer cannot silently rebase old refs.

Observer injection is immediate and document-id scoped after `onCommitted`.
Before injection, the extension confirms Chrome's HTTP/S host access for that
document. Agent site consent is a separate permission and cannot grant Chrome
extension access. An initial blank tab without a live HTTP parent is deferred;
an embedded blank document may inherit its live parent's host access. A host-permission
binding error may retry once after reconfirming access and the same document;
this shares a two-injection budget with a fresh read's missing-receiver repair.
Input checks never reinstall or rebase a snapshot. Only an
agent-created `about:blank` tab without an opener may make its explicit first navigation without
observation: HTTP host permissions alone do not guarantee injection there. Both sides verify that
exception, and navigation success waits for confirmed observation on the landing
document. A handed or already-loaded HTTP tab has no such exception.

Each command is `{method:<string>, params:<object>}` with an optional complete
scope `{frame_id:<CDP string id>, loader_id:<CDP loader id>, session_id:<owner>}`.
The owner is `root` (the claimed tab) or a stable child target id, **not** an ephemeral debugger
session id. Scoped input is accepted only after the extension rediscovers the
frame and verifies all three fields. `frame_stale` refuses missing or navigated
frames; `frame_ambiguous` refuses more than one matching candidate. Read-only
commands for the top document do not require a webNavigation association.

An unscoped `Page.getFrameTree` returns a composite tree including OOPIF trees.
Its `cdp` reply also includes `frame_mappings:[{frame_id, parent_id?, loader_id,
session_id, url, web_navigation_frame_id?, document_id?, unreadable_reason?}]`.
`unreadable_reason` is `ambiguous` or `stale`; such an entry has no verified
webNavigation identity and does not authorize input. The extension joins
`webNavigation.getAllFrames` to CDP by the parent chain and exact URL, narrowing
by `documentId` when exposed by both APIs. It verifies webNavigation document ids
before and after discovery and compares the CDP tree across the read. A changing
tree is retried once; if it changes again, only affected child subtrees are
omitted. URL duplicates without a document-id proof are marked ambiguous, never
resolved to an arbitrary sibling. Stray navigation entries and sessions without
a reachable parent in the claimed tab's tree do not invalidate readable documents. Cerebellum
renders `[embedded frame not readable: ambiguous|stale]` at the iframe owner,
removes its refs, and reports `truncated:true`. The top document stays readable
even if its webNavigation mapping is unavailable. Input and scoped child commands
still refuse omissions exactly as above; each revalidates before and after
dispatch. WebNavigation numeric ids never address CDP commands.

After the bridge receives `dispatch` for a validated and attached CDP plan,
the extension internally sends exactly
`Target.setAutoAttach` with `{autoAttach:true,waitForDebuggerOnStart:false,
flatten:true,filter:[{type:"iframe",exclude:false},{exclude:true}]}` to the claimed
tab and recursively to its attached iframe sessions (Chrome 125+, below the
manifest's minimum version). Child `Page.getFrameTree` roots establish which
stable target owns each frame, without assuming target ids equal frame ids.
Chrome can omit OOPIFs entirely from the parent's tree; child roots are grafted
using their explicit CDP `parentId`, only beneath an already reachable parent.
An iframe owner in the parent AX tree whose child was not included (including
undiscovered, failed, empty or bounded captures) is also marked unreadable and
cannot retain an actionable ref, even if discovery returned no child entry.
Only descendants of this attachment are addressable; caller-supplied raw sessions
or target attach commands are not admitted. Detaching the tab after every plan
detaches its children too; nothing is retained across actions except ref identity.

Frame-aware `DOM.getNodeForLocation` returns an additional `frame_point:{x,y}`
in the resolved frame session's input coordinates. The extension verifies the
point from the root renderer (so an overlay cannot be bypassed), follows iframe
owners into child renderers, and maps affine frame coordinates just as the own
browser does. Perspective or unavailable geometry refuses. The internal geometry
vocabulary is pinned by name to `DOM.getFrameOwner`, `DOM.getBoxModel`,
`Page.createIsolatedWorld`, `DOM.resolveNode`, `Runtime.callFunctionOn`,
`Page.getLayoutMetrics`, and `DOM.getNodeForLocation`. The only internal Runtime
declaration reads native computed content width/height in the isolated world
`cortexkit-frame-geometry`; no caller text is evaluated. The additional geometry
methods are not caller-allowlisted. Mouse dispatch still uses the resolved child
session's local coordinates.

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
{"version":2,"action":"cdp","tab":"opaque-handle","commands":[
  {"method":"DOM.getFlattenedDocument","params":{"depth":1}},
  {"method":"DOM.resolveNode","params":{
    "backendNodeId":{"$result":0,"path":["nodes",0,"backendNodeId"]}}}
]}
```

Result references do not authorize input or arbitrary JavaScript.

### Vetted CDP methods

Terminal dispatch accounting uses `terminal-read-only-methods.json`, shared with
the Rust bridge. A method absent from that array is mutating by default.
`Accessibility.enable`, `DOM.enable`, and `Runtime.enable` configure only the
per-action debugger; frame-owner, outer-HTML, quad and hit-test queries observe
the page without changing it. They are explicitly read-only so a child capture
does not mark the call dispatched. Input, focus emulation and selection/caret
changes remain mutating; only the exact pinned focus-check function is exempt.

Choosing a child session does not create a new action or work allowance. Its
plans use the same Rust dispatch gate and remaining action deadline as the root
session. Internal child attachment and geometry steps stay within their admitted
plan; they are not new caller commands and do not extend that deadline.

`commands.mjs` allows **exactly**:

- `Page.getNavigationHistory`, `Page.getFrameTree`, `Page.navigate`, `Page.captureScreenshot`, `Page.getLayoutMetrics`
- `Accessibility.enable`, `Accessibility.getFullAXTree`
- `DOM.enable`, `DOM.getFlattenedDocument`, `DOM.getOuterHTML`, `DOM.getContentQuads`,
  `DOM.getNodeForLocation`, `DOM.focus`, `DOM.resolveNode`, `DOM.getFrameOwner`,
  `DOM.scrollIntoViewIfNeeded` (modifying, requires the last read's interaction epoch)
- `Runtime.enable`, `Runtime.callFunctionOn` (hash-pinned only, below)
- `Input.dispatchMouseEvent`, `Input.dispatchKeyEvent`, `Input.insertText`
- `Emulation.setFocusEmulationEnabled` (only `{enabled:true}`)

`dom_full` snapshots use `DOM.getOuterHTML` with `backendNodeId` for both the
document and its outermost content/chrome landmarks. Cerebellum uses the shared
main-first layout when the markup exceeds `max_bytes` and retains the refs named
in its cut/omission comments. A `dom_full` zoom reads that ref's outerHTML in the
same verified frame session, under the same layout and byte limit; `ax` still
refuses zoom. Markup within the limit, including frame separators, is unchanged.
These reads need no additional CDP methods or extension revision: the contract
remains revision 2.

Everything else in caller plans refuses before attaching, including `Runtime.evaluate`, all
`Browser.*`/`Target.*`, `Page.bringToFront`, downloads, arbitrary JavaScript and
commands reaching another tab. The internal `Target.setAutoAttach` pin above is
not a caller command. CDP node resolution is **DOM.resolveNode**, not
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

`Emulation.setFocusEmulationEnabled` emulates document focus for clicking and
typing, not tab/window activation. A mouse gesture's plan enables it before the
press/release pair; the debugger detaches between plans. `DOM.focus` focuses the typed element;
both methods are input-guarded. The stricter user-
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
click/key/wheel/input/touch events increment the interaction epoch only outside
the extension's own debugger attachment for that tab. CDP input is also trusted,
so an attached action's input cannot be distinguished from the person's by
`isTrusted` or an event fingerprint. The action window starts when attach succeeds
and ends when detach completes, with no grace period. Sentinel event timestamps
and bounded sequence history attribute delayed messages to the event's actual
side of those boundaries; missing history refuses input rather than hiding it.
Outside the window, even a click identical to the preceding agent click counts.
Focus/blur, tab activation and window focus never count as interaction.
Cursor movement alone
(`pointermove`/`mousemove`) is not interaction and is neither observed nor attributed.
The browser adapter types text with `Input.insertText` and uses
`Input.dispatchKeyEvent` only for non-text keys. Non-agent main-frame navigation
still invalidates freshness; agent Page navigation is excluded. A child frame's
navigation does not count: page script, input inside a frame (already counted
by that frame's sentinel, since every live frame must answer a sample) or the
back button walking a frame's history start it, and its new document changes
continuity when it commits.
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

Script-created popups that an agent's input on a claimed opener causes are caught
through `tabs.onCreated`/`webNavigation.onCreatedNavigationTarget`, grouped
immediately, and inherit the claim of the route whose input opened them, only
while that route still holds the opener. The extension attributes a new tab to
the agent only when Chrome reports it while a CDP plan from the claiming route
has dispatched input to the opener and is still attached. A tab the person opens
from a group member (a link click, "open in new tab") never inherits a claim and
is not grouped, activated or restored by the extension; if Chrome itself places
it in the Agent group, it is adopted as an unclaimed handed tab, and an agent
must `claim_tab` it. If a popup activates, the extension restores the
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
