# Turn-stop cancellation, v1

This is the cerebellum receive-side contract for a head's relayed
`browser_use` and `computer_use` calls. It uses subc wire v2
(`subc-protocol` 0.31.0). The executable examples are in
[`crates/cerebellum/tests/vectors/turn-stop-cancel-v1`](../../crates/cerebellum/tests/vectors/turn-stop-cancel-v1/).
They contain exact frames, not reconstructed tool-result examples.

## What core sends

For **each outstanding request**, send `FrameType::Cancel` on the **same
route channel and epoch**, with the **same correlation (`corr`)** as that
request. Send a zero-length body: there is no JSON object, method name,
`call_key`, or cancellation reason in a Cancel. Preserve the negotiated wire
version. A relayed call is cancelled on cerebellum's receiving route, not on
channel zero or a newly opened management route. Core must retain the
receiving `(channel, epoch, corr)` for every in-flight relay. Cancelling one
correlation does not cancel another call, route, conversation, or head.

For example, channel 7, epoch 1, correlation 43 has this complete Cancel
frame (hex, including the body-length prefix):

```text
000000000206000700010000002b00000000000000
```

The body is not parsed. An older sender's `{}` body also works, but the wire
form to send is the empty body. The empty-body app-card test checks that both
forms produce identical reply bytes.

**Do not use `tool.withdraw {call_key}` to stop a turn.** It reads the recorded
call's disposition and answers about it; it does not signal the live request's
cancellation handle. Its guarantee about an already-held consent-only call is
not an interrupt of queued or running execution.

## Replies and races

Cancel has **no acknowledgement of its own**. A live request receives its
ordinary terminal `Response` or `Error`, addressed to its original route and
correlation. There is at most one terminal reply. If completion already won,
that reply can still be success. Core must not infer that an action was undone
from having sent Cancel, and must not automatically retry an interrupted action.

A Cancel after the terminal reply, for an unknown correlation, with the wrong
epoch/channel, or on channel zero is ignored with **no reply**. Core must not
wait for a cancellation acknowledgement in these cases. It should retire its
turn's outstanding relay bookkeeping independently of any acknowledgement.
A stop is not a route unbind: do not send `Goodbye` just to stop a turn.

Cancellation closes the dispatch gate: no new ordinary external mutation may
start through that gate. Work already inside a platform/browser call need not
be interruptible. The terminal arbiter allows bounded cleanup/release (currently
up to 6 seconds), then can answer while retaining the worker's lane and capacity
until the worker actually ends. A subsequent action against that quarantined
target can return `target_busy`; this is not permission to overlap/retry it.

## Queued calls

Queues include the computer per-application/per-conversation lanes and the
browser per-conversation lane. Waiting behind another call's consent card is
still queued work, not permission to run when that other card is answered.
Cancelling the queued call removes its ability to dispatch. It does **not**
withdraw or detach the predecessor's card.

* **Computer `read_state`** in the queue returns a `Response`, exactly:
  `{"outcome":"cancelled","remedy":"the call was cancelled before it ran; nothing was done"}`.
  Other non-input/non-wait computer actions use this same queue refusal.
* **Computer `wait`** uses its wait-result vocabulary: `outcome:"cancelled"`,
  `attempts:0`, `settle_path:"poll_with_deadline"`, and an `evidence` JSON string
  with `status:"indeterminate"`, the requested predicate, `readback:null`, and
  `reason:"{\"reason\":\"cancelled_while_awaiting_consent\"}"`.
* **Computer `keys`/`type` and takeover input** use the synthetic cancellation
  result: `outcome:"cancelled"`, `posts_returned:0`,
  `reason:"caller_interrupted_none_held"`, and
  `remedy:"the action was interrupted by the caller; no retry is implied"`.
  `keys`/`type` additionally carry their normal synthetic envelope
  (`containment_rung:"global_none"`, `target_fronted:false`,
  `effect_status:"not_dispatched"`).
* **Browser** queued work returns an `Error`, exactly:
  `{"code":"cancelled","message":"the queued browser call ended before authorization or execution"}`.

If Cancel wins before the computer handler even enters its queue, the outer
arbiter can instead return `{"attempts":0,"outcome":"cancelled"}`. The
corresponding browser pre-queue path uses the browser queue `Error` above.
Do not require the computer queue remedy to recognize a cancelled call.

## Running calls and held input

When a mutation may already have started, the frame handler for both
`browser_use` and `computer_use`
returns this `Response` family, not the older direct-dispatch `cancelled`
synthetic result:

```json
{"detail":{"dispatched":true,"held_state":"released","reason":"cancelled","step":"dispatch"},"effect_status":"effect_indeterminate","outcome":"dispatch_outcome_unknown","remedy":"read the state before retrying"}
```

`held_state` is `none_held`, `released`, or `unknown`. The running-key vector
has `released`; the running-navigation vector has `none_held`. `step` is
`dispatch` once a mutation may have started, or `release` when that later
checkpoint was recorded. Earlier checkpoints cannot override evidence of
possible dispatch. Use `dispatched` and `effect_status` to reason about possible
effects; `dispatch` does not assert that an effect was observed.

The synthetic dispatch layer itself can produce `outcome:"cancelled"`,
`posts_returned`, a held-state-dependent `reason` (`caller_interrupted_none_held`,
`caller_interrupted_held_input_released`, or
`caller_interrupted_held_state_unknown`), and
`remedy:"the action was interrupted by the caller; no retry is implied"`.
That is not a promise that this legacy shape survives arbitration after dispatch:
the outer frame handler's `dispatch_outcome_unknown` result takes precedence
once effects are possible.

Paired key and mouse-button releases are allowed even after the dispatch gate stops.
Computer sequences recover their outstanding presses; browser input tracks and
releases its outstanding presses as well. Release is best-effort and bounded,
not a claim that a wedged or exited platform accepted it. `unknown` means release
could not be confirmed; subsequent input must first resolve the held-input
quarantine. Cancelling never permits new presses in the name of recovery.

A running read/poll that has made no mutation can still return its cooperative
`cancelled` result. For example, `computer.wait` may carry its returned attempt
count and wait evidence. If cooperative cleanup cannot supply that reply within
the cleanup allowance, the outer before-dispatch fallback is
`{"attempts":0,"outcome":"cancelled"}` for computer and
`{"context":null,"outcome":"cancelled"}` for browser. These do not claim
that a readback or mutation succeeded.

## Waiting on a consent card

On a still-live route/conversation, turn-stop detaches the waiting card rather
than treating the person's silence as a denial. It ends the waiting call;
a late approval cannot resume that cancelled action. If Cingulate, the consent
service, reports
that the card could not be detached, the consent desk attempts withdrawal
instead. A transport error does not confirm either operation. A route close or
module drain is a
different event and ordinarily withdraws a still-attached waiting card.

### Computer app card

The `computer.wait` app-card example's exact response is in
`computer-app-card.json`: `outcome:"cancelled"`, `attempts:0`,
`settle_path:"poll_with_deadline"`, and the evidence string described above.
`keys`/`type` waiting on an app card use the zero-post synthetic result and
envelope described under queued calls. A cancelled read-state app request uses
the grant refusal `{"outcome":"cancelled"}`. Before-dispatch arbitration can
also supply the computer fallback described above.

The app question remains open and answerable for the conversation. A late
approval may record an app grant for a **future call**, never dispatch the
cancelled call. The same separation applies to a takeover card (permission to
control the person's mouse and keyboard): a grant may
outlive the call, but cannot authorize that call to restart.

### Owned-browser site card

The browser keeps the original authorization refusal and adds
`detail.decision:"cancelled"`. The exact example is:

```json
{"context":{"profile_disposition":"durable","profile_name":"default","profile_uuid":null,"session_kind_effective":"primary"},"detail":{"attempted_origin":"https://requested.example","decision":"cancelled","grant_request":{"hazards":[],"origins":["https://requested.example"],"severity_tier":3},"reason":"no_grant","required":{"credential":false,"financial":false,"tier":3}},"outcome":"authorization_denied","remedy":"call browser.open_grant with the arguments in detail.grant_request, then retry"}
```

The origin, required severity, grant request, context, and original refusal
reason/remedy are request-dependent. This is a `Response`, not the queued
browser `Error`. The detached site card is still answerable; its late answer
can mint the corresponding grant when the session drains its answer feed.
It cannot navigate, click, or otherwise resume the cancelled action. An
already-detached `open_grant` card is left answerable, not withdrawn just because
the request that raised it has ended.

### User-browser site card

`browser:"user"` site cards are different: their answer belongs only to the
current call. Cancellation **withdraws and forgets** that card, never detaches
it for another call to use. A late answer cannot mint permission from that
forgotten card. Before a user-browser mutation, the frame handler's outer
response is `{"context":null,"outcome":"cancelled"}`; once a mutation may
have started, the uncertainty family above applies. The user-browser bridge
also observes the request's Cancel while queued or awaiting a browser RPC;
an already-sent RPC cannot be recalled. This does not close any of the
person's tabs or revoke unrelated site grants.

## Login consent and login handoff

`capture_login` waiting on its card, **before window handoff**, is cancelled
through the same request address. Its frame-handler response is exactly
`{"context":null,"outcome":"cancelled"}`. The card is detached, not withdrawn
on an ordinary turn-stop. No browser is launched by a late approval alone.

`import_login` also detaches its login card on turn-stop. Its outer cancellation
response before dispatch is `{"context":null,"outcome":"cancelled"}`; the
inner import records a not-transferred result, not a transfer authorization.
This is distinct from the call's bounded wait for an unanswered card ending
normally, which replies
`consent_pending` with `ask_id` and the import/capture-specific pending fields.

Capture and import cards have a **30-minute lifetime** and `notify_only` late
execution. They remain answerable after the call stops (unless separately
withdrawn, expired, or invalidated by scope/session teardown). A late approval
is remembered and is **single-use on a matching retry**: it is consumed once,
not a standing permission, and does not execute anything by itself. Capture
matching includes its capture parameters; import matching includes the origin,
destination executable, and a rechecked source browser. Changed arguments do
not inherit the approval.

After a successful capture window handoff, the original request has already
replied `capture_pending` (with origin, expiry, and a notice-only message).
The capture then belongs to its custodian and continues independently of that
request. A subsequent Cancel for its old correlation is late, receives no
reply, and does **not** close the person's window or cancel the capture.
Shutdown still interrupts and cleans up the temporary browser profile used
only for that login capture.

Similarly a keyed `present` handoff replies `login_pending` with origin and
expiry; an unkeyed one replies `presented` with expiry. Waiting for the person
to finish sign-in is then a session handoff, not a still-pending relay that can
be interrupted by that old Cancel. It is left as is. Resume, expiry, session
closure, and the handoff's login observation govern its ending. A Cancel while
a blocking present/import operation is already running is subject to the
running-work rules above; it is not a guarantee to undo a fronted window or an
already-started transfer.

## Integration rules

1. Send one empty-body Cancel for each still-outstanding relayed call on stop.
2. Never wait for a separate Cancel reply, including when a reply won the race.
3. Accept `Error(cancelled)`, before-dispatch `cancelled`, site-card
   `authorization_denied` with `detail.decision:"cancelled"`, and the
   after-dispatch uncertainty family. Do not reduce these to a success flag.
4. Preserve uncertainty and held-input status. Read state before considering a
   retry; turn-stop itself implies no retry.
5. Do not dismiss a still-answerable card or active login handoff on the
   assumption that stopping a turn denied its permission or ended the session.
