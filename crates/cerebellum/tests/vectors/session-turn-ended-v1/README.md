# Session turn-ended v1 vectors

**Interim contract.** `session.turn_ended` is a direct call from Prefrontal
core (`reserved:prefrontal-core`) to cerebellum's management surface. It is to
be replaced by a harness module publishing its `turn_ended` event on the event
plane, with cerebellum subscribing; core's direct call is then deleted. The
parameters are exactly that event's fields, so the shape does not change when
the source does. Cerebellum advertises the call as `session-turn-ended/v1`
in its HELLO `capabilities.provides`.

## What the call does

It tells cerebellum a head session's turn ended, so the agent cursor badge that
session's computer calls drew comes off the screen at once instead of resting
there until it idles out after 30 seconds. It has no other effect: no journal
write, no cancellation, no change to grants or calls.

Request (`method` and `params` only; every parameter except `error_class` is
required, and unknown fields are refused):

```json
{"method": "session.turn_ended", "params": {
  "session_ref": "<32 lowercase hex>",
  "scope": {"owner": {"kind": "reserved", "module_id": "prefrontal-core"}, "ref": "...", "epoch": 3},
  "harness": "...", "turn_id": "...",
  "outcome": "completed" | "stopped" | "failed",
  "error_class": "provider_capacity" | "provider_quota" | "auth" | "transport" | "harness" | "unknown",
  "quality": "strong" | "weak" | "none",
  "source": "...", "seq": 7, "at_ms": 1700000000000}}
```

`session_ref` is the harness runner's ref, exactly 32 lowercase hex digits.
`scope` is the daemon-stamped head scope that relayed calls already carry.
Badges are matched on `scope.ref` only; `epoch` is required but not compared,
because a revived session keeps its ref. `owner` is checked against the
daemon's scope principal shapes. `error_class` may appear only when `outcome`
is `failed`; on any other outcome it is refused. `seq` and `at_ms` are
unsigned integers.

Replies:

- admitted and well formed: always `{"acknowledged": true}`, including for a
  session that drew no badge, so the caller learns nothing about which
  sessions used the computer;
- a missing, mistyped, unknown or out-of-vocabulary parameter:
  `invalid_request` with `detail.field` naming it (`scope.ref` for nested
  fields) and `detail.reason_code` one of `missing_field`, `wrong_type`,
  `unknown_field`, `invalid_value` (an `error_class` on a turn that did not
  fail is `invalid_value` naming `error_class`);
- any principal other than exactly `reserved:prefrontal-core`: an Error frame
  with code `principal_denied`.

## Files

Each case file records a request frame and its reply frame as observed at
cerebellum's production `handle_frame` entry point, on a management route bound
for `reserved:prefrontal-core`. They are not replies assembled from an expected
JSON object. The session and scope refs, harness, turn id, source and
sequence number are synthetic.

- `acknowledged.json`: the turn of a session that drew a badge ended; the
  badge is hidden and the call acknowledged.
- `unknown-session.json`: a session that drew no badge; still acknowledged.
- `failed-with-error-class.json`: a failed turn with
  `error_class: "provider_quota"`; the badge is hidden and the call
  acknowledged.
- `invalid-outcome.json`: `outcome: "paused"`, refused naming `outcome`.
- `error-class-without-failed.json`: `error_class` on a completed turn,
  refused naming `error_class`.

`body_utf8` is the exact body byte string. `wire_hex` is the whole frame
(`header.encode()` followed by the body), including the four-byte
little-endian body-length prefix; it is authoritative for the bytes.

`SHA256SUMS` pins every JSON file and this README. JSON formatting, newlines
and key order are part of the pinned file bytes.

## Check or regenerate

Run on macOS or Linux with a writable temporary directory. Ordinary runs only
compare captured frames and checksums:

```sh
cargo test -p cerebellum --lib cursor_end_tests
```

To update deliberately after a contract change, run that command once with
`CEREBELLUM_WRITE_TURN_ENDED_VECTORS=1`, then again without it, and review the
body-byte diff.
