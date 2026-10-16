# Turn-stop Cancel v1 vectors

These ten JSON files record frames observed at cerebellum's production
`handle_frame_for_test` entry point (which delegates to `handle_frame`). They
are not replies assembled by a test from an expected JSON object. The computer
cases use a scripted platform sequence or an in-process consent service; the
browser cases use a scripted browser and consent service. The user-browser
site-card case uses a scripted extension bridge and pins withdrawal as well as
its cancellation reply. No installed app,
real input post, screen text, page text, or login secret is required.

Each file contains:

- `request`: the original tool request frame shape;
- `cancel`: a newly built frame on the same `(channel, epoch, corr)`, with an
  actually empty body and a correct body-length prefix;
- `reply`: the original request's terminal frame, or the literal `"no reply"`;
- `state`: the fixture's synchronization point before Cancel was sent.

For `unknown-corr`, `request` describes the address but was **not sent**. For
`after-reply`, that request was sent and its reply consumed **before** Cancel.
The other cases synchronize on the open card, queued predecessor, or actual
platform/browser dispatch. The queued-browser test also answers the predecessor
and asserts that the cancelled successor never executes.

`body_utf8` is the exact body byte string, not reserialized parsed JSON.
`wire_hex` is the entire frame (`header.encode()` followed by body), including
the four-byte little-endian body-length prefix. The frame shapes duplicate the
header address for easy consumption; hex remains authoritative for the bytes.
Request ids, origins, app ids, account labels, and predicates are synthetic
fixture data. The readable bodies and their embedded wait-evidence JSON are
scanned for screen/page-content fields and machine-local paths.

`SHA256SUMS` pins all JSON files and this README. Verify the pins before
consuming a copied corpus. JSON formatting, newlines, and key order are part of
the pinned file bytes, while `body_utf8` and `wire_hex` pin the actual protocol.

## Check or regenerate

Run on macOS, with a writable temporary directory. Ordinary runs only check
captured frames and checksums; they do not rewrite the corpus:

```sh
TMPDIR=/tmp cargo test -p cerebellum --lib turn_stop_cancel
TMPDIR=/tmp cargo test -p cerebellum --lib a_cancel_during_consent_ends_the_capture_and_leaves_its_card_open
TMPDIR=/tmp cargo test -p cerebellum --test browser_session_wire turn_stop_cancel
TMPDIR=/tmp cargo test -p cerebellum --lib turn_stop_vectors_contain_no_screen_or_page_text
```

To deliberately update after a contract change, run the first three commands
**sequentially**, each with `CEREBELLUM_WRITE_TURN_STOP_VECTORS=1` in its
environment. The capturing tests rewrite their case files and `SHA256SUMS`.
Then run all four commands without that variable and review the body-byte diff.
The login capture case runs under the existing capture-card regression test;
the other cases have names prefixed with `turn_stop_cancel`.

The public behavior and race rules are in
[`docs/contracts/turn-stop-cancel-v1.md`](../../../../../docs/contracts/turn-stop-cancel-v1.md).
A running cancellation's `dispatch_outcome_unknown` is intentional: after a
mutation may have begun the frame handler does not claim that an action was
undone, even when held-input recovery succeeds.
