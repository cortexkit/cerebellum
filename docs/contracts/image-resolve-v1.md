# `image.resolve`, v1

This is the cerebellum receive-side contract for the model-call broker, which fetches the
screenshot a codemode program handed it by handle. A codemode program's result
is far too small to carry a screenshot's bytes, so a screenshot reply also
carries an opaque `image_handle`, and the broker resolves that handle here before
passing the image to a model call. The executable examples are in
[`crates/cerebellum/tests/vectors/image-resolve-v1`](../../crates/cerebellum/tests/vectors/image-resolve-v1/).
They are exact request and reply bytes captured at cerebellum's production
`handle_frame_for_test` entry point (which delegates to `handle_frame`), not
reconstructed examples.

## Where a handle comes from

Every screenshot cerebellum returns also gets a fresh `image_handle`, minted
when the reply is built:

- a `computer_use` `read_state` whose reply carries a window image
  (`crates/cerebellum/src/lib.rs`, `mint_image_handle`; the image field is
  `reply.image`, `mime: "image/jpeg"`);
- a `browser_use` `screenshot` on the agent's own browser
  (`mime: "image/png"`);
- a `browser_use` `screenshot` on the person's browser
  (`mime: "image/png"`).

The value is `ih` followed by 32 lowercase hex characters: 16 bytes from the
operating system's random source
(`crates/cerebellum/src/image_handles.rs`, `new_handle`). The field sits beside
the reply's existing image fields. `image.image_id` and `snapshot_id` stay
as they are: they are guessable or keep no bytes, so they never resolve. An
image over the size limit below gets no handle.

A handle is minted only when the capturing route carries a scope stamp. Its
`scope_ref` is recorded with the bytes, and it is the scope a resolve has to be
authorized by. A route with no stamp gets no handle and the field is omitted,
because nothing could ever resolve those bytes.

In a codemode run the handler rewrites a reply's image object before sending it
in the non-tool-result format, removing `data_b64`; `image_handle` sits beside
`image` and is untouched. The tool-result/v1 format strips the inline image
part and keeps `image_handle` in `structuredContent` the same way. A program
therefore sees the same handle in both result formats.

## Who may call

Only `reserved:broca`, on a management-surface route bound for `cerebellum`,
exactly as for `private_content.query`:

- A `reserved:broca` bind is admitted only on the management surface
  (`crates/cerebellum/src/private_content.rs`, `bind_admitted`). A bind anywhere
  else is refused before any request is served.
- On a management route, `reserved:broca` may call `private_content.query` and
  `image.resolve` and nothing else. Any other method, or any other surface,
  gets the route error `principal_denied` with
  "reserved:broca may call only private_content.query and image.resolve"
  (`crates/cerebellum/src/lib.rs`, `handle_route_request`).
- On a management route, any caller that is not `reserved:broca` never reaches
  the operation; its route refused the bind.

A route error is an `Error` frame carrying `{"code","message"}` and no
`detail` (`crates/cerebellum/src/wire.rs`, `build_error_frame`). It is not the
refusal body below.

## Request

```json
{"method": "image.resolve", "params": {"handle": "ih...", "scope_ref": "...", "parent_scope_ref": "..."}}
```

`handle` and `scope_ref` are required; `parent_scope_ref` is optional; `params`
is a closed key set (`crates/cerebellum/src/lib.rs`, `handle_image_resolve`).
Any other key is refused, and so is an empty or non-string value. The top-level
frame body takes only `method` and `params`, as for `private_content.query`.

| field | required | refused as |
|---|---|---|
| `params` | yes, an object | `wrong_type` when missing or not an object |
| `params.<anything else>` | never | `unknown_field`, naming the key |
| `params.handle` | yes, a non-empty string | `missing_field` when absent; `wrong_type` when not a string (including `null`); `empty_value` when `""` |
| `params.scope_ref` | yes, a non-empty string | `missing_field` when absent; `wrong_type` when not a string (including `null`); `empty_value` when `""` |
| `params.parent_scope_ref` | no; when present, a non-empty string | `wrong_type` when not a string (including `null`); `empty_value` when `""` |

## Success

The reply is a **binary** `Response` frame: its `flags` byte carries
`FLAG_BINARY` (bit 0, `subc-protocol` 0.33.0), so the body is raw bytes rather
than JSON. The body is laid out as

```
u32 big-endian head length | head JSON | the image's own encoded bytes
```

The head is a closed object with these exact members, using the model-batch
field names:

```json
{"content_type":"image/png","sha256":"<64 lowercase hex>","length":<byte count>}
```

- `content_type` is `image/png` or `image/jpeg`, the mime the capture reply
  declared.
- The image bytes after the head are exactly the bytes the capture reply
  carried, encoded (PNG or JPEG) as the capture produced them; nothing is
  downscaled, re-encoded or otherwise rewritten, because a handle must resolve
  to what the agent was shown.
- `sha256` is the SHA-256 of those image bytes, and `length` is their count in
  bytes. Both describe what follows the head, not the body or the frame.

A fixture that needs the exact bytes is in
[`crates/cerebellum/tests/vectors/image-resolve-v1/success.bin`](../../crates/cerebellum/tests/vectors/image-resolve-v1/success.bin),
with its SHA-256 in the case file beside it.

## How large a resolve can be

A resolve has to leave as one frame, and the daemon refuses a delivered frame
over 4 MiB. A handle is therefore minted only for an image of at most
**4,128,768 bytes** (`crates/cerebellum/src/image_handles.rs`,
`IMAGE_HANDLE_MAX_BYTES`): 4 MiB (4,194,304) minus a 64 KiB (65,536)
allowance, which covers the frame's 21-byte header, the four-byte head length,
and the head JSON itself. The head is at most about 150 bytes, so the allowance
is far larger than the head can be.

The number is the same one the broker's `MAX_REFERENCE_IMAGE_BYTES`
(`cortexkit_model_batch::image`) holds; cerebellum does not depend on that
crate, so it carries its own constant and a test pins both the value and the
arithmetic. An image over the limit gets no `image_handle`: the reply omits the
field, and on tool-result routes its text says the screenshot is too large for
a handle and to take a viewport screenshot instead.

## Refusal

A handle that does not resolve gets a `Response` frame (not an `Error` frame)
carrying exactly this body:

```json
{"outcome":"image_unavailable","context":null,"session":null,"detail":{"field":"handle"}}
```

(Key order on the wire is alphabetical — `context`, `detail`, `outcome`,
`session`. The goldens pin the exact bytes.)

Unknown handles, expired handles and handles captured under a scope outside the
caller's union all get this one body, byte for byte. Refusals are JSON in a
`Response` frame, never an `Error` frame. Distinguish a malformed request from a
handle that does not resolve by body shape, not frame type. `detail.field` is always
`handle`; there is no reason code, because a reason code would say which of the
three happened. A caller with the reply bytes cannot tell them apart, and a
handle that does not resolve tells it nothing about whether one does.

A malformed request is refused the same way `private_content.query` refuses one:

```json
{"outcome":"invalid_request","context":null,"session":null,"detail":{"field":"handle","reason_code":"missing_field"}}
```

## Rules

What a handle reaches, and for how long:

- **The scope union.** A handle resolves only when its capture's `scope_ref` is
  in this union: the request's `scope_ref`; `parent_scope_ref` when given; and,
  for every route bound with that scope ref whose linked head still resolves,
  the head's scope (`crates/cerebellum/src/private_content.rs`,
  `scope_union`). So naming a run's scope reaches the run's head, and naming a
  head reaches the runs under it only where the head is the one a bound route
  resolves to. `private_content.query` computes the same union from the same
  function, so what a handle reaches and what a mark reaches cannot drift
  apart. Nothing about the capture's conversation enters it.
- **A capture's scope is its route's, not its head's.** A run's screenshot is
  recorded under the run's own `scope_ref`, so resolving it needs that ref in
  the union: send the run's `scope_ref`, not only its head's.
- **Fifteen minutes from capture.** A handle resolves until its capture time
  plus 15 minutes (`crates/cerebellum/src/image_handles.rs`, `LIFETIME`).
  Resolving never extends that.
- **Eight per scope, 64 MiB in all.** One scope holds at most 8 handles and the
  store at most 64 MiB of screenshot bytes; reaching either cap evicts the
  oldest handle first (`PER_SCOPE_LIMIT`, `TOTAL_BYTES_LIMIT`). An evicted
  handle refuses exactly like an unknown one.
- **Memory only.** Nothing here touches the disk, the journal or a call record.
  The bytes are the decoded capture reply, held in a buffer that is wiped when
  it is dropped (`zeroize::Zeroizing`).
- **A conversation's end drops its handles.** When the last route of a capture's
  conversation closes, its handles are dropped at once, however much of their
  fifteen minutes is left (`ImageHandles::end_conversation`).

## For callers

- Send the handle a screenshot reply gave you. Never send `image_id`,
  `snapshot_id` or `data_b64` in its place: none of them resolves, and each
  costs a round trip to a single refusal.
- Send the `scope_ref` the screenshot call ran under, plus `parent_scope_ref`
  when the run has no cerebellum route of its own. A scope outside the union
  refuses, and the refusal is indistinguishable from an unknown handle.
- Treat `image_unavailable` as "fetch nothing": read the state or take the
  screenshot again rather than retrying the same handle. A handle whose
  fifteen minutes passed, whose conversation ended, or whose scope was evicted
  will never resolve.
