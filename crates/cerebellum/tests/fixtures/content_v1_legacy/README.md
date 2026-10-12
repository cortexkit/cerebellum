# Legacy result bytes

These files are exact response bodies captured from Cerebellum main at
`3101135f4f08d0a38805d7f66e244794ecab2917`, before route-level result negotiation.
The snapshot and screenshot represent `browser_use`; the application tree
represents `computer_use`. The screenshot contains a valid one-pixel PNG.

The capture used an isolated source archive of that commit.
Temporary tests reused main's synthetic browser and app-state fixtures. The
browser cases captured `Frame.body` from actual `browser_use` calls through
`handle_frame_for_test`; the computer case captured the production read-state
result from its in-memory app source. A temporary library test then passed all
three results through main's production `send_tool_response` and verified its
emitted bytes were unchanged. No normalization followed the final frame capture.
No installed application or native browser/desktop capture was needed. The
reference-source copy was removed after capture.

The current test installs actual route binds with neither `consumer_capabilities`
nor `call_mode`, carries the accepted bind into the production response boundary,
and sends the same payload through that boundary. The response boundary uses the
contract library's `consumer_reads_content_v1` predicate. The test compares the
emitted bytes, not just parsed JSON, to these files. Separate conformance calls
exercise the full `handle_frame_for_test` path with and without the
`content/v1` bind declaration.

Captured SHA-256 values:

- `browser_snapshot.json`: `f8ef1834fb2d2910e8601b4ea9ed3dab58589ac20c7d9fc22481b2156d81dea2`
- `browser_screenshot.json`: `9625a7285b11888330285938f8f5e2d04177cff5489ad50bccc47074566d2be2`
- `computer_read_state.json`: `c271fc27ab4ce369fc81e8403a75705e9db48ff4a1202f847e7b8360f1aec37f`

Do not regenerate these from the current projector. If `send_tool_response`
accidentally encoded legacy callers' replies as content/v1, regenerating the
files would save those same incorrect bytes as the expectation and make the
comparison pass. Keeping main's original bodies makes the test independent of
the encoding branch it checks.

## Route reader declaration

A provider sends the new body format only when the caller declares that it can
decode it; otherwise the caller keeps the legacy body. This rule is defined in
[`cortexkit-role-tool-provider` 0.7.3, CONTRACT.md §4.1](https://docs.rs/crate/cortexkit-role-tool-provider/0.7.3/source/CONTRACT.md).
The relevant contract text is:

> A consumer that decodes `content/v1` result bodies declares the string
> `content/v1` in its `route.open` `consumer_capabilities`. The daemon relays
> that list verbatim on the provider's route bind as
> `RouteBindRequest.consumer_capabilities`. This declaration is the consumer's
> unverified statement; it grants no permission or other authority.

> For a tool whose catalog entry declares `result_format: "content/v1"`, a
> provider sends a `content/v1` body only on a route whose bind declared
> `content/v1`. On every other route, including one whose bind has no
> `consumer_capabilities`, the provider sends that tool's legacy body exactly as
> before. The decision is made separately for each route from its bind, never
> from anything in a call. The catalog lists `result_format` regardless of who
> asks: it does not change schema digests, and older consumers ignore it.

The catalog lists `result_format` regardless of the declaration. It does not
change schema digests; older cores ignore that metadata. The existing daemon
relays the declaration list verbatim into the bind (Subconscious `control.rs`,
`route_open_relays_consumer_capabilities_verbatim`). This is a format selection,
not a grant. Calls on the same provider therefore remain safe for both old cores
and a reader that explicitly declares the new format.
