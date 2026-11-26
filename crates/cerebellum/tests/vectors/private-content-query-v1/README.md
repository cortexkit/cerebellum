# private_content.query v1 vectors

Byte-for-byte `private_content.query` examples for the model-call broker, captured at
cerebellum's production `handle_frame_for_test` entry point (which delegates
to `handle_frame`). They are not replies assembled from an expected JSON
object. The marked case seeds its mark the way production does: an
owned-browser snapshot of a page read while the profile holds login evidence,
recorded as `signed_in_site`. No installed app, real input post, screen text,
page text, or login secret is required: only the query request and its answer
are pinned.

Each file contains:

- `contract`: always `private-content-query-v1`;
- `case`: which exchange this is;
- `state`: the fixture's synchronization point before the query was sent;
- `principal`: always `reserved:broca`, the only admitted caller;
- `request`: the management-route query frame;
- `reply`: the query's terminal `Response` frame.

`body_utf8` is the exact body byte string, not reserialized parsed JSON.
`wire_hex` is the entire frame (`header.encode()` followed by body), including
the four-byte little-endian body-length prefix. Request ids, scope refs, and
origins are synthetic fixture data. The bodies are scanned for
screen/page-content fields and machine-local paths.

`SHA256SUMS` pins all JSON files and this README. Verify the pins before
consuming a copied corpus. JSON formatting, newlines, and key order are part
of the pinned file bytes, while `body_utf8` and `wire_hex` pin the actual
protocol.

## Check or regenerate

Run on macOS or Linux, with a writable temporary directory. Ordinary runs only
compare captured frames and checksums; they do not rewrite the corpus:

```sh
cargo test -p cerebellum --test private_content_query_v1
```

To deliberately update after a contract change, run that command once with
`CEREBELLUM_WRITE_PRIVATE_CONTENT_QUERY_VECTORS=1` in its environment. The
capturing test rewrites its case files and `SHA256SUMS`. Then run the command
again without that variable and review the body-byte diff.

The public behavior and marking rules are in
[`docs/contracts/private-content-query-v1.md`](../../../../../docs/contracts/private-content-query-v1.md).
