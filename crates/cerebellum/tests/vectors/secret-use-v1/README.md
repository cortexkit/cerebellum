# secret.use v1 vectors

Copied byte-for-byte (JSON code-block contents, without the Markdown newline) from
claustrum tag `secret-approval-vectors-v1`, `docs/wire-contract-v1.md` §15.
`error.result` is the shared refusal example. No API-key material is vendored.

| File | SHA-256 |
| --- | --- |
| `use.request.site_login.json` | `13939f01aa00751599cab852bc546701dd6d69c1ff76fec3f6b614d1a95662d7` |
| `use.result.released.site_login.json` | `a1bb04d56aedb6545cc3c9fbc11a74155355a46fb290b7b0244ce07f66715d0f` |
| `use.result.approval_required.json` | `c227bd0d37abaff792b2e8efba14ecdf0238fc2b0269c3cce7a5d3f4a0f7abf9` |
| `error.result.json` | `1ce8024a92bdadd867448f905e5cbae002d60327776bfdb01875a87f2711b99e` |

The upstream login request omits the optional coverage. Cerebellum always sends
`"coverage":"scope"`. `use.request.site_login.explicit_scope.json` is a **derived**
encoder fixture: explicit coverage and serde_json Value map order within the
unchanged stamp. It is not presented as an upstream golden. Its SHA-256 is
`eea1867444e6e0e5c82009947397d8814985fe59d07b7fa88b8a9bba09a106b5`. Tests pin both byte sequences separately.

## Dedicated Cingulate approval

`secret-approval-v1.json` is the byte-identical public deterministic vault corpus
vendored by Cingulate tag `secret-use-approval-v1` at `ed52285`, originally from
Claustrum tag `secret-approval-vectors-v1` (`cefc5c7041ffe93d17c4fcc80e5847260f3ad121`).
Its SHA-256 is `efd4ba60641586e143bce81087e4f9f5aaf8a99ffede74190303da7d4495cc27`.
Its private-key fields are published test keys, not production credentials.

`consent.request.secret_use.json` is the exact closed filing body for the corpus's
`approval` statement. The consent-card golden contains the same body in pretty
JSON. There are no filer-controlled display fields or expiry overrides; Cingulate
0.12.0 supplies those from the statement after advertising `secret-use-approval/v1`.

## Filer replies (Cingulate v1.1)

The eight `filer-*.json` files are untouched samples from Cingulate tag
`secret-use-approval-v1.1` at `133351a`. Each wraps the exact method, params,
and handler reply envelope produced by Cingulate's stamped filer path. They
were generated as `reserved:aft`; the dedicated contract also admits
`reserved:cerebellum`. Their complete file bytes, including whitespace, are
SHA-256 pinned individually in the decoder tests. The partial sample records
one allowed item and the omitted envelope item's effective decline. Cerebellum
still files exactly one item per fill call; the answer decoder selects that
request's effective decision rather than treating a card-level Allow as a grant.
