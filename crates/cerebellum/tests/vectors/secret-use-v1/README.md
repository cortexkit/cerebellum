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
