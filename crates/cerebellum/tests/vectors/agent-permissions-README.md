# Agent permissions contract corpora

`permissions-v1/` and `danger-option-group-v1/` are byte-for-byte copies of
the `cingulate` repository's `test-vectors/permissions-v1/` and
`test-vectors/danger-option-group-v1/` at commit `6bb5f4d`, named by the corpus tags
`permissions-v1` and `danger-option-group-v1` respectively. These names are
contract/corpus tags, not Git tags. Each directory retains its upstream README
and SHA256SUMS unchanged.

Pinned SHA-256 of each SHA256SUMS file:

- permissions-v1: `afec5cc3bcca2fdff8fbdd0ed8735e635f1a0425ea6caac002c5d81664c47b85`
- danger-option-group-v1: `b12c50344340930b688ab2f4a1536960e079138d774958f10071ea05d22e2619`

Verify each directory with `shasum -a 256 -c SHA256SUMS` from that directory.
