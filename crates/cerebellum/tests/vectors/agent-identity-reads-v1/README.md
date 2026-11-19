# Agent avatar read contract

`avatar-read.json` is copied byte for byte from `cortexkit/entorhinal`,
`test-vectors/agent-identity-reads-v1/avatar-read.json`, at commit
`c1f8d0d9bd4153d6de9acae32891eef1503ddba1` (tag `agent-identity-reads-v1.3`).

`SHA256SUMS` pins the owner's published bytes. The vectors cover present,
missing and avatar-less identities, deduplication, and request bounds. They are
test recipes only; runtime recipes and raster pixels are never persisted.

`wild-port-0005.hex` is the real wild corpus recipe used by `avatar-export`'s
raster test, copied from `vectors/wild/wild-port-0005.hex` in `cortexkit/avatar`
at commit `b9696127a4095e76b5ace3503aab877d449702f0`. Its checksum is also pinned.

`fleet-identity.json` is copied byte for byte from `cortexkit/entorhinal`,
`test-vectors/agent-identity-reads-v1/fleet-identity.json`, at commit `0d55ac4`.
It covers the full registry-name list, token-based unchanged replies, and a
malformed request. The names are display text; the attested agent id selects
the row and is never used as a display-name fallback.
