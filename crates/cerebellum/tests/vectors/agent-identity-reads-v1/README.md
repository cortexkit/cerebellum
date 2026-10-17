# Agent avatar read contract

`avatar-read.json` is copied byte for byte from `cortexkit/entorhinal`,
`test-vectors/agent-identity-reads-v1/avatar-read.json`, at commit
`b9c18d3a5a1c3e7049772ae3bbac9217c9e101d1`.

`SHA256SUMS` pins the owner's published bytes. The vectors cover present,
missing and avatar-less identities, deduplication, and request bounds. They are
test recipes only; runtime recipes and raster pixels are never persisted.

`wild-port-0005.hex` is the real wild corpus recipe used by `avatar-export`'s
raster test, copied from `vectors/wild/wild-port-0005.hex` in `cortexkit/avatar`
at commit `b9696127a4095e76b5ace3503aab877d449702f0`. Its checksum is also pinned.
