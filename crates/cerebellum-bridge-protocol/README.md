# Peer image trailers

Linux and Windows bridge callers use `peer_trailer::verify` on the executable
handle they already opened for the peer. They supply the expected role and the
target triple of their own build. Verification is blocking; the caller owns
the deadline and process liveness checks. The signed release version does not
have to match the caller's version.

Build the packaging tool with
`cargo build --locked --release -p cerebellum-bridge-protocol --bin peer-trailer`.
It does not select enabled platforms or release assets. Its commands are:

| Command | Inputs and effect |
| --- | --- |
| `preflight` | Checks `CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY` for a valid Ed25519 public key and rejects the repository test key, regardless of hex case. |
| `sign PATH ROLE TRIPLE VERSION` | Checks the bound public key against `BRIDGE_PEER_SIGNING_FINGERPRINT` and the Ed25519 PKCS#8 PEM private key read from stdin, then appends in place. Apply this after any other byte-changing steps. |
| `verify PATH ROLE TRIPLE` | Checks the bound public key against the fingerprint and verifies the trailer and image. Uses the supplied asset triple, not the triple of the runner. |
| `assert-unsigned PATH` | Refuses a terminal trailer marker, including one that does not describe a valid trailer. |

Release roles are `cerebellum` and `host`. The fingerprint is the lowercase hex
SHA-256 of the **32 decoded public-key bytes**, not of the hex text. The signer
does not read the private key from its arguments or environment. Sign and verify
do not accept the repository test public key.

For CI fixtures only, `sign --test-key PATH ROLE TRIPLE VERSION` requires
`CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY` to select the repository's public RFC 8032
test key. It uses the corresponding known test private key, with no stdin or
fingerprint input, and also permits the `test-parent` role.

`tests/fixtures/peer-trailer-v1.json` pins the complete image trailers for the
RFC 8032 key. The payloads were encoded from the byte layout and signed with
OpenSSL 3's Ed25519 implementation independently of this crate. The signing
tool test compares every output byte, and the verifier test reads those same
checked-in bytes as input.
