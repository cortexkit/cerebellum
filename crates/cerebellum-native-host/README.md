# Chrome native messaging host

`ck-cerebellum-native-host` is a macOS-only, silent transport. It has no action
policy and does not log, print, create directories, install manifests, or read a
Chrome profile. It connects only after verifying its parent's running-code
signature and process generation as Chrome, authenticates
the socket server using its kernel peer pid and process generation, sends one
parent attestation, and waits for acceptance before reading Chrome messages.
Socket-path ownership is not a substitute for that authentication. The server
must also have the current effective uid.

## Build and sign

Build with `cargo build --locked -p cerebellum-native-host --release`. For macOS
packaging, sign the artifact with the CortexKit signing certificate whose Team ID
is `5R5846NBPW`. Cerebellum's host requirement pins that team, so another
certificate does not authorize a host connection:

```sh
bash crates/cerebellum-native-host/sign-host.sh \
  target/release/ck-cerebellum-native-host '<fleet signing identity>'
```

The helper enables hardened runtime and verifies the exact deployed identifier
`ck-cerebellum-native-host` and fleet signer. A development/ad-hoc Cargo binary
does not satisfy the bridge's host requirement. The separate installer owns the
manifest, its fixed extension origin, and private filesystem writes. Browser
manifest directories are data in `browsers.rs`; only Chrome is enabled. Disabled
Brave, Edge and Arc destinations are reserved for future installation work, not
tested browser support.

Production admits Google-team-signed Chrome. Stock Chrome for Testing is ad-hoc
signed and **not** admitted in shipped builds: it has no certificate-backed
Google signing identity. An
operator-approved probe build may opt in to `chrome-for-testing-parent-probe`;
the macOS dependency pins the official 155.0.8059.39 mac-arm64 loader cdhash and
rejects that feature when the release signing-topology attestation is set.
See `../cerebellum-macos/PEER_ATTESTATION.md` for the probe's unsealed-framework
risk. The host attests either Google's team or that exact probe cdhash, never both.

## Bridge integration

The socket is `cortexkit_paths::cortexkit_run_dir()/cerebellum/user-browser.sock`.
Only cerebellum creates the private directory (0700) and socket (0600). The host's
server requirement is fixed: identifier `ck-cerebellum`, Apple generic anchor,
and certificate leaf Team ID `5R5846NBPW`. No frame or environment variable can
change it.

The host uses `cerebellum-bridge-protocol` for socket framing, control frames,
signing constants and raw relay codecs. Its raw relay API and the bridge's
Value-based frame API share the same wire envelope; interoperability tests cover
both directions. The socket protocol is:

- socket frames: big-endian u32 byte length, UTF-8 JSON, maximum body 16 MiB;
- `host_hello`: protocol 1, Chrome's argv[1] extension origin, checked parent
  signer or probe hash, pid and start time;
- `host_accepted`: protocol 1 and epoch, or `host_refused` and close;
- only `relay { message: <JSON> }` frames after acceptance; unknown envelope fields
  refuse;
- Chrome stdio: native-endian u32 byte length, maximum host-to-Chrome message
  1 MiB. Incoming allocation is also bounded by the socket's 16 MiB limit.

The relay keeps the JSON value as `serde_json::value::RawValue`: it validates JSON
syntax but never interprets action fields or converts numbers. Value bytes,
including internal whitespace and key order, survive both directions. Whitespace
outside the value belongs to the envelope, not the action content. Chunking,
invocation ids, epochs, Cancel and replay policy belong to the bridge/extension.
The handshake and socket writes have fixed deadlines; the accepted idle port has
no read timeout. Disconnecting the bridge exits without waiting on blocked stdin.

Tests use scratch sockets or socket pairs, never a live Chrome profile, journal,
or browser. A macOS unsigned-listener test retains real kernel peer/signature
checks while supplying only the Chrome-parent gate from a fixture. The real
Chrome-started signed-host probe remains an operator-approved integration test.
