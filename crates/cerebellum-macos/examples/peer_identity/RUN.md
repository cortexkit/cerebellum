# Peer identity desk measurement (head only)

The rig is delivered; the desk measurement is pending. These binaries do not
request permissions or start the production daemon. A byte from either attack
stops the rig immediately; do not replace the candidate or proceed to helpers.

## Preconditions and build

Use a dedicated macOS GUI login named **`ck-peer-probe`**. The rig requires the
real and effective uid to match, refuses root, checks the OS account name (not
environment variables), and requires `/dev/console` to belong to that uid. An
SSH/su session while the operator owns the console is not sufficient. Every role
also requires the literal `--scratch-peer-identity` flag.

Build in the worktree on that Mac, without a release signing-topology revision:

```sh
cargo build --locked -p cerebellum-macos --features desk-probe --example peer_identity
mkdir -p target/scratch/peer-identity
cp target/debug/examples/peer_identity target/scratch/peer-identity/ckdev-cerebellum
cp target/debug/examples/peer_identity target/scratch/peer-identity/ckdev-cerebellum-peer-helper
cp target/debug/examples/peer_identity target/scratch/peer-identity/ckdev-peer-attacker
```

The head supplies its team certificate signing identity; workers never hold it.
Sign `ckdev-cerebellum` and `ckdev-cerebellum-peer-helper` with the **same Apple
team certificate**, not ad hoc:

```sh
codesign --force --options runtime --sign "$IDENTITY" --identifier ckdev-cerebellum target/scratch/peer-identity/ckdev-cerebellum
codesign --force --options runtime --sign "$IDENTITY" --identifier ckdev-cerebellum-peer-helper target/scratch/peer-identity/ckdev-cerebellum-peer-helper
codesign --force --sign - --identifier ckdev-peer-attacker target/scratch/peer-identity/ckdev-peer-attacker
target/scratch/peer-identity/ckdev-peer-attacker --scratch-peer-identity --run
```

The outer rig, accomplice, and attacker must have no team certificate
(linker/ad-hoc signing is needed on Apple Silicon). Only the legitimate launcher
and the exec/write stand-ins run the signed cerebellum copy. The legitimate
launcher reads its own helper's first frame; the unsigned rig gets only its
result, never that channel. Both signed copies validate their running signatures.
The rig uses fixed sibling filenames and checks the suspended helper's mapped image
against the expected identifier and its own team before release. The temporary
swap-control directory beside those copies is removed automatically.

## Verdicts

One invocation runs the legitimate and unsigned controls, the pre-exec file swap,
and both attacks. Success prints exactly:

```text
PASS control-legitimate first-frame=received
PASS control-unsigned helper-byte=no wait=10s
PASS control-swapped-helper released=no request-sent=no
PASS attack-exec helper-byte=no wait=10s signed-alive=yes
PASS attack-version-write helper-byte=no wait=10s signed-alive=yes
PASS peer-identity candidate: both attacks silent; both controls passed
```

A positive attack prints one of these and exits nonzero, without running any
later case or fallback:

```text
STOP peer-identity: FAIL attack-exec helper-byte=yes; candidate rejected; no fallback
STOP peer-identity: FAIL attack-version-write helper-byte=yes; candidate rejected; no fallback
```

Control failures, missing signatures, account/flag refusal, or lost coordination
also print `STOP peer-identity: ...` and exit nonzero. They are **invalid
measurements**, not evidence that the attacks were refused. The signed stand-in
acknowledges readiness only after exec or its `--version` stdout write; exec and
the stdout write wait until the unsigned accomplice has adopted its copies. The
accomplice validates its live signature before releasing the helper, waits 10 s
before touching its copied endpoint, and checks both signature and responsiveness
again after reading the verdict. Unsigned code uses only the separate control
socket during that interval. Preserve the complete output with the build commit,
macOS version/build, and signing identifiers when recording the desk result.
