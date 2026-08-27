# ck-cerebellum

Browser use and computer use for the CortexKit fleet — the motor-execution organ.

Where AFT is the sensorimotor cortex for *code*, cerebellum is the layer below:
fine motor control on the *machine*. If the target is a file or a repository it
is AFT's; if the target is a screen, a window, or a page, it is this module's.
See [docs/charter.md](docs/charter.md).

## Building

This workspace has **path dependencies on a sibling checkout** of
[cortexkit/subconscious](https://github.com/cortexkit/subconscious), which
provides the wire protocol and transport. It is a path dependency rather than a
registry version, so the sibling has to be on disk: no published crate
substitutes for it.

Clone the two beside each other:

    git clone https://github.com/cortexkit/subconscious.git
    git clone https://github.com/cortexkit/cerebellum.git
    cd cerebellum && cargo build

The paths are relative, so any sibling layout works. `subconscious-source.txt`
pins the revisions this workspace is built against.

Verification runs through one script rather than a set of remembered commands:

    ./scripts/rust-test-gate.sh

It prints `GATE PASSED: all phases green` and nothing weaker counts. The phases
include a Linux lint pass, so a green run on macOS still checks the platform CI
builds on.

## What it does

**Browser plane** — Chrome driven over CDP through an inherited pipe rather than
a debugging port, so control is bound to process ancestry instead of local
network position. Seven capabilities are served: launch, status, close,
navigate, snapshot, click, screenshot. Each agent identity gets its own durable
browser profile, so a login a human sets up once persists across sessions.

**Computer plane** — macOS screen capture and semantic actuation through the
accessibility API. Three capabilities are served: screenshot (with window-local
region capture), wait, and click. Capture and actuation additionally require
attestations bound at compile time by `scripts/release-build.sh`, so a
development build advertises only what it can prove it is allowed to serve.
Synthetic input — typing, key presses, scrolling, dragging — is deliberately
unbuilt and gated on review.

Both planes refuse by default. Every action runs against a grant a human minted,
scoped to an origin or an application, and time-boxed. Every action is journaled
before it happens, so a crash mid-action leaves an explicit record rather than
silence.

## Platforms

macOS is the primary target and the only one with a computer plane. The browser
plane runs on macOS and Linux; each has its own launch seam
(`cerebellum-macos`, `cerebellum-linux`) and those are the only crates permitted
to contain `unsafe`, so everything above them holds `#![forbid(unsafe_code)]`.

## Layout

    crates/cerebellum            wire protocol, capability dispatch, browser plane
    crates/cerebellum-core       plane-agnostic substrate: identity, health, journal
    crates/cerebellum-computer   OS-level computer plane
    crates/cerebellum-macos      macOS framework seam
    crates/cerebellum-linux      Linux process and ptrace seam

`docs/` holds the charter and acceptance records. `scripts/` holds the
verification gate, the release build, and the mutation-testing harness.

## License

MIT. See [LICENSE](LICENSE).
