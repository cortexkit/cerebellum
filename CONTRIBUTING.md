# Contributing

Thank you for looking at ck-cerebellum. Two things decide whether a
contribution lands smoothly, and both are cheap to do up front.

## Issue first, then a go, then a pull request

Open an issue before writing code, labelled `bug` or `design discussion`,
and wait for an explicit go from a maintainer. A pull request that arrives
without an issue that got a go will be asked for the issue rather than
reviewed.

The reason is scope, not ceremony. This module runs under a supervisor that
also backs phones, scheduled work, and cross-host federation; a change that
is right for one caller can be wrong for the fleet in ways a diff does not
show. Ten lines in an issue settle that before it costs a review round on
several hundred lines of working code. Bug fixes with an obvious shape get a
go quickly; the gate exists for the cases where the shape is the question.

## What a change carries

- Tests that would fail if the mechanism were wrong: assert the exact value
  an invariant governs, not an inequality that a zero also satisfies, and for
  a guard, show which named test goes red when the guard is removed.
- Business logic in the platform-neutral crates, so Linux CI covers it;
  `crates/cerebellum-macos`, `cerebellum-linux`, and `cerebellum-windows`
  stay thin FFI seams with no decisions in them.
- Nothing in `tests/` that needs an installed application; live probes
  against a real browser or desktop live in `examples/`.
- `scripts/fast-gate.sh` green against `origin/main` (or the intended base).
  The full `scripts/rust-test-gate.sh` remains required after deployment; it is
  not a pre-push gate.

## Landing flow

Run `scripts/fast-gate.sh` against the landing base, then push the change. Stage
and deploy it with the normal release flow, and run `scripts/rust-test-gate.sh`
after deployment. The full gate still runs post-deploy so the running module is
checked without holding up the common landing path. If that full gate finds a
failure, fix it forward with a new change; do not roll back the deployed change
just to make the gate green.

## Dependencies

Subconscious and commons crates come from crates.io at exact versions, or as
a git dependency pinned to a full commit when a crate isn't published. Never
add a `path` dependency outside this repository; the gate refuses it. Moving a
dependency is its own commit, with its `Cargo.lock` change, never folded into
an unrelated one.
