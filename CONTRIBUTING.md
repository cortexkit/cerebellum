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
  a guard, record which named test goes red when the guard is removed in
  `mutations.d/`.
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

## Mutation proofs

`mutations.d/` replaces the old one-off `scripts/mutate.sh` flow with a replayable
catalogue: every guard edit is paired with the exact test that must fail. Run
`scripts/mutations.sh --diff origin/main` before landing to
replay changed rows narrowly and then replay every catalogue row. The narrow
selection is not a substitute for the full run; it limits each row to its named
expected tests and does not audit sibling tests for collateral failures.
When the selected base predates the catalogue, the wrapper runs every row
instead of claiming an empty narrow replay.

The wrapper runs only the `ckdev-mutate` installed in this checkout's own
`target/tools` root, pinned to version 0.12.3 from commons revision
`649d5f126c3b7da49e3019407ea1a94652d32eea` and verified against
`target/tools/.crates2.json`. It never uses a `ckdev-mutate` from `PATH` or
`~/.cargo/bin`: those are shared with every other repository on the machine,
and another repository installing a different version there must not change
this replay. The wrapper never installs the runner itself. When the runner is
missing, or is not the pinned version and revision, it stops and prints the
install command (each worktree has its own `target/`, and `cargo clean`
removes the runner too). From the repository root:

```sh
cargo install --locked --root "$PWD/target/tools" \
  --git https://github.com/cortexkit/commons \
  --rev 649d5f126c3b7da49e3019407ea1a94652d32eea cortexkit-mutate
```

The regular fast gate stays quick and leaves mutation replay opt-in. To include
the narrow replay for the fast gate's selected base, run
`scripts/fast-gate.sh --mutations` (or pass the base explicitly with
`scripts/fast-gate.sh --base REF --mutations`).

The runner edits source **in place**, not in a scratch checkout. It restores
saved bytes on normal exits, handled interrupts and timeouts, but cannot restore
after SIGKILL or power loss. Both gates run `scripts/check-mutation-tree.sh`
before compiling, even without mutation replay: it checks the original catalogue
anchors and rejects insertion mutants that retain their original anchor. Stop
the replay and its children before restoring an interrupted edit; never check out
a target while its tests are running. If a guard was intentionally changed,
update its catalogue row rather than bypassing this check.

A surviving mutant is not automatically equivalent. An `equivalent` disposition
must name the production invariant that preserves the result, and an outer-entry
regression must still pin that result. Such a row claims no caught test.

## Dependencies

Subconscious and commons crates come from crates.io at exact versions, or as
a git dependency pinned to a full commit when a crate isn't published. Never
add a `path` dependency outside this repository; the gate refuses it. Moving a
dependency is its own commit, with its `Cargo.lock` change, never folded into
an unrelated one.
