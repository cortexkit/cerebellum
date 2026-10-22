# Working in cerebellum

Read this before you change code here. Each rule comes from a defect a worker shipped.

## The computer plane runs only on macOS and Windows

`crates/cerebellum/src/computer_capability/` and the platform crates compile only on macOS and Windows. The Linux build server never runs their tests.

- For any change there, run `cargo test -p cerebellum --lib` on this Mac before you deliver, not with `runon`.
- The test `computer_consent_wire_tests::stack_tests::a_computer_consent_call_fits_half_a_default_thread_stack` runs a real call on a 1 MiB thread. When a future on the serve path grows too large, the whole test binary aborts with "fatal runtime error: stack overflow" and names no test. To find it, run each test alone with the binary's `--exact` flag. Box the future that grew (`Box::pin`) where it is created. Never raise a stack size.
- Also run clippy on Linux (`runon: linux,4c`, `cargo clippy --locked --workspace --all-targets -- -D warnings`). Code used only on macOS and Windows is dead code on Linux, and `-D warnings` refuses it.

## Mutation proofs

- Put new catalogue rows in a new file named for your change (`mutations.d/<topic>.toml`), not in a shared file such as `agent-cursor.toml`. Parallel workers appending to one file conflict at every merge. Edit an existing row only when your change moves its anchor or renames its test, and say so.
- Before you deliver, run `bash scripts/mutations.sh --check-only`. The strict check refuses a row whose expected test no longer exists, which the anchor checker alone misses.
- Prefer `scripts/mutations.sh` to replay catalogue rows with the pinned runner.
- When you run a test by hand under a mutation, never pipe the command through `grep`, `head` or `tail` without `set -o pipefail`. The pipe hides cargo's exit status.
- Print the mutated line in the same command that runs the test, so the output proves the job saw the mutation. Read the result of that run, not of a later clean run.

## What must not change by accident

- The advertised tool definitions (`flat_tools.rs` and the tool catalog) are part of every agent's prompt cache. Don't change them unless the brief says so. The catalog byte tests must stay unchanged.
- Never edit a published vocabulary file. Mint the next revision, following the last mint.
- `crates/cerebellum/src/profile/mod.rs` embeds a digest of its own source. After any edit to it, refresh the pin in `crates/cerebellum/resources/ck-browser-profile-registry-v1.json` last.

## Tests never touch the operator's state

- Tests never read `~/.config/cortexkit/cerebellum.jsonc` and never write the live journal. Use the isolated constructors (`JournalMode::Isolated`, `new_in_memory`).
- Test binaries that relaunch themselves, and fixture executables, go under `/tmp`, never `$TMPDIR` or the build folder.
