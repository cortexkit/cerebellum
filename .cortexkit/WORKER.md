# Working in cerebellum

Read this before you change code here. Each rule comes from a defect a worker shipped.

## Gates

Run cargo on this Mac only for the gate's Mac half and for tests that need macOS. Run check, clippy and every other test on the build server with `runon`. Each fresh test binary run on this Mac costs a system security scan while Ufuk works on it.

The fast gate has two halves, chosen from your diff:

- **Linux half:** fmt, clippy for Linux and both Windows targets, the tests that run on Linux, and the protective checks. The build server's copy of the repository carries no branch names, so take the base commit here first with `git rev-parse origin/main`, then run `bash scripts/fast-gate.sh --part linux --base <that commit>` with your bash tool's `runon: "linux,8c"`.
- **Mac half:** macOS clippy and the tests that need macOS, for the macOS crates your diff touches. Run it locally on this Mac: `bash scripts/fast-gate.sh --part mac --base <that commit>`. An opt-in remote form exists (`bash scripts/fast-gate.sh --part mac --remote --base <commit>` from a Mac terminal with `ck` access, or `--part mac --vm` with `runon: "macos"`), but don't use it: in the VM, cerebellum-computer's macOS lib tests hang until the job's 60-minute timeout, most likely because the VM has no window-server session (jobs 01a17ec1-843f-7155-8394-8e644365a681 and 01a17ef8-ad0b-712b-a7d2-7dfe9cb9386c on 2026-10-27). Use the local half. The remote form reports the desk-bound phases it cannot check as `NOT VERIFIED` lines, never silent skips.

Run both before you deliver, as two parallel tool calls, with the same `--base` commit. Each half prints a `FAST GATE FINGERPRINT` line; the two must match, which shows both checked the same tree. On the head's host, `bash scripts/fast-gate.sh` with no `--part` runs both halves at once. The `NOT VERIFIED` phases of a remote run (window-server desk tests, the desk-probe example build) need a real desk: run `bash scripts/fast-gate.sh --part mac --base <commit>` locally on a Mac with an unlocked screen to check those. Don't run `scripts/rust-test-gate.sh`: that full gate takes up to 40 minutes, and the head runs it on main after integrating. If a check can't run in your sandbox, name it in your report rather than skipping it silently.

## Some computer-plane tests run only on macOS

`crates/cerebellum/src/computer_capability/` compiles on every platform, but many of its tests, and all of `cerebellum-macos`, run only on macOS. The Linux build server runs only the platform-neutral ones. A test that relies on macOS behaviour, such as macOS's own keyboard shortcuts, needs `#[cfg(target_os = "macos")]`, or it fails on Linux.

- For any change there, the gate's Mac half must pass on this Mac; running it with `runon` doesn't count.
- The test `computer_consent_wire_tests::stack_tests::a_computer_consent_call_fits_half_a_default_thread_stack` runs a real call on a 1 MiB thread. When a future on the serve path grows too large, the whole test binary aborts with "fatal runtime error: stack overflow" and names no test. To find it, run each test alone with the binary's `--exact` flag. Box the future that grew (`Box::pin`) where it is created. Never raise a stack size.
- Clippy for Linux and Windows runs in the gate's Linux half. Code used only on macOS is dead code on Linux, and `-D warnings` refuses it.

## Verification scope

- For a bug fix, add a test that fails without the fix and show that once; otherwise run only the filtered tests for what you touched. Do not deliberately break working code for extra proofs, run full suites, or repeat runs.
- Never pipe a command through `grep`, `head` or `tail` without `set -o pipefail`. The pipe can hide the command's exit status.

## What must not change by accident

- The advertised tool definitions (`flat_tools.rs` and the tool catalog) are part of every agent's prompt cache. Don't change them unless the brief says so. The catalog byte tests must stay unchanged.
- Never edit a published vocabulary file. Mint the next revision, following the last mint.
- `crates/cerebellum/src/profile/mod.rs` embeds a digest of its own source. After any edit to it, refresh the pin in `crates/cerebellum/resources/ck-browser-profile-registry-v1.json` last.

## Tests never touch the operator's state

- Tests never read `~/.config/cortexkit/cerebellum.jsonc` and never write the live journal. Use the isolated constructors (`JournalMode::Isolated`, `new_in_memory`).
- Test binaries that relaunch themselves, and fixture executables, go under `/tmp`, never `$TMPDIR` or the build folder.
