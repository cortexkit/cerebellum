# Working in cerebellum

Read this before you change code here. Each rule comes from a defect a worker shipped.

## Gates

The file-size check keeps tracked hand-written Rust source under 5,000 lines and prevents already larger files from growing. Before adding to a baselined file, split something out first or ask the agent that assigned the work.

Don't run the fast gate (`scripts/fast-gate.sh`) or the full gate (`scripts/rust-test-gate.sh`). The head runs the fast gate when it merges your delivery, so running it yourself only doubles the wait: on 31 Oct and 1 Nov, workers spent most of each hour watching gate halves the head then ran again.

Run only what your change needs, and keep each run to minutes:

- **Tests:** the filtered tests for the files and behaviour you changed, by module path or test name. For a bug fix, also show once that its new test fails without the fix.
- **Lint:** `cargo clippy --locked -p <crate> --all-targets -- -D warnings` for the crates you changed, on Linux, plus `--target x86_64-pc-windows-gnu` if the change touches code that builds on Windows. Run these on the build server with your bash tool's `runon: "linux,8c"`. A 16-vCPU job waits for a whole free build server.
- **macOS:** if your change touches code that builds or runs only on macOS, run macOS clippy for that crate and its macOS tests on this Mac. Linux never compiles that code, so the build server can't check it.
- **Formatting:** `cargo fmt --check`.
- **Pinned surfaces:** some tests pin what cerebellum announces, far from the code that changes it. If you change the HELLO manifest (`manifest.rs`: capabilities, roles, operations), `management::OPERATIONS`, or a tool definition, also run these on Linux and, when the change builds on macOS, on this Mac: `cargo test --locked -p cerebellum --lib hello_manifest` and `cargo test --locked -p cerebellum --test conformance`. If one fails only because of your intended addition, update the pin. In a historical comparison, remove exactly your addition rather than repinning the older digest. If you change a budget, also run `cargo test --locked -p cerebellum --lib budgets`.

Run cargo on this Mac only for macOS-only checks. Each fresh test binary run on this Mac costs a system security scan while Ufuk works on it. Keep the normal build directory; a separate `CARGO_TARGET_DIR` forces a cold build.

Build-server Linux jobs can't change tracked files (from 2 Nov 2026): a write, `sed -i`, formatter or golden rewrite in a job fails with "Operation not permitted". So for a red-first proof, undo the fix in your local checkout (or a scratch copy under `$TMPDIR`), run the test, then restore it; never edit a tracked file inside the job, or the test runs against the fix and reads as a false red-first result. Regenerate tracked fixtures locally, or name them in the job's `return_paths`. Keep cargo `--locked` and use `cargo fmt --check` in jobs.

If a test you didn't touch fails, rerun that one test by name on the base commit; never rerun a whole suite. A filtered run that takes longer than about 15 minutes means the filter is too broad. If a check can't run in your sandbox, name it in your report rather than skipping it silently.

## Standing approvals

Start work as soon as you have read the brief. A brief's fence limits what you change, never when you start. Do these without asking, and list each one in your report with the reason:

- Fix tests, fixtures, test doubles and `examples/` that your change breaks, outside the fence included, as long as their assertions keep their meaning. Never loosen an assertion to make it pass.
- Add narrow plumbing (a parameter, a field or a call site) in a file next to the fence when the change can't reach its target otherwise.
- Regenerate a pin when its output changes only because of your stated change: digest pins in tests, the `profile/mod.rs` self-digest, goldens and fixtures produced by their generators.
- Add `#[cfg(test)]` hooks and test-only seams.
- Rebase onto `origin/main` and resolve conflicts by keeping both sides' intent.
- Run builds and tests remotely as needed, at 8 vCPUs.

These still come to the head before you change them:

- the advertised tool definitions and any agent-visible wording in them;
- stored formats, migrations and format floors;
- a new outcome or reason word in a vocabulary;
- anything that loosens a security, consent or credential check;
- dependencies and lockfiles.

## Some computer-plane tests run only on macOS

`crates/cerebellum/src/computer_capability/` compiles on every platform, but many of its tests, and all of `cerebellum-macos`, run only on macOS. The Linux build server runs only the platform-neutral ones. A test that relies on macOS behaviour, such as macOS's own keyboard shortcuts, needs `#[cfg(target_os = "macos")]`, or it fails on Linux.

- For any change there, run macOS clippy and the touched macOS tests on this Mac; running them with `runon` doesn't count.
- The test `computer_consent_wire_tests::stack_tests::a_computer_consent_call_fits_half_a_default_thread_stack` runs a real call on a 1 MiB thread. When a future on the serve path grows too large, the whole test binary aborts with "fatal runtime error: stack overflow" and names no test. To find it, run each test alone with the binary's `--exact` flag. Box the future that grew (`Box::pin`) where it is created. Never raise a stack size.
- Code used only on macOS is dead code on Linux, and Linux clippy with `-D warnings` refuses it.

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
