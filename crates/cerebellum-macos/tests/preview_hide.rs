// Separate binary: uses harness = false to open AppKit on the main thread.
//! The background-mode preview's window is the kind the helper promises, and
//! hiding it takes it off the screen at once.
//!
//! The preview is shown beside the person's own windows, so it must never
//! take focus or clicks: it is a non-activating panel that refuses to become
//! key or main, ignores the mouse and floats above normal windows. On a macOS
//! with Liquid Glass (macOS 26 and later) its pane is that view, looked up at
//! run time; otherwise it is the older blur. And when its agent is done the
//! helper hides it, often blocking on its event channel straight afterwards,
//! so the hide must reach the window server without another run-loop turn:
//! this test asks the window server right after the hide.
//!
//! WHY THIS TARGET HAS NO TEST HARNESS. AppKit windows must be created on a
//! process's main thread, and the standard harness runs every test on a
//! thread of its own, so `main` stands in for the harness and prints ok,
//! SKIPPED, or FAILED. An ok or FAILED run is reported in the standard
//! harness's format, summary line included, so tools that read test results
//! by name (the mutation catalogue's runner among them) can read this one.
//!
//! A SKIPPED run checked less than the test promises, so it exits with code 2
//! rather than 0: a run without a display must not read as a pass. A caller
//! that accepts a skip, and reports it itself, sets
//! `CEREBELLUM_DESK_TEST_SKIP_OK=1` to have it exit 0 instead.
//! `CEREBELLUM_PREVIEW_HIDE_FORCE_SKIP=1` is a test-binary-only seam: it
//! deterministically takes the no-display skip before touching AppKit, so a
//! child process can check both exit policies without changing the desk.
//!
//! The preview shows a window the person had covered, so it must also stay
//! out of screen sharing, recordings and screenshots: its sharing type is
//! checked too.
//!
//! The preview is shown fully transparent, so nothing appears on the desk of
//! the person running the test, and it never takes focus.

#[cfg(not(target_os = "macos"))]
fn main() {
    // AppKit exists only on macOS. The target still has to build so the
    // workspace does.
}

#[cfg(target_os = "macos")]
fn main() {
    const TEST_NAME: &str = "a_preview_is_a_click_through_panel_and_hiding_takes_it_off_the_screen";
    const SKIP_TEST: &str = "a_preview_skip_is_nonzero_unless_explicitly_accepted";
    if std::env::var_os("CEREBELLUM_PREVIEW_HIDE_FORCE_SKIP").is_some_and(|v| v == "1") {
        println!("test {TEST_NAME} ... SKIPPED: forced no-display probe");
        exit_skipped();
    }
    // Honour name filters the way the standard harness would.
    let mut filters = Vec::new();
    let mut skips = Vec::new();
    let mut list = false;
    let mut ignored_only = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--skip" => skips.extend(arguments.next()),
            "--list" => list = true,
            "--ignored" => ignored_only = true,
            "--test-threads" | "--format" | "--color" | "--logfile" | "-Z" => {
                arguments.next();
            }
            option if option.starts_with('-') => {}
            _ => filters.push(argument),
        }
    }
    let selected = |name: &str| {
        !ignored_only
            && !skips.iter().any(|skip| name.contains(skip.as_str()))
            && (filters.is_empty() || filters.iter().any(|filter| name.contains(filter.as_str())))
    };
    if list {
        let mut count = 0;
        for name in [TEST_NAME, SKIP_TEST] {
            if selected(name) {
                println!("{name}: test");
                count += 1;
            }
        }
        println!("\n{count} tests, 0 benchmarks");
        return;
    }
    if selected(SKIP_TEST) {
        println!("\nrunning 1 test");
        if let Err(reason) = check_skip_exit_policy() {
            println!("test {SKIP_TEST} ... FAILED\n{reason}");
            println!(
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out"
            );
            std::process::exit(101);
        }
        println!("test {SKIP_TEST} ... ok");
        println!("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out");
    }
    if !selected(TEST_NAME) {
        if selected(SKIP_TEST) {
            return;
        }
        println!("\nrunning 0 tests\n");
        println!(
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; \
             finished in 0.00s\n"
        );
        return;
    }
    println!("\nrunning 1 test");
    // If a locked screen keeps the shown preview out of the window server's
    // on-screen list, the hide cannot be checked; the window's kind still can.
    let locked = cerebellum_macos::screen_is_locked() == Some(true);
    let probe = match cerebellum_macos::probe_preview_hide() {
        Ok(probe) => probe,
        Err(reason) => {
            println!("test {TEST_NAME} ... SKIPPED: {reason}");
            exit_skipped();
        }
    };
    println!("{probe:?}");
    let mut failures = Vec::new();
    if probe.can_become_key || probe.can_become_main {
        failures.push("the preview's window can become key or main");
    }
    if !probe.ignores_mouse {
        failures.push("the preview's window takes clicks instead of letting them through");
    }
    if !probe.non_activating {
        failures.push("the preview's window is not a non-activating panel");
    }
    if probe.level <= 0 {
        failures.push("the preview's window does not float above normal windows");
    }
    if !probe.hidden_from_capture {
        failures.push(
            "the preview's window can be captured by screen sharing, recordings and screenshots",
        );
    }
    if !probe.badge_hidden_from_capture {
        failures.push("the badge's sharing type is not None");
    }
    if probe.liquid_glass != probe.liquid_glass_available {
        failures.push(if probe.liquid_glass_available {
            "this macOS has Liquid Glass, but the preview used the older blur"
        } else {
            "the preview claims Liquid Glass on a macOS without it"
        });
    }
    if !probe.listed_while_shown {
        // Without a window server session, or with the screen locked,
        // nothing is ever listed, and a pass would prove nothing about the
        // hide.
        if failures.is_empty() {
            let why = if locked {
                "the screen is locked, so no window is realised"
            } else {
                "the shown preview never appeared in the window server's on-screen list, which \
                 is what a session without a window server looks like"
            };
            println!(
                "test {TEST_NAME} ... SKIPPED (the window's kind was checked and is right): {why}"
            );
            exit_skipped();
        }
    } else {
        if probe.listed_after_hide {
            failures.push(
                "the window server still lists the hidden preview's window as on screen: the \
                 hide waits for a run-loop turn that a blocked helper never takes",
            );
        }
        if probe.visible_after_hide {
            failures.push("AppKit still calls the hidden preview's window visible");
        }
    }
    if failures.is_empty() {
        println!("test {TEST_NAME} ... ok\n");
        println!(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 0.00s\n"
        );
    } else {
        println!("test {TEST_NAME} ... FAILED\n");
        println!(
            "failures:\n\n---- {TEST_NAME} stdout ----\n{}\n\nfailures:\n    {TEST_NAME}\n",
            failures.join("\n")
        );
        println!(
            "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 0.00s\n"
        );
        std::process::exit(101);
    }
}

#[cfg(target_os = "macos")]
fn check_skip_exit_policy() -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    // Relaunched test binaries live outside the build tree. No operator state
    // or display is needed by the forced-skip child.
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let directory = std::path::PathBuf::from(format!(
        "/tmp/cerebellum-preview-skip-{}-{nonce}",
        std::process::id()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|e| e.to_string())?;
    let child = directory.join("preview-hide");
    let result = (|| {
        std::fs::copy(executable, &child).map_err(|e| e.to_string())?;
        for accepted in [false, true] {
            let mut command = std::process::Command::new(&child);
            command.env("CEREBELLUM_PREVIEW_HIDE_FORCE_SKIP", "1");
            command.env_remove("CEREBELLUM_DESK_TEST_SKIP_OK");
            if accepted {
                command.env("CEREBELLUM_DESK_TEST_SKIP_OK", "1");
            }
            let output = command.output().map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(&output.stdout);
            if output.status.code() != Some(if accepted { 0 } else { 2 })
                || !text.contains("SKIPPED: forced no-display probe")
            {
                return Err(format!(
                    "skip opt-in={accepted}: status {}: {text}",
                    output.status
                ));
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(child);
    let _ = std::fs::remove_dir(directory);
    result
}

/// End a run that could not check everything. Exit code 2 marks the skip as
/// not a pass; `CEREBELLUM_DESK_TEST_SKIP_OK=1` turns it into 0 for a caller
/// that reports the skip on its own.
#[cfg(target_os = "macos")]
fn exit_skipped() -> ! {
    let accepted =
        std::env::var_os("CEREBELLUM_DESK_TEST_SKIP_OK").is_some_and(|value| value == "1");
    std::process::exit(if accepted { 0 } else { 2 });
}
