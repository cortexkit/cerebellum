// Separate binary: uses harness = false to open AppKit on the main thread.
//! Hiding an agent cursor picture takes its window off the screen at once.
//!
//! The helper hides a picture when its agent's turn ends or its idle fade
//! finishes, and often blocks on its event channel straight afterwards, with
//! the AppKit run loop not turning again. A hide that only takes effect on
//! the next run-loop turn therefore leaves the badge on screen, frozen at
//! whatever opacity was last committed. So this test asks the window server,
//! not AppKit's own bookkeeping, and asks immediately after the hide, before
//! anything turns the run loop.
//!
//! WHY THIS TARGET HAS NO TEST HARNESS. AppKit windows must be created on a
//! process's main thread, and the standard harness runs every test on a
//! thread of its own, so `main` stands in for the harness and prints ok,
//! SKIPPED, or FAILED.
//!
//! The picture is shown fully transparent and never animated, so nothing
//! appears on the desk of the person running the test, and it never takes
//! focus: it is the helper's own click-through, non-activating panel.

#[cfg(not(target_os = "macos"))]
fn main() {
    // AppKit exists only on macOS. The target still has to build so the
    // workspace does.
}

#[cfg(target_os = "macos")]
fn main() {
    const TEST_NAME: &str = "hiding_a_cursor_picture_takes_its_window_off_the_screen";
    // Honour name filters the way the standard harness would.
    let mut filters = Vec::new();
    let mut skips = Vec::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--skip" => skips.extend(arguments.next()),
            "--test-threads" | "--format" | "--color" | "--logfile" | "-Z" => {
                arguments.next();
            }
            option if option.starts_with('-') => {}
            _ => filters.push(argument),
        }
    }
    if skips.iter().any(|skip| TEST_NAME.contains(skip.as_str()))
        || (!filters.is_empty()
            && !filters
                .iter()
                .any(|filter| TEST_NAME.contains(filter.as_str())))
    {
        return;
    }
    if cerebellum_macos::screen_is_locked() == Some(true) {
        println!("test {TEST_NAME} ... SKIPPED: the screen is locked, so no window is realised");
        return;
    }
    let probe = match cerebellum_macos::probe_cursor_hide(motion()) {
        Ok(probe) => probe,
        Err(reason) => {
            println!("test {TEST_NAME} ... SKIPPED: {reason}");
            return;
        }
    };
    println!("{probe:?}");
    if !probe.listed_while_shown {
        // Without a window server session nothing is ever listed, and a pass
        // would prove nothing about the hide.
        println!(
            "test {TEST_NAME} ... SKIPPED: the shown picture never appeared in the window \
             server's on-screen list, which is what a session without a window server looks like"
        );
        return;
    }
    let mut failures = Vec::new();
    if probe.listed_after_hide {
        failures.push(
            "the window server still lists the hidden picture's window as on screen: the hide \
             waits for a run-loop turn that a blocked helper never takes",
        );
    }
    if probe.visible_after_hide {
        failures.push("AppKit still calls the hidden picture's window visible");
    }
    if failures.is_empty() {
        println!("test {TEST_NAME} ... ok");
    } else {
        println!("test {TEST_NAME} ... FAILED\n\n{}\n", failures.join("\n"));
        std::process::exit(101);
    }
}

/// Plain stand-ins for the module's motion curves: the probe only needs a
/// picture that arrives fully transparent and stays put.
#[cfg(target_os = "macos")]
fn motion() -> cerebellum_macos::CursorMotion {
    cerebellum_macos::CursorMotion {
        duration_ms: |_, _| 0.0,
        position: |_, to, _, _| to,
        settle_scale: |_, _, _| 1.0,
        fade_alpha: |_, _| 1.0,
        arrival_ms: 250.0,
        arrival_start: |to, _| to,
        arrival_alpha: |_, _| 0.0,
    }
}
