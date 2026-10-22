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
//! SKIPPED, or FAILED.
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
    // If a locked screen keeps the shown preview out of the window server's
    // on-screen list, the hide cannot be checked; the window's kind still can.
    let locked = cerebellum_macos::screen_is_locked() == Some(true);
    let probe = match cerebellum_macos::probe_preview_hide() {
        Ok(probe) => probe,
        Err(reason) => {
            println!("test {TEST_NAME} ... SKIPPED: {reason}");
            return;
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
            return;
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
        println!("test {TEST_NAME} ... ok");
    } else {
        println!("test {TEST_NAME} ... FAILED\n\n{}\n", failures.join("\n"));
        std::process::exit(101);
    }
}
