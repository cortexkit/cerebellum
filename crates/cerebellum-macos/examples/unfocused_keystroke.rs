//! THE MEASUREMENT: does a keystroke posted to a process land when that process
//! is NOT frontmost, and does posting it steal focus?
//!
//! This decides the shape of the partial-takeover class. Three outcomes:
//!
//!   LANDS, FOCUS UNMOVED  -- per-process delivery is public-API-only, and the
//!                            class is buildable as designed.
//!   LANDS, FOCUS MOVED    -- delivery works but is not quiet, so the class is
//!                            not the non-disruptive rung we designed it to be.
//!   DOES NOT LAND         -- a private focus step is required for ALL apps, and
//!                            the public/private split is drawn in the wrong
//!                            place: keyboard versus pointer, not Cocoa versus
//!                            Chromium.
//!
//! Reference implementations call a PRIVATE SkyLight focus record before every
//! keystroke, for every target, with a comment saying a Cocoa app must be
//! AppKit-active for a keystroke to reach its key window. Their unit tests stub
//! that call out, so they prove transport selection rather than unfocused
//! delivery. This measures the thing they do not.
//!
//! Launches its own TextEdit and quits it. Nothing of the user's is touched.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this probe measures macOS per-process event delivery");
}

#[cfg(target_os = "macos")]
fn main() {
    use cerebellum_macos::post_event_to_pid;
    use objc2_core_graphics::{CGEvent, CGEventSource, CGEventSourceStateID};
    use std::process::Command;
    use std::thread::sleep;
    use std::time::Duration;

    // A file we own, so the keystroke has somewhere harmless to land and we can
    // read the result from disk rather than from the UI.
    let path = std::env::temp_dir().join("ck-unfocused-probe.txt");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, "").expect("seed the probe file");

    let launched = Command::new("/usr/bin/open")
        .args(["-a", "TextEdit"])
        .arg(&path)
        .status()
        .expect("launch TextEdit");
    assert!(launched.success(), "TextEdit did not launch");
    sleep(Duration::from_millis(2500));

    let target = match pid_of("TextEdit") {
        Some(pid) => pid,
        None => {
            eprintln!("PROBE FAILED: TextEdit did not appear in the process list");
            return;
        }
    };
    println!("target TextEdit pid: {target}");

    // Put something ELSE in front, so the target is genuinely not frontmost.
    // Without this the measurement answers a different question.
    let _ = Command::new("/usr/bin/open")
        .args(["-a", "Finder"])
        .status();
    sleep(Duration::from_millis(1500));

    let before = frontmost_process_id();
    println!("frontmost before posting: {before:?}");
    if before == Some(target) {
        eprintln!(
            "PROBE INCONCLUSIVE: TextEdit is still frontmost, so this cannot measure UNFOCUSED \
             delivery. Click another window and re-run."
        );
        quit_textedit();
        return;
    }

    // WATCH FOCUS THROUGHOUT. Sampling only before and after cannot see a human
    // click land in between: it reports the two endpoints and calls the gap
    // uneventful. If the target is ever frontmost during this window, the
    // keystroke may have been delivered to a FOCUSED app and the measurement
    // answers a different question than the one asked.
    let watcher = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..16 {
            if let Some(pid) = frontmost_process_id() {
                if !seen.contains(&pid) {
                    seen.push(pid);
                }
            }
            std::thread::sleep(Duration::from_millis(120));
        }
        seen
    });

    // One 'x' keystroke, down then up, addressed to the target process only.
    let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState).expect("an event source");
    const KEY_X: u16 = 7;
    for down in [true, false] {
        let event =
            CGEvent::new_keyboard_event(Some(&source), KEY_X, down).expect("a keyboard event");
        let _ = post_event_to_pid(target, &event);
        sleep(Duration::from_millis(60));
    }
    sleep(Duration::from_millis(1200));

    let after = frontmost_process_id();
    println!("frontmost after posting:  {after:?}");

    // THE CONTROL THAT DECIDES THE ANSWER. Reading the text after bringing
    // TextEdit forward cannot distinguish "landed while unfocused" from
    // "queued, delivered on activation" -- both put the character there, and
    // only the first is quiet delivery. So read the value through the
    // accessibility API while the target is STILL not frontmost.
    let unfocused_value = read_text_value(target);
    println!("value read while still unfocused: {unfocused_value:?}");

    let observed = watcher.join().unwrap_or_default();
    println!("every frontmost process seen while posting: {observed:?}");
    if observed.contains(&target) || observed.len() > 1 {
        eprintln!(
            "VERDICT: DISCARDED -- focus moved during the post, so the keystroke may have \
             reached a FOCUSED application. Re-run without touching the machine."
        );
        quit_textedit();
        let _ = std::fs::remove_file(&path);
        return;
    }

    // Ask TextEdit to save, so the answer comes from disk rather than a screen
    // reading. Cmd-S goes to whatever is frontmost, so bring it forward FIRST --
    // the measurement is already taken by this point.
    let _ = Command::new("/usr/bin/open")
        .args(["-a", "TextEdit"])
        .status();
    sleep(Duration::from_millis(1200));
    let _ = Command::new("/usr/bin/osascript")
        .args([
            "-e",
            "tell application \"System Events\" to keystroke \"s\" using command down",
        ])
        .status();
    sleep(Duration::from_millis(1500));

    let landed = std::fs::read_to_string(&path).unwrap_or_default();
    quit_textedit();
    let _ = std::fs::remove_file(&path);

    let text_arrived = unfocused_value.as_deref().is_some_and(|v| v.contains('x'));
    let arrived_only_after_activation = !text_arrived && landed.contains('x');
    let focus_moved = after == Some(target) && before != Some(target);

    println!();
    println!("keystroke landed WHILE UNFOCUSED:      {text_arrived}");
    println!("arrived only after activation:        {arrived_only_after_activation}");
    println!("posting moved focus to the target:     {focus_moved}");
    println!();
    println!(
        "VERDICT: {}",
        match (text_arrived, focus_moved) {
            (true, false) =>
                "LANDS QUIETLY -- per-process delivery works on the public API with no focus \
                 step. The partial-takeover class is buildable as designed.",
            (true, true) =>
                "LANDS BUT STEALS FOCUS -- delivery works and is NOT quiet, so this is not the \
                 non-disruptive rung the class was designed around.",
            (false, _) if arrived_only_after_activation =>
                "QUEUED, NOT DELIVERED -- the character appeared only once the app was brought \
                 forward, so this is not quiet delivery: the effect waits for focus the user \
                 controls.",
            (false, _) =>
                "DOES NOT LAND -- an unfocused Cocoa app did not receive the keystroke, so a \
                 focus step is required for every target and the public/private split is drawn \
                 in the wrong place.",
        }
    );
}

/// Which process is frontmost, read through System Events.
///
/// A probe-only reading: production has no need for it, and adding FFI to
/// answer a question asked twice in one throwaway measurement would be the
/// wrong trade.
#[cfg(target_os = "macos")]
fn frontmost_process_id() -> Option<i32> {
    let out = std::process::Command::new("/usr/bin/osascript")
        .args([
            "-e",
            "tell application \"System Events\" to get unix id of first process whose frontmost is true",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(target_os = "macos")]
fn pid_of(name: &str) -> Option<i32> {
    let out = std::process::Command::new("/usr/bin/pgrep")
        .args(["-x", name])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

/// The target's document text, read WITHOUT focusing it.
///
/// Our accessibility reader exposes `value_description` but not an element's
/// value, so it cannot answer this. Asking TextEdit for its own document text
/// can, and reading a document does not activate the application -- which is
/// the whole point: the reading must not create the focus whose absence is
/// being measured.
#[cfg(target_os = "macos")]
fn read_text_value(_pid: i32) -> Option<String> {
    let out = std::process::Command::new("/usr/bin/osascript")
        .args([
            "-e",
            "tell application \"TextEdit\" to get text of document 1",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(target_os = "macos")]
fn quit_textedit() {
    let _ = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", "tell application \"TextEdit\" to quit saving no"])
        .status();
}
