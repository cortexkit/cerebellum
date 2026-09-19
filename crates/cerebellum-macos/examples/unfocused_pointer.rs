//! THE MEASUREMENT: does a POINTER SEQUENCE posted to a process land when that
//! process is not frontmost?
//!
//! Its sibling `unfocused_keystroke` answered this for a single keystroke and
//! found that it lands, quietly, through the public API. A drag is the harder
//! case and the one the computer plane's durable action rests on: it is five
//! events that must arrive IN ORDER, and a sequence that half-arrives leaves a
//! mouse button down in a target the caller cannot see.
//!
//! WHY IT IS MEASURED HERE AND NOT AGAINST A BROWSER. A run against Chromium
//! reported zero events with the target backgrounded and sixteen with it
//! frontmost, on the same code and the same page. So Chromium does not receive
//! this path unfocused, which is why reference implementations reach for a
//! private SkyLight focus record before every post. Measuring the capability
//! against the one target class known to refuse it would answer a question
//! nobody asked: native applications are what the computer plane drives, since
//! browsers are policy-blocked from it and belong to the browser plane.
//!
//! THE OBSERVABLE is a text selection. A drag across seeded text selects it, and
//! the selection is readable while the target is STILL in the background, so the
//! reading cannot be explained by events queued and delivered on activation --
//! the confound that would make a delivered-on-focus result look like quiet
//! delivery.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this probe measures macOS event delivery and only runs there");
}

#[cfg(target_os = "macos")]
fn main() {
    use cerebellum_macos::post_event_to_pid;
    use std::process::Command;
    use std::thread::sleep;
    use std::time::Duration;

    const SEEDED: &str = "CEREBELLUM DRAG PROBE SELECT THIS LINE";

    let path = std::env::temp_dir().join("ck-unfocused-pointer.txt");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, SEEDED).expect("seed the probe file");

    let launched = Command::new("/usr/bin/open")
        .args(["-a", "TextEdit"])
        .arg(&path)
        .status()
        .expect("launch TextEdit");
    assert!(launched.success(), "TextEdit did not launch");
    sleep(Duration::from_millis(2500));

    let Some(target) = pid_of("TextEdit") else {
        eprintln!("PROBE FAILED: TextEdit did not appear in the process list");
        std::process::exit(1);
    };
    println!("target TextEdit pid: {target}");

    // Where the text actually is on screen. Taken BEFORE backgrounding, because
    // the geometry is the same either way and a reading taken later would be one
    // more thing the background state could be blamed for.
    let Some(text_frame) = read_text_area_frame(target) else {
        // An application launched while the screen is locked starts without
        // realising its windows, so this is the lock's fingerprint more often
        // than TextEdit's fault. Say which, and exit non-zero: a probe that
        // fails and exits 0 reads as a pass to anything that did not read it.
        eprintln!(
            "PROBE FAILED: TextEdit's text area has no readable frame (screen locked: {:?})",
            cerebellum_macos::screen_is_locked()
        );
        quit_textedit();
        std::process::exit(1);
    };
    println!("text area frame: {text_frame:?}");

    // Put something else in front. Without this the probe measures delivery to a
    // FOCUSED application, which an ordinary global post achieves too.
    //
    // The control run skips it deliberately. Its result is not a delivery
    // measurement: it establishes that the coordinates, the event construction
    // and the selection readback work at all, so that "no selection" in the real
    // run means the sequence did not arrive rather than that this probe could
    // never have seen it arrive.
    let control_run = std::env::var("CEREBELLUM_PROBE_KEEP_FOCUS").is_ok();
    if control_run {
        println!("CONTROL RUN: target left frontmost; this measures the INSTRUMENT, not delivery");
    } else {
        let _ = Command::new("/usr/bin/open")
            .args(["-a", "Finder"])
            .status();
        sleep(Duration::from_millis(1500));
    }

    let before = frontmost_process_id();
    println!("frontmost before posting: {before:?}");
    if !control_run && before == Some(target) {
        eprintln!(
            "PROBE INCONCLUSIVE: TextEdit is still frontmost, so this cannot measure UNFOCUSED \
             delivery."
        );
        quit_textedit();
        return;
    }

    // Sampled throughout: a check at the ends cannot see the target coming
    // forward in between, which is how two earlier runs on this desk were
    // invalidated by an ordinary click.
    let watcher = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..40 {
            if let Some(pid) = frontmost_process_id() {
                if !seen.contains(&pid) {
                    seen.push(pid);
                }
            }
            sleep(Duration::from_millis(60));
        }
        seen
    });

    // The five-event sequence: press at the start of the line, three moves
    // across it, release at the end. Posted one at a time to the target process
    // only, in the order a real drag produces them.
    // The PRODUCTION constructor, not a hand-rolled sequence. An earlier version
    // of this probe built its own CGEvents and measured nothing but its own
    // event-building: it bypassed the code it exists to test, so a negative
    // result would have indicted delivery for a defect in the probe.
    let y = text_frame.1 + 12.0;
    let from = cerebellum_macos::EventPoint {
        x: text_frame.0 + 6.0,
        y,
    };
    let to = cerebellum_macos::EventPoint {
        x: text_frame.0 + text_frame.2 - 12.0,
        y,
    };
    let events = match cerebellum_macos::mouse_drag_events(from, to) {
        Ok(events) => events,
        Err(error) => {
            eprintln!("PROBE FAILED: could not build the drag sequence: {error:?}");
            quit_textedit();
            std::process::exit(1);
        }
    };
    // A second control, for the control run only: post the SAME constructed
    // events to the global stream instead of to the pid. It separates two
    // explanations that look identical from the selection's side -- the events
    // are wrong, or per-process delivery does not carry pointer events. This is
    // the one place a global post appears in this repository, it is diagnostic,
    // and it is why it lives in a probe rather than in the driver.
    let post_globally = std::env::var("CEREBELLUM_PROBE_POST_GLOBAL").is_ok();
    // Stamp the window-routing fields before posting to the pid.
    //
    // The August run of this probe posted pointer events carrying NO routing
    // fields and measured nothing arriving, which was read as "the public
    // per-process path cannot carry pointer events". Reading trycua/cua's
    // driver showed their own public fallback stamps a set of integer fields
    // first -- windowNumber and the two window-under-pointer fields, plus the
    // target pid, which their comment attributes to Chromium's synthetic-event
    // filter. So what August measured was an UNROUTED event, which is a
    // narrower fact. This arm separates the two.
    //
    // The setter is public CoreGraphics. The field NUMBERS are undocumented,
    // which is why this lives in a probe and not in the driver: a measurement
    // is allowed to use an undocumented constant, a shipped path needs a
    // decision about depending on one.
    //
    // What this arm deliberately does NOT do is stamp a window-LOCAL point.
    // cua does that through a SkyLight private symbol, and the question worth
    // answering first is whether the public surface alone suffices. A negative
    // result here means "public fields alone are not enough", not "the public
    // path cannot do it" -- the difference is one more private symbol.
    // MEASURED, and it is why this arm cannot be read on its own. On this desk
    // on 2026-09-20, all three with the target FRONTMOST so delivery is not in
    // question:
    //
    //     no stamps, posted globally       -> selects the line
    //     stamps,    posted globally       -> selects NOTHING
    //     stamps,    posted to the pid     -> selects NOTHING
    //
    // The first two differ only by the stamps, so the stamps break the event
    // rather than routing it. Which field does it is not yet known; the pid
    // field (40) on a globally posted event is the first suspect, since it
    // tells the window server the event belongs to one process. Until that is
    // bisected, a negative from this arm is a fact about the stamping and not
    // about per-process pointer delivery.
    let window_routed = std::env::var("CEREBELLUM_PROBE_WINDOW_ROUTED").is_ok();
    let routed_window = if window_routed {
        match target_window(target) {
            Some(window) => {
                println!(
                    "routing to window {} at ({}, {}) {}x{}",
                    window.window_id, window.x, window.y, window.width, window.height
                );
                Some(window.window_id)
            }
            None => {
                eprintln!(
                    "PROBE FAILED: no on-screen window found for pid {target}, so there is no \
                     window number to route to."
                );
                quit_textedit();
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    // The HID tap resets the hardware idle table and the session tap does not
    // (measured with global_input_truth). An idleness gate can only read that
    // table if global posts enter at the session tap -- provided they still
    // DELIVER from there, which is what this switch lets the drag arm measure.
    let at_session_tap = std::env::var("CEREBELLUM_PROBE_SESSION_TAP").is_ok();
    println!(
        "posting {} pointer events {}",
        events.len(),
        if post_globally {
            format!(
                "GLOBALLY at the {} tap (diagnostic control)",
                if at_session_tap { "SESSION" } else { "HID" }
            )
        } else {
            format!("to pid {target}")
        }
    );
    for event in events {
        if let Some(window_id) = routed_window {
            stamp_window_routing(event.as_ref(), window_id, target);
        }
        if post_globally {
            objc2_core_graphics::CGEvent::post(
                if at_session_tap {
                    objc2_core_graphics::CGEventTapLocation::SessionEventTap
                } else {
                    objc2_core_graphics::CGEventTapLocation::HIDEventTap
                },
                Some(event.as_ref()),
            );
        } else {
            let _ = post_event_to_pid(target, event.as_ref());
        }
        sleep(Duration::from_millis(80));
    }
    sleep(Duration::from_millis(900));

    // Read the selection while the target is STILL in the background. Bringing
    // it forward first would make a queued-and-delivered-on-activation result
    // indistinguishable from quiet delivery.
    let selection = read_selected_text();
    println!("selection read while still unfocused: {selection:?}");
    let after = frontmost_process_id();
    println!("frontmost after posting: {after:?}");

    let observed = watcher.join().unwrap_or_default();
    println!("every frontmost process seen while posting: {observed:?}");
    if !control_run && (observed.contains(&target) || observed.len() > 1) {
        eprintln!(
            "VERDICT: DISCARDED -- focus moved during the post, so the sequence may have reached \
             a FOCUSED application."
        );
        quit_textedit();
        let _ = std::fs::remove_file(&path);
        return;
    }

    match selection.as_deref() {
        Some(text) if !text.trim().is_empty() && control_run => {
            println!(
                "CONTROL RESULT (NOT a delivery finding): the sequence selected {:?} with the \
                 target FRONTMOST. This establishes that the coordinates, the constructed events \
                 and the readback all work. It says nothing about unfocused delivery, because a \
                 frontmost target is reachable by any path.",
                text.trim()
            );
        }
        Some(text) if !text.trim().is_empty() => {
            println!(
                "VERDICT: THE SEQUENCE LANDED UNFOCUSED. A pointer drag reached a background \
                 native application in order and selected {:?}. Focus never moved.",
                text.trim()
            );
        }
        _ if window_routed => {
            println!(
                "VERDICT: NO SELECTION WITH WINDOW ROUTING -- AND THAT IS NOT A DELIVERY FINDING. \
                 Measured on this desk 2026-09-20: the same stamped sequence posted GLOBALLY to a \
                 FRONTMOST target also selects nothing, while the identical sequence WITHOUT the \
                 stamps selects the line. So the stamping breaks the event before delivery is \
                 reached, and a negative here says nothing about whether a per-process post can \
                 carry a pointer. Bisect the fields before reading this arm as an answer."
            );
        }
        _ => {
            println!(
                "VERDICT: NO SELECTION. Either the sequence did not arrive, or it arrived without \
                 the ordering a drag needs. Both are reported the same way here, and the audit \
                 record is what separates them: it names how far the sequence got."
            );
        }
    }

    quit_textedit();
    let _ = std::fs::remove_file(&path);
}

/// The largest on-screen window owned by `pid`.
///
/// Largest rather than first: an application owns several windows at once and
/// the document window is the one a drag is aimed at, while the others are
/// panels and toolbars that happen to enumerate earlier.
#[cfg(target_os = "macos")]
fn target_window(pid: i32) -> Option<cerebellum_macos::RawWindow> {
    cerebellum_macos::enumerate_windows(std::time::Duration::from_secs(3))
        .ok()?
        .into_iter()
        .filter(|window| window.owner_pid == pid as u32 && window.on_screen)
        .max_by(|left, right| {
            (left.width * left.height)
                .partial_cmp(&(right.width * right.height))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

/// Stamp the fields an AppKit window uses to route a mouse event it receives.
///
/// Field numbers are undocumented; the setter is public. Taken from cua's
/// public fallback path and named here so a reader is not left with bare
/// integers. The pid field carries their comment's reason: Chromium filters
/// synthetic events on it.
#[cfg(target_os = "macos")]
fn stamp_window_routing(event: &objc2_core_graphics::CGEvent, window_id: u32, pid: i32) {
    use objc2_core_graphics::{CGEvent, CGEventField};

    const CLICK_STATE: u32 = 1;
    const BUTTON_NUMBER: u32 = 3;
    const SUBTYPE: u32 = 7;
    const TARGET_PID: u32 = 40;
    const WINDOW_NUMBER: u32 = 51;
    const CLICK_GROUP: u32 = 58;
    const WINDOW_UNDER_POINTER: u32 = 91;
    const WINDOW_UNDER_POINTER_THAT_CAN_HANDLE: u32 = 92;

    let window = i64::from(window_id);
    for (field, value) in [
        (CLICK_STATE, 1_i64),
        (BUTTON_NUMBER, 0),
        (SUBTYPE, 3),
        (TARGET_PID, i64::from(pid)),
        (WINDOW_NUMBER, window),
        (CLICK_GROUP, window),
        (WINDOW_UNDER_POINTER, window),
        (WINDOW_UNDER_POINTER_THAT_CAN_HANDLE, window),
    ] {
        CGEvent::set_integer_value_field(Some(event), CGEventField(field), value);
    }
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

/// The screen rect of TextEdit's text area, as (x, y, width, height).
#[cfg(target_os = "macos")]
fn read_text_area_frame(pid: i32) -> Option<(f64, f64, f64, f64)> {
    let options = cerebellum_macos::AxReadOptions {
        max_depth: 12,
        max_elements: 4_000,
        timeout: std::time::Duration::from_secs(5),
    };
    let tree = cerebellum_macos::read_accessibility_tree(pid as u32, options).ok()?;
    fn find(element: &cerebellum_macos::AxElement) -> Option<cerebellum_macos::AxFrame> {
        if element.role.as_deref() == Some("AXTextArea") {
            return element.frame;
        }
        element.children.iter().find_map(find)
    }
    let frame = find(&tree.root)?;
    Some((frame.x, frame.y, frame.width, frame.height))
}

#[cfg(target_os = "macos")]
fn read_selected_text() -> Option<String> {
    let out = std::process::Command::new("/usr/bin/osascript")
        .args([
            "-e",
            "tell application \"System Events\" to tell process \"TextEdit\" to get value of attribute \"AXSelectedText\" of text area 1 of scroll area 1 of window 1",
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
