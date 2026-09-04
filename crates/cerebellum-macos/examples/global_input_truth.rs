//! Live readings for global post, idle tables, and the session event tap.
//!
//! One binary, three subcommands, each measurement a line:
//!
//! ```text
//! cargo run -p cerebellum-macos --example global_input_truth -- idle hid
//! cargo run -p cerebellum-macos --example global_input_truth -- idle combined
//! cargo run -p cerebellum-macos --example global_input_truth -- tap 5
//! cargo run -p cerebellum-macos --example global_input_truth -- tap-liveness 10
//! ```
//!
//! Exits non-zero when an arm could not be measured (no Input Monitoring, tap
//! not created, unknown table). A completed measurement that disagrees with the
//! banked invariant is still a measurement: it prints what it saw and exits 0.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this probe measures macOS global input and only runs there");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        eprintln!(
            "usage: global_input_truth idle <hid|combined> | tap [seconds] | tap-liveness [seconds]"
        );
        std::process::exit(1);
    };
    match command.as_str() {
        "idle" => idle(args.next().as_deref()),
        "tap" => tap(parse_seconds(args.next(), 5)),
        "tap-liveness" => tap_liveness(parse_seconds(args.next(), 10)),
        other => {
            eprintln!("unknown command {other}; use idle, tap, or tap-liveness");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "macos")]
fn parse_seconds(arg: Option<String>, default: u64) -> u64 {
    match arg {
        None => default,
        Some(value) => value.parse().unwrap_or_else(|_| {
            eprintln!("seconds must be an integer, got {value}");
            std::process::exit(1);
        }),
    }
}

#[cfg(target_os = "macos")]
fn idle(table_name: Option<&str>) {
    use cerebellum_macos::{
        mouse_move_event, mouse_move_event_from_private_source,
        post_event_at_hid_tap_for_measurement, post_event_globally, seconds_since_last_input,
        EventPoint, EventSourceStateTable,
    };

    // `--private-source` posts from a Private event source instead of the
    // production HIDSystemState one. Measured: the production source RESETS
    // the HID idle table (20024s -> 0.8s after one post), so this arm asks
    // whether a private source leaves it alone -- which decides whether the
    // idleness gate can read the HID table at all.
    let private_source = std::env::args().any(|arg| arg == "--private-source");
    // `--session-tap` posts at the session tap location instead of the HID
    // tap, the other variable that could decide which table a post disturbs.
    let session_tap = std::env::args().any(|arg| arg == "--session-tap");

    let table = match table_name {
        Some("hid") | Some("HIDSystemState") => EventSourceStateTable::HidSystem,
        Some("combined") | Some("CombinedSessionState") => EventSourceStateTable::CombinedSession,
        Some(other) => {
            eprintln!("unknown table {other}; use hid or combined");
            std::process::exit(1);
        }
        None => {
            eprintln!("idle requires a table: hid or combined");
            std::process::exit(1);
        }
    };

    let before = seconds_since_last_input(table);
    println!("table {}", table_label(table));
    println!("seconds_before {before}");

    let point = current_pointer();
    let at = EventPoint {
        x: point.x,
        y: point.y,
    };
    let built = if private_source {
        mouse_move_event_from_private_source(at)
    } else {
        mouse_move_event(at)
    };
    let event = match built {
        Ok(event) => event,
        Err(error) => {
            eprintln!("could not construct a mouse-move: {error}");
            std::process::exit(1);
        }
    };
    if session_tap {
        let _ = post_event_globally(event);
    } else {
        let _ = post_event_at_hid_tap_for_measurement(event);
    }
    println!(
        "posted mouse-moved at {} tap from {} source",
        if session_tap { "SESSION" } else { "HID" },
        if private_source {
            "PRIVATE"
        } else {
            "HIDSystemState"
        }
    );

    let after = seconds_since_last_input(table);
    println!("seconds_after {after}");
}

#[cfg(target_os = "macos")]
fn table_label(table: cerebellum_macos::EventSourceStateTable) -> &'static str {
    match table {
        cerebellum_macos::EventSourceStateTable::HidSystem => "hid",
        cerebellum_macos::EventSourceStateTable::CombinedSession => "combined",
    }
}

#[cfg(target_os = "macos")]
fn current_pointer() -> cerebellum_macos::EventPoint {
    use objc2_core_graphics::{CGEvent, CGEventSource, CGEventSourceStateID};

    let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState);
    let Some(source) = source else {
        eprintln!("could not create an event source to read the pointer");
        std::process::exit(1);
    };
    let Some(event) = CGEvent::new(Some(&source)) else {
        eprintln!("could not create an event to read the pointer");
        std::process::exit(1);
    };
    let loc = CGEvent::location(Some(&event));
    cerebellum_macos::EventPoint { x: loc.x, y: loc.y }
}

#[cfg(target_os = "macos")]
fn tap(seconds: u64) {
    use std::time::{Duration, Instant};

    use cerebellum_macos::{mouse_move_event, post_event_globally, EventPoint, SessionEventTap};

    let tap = match SessionEventTap::listen(64) {
        Ok(tap) => tap,
        Err(error) => exit_tap_unmeasured(error),
    };
    println!("tap_enabled {}", tap.is_enabled());
    println!("listen_seconds {seconds}");

    drain_for(&tap, Duration::from_secs(seconds));

    let our_pid = i64::from(std::process::id());
    let point = current_pointer();
    let event = match mouse_move_event(EventPoint {
        x: point.x,
        y: point.y,
    }) {
        Ok(event) => event,
        Err(error) => {
            eprintln!("could not construct a mouse-move: {error}");
            std::process::exit(1);
        }
    };
    let _ = post_event_globally(event);
    println!("posted mouse-moved our_pid={our_pid}");

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_ours = false;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tap.events().recv_timeout(remaining) {
            Ok(event) => {
                println!(
                    "event pid={} type={}",
                    event.source_unix_process_id, event.event_type
                );
                if event.source_unix_process_id == our_pid {
                    saw_ours = true;
                }
            }
            Err(_) => break,
        }
    }
    if saw_ours {
        println!("synthetic_event seen pid={our_pid}");
    } else {
        println!("synthetic_event not seen within 2s");
    }
}

#[cfg(target_os = "macos")]
fn tap_liveness(seconds: u64) {
    use std::thread::sleep;
    use std::time::Duration;

    use cerebellum_macos::{mouse_move_event, post_event_globally, EventPoint, SessionEventTap};

    // A rendezvous channel (bound 0): every send blocks until received, so the
    // callback stalls on the FIRST event and stays stalled for the whole sleep
    // with nothing draining. A bound of 1 could not prove a stall -- draining
    // afterwards wakes a blocked sender, so one event or two both drain as
    // two.
    let tap = match SessionEventTap::listen(0) {
        Ok(tap) => tap,
        Err(error) => exit_tap_unmeasured(error),
    };
    println!("enabled_before {}", tap.is_enabled());
    // Generate the load the arm is measuring. A silent machine produces no
    // events, so a tap that is never invoked can never stall and never be
    // disabled -- the first run of this arm reported enabled_after=true on an
    // idle desk with nobody draining, which proved only that. Two posts
    // against a bound of one: the second blocks the callback, and macOS's
    // timeout is what the sleep waits out.
    for _ in 0..1 {
        match mouse_move_event(EventPoint { x: 640.0, y: 400.0 }) {
            Ok(event) => {
                let _ = post_event_globally(event);
            }
            Err(error) => {
                eprintln!("UNMEASURED: could not construct a mouse-move: {error}");
                std::process::exit(1);
            }
        }
    }
    println!("posted 1 event into a rendezvous channel without draining");
    // Half the sleep with the callback stalled, then a second event from THIS
    // thread while the tap thread is still blocked. If CoreGraphics only
    // notices a timed-out callback when it next tries to deliver, this is the
    // delivery that lets it notice; on a silent desk nothing else would.
    let half = Duration::from_secs(seconds / 2);
    sleep(half);
    println!("enabled_midway {}", tap.is_enabled());
    if let Ok(event) = mouse_move_event(EventPoint { x: 650.0, y: 410.0 }) {
        let _ = post_event_globally(event);
        println!("posted a second event while the callback was stalled");
    }
    sleep(half);
    println!("slept_seconds {seconds}");
    println!("enabled_after {}", tap.is_enabled());
    // Drain what queued. One event means the second post's callback is still
    // blocked on the send (the stall happened); two means it was never blocked
    // and this arm measured nothing about a stalled tap.
    let mut drained = 0;
    while tap.events().try_recv().is_ok() {
        drained += 1;
    }
    sleep(Duration::from_millis(200));
    while tap.events().try_recv().is_ok() {
        drained += 1;
    }
    println!("drained_after_sleep {drained} (1 = the event was delivered and its callback blocked for the sleep; 0 = never delivered, arm unmeasured)");
}

#[cfg(target_os = "macos")]
fn drain_for(tap: &cerebellum_macos::SessionEventTap, duration: std::time::Duration) {
    use std::time::Instant;

    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tap.events().recv_timeout(remaining) {
            Ok(event) => println!(
                "event pid={} type={}",
                event.source_unix_process_id, event.event_type
            ),
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "macos")]
fn exit_tap_unmeasured(error: cerebellum_macos::SessionEventTapError) -> ! {
    use cerebellum_macos::SessionEventTapError;
    match error {
        SessionEventTapError::NotCreated { input_monitoring } => {
            eprintln!("tap not created; Input Monitoring: {input_monitoring:?}");
        }
        other => eprintln!("tap not created: {other}"),
    }
    std::process::exit(1);
}
