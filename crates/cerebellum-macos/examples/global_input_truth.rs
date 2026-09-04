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
        mouse_move_event, post_event_globally, seconds_since_last_input, EventPoint,
        EventSourceStateTable,
    };

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
    println!("posted mouse-moved globally");

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

    use cerebellum_macos::SessionEventTap;

    // Bound of 1 so an undrained tap stalls the callback on the next event,
    // which is the condition whose timeout this arm is measuring.
    let tap = match SessionEventTap::listen(1) {
        Ok(tap) => tap,
        Err(error) => exit_tap_unmeasured(error),
    };
    println!("enabled_before {}", tap.is_enabled());
    println!("slept_seconds {seconds} without draining");
    sleep(Duration::from_secs(seconds));
    println!("enabled_after {}", tap.is_enabled());
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
