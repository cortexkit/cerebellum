//! Time each primitive an observed global dispatch touches, ten times each,
//! on the host it runs on.
//!
//! The wire measured a refused drag at 160-370 ms and a completed one at
//! 1.0-1.3 s on a VM where the sequence itself is a quarter of a second;
//! this says which primitive carries the rest. Run under the same
//! attribution the module has (a supervised child of ck-subc) or the tap
//! creation arm answers permission, not cost.
//!
//! Run: `cargo run -p cerebellum-macos --example observed_stage_cost`

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("macOS only");
}

#[cfg(target_os = "macos")]
fn main() {
    use cerebellum_macos::{
        frontmost_process_id, heartbeat_marker_event, mouse_move_event, post_event_globally,
        seconds_since_last_input, EventPoint, EventSourceStateTable, SessionEventTap,
    };
    use std::time::Instant;

    fn report(name: &str, samples: &mut [u128]) {
        samples.sort_unstable();
        println!(
            "{name:<34} min {:>6} us  median {:>6} us  max {:>6} us",
            samples[0],
            samples[samples.len() / 2],
            samples[samples.len() - 1]
        );
    }

    let mut tap_create = Vec::new();
    let mut tap_drop = Vec::new();
    let mut idle_read = Vec::new();
    let mut frontmost = Vec::new();
    let mut marker_build = Vec::new();
    let mut marker_post = Vec::new();
    let mut move_build = Vec::new();
    let mut move_post = Vec::new();
    let mut marker_seen = Vec::new();

    for _ in 0..10 {
        let t = Instant::now();
        let tap = match SessionEventTap::listen(256) {
            Ok(tap) => tap,
            Err(error) => {
                println!("tap creation refused: {error:?}");
                return;
            }
        };
        tap_create.push(t.elapsed().as_micros());

        let t = Instant::now();
        let _ = seconds_since_last_input(EventSourceStateTable::HidSystem);
        idle_read.push(t.elapsed().as_micros());

        let t = Instant::now();
        let _ = frontmost_process_id();
        frontmost.push(t.elapsed().as_micros());

        let t = Instant::now();
        let marker = heartbeat_marker_event(7).expect("marker builds");
        marker_build.push(t.elapsed().as_micros());
        let t = Instant::now();
        let _ = post_event_globally(marker);
        marker_post.push(t.elapsed().as_micros());
        let posted = Instant::now();
        let seen = loop {
            match tap
                .events()
                .recv_timeout(std::time::Duration::from_millis(500))
            {
                Ok(event) if event.marker_nonce == 7 => break Some(posted.elapsed().as_micros()),
                Ok(_) => continue,
                Err(_) => break None,
            }
        };
        match seen {
            Some(us) => marker_seen.push(us),
            None => println!("marker not seen within 500 ms"),
        }

        let t = Instant::now();
        let event = mouse_move_event(EventPoint { x: 400.0, y: 400.0 }).expect("move builds");
        move_build.push(t.elapsed().as_micros());
        let t = Instant::now();
        let _ = post_event_globally(event);
        move_post.push(t.elapsed().as_micros());

        let t = Instant::now();
        drop(tap);
        tap_drop.push(t.elapsed().as_micros());
    }

    report("SessionEventTap::listen", &mut tap_create);
    report("drop(tap) (stop + join thread)", &mut tap_drop);
    report("seconds_since_last_input(HID)", &mut idle_read);
    report("frontmost_process_id", &mut frontmost);
    report("heartbeat_marker_event", &mut marker_build);
    report("post_event_globally(marker)", &mut marker_post);
    if !marker_seen.is_empty() {
        report("marker seen by tap (post->cb)", &mut marker_seen);
    }
    report("mouse_move_event", &mut move_build);
    report("post_event_globally(move)", &mut move_post);
}
