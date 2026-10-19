// Separate binary: uses harness = false to open AppKit on the main thread.
//! The agent cursor animates with real frames: its entry and its glides are
//! drawn as a run of small steps at the display's pace, not as a jump, and it
//! holds the animation activity only while it moves.
//!
//! The helper is a background process that sits with no window on screen
//! between turns, which is when macOS naps processes and coalesces their
//! timers. If its frame wake-ups come late, a third-of-a-second glide shows
//! as the badge at the start and then at the end. So this test drives the
//! helper's own loop through an idle spell, an entry, a glide, a window-follow
//! report and a hide, and reads the frame intervals and drawn positions the
//! loop recorded.
//!
//! It prints the measured frame intervals either way. Set
//! `CURSOR_MOTION_PROBE_WITHOUT_ACTIVITY=1` to run once more without the
//! animation activity and print what macOS does to the frames then; that run
//! is a measurement only and never fails. `CURSOR_MOTION_PROBE_IDLE_SECS`
//! sets the idle spell (default 10 seconds).
//!
//! WHY THIS TARGET HAS NO TEST HARNESS. AppKit windows must be created on a
//! process's main thread, and the standard harness runs every test on a
//! thread of its own, so `main` stands in for the harness and prints ok,
//! SKIPPED, or FAILED.
//!
//! A badge is visible in the middle of the main display for about three
//! seconds. It is the helper's own click-through, non-activating panel, so it
//! never takes focus or receives a click.

#[cfg(not(target_os = "macos"))]
fn main() {
    // AppKit exists only on macOS. The target still has to build so the
    // workspace does.
}

#[cfg(target_os = "macos")]
fn main() {
    const TEST_NAME: &str = "cursor_glides_with_unthrottled_frames_and_rests_with_no_activity";
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
    let idle = std::time::Duration::from_secs(
        std::env::var("CURSOR_MOTION_PROBE_IDLE_SECS")
            .ok()
            .and_then(|secs| secs.parse().ok())
            .unwrap_or(10),
    );
    let probe = match cerebellum_macos::probe_cursor_motion(motion(), idle, true) {
        Ok(probe) => probe,
        Err(reason) => {
            println!("test {TEST_NAME} ... SKIPPED: {reason}");
            return;
        }
    };
    let failures = check(&probe, "with the animation activity", true);
    if std::env::var_os("CURSOR_MOTION_PROBE_WITHOUT_ACTIVITY").is_some() {
        // A second NSApplication run in one process is fine for AppKit; the
        // helper's loop sets the same policy again.
        match cerebellum_macos::probe_cursor_motion(motion(), idle, false) {
            Ok(probe) => {
                let _ = check(
                    &probe,
                    "WITHOUT the animation activity (measurement only)",
                    false,
                );
            }
            Err(reason) => println!("comparison run skipped: {reason}"),
        }
    }
    if failures.is_empty() {
        println!("test {TEST_NAME} ... ok");
    } else {
        println!("test {TEST_NAME} ... FAILED\n\n{}\n", failures.join("\n"));
        std::process::exit(101);
    }
}

/// Stand-ins for the module's motion curves: a 300 ms ease-out glide and no
/// landing settle, so every frame of the glide moves the badge.
#[cfg(target_os = "macos")]
fn motion() -> cerebellum_macos::CursorMotion {
    cerebellum_macos::CursorMotion {
        duration_ms: |distance, _| if distance < 0.5 { 0.0 } else { 300.0 },
        position: |from, to, fraction, _| {
            if fraction >= 1.0 {
                return to;
            }
            let s = 1.0 - (1.0 - fraction.max(0.0)).powi(3);
            [
                from[0] + (to[0] - from[0]) * s,
                from[1] + (to[1] - from[1]) * s,
            ]
        },
        settle_scale: |_, _, _| 1.0,
        fade_alpha: |_, _| 1.0,
    }
}

#[cfg(target_os = "macos")]
fn percentile(sorted: &[f64], share: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() - 1) as f64 * share).round() as usize]
}

/// Print the measurement for one probe run and return its failures, one
/// message each; an empty list means the run passed.
#[cfg(target_os = "macos")]
fn check(probe: &cerebellum_macos::MotionProbe, run: &str, with_activity: bool) -> Vec<String> {
    let mut failures = Vec::new();
    let passes = &probe.passes;
    // Frame intervals while animating: the time from each pass that waited
    // a frame to the pass after it.
    let mut intervals: Vec<f64> = passes
        .windows(2)
        .filter(|pair| pair[0].frame_wait && pair[0].at_ms >= probe.entry_sent_ms)
        .map(|pair| pair[1].at_ms - pair[0].at_ms)
        .collect();
    intervals.sort_by(f64::total_cmp);
    let (median, p95, max) = (
        percentile(&intervals, 0.5),
        percentile(&intervals, 0.95),
        intervals.last().copied().unwrap_or(f64::NAN),
    );
    // Distinct positions drawn strictly between the glide's ends.
    let glide: Vec<[f64; 2]> = passes
        .iter()
        .filter(|pass| pass.at_ms >= probe.glide_sent_ms && pass.at_ms < probe.follow_sent_ms)
        .filter_map(|pass| pass.tip)
        .collect();
    let mut between: Vec<[f64; 2]> = glide
        .iter()
        .copied()
        .filter(|tip| *tip != probe.from && *tip != probe.to)
        .collect();
    between.dedup();
    let landed = glide.last().copied();
    let followed = passes
        .iter()
        .filter(|pass| pass.at_ms >= probe.follow_sent_ms && pass.at_ms < probe.hide_sent_ms)
        .filter_map(|pass| pass.tip)
        .next_back();
    let held_at_rest = passes
        .iter()
        .filter(|pass| !pass.frame_wait && pass.activity_held)
        .count();
    let frames_without = passes
        .iter()
        .filter(|pass| pass.frame_wait && !pass.activity_held)
        .count();
    println!(
        "{run}: {} animation frames, interval median {median:.1} ms, p95 {p95:.1} ms, max \
         {max:.1} ms; glide drew {} intermediate positions and landed at {landed:?} (target \
         {:?}); after the follow report the tip was at {followed:?}; {held_at_rest} resting \
         passes held the activity; {frames_without} frame waits ran without it",
        intervals.len(),
        between.len(),
        probe.to,
    );
    if intervals.len() < 20 {
        failures.push(format!(
            "only {} animation frames were drawn",
            intervals.len()
        ));
    }
    // 60 Hz is 16.7 ms. Allow for a loaded machine, but not for the hundreds
    // of milliseconds a throttled helper sees.
    // A NaN (no frames at all) counts as throttled too.
    if p95.is_nan() || p95 > 25.0 {
        failures.push(format!(
            "frames are throttled: p95 interval {p95:.1} ms (median {median:.1} ms)"
        ));
    }
    if between.len() < 8 {
        failures.push(format!(
            "the glide jumped: only {} positions drawn between its ends",
            between.len()
        ));
    }
    if landed != Some(probe.to) {
        failures.push(format!("the glide ended at {landed:?}, not {:?}", probe.to));
    }
    let expected = [
        probe.to[0] + probe.follow_offset[0],
        probe.to[1] + probe.follow_offset[1],
    ];
    if followed != Some(expected) {
        failures.push(format!(
            "a window-follow report moved the tip to {followed:?}, not {expected:?}"
        ));
    }
    if held_at_rest != 0 {
        failures.push(format!(
            "{held_at_rest} passes kept the animation activity while nothing moved"
        ));
    }
    if with_activity && frames_without != 0 {
        failures.push(format!(
            "{frames_without} frame waits ran without the animation activity"
        ));
    }
    if probe.passes.last().is_some_and(|pass| pass.frame_wait) {
        failures.push("the loop was still asking for frames after the hide".into());
    }
    failures
}
