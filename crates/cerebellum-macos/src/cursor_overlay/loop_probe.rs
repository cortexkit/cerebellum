use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSEvent, NSEventModifierFlags, NSEventType};
use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop, CFType};
use objc2_foundation::NSPoint;

use super::{
    event_loop, run_agent_cursor, run_cursor_loop, CursorMotion, OverlayMessage, OverlaySender,
    MESSAGE_BUDGET,
};

/// Exercise the helper's real loop without creating a badge or a preview.
/// Returns the independent run-loop ping latency and the time from EOF to exit.
#[doc(hidden)]
pub fn probe_cursor_run_loop(motion: CursorMotion) -> Result<(Duration, Duration), &'static str> {
    let mtm = MainThreadMarker::new().ok_or("the cursor probe must run on the main thread")?;
    let (sender, receiver) =
        event_loop::channel(mtm).ok_or("could not create the cursor channel")?;
    let script = std::thread::spawn(move || {
        let (reply, ready) = mpsc::sync_channel(1);
        sender
            .try_send(OverlayMessage::Ready { reply })
            .map_err(|_| "could not enqueue the readiness barrier")?;
        ready
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "the helper did not become ready")?;

        // Ping on two separate idle turns, without sending a cursor message
        // between them. A single ping can coincide with AppKit flushing the
        // readiness pass before the main thread starts waiting.
        let settle = Duration::from_millis(40);
        let burst_limit = Duration::from_millis(500);
        std::thread::sleep(settle);
        let first_ping = ping(sender.run_loop(), || {})?;
        std::thread::sleep(settle);
        let (release, queued) = mpsc::sync_channel(1);
        let queued = Mutex::new(queued);
        let burst_ping = ping(sender.run_loop(), move || {
            // Keep this run-loop turn open until the whole bounded queue is
            // full, so the source signals coalesce before the main thread can
            // handle any of the messages or their wake.
            if let Ok(queued) = queued.lock() {
                let _ = queued.recv_timeout(burst_limit);
            }
        })?;

        let (reply, answers) = mpsc::sync_channel(MESSAGE_BUDGET + 1);
        for _ in 0..MESSAGE_BUDGET {
            sender
                .try_send(OverlayMessage::Ready {
                    reply: reply.clone(),
                })
                .map_err(|_| "the bounded burst did not fit in the queue")?;
        }
        let _ = release.try_send(());
        // Also cross the main thread's per-pass drain bound.
        sender
            .send(OverlayMessage::Ready { reply })
            .map_err(|_| "the helper stopped during the burst")?;
        let burst_deadline = Instant::now() + burst_limit;
        for _ in 0..=MESSAGE_BUDGET {
            answers
                .recv_timeout(burst_deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| "the helper did not acknowledge the whole burst")?;
        }

        std::thread::sleep(settle);
        let eof = Instant::now();
        drop(sender);
        Ok((first_ping.max(burst_ping), eof))
    });
    run_cursor_loop(mtm, receiver, motion, None);
    let stopped = Instant::now();
    let (ping, eof) = script
        .join()
        .map_err(|_| "the cursor probe thread panicked")??;
    let exit = stopped
        .checked_duration_since(eof)
        .ok_or("the loop stopped before EOF")?;
    if exit > Duration::from_millis(500) {
        return Err("the idle main run loop did not wake promptly on EOF");
    }
    Ok((ping, exit))
}

/// Measure the main-thread service time under load for the helper's 50 ms
/// query for the window that would receive a mouse-down at a point. Measure
/// from enqueueing `PointerWindow` to receiving the real AppKit hit-test reply.
/// This bypasses the subprocess pipes, so it does not check whether the client
/// matches replies to request IDs or discards stale replies.
#[doc(hidden)]
pub fn probe_cursor_recipient_load(motion: CursorMotion) -> Result<Vec<Duration>, String> {
    let (report, result) = mpsc::sync_channel(1);
    run_agent_cursor(
        move |sender| {
            let _ = report.send(loaded_queries(&sender));
        },
        motion,
    );
    result
        .recv()
        .map_err(|_| "the cursor helper stopped without a load report")?
}

fn loaded_queries(sender: &OverlaySender) -> Result<Vec<Duration>, String> {
    const QUERIES: usize = 100;
    // The pipe client's QUERY_TIMEOUT lives in cerebellum-computer, which
    // depends on this crate; keep the same cap for the typed replies here.
    const QUERY_TIMEOUT: Duration = Duration::from_millis(50);
    const LOAD_TIMEOUT: Duration = Duration::from_millis(500);
    const FLOOD_MESSAGES: usize = 2 * MESSAGE_BUDGET - 1;

    let (reply, ready) = mpsc::sync_channel(1);
    sender
        .try_send(OverlayMessage::Ready { reply })
        .map_err(|_| "could not enqueue the readiness barrier")?;
    ready
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "the helper did not become ready")?;

    let mut latencies = Vec::with_capacity(QUERIES);
    for query in 1..=QUERIES {
        // Fill the queue while AppKit has the turn, so the measured query
        // occupies its last slot, not a slot that happened to be empty.
        let release = hold_appkit_turn(sender.run_loop(), LOAD_TIMEOUT)?;
        let (flood_reply, flood_acks) = mpsc::sync_channel(FLOOD_MESSAGES);
        let flood = || OverlayMessage::Ready {
            reply: flood_reply.clone(),
        };
        for _ in 1..MESSAGE_BUDGET {
            sender
                .try_send(flood())
                .map_err(|_| "could not fill the overlay queue ahead of the query")?;
        }

        // A reply with no window still proves that the hit test completed.
        let (reply, answer) = mpsc::sync_channel(1);
        let started = Instant::now();
        sender
            .try_send(OverlayMessage::PointerWindow {
                point: [0.0, 0.0],
                reply,
            })
            .map_err(|_| "could not enqueue the recipient query in the last slot")?;
        drop(release);
        let query_deadline = started + QUERY_TIMEOUT;
        let load_deadline = started + LOAD_TIMEOUT;
        let timeout = || format!("query {query}: no recipient reply within {QUERY_TIMEOUT:?}");

        // Keep feeding the queue as slots open for another full batch. Ready
        // messages exercise the overlay queue without drawing any windows.
        let mut elapsed = None;
        let mut sent = 0;
        while sent < MESSAGE_BUDGET {
            if elapsed.is_none() {
                match answer.try_recv() {
                    Ok(_) => elapsed = Some(started.elapsed()),
                    Err(mpsc::TryRecvError::Empty) if Instant::now() < query_deadline => {}
                    Err(mpsc::TryRecvError::Empty) => return Err(timeout()),
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err(format!("query {query}: recipient reply channel closed"));
                    }
                }
            }
            if Instant::now() >= load_deadline {
                return Err(format!("query {query}: could not refill the overlay queue"));
            }
            match sender.try_send(flood()) {
                Ok(()) => sent += 1,
                Err(mpsc::TrySendError::Full(_)) => std::thread::yield_now(),
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err("the helper stopped during the flood".into());
                }
            }
        }
        let latency = match elapsed {
            Some(elapsed) => elapsed,
            None => {
                answer
                    .recv_timeout(query_deadline.saturating_duration_since(Instant::now()))
                    .map_err(|error| match error {
                        mpsc::RecvTimeoutError::Timeout => timeout(),
                        mpsc::RecvTimeoutError::Disconnected => {
                            format!("query {query}: recipient reply channel closed")
                        }
                    })?;
                started.elapsed()
            }
        };
        latencies.push(latency);
        for _ in 0..FLOOD_MESSAGES {
            flood_acks
                .recv_timeout(load_deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| format!("query {query}: the helper did not drain the flood"))?;
        }
    }
    Ok(latencies)
}

fn hold_appkit_turn(
    run_loop: &CFRunLoop,
    limit: Duration,
) -> Result<mpsc::SyncSender<()>, &'static str> {
    let (posted, event) = mpsc::sync_channel(1);
    let (release, queued) = mpsc::sync_channel(1);
    let queued = Mutex::new(queued);
    on_run_loop(run_loop, move || {
        let _ = posted.try_send(post_load_event());
        if let Ok(queued) = queued.lock() {
            let _ = queued.recv_timeout(limit);
        }
    });
    if event.recv_timeout(limit) != Ok(true) {
        return Err("the main run loop did not post the application-defined event");
    }
    Ok(release)
}

fn post_load_event() -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    let event = NSEvent::otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2(
        NSEventType::ApplicationDefined,
        NSPoint::ZERO,
        NSEventModifierFlags::empty(),
        0.0,
        0,
        None,
        0x434c, // Distinct from the overlay wake event.
        0,
        0,
    );
    let Some(event) = event else { return false };
    // Put app-local work in front of the overlay wake, without posting input
    // or touching any window.
    NSApplication::sharedApplication(mtm).postEvent_atStart(&event, true);
    true
}

fn on_run_loop(run_loop: &CFRunLoop, callback: impl Fn() + Send + 'static) {
    let block = block2::RcBlock::new(callback);
    // SAFETY: CF copies the block, its captures can be transferred across
    // threads, and the mode is a process-lifetime constant.
    unsafe {
        let mode = kCFRunLoopDefaultMode.map(|mode| -> &CFType { mode });
        run_loop.perform_block(mode, Some(&block));
    }
    run_loop.wake_up();
}

fn ping(
    run_loop: &CFRunLoop,
    after_ping: impl Fn() + Send + 'static,
) -> Result<Duration, &'static str> {
    let (ping, pong) = mpsc::sync_channel(1);
    let started = Instant::now();
    on_run_loop(run_loop, move || {
        let _ = ping.try_send((MainThreadMarker::new().is_some(), Instant::now()));
        after_ping();
    });
    let limit = Duration::from_millis(100);
    let (on_main, answered) = pong
        .recv_timeout(limit)
        .map_err(|_| "the idle main run loop did not answer within 100 ms")?;
    let latency = answered.duration_since(started);
    if !on_main || latency > limit {
        return Err("the run-loop ping did not execute on the main thread within 100 ms");
    }
    Ok(latency)
}
