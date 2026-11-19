use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use objc2::MainThreadMarker;
use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop, CFType};

use super::{event_loop, run_cursor_loop, CursorMotion, OverlayMessage, MESSAGE_BUDGET};

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

fn ping(
    run_loop: &CFRunLoop,
    after_ping: impl Fn() + Send + 'static,
) -> Result<Duration, &'static str> {
    let (ping, pong) = mpsc::sync_channel(1);
    let block = block2::RcBlock::new(move || {
        let _ = ping.try_send((MainThreadMarker::new().is_some(), Instant::now()));
        after_ping();
    });
    let started = Instant::now();
    // SAFETY: CF copies the block, its captures can be transferred across
    // threads, and the mode is a process-lifetime constant.
    unsafe {
        let mode = kCFRunLoopDefaultMode.map(|mode| -> &CFType { mode });
        run_loop.perform_block(mode, Some(&block));
    }
    run_loop.wake_up();
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
