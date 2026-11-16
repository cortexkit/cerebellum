use super::*;
use crate::test_support::HANG_GUARD;
use cerebellum_core::clock::{FakeClock, MonoInstant, MonotonicClock};
use cerebellum_core::health::health_check_with_clock;
use std::sync::Mutex;
use subc_protocol::session::HealthStatus;

/// A fake clock shared between the spawned dispatch loop (which stamps the
/// heartbeat by reading it) and the test (which advances it), so both observe
/// the same epoch. They share one `FakeClock` behind an `Arc<Mutex<_>>`;
/// locks are held only for the instant read/advance, never across an await,
/// so the loop and the test cannot deadlock.
///
/// This is a newtype rather than a bare `Arc<Mutex<FakeClock>>` because the
/// `MonotonicClock` trait and `FakeClock` now live in `cerebellum-core`: the
/// orphan rules permit this impl only for a type local to this crate. `Deref`
/// keeps the existing `clock.lock()` call sites working unchanged.
#[derive(Clone)]
struct SharedFakeClock(Arc<Mutex<FakeClock>>);

impl std::ops::Deref for SharedFakeClock {
    type Target = Mutex<FakeClock>;
    fn deref(&self) -> &Mutex<FakeClock> {
        &self.0
    }
}

impl MonotonicClock for SharedFakeClock {
    fn now(&self) -> MonoInstant {
        self.0.lock().unwrap().now()
    }
}

/// A test-controlled idle wake: resolves when the test sends a permit on the
/// channel. When the channel closes (test drops the sender) the wake pends
/// forever rather than busy-resolving, so the loop exits only via the
/// transport (EOF), not a wake storm.
struct TestIdleWake {
    rx: mpsc::UnboundedReceiver<()>,
}

impl IdleWake for TestIdleWake {
    fn next_wake(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            match self.rx.recv().await {
                Some(()) => {}
                None => std::future::pending::<()>().await,
            }
        })
    }
}

/// Poll until the stamped heartbeat reaches `target` (nanoseconds since the
/// fake clock epoch). Reads only the health state's atomic heartbeat, never
/// the clock lock, so it cannot deadlock with the loop's stamping.
async fn wait_for_heartbeat(state: &HealthState, target: Duration) {
    let target_nanos = target.as_nanos() as u64;
    for _ in 0..100_000 {
        if state.heartbeat_instant().as_nanos() >= target_nanos {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("heartbeat did not reach {target:?}");
}

fn test_health_config() -> HealthConfig {
    HealthConfig {
        dispatch_heartbeat_stale_ms: 100,
        queue_age_stale_ms: 30000,
        in_flight_age_stale_ms: 30000,
    }
}

#[tokio::test]
async fn idle_module_stays_healthy_well_past_stale_threshold() {
    // Threshold 100ms; idle for 1000ms (10x) with NO frames, firing a
    // bounded idle wake each step. Before the fix the heartbeat was stamped
    // only per frame, so idling past 100ms reported Degraded. With the
    // bounded idle wake the heartbeat is re-stamped on each wake and the
    // report stays Ok even though cumulative idle time far exceeds the
    // threshold.
    let health_state = Arc::new(HealthState::with_config(test_health_config()));
    let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

    let (writer_io, mut reader_io) = tokio::io::duplex(1024);
    let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
    let mut idle_wake = TestIdleWake { rx: wake_rx };

    // No frames arrive in this test; the handler must never run.
    let handler = |_frame: Frame| -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<bool, ModuleError>> + Send>,
    > { Box::pin(async { panic!("no frame should arrive while idle") }) };

    let loop_health = Arc::clone(&health_state);
    let loop_clock = clock.clone();
    let loop_task = tokio::spawn(async move {
        run_dispatch_loop(
            &mut reader_io,
            &loop_health,
            &loop_clock,
            &mut idle_wake,
            handler,
        )
        .await
    });

    // Idle in 50ms steps for 1000ms. After each wake the heartbeat must be
    // re-stamped at the advanced clock, so the report stays Ok even once the
    // cumulative idle time is far past the 100ms threshold.
    let mut elapsed_ms = 0u64;
    for _ in 0..20 {
        elapsed_ms += 50;
        clock.lock().unwrap().advance(Duration::from_millis(50));
        wake_tx.send(()).unwrap();
        wait_for_heartbeat(&health_state, Duration::from_millis(elapsed_ms)).await;
        let report = health_check_with_clock(&health_state, &*clock.lock().unwrap());
        assert_eq!(
            report.status,
            HealthStatus::Ok,
            "idle module must stay healthy at {elapsed_ms}ms (threshold 100ms)"
        );
    }

    // The heartbeat tracked the clock all the way to 1000ms (10x the
    // threshold), proving each wake re-stamped rather than the heartbeat
    // being frozen at startup.
    assert_eq!(
        health_state.heartbeat_instant().as_nanos(),
        Duration::from_millis(1000).as_nanos() as u64,
        "heartbeat must track the idle wakes to 1000ms"
    );

    // Counterfactual (keeps the test non-vacuous): stop firing wakes and
    // advance past the threshold from the last stamp. The lane must now
    // report Degraded, proving the idle wake — not an always-healthy
    // short-circuit — is what kept it Ok.
    clock.lock().unwrap().advance(Duration::from_millis(200));
    let report = health_check_with_clock(&health_state, &*clock.lock().unwrap());
    assert_eq!(
        report.status,
        HealthStatus::Degraded,
        "without wakes the heartbeat must go stale"
    );

    // Clean shutdown: closing the transport gives the loop a clean EOF.
    drop(writer_io);
    drop(wake_tx);
    loop_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn wedged_handler_lets_heartbeat_go_stale() {
    // The idle wake wraps ONLY the read await, never the handler. A handler
    // that wedges leaves the loop parked past the read with no re-stamp, so
    // the heartbeat ages out and the report honestly goes Degraded — even
    // though idle wakes are available. This proves the fix does not paper
    // over a stuck handler.
    let health_state = Arc::new(HealthState::with_config(test_health_config()));
    let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

    let (mut writer_io, mut reader_io) = tokio::io::duplex(1024);
    let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
    let mut idle_wake = TestIdleWake { rx: wake_rx };

    // Handler that signals it was entered, then wedges forever.
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel::<()>();
    let handler = move |_frame: Frame| {
        let entered_tx = entered_tx.clone();
        async move {
            let _ = entered_tx.send(());
            std::future::pending::<Result<bool, ModuleError>>().await
        }
    };

    let loop_health = Arc::clone(&health_state);
    let loop_clock = clock.clone();
    let loop_task = tokio::spawn(async move {
        run_dispatch_loop(
            &mut reader_io,
            &loop_health,
            &loop_clock,
            &mut idle_wake,
            handler,
        )
        .await
    });

    // Deliver one frame so the loop reads it and enters the wedged handler.
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        1,
        1,
        7,
        b"{}".to_vec(),
    )
    .unwrap();
    write_frame(&mut writer_io, &frame).await.unwrap();

    // Wait until the handler is entered: the loop is now parked in the
    // handler, past the read. The last heartbeat stamp was at the top of
    // that iteration (clock offset 0).
    entered_rx.recv().await.expect("handler must be entered");

    // Advance well past the threshold and fire idle wakes too: with the
    // handler wedged the loop is not in the read select, so the wakes are
    // never processed and never re-stamp. The heartbeat must age out.
    clock.lock().unwrap().advance(Duration::from_millis(500));
    for _ in 0..5 {
        let _ = wake_tx.send(());
        clock.lock().unwrap().advance(Duration::from_millis(100));
    }

    let report = health_check_with_clock(&health_state, &*clock.lock().unwrap());
    assert_eq!(
        report.status,
        HealthStatus::Degraded,
        "a wedged handler must let the heartbeat go stale"
    );
    assert!(
        report.ages.heartbeat_age > Duration::from_millis(100),
        "heartbeat age {:?} must exceed the 100ms threshold",
        report.ages.heartbeat_age
    );

    loop_task.abort();
}

/// Build a frame with a non-trivial body plus its full wire encoding, for
/// the split-frame fence.
fn split_test_frame() -> (Frame, Vec<u8>) {
    let body = b"split-frame-payload-0123456789".to_vec(); // 30 bytes
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        3,
        1,
        99,
        body,
    )
    .unwrap();
    let mut bytes = frame.header.encode().to_vec();
    bytes.extend_from_slice(&frame.body);
    (frame, bytes)
}

/// Drive the split-frame scenario deterministically: write part 1 of the
/// frame, fire two idle wakes (the first ensures part 1 is consumed by the
/// read; the second fires mid-frame), then write part 2. Returns true if the
/// handler recorded the frame, false if the stream was corrupted (the
/// handler was never called). No wall-clock timing drives the result — the
/// 500ms recv timeout is only a hang guard for the corrupted case.
async fn drive_split_frame<W>(
    writer_io: &mut W,
    clock: &Mutex<FakeClock>,
    wake_tx: &mpsc::UnboundedSender<()>,
    health_state: &HealthState,
    done_rx: &mut mpsc::UnboundedReceiver<()>,
    bytes: &[u8],
) -> bool
where
    W: AsyncWrite + Unpin,
{
    let mid = bytes.len() / 2;
    let (part1, part2) = bytes.split_at(mid);

    // Part 1: the read consumes it and awaits the rest.
    writer_io.write_all(part1).await.unwrap();

    // Wake #1: with the read polled first (biased select), this turn reads
    // part 1 into the pinned read before the wake branch re-stamps. Advance
    // the clock so the re-stamp lands at a distinctive instant we can await.
    clock.lock().unwrap().advance(Duration::from_millis(10));
    wake_tx.send(()).unwrap();
    wait_for_heartbeat(health_state, Duration::from_millis(10)).await;

    // Wake #2 fires MID-FRAME: the read holds part 1 but part 2 has not
    // arrived. A pinned read survives this; a dropped-and-recreated read
    // (the timeout shape) loses part 1 here and corrupts the stream.
    clock.lock().unwrap().advance(Duration::from_millis(10));
    wake_tx.send(()).unwrap();
    wait_for_heartbeat(health_state, Duration::from_millis(20)).await;

    // Deliver the rest of the frame.
    writer_io.write_all(part2).await.unwrap();

    // True if the handler recorded the frame; false on timeout (corruption).
    tokio::time::timeout(HANG_GUARD, done_rx.recv())
        .await
        .is_ok()
}

#[tokio::test]
async fn split_frame_across_idle_wake_reassembles_uncorrupted() {
    // Regression fence: a frame whose bytes arrive split across an idle-wake
    // boundary must reassemble uncorrupted and be handled exactly once. The
    // pinned read future preserves partial-read progress across the wake.
    // (A `tokio::time::timeout(read_frame(..))` would drop the mid-frame
    // read and corrupt the stream — see the ignored fail-before variant
    // `split_frame_fail_before_dropped_read_corrupts`.)
    let health_state = Arc::new(HealthState::with_config(test_health_config()));
    let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

    let (mut writer_io, mut reader_io) = tokio::io::duplex(1024);
    let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
    let mut idle_wake = TestIdleWake { rx: wake_rx };

    let handled: Arc<Mutex<Vec<Frame>>> = Arc::new(Mutex::new(Vec::new()));
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
    let handler_handled = Arc::clone(&handled);
    let handler = move |frame: Frame| {
        let handled = Arc::clone(&handler_handled);
        let done_tx = done_tx.clone();
        async move {
            handled.lock().unwrap().push(frame);
            let _ = done_tx.send(());
            Ok::<bool, ModuleError>(true)
        }
    };

    let loop_health = Arc::clone(&health_state);
    let loop_clock = clock.clone();
    let loop_task = tokio::spawn(async move {
        run_dispatch_loop(
            &mut reader_io,
            &loop_health,
            &loop_clock,
            &mut idle_wake,
            handler,
        )
        .await
    });

    let (expected, bytes) = split_test_frame();
    let handled_ok = drive_split_frame(
        &mut writer_io,
        &clock,
        &wake_tx,
        &health_state,
        &mut done_rx,
        &bytes,
    )
    .await;
    assert!(handled_ok, "frame must be handled (stream not corrupted)");

    let handled = handled.lock().unwrap().clone();
    assert_eq!(handled.len(), 1, "frame handled exactly once");
    assert_eq!(handled[0], expected, "frame reassembled uncorrupted");

    drop(writer_io);
    drop(wake_tx);
    loop_task.await.unwrap().unwrap();
}

/// A deliberately-broken variant of [`run_dispatch_loop`] that recreates the
/// read future on every idle wake (what `tokio::time::timeout(read_frame(..))`
/// effectively does, since a timeout drops its inner future on expiry). Used
/// ONLY by the ignored fail-before test to demonstrate that dropping a
/// mid-frame read corrupts the stream.
async fn run_dispatch_loop_drop_read_on_wake<R, C, W, H, Fut>(
    read_half: &mut R,
    health_state: &Arc<HealthState>,
    clock: &C,
    idle_wake: &mut W,
    mut handler: H,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
    C: cerebellum_core::clock::MonotonicClock,
    W: IdleWake,
    H: FnMut(Frame) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ModuleError>>,
{
    health_state.stamp_heartbeat_with_clock(clock);
    loop {
        health_state.stamp_heartbeat_with_clock(clock);
        let frame = loop {
            // The defect being demonstrated: a fresh read future on every
            // wake, so dropping the in-progress read loses any partial
            // frame bytes already consumed.
            let mut read = std::pin::pin!(read_frame(read_half));
            let wake = idle_wake.next_wake();
            tokio::select! {
                biased;
                result = &mut read => {
                    let Some(frame) =
                        result.map_err(|e| ModuleError::Message(e.to_string()))?
                    else {
                        return Ok(());
                    };
                    break frame;
                }
                _ = wake => {
                    health_state.stamp_heartbeat_with_clock(clock);
                    // `read` is dropped here, losing partial frame bytes.
                }
            }
        };
        if !handler(frame).await? {
            return Ok(());
        }
    }
}

/// Fail-before demonstration (ignored by default). This is the SAME scenario
/// and the SAME assertions as
/// [`split_frame_across_idle_wake_reassembles_uncorrupted`], but run against
/// the dropped-read loop above. Un-ignoring it makes it go RED: the mid-frame
/// wake drops the partial read, part 1 is lost, and the stream mis-frames so
/// the frame is never reassembled. That is exactly the regression the
/// pinned-read fence guards against (e.g. a future "simplify to timeout()").
#[ignore = "fail-before fence: goes RED against a dropped-read (timeout-style) loop"]
#[tokio::test]
async fn split_frame_fail_before_dropped_read_corrupts() {
    let health_state = Arc::new(HealthState::with_config(test_health_config()));
    let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

    let (mut writer_io, mut reader_io) = tokio::io::duplex(1024);
    let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
    let mut idle_wake = TestIdleWake { rx: wake_rx };

    let handled: Arc<Mutex<Vec<Frame>>> = Arc::new(Mutex::new(Vec::new()));
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
    let handler_handled = Arc::clone(&handled);
    let handler = move |frame: Frame| {
        let handled = Arc::clone(&handler_handled);
        let done_tx = done_tx.clone();
        async move {
            handled.lock().unwrap().push(frame);
            let _ = done_tx.send(());
            Ok::<bool, ModuleError>(true)
        }
    };

    let loop_health = Arc::clone(&health_state);
    let loop_clock = clock.clone();
    let loop_task = tokio::spawn(async move {
        run_dispatch_loop_drop_read_on_wake(
            &mut reader_io,
            &loop_health,
            &loop_clock,
            &mut idle_wake,
            handler,
        )
        .await
    });

    let (expected, bytes) = split_test_frame();
    let handled_ok = drive_split_frame(
        &mut writer_io,
        &clock,
        &wake_tx,
        &health_state,
        &mut done_rx,
        &bytes,
    )
    .await;
    // Same assertions as the pinned test; they fail here because the
    // dropped-read loop corrupts the split frame.
    assert!(handled_ok, "frame must be handled (stream not corrupted)");
    let handled = handled.lock().unwrap().clone();
    assert_eq!(handled.len(), 1, "frame handled exactly once");
    assert_eq!(handled[0], expected, "frame reassembled uncorrupted");

    drop(writer_io);
    drop(wake_tx);
    let _ = loop_task.await;
}
