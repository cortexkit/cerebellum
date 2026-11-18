//! The hard cutoff against a restore history that understates the real
//! restore: a file at the smallest believable restore cost lets a shortcut
//! skip calibration and be admitted, while the person's application is in
//! fact slow to come back. The cutoff, armed on the absolute bound, must
//! still stop the shortcut's key press and request the restore by the bound,
//! in real time, whatever the file said.

use super::*;
use crate::dispatch::{
    BracketPlan, CutoffGate, FrontedKeyChecks, FrontingBracketHost, HardwareInputSnapshot,
    HeartbeatMarker, HeartbeatObservation, HeartbeatProbe, ObservedUnit, RestorePredictor,
    RestoreStatus, SeizeWatcher, SourcedInputEvent, UnitPosted, UserIdleEstimator,
    OBSERVED_DISPATCH_IDLE_MS,
};
use crate::platform::{
    post_event_sequence_fronted, PerProcessEventTransport, PostCallFailure, PostCallMade,
    ProcessEventTarget, ProcessGenerationReading, SyntheticStep, SyntheticStepRole, VisibilityMemo,
    WindowServerVisibility,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PREVIOUS: u32 = 100;
const TARGET: u32 = 200;
const OUR_PID: i64 = 7;
const GENERATION: u64 = 42;
/// The bracket's bound, in real milliseconds.
const BOUND_MS: u64 = 200;
/// The window server's listing of the target, read before the key press,
/// takes longer than the whole bound.
const LISTING_MS: u64 = 250;
/// The person's application takes this long to come back once asked.
const SLOW_RESTORE_MS: u64 = 150;
/// What scheduling on a busy test machine may add to a real-time deadline.
const SLACK_MS: u64 = 40;

/// What the test watches, in real time.
#[derive(Default)]
struct Desk {
    frontmost: Option<u32>,
    /// Key events posted to the target, with when.
    posted: Vec<(&'static str, Instant)>,
    /// When the previous application was asked back.
    restore_requested_at: Vec<Instant>,
}

type Shared = Arc<Mutex<Desk>>;

fn desk(shared: &Shared) -> std::sync::MutexGuard<'_, Desk> {
    shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The person's application, slow to come back.
struct SlowRestorer {
    shared: Shared,
    started: Instant,
}

impl FrontingRestoreHost for SlowRestorer {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        std::thread::sleep(Duration::from_millis(milliseconds));
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        desk(&self.shared).frontmost
    }
    fn request_front(&mut self, pid: u32) -> bool {
        desk(&self.shared).restore_requested_at.push(Instant::now());
        std::thread::sleep(Duration::from_millis(SLOW_RESTORE_MS));
        desk(&self.shared).frontmost = Some(pid);
        true
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        Some(HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: None,
        })
    }
}

/// The target's keyboard: a slow listing read, then the posts.
struct Keyboard(Shared);

impl PerProcessEventTransport for Keyboard {
    type Event = &'static str;
    fn process_generation(&mut self, _pid: u32) -> ProcessGenerationReading {
        ProcessGenerationReading::Started(GENERATION)
    }
    fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
        std::thread::sleep(Duration::from_millis(LISTING_MS));
        WindowServerVisibility::Visible
    }
    fn post_to_pid(
        &mut self,
        _pid: u32,
        event: &'static str,
    ) -> Result<PostCallMade, PostCallFailure> {
        desk(&self.0).posted.push((event, Instant::now()));
        Ok(PostCallMade::public_core_graphics())
    }
}

/// The macOS keystroke host's shape: real time, and a shortcut posted
/// through the per-post checks with the bracket's cutoff.
struct ShortcutHost {
    shared: Shared,
    started: Instant,
}

impl RestoreHostSource for ShortcutHost {
    fn restore_host(&self) -> Box<dyn FrontingRestoreHost> {
        Box::new(SlowRestorer {
            shared: Arc::clone(&self.shared),
            started: self.started,
        })
    }
    fn supports_needs_front_restore_predictor(&self) -> bool {
        true
    }
}

impl FrontingBracketHost for ShortcutHost {
    type Tap = ();
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        std::thread::sleep(Duration::from_millis(milliseconds));
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        desk(&self.shared).frontmost
    }
    fn request_front(&mut self, pid: u32) -> bool {
        desk(&self.shared).frontmost = Some(pid);
        true
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn create_tap(&mut self) -> Option<()> {
        Some(())
    }
    fn read_idle(&mut self) -> IdleReading {
        IdleReading::Milliseconds(OBSERVED_DISPATCH_IDLE_MS + 500)
    }
    fn drain(&mut self, _tap: &()) -> Vec<SourcedInputEvent> {
        Vec::new()
    }
    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        HeartbeatProbe {
            marker: HeartbeatMarker::new(1),
            posted_at_ms: self.now_ms(),
            our_pid: OUR_PID,
        }
    }
    fn observe_heartbeat(
        &mut self,
        _tap: &(),
        probe: HeartbeatProbe,
        _watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        HeartbeatObservation::Seen {
            marker: probe.marker,
            source_unix_process_id: OUR_PID,
            observed_at_ms: probe.posted_at_ms,
        }
    }
    fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
        unreachable!("the shortcut is posted only through its per-post checks")
    }
    fn post_observed_unit(
        &mut self,
        _index: usize,
        observation: ObservedUnit<'_, ()>,
    ) -> Result<UnitPosted, SequencePostFailure> {
        let started = self.started;
        let shared = Arc::clone(&self.shared);
        let mut checks = FrontedKeyChecks {
            target_pid: TARGET,
            deadline_ms: observation.deadline_ms,
            now_ms: || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            frontmost_pid: || desk(&shared).frontmost,
            cutoff: observation.cutoff,
        };
        let report = post_event_sequence_fronted(
            ProcessEventTarget {
                pid: TARGET,
                start_time_micros: GENERATION,
            },
            vec![
                SyntheticStep {
                    role: SyntheticStepRole::Press,
                    event: "command+k down",
                },
                SyntheticStep {
                    role: SyntheticStepRole::Release,
                    event: "command+k up",
                },
            ],
            &mut Keyboard(Arc::clone(&self.shared)),
            &mut VisibilityMemo::uncached(),
            observation.cancelled,
            &mut checks,
        )?;
        Ok(UnitPosted {
            posts_returned: report.posts_returned,
            generation_verifications: report.generation_verifications,
        })
    }
    fn unit_checks_cutoff(&self) -> bool {
        true
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        Some(HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: None,
        })
    }
}

/// Hooks whose one restore decision the cutoff's timer and the bracket
/// share, as a call's `RestoreCell` does in the module.
#[derive(Default)]
struct Decision {
    host: Option<Box<dyn FrontingRestoreHost>>,
    previous: Option<u32>,
    decided: bool,
    cutoff: Option<Arc<CutoffGate>>,
}

#[derive(Clone, Default)]
struct Hooks(Arc<Mutex<Decision>>);

impl Hooks {
    fn decide(&self) -> HookedRestore {
        let mut decision = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !decision.decided {
            decision.decided = true;
            let previous = decision.previous;
            if let (Some(host), Some(previous)) = (decision.host.as_mut(), previous) {
                host.request_front(previous);
            }
        }
        HookedRestore {
            restore: RestoreStatus::Restored,
            person_input_during_fronting: false,
            input_coverage_unavailable: false,
            restore_ms: None,
        }
    }
}

impl FrontedDispatchHooks for Hooks {
    fn uses_needs_front_restore_predictor(&self) -> bool {
        true
    }
    fn register(
        &mut self,
        previous: u32,
        _target: u32,
        host: Box<dyn FrontingRestoreHost>,
    ) -> bool {
        let mut decision = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        decision.previous = Some(previous);
        decision.host = Some(host);
        true
    }
    fn begin_front_attempt(&mut self, _front_instant_ms: u64) -> bool {
        true
    }
    fn front_attempt_returned(&mut self) {}
    fn decide_restore(&mut self) -> HookedRestore {
        self.decide()
    }
    fn cutoff_restore(&mut self) -> Option<Box<dyn FnOnce() + Send>> {
        let hooks = self.clone();
        Some(Box::new(move || {
            hooks.decide();
        }))
    }
    fn cutoff_armed(&mut self, gate: Arc<CutoffGate>) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cutoff = Some(gate);
    }
    fn finished(&mut self, _outcome: &crate::dispatch::BracketOutcome) {}
}

/// A history at the smallest restore cost the module believes, measured now.
struct FloorHistory(std::path::PathBuf);

impl FloorHistory {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ck-hooked-cutoff-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let path = dir.join("cortexkit/cerebellum/restore-latency/samples.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        std::fs::write(
            &path,
            format!("{{\"version\":2,\"samples\":[{{\"ms\":40,\"at_unix_ms\":{now}}}]}}"),
        )
        .unwrap();
        Self(dir)
    }
}

impl Drop for FloorHistory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_picture_capture_leaves_shared_idle_history_unlocked() {
    let idle = Mutex::new(UserIdleEstimator::new());
    let history = FloorHistory::new();
    let predictor = RestorePredictor::open_for_test(&history.0);
    let shared = Arc::new(Mutex::new(Desk {
        frontmost: Some(PREVIOUS),
        ..Desk::default()
    }));
    let mut read_ran = false;
    let outcome = run_hooked_fronted_with_predictor(
        &mut ShortcutHost {
            shared,
            started: Instant::now(),
        },
        crate::dispatch::BracketIdle::Shared(&idle),
        BracketPlan {
            target_pid: TARGET,
            units: 1,
            maximum_interval_ms: BOUND_MS,
            maximum_seize_detection_latency_ms: 50,
        },
        &|| false,
        &mut Hooks::default(),
        Some(&mut || {
            read_ran = true;
            assert!(
                idle.try_lock().is_ok(),
                "native capture must not hold idle history"
            );
        }),
        Some(&predictor),
    );
    assert!(read_ran, "{:?}", outcome.report);
}

#[test]
fn a_shortcut_admitted_on_a_floor_history_is_cut_off_at_the_bound_however_slow_the_restore() {
    let history = FloorHistory::new();
    let predictor = RestorePredictor::open_for_test(&history.0);
    let shared: Shared = Arc::new(Mutex::new(Desk {
        frontmost: Some(PREVIOUS),
        ..Desk::default()
    }));
    let mut hooks = Hooks::default();
    let started = Instant::now();
    let outcome = run_hooked_fronted_with_predictor(
        &mut ShortcutHost {
            shared: Arc::clone(&shared),
            started,
        },
        &mut UserIdleEstimator::new(),
        BracketPlan {
            target_pid: TARGET,
            units: 1,
            maximum_interval_ms: BOUND_MS,
            maximum_seize_detection_latency_ms: 50,
        },
        &|| false,
        &mut hooks,
        None,
        Some(&predictor),
    );
    let desk = desk(&shared);
    // Admitted on the file's word: the target was fronted without first
    // calibrating, so the shortcut was really attempted.
    assert_eq!(outcome.report.chunks, 1, "{:?}", outcome.report);
    assert!(!outcome.report.restore_calibrated);
    // The key press came after the slow listing read, past the bound: the
    // cutoff refused it, and nothing at all was posted.
    assert!(
        desk.posted.is_empty(),
        "posted after the cutoff: {:?}",
        desk.posted
    );
    assert_eq!(outcome.report.units_posted, 0);
    // The restore was requested by the bound, not after the slow read.
    let requested = desk
        .restore_requested_at
        .first()
        .map(|at| at.saturating_duration_since(started))
        .expect("the previous application was asked back");
    assert!(
        requested < Duration::from_millis(BOUND_MS + SLACK_MS),
        "restore requested {requested:?} after the bracket began"
    );
    assert_eq!(desk.restore_requested_at.len(), 1, "one restore request");
    assert!(outcome.report.restore_started_by_cutoff);
}
