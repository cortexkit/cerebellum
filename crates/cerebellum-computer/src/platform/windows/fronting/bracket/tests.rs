use super::*;
use crate::dispatch::{BracketOutcome, CutoffGate, HeartbeatMarker, OBSERVED_DISPATCH_IDLE_MS};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const ORIGINAL: u32 = 1;
const TARGET: u32 = 2;
const SIBLING: u32 = 3;

struct Screen {
    front: Option<u32>,
    desktop_safe: bool,
    original_safe: bool,
    original_present: bool,
    deny_front: bool,
    accept_without_move: bool,
    deny_restore: bool,
    activate_after_ms: u64,
    writes: Vec<u32>,
    foreground_reads: usize,
}

impl Default for Screen {
    fn default() -> Self {
        Self {
            front: Some(ORIGINAL),
            desktop_safe: true,
            original_safe: true,
            original_present: true,
            deny_front: false,
            accept_without_move: false,
            deny_restore: false,
            activate_after_ms: 0,
            writes: Vec::new(),
            foreground_reads: 0,
        }
    }
}

struct Desk {
    screen: Mutex<Screen>,
    start: Instant,
}

impl Desktop for Desk {
    type Window = u32;

    fn now(&self) -> u64 {
        crate::fronting_clock::now()
            .duration_since(self.start)
            .as_millis() as u64
    }
    fn pause(&self, ms: u64) {
        assert!(crate::fronting_clock::advance(Duration::from_millis(ms)));
    }
    fn safe(&self) -> bool {
        self.screen.lock().unwrap().desktop_safe
    }
    fn foreground(&self) -> Option<u32> {
        let mut screen = self.screen.lock().unwrap();
        screen.foreground_reads += 1;
        screen.front
    }
    fn bind(&self, number: u32) -> Option<u32> {
        Some(number)
    }
    fn number(&self, window: &u32) -> u32 {
        *window
    }
    fn pid(&self, window: &u32) -> u32 {
        if *window == ORIGINAL {
            10
        } else {
            20
        }
    }
    fn current(&self, window: &u32) -> bool {
        *window != ORIGINAL || self.screen.lock().unwrap().original_present
    }
    fn safe_integrity(&self, window: &u32) -> bool {
        *window != ORIGINAL || self.screen.lock().unwrap().original_safe
    }
    fn activate(&self, window: &u32) -> bool {
        let mut screen = self.screen.lock().unwrap();
        screen.writes.push(*window);
        if (*window == TARGET && screen.deny_front) || (*window == ORIGINAL && screen.deny_restore)
        {
            return false;
        }
        if *window == TARGET {
            if screen.accept_without_move {
                return true;
            }
            self.pause(screen.activate_after_ms);
        }
        screen.front = Some(*window);
        true
    }
}

#[derive(Default)]
struct Echo(AtomicUsize);

impl Observer for Echo {
    fn idle(&self) -> IdleReading {
        IdleReading::Milliseconds(OBSERVED_DISPATCH_IDLE_MS + 1)
    }
    fn drain(&self) -> Vec<SourcedInputEvent> {
        Vec::new()
    }
    fn probe(&self) -> HeartbeatProbe {
        self.0.fetch_add(1, Ordering::Relaxed);
        HeartbeatProbe {
            marker: HeartbeatMarker::new(1),
            posted_at_ms: 0,
            our_pid: i64::from(std::process::id()),
        }
    }
    fn echo(&self, probe: HeartbeatProbe, _: &mut SeizeWatcher) -> HeartbeatObservation {
        HeartbeatObservation::Seen {
            marker: probe.marker,
            source_unix_process_id: probe.our_pid,
            observed_at_ms: probe.posted_at_ms,
        }
    }
    fn snapshot(&self) -> Option<HardwareInputSnapshot> {
        Some(HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: None,
        })
    }
}

#[derive(Default)]
struct Hooks {
    restore: Option<(u32, u32, Box<dyn FrontingRestoreHost>)>,
    finished: Option<BracketReport>,
    denied: bool,
}

impl FrontedDispatchHooks for Hooks {
    fn prepare_next_windows_piece(&mut self) -> bool {
        self.restore.is_none()
            && self
                .finished
                .as_ref()
                .is_some_and(|report| report.restore == RestoreStatus::Restored)
    }

    fn register(
        &mut self,
        previous: u32,
        target: u32,
        mut host: Box<dyn FrontingRestoreHost>,
        _: &Arc<CutoffGate>,
    ) -> bool {
        assert!(host.remember_previous(previous));
        self.restore = Some((previous, target, host));
        true
    }
    fn restore_reserve_ms(&self) -> Option<u64> {
        Some(50)
    }
    fn begin_front_attempt(&mut self, _: u64) -> bool {
        true
    }
    fn front_attempt_returned(&mut self) {}
    fn front_attempt_denied(&mut self) {
        self.denied = true;
    }
    fn decide_restore(&mut self) -> HookedRestore {
        let (previous, target, mut host) = self.restore.take().unwrap();
        let status = match host.frontmost_pid() {
            Some(pid) if pid == previous && self.denied => RestoreStatus::NotNeeded,
            Some(pid) if pid == previous => RestoreStatus::Failed {
                left_in_front: Some(pid),
            },
            Some(pid) if pid == target => {
                if host.request_front(previous) && host.frontmost_pid() == Some(previous) {
                    RestoreStatus::Restored
                } else {
                    RestoreStatus::Failed {
                        left_in_front: host.frontmost_pid(),
                    }
                }
            }
            now_front => RestoreStatus::SkippedPerson { now_front },
        };
        HookedRestore {
            restore: status,
            person_input_during_fronting: false,
            input_coverage_unavailable: false,
            restore_ms: None,
        }
    }
    fn forgo_restore(&mut self) {
        panic!("picture holds no input");
    }
    fn finished(&mut self, outcome: &BracketOutcome) {
        self.finished = Some(outcome.report.clone());
    }
}

fn scripted_pieces(deny_restore: bool, cancel_after_one: bool) -> (BracketReport, Vec<u32>) {
    crate::fronting_clock::FakeClock::frozen().run(|| {
        let desk = Arc::new(Desk {
            screen: Mutex::new(Screen {
                deny_restore,
                ..Screen::default()
            }),
            start: crate::fronting_clock::now(),
        });
        let observer = Arc::new(Echo::default());
        let sent = std::cell::Cell::new(0);
        let report = run_pieces(
            3,
            &mut Hooks::default(),
            || (cancel_after_one && sent.get() == 1).then_some(BracketStop::Cancelled),
            |index, hooks| {
                assert_eq!(
                    desk.screen.lock().unwrap().front,
                    Some(ORIGINAL),
                    "piece {index} starts after restore"
                );
                run(
                    Arc::clone(&desk),
                    || Ok(TARGET),
                    Some(observer.clone()),
                    BracketPlan {
                        target_pid: desk.pid(&TARGET),
                        units: 1,
                        maximum_interval_ms: 300,
                        maximum_seize_detection_latency_ms: 50,
                    },
                    hooks,
                    &|| false,
                    Work::Dispatch(&mut |_, _| {
                        assert_eq!(desk.screen.lock().unwrap().front, Some(TARGET));
                        sent.set(sent.get() + 1);
                        Ok(UnitPosted {
                            posts_returned: 2,
                            generation_verifications: 2,
                        })
                    }),
                )
            },
        )
        .unwrap();
        let writes = desk.screen.lock().unwrap().writes.clone();
        (report, writes)
    })
}

#[test]
fn windows_each_piece_fronts_only_after_the_previous_piece_restored() {
    let (report, writes) = scripted_pieces(false, false);
    assert_eq!(
        writes,
        [TARGET, ORIGINAL, TARGET, ORIGINAL, TARGET, ORIGINAL]
    );
    assert_eq!(report.units_posted, 3);
    assert_eq!(report.stop, None);
}

#[test]
fn windows_failed_restore_names_the_pieces_sent_and_prevents_another_front() {
    let (report, writes) = scripted_pieces(true, false);
    assert_eq!(writes, [TARGET, ORIGINAL]);
    assert_eq!(report.units_posted, 1);
    assert_eq!(report.posts_returned, 2);
    assert_eq!(report.stop, Some(BracketStop::RestoreFailed));
}

#[test]
fn windows_cancel_between_pieces_sends_nothing_more() {
    let (report, writes) = scripted_pieces(false, true);
    assert_eq!(writes, [TARGET, ORIGINAL]);
    assert_eq!(report.units_posted, 1);
    assert_eq!(report.stop, Some(BracketStop::Cancelled));
}

fn picture(
    screen: Screen,
    observer: Option<Arc<dyn Observer>>,
    read: impl FnOnce(&Desk),
) -> (BracketReport, Arc<Desk>) {
    crate::fronting_clock::FakeClock::frozen().run(|| {
        let desk = Arc::new(Desk {
            screen: Mutex::new(screen),
            start: crate::fronting_clock::now(),
        });
        let mut hooks = Hooks::default();
        let mut read = Some(read);
        let report = run(
            Arc::clone(&desk),
            || Ok(TARGET),
            observer,
            BracketPlan {
                target_pid: desk.pid(&TARGET),
                units: 1,
                maximum_interval_ms: 300,
                maximum_seize_detection_latency_ms: 50,
            },
            &mut hooks,
            &|| false,
            Work::Read(&mut |window| {
                assert_eq!(*window, TARGET);
                (read.take().expect("only one picture"))(&desk);
            }),
        )
        .unwrap();
        assert_eq!(hooks.finished, Some(report.clone()));
        (report, desk)
    })
}

#[test]
fn observer_absence_refuses_before_desktop_reads_or_writes() {
    let (report, desk) = picture(Screen::default(), None, |_| panic!("read without observer"));
    assert_eq!(report.stop, Some(BracketStop::ObserverUnavailable));
    let screen = desk.screen.lock().unwrap();
    assert_eq!(screen.foreground_reads, 0);
    assert!(screen.writes.is_empty());
}

#[test]
fn a_keyboard_probe_without_mouse_echo_refuses_before_front_or_payload() {
    crate::fronting_clock::FakeClock::frozen().run(|| {
        let desk = Arc::new(Desk {
            screen: Mutex::new(Screen::default()),
            start: crate::fronting_clock::now(),
        });
        let probes = Arc::new(AtomicUsize::new(0));
        let observer = NativeObserver::keyboard_only_probe_for_test(Arc::clone(&probes));
        let report = run(
            Arc::clone(&desk),
            || Ok(TARGET),
            Some(observer.clone()),
            BracketPlan {
                target_pid: desk.pid(&TARGET),
                units: 1,
                maximum_interval_ms: 300,
                maximum_seize_detection_latency_ms: 50,
            },
            &mut Hooks::default(),
            &|| false,
            Work::Dispatch(&mut |_, _| panic!("keyboard echo alone admitted payload")),
        )
        .unwrap();
        assert!(matches!(
            report.stop,
            Some(BracketStop::Aborted(abort))
                if abort.reason == crate::dispatch::AbortReason::ObserverUnavailable
        ));
        assert_eq!(
            probes.load(Ordering::Relaxed),
            2,
            "the original probe pair was posted once"
        );
        assert!(
            observer.lost(),
            "a keyboard echo alone cannot prove both hooks live"
        );
        assert_eq!(report.posts_returned, 0, "no payload was posted");
        assert_eq!(report.restore, RestoreStatus::NotNeeded);
        assert!(
            desk.screen.lock().unwrap().writes.is_empty(),
            "no front was requested"
        );
    });
}

#[test]
fn previous_window_missing_or_a_same_pid_sibling_refuses_without_probes() {
    for front in [None, Some(SIBLING)] {
        let echo = Arc::new(Echo::default());
        let (report, desk) = picture(
            Screen {
                front,
                ..Screen::default()
            },
            Some(echo.clone()),
            |_| panic!("unbound previous"),
        );
        assert_eq!(report.stop, Some(BracketStop::PreviousUnknown));
        assert_eq!(report.restore, RestoreStatus::NotNeeded);
        assert_eq!(echo.0.load(Ordering::Relaxed), 0);
        assert!(desk.screen.lock().unwrap().writes.is_empty());
    }
}

#[test]
fn non_default_desktop_or_unreadable_foreground_integrity_sends_no_probes() {
    for screen in [
        Screen {
            desktop_safe: false,
            ..Screen::default()
        },
        Screen {
            original_safe: false,
            ..Screen::default()
        },
    ] {
        let echo = Arc::new(Echo::default());
        let (report, desk) = picture(screen, Some(echo.clone()), |_| panic!("unsafe foreground"));
        assert_eq!(report.stop, Some(BracketStop::ObserverUnavailable));
        assert_eq!(echo.0.load(Ordering::Relaxed), 0);
        assert!(desk.screen.lock().unwrap().writes.is_empty());
    }
}

#[test]
fn bounded_picture_restores_the_exact_original_window_once() {
    let (report, desk) = picture(Screen::default(), Some(Arc::new(Echo::default())), |desk| {
        assert_eq!(desk.foreground(), Some(TARGET));
        desk.pause(10);
    });
    assert!(report.held(300), "{report:?}");
    assert_eq!(report.longest_fronted_interval_ms, 10);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.screen.lock().unwrap().writes, [TARGET, ORIGINAL]);
}

#[test]
fn activation_denial_never_runs_the_picture() {
    let (report, desk) = picture(
        Screen {
            deny_front: true,
            ..Screen::default()
        },
        Some(Arc::new(Echo::default())),
        |_| panic!("denied activation"),
    );
    assert_eq!(report.stop, Some(BracketStop::FrontFailed));
    assert_eq!(report.restore, RestoreStatus::NotNeeded);
    assert_eq!(desk.screen.lock().unwrap().writes, [TARGET]);
}

#[test]
fn accepted_but_unconfirmed_activation_is_not_the_definitive_denial() {
    let (report, desk) = picture(
        Screen {
            accept_without_move: true,
            ..Screen::default()
        },
        Some(Arc::new(Echo::default())),
        |_| panic!("unconfirmed activation"),
    );
    assert_eq!(report.stop, Some(BracketStop::FrontFailed));
    assert_eq!(
        report.restore,
        RestoreStatus::Failed {
            left_in_front: Some(10)
        }
    );
    assert_eq!(desk.screen.lock().unwrap().writes, [TARGET]);
}

#[test]
fn late_activation_or_stalled_picture_is_not_certified_and_restores_once() {
    for activate_after_ms in [0, 301] {
        let (report, desk) = picture(
            Screen {
                activate_after_ms,
                ..Screen::default()
            },
            Some(Arc::new(Echo::default())),
            |desk| {
                assert_eq!(
                    activate_after_ms, 0,
                    "late activation must not start the picture"
                );
                desk.pause(301);
            },
        );
        assert!(!report.held(300), "{report:?}");
        assert!(report.longest_fronted_interval_ms > 300, "{report:?}");
        assert_eq!(report.restore, RestoreStatus::Restored);
        assert_eq!(desk.screen.lock().unwrap().writes, [TARGET, ORIGINAL]);
    }
}

#[test]
fn a_third_window_is_not_restored_over_even_if_it_shares_the_targets_pid() {
    let (report, desk) = picture(Screen::default(), Some(Arc::new(Echo::default())), |desk| {
        desk.screen.lock().unwrap().front = Some(SIBLING);
    });
    assert_eq!(
        report.restore,
        RestoreStatus::SkippedPerson { now_front: None }
    );
    assert_eq!(desk.screen.lock().unwrap().writes, [TARGET]);
}

#[test]
fn a_vanished_original_or_denied_restore_fails_without_retry() {
    for deny_restore in [false, true] {
        let (report, desk) = picture(
            Screen {
                deny_restore,
                ..Screen::default()
            },
            Some(Arc::new(Echo::default())),
            |desk| {
                desk.screen.lock().unwrap().original_present = deny_restore;
            },
        );
        assert!(matches!(report.restore, RestoreStatus::Failed { .. }));
        let screen = desk.screen.lock().unwrap();
        assert_eq!(screen.front, Some(TARGET));
        assert_eq!(
            screen
                .writes
                .iter()
                .filter(|&&number| number == ORIGINAL)
                .count(),
            usize::from(deny_restore)
        );
    }
}

#[test]
fn native_read_and_dispatch_require_the_observer_and_consume_hooks_once() {
    let mut driver = WindowsPlatformDriver::default();
    let target = ProcessGrant {
        pid: 0,
        bundle_identity: "no desktop access".into(),
        process_generation_evidence: "unreadable".into(),
    };
    assert!(driver.accept_fronted_dispatch_hooks(Box::new(Hooks::default())));
    let report = driver
        .read_fronted(&target, 300, &|| false, &mut || {
            panic!("read without observer")
        })
        .unwrap();
    assert_eq!(report.stop, Some(BracketStop::ObserverUnavailable));
    let report = driver.read_fronted(&target, 300, &|| false, &mut || panic!("no hooks"));
    assert!(matches!(report, Err(DriverError::InvalidRequest(_))));
    assert!(driver.accept_fronted_dispatch_hooks(Box::new(Hooks::default())));
    let report = driver
        .dispatch_fronted(
            FrontedDispatchRequest {
                synthetic: SyntheticDispatchRequest {
                    target,
                    action: SyntheticAction::TypeText {
                        text: "not posted".into(),
                    },
                },
                maximum_interval_ms: 200,
                maximum_seize_detection_latency_ms: 50,
            },
            &|| false,
        )
        .unwrap();
    assert_eq!(report.stop, Some(BracketStop::ObserverUnavailable));
    assert_eq!(report.posts_returned, 0);
}

#[test]
#[ignore = "requires two owned signed fixture windows on the split-token Windows desktop and WGC"]
fn native_fronting_picture_interval_matches_win_event_clock() {
    use crate::app_state::image::WindowImageCapture;
    use crate::capture::AcquisitionFence;
    use cerebellum_windows::{
        current_process_token_elevation_type, ForegroundEvents, TokenElevationType,
    };

    const BOUND: u64 = 300;
    assert!(
        desktop_safe(),
        "requires medium integrity on the Default input desktop"
    );
    assert_eq!(
        current_process_token_elevation_type(),
        Some(TokenElevationType::Limited)
    );
    assert_eq!(cerebellum_windows::capture_support(), Some(true));
    cerebellum_windows::set_process_per_monitor_v2();
    assert!(cerebellum_windows::per_monitor_v2());
    let number = |name| {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("missing fixture input {name}"))
            .parse::<u32>()
            .unwrap()
    };
    let pid = number("CK_WINDOWS_CAPTURE_FIXTURE_PID");
    let hwnd = number("CK_WINDOWS_CAPTURE_FIXTURE_HWND");
    let original = number("CK_WINDOWS_FRONTING_ORIGINAL_HWND");
    let original_pid = number("CK_WINDOWS_FRONTING_ORIGINAL_PID");
    assert_ne!(pid, original_pid);
    assert_eq!(foreground_window_number(), Some(original));
    let original_proof = Binding::read(original, None).expect("retain the original fixture");
    assert_eq!(original_proof.pid(), original_pid);
    let signed = |fixture_pid| {
        let identity = super::super::super::identity::live_identity(
            fixture_pid,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("verified signed fixture");
        assert!(identity.principal.to_string().starts_with("win-signed:"));
        identity.grant(fixture_pid)
    };
    let _original = signed(original_pid);
    let target = signed(pid);
    let retained = target_process(&target).expect("retained fixture process");
    let bound = Binding::read(hwnd, Some(retained)).expect("the exact fixture HWND");
    let sampled =
        super::super::snapshot(&target).expect("foreground and target window observations");
    assert!(sampled
        .frontmost_application_identity
        .unwrap()
        .starts_with(&format!("{original}:{original_pid}:")));
    assert!(sampled
        .target_windows
        .iter()
        .any(|window| window.observation_window_id == hwnd.to_string()));
    let events = ForegroundEvents::start().expect("foreground event hook");
    let lane = take_foreground_lane().expect("no concurrent Windows fronting");
    let mut hooks = Hooks::default();
    let mut captured: Option<WindowImageCapture> = None;
    let report = run(
        Arc::new(NativeDesktop {
            _lane: Some(lane),
            picture: true,
            previous: Binding::read(original, None).expect("saved foreground binding"),
        }),
        || Ok(bound),
        Some(Arc::new(Echo::default())),
        BracketPlan {
            target_pid: pid,
            units: 1,
            maximum_interval_ms: BOUND,
            maximum_seize_detection_latency_ms: 50,
        },
        &mut hooks,
        &|| false,
        Work::Read(&mut |binding: &Binding| {
            let binding_for_fence = binding.clone();
            let fence: AcquisitionFence = Arc::new(move || binding_for_fence.is_foreground());
            super::super::super::picture::with_fronted_window(binding, &mut || {
                captured = super::super::super::picture::capture(
                    &target,
                    Instant::now() + Duration::from_millis(150),
                    &fence,
                )
                .ok();
            });
        }),
    )
    .unwrap();
    assert_eq!(foreground_window_number(), Some(original), "{report:?}");
    assert!(
        report.held(BOUND),
        "the fixture must be able to take foreground without injected input: {report:?}"
    );
    assert_eq!(captured.unwrap().window_id, hwnd.to_string());
    let front = events
        .next(Duration::from_secs(1))
        .expect("target foreground event");
    let back = events
        .next(Duration::from_secs(1))
        .expect("original foreground event");
    assert_eq!((front.number, back.number), (hwnd, original));
    let native_interval = u64::from(back.event_tick.wrapping_sub(front.event_tick));
    assert!(
        native_interval <= BOUND,
        "WinEvent measured {native_interval} ms"
    );
    // WinEvent supplies millisecond ticks on a coarse Windows event clock.
    assert!(
        native_interval.abs_diff(report.longest_fronted_interval_ms) <= 32,
        "WinEvent measured {native_interval} ms; bracket: {report:?}"
    );
}
