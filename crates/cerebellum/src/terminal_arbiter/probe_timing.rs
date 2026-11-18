//! Passive timing records for the manual desk probe, never reply fields.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::computer::dispatch::RestoreStatus;

/// Milliseconds from the front request. Missing values mean the corresponding
/// confirmation was not observed, not that it took zero milliseconds.
#[derive(Clone, Debug)]
pub struct FrontingTiming {
    pub target_pid: u32,
    pub confirmed_front_ms: Option<f64>,
    pub late_landing_ms: Option<f64>,
    pub restore_confirmed_ms: Option<f64>,
    /// The first per-process post call to the target after the front
    /// request. With `confirmed_front_ms` it gives how long the target had
    /// been frontmost when the first keystroke went out.
    pub first_post_ms: Option<f64>,
    /// The instant every `_ms` value counts from, so the probe can place its
    /// own observations on the same scale.
    pub front_requested_at: Option<Instant>,
    /// This attempt's restores asked by activation first, the reverse of
    /// production order (see [`set_restore_activate_first`]).
    pub activate_first: bool,
    events: Vec<Event>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum RestoreRoute {
    /// The accessibility write (`request_front`).
    AxFrontmost,
    /// AppKit activation with all windows (`request_front_fallback`).
    ActivateAllWindows,
}

/// Which of a restore's requests the decision is making: the one it always
/// makes, or the one it adds when the first has not taken effect.
#[derive(Clone, Copy, Debug)]
pub(super) enum RestoreSlot {
    First,
    Second,
}

/// Whether restores of attempts that begin from now on ask by activation
/// first. Production asks by accessibility first and this probe-only switch
/// never changes that outside a desk-probe build; the probe turns it on for
/// part of a run so both orders are measured on the same desk.
static ACTIVATE_FIRST: AtomicBool = AtomicBool::new(false);

/// Set the restore order for attempts that begin after this call.
pub(crate) fn set_restore_activate_first(activate_first: bool) {
    ACTIVATE_FIRST.store(activate_first, Ordering::SeqCst);
}

/// The route a restore request in `slot` takes under this attempt's order.
fn route_for(slot: RestoreSlot, activate_first: bool) -> RestoreRoute {
    match (slot, activate_first) {
        (RestoreSlot::First, false) | (RestoreSlot::Second, true) => RestoreRoute::AxFrontmost,
        (RestoreSlot::First, true) | (RestoreSlot::Second, false) => {
            RestoreRoute::ActivateAllWindows
        }
    }
}

fn order_name(activate_first: bool) -> &'static str {
    if activate_first {
        "activate_first"
    } else {
        "ax_first"
    }
}

/// What the accessibility write behind the `ax_frontmost` route reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AxCall {
    /// The write returned this accessibility error code (0 is success).
    Code(i32),
    /// The request stopped before the write: no trust, or no such process.
    NotCalled,
    /// No record of the write was found on this thread, as with a host that
    /// does not use the accessibility route.
    Unnoted,
}

/// How one restore request's call returned.
#[derive(Clone, Copy, Debug)]
struct RequestReturn {
    accepted: bool,
    /// Only for the `ax_frontmost` route.
    ax: Option<AxCall>,
    at_ms: f64,
}

/// One reading taken while a restore waits: whether AppKit reports the
/// restored application as active, and the window the frontmost reading is
/// taken from, as `(owner pid, window id)`. The confirmation reads window
/// order only, so the two together tell "active but not on top" from "not
/// active".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RestoreSample {
    pub(super) active: Option<bool>,
    pub(super) top: Option<(i32, Option<u32>)>,
}

/// Takes one [`RestoreSample`] for the application being restored.
type Sampler = fn(u32) -> RestoreSample;

/// How the restore wait is sampled.
#[derive(Clone, Copy)]
struct Sampling {
    sampler: Option<Sampler>,
    interval: Duration,
    /// Sampling stops this long after the restore was seen confirmed.
    after_confirmation: Duration,
    /// And at the latest this long after it began: past the restore wait.
    limit: Duration,
}

/// Every 10 ms, for a little longer than the restore wait (300 ms).
const DESK_SAMPLING: Sampling = Sampling {
    sampler: Some(sample_restore_wait),
    interval: Duration::from_millis(10),
    after_confirmation: Duration::from_millis(30),
    limit: Duration::from_millis(450),
};

fn sample_restore_wait(pid: u32) -> RestoreSample {
    RestoreSample {
        active: cerebellum_macos::application_is_active_for_probe(pid),
        top: cerebellum_macos::normal_frontmost_window_for_probe(),
    }
}

#[derive(Clone, Debug)]
struct Event {
    at_ms: f64,
    kind: EventKind,
}

#[derive(Clone, Debug)]
enum EventKind {
    FrontRequest,
    Landing {
        in_call: bool,
    },
    RestoreRequest {
        id: usize,
        pid: u32,
        route: RestoreRoute,
        confirmed_ms: Option<f64>,
        returned: Option<RequestReturn>,
    },
    RestoreConfirmation {
        request: usize,
        pid: u32,
    },
    RestoreSample {
        pid: u32,
        sample: RestoreSample,
    },
    FirstPost,
    WatchFinished(RestoreStatus),
}

fn route_name(route: RestoreRoute) -> &'static str {
    match route {
        RestoreRoute::AxFrontmost => "ax_frontmost",
        RestoreRoute::ActivateAllWindows => "activate_all_windows",
    }
}

fn returned_text(returned: Option<RequestReturn>) -> String {
    let Some(returned) = returned else {
        return "returned=unobserved".into();
    };
    let ax = match returned.ax {
        None => String::new(),
        Some(AxCall::Code(code)) => format!(" ax_error={code}"),
        Some(AxCall::NotCalled) => " ax_error=not_called".into(),
        Some(AxCall::Unnoted) => " ax_error=unnoted".into(),
    };
    format!(
        "accepted={}{ax} returned_at_ms={:.3}",
        returned.accepted, returned.at_ms
    )
}

fn sample_text(sample: RestoreSample) -> String {
    let active = sample
        .active
        .map_or_else(|| "unknown".into(), |active| active.to_string());
    let top = match sample.top {
        None => "unreadable".into(),
        Some((pid, Some(window))) => format!("{pid}/{window}"),
        Some((pid, None)) => format!("{pid}/none"),
    };
    format!("active={active} top={top}")
}

impl FrontingTiming {
    /// This attempt's restore order, as its log lines name it.
    pub fn restore_order(&self) -> &'static str {
        order_name(self.activate_first)
    }

    /// The first restore request of this attempt: when it was made, its
    /// route, and whether the restored application was seen in front before
    /// any later request was made.
    pub fn first_restore_request(&self) -> Option<(f64, &'static str, bool)> {
        self.events.iter().find_map(|event| match event.kind {
            EventKind::RestoreRequest {
                id: 1,
                route,
                confirmed_ms,
                ..
            } => Some((event.at_ms, route_name(route), confirmed_ms.is_some())),
            _ => None,
        })
    }

    /// One line per passive observation, in collection order. A confirmation
    /// belongs to the latest request; it does not prove which asynchronous
    /// activation route caused the application to come forward. Consecutive
    /// restore samples that read the same are one line, with their count and
    /// the time of the last.
    pub fn record_lines(&self, attempt: usize) -> Vec<String> {
        let mut lines = Vec::new();
        let mut index = 0;
        while let Some(event) = self.events.get(index) {
            index += 1;
            let detail = match event.kind {
                EventKind::FrontRequest => format!(
                    "front_request pid={} restore_order={}",
                    self.target_pid,
                    order_name(self.activate_first)
                ),
                EventKind::Landing { in_call } => format!(
                    "target_landing pid={} source={}",
                    self.target_pid,
                    if in_call { "in_call" } else { "late" }
                ),
                EventKind::RestoreRequest {
                    id,
                    pid,
                    route,
                    confirmed_ms,
                    returned,
                } => format!(
                    "restore_request id={id} pid={pid} route={} confirmed={} confirmed_at_ms={} {}",
                    route_name(route),
                    confirmed_ms.is_some(),
                    confirmed_ms.map_or_else(|| "unobserved".into(), |ms| format!("{ms:.3}")),
                    returned_text(returned),
                ),
                EventKind::RestoreConfirmation { request, pid } => {
                    format!("restore_confirmation request={request} pid={pid}")
                }
                EventKind::RestoreSample { pid, sample } => {
                    let mut count = 1;
                    let mut until = event.at_ms;
                    while let Some(Event {
                        at_ms,
                        kind:
                            EventKind::RestoreSample {
                                pid: next_pid,
                                sample: next,
                            },
                    }) = self.events.get(index)
                    {
                        if (*next_pid, *next) != (pid, sample) {
                            break;
                        }
                        count += 1;
                        until = *at_ms;
                        index += 1;
                    }
                    format!(
                        "restore_sample pid={pid} {} count={count} until_ms={until:.3}",
                        sample_text(sample)
                    )
                }
                EventKind::FirstPost => format!("first_post pid={}", self.target_pid),
                EventKind::WatchFinished(restore) => format!(
                    "late_watch result={}",
                    match restore {
                        RestoreStatus::Restored => "restored".into(),
                        RestoreStatus::Failed { left_in_front } =>
                            format!("failed left_in_front={left_in_front:?}"),
                        RestoreStatus::SkippedPerson { now_front } =>
                            format!("skipped_person now_front={now_front:?}"),
                        RestoreStatus::NotNeeded => "not_needed".into(),
                    }
                ),
            };
            lines.push(format!(
                "RECORD needs-front attempt {attempt}: {detail} at_ms={:.3}",
                event.at_ms
            ));
        }
        lines
    }
}

struct State {
    started: Option<Instant>,
    timing: FrontingTiming,
    last_front: Option<u32>,
    requests: usize,
    awaiting_restore: Option<usize>,
    /// The latest restore request's event, which its return is written to.
    latest_request: Option<usize>,
    sampling: Sampling,
    /// A sampling thread is running for this attempt.
    sampling_running: bool,
    /// When the restore being sampled was seen confirmed.
    restore_confirmed_at: Option<Instant>,
}

impl State {
    fn record(&mut self, kind: EventKind) -> Option<f64> {
        let at_ms = self.started?.elapsed().as_secs_f64() * 1000.0;
        self.timing.events.push(Event { at_ms, kind });
        Some(at_ms)
    }
}

static ATTEMPTS: Mutex<Vec<Arc<Mutex<State>>>> = Mutex::new(Vec::new());

#[derive(Clone)]
pub(super) struct ProbeTiming(Arc<Mutex<State>>);

impl ProbeTiming {
    pub(super) fn new(target_pid: u32) -> Self {
        // Unit tests drive restores on a fake clock; a sampling thread there
        // would read this machine's real windows.
        let sampling = if cfg!(test) {
            Sampling {
                sampler: None,
                ..DESK_SAMPLING
            }
        } else {
            DESK_SAMPLING
        };
        Self::with_sampling(target_pid, sampling, ACTIVATE_FIRST.load(Ordering::SeqCst))
    }

    fn with_sampling(target_pid: u32, sampling: Sampling, activate_first: bool) -> Self {
        Self(Arc::new(Mutex::new(State {
            started: None,
            timing: FrontingTiming {
                target_pid,
                confirmed_front_ms: None,
                late_landing_ms: None,
                restore_confirmed_ms: None,
                first_post_ms: None,
                front_requested_at: None,
                activate_first,
                events: Vec::new(),
            },
            last_front: None,
            requests: 0,
            awaiting_restore: None,
            latest_request: None,
            sampling,
            sampling_running: false,
            restore_confirmed_at: None,
        })))
    }

    pub(super) fn begin(&self) {
        let mut state = self.0.lock().unwrap();
        if state.started.is_none() {
            let now = Instant::now();
            state.started = Some(now);
            state.timing.front_requested_at = Some(now);
            state.timing.events.push(Event {
                at_ms: 0.0,
                kind: EventKind::FrontRequest,
            });
            ATTEMPTS.lock().unwrap().push(Arc::clone(&self.0));
        }
    }

    pub(super) fn confirmed_front(&self) {
        let mut state = self.0.lock().unwrap();
        if state.timing.confirmed_front_ms.is_none() {
            state.timing.confirmed_front_ms = state.record(EventKind::Landing { in_call: true });
            state.last_front = Some(state.timing.target_pid);
        }
    }

    pub(super) fn late_landing(&self) {
        let mut state = self.0.lock().unwrap();
        if let Some(started) = state.started {
            state
                .timing
                .late_landing_ms
                .get_or_insert_with(|| started.elapsed().as_secs_f64() * 1000.0);
        }
    }

    pub(super) fn restore_requested(&self, pid: u32, route: RestoreRoute) {
        let mut state = self.0.lock().unwrap();
        // Posts happen before the restore is asked for, so reading them here
        // keeps the events in order.
        if let (Some(started), None) = (state.started, state.timing.first_post_ms) {
            let posts = cerebellum_macos::take_posts_for_probe();
            if let Some(at) = first_post_after(&posts, state.timing.target_pid, started) {
                let at_ms = at.duration_since(started).as_secs_f64() * 1000.0;
                state.timing.first_post_ms = Some(at_ms);
                state.timing.events.push(Event {
                    at_ms,
                    kind: EventKind::FirstPost,
                });
            }
        }
        let id = state.requests + 1;
        let index = state.timing.events.len();
        if state
            .record(EventKind::RestoreRequest {
                id,
                pid,
                route,
                confirmed_ms: None,
                returned: None,
            })
            .is_some()
        {
            state.requests = id;
            state.awaiting_restore = Some(index);
            state.latest_request = Some(index);
            state.restore_confirmed_at = None;
            if let (Some(sampler), false) = (state.sampling.sampler, state.sampling_running) {
                state.sampling_running = true;
                let shared = Arc::clone(&self.0);
                let sampling = state.sampling;
                std::thread::spawn(move || sample_restore(&shared, pid, sampler, sampling));
            }
        }
    }

    /// The latest restore request's call returned: whether the host accepted
    /// it, and for the accessibility route what the write reported.
    pub(super) fn restore_request_returned(&self, accepted: bool, ax: Option<AxCall>) {
        let mut state = self.0.lock().unwrap();
        let (Some(started), Some(index)) = (state.started, state.latest_request) else {
            return;
        };
        let at_ms = started.elapsed().as_secs_f64() * 1000.0;
        if let EventKind::RestoreRequest { returned, .. } = &mut state.timing.events[index].kind {
            *returned = Some(RequestReturn {
                accepted,
                ax,
                at_ms,
            });
        }
    }

    pub(super) fn frontmost_observed(&self, frontmost: Option<u32>) {
        let mut state = self.0.lock().unwrap();
        if frontmost == Some(state.timing.target_pid) && state.last_front != frontmost {
            state.record(EventKind::Landing { in_call: false });
        }
        state.last_front = frontmost;
        if let Some(index) = state.awaiting_restore {
            let EventKind::RestoreRequest { id, pid, .. } = state.timing.events[index].kind else {
                unreachable!("only restore requests await confirmation")
            };
            if frontmost == Some(pid) {
                let at_ms = state
                    .record(EventKind::RestoreConfirmation { request: id, pid })
                    .unwrap();
                if let EventKind::RestoreRequest { confirmed_ms, .. } =
                    &mut state.timing.events[index].kind
                {
                    *confirmed_ms = Some(at_ms);
                }
                state.timing.restore_confirmed_ms.get_or_insert(at_ms);
                state.awaiting_restore = None;
                state.restore_confirmed_at = Some(Instant::now());
            }
        }
    }

    pub(super) fn watch_finished(&self, restore: RestoreStatus) {
        self.0
            .lock()
            .unwrap()
            .record(EventKind::WatchFinished(restore));
    }
}

/// Make the restore request in `slot` through `host`, by the route this
/// attempt's order gives that slot, recording the request, how its call
/// returned, and for the accessibility route the write's error code.
pub(super) fn request_restore(
    host: &mut dyn super::RestoreHost,
    timing: &ProbeTiming,
    pid: u32,
    slot: RestoreSlot,
    check: &mut dyn crate::computer::platform::RestoreWriteCheck,
) -> bool {
    let activate_first = timing.0.lock().unwrap().timing.activate_first;
    let route = route_for(slot, activate_first);
    timing.restore_requested(pid, route);
    let (accepted, ax) = match route {
        RestoreRoute::AxFrontmost => {
            // Clear any record an earlier request on this thread left.
            let _ = cerebellum_macos::take_frontmost_call_for_probe();
            let accepted = host.request_front_while(pid, check);
            let ax = match cerebellum_macos::take_frontmost_call_for_probe() {
                Some(call) if call.pid == pid => {
                    call.ax_error.map_or(AxCall::NotCalled, AxCall::Code)
                }
                _ => AxCall::Unnoted,
            };
            (accepted, Some(ax))
        }
        RestoreRoute::ActivateAllWindows => (host.request_front_fallback_while(pid, check), None),
    };
    timing.restore_request_returned(accepted, ax);
    accepted
}

/// Sample the restore wait every `sampling.interval` until shortly after the
/// restore is confirmed or `sampling.limit` has passed, recording each
/// reading as an event of this attempt.
fn sample_restore(state: &Mutex<State>, pid: u32, sampler: Sampler, sampling: Sampling) {
    let began = Instant::now();
    loop {
        let sample = sampler(pid);
        let mut state = state.lock().unwrap();
        state.record(EventKind::RestoreSample { pid, sample });
        let confirmed_long_enough = state
            .restore_confirmed_at
            .is_some_and(|at| at.elapsed() >= sampling.after_confirmation);
        if confirmed_long_enough || began.elapsed() >= sampling.limit {
            state.sampling_running = false;
            return;
        }
        drop(state);
        std::thread::sleep(sampling.interval);
    }
}

/// The earliest post call to `target` made at or after `started`, from the
/// noted `(pid, when)` post calls.
fn first_post_after(posts: &[(i32, Instant)], target: u32, started: Instant) -> Option<Instant> {
    posts
        .iter()
        .filter(|(pid, at)| u32::try_from(*pid) == Ok(target) && *at >= started)
        .map(|(_, at)| *at)
        .min()
}

pub(crate) fn take_timings() -> Vec<FrontingTiming> {
    drain(&ATTEMPTS)
}

fn drain(attempts: &Mutex<Vec<Arc<Mutex<State>>>>) -> Vec<FrontingTiming> {
    let attempts = std::mem::take(&mut *attempts.lock().unwrap());
    attempts
        .into_iter()
        .map(|state| state.lock().unwrap().timing.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::dispatch::{watch_late_activation, HardwareInputSnapshot, LateWatch};
    use crate::terminal_arbiter::{RestoreDecisionHost, RestoreHost};

    #[test]
    fn record_format_names_routes_confirmations_and_watch_results() {
        let timing = FrontingTiming {
            target_pid: 42,
            confirmed_front_ms: Some(12.5),
            late_landing_ms: None,
            restore_confirmed_ms: Some(180.0),
            first_post_ms: Some(15.0),
            front_requested_at: None,
            activate_first: false,
            events: vec![
                Event {
                    at_ms: 0.0,
                    kind: EventKind::FrontRequest,
                },
                Event {
                    at_ms: 12.5,
                    kind: EventKind::Landing { in_call: true },
                },
                Event {
                    at_ms: 15.0,
                    kind: EventKind::FirstPost,
                },
                Event {
                    at_ms: 20.0,
                    kind: EventKind::RestoreRequest {
                        id: 1,
                        pid: 7,
                        route: RestoreRoute::AxFrontmost,
                        confirmed_ms: None,
                        returned: Some(RequestReturn {
                            accepted: false,
                            ax: Some(AxCall::Code(-25204)),
                            at_ms: 21.25,
                        }),
                    },
                },
                Event {
                    at_ms: 30.0,
                    kind: EventKind::RestoreSample {
                        pid: 7,
                        sample: RestoreSample {
                            active: Some(true),
                            top: Some((42, Some(501))),
                        },
                    },
                },
                Event {
                    at_ms: 40.0,
                    kind: EventKind::RestoreSample {
                        pid: 7,
                        sample: RestoreSample {
                            active: Some(true),
                            top: Some((42, Some(501))),
                        },
                    },
                },
                Event {
                    at_ms: 50.0,
                    kind: EventKind::RestoreSample {
                        pid: 7,
                        sample: RestoreSample {
                            active: None,
                            top: None,
                        },
                    },
                },
                Event {
                    at_ms: 170.0,
                    kind: EventKind::RestoreRequest {
                        id: 2,
                        pid: 7,
                        route: RestoreRoute::ActivateAllWindows,
                        confirmed_ms: Some(180.0),
                        returned: Some(RequestReturn {
                            accepted: true,
                            ax: None,
                            at_ms: 170.5,
                        }),
                    },
                },
                Event {
                    at_ms: 175.0,
                    kind: EventKind::RestoreSample {
                        pid: 7,
                        sample: RestoreSample {
                            active: Some(true),
                            top: Some((7, None)),
                        },
                    },
                },
                Event {
                    at_ms: 180.0,
                    kind: EventKind::RestoreConfirmation { request: 2, pid: 7 },
                },
                Event {
                    at_ms: 190.0,
                    kind: EventKind::RestoreRequest {
                        id: 3,
                        pid: 7,
                        route: RestoreRoute::AxFrontmost,
                        confirmed_ms: None,
                        returned: None,
                    },
                },
                Event {
                    at_ms: 191.0,
                    kind: EventKind::RestoreRequest {
                        id: 4,
                        pid: 7,
                        route: RestoreRoute::AxFrontmost,
                        confirmed_ms: None,
                        returned: Some(RequestReturn {
                            accepted: false,
                            ax: Some(AxCall::NotCalled),
                            at_ms: 191.0,
                        }),
                    },
                },
                Event {
                    at_ms: 800.0,
                    kind: EventKind::Landing { in_call: false },
                },
                Event {
                    at_ms: 1100.0,
                    kind: EventKind::WatchFinished(RestoreStatus::Restored),
                },
                Event {
                    at_ms: 1101.0,
                    kind: EventKind::WatchFinished(RestoreStatus::Failed {
                        left_in_front: Some(42),
                    }),
                },
                Event {
                    at_ms: 1102.0,
                    kind: EventKind::WatchFinished(RestoreStatus::SkippedPerson {
                        now_front: None,
                    }),
                },
            ],
        };
        assert_eq!(timing.record_lines(3), [
            "RECORD needs-front attempt 3: front_request pid=42 restore_order=ax_first at_ms=0.000",
            "RECORD needs-front attempt 3: target_landing pid=42 source=in_call at_ms=12.500",
            "RECORD needs-front attempt 3: first_post pid=42 at_ms=15.000",
            "RECORD needs-front attempt 3: restore_request id=1 pid=7 route=ax_frontmost confirmed=false confirmed_at_ms=unobserved accepted=false ax_error=-25204 returned_at_ms=21.250 at_ms=20.000",
            "RECORD needs-front attempt 3: restore_sample pid=7 active=true top=42/501 count=2 until_ms=40.000 at_ms=30.000",
            "RECORD needs-front attempt 3: restore_sample pid=7 active=unknown top=unreadable count=1 until_ms=50.000 at_ms=50.000",
            "RECORD needs-front attempt 3: restore_request id=2 pid=7 route=activate_all_windows confirmed=true confirmed_at_ms=180.000 accepted=true returned_at_ms=170.500 at_ms=170.000",
            "RECORD needs-front attempt 3: restore_sample pid=7 active=true top=7/none count=1 until_ms=175.000 at_ms=175.000",
            "RECORD needs-front attempt 3: restore_confirmation request=2 pid=7 at_ms=180.000",
            "RECORD needs-front attempt 3: restore_request id=3 pid=7 route=ax_frontmost confirmed=false confirmed_at_ms=unobserved returned=unobserved at_ms=190.000",
            "RECORD needs-front attempt 3: restore_request id=4 pid=7 route=ax_frontmost confirmed=false confirmed_at_ms=unobserved accepted=false ax_error=not_called returned_at_ms=191.000 at_ms=191.000",
            "RECORD needs-front attempt 3: target_landing pid=42 source=late at_ms=800.000",
            "RECORD needs-front attempt 3: late_watch result=restored at_ms=1100.000",
            "RECORD needs-front attempt 3: late_watch result=failed left_in_front=Some(42) at_ms=1101.000",
            "RECORD needs-front attempt 3: late_watch result=skipped_person now_front=None at_ms=1102.000",
        ]);
    }

    /// Only posts to the target made after the front request count, and the
    /// earliest of them is the first post.
    #[test]
    fn the_first_post_is_the_earliest_post_to_the_target_after_the_front_request() {
        let started = Instant::now();
        let at = |ms| started + std::time::Duration::from_millis(ms);
        let earlier = started - std::time::Duration::from_millis(5);
        let posts = [(42, earlier), (7, at(3)), (42, at(9)), (42, at(4))];
        assert_eq!(first_post_after(&posts, 42, started), Some(at(4)));
        assert_eq!(first_post_after(&posts, 8, started), None);
        assert_eq!(first_post_after(&[(42, earlier)], 42, started), None);
    }

    struct ReturningTarget {
        now: u64,
        front: u32,
        second_landing: bool,
    }

    impl RestoreHost for ReturningTarget {
        fn now_ms(&mut self) -> u64 {
            self.now
        }
        fn pause_ms(&mut self, ms: u64) {
            self.now += ms;
        }
        fn frontmost_pid(&mut self) -> Option<u32> {
            if self.now >= 800 && !self.second_landing {
                self.front = 42;
                self.second_landing = true;
            }
            Some(self.front)
        }
        fn request_front(&mut self, _pid: u32) -> bool {
            false
        }
        fn request_front_fallback(&mut self, pid: u32) -> bool {
            self.front = pid;
            true
        }
        fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
            Some(HardwareInputSnapshot {
                coverage_start_ms: 0,
                last_input_ms: None,
            })
        }
    }

    #[test]
    fn collection_keeps_both_restore_routes_and_second_landing() {
        let probe = ProbeTiming::new(42);
        probe.begin();
        probe.begin();
        let mut host = ReturningTarget {
            now: 110,
            front: 42,
            second_landing: false,
        };
        let (restore, _, _) = watch_late_activation(
            &mut RestoreDecisionHost {
                host: &mut host,
                _target: 42,
                requested_at: None,
                probe_timing: &probe,
            },
            7,
            42,
            0,
            1100,
            LateWatch::WholeWindow {
                already_restored: false,
            },
            &|| false,
        );
        probe.watch_finished(restore);
        assert_eq!(restore, RestoreStatus::Restored);
        let attempts = Mutex::new(vec![Arc::clone(&probe.0)]);
        let timings = drain(&attempts);
        let timing = timings
            .iter()
            .find(|timing| timing.target_pid == 42)
            .unwrap();
        let lines = timing.record_lines(1);
        assert_eq!(lines.len(), 10, "{lines:?}");
        for (text, count) in [
            ("front_request", 1),
            ("target_landing", 2),
            ("route=ax_frontmost confirmed=false", 2),
            // The fake host refuses the accessibility route without making
            // the accessibility write, and accepts the second route.
            (
                "confirmed_at_ms=unobserved accepted=false ax_error=unnoted returned_at_ms=",
                2,
            ),
            ("route=activate_all_windows confirmed=true", 2),
            ("accepted=true returned_at_ms=", 2),
            ("restore_confirmation", 2),
            ("late_watch result=restored", 1),
        ] {
            assert_eq!(
                lines.iter().filter(|line| line.contains(text)).count(),
                count,
                "{lines:?}"
            );
        }
        assert!(timing
            .events
            .windows(2)
            .all(|pair| pair[0].at_ms <= pair[1].at_ms));
        assert_eq!(timing.restore_confirmed_ms, Some(timing.events[4].at_ms));
        assert!(timing.late_landing_ms.is_some());
        assert!(timing.confirmed_front_ms.is_none());
        assert!(drain(&attempts).is_empty());
    }

    #[test]
    fn collection_records_in_call_landing_once_and_requires_matching_restore_pid() {
        let probe = ProbeTiming::new(43);
        probe.begin();
        probe.confirmed_front();
        probe.confirmed_front();
        probe.frontmost_observed(Some(43));
        probe.restore_requested(7, RestoreRoute::AxFrontmost);
        probe.frontmost_observed(Some(99));
        assert!(probe
            .0
            .lock()
            .unwrap()
            .timing
            .restore_confirmed_ms
            .is_none());
        probe.frontmost_observed(Some(7));
        let state = probe.0.lock().unwrap();
        assert_eq!(state.timing.events.len(), 4);
        assert!(matches!(
            state.timing.events[1].kind,
            EventKind::Landing { in_call: true }
        ));
        assert!(state.timing.restore_confirmed_ms.is_some());
    }

    fn fixed_sample(_pid: u32) -> RestoreSample {
        RestoreSample {
            active: Some(false),
            top: Some((42, Some(9))),
        }
    }

    /// A restore request starts sampling the wait, the samples are recorded
    /// against the restored application, and sampling stops shortly after the
    /// restore is confirmed.
    #[test]
    fn a_restore_request_samples_the_wait_until_shortly_after_confirmation() {
        let probe = ProbeTiming::with_sampling(
            42,
            Sampling {
                sampler: Some(fixed_sample),
                interval: Duration::from_millis(1),
                after_confirmation: Duration::from_millis(5),
                limit: Duration::from_secs(10),
            },
            false,
        );
        probe.begin();
        probe.restore_requested(7, RestoreRoute::AxFrontmost);
        let sampled = |probe: &ProbeTiming| {
            probe
                .0
                .lock()
                .unwrap()
                .timing
                .events
                .iter()
                .filter(|event| matches!(event.kind, EventKind::RestoreSample { pid: 7, .. }))
                .count()
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while sampled(&probe) < 3 {
            assert!(Instant::now() < deadline, "sampling never started");
            std::thread::sleep(Duration::from_millis(1));
        }
        probe.restore_requested(7, RestoreRoute::ActivateAllWindows);
        probe.frontmost_observed(Some(7));
        while probe.0.lock().unwrap().sampling_running {
            assert!(Instant::now() < deadline, "sampling never stopped");
            std::thread::sleep(Duration::from_millis(1));
        }
        let stopped_at = sampled(&probe);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(sampled(&probe), stopped_at);
        let timing = probe.0.lock().unwrap().timing.clone();
        let lines = timing.record_lines(2);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("restore_sample pid=7 active=false top=42/9 count=")),
            "{lines:?}"
        );
        // The ordinary path makes no sampler at all in unit tests.
        assert!(ProbeTiming::new(42)
            .0
            .lock()
            .unwrap()
            .sampling
            .sampler
            .is_none());
    }

    /// Records which host route each request reached. The accessibility
    /// route is refused and the activation route accepted, so the recorded
    /// results also show each request reached the route its label names.
    struct RouteCalls(Vec<&'static str>);

    impl RestoreHost for RouteCalls {
        fn now_ms(&mut self) -> u64 {
            0
        }
        fn pause_ms(&mut self, _ms: u64) {}
        fn frontmost_pid(&mut self) -> Option<u32> {
            None
        }
        fn request_front(&mut self, _pid: u32) -> bool {
            self.0.push("ax");
            false
        }
        fn request_front_fallback(&mut self, _pid: u32) -> bool {
            self.0.push("activate");
            true
        }
        fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
            None
        }
    }

    #[test]
    fn the_activate_first_order_swaps_the_route_each_restore_request_takes() {
        for (activate_first, calls, order, first, second) in [
            (
                false,
                ["ax", "activate"],
                "restore_order=ax_first",
                "route=ax_frontmost confirmed=false confirmed_at_ms=unobserved accepted=false",
                "route=activate_all_windows confirmed=false confirmed_at_ms=unobserved accepted=true",
            ),
            (
                true,
                ["activate", "ax"],
                "restore_order=activate_first",
                "route=activate_all_windows confirmed=false confirmed_at_ms=unobserved accepted=true",
                "route=ax_frontmost confirmed=false confirmed_at_ms=unobserved accepted=false",
            ),
        ] {
            let probe = ProbeTiming::with_sampling(
                42,
                Sampling {
                    sampler: None,
                    ..DESK_SAMPLING
                },
                activate_first,
            );
            probe.begin();
            let mut host = RouteCalls(Vec::new());
            request_restore(&mut host, &probe, 7, RestoreSlot::First);
            request_restore(&mut host, &probe, 7, RestoreSlot::Second);
            assert_eq!(host.0, calls);
            let timing = probe.0.lock().unwrap().timing.clone();
            let lines = timing.record_lines(1);
            assert!(lines[0].contains(order), "{lines:?}");
            assert!(lines[1].contains(first), "{lines:?}");
            assert!(lines[2].contains(second), "{lines:?}");
            assert_eq!(
                timing.first_restore_request().map(|(_, route, confirmed)| (route, confirmed)),
                Some((
                    if activate_first {
                        "activate_all_windows"
                    } else {
                        "ax_frontmost"
                    },
                    false
                ))
            );
        }
    }
}
