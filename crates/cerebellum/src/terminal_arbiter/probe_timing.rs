//! Passive timing records for the manual desk probe, never reply fields.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::computer::dispatch::RestoreStatus;

/// Milliseconds from the front request. Missing values mean the corresponding
/// confirmation was not observed, not that it took zero milliseconds.
#[derive(Clone, Debug)]
pub struct FrontingTiming {
    pub target_pid: u32,
    pub confirmed_front_ms: Option<f64>,
    pub late_landing_ms: Option<f64>,
    pub restore_confirmed_ms: Option<f64>,
    events: Vec<Event>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum RestoreRoute {
    AxFrontmost,
    Fallback,
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
    },
    RestoreConfirmation {
        request: usize,
        pid: u32,
    },
    WatchFinished(RestoreStatus),
}

impl FrontingTiming {
    /// One line per passive observation, in collection order. A confirmation
    /// belongs to the latest request; it does not prove which asynchronous
    /// activation route caused the application to come forward.
    pub fn record_lines(&self, attempt: usize) -> Vec<String> {
        self.events
            .iter()
            .map(|event| {
                let detail = match event.kind {
                    EventKind::FrontRequest => format!("front_request pid={}", self.target_pid),
                    EventKind::Landing { in_call } => format!(
                        "target_landing pid={} source={}",
                        self.target_pid,
                        if in_call { "in_call" } else { "late" }
                    ),
                    EventKind::RestoreRequest { id, pid, route, confirmed_ms } => format!(
                        "restore_request id={id} pid={pid} route={} confirmed={} confirmed_at_ms={}",
                        match route {
                            RestoreRoute::AxFrontmost => "ax_frontmost",
                            RestoreRoute::Fallback => "fallback",
                        },
                        confirmed_ms.is_some(),
                        confirmed_ms.map_or_else(|| "unobserved".into(), |ms| format!("{ms:.3}")),
                    ),
                    EventKind::RestoreConfirmation { request, pid } => {
                        format!("restore_confirmation request={request} pid={pid}")
                    }
                    EventKind::WatchFinished(restore) => format!(
                        "late_watch result={}",
                        match restore {
                            RestoreStatus::Restored => "restored".into(),
                            RestoreStatus::Failed { left_in_front } => format!("failed left_in_front={left_in_front:?}"),
                            RestoreStatus::SkippedPerson { now_front } => format!("skipped_person now_front={now_front:?}"),
                            RestoreStatus::NotNeeded => "not_needed".into(),
                        }
                    ),
                };
                format!("RECORD needs-front attempt {attempt}: {detail} at_ms={:.3}", event.at_ms)
            })
            .collect()
    }
}

struct State {
    started: Option<Instant>,
    timing: FrontingTiming,
    last_front: Option<u32>,
    requests: usize,
    awaiting_restore: Option<usize>,
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
        Self(Arc::new(Mutex::new(State {
            started: None,
            timing: FrontingTiming {
                target_pid,
                confirmed_front_ms: None,
                late_landing_ms: None,
                restore_confirmed_ms: None,
                events: Vec::new(),
            },
            last_front: None,
            requests: 0,
            awaiting_restore: None,
        })))
    }

    pub(super) fn begin(&self) {
        let mut state = self.0.lock().unwrap();
        if state.started.is_none() {
            state.started = Some(Instant::now());
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
        let id = state.requests + 1;
        let index = state.timing.events.len();
        if state
            .record(EventKind::RestoreRequest {
                id,
                pid,
                route,
                confirmed_ms: None,
            })
            .is_some()
        {
            state.requests = id;
            state.awaiting_restore = Some(index);
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
                    at_ms: 20.0,
                    kind: EventKind::RestoreRequest {
                        id: 1,
                        pid: 7,
                        route: RestoreRoute::AxFrontmost,
                        confirmed_ms: None,
                    },
                },
                Event {
                    at_ms: 170.0,
                    kind: EventKind::RestoreRequest {
                        id: 2,
                        pid: 7,
                        route: RestoreRoute::Fallback,
                        confirmed_ms: Some(180.0),
                    },
                },
                Event {
                    at_ms: 180.0,
                    kind: EventKind::RestoreConfirmation { request: 2, pid: 7 },
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
            "RECORD needs-front attempt 3: front_request pid=42 at_ms=0.000",
            "RECORD needs-front attempt 3: target_landing pid=42 source=in_call at_ms=12.500",
            "RECORD needs-front attempt 3: restore_request id=1 pid=7 route=ax_frontmost confirmed=false confirmed_at_ms=unobserved at_ms=20.000",
            "RECORD needs-front attempt 3: restore_request id=2 pid=7 route=fallback confirmed=true confirmed_at_ms=180.000 at_ms=170.000",
            "RECORD needs-front attempt 3: restore_confirmation request=2 pid=7 at_ms=180.000",
            "RECORD needs-front attempt 3: target_landing pid=42 source=late at_ms=800.000",
            "RECORD needs-front attempt 3: late_watch result=restored at_ms=1100.000",
            "RECORD needs-front attempt 3: late_watch result=failed left_in_front=Some(42) at_ms=1101.000",
            "RECORD needs-front attempt 3: late_watch result=skipped_person now_front=None at_ms=1102.000",
        ]);
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
            ("route=fallback confirmed=true", 2),
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
}
