//! Dispatch timing state.
//!
//! The dispatch loop publishes monotonic instants — not precomputed ages — so
//! the insulated health lane can take one clock sample and compute each age as
//! `now - instant`. Three instants are published:
//!
//! - **heartbeat**: refreshed on every dispatch-loop iteration and on bounded
//!   idle wake-up. The bounded idle wake wraps ONLY the loop's wait-for-input
//!   (read) await — never the frame handler — so an idle module stays healthy
//!   while a wedged handler still lets the heartbeat age out (Health-Path-Rule-v2
//!   honesty: Degraded means dispatch-impaired, not "no frame recently").
//!   Initialized before registration becomes externally visible
//!   (see [`DispatchTimingState::new`]).
//! - **oldest queued**: the enqueue instant of the oldest action currently
//!   queued for dispatch. Absent when the queue is empty.
//! - **oldest in-flight**: the start instant of the oldest action currently
//!   in-flight. Absent when nothing is in-flight.
//!
//! Queue and in-flight absence are represented explicitly (via a sentinel
//! `u64::MAX` in the atomic) rather than by a zero timestamp, so an empty set
//! contributes no stale age. All three instants are stored as atomics so the
//! health lane can read them without a lock that could wait behind an action.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::clock::MonoInstant;

/// Sentinel stored in the queued/in-flight atomics when the set is empty.
/// `u64::MAX` nanoseconds is ~584 years from the clock epoch, unreachable for
/// any realistic monotonic session.
const ABSENT: u64 = u64::MAX;

/// The dispatch timing state: three monotonic instants published by the
/// dispatch loop and read by the insulated health lane.
///
/// `heartbeat` is always present (initialized at construction). `oldest_queued`
/// and `oldest_in_flight` are optional: an absent value means the set is empty
/// and contributes no stale age. The instants are stored as atomics so the
/// health lane reads them without a lock.
#[derive(Debug)]
pub struct DispatchTimingState {
    in_flight: AtomicU64,
    awaiting_consent: AtomicU64,
    live: std::sync::Mutex<(u64, std::collections::BTreeMap<u64, MonoInstant>)>,
    /// Latest heartbeat instant, in nanoseconds since the clock epoch.
    heartbeat_nanos: AtomicU64,
    /// Oldest queued-action enqueue instant, or [`ABSENT`] when the queue is
    /// empty.
    oldest_queued_nanos: AtomicU64,
    /// Oldest in-flight action start instant, or [`ABSENT`] when nothing is
    /// in-flight.
    oldest_in_flight_nanos: AtomicU64,
}

impl DispatchTimingState {
    /// Create the timing state with the heartbeat initialized to `clock.now()`
    /// and the queued/in-flight sets empty. The heartbeat is stamped here so
    /// it is set before registration completes (the caller constructs this
    /// before making the module externally visible).
    pub fn new(clock: &impl crate::clock::MonotonicClock) -> Self {
        Self {
            in_flight: AtomicU64::new(0),
            awaiting_consent: AtomicU64::new(0),
            live: std::sync::Mutex::new((0, std::collections::BTreeMap::new())),
            heartbeat_nanos: AtomicU64::new(clock.now().as_nanos()),
            oldest_queued_nanos: AtomicU64::new(ABSENT),
            oldest_in_flight_nanos: AtomicU64::new(ABSENT),
        }
    }

    /// Register before spawning so health checks count a request even before its
    /// task is first polled.
    pub fn enter(
        self: &std::sync::Arc<Self>,
        clock: &(impl crate::clock::MonotonicClock + Clone + Send + Sync + 'static),
    ) -> InFlightGuard {
        let mut live = self.live.lock().expect("in-flight lock poisoned");
        let ticket = live.0;
        live.0 += 1;
        live.1.insert(ticket, clock.now());
        self.set_oldest_in_flight(live.1.values().copied().min());
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        InFlightGuard {
            timing: self.clone(),
            ticket,
            clock: Box::new(clock.clone()),
            state: std::sync::Mutex::new(ExecutionState::Executing),
        }
    }

    pub fn awaiting_consent(&self) -> u64 {
        self.awaiting_consent.load(Ordering::SeqCst)
    }

    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Refresh the heartbeat instant to `clock.now()`. Called by the dispatch
    /// loop on every iteration and on bounded idle wake-up. The idle wake-up
    /// re-stamps only while the loop is parked waiting for the next frame; it is
    /// NOT called around the frame handler, so a wedged handler still goes stale.
    pub fn refresh_heartbeat(&self, clock: &impl crate::clock::MonotonicClock) {
        self.heartbeat_nanos
            .store(clock.now().as_nanos(), Ordering::SeqCst);
    }

    /// Publish the enqueue instant of the oldest queued action. Pass `None`
    /// when the queue becomes empty.
    pub fn set_oldest_queued(&self, instant: Option<MonoInstant>) {
        let v = match instant {
            Some(i) => i.as_nanos(),
            None => ABSENT,
        };
        self.oldest_queued_nanos.store(v, Ordering::SeqCst);
    }

    /// Publish the start instant of the oldest in-flight action. Pass `None`
    /// when nothing is in-flight.
    pub fn set_oldest_in_flight(&self, instant: Option<MonoInstant>) {
        let v = match instant {
            Some(i) => i.as_nanos(),
            None => ABSENT,
        };
        self.oldest_in_flight_nanos.store(v, Ordering::SeqCst);
    }

    /// Read the current heartbeat instant.
    pub fn heartbeat(&self) -> MonoInstant {
        MonoInstant::from_nanos(self.heartbeat_nanos.load(Ordering::SeqCst))
    }

    /// Read the oldest queued-action enqueue instant, or `None` if the queue
    /// is empty.
    pub fn oldest_queued(&self) -> Option<MonoInstant> {
        let v = self.oldest_queued_nanos.load(Ordering::SeqCst);
        if v == ABSENT {
            None
        } else {
            Some(MonoInstant::from_nanos(v))
        }
    }

    /// Read the oldest in-flight action start instant, or `None` if nothing is
    /// in-flight.
    pub fn oldest_in_flight(&self) -> Option<MonoInstant> {
        let v = self.oldest_in_flight_nanos.load(Ordering::SeqCst);
        if v == ABSENT {
            None
        } else {
            Some(MonoInstant::from_nanos(v))
        }
    }
}

/// Removes a request from in-flight accounting on completion, cancellation, or
/// panic. Health checks read the published atomics without acquiring the map lock.
pub struct InFlightGuard {
    timing: std::sync::Arc<DispatchTimingState>,
    ticket: u64,
    clock: Box<dyn crate::clock::MonotonicClock + Send + Sync>,
    state: std::sync::Mutex<ExecutionState>,
}

#[derive(PartialEq, Eq)]
enum ExecutionState {
    Executing,
    AwaitingConsent,
}

impl InFlightGuard {
    /// Suspend execution accounting while a person decides. The borrowed token
    /// prevents the request guard from being destroyed before accounting resumes.
    pub fn park_on_consent(&self) -> ConsentParked<'_> {
        let mut state = self.state.lock().expect("request state lock poisoned");
        assert!(
            *state == ExecutionState::Executing,
            "request already parked"
        );
        let mut live = self.timing.live.lock().expect("in-flight lock poisoned");
        live.1.remove(&self.ticket);
        self.timing
            .set_oldest_in_flight(live.1.values().copied().min());
        self.timing.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.timing.awaiting_consent.fetch_add(1, Ordering::SeqCst);
        *state = ExecutionState::AwaitingConsent;
        ConsentParked { guard: self }
    }
}

/// Dropping this token starts a fresh execution interval, including on cancellation.
pub struct ConsentParked<'a> {
    guard: &'a InFlightGuard,
}

impl Drop for ConsentParked<'_> {
    fn drop(&mut self) {
        let guard = self.guard;
        let mut state = guard.state.lock().expect("request state lock poisoned");
        let mut live = guard.timing.live.lock().expect("in-flight lock poisoned");
        live.1.insert(guard.ticket, guard.clock.now());
        guard
            .timing
            .set_oldest_in_flight(live.1.values().copied().min());
        guard.timing.awaiting_consent.fetch_sub(1, Ordering::SeqCst);
        guard.timing.in_flight.fetch_add(1, Ordering::SeqCst);
        *state = ExecutionState::Executing;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut live = self.timing.live.lock().expect("in-flight lock poisoned");
        live.1.remove(&self.ticket);
        self.timing
            .set_oldest_in_flight(live.1.values().copied().min());
        match *self.state.get_mut().expect("request state lock poisoned") {
            ExecutionState::Executing => {
                self.timing.in_flight.fetch_sub(1, Ordering::SeqCst);
            }
            ExecutionState::AwaitingConsent => {
                self.timing.awaiting_consent.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}
