//! The observed-mode abort guard.
//!
//! A stalled tap still reports itself enabled, so observer liveness is derived
//! from a heartbeat: the dispatcher posts a marker and requires the observer to
//! have seen it (our pid, non-zero) within a bound. Hardware input is pid 0;
//! our own posts must not abort us. Once the guard records an abort, queued
//! work is cancelled and the guard never permits another post.

use crate::platform::{IdleReading, IdleUnreadable, InputObservationResult, InputObserverLiveness};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeizeWatcherState {
    pub session_tap_live: bool,
    pub raw_hid_live: bool,
    pub self_echo_filter_live: bool,
}

impl From<InputObserverLiveness> for SeizeWatcherState {
    fn from(value: InputObserverLiveness) -> Self {
        Self {
            session_tap_live: value.session_tap_live,
            raw_hid_live: value.raw_hid_live,
            self_echo_filter_live: value.self_echo_filter_live,
        }
    }
}

impl SeizeWatcherState {
    pub fn live(self) -> bool {
        self.session_tap_live && self.raw_hid_live && self.self_echo_filter_live
    }
}

/// The next protected post must not be scheduled before the observer's worst
/// case abort signal can arrive.  Otherwise a human event could be detected only
/// after the following post had already escaped the stop path.
pub const fn seize_latency_fits_inter_post_interval(
    maximum_detection_latency_ms: u32,
    inter_post_interval_ms: u32,
) -> bool {
    inter_post_interval_ms >= maximum_detection_latency_ms
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    UserSeizedControl,
    ObserverUnavailable,
    SeizeLatencyBoundExceeded,
    /// Carries the refusal, because "not idle" without the threshold and the
    /// observed milliseconds cannot tell an operator why it was true.
    IdleGateRefused(IdleGateRefusal),
    FocusMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortDecision {
    pub reason: AbortReason,
    pub stopped_action_index: usize,
    pub detection_latency_ms: Option<u32>,
    pub maximum_detection_latency_ms: u32,
    pub queued_posts_cancelled: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeizeWatcher {
    abort: Option<AbortDecision>,
    queued_posts: u32,
    maximum_detection_latency_ms: u32,
}

impl SeizeWatcher {
    pub fn new(maximum_detection_latency_ms: u32) -> Self {
        Self {
            abort: None,
            queued_posts: 0,
            maximum_detection_latency_ms,
        }
    }

    pub fn queue_post(&mut self) -> bool {
        if self.abort.is_some() {
            return false;
        }
        self.queued_posts = self.queued_posts.saturating_add(1);
        true
    }

    pub fn can_post(&self) -> bool {
        self.abort.is_none()
    }

    pub fn abort(&mut self, reason: AbortReason, index: usize, latency: Option<u32>) {
        if self.abort.is_some() {
            return;
        }
        let cancelled = self.queued_posts;
        self.queued_posts = 0;
        self.abort = Some(AbortDecision {
            reason,
            stopped_action_index: index,
            detection_latency_ms: latency,
            maximum_detection_latency_ms: self.maximum_detection_latency_ms,
            queued_posts_cancelled: cancelled,
        });
    }

    pub fn observe_liveness(&mut self, state: SeizeWatcherState, index: usize) {
        if !state.live() {
            self.abort(AbortReason::ObserverUnavailable, index, None);
        }
    }

    pub fn observe_input(&mut self, observation: InputObservationResult, index: usize) {
        if observation.human_or_ambiguous_input {
            let reason = if observation.detection_latency_ms > self.maximum_detection_latency_ms {
                AbortReason::SeizeLatencyBoundExceeded
            } else {
                AbortReason::UserSeizedControl
            };
            self.abort(reason, index, Some(observation.detection_latency_ms));
        }
    }

    pub fn take_post_slot(&mut self) -> bool {
        if self.abort.is_some() {
            return false;
        }
        self.queued_posts = self.queued_posts.saturating_sub(1);
        true
    }

    pub fn abort_decision(&self) -> Option<AbortDecision> {
        self.abort
    }

    pub fn queued_posts(&self) -> u32 {
        self.queued_posts
    }

    /// Abort if the heartbeat showed a blind observer.
    ///
    /// A blind observer cannot see hardware input either, so the sequence stops
    /// before the next real post rather than proceeding with a warning.
    pub fn observe_heartbeat(&mut self, liveness: ObserverLiveness, index: usize) {
        if matches!(liveness, ObserverLiveness::Blind) {
            self.abort(AbortReason::ObserverUnavailable, index, None);
        }
    }

    /// Classify a sourced event and abort on anything that is not ours.
    ///
    /// Hardware (pid 0) is the user. Another process's synthetic input is
    /// ALSO treated as the user, because on the desk it was: every scroll
    /// event in a 150-second window arrived from the Logi Options+ agent's
    /// pid and never from pid 0 -- the driver intercepts the wheel and
    /// re-posts it as synthetic. A rule that aborted only on pid 0 was blind
    /// to the user scrolling while we drove the cursor. So the only input
    /// that does not abort is our own; the classification is returned so the
    /// journal can say WHICH pid seized, and an operator can tell a driver
    /// utility from another agent after the fact.
    ///
    /// The cost is stated rather than hidden: another agent posting global
    /// synthetic input on the same desk aborts us. Two global drivers on one
    /// cursor are a collision either way, and stopping is the safe half of
    /// it. Per-process posts from another agent are believed not to reach a
    /// session tap at all; unmeasured, and noted.
    pub fn observe_sourced_input(
        &mut self,
        event: SourcedInputEvent,
        our_pid: i64,
        index: usize,
    ) -> SourcedInputKind {
        let kind = classify_sourced_input(event.source_unix_process_id, our_pid);
        if !matches!(kind, SourcedInputKind::OurProcess) {
            self.abort(
                AbortReason::UserSeizedControl,
                index,
                Some(event.detection_latency_ms),
            );
        }
        kind
    }
}

/// Bound within which a posted heartbeat marker must reappear in the observed
/// stream.
///
/// A listen-only tap whose callback was blocked for ten seconds still reported
/// itself enabled, so an enabled flag cannot detect a blind observer. Fifty
/// milliseconds is a starting point aligned with the existing seize-detection
/// latency default: if the observer cannot echo our own marker in that window,
/// it cannot abort on hardware either.
pub const OBSERVER_HEARTBEAT_BOUND_MS: u64 = 50;

/// Starting point for how long the desk must have been idle before an observed
/// post may go out, in milliseconds.
///
/// One second is a starting point, not a measured human-factors result: it is
/// long enough that a key still bouncing is "not idle", and short enough that
/// a pause between thoughts is not a lockout. The gate is evaluated at each
/// post against a reading handed in, never at grant time and never at sequence
/// start.
pub const OBSERVED_DISPATCH_IDLE_MS: u64 = 1_000;

/// `kCGEventSourceUnixProcessID` value treated as hardware input.
///
/// Synthetic posts carry our real non-zero pid at the tap. Hardware is
/// expected to carry 0; that arm has not been measured with a human at the
/// desk, and the abort still fires on this value. Our own events must not
/// fire it: a sequence that aborts on its own posts makes every abort test
/// pass for the wrong reason.
pub const HARDWARE_INPUT_SOURCE_PID: i64 = 0;

/// Identity of a marker the dispatcher posted so it can recognise the echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeartbeatMarker {
    pub nonce: u64,
}

impl HeartbeatMarker {
    pub const fn new(nonce: u64) -> Self {
        Self { nonce }
    }
}

/// The marker we posted, when we posted it, and which pid counts as ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatProbe {
    pub marker: HeartbeatMarker,
    pub posted_at_ms: u64,
    pub our_pid: i64,
}

/// Whether the observer saw the marker we posted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatObservation {
    /// The observer saw this marker, attributed to this pid, at this time.
    Seen {
        marker: HeartbeatMarker,
        source_unix_process_id: i64,
        observed_at_ms: u64,
    },
    /// Nothing matching the marker arrived.
    Missed,
}

/// Liveness derived from a heartbeat echo, not from a platform enabled flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverLiveness {
    Live,
    Blind,
}

/// Decide whether the observer saw our marker within the bound.
///
/// The echo must carry our pid, and that pid must be non-zero: a zero pid is
/// hardware, and treating it as our own heartbeat would make a live observer
/// indistinguishable from a user at the keys.
pub fn heartbeat_liveness(
    posted: HeartbeatProbe,
    observation: HeartbeatObservation,
) -> ObserverLiveness {
    if posted.our_pid == HARDWARE_INPUT_SOURCE_PID {
        return ObserverLiveness::Blind;
    }
    match observation {
        HeartbeatObservation::Seen {
            marker,
            source_unix_process_id,
            observed_at_ms,
        } if marker == posted.marker
            && source_unix_process_id == posted.our_pid
            && observed_at_ms >= posted.posted_at_ms
            && observed_at_ms.saturating_sub(posted.posted_at_ms)
                <= OBSERVER_HEARTBEAT_BOUND_MS =>
        {
            ObserverLiveness::Live
        }
        _ => ObserverLiveness::Blind,
    }
}

/// An observed input event carrying the source pid the tap attributed to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcedInputEvent {
    pub source_unix_process_id: i64,
    pub detection_latency_ms: u32,
}

/// How a sourced event relates to us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcedInputKind {
    Hardware,
    OurProcess,
    OtherProcess { pid: i64 },
}

/// Classify a source pid against ours.
///
/// The three kinds are kept distinct for the journal even though two of them
/// abort: which pid seized is the difference between "the user scrolled
/// through a driver utility" and "another agent is driving this desk", and
/// only the record can tell an operator which.
pub fn classify_sourced_input(source_unix_process_id: i64, our_pid: i64) -> SourcedInputKind {
    if source_unix_process_id == HARDWARE_INPUT_SOURCE_PID {
        SourcedInputKind::Hardware
    } else if source_unix_process_id == our_pid && our_pid != HARDWARE_INPUT_SOURCE_PID {
        SourcedInputKind::OurProcess
    } else {
        SourcedInputKind::OtherProcess {
            pid: source_unix_process_id,
        }
    }
}

/// Why the idle gate refused a post.
///
/// `BelowThreshold` carries both numbers so a caller can show why "non-idle"
/// was true rather than collapsing it to a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "idle")]
pub enum IdleGateRefusal {
    Unreadable(IdleUnreadable),
    BelowThreshold { threshold_ms: u64, observed_ms: u64 },
}

/// Check an idle reading against [`OBSERVED_DISPATCH_IDLE_MS`].
///
/// Unreadable refuses. Below the threshold refuses. Equal or above proceeds.
pub fn idle_gate(reading: IdleReading) -> Result<(), IdleGateRefusal> {
    match reading {
        IdleReading::Unreadable(reason) => Err(IdleGateRefusal::Unreadable(reason)),
        IdleReading::Milliseconds(observed) if observed < OBSERVED_DISPATCH_IDLE_MS => {
            Err(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                observed_ms: observed,
            })
        }
        IdleReading::Milliseconds(_) => Ok(()),
    }
}

/// Why an observed post did not go out.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObservedPostRefusal {
    ObserverBlind,
    Idle(IdleGateRefusal),
    FocusMismatch,
    AlreadyAborted(AbortReason),
}

/// Everything an observed post decides before the platform is asked to post,
/// in the order it decides it, with the platform calls handed in.
///
/// The order is the property: HEARTBEAT LIVENESS, then IDLE, then FOCUS, then
/// the post. Heartbeat first because a stalled tap still reports itself
/// enabled, and posting while blind means hardware input cannot abort us.
/// Idle next because a non-idle desk is the user present at the keys. Focus
/// before post because a mismatch means the events land in the wrong place.
/// The post must not have run if any prior gate refused. The platform calls
/// arrive as closures so this ordering compiles and is tested on every host;
/// nothing here posts to the seam.
pub fn dispatch_observed_post_in_order<H, I, F, P, T>(
    watcher: &mut SeizeWatcher,
    index: usize,
    posted: HeartbeatProbe,
    observe_heartbeat: H,
    read_idle: I,
    query_focus: F,
    post: P,
) -> Result<T, ObservedPostRefusal>
where
    H: FnOnce(&HeartbeatProbe) -> HeartbeatObservation,
    I: FnOnce() -> IdleReading,
    F: FnOnce() -> bool,
    P: FnOnce() -> T,
{
    if let Some(decision) = watcher.abort_decision() {
        return Err(ObservedPostRefusal::AlreadyAborted(decision.reason));
    }

    let observation = observe_heartbeat(&posted);
    let liveness = heartbeat_liveness(posted, observation);
    watcher.observe_heartbeat(liveness, index);
    if matches!(liveness, ObserverLiveness::Blind) {
        return Err(ObservedPostRefusal::ObserverBlind);
    }

    let idle_reading = read_idle();
    if let Err(refusal) = idle_gate(idle_reading) {
        watcher.abort(AbortReason::IdleGateRefused(refusal), index, None);
        return Err(ObservedPostRefusal::Idle(refusal));
    }

    if !query_focus() {
        watcher.abort(AbortReason::FocusMismatch, index, None);
        return Err(ObservedPostRefusal::FocusMismatch);
    }

    Ok(post())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const OUR_PID: i64 = 7282;
    const OTHER_PID: i64 = 99;

    fn probe(posted_at_ms: u64) -> HeartbeatProbe {
        HeartbeatProbe {
            marker: HeartbeatMarker::new(7),
            posted_at_ms,
            our_pid: OUR_PID,
        }
    }

    fn seen_at(posted: HeartbeatProbe, observed_at_ms: u64) -> HeartbeatObservation {
        HeartbeatObservation::Seen {
            marker: posted.marker,
            source_unix_process_id: posted.our_pid,
            observed_at_ms,
        }
    }

    fn idle_enough() -> IdleReading {
        IdleReading::Milliseconds(OBSERVED_DISPATCH_IDLE_MS + 100)
    }

    fn run_post<H, I, F, P, T>(
        watcher: &mut SeizeWatcher,
        observe_heartbeat: H,
        read_idle: I,
        query_focus: F,
        post: P,
    ) -> Result<T, ObservedPostRefusal>
    where
        H: FnOnce(&HeartbeatProbe) -> HeartbeatObservation,
        I: FnOnce() -> IdleReading,
        F: FnOnce() -> bool,
        P: FnOnce() -> T,
    {
        let posted = probe(0);
        dispatch_observed_post_in_order(
            watcher,
            0,
            posted,
            observe_heartbeat,
            read_idle,
            query_focus,
            post,
        )
    }

    #[test]
    fn heartbeat_not_observed_within_bound_is_blind_and_does_not_post() {
        let posted = probe(0);
        assert_eq!(
            heartbeat_liveness(posted, HeartbeatObservation::Missed),
            ObserverLiveness::Blind
        );
        assert_eq!(
            heartbeat_liveness(posted, seen_at(posted, OBSERVER_HEARTBEAT_BOUND_MS + 1),),
            ObserverLiveness::Blind
        );

        let mut watcher = SeizeWatcher::new(50);
        let posts = Cell::new(0u32);
        let refused = run_post(
            &mut watcher,
            |_| HeartbeatObservation::Missed,
            idle_enough,
            || true,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert_eq!(refused, Err(ObservedPostRefusal::ObserverBlind));
        assert_eq!(posts.get(), 0);
        assert!(!watcher.can_post());
        assert_eq!(
            watcher.abort_decision().unwrap().reason,
            AbortReason::ObserverUnavailable
        );
    }

    #[test]
    fn heartbeat_observed_within_bound_proceeds() {
        let posted = probe(10);
        assert_eq!(
            heartbeat_liveness(posted, seen_at(posted, 10)),
            ObserverLiveness::Live
        );
        assert_eq!(
            heartbeat_liveness(posted, seen_at(posted, 10 + OBSERVER_HEARTBEAT_BOUND_MS)),
            ObserverLiveness::Live
        );

        let mut watcher = SeizeWatcher::new(50);
        let posts = Cell::new(0u32);
        let accepted = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            idle_enough,
            || true,
            || {
                posts.set(posts.get() + 1);
                "posted"
            },
        );
        assert_eq!(accepted, Ok("posted"));
        assert_eq!(posts.get(), 1);
        assert!(watcher.can_post());
    }

    #[test]
    fn pid_zero_event_aborts_and_blocks_further_posts() {
        let mut watcher = SeizeWatcher::new(50);
        assert!(watcher.queue_post());
        assert!(watcher.queue_post());

        let kind = watcher.observe_sourced_input(
            SourcedInputEvent {
                source_unix_process_id: HARDWARE_INPUT_SOURCE_PID,
                detection_latency_ms: 2,
            },
            OUR_PID,
            1,
        );
        assert_eq!(kind, SourcedInputKind::Hardware);
        assert!(!watcher.can_post());
        assert_eq!(
            watcher.abort_decision().unwrap().reason,
            AbortReason::UserSeizedControl
        );
        assert!(!watcher.take_post_slot());

        let posts = Cell::new(0u32);
        let refused = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            idle_enough,
            || true,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert_eq!(
            refused,
            Err(ObservedPostRefusal::AlreadyAborted(
                AbortReason::UserSeizedControl
            ))
        );
        assert_eq!(posts.get(), 0);
        assert!(!watcher.can_post());
    }

    #[test]
    fn our_pid_event_does_not_abort() {
        let mut watcher = SeizeWatcher::new(50);
        let kind = watcher.observe_sourced_input(
            SourcedInputEvent {
                source_unix_process_id: OUR_PID,
                detection_latency_ms: 1,
            },
            OUR_PID,
            0,
        );
        assert_eq!(kind, SourcedInputKind::OurProcess);
        assert!(watcher.can_post());
        assert!(watcher.abort_decision().is_none());

        let posts = Cell::new(0u32);
        let accepted = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            idle_enough,
            || true,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert!(accepted.is_ok());
        assert_eq!(posts.get(), 1);
    }

    /// Another process's synthetic input aborts, and the journal still learns
    /// which process.
    ///
    /// Measured on the desk: the user's scroll wheel arrives from the Logi
    /// Options+ agent's pid, never from pid 0. The first version of this rule
    /// let other-pid input through as "not the user", and would have kept
    /// posting while the user scrolled.
    #[test]
    fn other_pid_event_aborts_and_is_still_attributed() {
        let mut watcher = SeizeWatcher::new(50);
        let kind = watcher.observe_sourced_input(
            SourcedInputEvent {
                source_unix_process_id: OTHER_PID,
                detection_latency_ms: 1,
            },
            OUR_PID,
            0,
        );
        assert_eq!(kind, SourcedInputKind::OtherProcess { pid: OTHER_PID });
        assert!(!watcher.can_post(), "another process's input did not abort");
        assert_eq!(
            watcher.abort_decision().map(|d| d.reason),
            Some(AbortReason::UserSeizedControl)
        );
    }

    #[test]
    fn unreadable_idle_refuses() {
        assert_eq!(
            idle_gate(IdleReading::Unreadable(IdleUnreadable::TableUnavailable)),
            Err(IdleGateRefusal::Unreadable(
                IdleUnreadable::TableUnavailable
            ))
        );

        let mut watcher = SeizeWatcher::new(50);
        let posts = Cell::new(0u32);
        let refused = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            || IdleReading::Unreadable(IdleUnreadable::TableUnavailable),
            || true,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert_eq!(
            refused,
            Err(ObservedPostRefusal::Idle(IdleGateRefusal::Unreadable(
                IdleUnreadable::TableUnavailable
            )))
        );
        assert_eq!(posts.get(), 0);
        assert!(!watcher.can_post());
    }

    #[test]
    fn idle_below_threshold_refuses_carrying_both_numbers() {
        let observed = OBSERVED_DISPATCH_IDLE_MS - 100;
        assert_eq!(
            idle_gate(IdleReading::Milliseconds(observed)),
            Err(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                observed_ms: observed,
            })
        );

        let mut watcher = SeizeWatcher::new(50);
        let posts = Cell::new(0u32);
        let refused = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            || IdleReading::Milliseconds(observed),
            || true,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert_eq!(
            refused,
            Err(ObservedPostRefusal::Idle(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                observed_ms: observed,
            }))
        );
        assert_eq!(posts.get(), 0);
    }

    #[test]
    fn idle_above_threshold_proceeds() {
        assert_eq!(idle_gate(idle_enough()), Ok(()));

        let mut watcher = SeizeWatcher::new(50);
        let posts = Cell::new(0u32);
        let accepted = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            idle_enough,
            || true,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert!(accepted.is_ok());
        assert_eq!(posts.get(), 1);
    }

    #[test]
    fn focus_mismatch_does_not_call_the_post() {
        let mut watcher = SeizeWatcher::new(50);
        let posts = Cell::new(0u32);
        let refused = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            idle_enough,
            || false,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert_eq!(refused, Err(ObservedPostRefusal::FocusMismatch));
        assert_eq!(posts.get(), 0);
        assert!(!watcher.can_post());
        assert_eq!(
            watcher.abort_decision().unwrap().reason,
            AbortReason::FocusMismatch
        );
    }

    #[test]
    fn observed_post_gates_run_heartbeat_then_idle_then_focus_then_post() {
        let order = RefCell::new(Vec::new());
        let mut watcher = SeizeWatcher::new(50);
        let accepted = run_post(
            &mut watcher,
            |posted| {
                order.borrow_mut().push("heartbeat");
                seen_at(*posted, posted.posted_at_ms)
            },
            || {
                order.borrow_mut().push("idle");
                idle_enough()
            },
            || {
                order.borrow_mut().push("focus");
                true
            },
            || {
                order.borrow_mut().push("post");
            },
        );
        assert!(accepted.is_ok());
        assert_eq!(*order.borrow(), ["heartbeat", "idle", "focus", "post"]);
    }

    #[test]
    fn existing_enabled_flag_liveness_still_aborts_when_any_channel_is_down() {
        let mut watcher = SeizeWatcher::new(50);
        watcher.observe_liveness(
            SeizeWatcherState {
                session_tap_live: true,
                raw_hid_live: false,
                self_echo_filter_live: true,
            },
            0,
        );
        assert!(!watcher.can_post());
        assert_eq!(
            watcher.abort_decision().unwrap().reason,
            AbortReason::ObserverUnavailable
        );
    }
}
