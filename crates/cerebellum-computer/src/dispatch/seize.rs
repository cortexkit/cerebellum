//! The observed-mode abort guard.
//!
//! A stalled tap still reports itself enabled, so observer liveness is derived
//! from a heartbeat: the dispatcher posts a marker and requires the observer to
//! have seen it (our pid, non-zero) within a bound. Hardware input is pid 0;
//! our own posts must not abort us. Once the guard records an abort, queued
//! work is cancelled and the guard never permits another post.

use crate::platform::{IdleReading, IdleUnreadable, InputObservationResult, InputObserverLiveness};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

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
    /// Carries the refusal, because "not idle" without the threshold, raw HID
    /// idle, and attributed user idle cannot tell an operator why it was true.
    IdleGateRefused(IdleGateRefusal),
    FocusMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortDecision {
    pub reason: AbortReason,
    pub stopped_action_index: usize,
    pub detection_latency_ms: Option<u32>,
    /// Which source seized control when the tap supplied source attribution.
    pub sourced_input_kind: Option<SourcedInputKind>,
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
            sourced_input_kind: None,
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
        if !matches!(kind, SourcedInputKind::OurProcess) && self.abort.is_none() {
            self.abort(
                AbortReason::UserSeizedControl,
                index,
                Some(event.detection_latency_ms),
            );
            if let Some(abort) = self.abort.as_mut() {
                abort.sourced_input_kind = Some(kind);
            }
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
/// sequence may post, in milliseconds.
///
/// One second is a starting point, not a measured human-factors result: it is
/// long enough that a key still bouncing is "not idle", and short enough that
/// a pause between thoughts is not a lockout. The gate is evaluated once per
/// sequence, before the heartbeat is posted, against the user idle the
/// estimator reports. Between posts the seize watcher aborts on any non-self
/// event. Never at grant time.
pub const OBSERVED_DISPATCH_IDLE_MS: u64 = 1_000;

/// How late a session-tap post may appear in the HID idle table, in milliseconds.
///
/// The table updates when the window server processes the event, not when we
/// post. One hundred milliseconds is the measured lag rounded up. It is a bound
/// on our own event's appearance in that table, not on how close a human event
/// may be to ours; the session tap, which attributes source pid, is that
/// discriminator, and it is held for this long after the last post so a late
/// echo of our own event is not mistaken for a later hardware event.
pub const HID_IDLE_TABLE_LAG_MS: u64 = 100;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "source")]
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
/// `BelowThreshold` carries the raw HID reading and the attributed user idle
/// so a caller can see which value the gate interpreted rather than receiving
/// only a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "idle")]
pub enum IdleGateRefusal {
    Unreadable(IdleUnreadable),
    BelowThreshold {
        threshold_ms: u64,
        hid_idle_ms: u64,
        user_idle_ms: u64,
    },
}

/// Check an idle reading against [`OBSERVED_DISPATCH_IDLE_MS`].
///
/// Unreadable refuses. Below the threshold refuses. Equal or above proceeds.
pub fn idle_gate(reading: IdleReading) -> Result<(), IdleGateRefusal> {
    idle_gate_with_hid(reading, reading)
}

fn idle_gate_with_hid(
    hid_idle: IdleReading,
    user_idle: IdleReading,
) -> Result<(), IdleGateRefusal> {
    match (hid_idle, user_idle) {
        (_, IdleReading::Unreadable(reason))
        | (IdleReading::Unreadable(reason), IdleReading::Milliseconds(_)) => {
            Err(IdleGateRefusal::Unreadable(reason))
        }
        (IdleReading::Milliseconds(hid_idle_ms), IdleReading::Milliseconds(user_idle_ms))
            if user_idle_ms < OBSERVED_DISPATCH_IDLE_MS =>
        {
            Err(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                hid_idle_ms,
                user_idle_ms,
            })
        }
        (IdleReading::Milliseconds(_), IdleReading::Milliseconds(_)) => Ok(()),
    }
}

/// Reconstructs time since the last hardware input after we have posted.
///
/// The HID idle table counts our session-tap posts as input, so a raw reading
/// taken after we have posted is the age of our own event, not the user's.
/// This estimator carries the user idle established at the previous sequence
/// (idle at that start plus that sequence's duration) across sequences, and
/// only believes the raw table when it is strictly younger than our last post
/// by more than [`HID_IDLE_TABLE_LAG_MS`]: that is a hardware event that landed
/// after we stopped watching. Carry is recorded only when the session tap saw
/// zero non-self events through the post tail. During a sequence the tap is
/// the discriminator; this type is only the across-sequence memory.
#[derive(Debug, Clone)]
pub struct UserIdleEstimator {
    last_post_at: Option<Instant>,
    idle_carried: Option<u64>,
    tolerance_ms: u64,
}

impl Default for UserIdleEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl UserIdleEstimator {
    pub fn new() -> Self {
        Self {
            last_post_at: None,
            idle_carried: None,
            tolerance_ms: HID_IDLE_TABLE_LAG_MS,
        }
    }

    /// User idle at `now`, given a HID table reading taken at the same instant.
    ///
    /// Unreadable stays unreadable: inventing a number would pass or fail the
    /// gate for the wrong reason. With no prior post there is nothing to carry,
    /// so the raw reading stands.
    pub fn user_idle(&self, hid_idle: IdleReading, now: Instant) -> IdleReading {
        match hid_idle {
            IdleReading::Unreadable(reason) => IdleReading::Unreadable(reason),
            IdleReading::Milliseconds(hid_ms) => match (self.last_post_at, self.idle_carried) {
                (Some(last_post_at), Some(idle_carried)) => {
                    let since_post_ms = duration_ms(now.saturating_duration_since(last_post_at));
                    if hid_ms < since_post_ms.saturating_sub(self.tolerance_ms) {
                        IdleReading::Milliseconds(hid_ms)
                    } else {
                        IdleReading::Milliseconds(idle_carried.saturating_add(since_post_ms))
                    }
                }
                _ => IdleReading::Milliseconds(hid_ms),
            },
        }
    }

    /// Remember a fully observed sequence so the next one can distinguish our
    /// last post from later hardware input.
    ///
    /// `duration` runs from the idle reading to `last_post_at`; time after that
    /// post is added by [`Self::user_idle`] at the next sequence start.
    pub fn sequence_finished(
        &mut self,
        last_post_at: Instant,
        user_idle_at_start: IdleReading,
        duration: Duration,
    ) {
        let IdleReading::Milliseconds(start_ms) = user_idle_at_start else {
            self.clear_carry();
            return;
        };
        self.last_post_at = Some(last_post_at);
        self.idle_carried = Some(start_ms.saturating_add(duration_ms(duration)));
    }

    /// Drop the carry when the tap saw hardware or could not observe the whole
    /// sequence through the post tail.
    pub fn clear_carry(&mut self) {
        self.last_post_at = None;
        self.idle_carried = None;
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Instant at which the post tail closes: [`HID_IDLE_TABLE_LAG_MS`] after the
/// last global post. Events after this are not in the watched window.
pub fn observed_tail_deadline(last_post_at: Instant) -> Instant {
    last_post_at + Duration::from_millis(HID_IDLE_TABLE_LAG_MS)
}

/// Whether a sourced event is our own post.
pub fn event_is_ours(event: SourcedInputEvent, our_pid: i64) -> bool {
    matches!(
        classify_sourced_input(event.source_unix_process_id, our_pid),
        SourcedInputKind::OurProcess
    )
}

/// Whether any drained event is not ours.
///
/// Used for the post tail, which decides whether to carry idle into the next
/// sequence rather than aborting posts that have already gone out.
pub fn non_self_seen(events: impl IntoIterator<Item = SourcedInputEvent>, our_pid: i64) -> bool {
    events
        .into_iter()
        .any(|event| !event_is_ours(event, our_pid))
}

/// Feed drained tap events to the watcher.
///
/// Returns whether a non-self event was among them. Our own pid is ignored:
/// the tap sees our posts, and those must not count as the user.
pub fn observe_drained_events(
    watcher: &mut SeizeWatcher,
    events: impl IntoIterator<Item = SourcedInputEvent>,
    our_pid: i64,
    index: usize,
) -> bool {
    let mut hardware_seen = false;
    for event in events {
        if !event_is_ours(event, our_pid) {
            hardware_seen = true;
        }
        watcher.observe_sourced_input(event, our_pid, index);
    }
    hardware_seen
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
/// The order is the property: HEARTBEAT LIVENESS, then FOCUS, then the post.
/// Heartbeat first because a stalled tap still reports itself enabled, and
/// posting while blind means hardware input cannot abort us. Focus before post
/// because a mismatch means the events land in the wrong place. Idle is not
/// here: it is read once per sequence, before the heartbeat is posted, because
/// a re-read after our own post can only ever see the age of that post. The
/// post must not have run if any prior gate refused. The platform calls arrive
/// as closures so this ordering compiles and is tested on every host; nothing
/// here posts to the seam.
pub fn dispatch_observed_post_in_order<H, F, P, T>(
    watcher: &mut SeizeWatcher,
    index: usize,
    posted: HeartbeatProbe,
    observe_heartbeat: H,
    query_focus: F,
    post: P,
) -> Result<T, ObservedPostRefusal>
where
    H: FnOnce(&HeartbeatProbe) -> HeartbeatObservation,
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

    if !query_focus() {
        watcher.abort(AbortReason::FocusMismatch, index, None);
        return Err(ObservedPostRefusal::FocusMismatch);
    }

    Ok(post())
}

/// Closures that start an observed sequence, in the order they are called.
pub struct ObservedSequenceHooks<CreateTap, ReadIdle, Drain, PostHeartbeat> {
    pub create_tap: CreateTap,
    pub read_idle: ReadIdle,
    pub drain: Drain,
    pub post_heartbeat: PostHeartbeat,
}

/// Start an observed sequence: create the tap, read idle, gate, drain, then
/// post the heartbeat.
///
/// The order is the property. The tap must exist before the idle read so a
/// hardware event between the read and the heartbeat is visible. The idle read
/// must precede the heartbeat because a session-tap post lands in the HID table
/// and would make the table report the age of our own marker. A non-self event
/// drained in that window aborts without posting the heartbeat.
pub fn begin_observed_sequence<CreateTap, ReadIdle, Drain, PostHeartbeat, Tap, Marker>(
    estimator: &UserIdleEstimator,
    watcher: &mut SeizeWatcher,
    our_pid: i64,
    idle_read_at: Instant,
    hooks: ObservedSequenceHooks<CreateTap, ReadIdle, Drain, PostHeartbeat>,
) -> Result<(Tap, IdleReading, Marker), ObservedPostRefusal>
where
    CreateTap: FnOnce() -> Tap,
    ReadIdle: FnOnce() -> IdleReading,
    Drain: FnOnce(&Tap) -> Vec<SourcedInputEvent>,
    PostHeartbeat: FnOnce() -> Marker,
{
    if let Some(decision) = watcher.abort_decision() {
        return Err(ObservedPostRefusal::AlreadyAborted(decision.reason));
    }

    let tap = (hooks.create_tap)();
    let hid_idle = (hooks.read_idle)();
    let user_idle = estimator.user_idle(hid_idle, idle_read_at);
    if let Err(refusal) = idle_gate_with_hid(hid_idle, user_idle) {
        watcher.abort(AbortReason::IdleGateRefused(refusal), 0, None);
        return Err(ObservedPostRefusal::Idle(refusal));
    }
    if observe_drained_events(watcher, (hooks.drain)(&tap), our_pid, 0) {
        let reason = watcher
            .abort_decision()
            .map(|d| d.reason)
            .unwrap_or(AbortReason::UserSeizedControl);
        return Err(ObservedPostRefusal::AlreadyAborted(reason));
    }
    let marker = (hooks.post_heartbeat)();
    Ok((tap, user_idle, marker))
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

    fn run_post<H, F, P, T>(
        watcher: &mut SeizeWatcher,
        observe_heartbeat: H,
        query_focus: F,
        post: P,
    ) -> Result<T, ObservedPostRefusal>
    where
        H: FnOnce(&HeartbeatProbe) -> HeartbeatObservation,
        F: FnOnce() -> bool,
        P: FnOnce() -> T,
    {
        let posted = probe(0);
        dispatch_observed_post_in_order(watcher, 0, posted, observe_heartbeat, query_focus, post)
    }

    fn instant_ago(ms: u64) -> (Instant, Instant) {
        let now = Instant::now();
        let past = now
            .checked_sub(Duration::from_millis(ms))
            .expect("test clock is more than a few hundred milliseconds past epoch");
        (past, now)
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
        let heartbeat_posted = Cell::new(false);
        let refused = begin_observed_sequence(
            &UserIdleEstimator::new(),
            &mut watcher,
            OUR_PID,
            Instant::now(),
            ObservedSequenceHooks {
                create_tap: || (),
                read_idle: || IdleReading::Unreadable(IdleUnreadable::TableUnavailable),
                drain: |_: &()| Vec::new(),
                post_heartbeat: || {
                    heartbeat_posted.set(true);
                },
            },
        );
        assert_eq!(
            refused.map(|_| ()),
            Err(ObservedPostRefusal::Idle(IdleGateRefusal::Unreadable(
                IdleUnreadable::TableUnavailable
            )))
        );
        assert!(!heartbeat_posted.get());
        assert!(!watcher.can_post());
    }

    #[test]
    fn idle_below_threshold_refuses_carrying_both_numbers() {
        let observed = OBSERVED_DISPATCH_IDLE_MS - 100;
        assert_eq!(
            idle_gate(IdleReading::Milliseconds(observed)),
            Err(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                hid_idle_ms: observed,
                user_idle_ms: observed,
            })
        );

        let mut watcher = SeizeWatcher::new(50);
        let heartbeat_posted = Cell::new(false);
        let refused = begin_observed_sequence(
            &UserIdleEstimator::new(),
            &mut watcher,
            OUR_PID,
            Instant::now(),
            ObservedSequenceHooks {
                create_tap: || (),
                read_idle: || IdleReading::Milliseconds(observed),
                drain: |_: &()| Vec::new(),
                post_heartbeat: || {
                    heartbeat_posted.set(true);
                },
            },
        );
        assert_eq!(
            refused.map(|_| ()),
            Err(ObservedPostRefusal::Idle(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                hid_idle_ms: observed,
                user_idle_ms: observed,
            }))
        );
        assert!(!heartbeat_posted.get());
        assert!(!watcher.can_post());
    }

    #[test]
    fn idle_refusal_keeps_raw_and_attributed_values_distinct() {
        assert_eq!(
            idle_gate_with_hid(
                IdleReading::Milliseconds(320),
                IdleReading::Milliseconds(120),
            ),
            Err(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                hid_idle_ms: 320,
                user_idle_ms: 120,
            })
        );
    }

    #[test]
    fn idle_above_threshold_proceeds() {
        assert_eq!(idle_gate(idle_enough()), Ok(()));

        let mut watcher = SeizeWatcher::new(50);
        let heartbeat_posted = Cell::new(false);
        let accepted = begin_observed_sequence(
            &UserIdleEstimator::new(),
            &mut watcher,
            OUR_PID,
            Instant::now(),
            ObservedSequenceHooks {
                create_tap: || (),
                read_idle: idle_enough,
                drain: |_: &()| Vec::new(),
                post_heartbeat: || {
                    heartbeat_posted.set(true);
                },
            },
        );
        assert!(accepted.is_ok());
        assert!(heartbeat_posted.get());
        assert!(watcher.can_post());

        let posts = Cell::new(0u32);
        let posted = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
            || true,
            || {
                posts.set(posts.get() + 1);
            },
        );
        assert!(posted.is_ok());
        assert_eq!(posts.get(), 1);
    }

    #[test]
    fn focus_mismatch_does_not_call_the_post() {
        let mut watcher = SeizeWatcher::new(50);
        let posts = Cell::new(0u32);
        let refused = run_post(
            &mut watcher,
            |posted| seen_at(*posted, posted.posted_at_ms),
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
    fn observed_post_gates_run_heartbeat_then_focus_then_post() {
        let order = RefCell::new(Vec::new());
        let mut watcher = SeizeWatcher::new(50);
        let accepted = run_post(
            &mut watcher,
            |posted| {
                order.borrow_mut().push("heartbeat");
                seen_at(*posted, posted.posted_at_ms)
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
        assert_eq!(*order.borrow(), ["heartbeat", "focus", "post"]);
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

    fn hardware_event() -> SourcedInputEvent {
        SourcedInputEvent {
            source_unix_process_id: HARDWARE_INPUT_SOURCE_PID,
            detection_latency_ms: 1,
        }
    }

    fn our_event() -> SourcedInputEvent {
        SourcedInputEvent {
            source_unix_process_id: OUR_PID,
            detection_latency_ms: 1,
        }
    }

    fn other_event() -> SourcedInputEvent {
        SourcedInputEvent {
            source_unix_process_id: OTHER_PID,
            detection_latency_ms: 1,
        }
    }

    struct SequenceScript {
        hid_idle: IdleReading,
        between_idle_and_heartbeat: Vec<SourcedInputEvent>,
        during_posts: Vec<SourcedInputEvent>,
        /// Offset from the last post. Only events at or before the tail
        /// deadline are drained; later ones are not in the watched window.
        tail: Vec<(Duration, SourcedInputEvent)>,
        post_count: usize,
        echo_own_posts: bool,
    }

    impl Default for SequenceScript {
        fn default() -> Self {
            Self {
                hid_idle: idle_enough(),
                between_idle_and_heartbeat: Vec::new(),
                during_posts: Vec::new(),
                tail: Vec::new(),
                post_count: 1,
                echo_own_posts: false,
            }
        }
    }

    struct SequenceOutcome {
        result: Result<u32, ObservedPostRefusal>,
        order: Vec<&'static str>,
        idle_reads: u32,
        heartbeat_posts: u32,
        hardware_seen: bool,
    }

    fn run_sequence(
        estimator: &mut UserIdleEstimator,
        started: Instant,
        script: SequenceScript,
    ) -> SequenceOutcome {
        let order = RefCell::new(Vec::new());
        let idle_reads = Cell::new(0u32);
        let heartbeat_posts = Cell::new(0u32);
        let action_posts = Cell::new(0u32);
        let mut watcher = SeizeWatcher::new(50);
        let mut hardware_seen = false;
        let between = script.between_idle_and_heartbeat.clone();
        let during = script.during_posts.clone();
        let tail = script.tail.clone();
        let echo_own_posts = script.echo_own_posts;
        let post_count = script.post_count;
        let hid_idle = script.hid_idle;

        let begin = begin_observed_sequence(
            estimator,
            &mut watcher,
            OUR_PID,
            started,
            ObservedSequenceHooks {
                create_tap: || {
                    order.borrow_mut().push("tap");
                },
                read_idle: || {
                    order.borrow_mut().push("idle");
                    idle_reads.set(idle_reads.get() + 1);
                    hid_idle
                },
                drain: |_: &()| between,
                post_heartbeat: || {
                    order.borrow_mut().push("heartbeat");
                    heartbeat_posts.set(heartbeat_posts.get() + 1);
                    probe(0)
                },
            },
        );

        let (user_idle, posted) = match begin {
            Ok((_, user_idle, posted)) => {
                if echo_own_posts {
                    let _ = observe_drained_events(&mut watcher, [our_event()], OUR_PID, 0);
                }
                (user_idle, posted)
            }
            Err(refusal) => {
                return SequenceOutcome {
                    result: Err(refusal),
                    order: order.into_inner(),
                    idle_reads: idle_reads.get(),
                    heartbeat_posts: heartbeat_posts.get(),
                    hardware_seen,
                };
            }
        };

        for index in 0..post_count {
            if observe_drained_events(&mut watcher, during.clone(), OUR_PID, index) {
                hardware_seen = true;
            }
            if echo_own_posts {
                let _ = observe_drained_events(&mut watcher, [our_event()], OUR_PID, index);
            }
            if let Err(error) = dispatch_observed_post_in_order(
                &mut watcher,
                index,
                posted,
                |probe| seen_at(*probe, probe.posted_at_ms),
                || true,
                || {
                    order.borrow_mut().push("post");
                    action_posts.set(action_posts.get() + 1);
                },
            ) {
                if hardware_seen {
                    estimator.clear_carry();
                } else {
                    estimator.sequence_finished(started, user_idle, Duration::ZERO);
                }
                return SequenceOutcome {
                    result: Err(error),
                    order: order.into_inner(),
                    idle_reads: idle_reads.get(),
                    heartbeat_posts: heartbeat_posts.get(),
                    hardware_seen,
                };
            }
        }

        // The tail drain is the watched window after the last post. Dropping
        // it would let a hardware event 40 ms later ride into the next
        // sequence as if the desk were still idle.
        let last = started;
        let deadline = observed_tail_deadline(last);
        let tail_events: Vec<_> = tail
            .into_iter()
            .filter(|(offset, _)| last + *offset <= deadline)
            .map(|(_, event)| event)
            .collect();
        if non_self_seen(tail_events, OUR_PID) {
            hardware_seen = true;
        }
        if hardware_seen {
            estimator.clear_carry();
        } else {
            estimator.sequence_finished(last, user_idle, Duration::ZERO);
        }
        SequenceOutcome {
            result: Ok(action_posts.get()),
            order: order.into_inner(),
            idle_reads: idle_reads.get(),
            heartbeat_posts: heartbeat_posts.get(),
            hardware_seen,
        }
    }

    #[test]
    fn our_own_post_is_not_user_input() {
        let (last_post_at, now) = instant_ago(300);
        let mut estimator = UserIdleEstimator::new();
        estimator.sequence_finished(
            last_post_at,
            IdleReading::Milliseconds(5_000),
            Duration::ZERO,
        );
        let user = estimator.user_idle(IdleReading::Milliseconds(320), now);
        assert_eq!(
            user,
            IdleReading::Milliseconds(5_300),
            "raw HID idle of 320 ms is the age of our own post, not the user"
        );
        assert_eq!(idle_gate(user), Ok(()));
    }

    #[test]
    fn a_hardware_event_after_our_post_is_user_input() {
        let (last_post_at, now) = instant_ago(300);
        let mut estimator = UserIdleEstimator::new();
        estimator.sequence_finished(
            last_post_at,
            IdleReading::Milliseconds(5_000),
            Duration::ZERO,
        );
        let user = estimator.user_idle(IdleReading::Milliseconds(120), now);
        assert_eq!(
            user,
            IdleReading::Milliseconds(120),
            "HID idle younger than our post by more than the table lag is hardware"
        );
        assert_eq!(
            idle_gate(user),
            Err(IdleGateRefusal::BelowThreshold {
                threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
                hid_idle_ms: 120,
                user_idle_ms: 120,
            })
        );
    }

    #[test]
    fn first_sequence_has_no_carry() {
        let estimator = UserIdleEstimator::new();
        let now = Instant::now();
        let young = estimator.user_idle(IdleReading::Milliseconds(40), now);
        assert_eq!(young, IdleReading::Milliseconds(40));
        assert!(idle_gate(young).is_err());
        let old = estimator.user_idle(IdleReading::Milliseconds(4_000), now);
        assert_eq!(old, IdleReading::Milliseconds(4_000));
        assert_eq!(idle_gate(old), Ok(()));
    }

    #[test]
    fn idle_is_read_before_the_heartbeat_is_posted() {
        let mut estimator = UserIdleEstimator::new();
        let outcome = run_sequence(&mut estimator, Instant::now(), SequenceScript::default());
        assert!(outcome.result.is_ok());
        let idle = outcome
            .order
            .iter()
            .position(|step| *step == "idle")
            .expect("idle was not read");
        let heartbeat = outcome
            .order
            .iter()
            .position(|step| *step == "heartbeat")
            .expect("heartbeat was not posted");
        assert!(
            idle < heartbeat,
            "heartbeat ran before idle: {:?}",
            outcome.order
        );
    }

    #[test]
    fn tap_is_created_before_the_idle_read() {
        let mut estimator = UserIdleEstimator::new();
        let outcome = run_sequence(&mut estimator, Instant::now(), SequenceScript::default());
        assert!(outcome.result.is_ok());
        let tap = outcome
            .order
            .iter()
            .position(|step| *step == "tap")
            .expect("tap was not created");
        let idle = outcome
            .order
            .iter()
            .position(|step| *step == "idle")
            .expect("idle was not read");
        assert!(
            tap < idle,
            "idle ran before tap create: {:?}",
            outcome.order
        );
    }

    #[test]
    fn no_per_post_idle_reread() {
        let mut estimator = UserIdleEstimator::new();
        let outcome = run_sequence(
            &mut estimator,
            Instant::now(),
            SequenceScript {
                post_count: 3,
                ..SequenceScript::default()
            },
        );
        assert_eq!(outcome.result, Ok(3));
        assert_eq!(
            outcome.idle_reads, 1,
            "idle was re-read per post: {} reads for 3 posts",
            outcome.idle_reads
        );
    }

    #[test]
    fn a_hardware_event_between_the_idle_read_and_the_heartbeat_aborts() {
        let mut estimator = UserIdleEstimator::new();
        let outcome = run_sequence(
            &mut estimator,
            Instant::now(),
            SequenceScript {
                between_idle_and_heartbeat: vec![hardware_event()],
                ..SequenceScript::default()
            },
        );
        assert_eq!(
            outcome.result,
            Err(ObservedPostRefusal::AlreadyAborted(
                AbortReason::UserSeizedControl
            ))
        );
        assert_eq!(
            outcome.heartbeat_posts, 0,
            "heartbeat posted after hardware"
        );
    }

    #[test]
    fn a_hardware_event_in_the_post_tail_clears_the_carry() {
        let mut estimator = UserIdleEstimator::new();
        let started = Instant::now();
        let outcome = run_sequence(
            &mut estimator,
            started,
            SequenceScript {
                tail: vec![(Duration::from_millis(40), hardware_event())],
                ..SequenceScript::default()
            },
        );
        assert_eq!(
            outcome.result,
            Ok(1),
            "tail hardware must not abort the sequence"
        );
        assert!(outcome.hardware_seen);
        let later = started + Duration::from_millis(40);
        let user = estimator.user_idle(IdleReading::Milliseconds(40), later);
        assert_eq!(
            user,
            IdleReading::Milliseconds(40),
            "tail hardware left a carry, so the next sequence treated our desk as idle"
        );
        assert!(idle_gate(user).is_err());
    }

    #[test]
    fn own_posts_seen_by_the_tap_do_not_count() {
        let mut estimator = UserIdleEstimator::new();
        let started = Instant::now();
        let outcome = run_sequence(
            &mut estimator,
            started,
            SequenceScript {
                echo_own_posts: true,
                post_count: 2,
                ..SequenceScript::default()
            },
        );
        assert_eq!(outcome.result, Ok(2));
        assert!(!outcome.hardware_seen);
        let later = started + Duration::from_millis(300);
        let user = estimator.user_idle(IdleReading::Milliseconds(320), later);
        assert_eq!(
            user,
            IdleReading::Milliseconds(idle_enough_ms() + 300),
            "our own tap echoes cleared the carry"
        );
        assert_eq!(idle_gate(user), Ok(()));
    }

    fn idle_enough_ms() -> u64 {
        OBSERVED_DISPATCH_IDLE_MS + 100
    }

    #[test]
    fn a_non_self_event_inside_the_window_aborts() {
        let mut estimator = UserIdleEstimator::new();
        let outcome = run_sequence(
            &mut estimator,
            Instant::now(),
            SequenceScript {
                during_posts: vec![other_event()],
                ..SequenceScript::default()
            },
        );
        assert_eq!(
            outcome.result,
            Err(ObservedPostRefusal::AlreadyAborted(
                AbortReason::UserSeizedControl
            )),
            "a tap that counted every pid as ours would have posted"
        );
    }

    #[test]
    fn a_non_self_event_after_the_tail_clears_the_carry_without_aborting() {
        let mut estimator = UserIdleEstimator::new();
        let started = Instant::now();
        let outcome = run_sequence(
            &mut estimator,
            started,
            SequenceScript {
                tail: vec![(Duration::from_millis(200), other_event())],
                ..SequenceScript::default()
            },
        );
        assert_eq!(
            outcome.result,
            Ok(1),
            "an event after the tail aborted the sequence"
        );
        assert!(
            !outcome.hardware_seen,
            "an event 200 ms after the last post was treated as inside the tail"
        );
        // Carry survived the tail. A HID reading that still looks like our
        // post (within the table lag) must keep it; one strictly younger than
        // the post by more than the lag is the hardware event after we left.
        let still_ours = started + Duration::from_millis(50);
        assert_eq!(
            estimator.user_idle(IdleReading::Milliseconds(50), still_ours),
            IdleReading::Milliseconds(idle_enough_ms() + 50),
        );
        let after_tail = started + Duration::from_millis(200);
        let user = estimator.user_idle(IdleReading::Milliseconds(50), after_tail);
        assert_eq!(user, IdleReading::Milliseconds(50));
        assert!(idle_gate(user).is_err());
    }
}
