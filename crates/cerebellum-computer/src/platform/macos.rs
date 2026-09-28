//! macOS 26 startup and capability skeleton.
//!
//! The probe is intentionally data-driven so conformance can exercise stale
//! grants and envelope drift without linking macOS frameworks on other hosts.

use super::*;
use crate::dispatch::{
    begin_observed_sequence, dispatch_observed_post_in_order, event_is_ours,
    observed_tail_deadline, AbortReason, HeartbeatMarker, HeartbeatObservation, HeartbeatProbe,
    ObservedPostRefusal, ObservedSequenceHooks, SeizeWatcher, SourcedInputEvent, UserIdleEstimator,
    OBSERVER_HEARTBEAT_BOUND_MS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MACOS_MAJOR_VERSION: u16 = 26;
pub const PRIVATE_ENVELOPE_REVISION: &str = "skylight-macos26-v1";
pub const PRIVATE_PID_POST_SYMBOL: &str = "SLEventPostToPid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupProbeInput {
    pub os_major: u16,
    pub private_envelope_revision: Option<String>,
    pub resolved_private_symbols: BTreeSet<String>,
    pub permission_results: Vec<PermissionProbeResult>,
    /// The process this system attributes our permission grants to, resolved at
    /// runtime rather than assumed, and `None` until it has been.
    ///
    /// It is NOT this module. macOS attributes a grant to the process
    /// responsible for launching ours, so for a daemon-launched module the
    /// grants belong to the daemon, and a probe reporting that truthfully has
    /// to be counted rather than discarded. Naming a fixed process here would
    /// suppress every capability that depends on a grant, silently and
    /// permanently.
    ///
    /// `None` means the attribution has not been established, which is not the
    /// same as knowing it and finding no match: an unestablished attribution
    /// admits no probe result at all, because a grant cannot be credited to a
    /// process nobody has identified.
    pub responsible_process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateEnvelopeStartupProbe {
    pub expected_os_major: u16,
    pub expected_revision: &'static str,
    pub required_symbols: &'static [&'static str],
}

impl Default for PrivateEnvelopeStartupProbe {
    fn default() -> Self {
        Self {
            expected_os_major: MACOS_MAJOR_VERSION,
            expected_revision: PRIVATE_ENVELOPE_REVISION,
            required_symbols: &[PRIVATE_PID_POST_SYMBOL],
        }
    }
}

impl PrivateEnvelopeStartupProbe {
    pub fn run(&self, input: &StartupProbeInput) -> bool {
        input.os_major == self.expected_os_major
            && input.private_envelope_revision.as_deref() == Some(self.expected_revision)
            && self
                .required_symbols
                .iter()
                .all(|symbol| input.resolved_private_symbols.contains(*symbol))
    }
}

impl StartupCapabilityProbe {
    pub fn run(input: &StartupProbeInput) -> Self {
        let envelope = PrivateEnvelopeStartupProbe::default();
        let permissions = attributed_permission_liveness(
            input.responsible_process.as_deref(),
            &input.permission_results,
        );
        Self {
            os_major: input.os_major,
            private_envelope_recognized: envelope.run(input),
            permissions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedAccessibilityElement {
    identifier: Option<String>,
    role: Option<String>,
    title: Option<String>,
    actions: Vec<String>,
    children: Vec<CachedAccessibilityElement>,
}

#[derive(Debug, Clone)]
struct CachedAccessibilityTree {
    target: ProcessGrant,
    tree: CachedAccessibilityElement,
    unreadable_subtrees: usize,
}

const AMBIGUOUS_ELEMENT_NAME: &str =
    "more than one element matches the supplied accessibility name";
const UNUSABLE_ELEMENT_NAME: &str = "unusable accessibility element name";

#[derive(Debug, Clone)]
pub struct MacOs26PlatformDriver {
    startup: StartupCapabilityProbe,
    accessibility_trees: BTreeMap<String, CachedAccessibilityTree>,
    expected_post_condition_available: bool,
    global_dispatch_review_revision: Option<String>,
    /// The review that admits the fronting bracket. Bringing an application
    /// forward can take the person's keystrokes, so the driver refuses the
    /// bracket itself without it, whatever its caller decided.
    takeover_dispatch_review_revision: Option<String>,
    /// Shared across every driver the plane builds. The plane builds a driver
    /// per dispatch (its accessibility cache must not outlive a process
    /// generation), but the idle estimator's whole purpose is to remember the
    /// PREVIOUS sequence's posts at the next sequence's start; an estimator
    /// that dies with the request never carries, and a move followed by a
    /// drag is refused as not_idle on the age of the move's own last post.
    /// Measured on the VM: user_idle == hid_idle on every second action.
    user_idle: Arc<Mutex<UserIdleEstimator>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessibilityReaderFailure {
    PermissionDenied,
    ProcessGone,
    ProcessNotInspectable,
    DeadlineExceeded,
    BoundExceeded,
    IncompatibleValue,
    SystemFailure,
}

impl From<AccessibilityReaderFailure> for AccessibilityReadFailure {
    fn from(failure: AccessibilityReaderFailure) -> Self {
        match failure {
            AccessibilityReaderFailure::PermissionDenied => Self::PermissionRequired,
            AccessibilityReaderFailure::ProcessGone => Self::TargetGone,
            AccessibilityReaderFailure::ProcessNotInspectable => Self::TargetNotInspectable,
            AccessibilityReaderFailure::DeadlineExceeded => Self::RetryableDeadlineExceeded,
            // A depth and an element-count limit both mean the reader's bounded
            // traversal policy must change; neither says anything about target liveness.
            AccessibilityReaderFailure::BoundExceeded => Self::TreeExceedsBound,
            AccessibilityReaderFailure::IncompatibleValue => Self::IncompatiblePlatformValue,
            AccessibilityReaderFailure::SystemFailure => Self::PlatformReadFailed,
        }
    }
}

fn accessibility_read_timeout(settle_interval_ms: u32) -> Result<Duration, DriverError> {
    // The interval caps how long AX may block this read. Waiting beforehand
    // would only age the tree and would not make a rejected read more usable.
    <MacOs26PlatformDriver as PlatformDriver>::bounded_duration(u64::from(settle_interval_ms))
}

/// Bound on the window-server read each per-event routing decision makes.
const WINDOW_LIST_READ_TIMEOUT: Duration = Duration::from_millis(1_000);

/// Deliver one neutral synthetic action to the granted process generation.
///
/// Split from `dispatch_per_pid` so a test can drive it against a recording
/// transport: grant parsing, translation, routing, and mid-sequence recovery
/// are identical either way, and the transport is the only part that touches
/// the window server.
fn dispatch_synthetic_to_pid(
    request: &SyntheticDispatchRequest,
    transport: &mut impl PerProcessEventTransport<Event = cerebellum_macos::OwnedCgEvent>,
    cancelled: &dyn Fn() -> bool,
) -> Result<DispatchResult, DriverError> {
    // The grant records the kernel start time of the process it was made
    // for. That reading is what separates the granted process from a
    // replacement holding the same pid; it is re-read immediately before
    // every post by the routing, not trusted from here.
    let start_time_micros = request
        .target
        .process_generation_evidence
        .parse::<u64>()
        .map_err(|_| {
            DriverError::InvalidRequest("process generation evidence is not a kernel start time")
        })?;
    let steps = super::macos_synthetic::synthetic_event_steps(&request.action)?;
    let target = ProcessEventTarget {
        pid: request.target.pid,
        start_time_micros,
    };
    let report = post_event_sequence(target, steps, transport, cancelled)
        .map_err(DriverError::SyntheticDispatchFailed)?;
    Ok(DispatchResult {
        // The post calls returned, and that is ALL this says: the post call
        // is void, so receipt — let alone effect — is for effect observation
        // to establish separately.
        accepted_by_platform: report.posts_returned > 0,
        effect_status: EffectStatus::EffectIndeterminate,
        // No accessibility tree is read on this path.
        unreadable_subtrees: 0,
        delivery_posts_returned: report.posts_returned,
        delivery_generation_verifications: report.generation_verifications,
    })
}

const SESSION_TAP_UNREAD_BOUND: usize = 256;
static NEXT_HEARTBEAT_NONCE: AtomicU64 = AtomicU64::new(1);

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn observe_session_event(
    watcher: &mut SeizeWatcher,
    event: cerebellum_macos::SessionEvent,
    our_pid: i64,
    index: usize,
) {
    watcher.observe_sourced_input(sourced_event(&event), our_pid, index);
}

fn drain_session_events(
    tap: &cerebellum_macos::SessionEventTap,
    watcher: &mut SeizeWatcher,
    our_pid: i64,
    index: usize,
) {
    while let Ok(event) = tap.events().try_recv() {
        observe_session_event(watcher, event, our_pid, index);
    }
}

/// How late this loop learned of an event: the event's own timestamp against
/// the same clock read now, so the number covers the window server, the tap
/// callback, the channel, and this loop's own pace. Measured against the
/// sequence start it read as the age of the sequence and exceeded every
/// bound on a VM; the bound is about the event.
fn detection_latency_ms(event: &cerebellum_macos::SessionEvent) -> u32 {
    let now = cerebellum_macos::uptime_now_ns();
    u32::try_from(now.saturating_sub(event.timestamp_ns) / 1_000_000).unwrap_or(u32::MAX)
}

/// The platform's share of the latency: event timestamp to the tap callback.
/// What remains after subtracting this from the end-to-end number is this
/// loop's own pace, which is what the seize bound promises.
fn platform_delivery_latency_ms(event: &cerebellum_macos::SessionEvent) -> u32 {
    u32::try_from(event.observed_at_ns.saturating_sub(event.timestamp_ns) / 1_000_000)
        .unwrap_or(u32::MAX)
}

fn sourced_event(event: &cerebellum_macos::SessionEvent) -> SourcedInputEvent {
    SourcedInputEvent {
        source_unix_process_id: event.source_unix_process_id,
        detection_latency_ms: detection_latency_ms(event),
        platform_delivery_latency_ms: Some(platform_delivery_latency_ms(event)),
    }
}

fn sourced_from_tap(tap: &cerebellum_macos::SessionEventTap) -> Vec<SourcedInputEvent> {
    let mut events = Vec::new();
    while let Ok(event) = tap.events().try_recv() {
        events.push(sourced_event(&event));
    }
    events
}

fn observed_abort_error(watcher: &SeizeWatcher) -> DriverError {
    match watcher.abort_decision() {
        Some(abort) => DriverError::ObservedDispatchAborted(abort),
        None => {
            DriverError::StartupRefused("observed post refused without a recorded abort reason")
        }
    }
}

fn heartbeat_observation(
    tap: &cerebellum_macos::SessionEventTap,
    watcher: &mut SeizeWatcher,
    probe: HeartbeatProbe,
    started: Instant,
) -> HeartbeatObservation {
    let deadline = Instant::now() + Duration::from_millis(OBSERVER_HEARTBEAT_BOUND_MS);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(event) = tap.events().recv_timeout(remaining) else {
            return HeartbeatObservation::Missed;
        };
        observe_session_event(watcher, event, probe.our_pid, 0);
        if event.source_unix_process_id == probe.our_pid && event.marker_nonce == probe.marker.nonce
        {
            return HeartbeatObservation::Seen {
                marker: probe.marker,
                source_unix_process_id: event.source_unix_process_id,
                observed_at_ms: elapsed_millis(started),
            };
        }
        if watcher.abort_decision().is_some() {
            return HeartbeatObservation::Missed;
        }
    }
}

/// The heartbeat marker one observed sequence posts, ready to post once.
///
/// Shared by the global pointer sequence and the fronting bracket, so both
/// prove their observer live the same way.
struct HeartbeatPoster {
    marker: HeartbeatMarker,
    event: Option<cerebellum_macos::OwnedCgEvent>,
    started: Instant,
    our_pid: i64,
}

impl HeartbeatPoster {
    /// Post the marker, returning the probe to look for and when it went.
    fn post(&mut self) -> (HeartbeatProbe, Instant) {
        let posted_at_ms = elapsed_millis(self.started);
        if let Some(event) = self.event.take() {
            let _ = cerebellum_macos::post_event_globally(event);
        }
        (
            HeartbeatProbe {
                marker: self.marker,
                posted_at_ms,
                our_pid: self.our_pid,
            },
            Instant::now(),
        )
    }
}

/// Start watching session input for one observed sequence: the tap, and the
/// heartbeat that will prove it live.
///
/// The tap is created here, before the caller reads idle, so a hardware
/// event between that read and the heartbeat is seen.
fn open_session_observation(
    started: Instant,
) -> Result<(cerebellum_macos::SessionEventTap, HeartbeatPoster), DriverError> {
    let our_pid = i64::from(std::process::id());
    let nonce = NEXT_HEARTBEAT_NONCE.fetch_add(1, Ordering::Relaxed) & i64::MAX as u64;
    let marker = HeartbeatMarker::new(nonce.max(1));
    let event = cerebellum_macos::heartbeat_marker_event(marker.nonce)
        .map_err(|_| DriverError::EventConstructionFailed("observer heartbeat marker"))?;
    let tap = cerebellum_macos::SessionEventTap::listen(SESSION_TAP_UNREAD_BOUND)
        .map_err(|_| DriverError::StartupRefused("session input observer is unavailable"))?;
    Ok((
        tap,
        HeartbeatPoster {
            marker,
            event: Some(event),
            started,
            our_pid,
        },
    ))
}

/// Time since the last hardware input, from the HID table.
fn read_hid_idle() -> IdleReading {
    IdleReading::from_seconds(cerebellum_macos::seconds_since_last_input(
        cerebellum_macos::EventSourceStateTable::HidSystem,
    ))
}

/// The fronting bracket's view of this Mac: the frontmost application through
/// the window list, fronting through accessibility, and posting to the
/// target's exact process generation. Session observation is the same as the
/// global pointer sequence's.
struct MacBracketHost {
    started: Instant,
    tap: Option<cerebellum_macos::SessionEventTap>,
    heartbeat: HeartbeatPoster,
    target: ProcessEventTarget,
    units: Vec<Option<Vec<SyntheticStep<cerebellum_macos::OwnedCgEvent>>>>,
    transport: MacOsPerProcessEventTransport,
}

impl crate::dispatch::FrontingBracketHost for MacBracketHost {
    type Tap = cerebellum_macos::SessionEventTap;

    fn now_ms(&mut self) -> u64 {
        elapsed_millis(self.started)
    }

    fn pause_ms(&mut self, milliseconds: u64) {
        std::thread::sleep(Duration::from_millis(milliseconds));
    }

    fn frontmost_pid(&mut self) -> Option<u32> {
        cerebellum_macos::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok())
    }

    fn request_front(&mut self, pid: u32) -> bool {
        cerebellum_macos::request_frontmost(pid).is_ok()
    }

    fn our_pid(&self) -> i64 {
        self.heartbeat.our_pid
    }

    fn create_tap(&mut self) -> Option<Self::Tap> {
        self.tap.take()
    }

    fn read_idle(&mut self) -> IdleReading {
        read_hid_idle()
    }

    fn drain(&mut self, tap: &Self::Tap) -> Vec<SourcedInputEvent> {
        sourced_from_tap(tap)
    }

    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        self.heartbeat.post().0
    }

    fn observe_heartbeat(
        &mut self,
        tap: &Self::Tap,
        probe: HeartbeatProbe,
        watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        heartbeat_observation(tap, watcher, probe, self.started)
    }

    fn post_unit(
        &mut self,
        index: usize,
    ) -> Result<crate::dispatch::UnitPosted, SequencePostFailure> {
        let steps = self
            .units
            .get_mut(index)
            .and_then(Option::take)
            .unwrap_or_default();
        let report = post_event_sequence(self.target, steps, &mut self.transport, &|| false)?;
        Ok(crate::dispatch::UnitPosted {
            posts_returned: report.posts_returned,
            generation_verifications: report.generation_verifications,
        })
    }
}

/// The units a bracket posts one at a time: each character of typed text on
/// its own, so a long text can be split between chunks, and a chord whole,
/// so its modifiers are never left held while another application is in
/// front.
fn bracket_units(
    action: &SyntheticAction,
) -> Result<Vec<Option<Vec<SyntheticStep<cerebellum_macos::OwnedCgEvent>>>>, DriverError> {
    match action {
        SyntheticAction::TypeText { text } => text
            .chars()
            .map(|character| {
                super::macos_synthetic::synthetic_event_steps(&SyntheticAction::type_text(
                    character.to_string(),
                ))
                .map(Some)
            })
            .collect(),
        SyntheticAction::KeyCombination { .. } => Ok(vec![Some(
            super::macos_synthetic::synthetic_event_steps(action)?,
        )]),
        _ => Err(DriverError::InvalidRequest(
            "only keystrokes are posted through a fronting bracket",
        )),
    }
}

/// Deliver one action through the session-global transport under observed gates.
///
/// The tap precedes the idle read and stays live through the HID table's update
/// lag after the final post. Idle is read once before the heartbeat because our
/// session-tap posts also reset the HID idle table.
fn dispatch_synthetic_globally(
    request: GlobalDispatchRequest,
    estimator: &mut UserIdleEstimator,
    cancelled: &dyn Fn() -> bool,
) -> Result<DispatchResult, DriverError> {
    let GlobalDispatchRequest {
        synthetic,
        once_dispatch_token: _once_dispatch_token,
        maximum_seize_detection_latency_ms,
        minimum_inter_post_interval_ms,
    } = request;
    if minimum_inter_post_interval_ms < maximum_seize_detection_latency_ms {
        return Err(DriverError::InvalidRequest(
            "observed inter-post interval is shorter than the seize-detection bound",
        ));
    }

    let steps = super::macos_synthetic::synthetic_event_steps(&synthetic.action)?;
    let our_pid = i64::from(std::process::id());
    let started = Instant::now();
    let (tap, mut heartbeat) = open_session_observation(started)?;
    let mut watcher = SeizeWatcher::new(maximum_seize_detection_latency_ms);
    for _ in &steps {
        watcher.queue_post();
    }

    let idle_read_at = Instant::now();
    let begin = begin_observed_sequence(
        estimator,
        &mut watcher,
        our_pid,
        idle_read_at,
        ObservedSequenceHooks {
            create_tap: || tap,
            read_idle: read_hid_idle,
            drain: |tap: &cerebellum_macos::SessionEventTap| sourced_from_tap(tap),
            post_heartbeat: || heartbeat.post(),
        },
    );
    let (tap, user_idle, (probe, mut last_post_at)) = match begin {
        Ok(started_sequence) => started_sequence,
        Err(refusal) => {
            if matches!(
                refusal,
                ObservedPostRefusal::AlreadyAborted(AbortReason::UserSeizedControl)
            ) {
                estimator.clear_carry();
            }
            return Err(observed_abort_error(&watcher));
        }
    };

    let heartbeat = heartbeat_observation(&tap, &mut watcher, probe, started);
    if let Some(abort) = watcher.abort_decision() {
        estimator.clear_carry();
        return Err(DriverError::ObservedDispatchAborted(abort));
    }

    let target_pid = synthetic.target.pid;
    let target = ProcessEventTarget {
        pid: target_pid,
        start_time_micros: synthetic
            .target
            .process_generation_evidence
            .parse()
            .map_err(|_| {
                DriverError::InvalidRequest(
                    "process generation evidence is not a kernel start time",
                )
            })?,
    };
    let mut identity_transport = MacOsPerProcessEventTransport::new(WINDOW_LIST_READ_TIMEOUT);
    let sequence = post_global_sequence(steps, cancelled, |index, event, recovery| {
        if event.is_none() && index > 0 {
            // Wait out the inter-post interval ON the tap, not beside it: a
            // sleep followed by a drain detects an event that lands just after
            // a post only when the sleep ends, so the measured detection
            // latency was the interval plus jitter (88 ms against a 50 ms
            // bound on the VM) and could never be inside the bound by
            // construction. Blocking on the tap wakes on the event itself.
            let next_post_at =
                last_post_at + Duration::from_millis(u64::from(minimum_inter_post_interval_ms));
            loop {
                let remaining = next_post_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tap.events().recv_timeout(remaining) {
                    Ok(event) => {
                        observe_session_event(&mut watcher, event, our_pid, index);
                        if let Some(abort) = watcher.abort_decision() {
                            estimator.clear_carry();
                            return Err(DriverError::ObservedDispatchAborted(abort));
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        }
        let Some(event) = event else {
            drain_session_events(&tap, &mut watcher, our_pid, index);
            if let Some(abort) = watcher.abort_decision() {
                estimator.clear_carry();
                return Err(DriverError::ObservedDispatchAborted(abort));
            }
            return Ok(0);
        };
        super::process_event::require_exact_generation(
            target,
            identity_transport.process_generation(target_pid),
        )
        .map_err(|_| DriverError::Unsupported("global target generation changed"))?;
        if recovery {
            if cerebellum_macos::frontmost_process_id() != i32::try_from(target_pid).ok() {
                return Err(DriverError::Unsupported(
                    "global release target is no longer frontmost",
                ));
            }
            let _ = cerebellum_macos::post_event_globally(event);
            return Ok(1);
        }
        let result = dispatch_observed_post_in_order(
            &mut watcher,
            index,
            probe,
            |_| heartbeat,
            || cerebellum_macos::frontmost_process_id() == i32::try_from(target_pid).ok(),
            || cerebellum_macos::post_event_globally(event),
        );
        match result {
            Ok(_) => {
                watcher.take_post_slot();
                last_post_at = Instant::now();
            }
            Err(
                ObservedPostRefusal::ObserverBlind
                | ObservedPostRefusal::Idle(_)
                | ObservedPostRefusal::FocusMismatch
                | ObservedPostRefusal::AlreadyAborted(_),
            ) => {
                // Every refusal arm records an abort before returning. Keep a
                // defensive startup refusal if a future arm breaks that invariant.
                estimator.clear_carry();
                return Err(observed_abort_error(&watcher));
            }
        }
        Ok(1)
    });
    let posts_returned = match sequence {
        Ok(report) => report.posts_returned,
        Err(failure) => {
            estimator.clear_carry();
            return Err(failure);
        }
    };

    let tail_until = observed_tail_deadline(last_post_at);
    let mut hardware_seen = false;
    let mut tail_observed = true;
    while Instant::now() < tail_until {
        let remaining = tail_until.saturating_duration_since(Instant::now());
        match tap.events().recv_timeout(remaining) {
            Ok(event) => {
                let sourced = sourced_event(&event);
                if !event_is_ours(sourced, our_pid) {
                    hardware_seen = true;
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tail_observed = false;
                break;
            }
        }
    }
    if hardware_seen || !tail_observed {
        estimator.clear_carry();
    } else {
        estimator.sequence_finished(
            last_post_at,
            user_idle,
            last_post_at.saturating_duration_since(idle_read_at),
        );
    }

    Ok(DispatchResult {
        accepted_by_platform: posts_returned > 0,
        effect_status: EffectStatus::EffectIndeterminate,
        unreadable_subtrees: 0,
        delivery_posts_returned: posts_returned,
        delivery_generation_verifications: 0,
    })
}

/// What a platform acceptance means for the caller's dispatch result.
///
/// ACCEPTED IS NOT PERFORMED. The accessibility API returns once the
/// application's handler returns, and some applications return success from a
/// handler that forwards nothing. So acceptance is recorded and the effect is
/// left INDETERMINATE for a separate observation to settle: reporting an effect
/// here would be this layer asserting something it never looked at, and a
/// caller reading that would skip the check that establishes it.
///
/// A separate function rather than a literal at the call site, because the call
/// site can only run against a live application with a granted permission,
/// which no test on an arbitrary machine has. Written here, the meaning of an
/// acceptance is checkable everywhere.
#[cfg(target_os = "macos")]
fn dispatch_result_for_accepted_action(
    outcome: cerebellum_macos::AxActionRequestOutcome,
) -> DispatchResult {
    match outcome {
        cerebellum_macos::AxActionRequestOutcome::HandlerReturned {
            unreadable_subtrees,
            ..
        } => DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
            unreadable_subtrees: u64::try_from(unreadable_subtrees).unwrap_or(u64::MAX),
            delivery_posts_returned: 0,
            delivery_generation_verifications: 0,
        },
    }
}

#[cfg(target_os = "macos")]
impl From<cerebellum_macos::AxElementName> for AccessibilityElementName {
    fn from(name: cerebellum_macos::AxElementName) -> Self {
        match name {
            cerebellum_macos::AxElementName::Identifier(identifier) => Self::Identifier(identifier),
            cerebellum_macos::AxElementName::RoleAndTitle { role, title } => {
                Self::RoleAndTitle { role, title }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn ax_element_name(
    name: &AccessibilityElementName,
) -> Result<cerebellum_macos::AxElementName, DriverError> {
    match name {
        AccessibilityElementName::Identifier(identifier) => {
            cerebellum_macos::AxElementName::identifier(identifier)
        }
        AccessibilityElementName::RoleAndTitle { role, title } => {
            cerebellum_macos::AxElementName::role_and_title(role, title)
        }
    }
    .map_err(|_| DriverError::InvalidRequest(UNUSABLE_ELEMENT_NAME))
}

/// Map an action failure onto the driver's typed remedy vocabulary.
///
/// Every `AxActionError` is handled explicitly rather than through a catch-all,
/// so a variant added later stops the build here instead of silently inheriting
/// whichever case happened to be last.
#[cfg(target_os = "macos")]
fn map_ax_action_error(
    error: cerebellum_macos::AxActionError,
    requested_action: &str,
    deadline_ms: u64,
) -> DriverError {
    use cerebellum_macos::AxActionError;

    let semantic = match error {
        AxActionError::PermissionNotGranted => {
            SemanticDriverError::AccessibilityPermissionUnavailable
        }
        AxActionError::NoSuchProcess { .. } => SemanticDriverError::TargetNoLongerCurrent {
            disposition: TargetDisposition::Gone,
        },
        // No handler was reached, and no caller-controlled variation can make
        // an application that exposes no accessibility surface inspectable.
        AxActionError::ProcessNotAccessible { .. } => SemanticDriverError::PathUnavailable,
        AxActionError::ElementNotFound { element_name } => SemanticDriverError::ElementNotFound {
            key_form: AccessibilityElementName::from(element_name).key_form(),
        },
        AxActionError::ElementIdentifierAmbiguous {
            element_name,
            match_count,
        } => SemanticDriverError::ElementNameAmbiguous {
            key_form: AccessibilityElementName::from(element_name).key_form(),
            match_count: u64::try_from(match_count).unwrap_or(u64::MAX),
        },
        AxActionError::ActionNotAdvertised { advertised, .. } => {
            SemanticDriverError::ActionNotAdvertised {
                action: requested_action.to_owned(),
                advertised,
            }
        }
        AxActionError::ApplicationRefusedAction { ax_error, .. } => {
            SemanticDriverError::ApplicationRefused { ax_error }
        }
        AxActionError::DeadlineExceeded { timeout } => SemanticDriverError::Transient {
            deadline_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        },
        AxActionError::SystemCallFailed { .. } => SemanticDriverError::Transient { deadline_ms },
        // Traversal bounds and unexpected framework values are module-internal
        // limits rather than caller remedies.
        AxActionError::DepthLimitExceeded { .. }
        | AxActionError::ElementLimitExceeded { .. }
        | AxActionError::UnexpectedValueType { .. } => SemanticDriverError::PathUnavailable,
    };
    DriverError::Semantic(semantic)
}

fn root_cache_key(target: &ProcessGrant) -> String {
    // Keyed on the grant's process identity rather than on an accessibility
    // identifier, which is optional and chosen by the application.
    //
    // Including the generation alongside the pid keeps two generations of the
    // same pid on separate keys, so a cache entry cannot be retrieved for a
    // process that merely inherited the identifier. Whether the process behind a
    // key is still the granted one is established by verifying the grant at use,
    // not by this key.
    format!(
        "accessibility-root:{}:{}",
        target.pid, target.process_generation_evidence
    )
}

fn root_degenerate_reason(child_count: u32, unreadable_subtrees: usize) -> Option<String> {
    if unreadable_subtrees > 0 {
        Some(format!(
            "incomplete_accessibility_tree:{unreadable_subtrees}_unreadable_subtrees"
        ))
    } else {
        (child_count == 0).then(|| "missing_children_for_nontrivial_window".to_string())
    }
}

#[cfg(target_os = "macos")]
fn map_ax_read_error(error: cerebellum_macos::AxReadError) -> DriverError {
    let failure = match error {
        cerebellum_macos::AxReadError::PermissionNotGranted => {
            AccessibilityReaderFailure::PermissionDenied
        }
        cerebellum_macos::AxReadError::NoSuchProcess { .. } => {
            AccessibilityReaderFailure::ProcessGone
        }
        cerebellum_macos::AxReadError::ProcessNotAccessible { .. } => {
            AccessibilityReaderFailure::ProcessNotInspectable
        }
        cerebellum_macos::AxReadError::DeadlineExceeded { .. } => {
            AccessibilityReaderFailure::DeadlineExceeded
        }
        cerebellum_macos::AxReadError::DepthLimitExceeded { .. }
        | cerebellum_macos::AxReadError::ElementLimitExceeded { .. } => {
            AccessibilityReaderFailure::BoundExceeded
        }
        cerebellum_macos::AxReadError::UnexpectedValueType { .. } => {
            AccessibilityReaderFailure::IncompatibleValue
        }
        cerebellum_macos::AxReadError::SystemCallFailed { .. } => {
            AccessibilityReaderFailure::SystemFailure
        }
    };
    AccessibilityReadFailure::from(failure).into()
}

#[cfg(target_os = "macos")]
fn map_ax_element_read_error(error: cerebellum_macos::AxElementReadError) -> DriverError {
    match error {
        cerebellum_macos::AxElementReadError::Read(error) => map_ax_read_error(error),
        cerebellum_macos::AxElementReadError::ElementNameAmbiguous {
            element_name,
            match_count,
        } => DriverError::Semantic(SemanticDriverError::ElementNameAmbiguous {
            key_form: AccessibilityElementName::from(element_name).key_form(),
            match_count: u64::try_from(match_count).unwrap_or(u64::MAX),
        }),
        // An omitted subtree may contain the named element or a duplicate key,
        // so neither absence nor uniqueness can be established from this read.
        cerebellum_macos::AxElementReadError::IncompleteSearch { .. } => {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::PlatformReadFailed)
        }
    }
}

#[cfg(target_os = "macos")]
fn cache_ax_element(element: cerebellum_macos::AxElement) -> CachedAccessibilityElement {
    CachedAccessibilityElement {
        identifier: element.identifier,
        role: element.role,
        title: element.title,
        actions: element.actions,
        children: element.children.into_iter().map(cache_ax_element).collect(),
    }
}

fn cached_element_matches(
    element: &CachedAccessibilityElement,
    name: &AccessibilityElementName,
) -> bool {
    match name {
        AccessibilityElementName::Identifier(identifier) => {
            element.identifier.as_deref() == Some(identifier.as_str())
        }
        AccessibilityElementName::RoleAndTitle { role, title } => {
            element.role.as_deref() == Some(role.as_str())
                && element.title.as_deref().unwrap_or_default() == title
        }
    }
}

fn find_cached_element<'a>(
    element: &'a CachedAccessibilityElement,
    name: &AccessibilityElementName,
    found: &mut Option<&'a CachedAccessibilityElement>,
    match_count: &mut usize,
) {
    if cached_element_matches(element, name) {
        *match_count += 1;
        if found.is_none() {
            *found = Some(element);
        }
    }
    for child in &element.children {
        find_cached_element(child, name, found, match_count);
    }
}

fn resolve_cached_element<'a>(
    tree: &'a CachedAccessibilityTree,
    request: &ElementResolutionRequest,
) -> Result<&'a CachedAccessibilityElement, DriverError> {
    if !request.element_name.is_usable() {
        return Err(DriverError::InvalidRequest(UNUSABLE_ELEMENT_NAME));
    }

    let mut found = None;
    let mut match_count = 0;
    find_cached_element(
        &tree.tree,
        &request.element_name,
        &mut found,
        &mut match_count,
    );
    match match_count {
        0 => Err(DriverError::ElementNotFound),
        1 => Ok(found.expect("one counted match stores one element")),
        _ => Err(DriverError::InvalidRequest(AMBIGUOUS_ELEMENT_NAME)),
    }
}

fn alternate_element_name(
    element: &CachedAccessibilityElement,
    matched_by: &AccessibilityElementName,
) -> Option<AccessibilityElementName> {
    match matched_by {
        AccessibilityElementName::Identifier(_) => Some(AccessibilityElementName::RoleAndTitle {
            role: element.role.clone()?,
            title: element.title.clone().unwrap_or_default(),
        }),
        AccessibilityElementName::RoleAndTitle { .. } => element
            .identifier
            .clone()
            .map(AccessibilityElementName::Identifier),
    }
}

fn semantic_intents_advertised_by(platform_actions: &[String]) -> Vec<String> {
    SemanticActionIntent::ALL
        .into_iter()
        .filter_map(|intent| {
            let delivered =
                delivered_semantic_action(SemanticActionPlatform::MacOs, intent).ok()?;
            platform_actions
                .iter()
                .any(|action| action == delivered)
                .then(|| intent.wire_name().to_owned())
        })
        .collect()
}

fn resolution_from_cached_tree(
    tree: &CachedAccessibilityTree,
    request: &ElementResolutionRequest,
) -> Result<ElementResolutionResult, DriverError> {
    let element = resolve_cached_element(tree, request)?;
    Ok(ElementResolutionResult {
        element_name: request.element_name.clone(),
        alternate_name: alternate_element_name(element, &request.element_name),
        owning_process: tree.target.clone(),
        semantic_actions: semantic_intents_advertised_by(&element.actions),
        unreadable_subtrees: u64::try_from(tree.unreadable_subtrees).unwrap_or(u64::MAX),
    })
}

/// Resolve `name` against a tree whose Save button has a role and title and no
/// identifier. An identifier lookup for "Save" cannot find it; a role+title
/// lookup can. That is the distinction the wire target object exists to carry.
pub fn resolve_against_identifierless_save_fixture(
    name: AccessibilityElementName,
) -> Result<ElementResolutionResult, DriverError> {
    let tree = CachedAccessibilityTree {
        target: ProcessGrant {
            pid: 41,
            bundle_identity: "com.example.reader".to_string(),
            process_generation_evidence: "generation-a".to_string(),
        },
        tree: CachedAccessibilityElement {
            identifier: Some("root-actual-id".to_string()),
            role: Some("AXApplication".to_string()),
            title: Some("Reader".to_string()),
            actions: Vec::new(),
            children: vec![CachedAccessibilityElement {
                identifier: None,
                role: Some("AXButton".to_string()),
                title: Some("Save".to_string()),
                actions: vec!["AXPress".to_string()],
                children: Vec::new(),
            }],
        },
        unreadable_subtrees: 0,
    };
    resolution_from_cached_tree(
        &tree,
        &ElementResolutionRequest {
            root_identifier: "fixture".to_string(),
            element_name: name,
        },
    )
}

#[cfg(target_os = "macos")]
fn verify_cached_tree_owner(target: &ProcessGrant) -> Result<(), DriverError> {
    match super::native::verify_grant(target.pid, target) {
        super::native::GrantVerification::Current => Ok(()),
        super::native::GrantVerification::TargetReplaced => {
            Err(AccessibilityReadFailure::TargetReplaced.into())
        }
        super::native::GrantVerification::TargetGone => {
            Err(AccessibilityReadFailure::TargetGone.into())
        }
        super::native::GrantVerification::TargetUnreadable => {
            Err(AccessibilityReadFailure::TargetNotInspectable.into())
        }
        super::native::GrantVerification::DifferentProcess => Err(DriverError::InvalidRequest(
            "cached accessibility root belongs to another process",
        )),
    }
}

impl MacOs26PlatformDriver {
    pub fn new(input: &StartupProbeInput) -> Self {
        Self {
            startup: StartupCapabilityProbe::run(input),
            accessibility_trees: BTreeMap::new(),
            expected_post_condition_available: true,
            global_dispatch_review_revision: None,
            takeover_dispatch_review_revision: None,
            user_idle: Arc::new(Mutex::new(UserIdleEstimator::new())),
        }
    }

    /// Store the review that admits the fronting bracket. The bracket stays
    /// unavailable unless this revision is supplied.
    pub fn with_takeover_dispatch_review_revision(mut self, revision: Option<String>) -> Self {
        self.takeover_dispatch_review_revision = revision;
        self
    }

    /// Share one idle estimator across drivers. The plane's driver factory
    /// calls this with a single `Arc` so that every dispatch, each on a fresh
    /// driver, reads and updates the same post log.
    pub fn with_shared_user_idle(mut self, user_idle: Arc<Mutex<UserIdleEstimator>>) -> Self {
        self.user_idle = user_idle;
        self
    }

    /// Mark a request surface that cannot express an expected post-condition.
    ///
    /// The semantic action still runs and is journaled, but effect observation
    /// must not invent a predicate and then report that invented claim as the
    /// caller's. The existing vocabulary represents this as an indeterminate
    /// effect with an undeclarable post-condition.
    pub fn without_expected_post_condition(mut self) -> Self {
        self.expected_post_condition_available = false;
        self
    }

    /// Store the external authorization for session-global event posting.
    /// Global dispatch remains unavailable unless this revision is supplied.
    pub fn with_global_dispatch_review_revision(mut self, revision: Option<String>) -> Self {
        self.global_dispatch_review_revision = revision;
        self
    }

    pub fn startup_probe(&self) -> &StartupCapabilityProbe {
        &self.startup
    }

    /// Describe every current action, advertising only the ones that can be served.
    ///
    /// The platform-neutral policy owns the declaration data. This driver only
    /// reports that macOS is available and supplies its startup probe result.
    pub fn declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        capability_declarations(context, true)
    }

    #[cfg(test)]
    fn declaration(
        &self,
        id: &str,
        context: &CapabilityAdvertisementContext,
    ) -> CapabilityDeclaration {
        let capability = crate::audit::ComputerCapability::parse(id)
            .unwrap_or_else(|| panic!("{id} is not a current capability"));
        capability_declaration(capability, context, true)
    }
}

impl Default for MacOs26PlatformDriver {
    fn default() -> Self {
        Self::new(&StartupProbeInput {
            os_major: MACOS_MAJOR_VERSION,
            private_envelope_revision: None,
            resolved_private_symbols: BTreeSet::new(),
            permission_results: Vec::new(),
            responsible_process: None,
        })
    }
}

impl PlatformDriver for MacOs26PlatformDriver {
    fn capability_declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        self.declarations(context)
    }

    fn read_accessibility_tree(
        &mut self,
        request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        request.target.validate()?;
        let timeout = accessibility_read_timeout(request.settle_interval_ms)?;

        #[cfg(target_os = "macos")]
        {
            let tree = cerebellum_macos::read_accessibility_tree(
                request.target.pid,
                cerebellum_macos::AxReadOptions {
                    timeout,
                    ..Default::default()
                },
            )
            .map_err(map_ax_read_error)?;
            let unreadable_subtrees = match tree.completeness {
                cerebellum_macos::AxTreeCompleteness::Complete => 0,
                cerebellum_macos::AxTreeCompleteness::Incomplete {
                    unreadable_subtrees,
                } => unreadable_subtrees,
            };
            let root_child_count = tree
                .root
                .children
                .len()
                .checked_add(tree.root.unreadable_children.len())
                .expect("the reader's element bound keeps child count within usize");
            let child_count = u32::try_from(root_child_count)
                .expect("the reader's element bound keeps child count within u32");
            let root_identifier = root_cache_key(&request.target);
            self.accessibility_trees.insert(
                root_identifier.clone(),
                CachedAccessibilityTree {
                    target: request.target,
                    tree: cache_ax_element(tree.root),
                    unreadable_subtrees,
                },
            );
            Ok(AccessibilityTreeResult {
                root_identifier: Some(root_identifier),
                child_count,
                handshake_attempted: true,
                degenerate_reason: root_degenerate_reason(child_count, unreadable_subtrees),
                unreadable_subtrees: u64::try_from(unreadable_subtrees)
                    .expect("the accessibility reader's element bound fits u64"),
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = timeout;
            Err(DriverError::Unsupported("accessibility tree read"))
        }
    }
    fn read_accessibility_element(
        &mut self,
        request: AccessibilityElementReadRequest,
    ) -> Result<AccessibilityElementReadResult, DriverError> {
        request.target.validate()?;
        let timeout = <Self as PlatformDriver>::bounded_duration(u64::from(request.deadline_ms))?;

        #[cfg(target_os = "macos")]
        {
            match super::native::verify_grant(request.target.pid, &request.target) {
                super::native::GrantVerification::Current => {}
                super::native::GrantVerification::TargetGone => {
                    return Err(AccessibilityReadFailure::TargetGone.into())
                }
                super::native::GrantVerification::TargetReplaced => {
                    return Err(AccessibilityReadFailure::TargetReplaced.into())
                }
                super::native::GrantVerification::TargetUnreadable => {
                    return Err(AccessibilityReadFailure::TargetNotInspectable.into())
                }
                super::native::GrantVerification::DifferentProcess => {
                    return Err(DriverError::InvalidRequest(
                        "scoped read target differs from its grant",
                    ))
                }
            }
            let attribute = match request.attribute {
                AccessibilityReadbackAttribute::Presence => {
                    cerebellum_macos::AxReadbackAttribute::Presence
                }
                AccessibilityReadbackAttribute::Focused => {
                    cerebellum_macos::AxReadbackAttribute::Focused
                }
                AccessibilityReadbackAttribute::Enabled => {
                    cerebellum_macos::AxReadbackAttribute::Enabled
                }
                AccessibilityReadbackAttribute::Value => {
                    cerebellum_macos::AxReadbackAttribute::Value
                }
            };
            let readback = cerebellum_macos::read_accessibility_element(
                request.target.pid,
                &ax_element_name(&request.element_name)?,
                attribute,
                cerebellum_macos::AxReadOptions {
                    timeout,
                    ..Default::default()
                },
            )
            .map_err(map_ax_element_read_error)?;
            Ok(AccessibilityElementReadResult {
                element_name: request.element_name,
                present: readback.present,
                focused: readback.focused,
                enabled: readback.enabled,
                value: readback.value,
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = timeout;
            Err(DriverError::Unsupported("scoped accessibility read"))
        }
    }

    fn resolve_element(
        &mut self,
        request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        #[cfg(target_os = "macos")]
        {
            let Some(cached) = self.accessibility_trees.get(&request.root_identifier) else {
                return Err(DriverError::ElementNotFound);
            };
            verify_cached_tree_owner(&cached.target)?;
            // Resolution clones the owning grant only after the kernel
            // generation check above; otherwise a reused PID could be reported
            // as the old grant.
            resolution_from_cached_tree(cached, &request)
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("element resolution"))
        }
    }
    fn dispatch_semantic(
        &mut self,
        request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("semantic dispatch"))
        }
        #[cfg(target_os = "macos")]
        {
            // The grant is re-verified here rather than trusted from
            // resolution. Between resolving an element and acting on it the
            // process may have exited and its identifier been reused, and this
            // is the last moment before something changes.
            verify_cached_tree_owner(&request.element.owning_process)?;

            let intent = SemanticActionIntent::from_wire_name(&request.action).ok_or(
                DriverError::InvalidRequest("unknown semantic action intent"),
            )?;
            let delivered_action = delivered_semantic_action(SemanticActionPlatform::MacOs, intent)
                .map_err(|refusal| {
                    DriverError::Semantic(SemanticDriverError::ActionUnsupported {
                        intent: refusal.intent,
                        platform: refusal.platform,
                    })
                })?;
            let action =
                cerebellum_macos::AxAction::from_name(delivered_action)
                    .ok_or(DriverError::StartupRefused(
                    "semantic action mapping is not recognized by the macOS framework vocabulary",
                ))?;

            let element_name = ax_element_name(&request.element.element_name)?;

            let options = cerebellum_macos::AxActionOptions::default();
            let deadline_ms = u64::try_from(options.timeout.as_millis()).unwrap_or(u64::MAX);
            let outcome = cerebellum_macos::request_accessibility_action(
                request.element.owning_process.pid,
                &element_name,
                action,
                options,
            )
            .map_err(|error| map_ax_action_error(error, &request.action, deadline_ms))?;

            Ok(dispatch_result_for_accepted_action(outcome))
        }
    }
    fn dispatch_per_pid(
        &mut self,
        request: SyntheticDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        request.target.validate()?;
        let mut transport = MacOsPerProcessEventTransport::new(WINDOW_LIST_READ_TIMEOUT);
        dispatch_synthetic_to_pid(&request, &mut transport, cancelled)
    }
    fn dispatch_global(
        &mut self,
        request: GlobalDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        if self
            .global_dispatch_review_revision
            .as_deref()
            .is_none_or(|revision| revision.trim().is_empty())
        {
            return Err(DriverError::StartupRefused(
                "global_dispatch_review_revision is not bound",
            ));
        }
        request.synthetic.target.validate()?;
        let mut user_idle = self
            .user_idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        dispatch_synthetic_globally(request, &mut user_idle, cancelled)
    }
    fn dispatch_fronted(
        &mut self,
        request: FrontedDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<crate::dispatch::BracketReport, DriverError> {
        if self
            .takeover_dispatch_review_revision
            .as_deref()
            .is_none_or(|revision| revision.trim().is_empty())
        {
            return Err(DriverError::StartupRefused(
                "takeover_dispatch_review_revision is not bound",
            ));
        }
        let target = &request.synthetic.target;
        target.validate()?;
        let start_time_micros =
            target
                .process_generation_evidence
                .parse::<u64>()
                .map_err(|_| {
                    DriverError::InvalidRequest(
                        "process generation evidence is not a kernel start time",
                    )
                })?;
        let units = bracket_units(&request.synthetic.action)?;
        let started = Instant::now();
        let (tap, heartbeat) = open_session_observation(started)?;
        let plan = crate::dispatch::BracketPlan {
            target_pid: target.pid,
            units: units.len(),
            maximum_interval_ms: request.maximum_interval_ms,
            maximum_seize_detection_latency_ms: request.maximum_seize_detection_latency_ms,
        };
        let mut host = MacBracketHost {
            started,
            tap: Some(tap),
            heartbeat,
            target: ProcessEventTarget {
                pid: target.pid,
                start_time_micros,
            },
            units,
            transport: MacOsPerProcessEventTransport::new(WINDOW_LIST_READ_TIMEOUT),
        };
        let mut user_idle = self
            .user_idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(crate::dispatch::run_fronting_bracket(
            &mut host,
            &mut user_idle,
            plan,
            cancelled,
        ))
    }
    fn query_focus(&mut self, request: FocusQueryRequest) -> Result<FocusQueryResult, DriverError> {
        request.target.validate()?;
        let frontmost = cerebellum_macos::frontmost_process_id()
            .ok_or(DriverError::Unsupported("frontmost process reading"))?;
        Ok(FocusQueryResult {
            matches_target: i32::try_from(request.target.pid).ok() == Some(frontmost),
        })
    }
    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported("fronting snapshot"))
    }
    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: false,
            raw_hid_live: false,
            self_echo_filter_live: false,
        }
    }
    /// Asked of the window server on every call, never cached: the person can
    /// lock the screen between two actions, or while one waits for consent.
    fn session_locked(&self) -> Option<bool> {
        #[cfg(target_os = "macos")]
        {
            cerebellum_macos::screen_is_locked()
        }
        // This driver also compiles on other hosts, for conformance tests
        // that link no macOS framework; there is no session to ask there.
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }
    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Err(DriverError::Unsupported("input observation"))
    }
    fn observe_effect(
        &mut self,
        request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("effect observation"))
        }
        #[cfg(target_os = "macos")]
        {
            use crate::dispatch::post_condition::{evaluate, ConditionOutcome, ObservedElement};
            use crate::dispatch::ExpectedPostCondition;

            if !self.expected_post_condition_available {
                return Ok(EffectObservationResult {
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("post_condition_undeclarable".to_string()),
                });
            }

            // A condition this driver cannot decide is reported as
            // INDETERMINATE rather than refused. The action already happened;
            // the caller needs to know that its effect is unestablished, which
            // is a different fact from the observation machinery being broken.
            // Deserialized into the type that WROTE it, rather than a local copy
            // of its shape: a second definition of the same envelope drifts
            // silently, and the failure would be a condition that reads back
            // wrong rather than one that fails to read.
            let Ok(envelope) = serde_json::from_str::<ExpectedPostCondition>(&request.predicate)
            else {
                return Ok(EffectObservationResult {
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("post_condition_undeclarable".to_string()),
                });
            };

            // Read fresh rather than using the cached tree: the cache was
            // populated before the action, so it would report the pre-action
            // state. This scoped read walks only element keys and retrieves
            // only the predicate's attribute.
            let readback = match self.read_accessibility_element(AccessibilityElementReadRequest {
                target: request.target,
                element_name: envelope.condition.element().clone(),
                attribute: envelope.condition.readback_attribute(),
                deadline_ms: request.deadline_ms,
            }) {
                Ok(readback) => readback,
                Err(error) => {
                    let failure_reason = match error {
                        DriverError::AccessibilityUnreadable(
                            AccessibilityReadFailure::RetryableDeadlineExceeded,
                        ) => "deadline_exceeded",
                        _ => "observation_primitive_unavailable",
                    };
                    return Ok(EffectObservationResult {
                        status: EffectStatus::EffectIndeterminate,
                        failure_reason: Some(failure_reason.to_string()),
                    });
                }
            };
            let observed = ObservedElement {
                present: readback.present,
                focused: readback.focused,
                enabled: readback.enabled,
                value: readback.value,
            };
            let status = match evaluate(&envelope.condition, &observed) {
                ConditionOutcome::Satisfied => EffectStatus::EffectObserved,
                ConditionOutcome::Unsatisfied => EffectStatus::NoEffectObserved,
                ConditionOutcome::Indeterminate => EffectStatus::EffectIndeterminate,
            };
            let failure_reason = match status {
                // The application does not report the attribute the condition
                // is about, so nothing here can say whether the action worked.
                EffectStatus::EffectIndeterminate => {
                    Some("post_condition_undeclarable".to_string())
                }
                _ => None,
            };
            Ok(EffectObservationResult {
                status,
                failure_reason,
            })
        }
    }
    fn verify_attendance(
        &mut self,
        request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("attendance verification"))
        }
        #[cfg(target_os = "macos")]
        {
            // What this adds to the caller's own lease checks: whether the
            // TARGET is still the process the lease was granted for. The caller
            // can see that its lease has not expired and belongs to this
            // conversation, and cannot see that the process behind the
            // identifier was replaced in the meantime -- which is the failure a
            // lease alone cannot detect, because the replacement inherits the
            // identifier the lease names.
            let verification = super::native::verify_grant(request.target.pid, &request.target);
            Ok(AttendancePreconditionResult {
                valid: verification.is_current(),
                // Not reported: the lease's own generation and age are the
                // caller's, and echoing them back would present the caller's
                // input as an independent reading. This answers one question,
                // and says nothing about the rest.
                lease_generation: None,
                age_ms: None,
            })
        }
    }
}

// The whole module is target-gated, not only `test`: `cerebellum-macos` builds
// to an empty library off macOS, so a test naming its types fails to COMPILE on
// Linux CI rather than failing to run. The production code above is already
// gated the same way; these tests exercise it and inherit the constraint.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Two drivers from one factory share one idle estimator: what the first
    /// sequence records, the second reads. A plane builds a driver per
    /// dispatch, so an estimator owned by the driver would be new every time
    /// and could never carry; this is the shape that fails under that
    /// implementation and passes under a shared one.
    #[test]
    fn drivers_from_one_factory_share_the_idle_estimator() {
        let shared = Arc::new(Mutex::new(UserIdleEstimator::new()));
        let factory = {
            let shared = shared.clone();
            move || MacOs26PlatformDriver::default().with_shared_user_idle(shared.clone())
        };
        let last_post_at = Instant::now()
            .checked_sub(Duration::from_millis(300))
            .expect("clock past epoch");
        // The first driver finishes a sequence and records it.
        factory()
            .user_idle
            .lock()
            .expect("estimator lock")
            .sequence_finished(
                last_post_at,
                IdleReading::Milliseconds(5_000),
                Duration::ZERO,
            );
        // The second driver, built afresh, reads that record: a raw HID idle
        // of 320 ms is the age of our own post, and the user idle carries.
        let user = factory()
            .user_idle
            .lock()
            .expect("estimator lock")
            .user_idle(IdleReading::Milliseconds(320), Instant::now());
        assert_eq!(
            user,
            IdleReading::Milliseconds(5_300),
            "the second driver did not see the first driver's sequence"
        );
    }

    /// A capability whose permission requirements cannot be read is suppressed,
    /// not advertised, and the process survives.
    ///
    /// The lookup reads the action vocabulary, which contains every id this
    /// driver asks about, so this cannot happen through `declarations` — which
    /// is exactly why it is worth a test. That branch is unreachable there, so
    /// nothing else can tell whether it suppresses, advertises, or ends the
    /// process. Ending it would take down every other capability along with the
    /// one whose permissions could not be read.
    #[test]
    fn a_capability_with_unreadable_permissions_is_suppressed_rather_than_fatal() {
        let driver = MacOs26PlatformDriver::default();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs::default(),
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        // A retired capability is one the vocabulary no longer lists, so its
        // permission lookup fails the way any unlisted capability's would.
        let declaration =
            capability_declaration(crate::audit::ComputerCapability::Click, &context, true);

        assert!(
            !declaration.advertised,
            "a capability with unknown permission requirements was advertised"
        );
        assert!(
            declaration.required_permissions.is_empty(),
            "an unresolvable lookup produced a permission list"
        );
        // The reason names the missing fact rather than the release-input note
        // that would otherwise overwrite it: a reader told the wrong cause looks
        // for a build omission instead of a vocabulary one.
        let reason = declaration
            .suppression_reason
            .expect("a suppressed capability states why");
        assert!(
            reason.contains("required permissions are not resolvable"),
            "the suppression reason does not name the permission lookup: {reason}"
        );
    }

    fn fully_bound_inputs() -> ImmutableReleaseInputs {
        ImmutableReleaseInputs {
            attendance_contract_owner: Some("fixture-owner".to_string()),
            attendance_contract_revision: Some("fixture-attendance-v1".to_string()),
            input_review_revision: Some("fixture-input-review-v1".to_string()),
            global_dispatch_review_revision: Some("fixture-global-review-v1".to_string()),
            capture_review_revision: Some("fixture-capture-review-v1".to_string()),
            semantic_actuation_review_revision: Some("fixture-semantic-review-v1".to_string()),
            app_state_review_revision: Some("fixture-app-state-review-v1".to_string()),
            element_addressed_review_revision: Some(
                "fixture-element-addressed-review-v1".to_string(),
            ),
            takeover_dispatch_review_revision: Some(
                "fixture-takeover-dispatch-review-v1".to_string(),
            ),
            windows_actuation_review_revision: Some("fixture-windows-review-v1".to_string()),
            release_signing_topology_revision: Some("fixture-topology-v1".to_string()),
            vocabulary_digests: VocabularyDigestInputs {
                manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
            },
        }
    }

    fn live(services: &[PermissionService]) -> PermissionLivenessReport {
        PermissionLivenessReport::from_results(services.iter().map(|service| {
            PermissionProbeResult {
                service: *service,
                liveness: PermissionLiveness::Live,
                responsible_process: String::new(),
                off_main: true,
            }
        }))
    }

    /// The takeover rows are advertised only when both of their reviews are
    /// bound, and each review is proved by isolation: with every other input
    /// bound and every permission live, leaving that one review unbound
    /// withholds all three rows and names that review.
    #[test]
    fn the_takeover_rows_need_both_reviews_each_proved_by_isolation() {
        let driver = MacOs26PlatformDriver::default();
        let everything = live(&[
            PermissionService::Accessibility,
            PermissionService::PostEvent,
            PermissionService::InputMonitoring,
            PermissionService::ScreenRecording,
        ]);
        let context = |inputs: ImmutableReleaseInputs| CapabilityAdvertisementContext {
            inputs,
            permissions: everything.clone(),
            startup: StartupCapabilityProbe {
                permissions: everything.clone(),
                ..driver.startup_probe().clone()
            },
        };
        let rows = [
            "computer.takeover_move",
            "computer.takeover_drag",
            "computer.takeover_scroll",
        ];
        // The accepting case first, so a gate that withheld everything fails.
        for id in rows {
            let declaration = driver.declaration(id, &context(fully_bound_inputs()));
            assert!(
                declaration.advertised,
                "{id} was withheld with everything bound: {:?}",
                declaration.suppression_reason
            );
        }
        let mut without_global = fully_bound_inputs();
        without_global.global_dispatch_review_revision = None;
        let mut without_takeover = fully_bound_inputs();
        without_takeover.takeover_dispatch_review_revision = None;
        for (reason, inputs) in [
            (
                "global dispatch review revision is not bound",
                without_global,
            ),
            (
                "takeover dispatch review revision is not bound",
                without_takeover,
            ),
        ] {
            for id in rows {
                let declaration = driver.declaration(id, &context(inputs.clone()));
                assert!(!declaration.advertised, "{id} was advertised: {reason}");
                assert_eq!(
                    declaration.suppression_reason.as_deref(),
                    Some(reason),
                    "{id}"
                );
            }
        }
    }

    /// computer.read_state is advertised on its own review and accessibility
    /// alone: with its review unbound it is withheld and says why, and with
    /// Screen Recording off it is still advertised, because only the optional
    /// image needs that grant.
    #[test]
    fn read_state_is_gated_on_its_own_review_and_not_on_screen_recording() {
        let driver = MacOs26PlatformDriver::default();
        let accessibility_only = live(&[PermissionService::Accessibility]);
        let context = |inputs: ImmutableReleaseInputs| CapabilityAdvertisementContext {
            inputs,
            permissions: accessibility_only.clone(),
            startup: StartupCapabilityProbe {
                permissions: accessibility_only.clone(),
                ..driver.startup_probe().clone()
            },
        };
        let bound = driver.declaration("computer.read_state", &context(fully_bound_inputs()));
        assert!(bound.advertised, "{:?}", bound.suppression_reason);

        let mut inputs = fully_bound_inputs();
        inputs.app_state_review_revision = None;
        let unbound = driver.declaration("computer.read_state", &context(inputs));
        assert!(!unbound.advertised);
        assert_eq!(
            unbound.suppression_reason.as_deref(),
            Some("application state review revision is not bound")
        );
    }

    /// computer.keys is withheld when accessibility is denied.
    ///
    /// Its row names accessibility because keys reads the target's focused
    /// element before posting, to refuse a secure field; on a machine that
    /// grants posting and input monitoring but denies accessibility, keys
    /// would advertise and then be unable to make that check.
    #[test]
    fn computer_keys_is_withheld_without_accessibility() {
        let driver = MacOs26PlatformDriver::default();
        assert!(
            crate::platform::vocabulary::required_permission_services("computer.keys")
                .expect("the vocabulary lists computer.keys")
                .contains(&PermissionService::Accessibility)
        );
        let context = |permissions: PermissionLivenessReport| CapabilityAdvertisementContext {
            inputs: fully_bound_inputs(),
            permissions: permissions.clone(),
            // The gate reads startup.permissions, so the readings must be
            // installed THERE. Setting the sibling field alone produced a
            // fixture that granted nothing while appearing to grant a lot.
            startup: StartupCapabilityProbe {
                permissions,
                ..driver.startup_probe().clone()
            },
        };

        let without = driver.declaration(
            "computer.keys",
            &context(live(&[
                PermissionService::PostEvent,
                PermissionService::InputMonitoring,
            ])),
        );
        assert!(
            !without.advertised,
            "computer.keys advertised with accessibility denied"
        );

        // The same context plus accessibility clears the refusal, so the one
        // above is the accessibility check and not some unrelated gate.
        let with = driver.declaration(
            "computer.keys",
            &context(live(&[
                PermissionService::Accessibility,
                PermissionService::PostEvent,
                PermissionService::InputMonitoring,
            ])),
        );
        assert!(
            with.advertised,
            "computer.keys was suppressed after every permission became live: {:?}",
            with.suppression_reason
        );
    }

    /// Binding every release input does not, by itself, activate an actuating row.
    ///
    /// The context below binds all six attestations and supplies NO permission
    /// readings. Both are required, and this fixes the direction that matters:
    /// a build carrying every review is still refused on a machine that has not
    /// granted the services the vocabulary names. A reviewer approving the code
    /// does not thereby approve access to a stranger's desktop.
    ///
    /// The suppression reason changed when the wire handlers landed -- it was
    /// "no wire serving handler", which stopped being true -- and the reason is
    /// asserted rather than only the refusal, because a row refused for a reason
    /// nobody checks can start being refused for a reason that is wrong.
    #[test]
    fn other_actuating_rows_remain_suppressed_for_fully_bound_release_inputs() {
        let driver = MacOs26PlatformDriver::default();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs {
                attendance_contract_owner: Some("fixture-owner".to_string()),
                attendance_contract_revision: Some("fixture-attendance-v1".to_string()),
                input_review_revision: Some("fixture-input-review-v1".to_string()),
                global_dispatch_review_revision: Some("fixture-global-review-v1".to_string()),
                capture_review_revision: Some("fixture-capture-review-v1".to_string()),
                semantic_actuation_review_revision: Some("fixture-semantic-review-v1".to_string()),
                app_state_review_revision: Some("fixture-app-state-review-v1".to_string()),
                element_addressed_review_revision: Some(
                    "fixture-element-addressed-review-v1".to_string(),
                ),
                takeover_dispatch_review_revision: Some(
                    "fixture-takeover-dispatch-review-v1".to_string(),
                ),
                windows_actuation_review_revision: Some("fixture-windows-review-v1".to_string()),
                release_signing_topology_revision: Some("fixture-topology-v1".to_string()),
                vocabulary_digests: VocabularyDigestInputs {
                    manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                    source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                    computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                },
            },
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        for id in ["computer.type", "computer.keys"] {
            let declaration = driver.declaration(id, &context);
            assert!(!declaration.advertised, "{id} was advertised");
            let reason = declaration
                .suppression_reason
                .expect("a suppressed capability states why");
            assert!(
                reason.contains("permission is not established"),
                "{id} is suppressed for an unexpected reason: {reason}"
            );
        }
    }

    /// A probe that panicked is not an absent grant, and the reason must say
    /// so on every row that consults permissions. The two send an operator to
    /// different places -- "not established" is answered in System Settings;
    /// a crashed probe is a module fault that no settings change repairs --
    /// so a report that names the wrong one costs a real person a wrong trip.
    /// Fixed against every OTHER gate so a row can only be withheld for this.
    #[test]
    fn a_panicked_permission_probe_is_named_as_a_module_fault_not_as_an_absent_grant() {
        let driver = MacOs26PlatformDriver::default();
        let mut startup = driver.startup_probe().clone();
        startup.permissions = PermissionLivenessReport::probe_failed();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs {
                attendance_contract_owner: Some("fixture-owner".to_string()),
                attendance_contract_revision: Some("fixture-attendance-v1".to_string()),
                input_review_revision: Some("fixture-input-review-v1".to_string()),
                global_dispatch_review_revision: Some("fixture-global-review-v1".to_string()),
                capture_review_revision: Some("fixture-capture-review-v1".to_string()),
                semantic_actuation_review_revision: Some("fixture-semantic-review-v1".to_string()),
                app_state_review_revision: Some("fixture-app-state-review-v1".to_string()),
                element_addressed_review_revision: Some(
                    "fixture-element-addressed-review-v1".to_string(),
                ),
                takeover_dispatch_review_revision: Some(
                    "fixture-takeover-dispatch-review-v1".to_string(),
                ),
                windows_actuation_review_revision: Some("fixture-windows-review-v1".to_string()),
                release_signing_topology_revision: Some("fixture-topology-v1".to_string()),
                vocabulary_digests: VocabularyDigestInputs {
                    manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                    source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                    computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                },
            },
            permissions: PermissionLivenessReport::probe_failed(),
            startup,
        };

        for id in ["computer.type", "computer.keys"] {
            let declaration = driver.declaration(id, &context);
            assert!(!declaration.advertised, "{id} was advertised");
            let reason = declaration
                .suppression_reason
                .expect("a suppressed capability states why");
            assert!(
                reason.contains("probe did not complete") && reason.contains("module fault"),
                "{id} names something other than the crash: {reason}"
            );
            assert!(
                !reason.contains("not established") && !reason.contains("not granted"),
                "{id} describes a grant nobody looked at: {reason}"
            );
        }
    }

    /// A wire surface with no expected post-condition makes no effect claim.
    #[test]
    fn absent_wire_post_condition_skips_observation_and_reports_the_frozen_coarser_status() {
        let mut driver = MacOs26PlatformDriver::default().without_expected_post_condition();
        let result = driver
            .observe_effect(EffectObservationRequest {
                target: ProcessGrant {
                    // No process can be inspected at pid zero. If the dedicated
                    // branch is removed, the attempted read reports the distinct
                    // observation-primitive-unavailable reason.
                    pid: 0,
                    bundle_identity: "com.example.target".to_string(),
                    process_generation_evidence: "generation-1".to_string(),
                },
                predicate: serde_json::to_string(&crate::dispatch::ExpectedPostCondition::new(
                    "fixture-effect-v1",
                    crate::dispatch::post_condition::PostCondition::ElementPresent {
                        element: AccessibilityElementName::identifier("element-1"),
                    },
                ))
                .expect("the fixture post-condition serializes"),
                deadline_ms: 1,
            })
            .expect("absence of a claim is a result, not a platform failure");

        assert_eq!(result.status, EffectStatus::EffectIndeterminate);
        assert_eq!(
            result.failure_reason.as_deref(),
            Some("post_condition_undeclarable")
        );
    }

    /// Every mapped macOS action is accepted by the framework vocabulary.
    ///
    /// The platform driver delivers the mapping result rather than the wire intent.
    /// Keeping this assertion against `AxAction` prevents a mapping typo from being
    /// accepted by neutral test doubles while every live action is refused.
    #[test]
    fn macos_delivered_actions_match_the_framework_vocabulary() {
        let actions = [
            (
                SemanticActionIntent::Press,
                cerebellum_macos::AxAction::Press,
            ),
            (
                SemanticActionIntent::Cancel,
                cerebellum_macos::AxAction::Cancel,
            ),
        ];

        for (intent, action) in actions {
            let delivered = delivered_semantic_action(SemanticActionPlatform::MacOs, intent)
                .expect("macOS serves every semantic intent");
            assert_eq!(
                delivered,
                action.name(),
                "the delivered action differs from the framework spelling"
            );
            assert_eq!(
                cerebellum_macos::AxAction::from_name(delivered),
                Some(action),
                "the framework vocabulary does not recognise the delivered action"
            );
        }
    }

    /// A capability in the vocabulary carries the permissions it lists.
    ///
    /// The accepting case. Without it, a driver that suppressed EVERY capability
    /// would satisfy the refusal test and look correct.
    #[test]
    fn a_frozen_capability_carries_the_permissions_the_vocabulary_lists() {
        let driver = MacOs26PlatformDriver::default();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs::default(),
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        let declaration = driver.declaration("computer.type", &context);
        assert_eq!(
            declaration.required_permissions,
            vec![
                PermissionService::Accessibility,
                PermissionService::PostEvent,
                PermissionService::InputMonitoring,
            ]
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod accessibility_tests {

    /// A replaced target fails attendance even when the lease is otherwise good.
    ///
    /// This is what the platform check adds. A lease can be unexpired and
    /// correctly bound to its conversation while the process behind the
    /// identifier has been replaced, because a replacement inherits the
    /// identifier the lease names. The caller cannot see that, and acting on it
    /// delivers to whatever holds the identifier now.
    ///
    /// Constructed against an identifier this process can read: a grant whose
    /// recorded generation cannot match the running process stands for the
    /// replacement case, since the two are the same observation.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_target_whose_generation_does_not_match_fails_attendance() {
        let mut driver = MacOs26PlatformDriver::new(&crate::platform::StartupProbeInput {
            os_major: 26,
            private_envelope_revision: None,
            resolved_private_symbols: Default::default(),
            permission_results: Vec::new(),
            responsible_process: None,
        });

        let stale = ProcessGrant {
            pid: std::process::id(),
            bundle_identity: "com.example.self".into(),
            process_generation_evidence: "generation-that-never-was".into(),
        };
        let result = driver
            .verify_attendance(AttendancePreconditionRequest {
                conversation_id: "conversation-1".into(),
                target: stale,
                maximum_lease_age_ms: 300_000,
            })
            .expect("the check answers rather than refusing");
        assert!(
            !result.valid,
            "a target whose generation does not match was reported as current"
        );

        // Nothing about the lease is echoed back: this check answers one
        // question, and reporting the caller's own values would present them as
        // an independent reading.
        assert_eq!(result.lease_generation, None);
        assert_eq!(result.age_ms, None);
    }

    /// A process that no longer exists fails attendance.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_target_that_is_gone_fails_attendance() {
        let mut driver = MacOs26PlatformDriver::new(&crate::platform::StartupProbeInput {
            os_major: 26,
            private_envelope_revision: None,
            resolved_private_symbols: Default::default(),
            permission_results: Vec::new(),
            responsible_process: None,
        });

        let result = driver
            .verify_attendance(AttendancePreconditionRequest {
                conversation_id: "conversation-1".into(),
                // A pid the kernel will not resolve to a running process.
                target: ProcessGrant {
                    pid: u32::MAX - 1,
                    bundle_identity: "com.example.gone".into(),
                    process_generation_evidence: "generation-1".into(),
                },
                maximum_lease_age_ms: 300_000,
            })
            .expect("the check answers rather than refusing");
        assert!(!result.valid);
    }

    /// A platform acceptance does not claim an effect.
    ///
    /// The single most important property here: the accessibility API returns
    /// when the application's handler returns, so acceptance is evidence the
    /// request was delivered and nothing more. A caller told the effect was
    /// OBSERVED would skip the observation that establishes it, and would do so
    /// exactly against the applications whose handlers return without acting.
    #[test]
    fn platform_acceptance_discloses_partial_tree_without_claiming_effect() {
        let result = dispatch_result_for_accepted_action(
            cerebellum_macos::AxActionRequestOutcome::HandlerReturned {
                matched_by: cerebellum_macos::AxElementName::Identifier("button".to_owned()),
                alternate_name: Some(cerebellum_macos::AxElementName::RoleAndTitle {
                    role: "AXButton".to_owned(),
                    title: "Save".to_owned(),
                }),
                unreadable_subtrees: 3,
            },
        );
        assert!(result.accepted_by_platform);
        assert_eq!(result.effect_status, EffectStatus::EffectIndeterminate);
        assert_eq!(result.unreadable_subtrees, 3);
    }

    /// Every framework action failure maps to its caller remedy.
    ///
    /// Internal traversal and value faults deliberately share `PathUnavailable`;
    /// the remaining cases stay distinct because their callers must take
    /// different actions.
    #[test]
    fn every_action_failure_maps_to_a_distinct_remedy() {
        use cerebellum_macos::{AxAction, AxActionError, AxElementName};

        let advertised = vec!["AXPress".to_string(), "AXConfirm".to_string()];
        let cases = [
            (
                AxActionError::PermissionNotGranted,
                DriverError::Semantic(SemanticDriverError::AccessibilityPermissionUnavailable),
            ),
            (
                AxActionError::NoSuchProcess { pid: 7 },
                DriverError::Semantic(SemanticDriverError::TargetNoLongerCurrent {
                    disposition: TargetDisposition::Gone,
                }),
            ),
            (
                AxActionError::ProcessNotAccessible {
                    pid: 7,
                    ax_error: -25204,
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::ElementNotFound {
                    element_name: AxElementName::Identifier("absent".to_string()),
                },
                DriverError::Semantic(SemanticDriverError::ElementNotFound {
                    key_form: AccessibilityKeyForm::Identifier,
                }),
            ),
            (
                AxActionError::ElementIdentifierAmbiguous {
                    element_name: AxElementName::RoleAndTitle {
                        role: "AXButton".to_string(),
                        title: "Save".to_string(),
                    },
                    match_count: 2,
                },
                DriverError::Semantic(SemanticDriverError::ElementNameAmbiguous {
                    key_form: AccessibilityKeyForm::RoleAndTitle,
                    match_count: 2,
                }),
            ),
            (
                AxActionError::ActionNotAdvertised {
                    element_name: AxElementName::Identifier("save".to_string()),
                    action: AxAction::Press,
                    advertised: advertised.clone(),
                },
                DriverError::Semantic(SemanticDriverError::ActionNotAdvertised {
                    action: "press".to_string(),
                    advertised: advertised.clone(),
                }),
            ),
            (
                AxActionError::ApplicationRefusedAction {
                    element_name: AxElementName::Identifier("save".to_string()),
                    action: AxAction::Press,
                    ax_error: -25205,
                },
                DriverError::Semantic(SemanticDriverError::ApplicationRefused { ax_error: -25205 }),
            ),
            (
                AxActionError::DeadlineExceeded {
                    timeout: Duration::from_millis(1),
                },
                DriverError::Semantic(SemanticDriverError::Transient { deadline_ms: 1 }),
            ),
            (
                AxActionError::DepthLimitExceeded {
                    max_depth: 32,
                    attempted_depth: 33,
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::ElementLimitExceeded {
                    max_elements: 10_000,
                    attempted_elements: 10_001,
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::UnexpectedValueType {
                    attribute: "AXRole",
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::SystemCallFailed {
                    operation: "AXUIElementPerformAction",
                    ax_error: -25206,
                },
                DriverError::Semantic(SemanticDriverError::Transient { deadline_ms: 3_000 }),
            ),
        ];

        for (raw, expected) in cases {
            assert_eq!(
                map_ax_action_error(raw.clone(), "press", 3_000),
                expected,
                "{raw:?}"
            );
        }
    }

    use super::*;

    #[test]
    fn reader_failures_map_to_distinct_typed_driver_errors() {
        let cases = [
            (
                AccessibilityReaderFailure::PermissionDenied,
                AccessibilityReadFailure::PermissionRequired,
            ),
            (
                AccessibilityReaderFailure::ProcessGone,
                AccessibilityReadFailure::TargetGone,
            ),
            (
                AccessibilityReaderFailure::ProcessNotInspectable,
                AccessibilityReadFailure::TargetNotInspectable,
            ),
            (
                AccessibilityReaderFailure::DeadlineExceeded,
                AccessibilityReadFailure::RetryableDeadlineExceeded,
            ),
            (
                AccessibilityReaderFailure::BoundExceeded,
                AccessibilityReadFailure::TreeExceedsBound,
            ),
            (
                AccessibilityReaderFailure::IncompatibleValue,
                AccessibilityReadFailure::IncompatiblePlatformValue,
            ),
            (
                AccessibilityReaderFailure::SystemFailure,
                AccessibilityReadFailure::PlatformReadFailed,
            ),
        ];

        for (reader_failure, expected) in cases {
            assert_eq!(
                DriverError::from(AccessibilityReadFailure::from(reader_failure)),
                DriverError::AccessibilityUnreadable(expected),
                "the reader failure {reader_failure:?} did not retain its caller-visible remedy"
            );
        }
    }

    #[test]
    fn settle_interval_bounds_the_read_without_a_pre_read_wait() {
        assert_eq!(
            accessibility_read_timeout(500),
            Ok(Duration::from_millis(500))
        );
        assert_eq!(
            accessibility_read_timeout(300_001),
            Err(DriverError::InvalidRequest(
                "duration exceeds vocabulary bound"
            ))
        );
    }

    #[test]
    fn root_handle_binds_the_cache_to_the_granted_process_generation() {
        let first = ProcessGrant {
            pid: 41,
            bundle_identity: "com.example.reader".to_string(),
            process_generation_evidence: "generation-a".to_string(),
        };
        let replacement = ProcessGrant {
            process_generation_evidence: "generation-b".to_string(),
            ..first.clone()
        };

        assert_eq!(root_cache_key(&first), "accessibility-root:41:generation-a");
        assert_ne!(root_cache_key(&first), root_cache_key(&replacement));
    }

    #[test]
    fn an_empty_root_uses_the_closed_degeneracy_vocabulary() {
        assert_eq!(
            root_degenerate_reason(0, 0),
            Some("missing_children_for_nontrivial_window".to_string())
        );
        assert_eq!(root_degenerate_reason(1, 0), None);
        assert_eq!(
            root_degenerate_reason(2, 3),
            Some("incomplete_accessibility_tree:3_unreadable_subtrees".to_string())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn every_raw_read_error_preserves_its_typed_remedy() {
        let cases = [
            (
                cerebellum_macos::AxReadError::PermissionNotGranted,
                AccessibilityReadFailure::PermissionRequired,
            ),
            (
                cerebellum_macos::AxReadError::NoSuchProcess { pid: 41 },
                AccessibilityReadFailure::TargetGone,
            ),
            (
                cerebellum_macos::AxReadError::ProcessNotAccessible {
                    pid: 41,
                    ax_error: -25204,
                },
                AccessibilityReadFailure::TargetNotInspectable,
            ),
            (
                cerebellum_macos::AxReadError::DeadlineExceeded {
                    timeout: Duration::from_millis(500),
                },
                AccessibilityReadFailure::RetryableDeadlineExceeded,
            ),
            (
                cerebellum_macos::AxReadError::DepthLimitExceeded {
                    max_depth: 4,
                    attempted_depth: 5,
                },
                AccessibilityReadFailure::TreeExceedsBound,
            ),
            (
                cerebellum_macos::AxReadError::ElementLimitExceeded {
                    max_elements: 4,
                    attempted_elements: 5,
                },
                AccessibilityReadFailure::TreeExceedsBound,
            ),
            (
                cerebellum_macos::AxReadError::UnexpectedValueType {
                    attribute: "AXChildren",
                },
                AccessibilityReadFailure::IncompatiblePlatformValue,
            ),
            (
                cerebellum_macos::AxReadError::SystemCallFailed {
                    operation: "AXUIElementCopyAttributeValue",
                    ax_error: -25205,
                },
                AccessibilityReadFailure::PlatformReadFailed,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(
                map_ax_read_error(error),
                DriverError::AccessibilityUnreadable(expected)
            );
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod cached_element_tests {
    use super::*;

    fn cached_tree() -> CachedAccessibilityTree {
        CachedAccessibilityTree {
            target: ProcessGrant {
                pid: 41,
                bundle_identity: "com.example.reader".to_string(),
                process_generation_evidence: "generation-a".to_string(),
            },
            tree: CachedAccessibilityElement {
                identifier: Some("root-actual-id".to_string()),
                role: Some("AXApplication".to_string()),
                title: Some("Reader".to_string()),
                actions: Vec::new(),
                children: vec![
                    CachedAccessibilityElement {
                        identifier: Some("identifier-only".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("Shared".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: None,
                        role: Some("AXButton".to_string()),
                        title: Some("Save".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: Some("shared-title-peer".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("Shared".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: Some("duplicate-identifier".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("First Duplicate".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: Some("duplicate-identifier".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("Second Duplicate".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                ],
            },
            unreadable_subtrees: 0,
        }
    }

    #[test]
    fn missing_element_is_distinct_from_an_unreadable_tree() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::Identifier("missing".to_string()),
        };

        assert_eq!(
            resolve_cached_element(&cached_tree(), &request),
            Err(DriverError::ElementNotFound)
        );
    }

    #[test]
    fn an_incomplete_cached_tree_resolves_a_unique_in_scope_element_and_discloses_scope() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::Identifier("identifier-only".to_string()),
        };
        let mut tree = cached_tree();
        tree.unreadable_subtrees = 1;

        let resolution = resolution_from_cached_tree(&tree, &request)
            .expect("the readable tree contains one matching element");
        assert_eq!(resolution.element_name, request.element_name);
        assert_eq!(resolution.unreadable_subtrees, 1);
    }

    #[test]
    fn cached_element_preserves_advertised_action_names() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::Identifier("identifier-only".to_string()),
        };

        let tree = cached_tree();
        let element = resolve_cached_element(&tree, &request)
            .expect("the constructed cache contains the named child");
        assert_eq!(element.actions, vec!["AXPress"]);
    }

    #[test]
    fn resolution_exposes_only_closed_wire_intents() {
        let platform_actions = vec![
            "AXPress".to_owned(),
            "AXCancel".to_owned(),
            "AXConfirm".to_owned(),
            "caller_knows_best".to_owned(),
        ];

        assert_eq!(
            semantic_intents_advertised_by(&platform_actions),
            vec![SEMANTIC_PRESS_ACTION, SEMANTIC_CANCEL_ACTION]
        );
    }

    #[test]
    fn resolution_reports_the_exact_key_that_established_uniqueness() {
        let cases = [
            (
                AccessibilityElementName::Identifier("identifier-only".to_string()),
                Some(AccessibilityElementName::RoleAndTitle {
                    role: "AXButton".to_string(),
                    title: "Shared".to_string(),
                }),
            ),
            (
                AccessibilityElementName::RoleAndTitle {
                    role: "AXButton".to_string(),
                    title: "Save".to_string(),
                },
                None,
            ),
        ];
        let tree = cached_tree();

        for (name, alternate_name) in cases {
            let request = ElementResolutionRequest {
                root_identifier: "accessibility-root:41:generation-a".to_string(),
                element_name: name.clone(),
            };
            let resolution = resolution_from_cached_tree(&tree, &request)
                .expect("the fixture makes each supplied key unique");
            assert_eq!(resolution.element_name, name);
            assert_eq!(resolution.alternate_name, alternate_name);
            assert_eq!(resolution.semantic_actions, vec![SEMANTIC_PRESS_ACTION]);
            assert_eq!(resolution.unreadable_subtrees, 0);
        }
    }

    #[test]
    fn resolution_never_falls_back_between_key_forms() {
        let requests = [
            ElementResolutionRequest {
                root_identifier: "accessibility-root:41:generation-a".to_string(),
                element_name: AccessibilityElementName::Identifier("Save".to_string()),
            },
            ElementResolutionRequest {
                root_identifier: "accessibility-root:41:generation-a".to_string(),
                element_name: AccessibilityElementName::RoleAndTitle {
                    role: "AXButton".to_string(),
                    title: "identifier-only".to_string(),
                },
            },
        ];
        let tree = cached_tree();

        for request in requests {
            assert_eq!(
                resolution_from_cached_tree(&tree, &request),
                Err(DriverError::ElementNotFound)
            );
        }
    }

    #[test]
    fn a_shared_role_and_title_is_refused_instead_of_resolving_the_first_match() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::RoleAndTitle {
                role: "AXButton".to_string(),
                title: "Shared".to_string(),
            },
        };

        assert_eq!(
            resolution_from_cached_tree(&cached_tree(), &request),
            Err(DriverError::InvalidRequest(AMBIGUOUS_ELEMENT_NAME))
        );
    }

    #[test]
    fn a_shared_identifier_is_refused_instead_of_resolving_the_first_match() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::Identifier("duplicate-identifier".to_string()),
        };

        assert_eq!(
            resolution_from_cached_tree(&cached_tree(), &request),
            Err(DriverError::InvalidRequest(AMBIGUOUS_ELEMENT_NAME))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dispatch_preserves_a_role_and_title_resolution_key() {
        let name = AccessibilityElementName::RoleAndTitle {
            role: "AXButton".to_string(),
            title: "Save".to_string(),
        };

        let ax_name = ax_element_name(&name).expect("the fixture name is usable");
        assert_eq!(
            ax_name,
            cerebellum_macos::AxElementName::RoleAndTitle {
                role: "AXButton".to_string(),
                title: "Save".to_string(),
            }
        );
        assert_eq!(AccessibilityElementName::from(ax_name), name);
    }

    mod synthetic_dispatch {
        use super::*;
        use objc2_core_graphics::{CGEvent, CGEventField, CGEventFlags, CGEventType};
        use std::collections::VecDeque;

        const PID: u32 = 41;
        const START_TIME_MICROS: u64 = 8_000_123;

        /// A transport that records what it was asked to post instead of
        /// calling the window server.
        ///
        /// The events it stores are the real constructed CoreGraphics events,
        /// so a test reads back exactly what the platform would have received
        /// — an `Ok` from dispatch alone would also pass against a driver
        /// that posted nothing at all.
        struct RecordingTransport {
            generations: VecDeque<ProcessGenerationReading>,
            post_results: VecDeque<Result<PostCallMade, PostCallFailure>>,
            calls: Vec<&'static str>,
            posted: Vec<cerebellum_macos::OwnedCgEvent>,
        }

        impl RecordingTransport {
            fn new(
                generation_readings: usize,
                post_results: impl IntoIterator<Item = Result<PostCallMade, PostCallFailure>>,
            ) -> Self {
                Self {
                    generations: (0..generation_readings)
                        .map(|_| ProcessGenerationReading::Started(START_TIME_MICROS))
                        .collect(),
                    post_results: post_results.into_iter().collect(),
                    calls: Vec::new(),
                    posted: Vec::new(),
                }
            }

            fn succeeding(event_count: usize) -> Self {
                Self::new(
                    event_count * 2,
                    (0..event_count).map(|_| Ok(PostCallMade::public_core_graphics())),
                )
            }

            /// The calls made per event, in order: a generation read before
            /// the visibility read, another immediately before the post.
            fn calls_per_event(&self) -> Vec<&[&'static str]> {
                self.calls.chunks(4).collect()
            }
        }

        impl PerProcessEventTransport for RecordingTransport {
            type Event = cerebellum_macos::OwnedCgEvent;

            fn process_generation(&mut self, _pid: u32) -> ProcessGenerationReading {
                self.calls.push("generation");
                self.generations
                    .pop_front()
                    .expect("the test supplied every expected generation reading")
            }

            fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
                self.calls.push("visibility");
                WindowServerVisibility::Visible
            }

            fn post_to_pid(
                &mut self,
                _pid: u32,
                event: Self::Event,
            ) -> Result<PostCallMade, PostCallFailure> {
                self.calls.push("post");
                self.posted.push(event);
                self.post_results
                    .pop_front()
                    .expect("the test supplied every expected post result")
            }
        }

        fn grant() -> ProcessGrant {
            ProcessGrant {
                pid: PID,
                bundle_identity: "com.example.target".to_string(),
                process_generation_evidence: START_TIME_MICROS.to_string(),
            }
        }

        fn request(action: SyntheticAction) -> SyntheticDispatchRequest {
            SyntheticDispatchRequest {
                target: grant(),
                action,
            }
        }

        fn global_request(action: SyntheticAction) -> GlobalDispatchRequest {
            GlobalDispatchRequest {
                synthetic: request(action),
                once_dispatch_token:
                    cerebellum_core::consent::OnceDispatchToken::admitted_by_takeover_grant(),
                maximum_seize_detection_latency_ms: 50,
                minimum_inter_post_interval_ms: 50,
            }
        }

        fn dispatch(
            action: SyntheticAction,
            transport: &mut RecordingTransport,
        ) -> Result<DispatchResult, DriverError> {
            dispatch_synthetic_to_pid(
                &request(action),
                transport,
                &super::super::process_event::never_cancelled,
            )
        }

        #[test]
        fn each_action_posts_the_events_that_tell_it_apart_from_the_others() {
            // Text: a down/up pair per character on the Unicode path —
            // keycode zero with no modifiers, so no keyboard layout or
            // shortcut table is involved. (The characters themselves are
            // asserted by the constructor's own tests in cerebellum-macos;
            // reading them back requires unsafe, which this crate forbids.)
            let mut transport = RecordingTransport::succeeding(4);
            let result = dispatch(SyntheticAction::type_text("hi"), &mut transport)
                .expect("text dispatch posts");
            assert!(result.accepted_by_platform);
            assert_eq!(result.effect_status, EffectStatus::EffectIndeterminate);
            assert_eq!(result.delivery_posts_returned, 4);
            assert_eq!(result.delivery_generation_verifications, 8);
            assert_eq!(
                result.identity_to_delivery_binding(),
                crate::platform::containment::IdentityAtomicBinding::Atomic
            );
            assert_eq!(transport.posted.len(), 4);
            for (index, event) in transport.posted.iter().enumerate() {
                assert_eq!(
                    CGEvent::r#type(Some(event)),
                    if index % 2 == 0 {
                        CGEventType::KeyDown
                    } else {
                        CGEventType::KeyUp
                    }
                );
                assert_eq!(
                    CGEvent::integer_value_field(Some(event), CGEventField::KeyboardEventKeycode,),
                    0
                );
                assert_eq!(CGEvent::flags(Some(event)), CGEventFlags::empty());
            }

            // Combination: one down/up pair with the keycode and the modifier.
            let mut transport = RecordingTransport::succeeding(2);
            dispatch(
                SyntheticAction::key_combination(
                    SyntheticKey::K,
                    SyntheticKeyModifiers {
                        command: true,
                        ..SyntheticKeyModifiers::NONE
                    },
                ),
                &mut transport,
            )
            .expect("combination dispatch posts");
            assert_eq!(transport.posted.len(), 2);
            for event in &transport.posted {
                assert_eq!(
                    CGEvent::integer_value_field(Some(event), CGEventField::KeyboardEventKeycode,),
                    0x28
                );
                assert!(CGEvent::flags(Some(event)).contains(CGEventFlags::MaskCommand));
            }

            // Scroll: one wheel event with the delta.
            let mut transport = RecordingTransport::succeeding(1);
            dispatch(
                SyntheticAction::scroll(SyntheticScrollUnit::Line, -3),
                &mut transport,
            )
            .expect("scroll dispatch posts");
            assert_eq!(transport.posted.len(), 1);
            let event = &transport.posted[0];
            assert_eq!(CGEvent::r#type(Some(event)), CGEventType::ScrollWheel);
            assert_eq!(
                CGEvent::integer_value_field(Some(event), CGEventField::ScrollWheelEventDeltaAxis1,),
                -3
            );

            // Move: one move event at the point.
            let mut transport = RecordingTransport::succeeding(1);
            dispatch(
                SyntheticAction::move_pointer(SyntheticPoint { x: 10.0, y: 20.0 }),
                &mut transport,
            )
            .expect("move dispatch posts");
            assert_eq!(transport.posted.len(), 1);
            let event = &transport.posted[0];
            assert_eq!(CGEvent::r#type(Some(event)), CGEventType::MouseMoved);
            assert_eq!(CGEvent::location(Some(event)).x, 10.0);
            assert_eq!(CGEvent::location(Some(event)).y, 20.0);

            // Drag: press, drag, release, in that order.
            let mut transport = RecordingTransport::succeeding(3);
            dispatch(
                SyntheticAction::drag_pointer(
                    SyntheticPoint { x: 10.0, y: 20.0 },
                    SyntheticPoint { x: 90.0, y: 120.0 },
                ),
                &mut transport,
            )
            .expect("drag dispatch posts");
            assert_eq!(transport.posted.len(), 3);
            let types: Vec<_> = transport
                .posted
                .iter()
                .map(|event| CGEvent::r#type(Some(event)))
                .collect();
            assert_eq!(
                types,
                vec![
                    CGEventType::LeftMouseDown,
                    CGEventType::LeftMouseDragged,
                    CGEventType::LeftMouseUp,
                ]
            );
        }

        #[test]
        fn the_generation_is_re_read_immediately_before_every_post() {
            let mut transport = RecordingTransport::succeeding(3);
            let result = dispatch(
                SyntheticAction::drag_pointer(
                    SyntheticPoint { x: 0.0, y: 0.0 },
                    SyntheticPoint { x: 1.0, y: 1.0 },
                ),
                &mut transport,
            )
            .expect("drag dispatch posts");

            assert_eq!(result.delivery_posts_returned, 3);
            assert_eq!(result.delivery_generation_verifications, 6);
            assert_eq!(
                result.identity_to_delivery_binding(),
                crate::platform::containment::IdentityAtomicBinding::Atomic,
                "every returned post needs both generation checks"
            );
            for per_event in transport.calls_per_event() {
                assert_eq!(
                    per_event,
                    &["generation", "visibility", "generation", "post"],
                    "an event was posted without a fresh generation read before it"
                );
            }
        }

        #[test]
        fn a_recycled_pid_stops_the_sequence_and_leaves_no_claim_of_release() {
            // The late generation read before the SECOND text event observes
            // a replacement. The first event was a key-down whose paired
            // key-up is the step that failed, so its event is gone and the
            // held state can only be reported as unknown.
            let mut transport = RecordingTransport::new(
                3,
                [
                    Ok(PostCallMade::public_core_graphics()),
                    Ok(PostCallMade::public_core_graphics()),
                ],
            );
            transport.generations = VecDeque::from([
                ProcessGenerationReading::Started(START_TIME_MICROS),
                ProcessGenerationReading::Started(START_TIME_MICROS),
                ProcessGenerationReading::Started(START_TIME_MICROS),
                ProcessGenerationReading::Started(START_TIME_MICROS + 1),
            ]);

            let error = dispatch(SyntheticAction::type_text("hi"), &mut transport)
                .expect_err("a replaced target stops the sequence");

            let DriverError::SyntheticDispatchFailed(failure) = error else {
                panic!("a mid-sequence replacement is a synthetic dispatch failure: {error:?}")
            };
            assert_eq!(failure.posts_returned, 1);
            assert_eq!(
                failure.refusal,
                ProcessEventRefusal::ProcessReplaced {
                    expected_start_time_micros: START_TIME_MICROS,
                    observed_start_time_micros: START_TIME_MICROS + 1,
                }
            );
            assert_eq!(failure.held_state, HeldStateDisposition::Unknown);
            assert_eq!(transport.posted.len(), 1);
        }

        #[test]
        fn a_mid_sequence_failure_releases_the_held_button_and_says_so() {
            // The drag move fails after the press posted; the release is
            // still in hand and is posted rather than leaving the button down.
            let mut transport = RecordingTransport::new(
                6,
                [
                    Ok(PostCallMade::public_core_graphics()),
                    Err(PostCallFailure::new("framework call failed")),
                    Ok(PostCallMade::public_core_graphics()),
                ],
            );

            let error = dispatch(
                SyntheticAction::drag_pointer(
                    SyntheticPoint { x: 0.0, y: 0.0 },
                    SyntheticPoint { x: 1.0, y: 1.0 },
                ),
                &mut transport,
            )
            .expect_err("a failed drag move stops the sequence");

            let DriverError::SyntheticDispatchFailed(failure) = error else {
                panic!("a mid-sequence failure is a synthetic dispatch failure: {error:?}")
            };
            assert_eq!(failure.posts_returned, 1);
            assert_eq!(
                failure.held_state,
                HeldStateDisposition::Released { posts_returned: 1 }
            );
            // Three post attempts: the press, the move that failed, and then
            // the release — attempted after the failure rather than
            // abandoning the held button.
            assert_eq!(transport.posted.len(), 3);
            assert_eq!(
                CGEvent::r#type(Some(&transport.posted[2])),
                CGEventType::LeftMouseUp
            );
        }

        #[test]
        fn a_failed_release_reports_the_button_state_as_unknown() {
            let mut transport = RecordingTransport::new(
                6,
                [
                    Ok(PostCallMade::public_core_graphics()),
                    Ok(PostCallMade::public_core_graphics()),
                    Err(PostCallFailure::new("framework call failed")),
                ],
            );

            let error = dispatch(
                SyntheticAction::drag_pointer(
                    SyntheticPoint { x: 0.0, y: 0.0 },
                    SyntheticPoint { x: 1.0, y: 1.0 },
                ),
                &mut transport,
            )
            .expect_err("a failed release stops the sequence");

            let DriverError::SyntheticDispatchFailed(failure) = error else {
                panic!("a failed release is a synthetic dispatch failure: {error:?}")
            };
            assert_eq!(failure.posts_returned, 2);
            assert_eq!(failure.held_state, HeldStateDisposition::Unknown);
            assert_eq!(transport.posted.len(), 3);
        }

        #[test]
        fn a_grant_without_kernel_generation_evidence_is_refused_before_any_post() {
            let mut request = request(SyntheticAction::type_text("hi"));
            request.target.process_generation_evidence = "generation-1".to_string();
            let mut transport = RecordingTransport::succeeding(4);

            assert_eq!(
                dispatch_synthetic_to_pid(
                    &request,
                    &mut transport,
                    &super::super::process_event::never_cancelled
                ),
                Err(DriverError::InvalidRequest(
                    "process generation evidence is not a kernel start time"
                ))
            );
            assert!(transport.posted.is_empty());
        }

        #[test]
        fn dispatch_global_is_refused_by_the_unbound_review_key() {
            let mut driver = MacOs26PlatformDriver::default();
            let refusal = driver
                .dispatch_global(
                    global_request(SyntheticAction::move_pointer(SyntheticPoint {
                        x: 0.0,
                        y: 0.0,
                    })),
                    &super::super::process_event::never_cancelled,
                )
                .expect_err("an unbound global review key refuses dispatch");

            assert_eq!(
                refusal,
                DriverError::StartupRefused("global_dispatch_review_revision is not bound"),
                "the refusal must name the missing release gate"
            );
        }
    }
}

/// The global sequence owns recovery as well as cancellation: its event poster
/// is injected so a release can be proved without holding the desktop's button.
fn post_global_sequence<E>(
    steps: Vec<super::process_event::SyntheticStep<E>>,
    cancelled: &dyn Fn() -> bool,
    post: impl FnMut(usize, Option<E>, bool) -> Result<u64, DriverError>,
) -> Result<super::process_event::SequencePostReport, DriverError> {
    super::process_event::post_guarded_event_sequence(steps, cancelled, post).map_err(|failure| {
        failure.refusal.unwrap_or({
            DriverError::SyntheticDispatchFailed(super::process_event::SequencePostFailure {
                posts_returned: failure.posts_returned,
                refusal: super::process_event::ProcessEventRefusal::Cancelled,
                held_state: failure.held_state,
            })
        })
    })
}

#[cfg(test)]
mod global_cancellation_tests {
    use super::super::process_event::{HeldStateDisposition, SyntheticStep, SyntheticStepRole};
    use super::*;
    use std::cell::Cell;

    #[test]
    fn a_cancelled_global_drag_releases_the_desktop_button() {
        let returned = Cell::new(0);
        let mut posted = Vec::new();
        let steps = vec![
            SyntheticStep {
                event: "press",
                role: SyntheticStepRole::Press,
            },
            SyntheticStep {
                event: "move",
                role: SyntheticStepRole::SelfContained,
            },
            SyntheticStep {
                event: "release",
                role: SyntheticStepRole::Release,
            },
        ];
        let failure = post_global_sequence(steps, &|| returned.get() == 1, |_, event, recovery| {
            if let Some(event) = event {
                posted.push((event, recovery));
                returned.set(returned.get() + 1);
            }
            Ok(1)
        })
        .unwrap_err();
        let DriverError::SyntheticDispatchFailed(failure) = failure else {
            panic!("not a sequence cancellation")
        };
        assert_eq!(failure.posts_returned, 1);
        assert_eq!(
            failure.held_state,
            HeldStateDisposition::Released { posts_returned: 1 }
        );
        assert_eq!(posted, [("press", false), ("release", true)]);
    }
}
