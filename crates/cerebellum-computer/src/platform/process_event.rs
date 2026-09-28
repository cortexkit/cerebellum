//! Platform-neutral routing for one synthesized event to one process.
//!
//! This module decides whether the selected per-process transport may be called.
//! It does not expose a global transport, and the event is moved into the
//! selected transport even when that transport reports failure. That ownership
//! boundary makes retrying the same event through another transport impossible.

#[cfg(target_os = "macos")]
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The process generation an event was authorized for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessEventTarget {
    pub pid: u32,
    pub start_time_micros: u64,
}

/// A fresh kernel reading of the process currently holding a pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGenerationReading {
    Started(u64),
    Gone,
    NotInspectable,
}

/// Whether the window server currently describes the target process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowServerVisibility {
    Visible,
    NotVisible,
    Unreadable(String),
}

/// The one per-process transport this routing slice selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerProcessTransport {
    PublicCoreGraphics,
    PrivateSkyLight,
}

impl PerProcessTransport {
    pub fn journal_name(self) -> &'static str {
        match self {
            Self::PublicCoreGraphics => "public_core_graphics",
            Self::PrivateSkyLight => "private_skylight",
        }
    }
}

/// Private keyboard posting wakes background renderers. Public posting is a
/// fallback only when the private entry point is unavailable, never a retry
/// after a post whose delivery is uncertain.
pub fn keyboard_transport(skylight_available: bool) -> PerProcessTransport {
    if skylight_available {
        PerProcessTransport::PrivateSkyLight
    } else {
        PerProcessTransport::PublicCoreGraphics
    }
}

pub fn post_on_selected_route<E, R>(
    route: PerProcessTransport,
    event: E,
    private: impl FnOnce(E) -> R,
    public: impl FnOnce(E) -> R,
) -> R {
    match route {
        PerProcessTransport::PrivateSkyLight => private(event),
        PerProcessTransport::PublicCoreGraphics => public(event),
    }
}

/// Evidence that the selected transport's post call returned.
///
/// This is deliberately not named `Delivered`: CoreGraphics does not report
/// whether the target received the event or acted on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a returned post call is not evidence that the event was delivered"]
pub struct PostCallMade {
    pub transport: PerProcessTransport,
}

impl PostCallMade {
    pub fn public_core_graphics() -> Self {
        Self {
            transport: PerProcessTransport::PublicCoreGraphics,
        }
    }
}

/// Why the selected transport could not complete its post call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostCallFailure {
    pub reason: String,
}

impl PostCallFailure {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// A refusal to call, or a failure reported by, the per-process transport.
///
/// Serialized into dispatch refusals, which are audit material: a failure that
/// stopped a sequence mid-flight is recorded with the same fidelity it is
/// answered with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ProcessEventRefusal {
    Cancelled,
    ProcessGone,
    ProcessReplaced {
        expected_start_time_micros: u64,
        observed_start_time_micros: u64,
    },
    ProcessNotInspectable,
    NotVisibleToWindowServer,
    WindowServerUnreadable {
        reason: String,
    },
    PostCallFailed(PostCallFailure),
}

/// Raw readings and the single effectful call needed by the routing decision.
///
/// `event` is consumed by `post_to_pid`, including on failure. An uncertain
/// failed call therefore cannot return the event for a second transport to post.
pub trait PerProcessEventTransport {
    type Event;

    fn set_recovery(&mut self, _recovery: bool) {}
    fn process_generation(&mut self, pid: u32) -> ProcessGenerationReading;
    fn window_server_visibility(&mut self, pid: u32) -> WindowServerVisibility;
    fn post_to_pid(
        &mut self,
        pid: u32,
        event: Self::Event,
    ) -> Result<PostCallMade, PostCallFailure>;
}

/// Route one event to the exact process generation named by `target`.
///
/// Generation is checked once before the window-server read so a departed
/// process is not mistaken for an invisible one, then checked again immediately
/// before posting to close pid reuse during that read.
pub fn route_event_to_process<T: PerProcessEventTransport>(
    target: ProcessEventTarget,
    event: T::Event,
    transport: &mut T,
) -> Result<(PostCallMade, u64), ProcessEventRefusal> {
    let mut verifications = 0_u64;
    require_exact_generation(target, transport.process_generation(target.pid))?;
    verifications += 1;

    match transport.window_server_visibility(target.pid) {
        WindowServerVisibility::Visible => {}
        WindowServerVisibility::NotVisible => {
            return Err(ProcessEventRefusal::NotVisibleToWindowServer)
        }
        WindowServerVisibility::Unreadable(reason) => {
            return Err(ProcessEventRefusal::WindowServerUnreadable { reason })
        }
    }

    // This is the post-time identity check. Nothing that can block or inspect
    // another subsystem occurs between this reading and the selected post call.
    require_exact_generation(target, transport.process_generation(target.pid))?;
    verifications += 1;

    transport
        .post_to_pid(target.pid, event)
        .map(|made| (made, verifications))
        .map_err(ProcessEventRefusal::PostCallFailed)
}

/// Post a sequence of events to one process generation.
///
/// Every event goes through `route_event_to_process` on its own, so the
/// generation is re-verified immediately before EVERY post. A check at the
/// top of a five-event drag would not cover the fifth event: the process can
/// be replaced while the sequence is in flight, and only a post-time reading
/// separates the granted process from whoever inherited its pid.
///
/// On a mid-sequence failure the sequence does not silently stop. Posted
/// presses whose paired release is still in hand are released best-effort
/// through the same routing (a replaced target refuses the release rather
/// than receiving it), and the outcome is reported as `Released` or
/// `Unknown`. The release paired with a press is never substituted: posting
/// a later release for an earlier press would inject an event the action did
/// not mean. A failed step's own event is consumed by the routing even on a
/// refusal, so when the failed step IS the release, the held state can only
/// be reported as unknown.
pub fn post_event_sequence<T: PerProcessEventTransport>(
    target: ProcessEventTarget,
    steps: Vec<SyntheticStep<T::Event>>,
    transport: &mut T,
    cancelled: &dyn Fn() -> bool,
) -> Result<SequencePostReport, SequencePostFailure> {
    post_guarded_event_sequence(steps, cancelled, |_, event, recovery| {
        transport.set_recovery(recovery);
        match event {
            Some(event) => {
                route_event_to_process(target, event, transport).map(|(_, checks)| checks)
            }
            None => Ok(0),
        }
    })
    .map_err(|failure| SequencePostFailure {
        posts_returned: failure.posts_returned,
        refusal: failure.refusal.unwrap_or(ProcessEventRefusal::Cancelled),
        held_state: failure.held_state,
    })
}

/// An explicit observer for probes and callers with no interrupt source.
pub fn never_cancelled() -> bool {
    false
}

/// A sequence stop retains both the main post count and paired-release recovery.
/// A missing refusal means the caller cancelled, not a transport error or timeout.
pub struct GuardedSequenceFailure<F> {
    pub posts_returned: u64,
    pub refusal: Option<F>,
    pub held_state: HeldStateDisposition,
}

/// Shared by per-process and global sequences. Cancellation precedes the
/// callback's generation check; recovery bypasses cancellation so a held input
/// can be released. A `None` event lets the callback wait between posts before
/// cancellation is checked; `Some` must check generation then post without a
/// blocking preparation step. Recovery must still enforce identity.
pub fn post_guarded_event_sequence<E, F>(
    steps: Vec<SyntheticStep<E>>,
    cancelled: &dyn Fn() -> bool,
    mut post: impl FnMut(usize, Option<E>, bool) -> Result<u64, F>,
) -> Result<SequencePostReport, GuardedSequenceFailure<F>> {
    // Outer Some marks a press; inner None means its release is unavailable.
    // Self-contained steps must not be mistaken for unmatched held presses.
    let mut release_for_press: Vec<Option<Option<usize>>> = vec![None; steps.len()];
    let mut unmatched_presses: Vec<usize> = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        match step.role {
            SyntheticStepRole::Press => {
                release_for_press[index] = Some(None);
                unmatched_presses.push(index);
            }
            SyntheticStepRole::Release => {
                if let Some(press) = unmatched_presses.pop() {
                    release_for_press[press] = Some(Some(index));
                }
            }
            SyntheticStepRole::SelfContained => {}
        }
    }

    let mut steps: Vec<Option<SyntheticStep<E>>> = steps.into_iter().map(Some).collect();
    let mut posts_returned = 0_u64;
    let mut generation_verifications = 0_u64;
    for index in 0..steps.len() {
        let preparation = post(index, None, false);
        if preparation.is_err() || cancelled() {
            let held_state = recover_held_state(&release_for_press, &mut steps, index, &mut post);
            return Err(GuardedSequenceFailure {
                posts_returned,
                refusal: preparation.err(),
                held_state,
            });
        }
        let step = match steps[index].take() {
            Some(step) => step,
            None => continue,
        };
        let routed = post(index, Some(step.event), false);
        if let Ok(verifications) = &routed {
            generation_verifications += verifications;
        }
        if let Err(refusal) = routed {
            let held_state = recover_held_state(&release_for_press, &mut steps, index, &mut post);
            return Err(GuardedSequenceFailure {
                posts_returned,
                refusal: Some(refusal),
                held_state,
            });
        }
        posts_returned += 1;
    }
    Ok(SequencePostReport {
        posts_returned,
        generation_verifications,
    })
}

/// Release whatever the posted steps left held, and say how that went.
///
/// A press posted before the failure is still held when its paired release
/// never posted. Cancellation leaves the current event in hand, including a
/// release at that boundary; a failed routing attempt consumes its event.
fn recover_held_state<E, F>(
    release_for_press: &[Option<Option<usize>>],
    steps: &mut [Option<SyntheticStep<E>>],
    failed_index: usize,
    post: &mut impl FnMut(usize, Option<E>, bool) -> Result<u64, F>,
) -> HeldStateDisposition {
    let mut release_indices: Vec<usize> = Vec::new();
    let mut unrecoverable = false;
    for release in release_for_press.iter().take(failed_index).flatten() {
        let still_held = match release {
            Some(release) => *release >= failed_index,
            None => true,
        };
        if !still_held {
            continue;
        }
        match release {
            Some(release) if steps[*release].is_some() => release_indices.push(*release),
            _ => unrecoverable = true,
        }
    }
    if release_indices.is_empty() && !unrecoverable {
        return HeldStateDisposition::NoneHeld;
    }
    let mut released_posts = 0_u64;
    for index in release_indices {
        let step = match steps[index].take() {
            Some(step) => step,
            None => continue,
        };
        match post(index, Some(step.event), true) {
            Ok(_) => released_posts += 1,
            Err(_) => unrecoverable = true,
        }
    }
    if unrecoverable {
        HeldStateDisposition::Unknown
    } else {
        HeldStateDisposition::Released {
            posts_returned: released_posts,
        }
    }
}

/// Proof that one post-time identity check happened.
///
/// Returned rather than discarded so a caller can COUNT the checks it actually
/// performed. The containment rung claims events reached the process it
/// verified, and it earns that claim from atomic binding -- the check running
/// inside the delivery with no window between. A claim asserted beside the code
/// would survive someone hoisting the check out of the per-post loop; a claim
/// counted from these witnesses cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationVerified;

pub(crate) fn require_exact_generation(
    target: ProcessEventTarget,
    reading: ProcessGenerationReading,
) -> Result<GenerationVerified, ProcessEventRefusal> {
    match reading {
        ProcessGenerationReading::Started(observed) if observed == target.start_time_micros => {
            Ok(GenerationVerified)
        }
        ProcessGenerationReading::Started(observed) => Err(ProcessEventRefusal::ProcessReplaced {
            expected_start_time_micros: target.start_time_micros,
            observed_start_time_micros: observed,
        }),
        ProcessGenerationReading::Gone => Err(ProcessEventRefusal::ProcessGone),
        ProcessGenerationReading::NotInspectable => Err(ProcessEventRefusal::ProcessNotInspectable),
    }
}

/// What one step of a synthetic input sequence does to held input state.
///
/// The role decides what a mid-sequence failure must do: a posted press whose
/// paired release never posted has left a key or button down, and pretending
/// otherwise would return an error that implies nothing happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticStepRole {
    /// Nothing is held after this event's post call returns.
    SelfContained,
    /// This event holds state (a key or mouse button down) until the paired
    /// release posts.
    Press,
    /// This event releases the most recent unmatched press.
    Release,
}

/// One event in a synthetic input sequence, in posting order.
#[derive(Debug)]
pub struct SyntheticStep<E> {
    pub role: SyntheticStepRole,
    pub event: E,
}

/// What a completed sequence can truthfully say.
///
/// `posts_returned` counts post calls that RETURNED. CoreGraphics reports
/// nothing about receipt, so this is evidence of calls made and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequencePostReport {
    pub posts_returned: u64,
    /// How many post-time identity checks this sequence actually performed.
    ///
    /// Counted from witnesses the checks themselves return rather than from the
    /// number of steps, so it measures what ran instead of what was intended.
    /// The containment rung reads this to decide whether its identity evidence
    /// is ATOMICALLY bound to the delivery: two checks per post means every post
    /// was preceded by one, with no window in between. Hoisting a check out of
    /// the per-post loop lowers this count and the atomic claim fails with it.
    pub generation_verifications: u64,
}

/// What a failed sequence did about input state its posted events left held.
///
/// Serialized into dispatch refusals for the same reason
/// [`ProcessEventRefusal`] is: `Unknown` in an audit record is the difference
/// between a target that may still have a key down and one that does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum HeldStateDisposition {
    /// No posted event could have left a key or button held.
    NoneHeld,
    /// Every held press had its paired releasing event posted; those post
    /// calls returned. Their receipt is not claimed any more than the main
    /// sequence's was.
    Released { posts_returned: u64 },
    /// At least one held press could not be released: its releasing event was
    /// lost in the failure that stopped the sequence, or its own routing or
    /// post failed. The target may still have a key or button down.
    Unknown,
}

/// Why a synthetic input sequence stopped, and what followed.
///
/// This is never a bare error: `posts_returned` says how far the sequence got
/// and `held_state` says what was done about what that may have left held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencePostFailure {
    /// Post calls that returned before the sequence stopped.
    pub posts_returned: u64,
    /// The routing refusal or post failure that stopped the sequence.
    pub refusal: ProcessEventRefusal,
    pub held_state: HeldStateDisposition,
}

/// Public CoreGraphics transport readings for production macOS callers.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct MacOsPerProcessEventTransport {
    window_list_timeout: Duration,
    keyboard: Option<super::input_route::KeyboardRoute>,
    recovery: bool,
    pub evidence: super::input_route::InputRouteEvidence,
}

#[cfg(target_os = "macos")]
impl MacOsPerProcessEventTransport {
    pub fn new(window_list_timeout: Duration) -> Self {
        Self {
            window_list_timeout,
            keyboard: None,
            recovery: false,
            evidence: Default::default(),
        }
    }

    pub fn for_keyboard(window_list_timeout: Duration) -> Self {
        Self {
            window_list_timeout,
            keyboard: Some(super::input_route::KeyboardRoute {
                reviewed: super::input_route::private_route_review_bound(),
                symbol_available: cerebellum_macos::skylight_available(),
                factory_available: cerebellum_macos::keyboard_auth_available(),
            }),
            recovery: false,
            evidence: Default::default(),
        }
    }
}

#[cfg(target_os = "macos")]
impl PerProcessEventTransport for MacOsPerProcessEventTransport {
    type Event = cerebellum_macos::OwnedCgEvent;

    fn set_recovery(&mut self, recovery: bool) {
        self.recovery = recovery;
    }

    fn process_generation(&mut self, pid: u32) -> ProcessGenerationReading {
        match cerebellum_macos::process_start_time(pid) {
            cerebellum_macos::ProcessStartTime::Started(micros) => {
                ProcessGenerationReading::Started(micros)
            }
            cerebellum_macos::ProcessStartTime::NoSuchProcess => ProcessGenerationReading::Gone,
            cerebellum_macos::ProcessStartTime::NotPermitted
            | cerebellum_macos::ProcessStartTime::LayoutMismatch
            | cerebellum_macos::ProcessStartTime::Unclassified(_)
            | cerebellum_macos::ProcessStartTime::NoStartTime => {
                ProcessGenerationReading::NotInspectable
            }
        }
    }

    fn window_server_visibility(&mut self, pid: u32) -> WindowServerVisibility {
        match cerebellum_macos::enumerate_windows(self.window_list_timeout) {
            Ok(windows) if windows.iter().any(|window| window.owner_pid == pid) => {
                WindowServerVisibility::Visible
            }
            Ok(_) => WindowServerVisibility::NotVisible,
            Err(reason) => WindowServerVisibility::Unreadable(reason),
        }
    }

    fn post_to_pid(
        &mut self,
        pid: u32,
        event: Self::Event,
    ) -> Result<PostCallMade, PostCallFailure> {
        let pid = i32::try_from(pid)
            .map_err(|_| PostCallFailure::new("process id does not fit macOS pid_t"))?;
        let public = || {
            let _call_made_not_delivery = cerebellum_macos::post_event_to_pid(pid, &event);
            Ok(())
        };
        if let Some(keyboard) = self.keyboard {
            keyboard.post(
                self.recovery,
                &mut self.evidence,
                |attach_auth| match cerebellum_macos::post_single_key_to_pid(
                    pid,
                    &event,
                    attach_auth,
                ) {
                    cerebellum_macos::PostResult::Posted { .. } => Ok(()),
                    cerebellum_macos::PostResult::AuthUnavailable
                    | cerebellum_macos::PostResult::AuthFailed => Err(PostCallFailure::new(
                        super::input_route::PRIVATE_INPUT_AUTH_FAILED,
                    )),
                    error => Err(PostCallFailure::new(format!(
                        "SkyLight post failed: {error:?}"
                    ))),
                },
                public,
            )
        } else {
            public()?;
            self.evidence
                .record(PerProcessTransport::PublicCoreGraphics, self.recovery);
            Ok(PostCallMade::public_core_graphics())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const PID: u32 = 41;
    const START_TIME: u64 = 8_000_123;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FakeEvent(u8);

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        ReadGeneration,
        ReadVisibility,
        Post { pid: u32, event: FakeEvent },
    }

    struct FakeTransport {
        generations: VecDeque<ProcessGenerationReading>,
        visibility: WindowServerVisibility,
        post_results: VecDeque<Result<PostCallMade, PostCallFailure>>,
        calls: Vec<Call>,
        route: PerProcessTransport,
        selected_routes: Vec<PerProcessTransport>,
    }

    impl FakeTransport {
        fn new(
            generations: impl IntoIterator<Item = ProcessGenerationReading>,
            visibility: WindowServerVisibility,
            post_results: impl IntoIterator<Item = Result<PostCallMade, PostCallFailure>>,
        ) -> Self {
            Self {
                generations: generations.into_iter().collect(),
                visibility,
                post_results: post_results.into_iter().collect(),
                calls: Vec::new(),
                route: PerProcessTransport::PublicCoreGraphics,
                selected_routes: Vec::new(),
            }
        }

        fn posting(
            generations: impl IntoIterator<Item = ProcessGenerationReading>,
            visibility: WindowServerVisibility,
        ) -> Self {
            Self::new(
                generations,
                visibility,
                [Ok(PostCallMade::public_core_graphics())],
            )
        }

        fn post_count(&self) -> usize {
            self.calls
                .iter()
                .filter(|call| matches!(call, Call::Post { .. }))
                .count()
        }
    }

    impl PerProcessEventTransport for FakeTransport {
        type Event = FakeEvent;

        fn process_generation(&mut self, _pid: u32) -> ProcessGenerationReading {
            self.calls.push(Call::ReadGeneration);
            self.generations
                .pop_front()
                .expect("the test supplied every expected generation reading")
        }

        fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
            self.calls.push(Call::ReadVisibility);
            self.visibility.clone()
        }

        fn post_to_pid(
            &mut self,
            pid: u32,
            event: Self::Event,
        ) -> Result<PostCallMade, PostCallFailure> {
            let selected = post_on_selected_route(
                self.route,
                (),
                |_| PerProcessTransport::PrivateSkyLight,
                |_| PerProcessTransport::PublicCoreGraphics,
            );
            self.selected_routes.push(selected);
            self.calls.push(Call::Post { pid, event });
            self.post_results
                .pop_front()
                .unwrap_or_else(|| Err(PostCallFailure::new("unexpected second transport")))
        }
    }

    fn target() -> ProcessEventTarget {
        ProcessEventTarget {
            pid: PID,
            start_time_micros: START_TIME,
        }
    }

    fn current() -> ProcessGenerationReading {
        ProcessGenerationReading::Started(START_TIME)
    }

    fn route(transport: &mut FakeTransport) -> Result<PostCallMade, ProcessEventRefusal> {
        route_event_to_process(target(), FakeEvent(7), transport).map(|(made, _)| made)
    }

    #[test]
    fn one_synthesized_event_reaches_exactly_one_transport() {
        let mut transport =
            FakeTransport::posting([current(), current()], WindowServerVisibility::Visible);

        let result = route(&mut transport).expect("the selected post call should be made");

        assert_eq!(result.transport, PerProcessTransport::PublicCoreGraphics);
        assert_eq!(transport.post_count(), 1);
        assert_eq!(
            transport.calls,
            vec![
                Call::ReadGeneration,
                Call::ReadVisibility,
                Call::ReadGeneration,
                Call::Post {
                    pid: PID,
                    event: FakeEvent(7),
                },
            ]
        );
    }

    #[test]
    fn a_failed_post_is_not_retried_through_another_transport() {
        let failure = PostCallFailure::new("framework call failed");
        let mut transport = FakeTransport::new(
            [current(), current()],
            WindowServerVisibility::Visible,
            [Err(failure.clone())],
        );

        assert_eq!(
            route(&mut transport),
            Err(ProcessEventRefusal::PostCallFailed(failure))
        );
        assert_eq!(transport.post_count(), 1);
    }

    #[test]
    fn an_undeliverable_target_is_a_named_refusal_not_silent_success() {
        let mut transport = FakeTransport::posting([current()], WindowServerVisibility::NotVisible);

        assert_eq!(
            route(&mut transport),
            Err(ProcessEventRefusal::NotVisibleToWindowServer)
        );
        assert_eq!(transport.post_count(), 0);
    }

    #[test]
    fn a_recycled_pid_is_refused_by_the_final_generation_read() {
        let mut transport = FakeTransport::posting(
            [current(), ProcessGenerationReading::Started(START_TIME + 1)],
            WindowServerVisibility::Visible,
        );

        assert_eq!(
            route(&mut transport),
            Err(ProcessEventRefusal::ProcessReplaced {
                expected_start_time_micros: START_TIME,
                observed_start_time_micros: START_TIME + 1,
            })
        );
        assert_eq!(transport.post_count(), 0);
        assert_eq!(
            transport.calls,
            vec![
                Call::ReadGeneration,
                Call::ReadVisibility,
                Call::ReadGeneration,
            ]
        );
    }

    #[test]
    fn every_typed_refusal_is_preserved_for_the_caller() {
        let unreadable_window_list = "window list timed out".to_string();
        let post_failure = PostCallFailure::new("framework call failed");
        let cases = [
            (
                FakeTransport::posting(
                    [ProcessGenerationReading::Gone],
                    WindowServerVisibility::Visible,
                ),
                ProcessEventRefusal::ProcessGone,
            ),
            (
                FakeTransport::posting(
                    [ProcessGenerationReading::Started(START_TIME + 1)],
                    WindowServerVisibility::Visible,
                ),
                ProcessEventRefusal::ProcessReplaced {
                    expected_start_time_micros: START_TIME,
                    observed_start_time_micros: START_TIME + 1,
                },
            ),
            (
                FakeTransport::posting(
                    [ProcessGenerationReading::NotInspectable],
                    WindowServerVisibility::Visible,
                ),
                ProcessEventRefusal::ProcessNotInspectable,
            ),
            (
                FakeTransport::posting([current()], WindowServerVisibility::NotVisible),
                ProcessEventRefusal::NotVisibleToWindowServer,
            ),
            (
                FakeTransport::posting(
                    [current()],
                    WindowServerVisibility::Unreadable(unreadable_window_list.clone()),
                ),
                ProcessEventRefusal::WindowServerUnreadable {
                    reason: unreadable_window_list,
                },
            ),
            (
                FakeTransport::new(
                    [current(), current()],
                    WindowServerVisibility::Visible,
                    [Err(post_failure.clone())],
                ),
                ProcessEventRefusal::PostCallFailed(post_failure),
            ),
        ];

        for (mut transport, expected) in cases {
            assert_eq!(route(&mut transport), Err(expected));
        }
    }

    fn step(role: SyntheticStepRole, id: u8) -> SyntheticStep<FakeEvent> {
        SyntheticStep {
            role,
            event: FakeEvent(id),
        }
    }

    /// Press, drag, release — the shape of a drag, which is the sequence whose
    /// mid-flight failure can leave a mouse button held.
    fn drag_steps() -> Vec<SyntheticStep<FakeEvent>> {
        vec![
            step(SyntheticStepRole::Press, 1),
            step(SyntheticStepRole::SelfContained, 2),
            step(SyntheticStepRole::Release, 3),
        ]
    }

    fn posting_transport(
        generations: impl IntoIterator<Item = ProcessGenerationReading>,
        post_results: impl IntoIterator<Item = Result<PostCallMade, PostCallFailure>>,
    ) -> FakeTransport {
        FakeTransport::new(generations, WindowServerVisibility::Visible, post_results)
    }

    fn posted_events(transport: &FakeTransport) -> Vec<FakeEvent> {
        transport
            .calls
            .iter()
            .filter_map(|call| match call {
                Call::Post { event, .. } => Some(*event),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn every_sequence_event_is_posted_only_after_its_own_generation_reads() {
        for selected in [
            PerProcessTransport::PublicCoreGraphics,
            PerProcessTransport::PrivateSkyLight,
        ] {
            let mut transport = posting_transport(
                [
                    current(),
                    current(),
                    current(),
                    current(),
                    current(),
                    current(),
                ],
                [
                    Ok(PostCallMade::public_core_graphics()),
                    Ok(PostCallMade::public_core_graphics()),
                    Ok(PostCallMade::public_core_graphics()),
                ],
            );

            transport.route = selected;
            let report =
                post_event_sequence(target(), drag_steps(), &mut transport, &never_cancelled)
                    .expect("a fully routed sequence completes");
            assert_eq!(transport.selected_routes, vec![selected; 3]);

            assert_eq!(report.posts_returned, 3);
            // The generation is read once before the visibility read and again
            // immediately before EVERY post — the check covering the first event
            // of a drag says nothing about the process at the fifth.
            assert_eq!(
                transport.calls,
                vec![
                    Call::ReadGeneration,
                    Call::ReadVisibility,
                    Call::ReadGeneration,
                    Call::Post {
                        pid: PID,
                        event: FakeEvent(1),
                    },
                    Call::ReadGeneration,
                    Call::ReadVisibility,
                    Call::ReadGeneration,
                    Call::Post {
                        pid: PID,
                        event: FakeEvent(2),
                    },
                    Call::ReadGeneration,
                    Call::ReadVisibility,
                    Call::ReadGeneration,
                    Call::Post {
                        pid: PID,
                        event: FakeEvent(3),
                    },
                ]
            );
        }
    }

    #[test]
    fn private_keyboard_route_is_preferred_and_public_is_only_the_unavailable_fallback() {
        for (available, expected) in [
            (true, PerProcessTransport::PrivateSkyLight),
            (false, PerProcessTransport::PublicCoreGraphics),
        ] {
            let route = keyboard_transport(available);
            let selected = post_on_selected_route(route, 42, |_| "private", |_| "public");
            assert_eq!(route, expected);
            assert_eq!(selected, if available { "private" } else { "public" });
        }
    }

    #[test]
    fn a_generation_change_at_the_late_recheck_stops_the_sequence_before_that_post() {
        let mut transport = posting_transport(
            [
                current(),
                current(),
                current(),
                ProcessGenerationReading::Started(START_TIME + 1),
                // The recovery release is routed to the still-current process.
                current(),
                current(),
            ],
            [
                Ok(PostCallMade::public_core_graphics()),
                Ok(PostCallMade::public_core_graphics()),
            ],
        );

        let failure = post_event_sequence(target(), drag_steps(), &mut transport, &never_cancelled)
            .expect_err("a replaced target stops the sequence");

        assert_eq!(
            failure,
            SequencePostFailure {
                posts_returned: 1,
                refusal: ProcessEventRefusal::ProcessReplaced {
                    expected_start_time_micros: START_TIME,
                    observed_start_time_micros: START_TIME + 1,
                },
                held_state: HeldStateDisposition::Released { posts_returned: 1 },
            }
        );
        // The middle event was never posted, and the press that WAS posted
        // had its paired release posted rather than leaving the button down.
        assert_eq!(posted_events(&transport), vec![FakeEvent(1), FakeEvent(3)]);
    }

    #[test]
    fn a_mid_sequence_failure_releases_what_the_posted_events_left_held() {
        let post_failure = PostCallFailure::new("framework call failed");
        let mut transport = posting_transport(
            [
                current(),
                current(),
                current(),
                current(),
                current(),
                current(),
            ],
            [
                Ok(PostCallMade::public_core_graphics()),
                Err(post_failure.clone()),
                Ok(PostCallMade::public_core_graphics()),
            ],
        );

        let failure = post_event_sequence(target(), drag_steps(), &mut transport, &never_cancelled)
            .expect_err("a failed post stops the sequence");

        assert_eq!(
            failure,
            SequencePostFailure {
                posts_returned: 1,
                refusal: ProcessEventRefusal::PostCallFailed(post_failure),
                held_state: HeldStateDisposition::Released { posts_returned: 1 },
            }
        );
        // Post ATTEMPTS, in order: the press, the move that failed, and then
        // the release — attempted after the failure rather than abandoning
        // the held button.
        assert_eq!(
            posted_events(&transport),
            vec![FakeEvent(1), FakeEvent(2), FakeEvent(3)]
        );
    }

    #[test]
    fn a_failure_before_anything_is_held_posts_no_recovery_events() {
        let post_failure = PostCallFailure::new("framework call failed");
        let mut transport = posting_transport([current(), current()], [Err(post_failure.clone())]);

        let failure = post_event_sequence(target(), drag_steps(), &mut transport, &never_cancelled)
            .expect_err("the failed first post stops the sequence");

        assert_eq!(
            failure,
            SequencePostFailure {
                posts_returned: 0,
                refusal: ProcessEventRefusal::PostCallFailed(post_failure),
                held_state: HeldStateDisposition::NoneHeld,
            }
        );
        assert_eq!(transport.post_count(), 1);
    }

    #[test]
    fn a_failed_release_reports_the_held_state_as_unknown() {
        let post_failure = PostCallFailure::new("framework call failed");
        let mut transport = posting_transport(
            [
                current(),
                current(),
                current(),
                current(),
                current(),
                current(),
            ],
            [
                Ok(PostCallMade::public_core_graphics()),
                Ok(PostCallMade::public_core_graphics()),
                Err(post_failure.clone()),
            ],
        );

        let failure = post_event_sequence(target(), drag_steps(), &mut transport, &never_cancelled)
            .expect_err("the failed release stops the sequence");

        // The press posted and its release may not have landed; nothing may
        // claim the button came back up.
        assert_eq!(
            failure,
            SequencePostFailure {
                posts_returned: 2,
                refusal: ProcessEventRefusal::PostCallFailed(post_failure),
                held_state: HeldStateDisposition::Unknown,
            }
        );
        assert_eq!(transport.post_count(), 3);
    }

    #[test]
    fn a_recovery_release_the_routing_refuses_is_reported_as_unknown() {
        let post_failure = PostCallFailure::new("framework call failed");
        let mut transport = posting_transport(
            [
                current(),
                current(),
                current(),
                current(),
                // The process is gone by the time the release is attempted.
                ProcessGenerationReading::Gone,
            ],
            [
                Ok(PostCallMade::public_core_graphics()),
                Err(post_failure.clone()),
            ],
        );

        let failure = post_event_sequence(target(), drag_steps(), &mut transport, &never_cancelled)
            .expect_err("the failed drag move stops the sequence");

        // The release was attempted but refused before posting — correctly,
        // since the granted process no longer holds the pid — so the button
        // state is unknown rather than released.
        assert_eq!(
            failure,
            SequencePostFailure {
                posts_returned: 1,
                refusal: ProcessEventRefusal::PostCallFailed(post_failure),
                held_state: HeldStateDisposition::Unknown,
            }
        );
        assert_eq!(transport.post_count(), 2);
    }

    /// The recovery release can itself fail to post, and that must be the end
    /// of it: the sequence is already failing, so a recovery path that wedged
    /// would take down the path taken when things are going wrong.
    #[test]
    fn a_failed_post_followed_by_a_failed_recovery_release_reports_unknown_and_returns() {
        let first_failure = PostCallFailure::new("framework call failed");
        let second_failure = PostCallFailure::new("framework call failed again");
        let mut transport = posting_transport(
            [
                current(),
                current(),
                current(),
                current(),
                current(),
                current(),
            ],
            [
                Ok(PostCallMade::public_core_graphics()),
                Err(first_failure.clone()),
                Err(second_failure),
            ],
        );

        let failure = post_event_sequence(target(), drag_steps(), &mut transport, &never_cancelled)
            .expect_err("the failed drag move stops the sequence");

        // The press posted, the move's post failed, and the recovery release's
        // own post failed too. Nothing may claim the button came back up, and
        // the report must still arrive: this is the answer a caller gets when
        // the target may be wedged, so producing it cannot itself wedge.
        assert_eq!(
            failure,
            SequencePostFailure {
                posts_returned: 1,
                refusal: ProcessEventRefusal::PostCallFailed(first_failure),
                held_state: HeldStateDisposition::Unknown,
            }
        );
        assert_eq!(transport.post_count(), 3);
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::cell::Cell;

    struct CountingTransport<'a> {
        returned: &'a Cell<u64>,
        events: Vec<u8>,
        checks: u64,
        observer_calls: Option<&'a Cell<u64>>,
        observers_before_posts: Vec<u64>,
    }
    impl PerProcessEventTransport for CountingTransport<'_> {
        type Event = u8;
        fn process_generation(&mut self, _: u32) -> ProcessGenerationReading {
            self.checks += 1;
            ProcessGenerationReading::Started(123)
        }
        fn window_server_visibility(&mut self, _: u32) -> WindowServerVisibility {
            WindowServerVisibility::Visible
        }
        fn post_to_pid(&mut self, _: u32, event: u8) -> Result<PostCallMade, PostCallFailure> {
            self.events.push(event);
            if let Some(calls) = self.observer_calls {
                self.observers_before_posts.push(calls.get());
            }
            self.returned.set(self.returned.get() + 1);
            Ok(PostCallMade::public_core_graphics())
        }
    }

    #[test]
    fn a_cancelled_sequence_stops_at_the_next_post_boundary() {
        let returned = Cell::new(0);
        let mut transport = CountingTransport {
            returned: &returned,
            events: vec![],
            checks: 0,
            observer_calls: None,
            observers_before_posts: vec![],
        };
        let observer_calls = Cell::new(0);
        transport.observer_calls = Some(&observer_calls);
        let steps = (0..5)
            .map(|event| SyntheticStep {
                event,
                role: SyntheticStepRole::SelfContained,
            })
            .collect();
        let failure = post_event_sequence(
            ProcessEventTarget {
                pid: 10,
                start_time_micros: 123,
            },
            steps,
            &mut transport,
            &|| {
                observer_calls.set(observer_calls.get() + 1);
                returned.get() >= 2
            },
        )
        .unwrap_err();
        assert_eq!(failure.posts_returned, 2);
        assert_eq!(failure.refusal, ProcessEventRefusal::Cancelled);
        assert_eq!(transport.events, [0, 1]);
        assert_eq!(failure.held_state, HeldStateDisposition::NoneHeld);
        assert_eq!(transport.checks, 4);
        assert_eq!(
            transport.observers_before_posts,
            [1, 2],
            "cancellation must be checked BEFORE every post, not after it"
        );
    }

    #[test]
    fn a_cancelled_sequence_releases_what_it_was_holding() {
        let returned = Cell::new(0);
        let mut transport = CountingTransport {
            returned: &returned,
            events: vec![],
            checks: 0,
            observer_calls: None,
            observers_before_posts: vec![],
        };
        let steps = vec![
            SyntheticStep {
                event: 0,
                role: SyntheticStepRole::Press,
            },
            SyntheticStep {
                event: 1,
                role: SyntheticStepRole::Release,
            },
        ];
        let failure = post_event_sequence(
            ProcessEventTarget {
                pid: 10,
                start_time_micros: 123,
            },
            steps,
            &mut transport,
            &|| returned.get() >= 1,
        )
        .unwrap_err();
        assert_eq!(failure.posts_returned, 1);
        assert_eq!(
            failure.held_state,
            HeldStateDisposition::Released { posts_returned: 1 }
        );
        assert_eq!(transport.events, [0, 1]);
    }

    #[test]
    fn cancellation_after_the_last_post_is_completion() {
        let returned = Cell::new(0);
        let mut transport = CountingTransport {
            returned: &returned,
            events: vec![],
            checks: 0,
            observer_calls: None,
            observers_before_posts: vec![],
        };
        let steps = vec![SyntheticStep {
            event: 0,
            role: SyntheticStepRole::SelfContained,
        }];
        let report = post_event_sequence(
            ProcessEventTarget {
                pid: 10,
                start_time_micros: 123,
            },
            steps,
            &mut transport,
            &|| returned.get() >= 1,
        )
        .unwrap();
        assert_eq!(report.posts_returned, 1);
    }
}
