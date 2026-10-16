//! A native-driver forwarding seam only in unit-test builds. It lets frame-loop
//! tests post to a recording sequence instead of the person's desktop.

use cerebellum_computer::platform::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(crate) struct Sequence {
    pub posted: tokio::sync::Notify,
    pub events: Mutex<Vec<(usize, bool)>>,
}

#[derive(Default)]
pub struct Driver {
    native: MacOs26PlatformDriver,
    sequence: Option<Arc<Sequence>>,
}

impl Driver {
    pub(crate) fn scripted(sequence: Arc<Sequence>) -> Self {
        Self {
            native: MacOs26PlatformDriver::default().without_expected_post_condition(),
            sequence: Some(sequence),
        }
    }
    pub fn without_expected_post_condition(mut self) -> Self {
        self.native = self.native.without_expected_post_condition();
        self
    }
    pub fn with_global_dispatch_review_revision(mut self, revision: Option<String>) -> Self {
        self.native = self.native.with_global_dispatch_review_revision(revision);
        self
    }
    pub fn with_takeover_dispatch_review_revision(mut self, revision: Option<String>) -> Self {
        self.native = self.native.with_takeover_dispatch_review_revision(revision);
        self
    }
    pub fn with_shared_user_idle(
        mut self,
        idle: Arc<Mutex<cerebellum_computer::dispatch::UserIdleEstimator>>,
    ) -> Self {
        self.native = self.native.with_shared_user_idle(idle);
        self
    }
}

// Forward every native method, including optional ones, so installing the
// recording seam cannot change the behavior of unrelated unit tests.
macro_rules! forward_mut {
    ($name:ident ($($arg:ident: $ty:ty),* $(,)?) -> $result:ty) => {
        fn $name(&mut self, $($arg: $ty),*) -> $result {
            assert!(self.sequence.is_none(), "unexpected native operation in scripted driver: {}", stringify!($name));
            self.native.$name($($arg),*)
        }
    };
}

impl PlatformDriver for Driver {
    fn capability_declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        self.native.capability_declarations(context)
    }
    forward_mut!(
        read_accessibility_tree(
            request: AccessibilityTreeRequest,
        ) -> Result<AccessibilityTreeResult, DriverError>
    );
    forward_mut!(
        read_accessibility_element(
            request: AccessibilityElementReadRequest,
        ) -> Result<AccessibilityElementReadResult, DriverError>
    );
    forward_mut!(
        resolve_element(
            request: ElementResolutionRequest,
        ) -> Result<ElementResolutionResult, DriverError>
    );
    forward_mut!(
        dispatch_semantic(request: SemanticDispatchRequest) -> Result<DispatchResult, DriverError>
    );
    fn take_input_route_evidence(&mut self) -> input_route::InputRouteEvidence {
        if self.sequence.is_some() {
            return input_route::InputRouteEvidence::default();
        }
        self.native.take_input_route_evidence()
    }
    fn per_process_transport(
        &self,
        action: &SyntheticAction,
    ) -> Option<process_event::PerProcessTransport> {
        self.native.per_process_transport(action)
    }
    fn dispatch_per_pid(
        &mut self,
        request: SyntheticDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        let Some(sequence) = &self.sequence else {
            return self.native.dispatch_per_pid(request, cancelled);
        };
        use process_event::{post_guarded_event_sequence, SyntheticStep, SyntheticStepRole};
        assert!(matches!(
            request.action,
            SyntheticAction::KeyCombination { .. }
        ));
        let steps = [
            SyntheticStepRole::Press,
            SyntheticStepRole::Press,
            SyntheticStepRole::Release,
            SyntheticStepRole::Release,
            SyntheticStepRole::SelfContained,
        ]
        .into_iter()
        .enumerate()
        .map(|(event, role)| SyntheticStep { event, role })
        .collect();
        let failure = post_guarded_event_sequence(steps, cancelled, |index, event, recovery| {
            if let Some(event) = event {
                sequence.events.lock().unwrap().push((event, recovery));
            }
            // Pause between posts, with two keys held. Cancellation must still
            // run the paired recovery releases, but never the remaining step.
            if index == 2 && event.is_none() && !recovery {
                sequence.posted.notify_one();
                let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !cancelled() && std::time::Instant::now() < end {
                    std::thread::yield_now();
                }
            }
            Ok::<_, ProcessEventRefusal>(2)
        })
        .expect_err("Cancel must interrupt the sequence");
        Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: failure.posts_returned,
            refusal: failure.refusal.unwrap_or(ProcessEventRefusal::Cancelled),
            held_state: failure.held_state,
        }))
    }
    forward_mut!(
        dispatch_global(
            request: GlobalDispatchRequest,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<DispatchResult, DriverError>
    );
    forward_mut!(
        release_held(target: &ProcessGrant, action: &SyntheticAction) -> Result<u64, DriverError>
    );
    forward_mut!(
        dispatch_fronted(
            request: FrontedDispatchRequest,
            cancelled: &dyn Fn() -> bool,
        )
            -> Result<cerebellum_computer::dispatch::BracketReport, DriverError>
    );
    forward_mut!(
        read_fronted(
            target: &ProcessGrant,
            maximum_interval_ms: u64,
            cancelled: &dyn Fn() -> bool,
            read: &mut dyn FnMut(),
        ) -> Result<cerebellum_computer::dispatch::BracketReport, DriverError>
    );
    fn query_focus(&mut self, request: FocusQueryRequest) -> Result<FocusQueryResult, DriverError> {
        if self.sequence.is_some() {
            return Ok(FocusQueryResult {
                matches_target: true,
            });
        }
        self.native.query_focus(request)
    }
    fn fronting_snapshot(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        if self.sequence.is_some() {
            return Err(DriverError::Unsupported(
                "script captures no fronting state",
            ));
        }
        self.native.fronting_snapshot(target)
    }
    fn input_observer_liveness(&self) -> InputObserverLiveness {
        if self.sequence.is_some() {
            return InputObserverLiveness {
                session_tap_live: true,
                raw_hid_live: true,
                self_echo_filter_live: true,
            };
        }
        self.native.input_observer_liveness()
    }
    fn observe_input(
        &mut self,
        request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        if self.sequence.is_some() {
            return Ok(InputObservationResult {
                human_or_ambiguous_input: false,
                detection_latency_ms: 1,
            });
        }
        self.native.observe_input(request)
    }
    forward_mut!(
        observe_effect(
            request: EffectObservationRequest,
        ) -> Result<EffectObservationResult, DriverError>
    );
    fn verify_attendance(
        &mut self,
        request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        if self.sequence.is_some() {
            return Ok(AttendancePreconditionResult {
                valid: true,
                lease_generation: Some("fixture-lease".into()),
                age_ms: Some(1),
            });
        }
        self.native.verify_attendance(request)
    }
    fn session_locked(&self) -> Option<bool> {
        if self.sequence.is_some() {
            return Some(false);
        }
        self.native.session_locked()
    }
}
