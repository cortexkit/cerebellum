//! A scripted platform for held-key and temporary-front wire fixtures. It has
//! no native fallback, so an unexpected operation cannot reach the desktop.

use crate::test_support::HANG_GUARD;
use cerebellum_computer::platform::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(crate) struct Sequence {
    pub posted: tokio::sync::Notify,
    pub events: Mutex<Vec<(usize, bool)>>,
}

pub(crate) struct Driver {
    sequence: Arc<Sequence>,
    fronted: Option<Box<super::fronting_tests::FakeDriver>>,
}

impl Driver {
    pub(crate) fn scripted(sequence: Arc<Sequence>) -> Self {
        Self {
            sequence,
            fronted: None,
        }
    }

    pub(crate) fn fronted(driver: Box<super::fronting_tests::FakeDriver>) -> Self {
        Self {
            sequence: Arc::default(),
            fronted: Some(driver),
        }
    }
}

macro_rules! reject {
    ($name:ident ($($arg:ident: $ty:ty),* $(,)?) -> $result:ty) => {
        fn $name(&mut self, $($arg: $ty),*) -> $result {
            $(let _ = $arg;)*
            panic!("unexpected operation in scripted driver: {}", stringify!($name));
        }
    };
}

impl PlatformDriver for Driver {
    fn accept_fronted_dispatch_hooks(&mut self, hooks: Box<dyn FrontedDispatchHooks>) -> bool {
        self.fronted
            .as_mut()
            .is_some_and(|driver| driver.accept_fronted_dispatch_hooks(hooks))
    }

    fn dispatch_fronted(
        &mut self,
        request: FrontedDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<cerebellum_computer::dispatch::BracketReport, DriverError> {
        self.fronted
            .as_mut()
            .expect("a fronted wire fixture")
            .dispatch_fronted(request, cancelled)
    }
    fn capability_declarations(
        &self,
        _: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        Vec::new()
    }
    reject!(
        read_accessibility_tree(
            request: AccessibilityTreeRequest,
        ) -> Result<AccessibilityTreeResult, DriverError>
    );
    reject!(
        resolve_element(
            request: ElementResolutionRequest,
        ) -> Result<ElementResolutionResult, DriverError>
    );
    reject!(
        dispatch_semantic(request: SemanticDispatchRequest) -> Result<DispatchResult, DriverError>
    );
    fn dispatch_per_pid(
        &mut self,
        request: SyntheticDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        let sequence = &self.sequence;
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
                let end = std::time::Instant::now() + HANG_GUARD;
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
    reject!(
        dispatch_global(
            request: GlobalDispatchRequest,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<DispatchResult, DriverError>
    );
    reject!(
        release_held(target: &ProcessGrant, action: &SyntheticAction) -> Result<u64, DriverError>
    );
    fn query_focus(&mut self, _: FocusQueryRequest) -> Result<FocusQueryResult, DriverError> {
        Ok(FocusQueryResult {
            matches_target: true,
        })
    }
    fn fronting_snapshot(&mut self, _: &ProcessGrant) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported(
            "script captures no fronting state",
        ))
    }
    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: true,
            raw_hid_live: true,
            self_echo_filter_live: true,
        }
    }
    fn observe_input(
        &mut self,
        _: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Ok(InputObservationResult {
            human_or_ambiguous_input: false,
            detection_latency_ms: 1,
        })
    }
    fn observe_effect(
        &mut self,
        request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        self.fronted
            .as_mut()
            .expect("a fronted wire fixture")
            .observe_effect(request)
    }
    fn verify_attendance(
        &mut self,
        _: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        Ok(AttendancePreconditionResult {
            valid: true,
            lease_generation: Some("fixture-lease".into()),
            age_ms: Some(1),
        })
    }
    fn session_locked(&self) -> Option<bool> {
        Some(false)
    }
}
