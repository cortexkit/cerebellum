//! Semantic-first computer input dispatch.
//!
//! This module is deliberately an orchestration seam.  Identity and containment
//! evidence remain owned by `platform::containment`; grounding remains owned by
//! `grounding`; and the platform driver remains the only object that can post an
//! event.  The dispatcher chooses one explicitly requested primitive, records
//! one effect status, and never changes a mode to make a failed post succeed.

mod attendance;
mod effect;
pub mod post_condition;
mod retry;
mod seize;

pub use attendance::*;
pub use effect::*;
pub use retry::*;
pub use seize::*;

use crate::platform::containment::{
    finalize_containment, ContainmentEvidence, ContainmentFinalization, ContainmentRefusal,
    DeliveryPrimitive, FrontingComparisonEvidence, IdentityCheckEvidence,
    IdentityVerificationStatus,
};
use crate::platform::{
    ActionKind, DispatchMode, DispatchResult as PlatformDispatchResult, DriverError,
    ElementResolutionResult, FocusQueryRequest, InputObservationRequest, PermissionLiveness,
    PlatformDriver, ProcessGrant, SemanticDispatchRequest, SyntheticDispatchRequest,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenDispatchRow {
    pub capability_id: String,
    pub action_kind: ActionKind,
    pub semantic_supported: bool,
    pub synthetic_background_supported: bool,
    pub synthetic_observed_supported: bool,
    pub pixel_fallback_eligible: bool,
    pub coordinate_addressed: bool,
    pub global_none_authorized: bool,
    pub private_envelope_recognized: bool,
    pub global_cursor_movement: PermissionLiveness,
    pub effect_observation: EffectObservationPolicy,
    pub maximum_identity_check_to_dispatch_interval_ms: u64,
    pub maximum_fronting_bracket_interval_ms: u64,
    pub fronting_observation_window_ms: u64,
    pub maximum_focus_check_to_post_interval_ms: u64,
    pub maximum_seize_detection_latency_ms: u32,
    pub minimum_inter_post_interval_ms: u32,
    pub maximum_attendance_lease_age_ms: u64,
    pub maximum_attendance_check_to_dispatch_interval_ms: u64,
}

impl FrozenDispatchRow {
    pub fn for_capability(capability_id: &str) -> Option<Self> {
        let action_kind = match capability_id {
            "computer.drag" => ActionKind::MutateDurable,
            "computer.screenshot" | "computer.wait" => ActionKind::Observe,
            "computer.click" | "computer.type" | "computer.keys" | "computer.scroll"
            | "computer.move" => ActionKind::Compose,
            _ => return None,
        };
        let semantic_supported = matches!(
            capability_id,
            "computer.click" | "computer.type" | "computer.scroll"
        );
        let input = action_kind != ActionKind::Observe;
        Some(Self {
            capability_id: capability_id.to_string(),
            action_kind,
            semantic_supported,
            synthetic_background_supported: input && capability_id != "computer.move",
            synthetic_observed_supported: input,
            pixel_fallback_eligible: matches!(capability_id, "computer.click" | "computer.scroll"),
            coordinate_addressed: false,
            global_none_authorized: input,
            private_envelope_recognized: true,
            global_cursor_movement: PermissionLiveness::Live,
            effect_observation: EffectObservationPolicy::default(),
            maximum_identity_check_to_dispatch_interval_ms: 5,
            maximum_fronting_bracket_interval_ms: 100,
            fronting_observation_window_ms: 100,
            maximum_focus_check_to_post_interval_ms: 5,
            maximum_seize_detection_latency_ms: 50,
            minimum_inter_post_interval_ms: 50,
            maximum_attendance_lease_age_ms: 300_000,
            maximum_attendance_check_to_dispatch_interval_ms: 50,
        })
    }

    pub fn with_global_none_authorized(mut self, authorized: bool) -> Self {
        self.global_none_authorized = authorized;
        self
    }

    pub fn with_private_envelope(mut self, recognized: bool) -> Self {
        self.private_envelope_recognized = recognized;
        self
    }

    pub fn with_global_cursor_movement(mut self, state: PermissionLiveness) -> Self {
        self.global_cursor_movement = state;
        self
    }

    pub fn with_inter_post_interval(mut self, interval_ms: u32) -> Self {
        self.minimum_inter_post_interval_ms = interval_ms;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FocusCheckPlan {
    pub checked_at_ms: u64,
    pub post_at_ms: u64,
    pub retry_checked_at_ms: Option<u64>,
    pub retry_post_at_ms: Option<u64>,
}

impl FocusCheckPlan {
    pub fn immediate(at_ms: u64) -> Self {
        Self {
            checked_at_ms: at_ms,
            post_at_ms: at_ms,
            retry_checked_at_ms: None,
            retry_post_at_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchRequest {
    pub row: FrozenDispatchRow,
    pub mode: DispatchMode,
    pub target: ProcessGrant,
    pub semantic: Option<SemanticDispatchRequest>,
    pub synthetic: Option<SyntheticDispatchRequest>,
    pub semantic_known_ineffective: bool,
    pub identity: Option<IdentityCheckEvidence>,
    pub expected_post_condition: ExpectedPostCondition,
    pub attendance: AttendanceContext,
    pub focus_plan: Option<FocusCheckPlan>,
    pub now_ms: u64,
}

impl DispatchRequest {
    pub fn new(
        row: FrozenDispatchRow,
        mode: DispatchMode,
        target: ProcessGrant,
        expected_post_condition: ExpectedPostCondition,
        attendance: AttendanceContext,
        now_ms: u64,
    ) -> Self {
        Self {
            row,
            mode,
            target,
            semantic: None,
            synthetic: None,
            semantic_known_ineffective: false,
            identity: None,
            expected_post_condition,
            attendance,
            focus_plan: None,
            now_ms,
        }
    }

    pub fn with_semantic(
        mut self,
        element: ElementResolutionResult,
        action: impl Into<String>,
    ) -> Self {
        self.semantic = Some(SemanticDispatchRequest {
            element,
            action: action.into(),
        });
        self
    }

    pub fn with_synthetic(mut self, event_count: u8, coordinate_addressed: bool) -> Self {
        self.synthetic = Some(SyntheticDispatchRequest {
            target: self.target.clone(),
            event_count,
            coordinate_addressed,
        });
        self.row.coordinate_addressed = coordinate_addressed;
        self
    }

    pub fn with_identity(mut self, identity: IdentityCheckEvidence) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_focus_plan(mut self, plan: FocusCheckPlan) -> Self {
        self.focus_plan = Some(plan);
        self
    }

    pub fn mark_semantic_ineffective(mut self) -> Self {
        self.semantic_known_ineffective = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchReport {
    pub mode: DispatchMode,
    pub delivery_primitive: DeliveryPrimitive,
    pub containment: ContainmentFinalization,
    pub effect: EffectEvidence,
    pub platform_result: PlatformDispatchResult,
    pub predicate_bytes: Vec<u8>,
    pub attendance: AttendanceDispatchEvidence,
    pub fronting: Option<FrontingComparisonEvidence>,
    pub focus: Option<FocusEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FocusEvidence {
    pub matches_target: bool,
    pub checked_at_ms: u64,
    pub post_at_ms: u64,
    pub measured_check_to_post_interval_ms: Option<u64>,
    pub maximum_check_to_post_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceDispatchReport {
    pub completed: Vec<DispatchReport>,
    pub abort: Option<AbortDecision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPhase {
    PredicateSerialized,
    SemanticDispatch,
    PerPidDispatch,
    GlobalFocusChecked,
    GlobalDispatch,
    EffectObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    InvalidRequest,
    SemanticUnavailable,
    SyntheticUnavailable,
    EnvelopeUnrecognized,
    UnsupportedMode,
    ObserverUnavailable,
    UserSeizedControl,
    AttendanceUnavailable,
    TargetFocusMismatch,
    GroundingUntrusted,
    StaleElement,
    StaleGrounding,
    GrantIdentityMismatch,
    IdentityVerificationUnavailable,
    EffectObservationUnavailable,
    BackgroundUnsupportedTarget,
    ContainmentRefused,
    Platform,
}

impl DispatchError {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::SemanticUnavailable => "semantic_target_unavailable",
            Self::SyntheticUnavailable => "synthetic_unavailable",
            Self::EnvelopeUnrecognized => "envelope_unrecognized",
            Self::UnsupportedMode => "unsupported_mode",
            Self::ObserverUnavailable => "observer_unavailable",
            Self::UserSeizedControl => "user_seized_control",
            Self::AttendanceUnavailable => "attendance_unavailable",
            Self::TargetFocusMismatch => "target_focus_mismatch",
            Self::GroundingUntrusted => "grounding_untrusted",
            Self::StaleElement => "stale_element",
            Self::StaleGrounding => "stale_grounding",
            Self::GrantIdentityMismatch => "grant_identity_mismatch",
            Self::IdentityVerificationUnavailable => "identity_verification_unavailable",
            Self::EffectObservationUnavailable => "observation_primitive_unavailable",
            Self::BackgroundUnsupportedTarget => "background_unsupported_target",
            Self::ContainmentRefused => "identity_verification_unavailable",
            Self::Platform => "platform_error",
        }
    }
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}
impl std::error::Error for DispatchError {}

#[derive(Debug)]
pub struct Dispatcher<D> {
    driver: D,
    trace: Vec<DispatchPhase>,
}

impl<D> Dispatcher<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            trace: Vec::new(),
        }
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    pub fn into_driver(self) -> D {
        self.driver
    }

    pub fn trace(&self) -> &[DispatchPhase] {
        &self.trace
    }

    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }
}

impl<D: PlatformDriver> Dispatcher<D> {
    pub fn dispatch(&mut self, request: DispatchRequest) -> Result<DispatchReport, DispatchError> {
        let predicate_bytes = request
            .expected_post_condition
            .serialize_before_dispatch()
            .map_err(|_| DispatchError::InvalidRequest)?;
        self.trace.push(DispatchPhase::PredicateSerialized);
        let attendance = self.attendance(&request)?;
        self.validate_row_and_target(&request)?;

        let input = request.row.action_kind != ActionKind::Observe;
        if request
            .identity
            .as_ref()
            .is_some_and(|identity| identity.status == IdentityVerificationStatus::Mismatch)
        {
            return Err(DispatchError::GrantIdentityMismatch);
        }
        let mut watcher = SeizeWatcher::new(request.row.maximum_seize_detection_latency_ms);
        if request.mode == DispatchMode::Observed && input {
            self.observe_before_post(&request, &mut watcher, 0)?;
        }

        let pre_fronting = if input {
            self.driver.fronting_snapshot(&request.target).ok()
        } else {
            None
        };
        if input && !request.row.global_none_authorized {
            return Err(DispatchError::IdentityVerificationUnavailable);
        }

        let (delivery_primitive, platform_result, focus) = self.deliver(&request, &mut watcher)?;
        if !watcher.can_post() {
            return Err(
                match watcher.abort_decision().map(|decision| decision.reason) {
                    Some(
                        AbortReason::ObserverUnavailable | AbortReason::SeizeLatencyBoundExceeded,
                    ) => DispatchError::ObserverUnavailable,
                    Some(AbortReason::UserSeizedControl) | None => DispatchError::UserSeizedControl,
                },
            );
        }

        let effect = EffectEvidence::observe_serialized(
            &mut self.driver,
            &request.expected_post_condition,
            predicate_bytes.clone(),
            &request.row.effect_observation,
        )
        .map_err(|_| DispatchError::EffectObservationUnavailable)?;
        self.trace.push(DispatchPhase::EffectObserved);

        let post_fronting = if input {
            self.driver.fronting_snapshot(&request.target).ok()
        } else {
            None
        };
        let fronting = if input {
            Some(crate::platform::containment::compare_fronting(
                &request.target,
                pre_fronting,
                post_fronting,
                request.now_ms,
                request.row.fronting_observation_window_ms,
                request.row.maximum_fronting_bracket_interval_ms,
            ))
        } else {
            None
        };

        let containment = finalize_containment(ContainmentEvidence::input(
            request.row.action_kind,
            delivery_primitive,
            request.row.coordinate_addressed,
            request.identity,
            fronting.clone(),
            request.row.global_none_authorized,
        ))
        .map_err(DispatchError::from)?;

        Ok(DispatchReport {
            mode: request.mode,
            delivery_primitive,
            containment,
            effect,
            platform_result,
            predicate_bytes,
            attendance,
            fronting,
            focus,
        })
    }

    pub fn dispatch_sequence(
        &mut self,
        requests: impl IntoIterator<Item = DispatchRequest>,
    ) -> Result<SequenceDispatchReport, DispatchError> {
        let mut completed = Vec::new();
        let mut watcher: Option<SeizeWatcher> = None;
        let mut previous_post_at_ms = None;
        for (index, request) in requests.into_iter().enumerate() {
            if request.mode == DispatchMode::Observed
                && request.row.action_kind != ActionKind::Observe
            {
                let guard = watcher.get_or_insert_with(|| {
                    SeizeWatcher::new(request.row.maximum_seize_detection_latency_ms)
                });
                guard.observe_liveness(self.driver.input_observer_liveness().into(), index);
                if let Some(previous) = previous_post_at_ms {
                    if request.now_ms.saturating_sub(previous)
                        < request.row.maximum_seize_detection_latency_ms as u64
                    {
                        guard.abort(
                            AbortReason::SeizeLatencyBoundExceeded,
                            index,
                            Some(request.row.maximum_seize_detection_latency_ms),
                        );
                    }
                }
                if let Ok(observation) = self.driver.observe_input(InputObservationRequest {
                    maximum_latency_ms: request.row.maximum_seize_detection_latency_ms,
                }) {
                    guard.observe_input(observation, index);
                }
                if guard.abort_decision().is_some() {
                    return Ok(SequenceDispatchReport {
                        completed,
                        abort: guard.abort_decision(),
                    });
                }
            }
            let post_at = request
                .focus_plan
                .as_ref()
                .map(|plan| plan.post_at_ms)
                .unwrap_or(request.now_ms);
            match self.dispatch(request) {
                Ok(report) => {
                    previous_post_at_ms = Some(post_at);
                    completed.push(report)
                }
                Err(DispatchError::UserSeizedControl | DispatchError::ObserverUnavailable) => {
                    return Ok(SequenceDispatchReport {
                        completed,
                        abort: watcher.as_ref().and_then(SeizeWatcher::abort_decision),
                    })
                }
                Err(error) => return Err(error),
            }
        }
        Ok(SequenceDispatchReport {
            completed,
            abort: watcher.as_ref().and_then(SeizeWatcher::abort_decision),
        })
    }

    fn validate_row_and_target(&self, request: &DispatchRequest) -> Result<(), DispatchError> {
        if request.target.validate().is_err()
            || request.row.capability_id.is_empty()
            || request.row.maximum_identity_check_to_dispatch_interval_ms == 0
            || request.row.effect_observation.deadline_ms == 0
        {
            return Err(DispatchError::InvalidRequest);
        }
        if request.mode == DispatchMode::Observed
            && request.synthetic.is_some()
            && !seize_latency_fits_inter_post_interval(
                request.row.maximum_seize_detection_latency_ms,
                request.row.minimum_inter_post_interval_ms,
            )
        {
            return Err(DispatchError::ObserverUnavailable);
        }
        if request.row.coordinate_addressed && !request.row.pixel_fallback_eligible {
            return Err(DispatchError::GroundingUntrusted);
        }
        if request.mode == DispatchMode::Background && !request.row.synthetic_background_supported {
            return Err(DispatchError::UnsupportedMode);
        }
        if request.mode == DispatchMode::Observed && !request.row.synthetic_observed_supported {
            return Err(DispatchError::UnsupportedMode);
        }
        Ok(())
    }

    fn attendance(
        &mut self,
        request: &DispatchRequest,
    ) -> Result<AttendanceDispatchEvidence, DispatchError> {
        if request.row.action_kind != ActionKind::Observe
            && ((request.mode == DispatchMode::Background
                && request.attendance.requirement != AttendanceRequirement::Background)
                || (request.mode == DispatchMode::Observed
                    && request.attendance.requirement != AttendanceRequirement::Observed))
        {
            return Err(DispatchError::AttendanceUnavailable);
        }
        let mut evidence = request
            .attendance
            .validate_local()
            .map_err(|_| DispatchError::AttendanceUnavailable)?;
        if request.attendance.requirement == AttendanceRequirement::Background {
            let result = self
                .driver
                .verify_attendance(crate::platform::AttendancePreconditionRequest {
                    conversation_id: request.attendance.conversation_id.clone(),
                    target: request.target.clone(),
                    maximum_lease_age_ms: request.row.maximum_attendance_lease_age_ms,
                })
                .map_err(|_| DispatchError::AttendanceUnavailable)?;
            if !result.valid {
                return Err(DispatchError::AttendanceUnavailable);
            }
            let expires_at_ms = evidence.check.expires_at_ms;
            evidence.check = AttendanceCheckEvidence::from_platform(
                result,
                request.attendance.check_time_ms,
                request.row.maximum_attendance_lease_age_ms,
            );
            evidence.check.expires_at_ms = expires_at_ms;
            evidence.maximum_check_to_dispatch_interval_ms =
                request.row.maximum_attendance_check_to_dispatch_interval_ms;
            if !request.attendance.atomic_enforcement && !evidence.within_bound() {
                return Err(DispatchError::AttendanceUnavailable);
            }
        }
        Ok(evidence)
    }

    fn observe_before_post(
        &mut self,
        request: &DispatchRequest,
        watcher: &mut SeizeWatcher,
        index: usize,
    ) -> Result<(), DispatchError> {
        watcher.observe_liveness(self.driver.input_observer_liveness().into(), index);
        if watcher.abort_decision().is_some() {
            return Err(DispatchError::ObserverUnavailable);
        }
        let observation = self
            .driver
            .observe_input(InputObservationRequest {
                maximum_latency_ms: request.row.maximum_seize_detection_latency_ms,
            })
            .map_err(|_| DispatchError::ObserverUnavailable)?;
        watcher.observe_input(observation, index);
        if watcher.abort_decision().is_some() {
            return Err(DispatchError::UserSeizedControl);
        }
        Ok(())
    }

    fn deliver(
        &mut self,
        request: &DispatchRequest,
        watcher: &mut SeizeWatcher,
    ) -> Result<
        (
            DeliveryPrimitive,
            PlatformDispatchResult,
            Option<FocusEvidence>,
        ),
        DispatchError,
    > {
        if let Some(semantic) = request.semantic.clone() {
            let semantic_expresses_action = semantic.element.owning_process == request.target
                && semantic
                    .element
                    .semantic_actions
                    .iter()
                    .any(|candidate| candidate == &semantic.action);
            if request.row.semantic_supported
                && semantic_expresses_action
                && !request.semantic_known_ineffective
            {
                match self.driver.dispatch_semantic(semantic) {
                    Ok(result) => {
                        self.trace.push(DispatchPhase::SemanticDispatch);
                        return Ok((DeliveryPrimitive::SemanticAccessibility, result, None));
                    }
                    Err(DriverError::Unsupported(_)) => {}
                    Err(_) => return Err(DispatchError::SemanticUnavailable),
                }
            }
        }

        let synthetic = request
            .synthetic
            .clone()
            .ok_or(DispatchError::SyntheticUnavailable)?;
        if synthetic.target != request.target
            || synthetic.event_count == 0
            || synthetic.coordinate_addressed != request.row.coordinate_addressed
        {
            return Err(DispatchError::InvalidRequest);
        }
        match request.mode {
            DispatchMode::Background => {
                if !request.row.private_envelope_recognized {
                    return Err(DispatchError::EnvelopeUnrecognized);
                }
                watcher.observe_liveness(
                    SeizeWatcherState {
                        session_tap_live: true,
                        raw_hid_live: true,
                        self_echo_filter_live: true,
                    },
                    0,
                );
                self.trace.push(DispatchPhase::PerPidDispatch);
                let result = self
                    .driver
                    .dispatch_per_pid(synthetic)
                    .map_err(|_| DispatchError::SyntheticUnavailable)?;
                Ok((DeliveryPrimitive::PerPidSynthetic, result, None))
            }
            DispatchMode::Observed => {
                if request.row.global_cursor_movement != PermissionLiveness::Live {
                    return Err(DispatchError::AttendanceUnavailable);
                }
                let focus = self.focus_before_global_post(request)?;
                self.trace.push(DispatchPhase::GlobalFocusChecked);
                watcher.queue_post();
                if !watcher.take_post_slot() {
                    return Err(DispatchError::UserSeizedControl);
                }
                self.trace.push(DispatchPhase::GlobalDispatch);
                let result = self
                    .driver
                    .dispatch_global(synthetic)
                    .map_err(|_| DispatchError::SyntheticUnavailable)?;
                Ok((DeliveryPrimitive::GlobalSynthetic, result, Some(focus)))
            }
        }
    }

    fn focus_before_global_post(
        &mut self,
        request: &DispatchRequest,
    ) -> Result<FocusEvidence, DispatchError> {
        let plan = request
            .focus_plan
            .clone()
            .unwrap_or_else(|| FocusCheckPlan::immediate(request.now_ms));
        let first = self
            .driver
            .query_focus(FocusQueryRequest {
                target: request.target.clone(),
            })
            .map_err(|_| DispatchError::TargetFocusMismatch)?;
        let mut checked_at = plan.checked_at_ms;
        let mut post_at = plan.post_at_ms;
        let mut measured = post_at.checked_sub(checked_at);
        if measured.is_none_or(|value| value > request.row.maximum_focus_check_to_post_interval_ms)
        {
            let (Some(retry_checked), Some(retry_post)) =
                (plan.retry_checked_at_ms, plan.retry_post_at_ms)
            else {
                return Err(DispatchError::TargetFocusMismatch);
            };
            let retry = self
                .driver
                .query_focus(FocusQueryRequest {
                    target: request.target.clone(),
                })
                .map_err(|_| DispatchError::TargetFocusMismatch)?;
            if !retry.matches_target {
                return Err(DispatchError::TargetFocusMismatch);
            }
            checked_at = retry_checked;
            post_at = retry_post;
            measured = post_at.checked_sub(checked_at);
            if measured
                .is_none_or(|value| value > request.row.maximum_focus_check_to_post_interval_ms)
            {
                return Err(DispatchError::TargetFocusMismatch);
            }
            return Ok(FocusEvidence {
                matches_target: true,
                checked_at_ms: checked_at,
                post_at_ms: post_at,
                measured_check_to_post_interval_ms: measured,
                maximum_check_to_post_interval_ms: request
                    .row
                    .maximum_focus_check_to_post_interval_ms,
            });
        }
        if !first.matches_target {
            return Err(DispatchError::TargetFocusMismatch);
        }
        Ok(FocusEvidence {
            matches_target: true,
            checked_at_ms: checked_at,
            post_at_ms: post_at,
            measured_check_to_post_interval_ms: measured,
            maximum_check_to_post_interval_ms: request.row.maximum_focus_check_to_post_interval_ms,
        })
    }
}

impl From<ContainmentRefusal> for DispatchError {
    fn from(value: ContainmentRefusal) -> Self {
        match value.code {
            crate::platform::containment::ContainmentRefusalCode::GrantIdentityMismatch => {
                Self::GrantIdentityMismatch
            }
            crate::platform::containment::ContainmentRefusalCode::IdentityVerificationUnavailable => {
                Self::IdentityVerificationUnavailable
            }
        }
    }
}

// Keep these public aliases so downstream integrations can use the dispatch
// controller and result types without importing the internal modules that define them.
pub type DispatchController<D> = Dispatcher<D>;
pub type DispatchOutcome = DispatchReport;
pub type DispatchSequenceOutcome = SequenceDispatchReport;
pub type ExpectedPredicate = ExpectedPostCondition;
pub type EffectResult = EffectEvidence;
