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
mod wait;

pub use attendance::*;
pub use effect::*;
pub use retry::*;
pub use seize::*;
pub use wait::*;

use crate::audit::{
    ActuationElementIdentity, ActuationIntent, ActuationOutcome, ComputerAudit, ComputerCapability,
    ComputerPlaneDescriptor, ObservationState,
};
use crate::grounding::ContainmentRung;
use crate::platform::containment::{
    finalize_containment, ContainmentEvidence, ContainmentFinalization, ContainmentRefusal,
    ContainmentRung as FinalizedContainmentRung, DeliveryPrimitive, FrontingComparisonEvidence,
    IdentityCheckEvidence, IdentityDiscriminationRequirement, IdentityVerificationStatus,
    ProcessExitWatcherHint, ProcessIdentityEvidence, ProcessIdentityPrimitive,
};
use crate::platform::{
    AccessibilityKeyForm, ActionKind, DispatchMode, DispatchResult as PlatformDispatchResult,
    DriverError, ElementResolutionResult, FocusQueryRequest, HeldStateDisposition,
    InputObservationRequest, PermissionLiveness, PlatformDriver, ProcessEventRefusal, ProcessGrant,
    SemanticDispatchRequest, SemanticDriverError, SyntheticAction, SyntheticDispatchRequest,
    TargetDisposition,
};
use cerebellum_core::journal::redaction::Redactor;
use cerebellum_core::journal::severity::SeverityTaxonomy;
use cerebellum_core::journal::storage::JournalStorage;
use cerebellum_core::journal::{DispatchCommitmentToken, JournalIdentity, ReservationHandle};
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

    pub fn with_synthetic(mut self, action: SyntheticAction) -> Self {
        self.row.coordinate_addressed = action.is_coordinate_addressed();
        self.synthetic = Some(SyntheticDispatchRequest {
            target: self.target.clone(),
            action,
        });
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DispatchError {
    InvalidRequest,
    ElementNameAmbiguous {
        key_form: AccessibilityKeyForm,
        match_count: u64,
    },
    ElementNotFound {
        key_form: AccessibilityKeyForm,
    },
    ActionNotAdvertised {
        action: String,
        advertised: Vec<String>,
    },
    ApplicationRefused {
        ax_error: i32,
    },
    AccessibilityPermissionUnavailable,
    TargetNoLongerCurrent {
        disposition: TargetDisposition,
    },
    SemanticDispatchTransient {
        deadline_ms: u64,
    },
    SemanticPathUnavailable,
    SyntheticUnavailable,
    /// A per-process synthetic sequence stopped mid-flight.
    ///
    /// Not folded into `SyntheticUnavailable`: a sequence that stopped after
    /// some of its events posted is a different fact from one that never
    /// started. `posts_returned` says how far it got, and `held_state` says
    /// what was done about input state the posted events left held -- a caller
    /// told only "unavailable" would send its next action not knowing a key
    /// or button may still be down in the target.
    SyntheticSequenceFailed {
        posts_returned: u64,
        refusal: ProcessEventRefusal,
        held_state: HeldStateDisposition,
    },
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
    Platform,
    AuditUnavailable,
}

/// Every dispatch reason code is distinct.
///
/// Two variants sharing a wire string collapse them for the caller, which is
/// the same defect as a catch-all arm reached one layer later: the remedies
/// differ and nothing downstream can tell which applies. It is also invisible
/// to every other kind of test, because both variants individually render a
/// string that reads correct.
///
/// This fires on the ADDITION rather than on the use, which matters because a
/// duplicate can be introduced by a variant nobody constructs yet -- one was,
/// and it survived until a reviewer read the arms side by side.
#[cfg(test)]
mod reason_code_tests {
    use super::*;

    #[test]
    fn no_two_dispatch_errors_share_a_reason_code() {
        // Listed by hand rather than derived, so adding a variant forces a
        // decision here. A macro over the enum would keep this green by
        // construction and prove nothing.
        let all = [
            DispatchError::InvalidRequest,
            DispatchError::SyntheticUnavailable,
            DispatchError::SyntheticSequenceFailed {
                posts_returned: 1,
                refusal: ProcessEventRefusal::ProcessGone,
                held_state: HeldStateDisposition::Unknown,
            },
            DispatchError::EnvelopeUnrecognized,
            DispatchError::UnsupportedMode,
            DispatchError::ObserverUnavailable,
            DispatchError::UserSeizedControl,
            DispatchError::AttendanceUnavailable,
            DispatchError::TargetFocusMismatch,
            DispatchError::GroundingUntrusted,
            DispatchError::StaleElement,
            DispatchError::StaleGrounding,
            DispatchError::GrantIdentityMismatch,
            DispatchError::IdentityVerificationUnavailable,
            DispatchError::EffectObservationUnavailable,
            DispatchError::BackgroundUnsupportedTarget,
            DispatchError::Platform,
            DispatchError::AuditUnavailable,
        ];

        let mut seen: std::collections::BTreeMap<&'static str, usize> = Default::default();
        for error in &all {
            *seen.entry(error.reason_code()).or_insert(0) += 1;
        }
        let shared: Vec<_> = seen
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(code, count)| format!("{code} is used by {count} variants"))
            .collect();
        assert!(
            shared.is_empty(),
            "dispatch reason codes must be distinct, or a caller cannot tell \
             which remedy applies: {shared:?}"
        );
        assert_eq!(
            seen.len(),
            all.len(),
            "every listed variant must contribute a code"
        );
    }
}

impl DispatchError {
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::ElementNameAmbiguous { .. } => "element_name_ambiguous",
            Self::ElementNotFound { .. } => "element_not_found",
            Self::ActionNotAdvertised { .. } => "action_not_advertised",
            Self::ApplicationRefused { .. } => "application_refused",
            Self::AccessibilityPermissionUnavailable => "accessibility_permission_unavailable",
            Self::TargetNoLongerCurrent { .. } => "target_no_longer_current",
            Self::SemanticDispatchTransient { .. } => "semantic_dispatch_transient",
            Self::SemanticPathUnavailable => "semantic_path_unavailable",
            Self::SyntheticUnavailable => "synthetic_unavailable",
            Self::SyntheticSequenceFailed { .. } => "synthetic_sequence_failed",
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
            Self::Platform => "platform_error",
            Self::AuditUnavailable => "audit_unavailable",
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

#[derive(Debug)]
struct ActuationAuditState {
    handle: ReservationHandle,
    descriptor: ComputerPlaneDescriptor,
    token: Option<DispatchCommitmentToken>,
    finalized: bool,
    transition_failed: bool,
}

impl ActuationAuditState {
    fn reserved(handle: ReservationHandle, descriptor: ComputerPlaneDescriptor) -> Self {
        Self {
            handle,
            descriptor,
            token: None,
            finalized: false,
            transition_failed: false,
        }
    }

    fn needs_no_action_terminal(&self) -> bool {
        self.token.is_none() && !self.finalized && !self.transition_failed
    }
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
    pub fn dispatch<R, T, S>(
        &mut self,
        audit: &mut ComputerAudit<R, T, S>,
        journal_identity: JournalIdentity,
        request: DispatchRequest,
    ) -> Result<DispatchReport, DispatchError>
    where
        R: Redactor,
        T: SeverityTaxonomy,
        S: JournalStorage,
    {
        let mut audit_state = if request.row.action_kind == ActionKind::Observe {
            None
        } else {
            let descriptor = Self::actuation_descriptor(&request)?;
            let handle = audit
                .reserve(journal_identity, descriptor.clone())
                .map_err(|_| DispatchError::AuditUnavailable)?;
            Some(ActuationAuditState::reserved(handle, descriptor))
        };

        let result = self.dispatch_inner(audit, audit_state.as_mut(), request);
        if let Err(ref refusal) = result {
            if let Some(state) = audit_state
                .as_mut()
                .filter(|state| state.needs_no_action_terminal())
            {
                if audit
                    .finalize_actuation_no_action(state.handle, refusal)
                    .is_err()
                {
                    state.transition_failed = true;
                    return Err(DispatchError::AuditUnavailable);
                }
                state.finalized = true;
            }
        }
        result
    }

    fn dispatch_inner<R, T, S>(
        &mut self,
        audit: &mut ComputerAudit<R, T, S>,
        audit_state: Option<&mut ActuationAuditState>,
        request: DispatchRequest,
    ) -> Result<DispatchReport, DispatchError>
    where
        R: Redactor,
        T: SeverityTaxonomy,
        S: JournalStorage,
    {
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

        let (delivery_primitive, platform_result, focus) =
            self.deliver(audit, audit_state, &request, &mut watcher)?;
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
            // The grant the action was authorised against, so the condition is
            // checked in the application the action was aimed at.
            &request.target,
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

        let identity = if delivery_primitive == DeliveryPrimitive::PerPidSynthetic {
            Some(Self::per_pid_delivery_identity(
                &request.target,
                &platform_result,
            ))
        } else {
            request.identity
        };
        let containment = Self::finalize_delivery_containment(
            request.row.action_kind,
            delivery_primitive,
            request.row.coordinate_addressed,
            identity,
            fronting.clone(),
            request.row.global_none_authorized,
        )?;
        Self::validate_delivery_containment(delivery_primitive, &containment)?;

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

    fn per_pid_delivery_identity(
        target: &ProcessGrant,
        result: &PlatformDispatchResult,
    ) -> IdentityCheckEvidence {
        let identity_to_delivery_binding = result.identity_to_delivery_binding();
        let primitive = ProcessIdentityPrimitive::pinned_v1()
            .with_identity_to_delivery_binding(identity_to_delivery_binding);
        let evidence =
            ProcessIdentityEvidence::kernel_vouched(target.process_generation_evidence.clone());
        let requirement = IdentityDiscriminationRequirement::GenerationDiscriminating;
        let verification_succeeded = result.delivery_generation_verifications > 0;

        IdentityCheckEvidence {
            status: if verification_succeeded {
                IdentityVerificationStatus::Matched
            } else {
                IdentityVerificationStatus::Unavailable
            },
            grant_tuple_matches: verification_succeeded.then_some(true),
            compatibility: primitive.compatibility(requirement, &evidence),
            primitive_kind: primitive.evidence_kind,
            declared_discrimination: primitive.declared_discrimination,
            identity_discrimination_requirement: requirement,
            check_time_ms: None,
            dispatch_time_ms: None,
            measured_check_to_dispatch_interval_ms: None,
            maximum_identity_check_to_dispatch_interval_ms: None,
            identity_to_delivery_binding,
            process_exit_watcher_hint: ProcessExitWatcherHint::Unavailable,
        }
    }

    fn finalize_delivery_containment(
        action_kind: ActionKind,
        delivery_primitive: DeliveryPrimitive,
        coordinate_addressed: bool,
        identity: Option<IdentityCheckEvidence>,
        fronting: Option<FrontingComparisonEvidence>,
        global_none_authorized: bool,
    ) -> Result<ContainmentFinalization, DispatchError> {
        // Semantic accessibility invokes the resolved element's own action
        // handler, so missing process or fronting evidence cannot turn that
        // delivery into an uncontained global input event.
        if delivery_primitive == DeliveryPrimitive::SemanticAccessibility {
            return Ok(ContainmentFinalization {
                containment_rung: Some(FinalizedContainmentRung::SemanticElement),
                fronting_stable: fronting
                    .as_ref()
                    .is_some_and(FrontingComparisonEvidence::unchanged),
                input_action: true,
                dispatch_permitted: true,
                forfeiture_reason: None,
                identity,
                fronting,
                delivery_primitive,
            });
        }

        finalize_containment(ContainmentEvidence::input(
            action_kind,
            delivery_primitive,
            coordinate_addressed,
            identity,
            fronting,
            global_none_authorized,
        ))
        .map_err(DispatchError::from)
    }

    fn validate_delivery_containment(
        delivery_primitive: DeliveryPrimitive,
        containment: &ContainmentFinalization,
    ) -> Result<(), DispatchError> {
        if containment.delivery_primitive != delivery_primitive {
            return Err(DispatchError::AuditUnavailable);
        }
        if delivery_primitive == DeliveryPrimitive::SemanticAccessibility
            && containment.rung() != Some(FinalizedContainmentRung::SemanticElement)
        {
            return Err(DispatchError::AuditUnavailable);
        }
        Ok(())
    }

    fn semantic_delivery_selected(request: &DispatchRequest) -> bool {
        request.semantic.as_ref().is_some_and(|semantic| {
            request.row.semantic_supported
                && semantic.element.owning_process == request.target
                && !request.semantic_known_ineffective
        })
    }

    fn actuation_descriptor(
        request: &DispatchRequest,
    ) -> Result<ComputerPlaneDescriptor, DispatchError> {
        let capability = ComputerCapability::parse(&request.row.capability_id)
            .ok_or(DispatchError::InvalidRequest)?;
        let containment = if Self::semantic_delivery_selected(request) {
            ContainmentRung::SemanticElement
        } else {
            match request.mode {
                DispatchMode::Background => ContainmentRung::PidStructural,
                DispatchMode::Observed => ContainmentRung::GlobalNone,
            }
        };
        let observation = match request.mode {
            DispatchMode::Observed => ObservationState::HumanObserved,
            DispatchMode::Background => ObservationState::HumanUnobserved,
        };
        Ok(ComputerPlaneDescriptor::new(
            capability,
            containment,
            observation,
        ))
    }

    fn journal_no_action<R, T, S>(
        audit: &mut ComputerAudit<R, T, S>,
        journal_identity: JournalIdentity,
        request: &DispatchRequest,
        refusal: &DispatchError,
    ) -> Result<(), DispatchError>
    where
        R: Redactor,
        T: SeverityTaxonomy,
        S: JournalStorage,
    {
        let descriptor = Self::actuation_descriptor(request)?;
        let handle = audit
            .reserve(journal_identity, descriptor)
            .map_err(|_| DispatchError::AuditUnavailable)?;
        audit
            .finalize_actuation_no_action(handle, refusal)
            .map_err(|_| DispatchError::AuditUnavailable)?;
        Ok(())
    }

    pub fn dispatch_sequence<R, T, S>(
        &mut self,
        audit: &mut ComputerAudit<R, T, S>,
        journal_identity: &JournalIdentity,
        requests: impl IntoIterator<Item = DispatchRequest>,
    ) -> Result<SequenceDispatchReport, DispatchError>
    where
        R: Redactor,
        T: SeverityTaxonomy,
        S: JournalStorage,
    {
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
                if let Some(abort) = guard.abort_decision() {
                    let refusal = match abort.reason {
                        AbortReason::ObserverUnavailable
                        | AbortReason::SeizeLatencyBoundExceeded => {
                            DispatchError::ObserverUnavailable
                        }
                        AbortReason::UserSeizedControl => DispatchError::UserSeizedControl,
                    };
                    Self::journal_no_action(audit, journal_identity.clone(), &request, &refusal)?;
                    return Ok(SequenceDispatchReport {
                        completed,
                        abort: Some(abort),
                    });
                }
            }
            let post_at = request
                .focus_plan
                .as_ref()
                .map(|plan| plan.post_at_ms)
                .unwrap_or(request.now_ms);
            match self.dispatch(audit, journal_identity.clone(), request) {
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
        // A coordinate-addressed action needs a row that authorizes naming a
        // target by coordinate at all. That is either pixel-fallback
        // eligibility -- the row may ground an element by pixels -- or the
        // frozen grounding policy declaring the capability coordinate-
        // addressable in its own right, which is how computer.move and
        // computer.drag are frozen. Without one of those, a coordinate is an
        // assertion nothing has grounded.
        if request.row.coordinate_addressed
            && !request.row.pixel_fallback_eligible
            && crate::grounding::GroundingPolicy::coordinate_addressable_for_capability(
                &request.row.capability_id,
            ) != Some(true)
        {
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

    fn deliver<R, T, S>(
        &mut self,
        audit: &mut ComputerAudit<R, T, S>,
        mut audit_state: Option<&mut ActuationAuditState>,
        request: &DispatchRequest,
        watcher: &mut SeizeWatcher,
    ) -> Result<
        (
            DeliveryPrimitive,
            PlatformDispatchResult,
            Option<FocusEvidence>,
        ),
        DispatchError,
    >
    where
        R: Redactor,
        T: SeverityTaxonomy,
        S: JournalStorage,
    {
        if let Some(semantic) = request.semantic.clone() {
            if Self::semantic_delivery_selected(request) {
                if !semantic
                    .element
                    .semantic_actions
                    .iter()
                    .any(|candidate| candidate == &semantic.action)
                {
                    return Err(DispatchError::ActionNotAdvertised {
                        action: semantic.action,
                        advertised: semantic.element.semantic_actions,
                    });
                }

                let intent = ActuationIntent {
                    element: Some(ActuationElementIdentity {
                        matched_by: semantic.element.element_name.clone(),
                        alternate_name: semantic.element.alternate_name.clone(),
                    }),
                    action: semantic.action.clone(),
                    grant_identity: request.target.clone(),
                };
                let state = audit_state
                    .as_deref_mut()
                    .ok_or(DispatchError::AuditUnavailable)?;
                Self::commit_audit_intent(audit, state, &intent)?;

                match self.driver.dispatch_semantic(semantic.clone()) {
                    Ok(result) => {
                        Self::finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::HandlerReturned {
                                unreadable_subtrees: result.unreadable_subtrees,
                            },
                        )?;
                        self.trace.push(DispatchPhase::SemanticDispatch);
                        return Ok((DeliveryPrimitive::SemanticAccessibility, result, None));
                    }
                    Err(error) => {
                        let refusal = Self::semantic_refusal(error, &semantic);
                        Self::finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                            },
                        )?;
                        return Err(refusal);
                    }
                }
            }
        }

        let synthetic = request
            .synthetic
            .clone()
            .ok_or(DispatchError::SyntheticUnavailable)?;
        if synthetic.target != request.target
            || synthetic.action.planned_event_count() == 0
            || synthetic.action.is_coordinate_addressed() != request.row.coordinate_addressed
        {
            return Err(DispatchError::InvalidRequest);
        }

        let element = request.semantic.as_ref().and_then(|semantic| {
            (semantic.element.owning_process == request.target).then(|| ActuationElementIdentity {
                matched_by: semantic.element.element_name.clone(),
                alternate_name: semantic.element.alternate_name.clone(),
            })
        });
        let action = request.semantic.as_ref().map_or_else(
            || request.row.capability_id.clone(),
            |semantic| semantic.action.clone(),
        );
        let intent = ActuationIntent {
            element,
            action,
            grant_identity: request.target.clone(),
        };

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
                let state = audit_state
                    .as_deref_mut()
                    .ok_or(DispatchError::AuditUnavailable)?;
                Self::commit_audit_intent(audit, state, &intent)?;
                let result = match self.driver.dispatch_per_pid(synthetic) {
                    Ok(result) => {
                        Self::finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::HandlerReturned {
                                unreadable_subtrees: result.unreadable_subtrees,
                            },
                        )?;
                        result
                    }
                    Err(error) => {
                        // A sequence that stopped mid-flight keeps its whole
                        // report: how many post calls returned, why it stopped,
                        // and what became of input state its posted events left
                        // held. Collapsing that into the transport-level
                        // refusal would tell the caller nothing happened when a
                        // key or button may still be down in the target.
                        let refusal = match error {
                            DriverError::SyntheticDispatchFailed(failure) => {
                                DispatchError::SyntheticSequenceFailed {
                                    posts_returned: failure.posts_returned,
                                    refusal: failure.refusal,
                                    held_state: failure.held_state,
                                }
                            }
                            _ => DispatchError::SyntheticUnavailable,
                        };
                        Self::finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                            },
                        )?;
                        return Err(refusal);
                    }
                };
                self.trace.push(DispatchPhase::PerPidDispatch);
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
                let state = audit_state.ok_or(DispatchError::AuditUnavailable)?;
                Self::commit_audit_intent(audit, state, &intent)?;
                let result = match self.driver.dispatch_global(synthetic) {
                    Ok(result) => {
                        Self::finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::HandlerReturned {
                                unreadable_subtrees: result.unreadable_subtrees,
                            },
                        )?;
                        result
                    }
                    Err(_) => {
                        let refusal = DispatchError::SyntheticUnavailable;
                        Self::finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                            },
                        )?;
                        return Err(refusal);
                    }
                };
                self.trace.push(DispatchPhase::GlobalDispatch);
                Ok((DeliveryPrimitive::GlobalSynthetic, result, Some(focus)))
            }
        }
    }

    fn commit_audit_intent<R, T, S>(
        audit: &mut ComputerAudit<R, T, S>,
        state: &mut ActuationAuditState,
        intent: &ActuationIntent,
    ) -> Result<(), DispatchError>
    where
        R: Redactor,
        T: SeverityTaxonomy,
        S: JournalStorage,
    {
        if state.token.is_some() || state.finalized || state.transition_failed {
            return Err(DispatchError::AuditUnavailable);
        }
        match audit.commit_actuation_intent(state.handle, &state.descriptor, intent) {
            Ok(token) => {
                state.token = Some(token);
                Ok(())
            }
            Err(_) => {
                state.transition_failed = true;
                Err(DispatchError::AuditUnavailable)
            }
        }
    }

    fn finalize_audit_outcome<R, T, S>(
        audit: &mut ComputerAudit<R, T, S>,
        state: &mut ActuationAuditState,
        outcome: &ActuationOutcome,
    ) -> Result<(), DispatchError>
    where
        R: Redactor,
        T: SeverityTaxonomy,
        S: JournalStorage,
    {
        let token = state.token.ok_or(DispatchError::AuditUnavailable)?;
        match audit.finalize_actuation_outcome(token, outcome) {
            Ok(_) => {
                state.finalized = true;
                Ok(())
            }
            Err(_) => {
                state.transition_failed = true;
                Err(DispatchError::AuditUnavailable)
            }
        }
    }

    fn semantic_refusal(error: DriverError, semantic: &SemanticDispatchRequest) -> DispatchError {
        match error {
            DriverError::Semantic(failure) => match failure {
                SemanticDriverError::ElementNameAmbiguous {
                    key_form,
                    match_count,
                } => DispatchError::ElementNameAmbiguous {
                    key_form,
                    match_count,
                },
                SemanticDriverError::ElementNotFound { key_form } => {
                    DispatchError::ElementNotFound { key_form }
                }
                SemanticDriverError::ActionNotAdvertised { action, advertised } => {
                    DispatchError::ActionNotAdvertised { action, advertised }
                }
                SemanticDriverError::ApplicationRefused { ax_error } => {
                    DispatchError::ApplicationRefused { ax_error }
                }
                SemanticDriverError::AccessibilityPermissionUnavailable => {
                    DispatchError::AccessibilityPermissionUnavailable
                }
                SemanticDriverError::TargetNoLongerCurrent { disposition } => {
                    DispatchError::TargetNoLongerCurrent { disposition }
                }
                SemanticDriverError::Transient { deadline_ms } => {
                    DispatchError::SemanticDispatchTransient { deadline_ms }
                }
                SemanticDriverError::PathUnavailable => DispatchError::SemanticPathUnavailable,
            },
            DriverError::AccessibilityUnreadable(failure) => match failure {
                crate::platform::AccessibilityReadFailure::PermissionRequired => {
                    DispatchError::AccessibilityPermissionUnavailable
                }
                crate::platform::AccessibilityReadFailure::TargetGone => {
                    DispatchError::TargetNoLongerCurrent {
                        disposition: TargetDisposition::Gone,
                    }
                }
                crate::platform::AccessibilityReadFailure::TargetReplaced => {
                    DispatchError::TargetNoLongerCurrent {
                        disposition: TargetDisposition::Replaced,
                    }
                }
                crate::platform::AccessibilityReadFailure::RetryableDeadlineExceeded => {
                    DispatchError::SemanticDispatchTransient { deadline_ms: 3_000 }
                }
                crate::platform::AccessibilityReadFailure::TargetNotInspectable
                | crate::platform::AccessibilityReadFailure::TreeExceedsBound
                | crate::platform::AccessibilityReadFailure::IncompatiblePlatformValue
                | crate::platform::AccessibilityReadFailure::PlatformReadFailed => {
                    DispatchError::SemanticPathUnavailable
                }
            },
            DriverError::ElementNotFound => DispatchError::ElementNotFound {
                key_form: semantic.element.element_name.key_form(),
            },
            DriverError::Unsupported(_)
            | DriverError::InvalidRequest(_)
            | DriverError::StartupRefused(_)
            | DriverError::EventConstructionFailed(_)
            | DriverError::SyntheticDispatchFailed(_) => DispatchError::SemanticPathUnavailable,
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

#[cfg(test)]
mod delivery_containment_validation_tests {
    use super::*;
    use crate::platform::{
        containment::{ContainmentFinalization, ContainmentRung},
        PlatformNeutralTestDriver,
    };

    fn finalization(
        delivery_primitive: DeliveryPrimitive,
        containment_rung: Option<ContainmentRung>,
    ) -> ContainmentFinalization {
        ContainmentFinalization {
            containment_rung,
            fronting_stable: false,
            input_action: true,
            dispatch_permitted: true,
            forfeiture_reason: None,
            identity: None,
            fronting: None,
            delivery_primitive,
        }
    }

    /// A semantic delivery carrying any other rung is refused, not reported.
    ///
    /// This is a backstop rather than the mechanism: the finalizer awards
    /// SemanticElement to a semantic delivery directly, so nothing that goes
    /// through it can produce a mismatch. That is exactly why the check needs
    /// its own test — its refusing branch is unreachable from any dispatch
    /// fixture, so deleting it left the dispatch-level tests green, and a guard
    /// nobody can observe failing is one nobody can tell is working.
    ///
    /// The state is built directly here for the same reason. Constructing it
    /// through a dispatch would require breaking the mechanism this backstop
    /// exists to survive.
    #[test]
    fn a_semantic_delivery_carrying_a_weaker_rung_is_refused() {
        // The exact shape the live probe reported before this was fixed: a
        // semantic accessibility delivery labelled with the rung meaning an
        // uncontained global input event, which that path cannot produce.
        let mismatched = finalization(
            DeliveryPrimitive::SemanticAccessibility,
            Some(ContainmentRung::GlobalNone),
        );
        assert_eq!(
            Dispatcher::<PlatformNeutralTestDriver>::validate_delivery_containment(
                DeliveryPrimitive::SemanticAccessibility,
                &mismatched,
            ),
            Err(DispatchError::AuditUnavailable),
            "a semantic delivery reporting a non-semantic rung must refuse rather than record it"
        );
    }

    /// A semantic delivery with the earned rung is accepted.
    ///
    /// This test complements the weaker-rung refusal case by ensuring that the
    /// validator does not pass it merely by rejecting every semantic delivery.
    #[test]
    fn a_semantic_delivery_with_the_semantic_rung_is_accepted() {
        let agreeing = finalization(
            DeliveryPrimitive::SemanticAccessibility,
            Some(ContainmentRung::SemanticElement),
        );
        assert_eq!(
            Dispatcher::<PlatformNeutralTestDriver>::validate_delivery_containment(
                DeliveryPrimitive::SemanticAccessibility,
                &agreeing,
            ),
            Ok(())
        );
    }
}
