//! Semantic-first computer input dispatch.
//!
//! This module is deliberately an orchestration seam.  Identity and containment
//! evidence remain owned by `platform::containment`; grounding remains owned by
//! `grounding`; and the platform driver remains the only object that can post an
//! event.  The dispatcher chooses one explicitly requested primitive, records
//! one effect status, and never changes a mode to make a failed post succeed.

mod attendance;
mod bracket;
mod effect;
mod gate;
pub mod post_condition;
mod retry;
mod seize;
mod wait;

pub use attendance::*;
pub use bracket::*;
pub use effect::*;
pub use gate::*;
pub use retry::*;
pub use seize::*;
pub use wait::*;

use crate::audit::{
    ActuationAudit, ActuationElementIdentity, ActuationIntent, ActuationOutcome,
    ComputerCapability, ComputerPlaneDescriptor, ObservationState,
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
    DriverError, EffectStatus, ElementResolutionResult, FrontedDispatchRequest,
    GlobalDispatchRequest, HeldStateDisposition, PermissionLiveness, PlatformDriver,
    ProcessEventRefusal, ProcessGrant, SemanticActionIntent, SemanticActionPlatform,
    SemanticDispatchRequest, SemanticDriverError, SyntheticAction, SyntheticDispatchRequest,
    TargetDisposition,
};
use cerebellum_core::consent::OnceDispatchToken;
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
    /// The dispatch row of a current capability; `None` for any other id,
    /// including every retired one, so nothing can build a dispatch for a
    /// capability the vocabulary no longer carries.
    pub fn for_capability(capability_id: &str) -> Option<Self> {
        let capability = ComputerCapability::parse(capability_id)?;
        let action_kind = capability.action_kind();
        // Which delivery each row may use, as its frozen row declares: the
        // press and write rows act through accessibility and post nothing, the
        // keystroke rows post per process or globally, and the pointer rows
        // post only globally because the per-process path does not carry
        // pointer events.
        let (semantic_supported, synthetic_background_supported, synthetic_observed_supported) =
            match capability {
                ComputerCapability::PressElement
                | ComputerCapability::PressPoint
                | ComputerCapability::WriteText => (true, false, false),
                ComputerCapability::Type => (true, true, true),
                ComputerCapability::Keys => (false, true, true),
                ComputerCapability::TakeoverMove
                | ComputerCapability::TakeoverClick
                | ComputerCapability::TakeoverDrag
                | ComputerCapability::TakeoverScroll => (false, false, true),
                ComputerCapability::ReadState
                | ComputerCapability::Wait
                | ComputerCapability::ListApps
                | ComputerCapability::OpenApp => (false, false, false),
                ComputerCapability::Click
                | ComputerCapability::Scroll
                | ComputerCapability::Move
                | ComputerCapability::Drag
                | ComputerCapability::Screenshot => return None,
            };
        let input = action_kind != ActionKind::Observe;
        Some(Self {
            capability_id: capability_id.to_string(),
            action_kind,
            semantic_supported,
            synthetic_background_supported,
            synthetic_observed_supported,
            // No current row falls back to pixels: the element rows name
            // elements by id and the pointer rows name points, never a
            // pixel match standing in for an element.
            pixel_fallback_eligible: false,
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
    #[serde(skip)]
    pub once_dispatch_token: Option<OnceDispatchToken>,
    pub now_ms: u64,
    /// Present when a background delivery must bring the target forward for
    /// the length of each post, because it is not frontmost.
    #[serde(default)]
    pub fronting_bracket: Option<FrontingBracketPlan>,
}

/// How a fronting bracket is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontingBracketPlan {
    /// The longest the target may stay in front at a time.
    pub maximum_interval_ms: u64,
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
            once_dispatch_token: None,
            now_ms,
            fronting_bracket: None,
        }
    }

    /// Deliver in the background through a fronting bracket bounded at
    /// `maximum_interval_ms`.
    pub fn with_fronting_bracket(mut self, maximum_interval_ms: u64) -> Self {
        self.fronting_bracket = Some(FrontingBracketPlan {
            maximum_interval_ms,
        });
        self
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

    pub fn with_once_dispatch_token(mut self, token: OnceDispatchToken) -> Self {
        self.once_dispatch_token = Some(token);
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
    SemanticActionUnsupported {
        intent: SemanticActionIntent,
        platform: SemanticActionPlatform,
    },
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
    SessionNotInspectable {
        session: crate::platform::SessionProvenanceRefusal,
    },
    WindowVisibilityUnknown {
        pid: u32,
    },
    SyntheticUnavailable,
    /// A caller interrupted the action; the count and recovery come from the sequence.
    Cancelled {
        posts_returned: u64,
        held_state: HeldStateDisposition,
    },
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
    SeizeLatencyBoundExceeded,
    /// The machine is in use, or its idleness could not be read. Carries the
    /// refusal so the wire shows the threshold and the observed milliseconds
    /// -- the remedy ("wait for the user to step away") is nothing like the
    /// remedy for an unavailable observer, and the two used to share a word.
    IdleGateRefused(IdleGateRefusal),
    UserSeizedControl {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sourced_input_kind: Option<SourcedInputKind>,
    },
    AttendanceUnavailable,
    /// A fronting bracket could not bring the target forward; nothing was
    /// posted in the chunk that tried.
    FrontingFailed,
    /// A fronting bracket could not fit its posts inside the bound on how
    /// long the target may stay in front.
    FrontingBoundExceeded,
    /// A fronting bracket could not put the previous application back, and
    /// stopped rather than front the target again.
    FrontingRestoreFailed,
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
    /// The call reached its terminal decision (deadline, cancel, closed
    /// route or drain) before this action could start, so nothing was sent.
    DispatchStopped,
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
            DispatchError::SemanticActionUnsupported {
                intent: SemanticActionIntent::Cancel,
                platform: SemanticActionPlatform::Windows,
            },
            DispatchError::SessionNotInspectable {
                session: crate::platform::SessionProvenanceRefusal::OtherSession {
                    session_id: 0,
                    console_session_id: 1,
                },
            },
            DispatchError::WindowVisibilityUnknown { pid: 41 },
            DispatchError::SyntheticUnavailable,
            DispatchError::Cancelled {
                posts_returned: 0,
                held_state: HeldStateDisposition::NoneHeld,
            },
            DispatchError::SyntheticSequenceFailed {
                posts_returned: 1,
                refusal: ProcessEventRefusal::ProcessGone,
                held_state: HeldStateDisposition::Unknown,
            },
            DispatchError::EnvelopeUnrecognized,
            DispatchError::UnsupportedMode,
            DispatchError::ObserverUnavailable,
            DispatchError::SeizeLatencyBoundExceeded,
            DispatchError::UserSeizedControl {
                sourced_input_kind: None,
            },
            DispatchError::AttendanceUnavailable,
            DispatchError::FrontingFailed,
            DispatchError::FrontingBoundExceeded,
            DispatchError::FrontingRestoreFailed,
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
            DispatchError::DispatchStopped,
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
            Self::SemanticActionUnsupported { .. } => "semantic_action_unsupported",
            Self::ElementNameAmbiguous { .. } => "element_name_ambiguous",
            Self::ElementNotFound { .. } => "element_not_found",
            Self::ActionNotAdvertised { .. } => "action_not_advertised",
            Self::ApplicationRefused { .. } => "application_refused",
            Self::AccessibilityPermissionUnavailable => "accessibility_permission_unavailable",
            Self::TargetNoLongerCurrent { .. } => "target_no_longer_current",
            Self::SemanticDispatchTransient { .. } => "semantic_dispatch_transient",
            Self::SemanticPathUnavailable => "semantic_path_unavailable",
            Self::SessionNotInspectable { .. } => "session_not_console",
            Self::WindowVisibilityUnknown { .. } => "window_visibility_unknown",
            Self::SyntheticUnavailable => "synthetic_unavailable",
            Self::SyntheticSequenceFailed { .. } => "synthetic_sequence_failed",
            Self::Cancelled { .. } => "cancelled",
            Self::EnvelopeUnrecognized => "envelope_unrecognized",
            Self::UnsupportedMode => "unsupported_mode",
            Self::ObserverUnavailable => "observer_unavailable",
            Self::SeizeLatencyBoundExceeded => "seize_latency_bound_exceeded",
            Self::IdleGateRefused(IdleGateRefusal::Unreadable(_)) => "idle_unreadable",
            Self::IdleGateRefused(IdleGateRefusal::BelowThreshold { .. }) => "not_idle",
            Self::UserSeizedControl { .. } => "user_seized_control",
            Self::AttendanceUnavailable => "attendance_unavailable",
            Self::FrontingFailed => "fronting_failed",
            Self::FrontingBoundExceeded => "fronting_bound_exceeded",
            Self::FrontingRestoreFailed => "restore_failed",
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
            Self::DispatchStopped => "dispatch_stopped",
        }
    }
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}
impl std::error::Error for DispatchError {}

fn semantic_delivery_selected(request: &DispatchRequest) -> bool {
    request.semantic.as_ref().is_some_and(|semantic| {
        request.row.semantic_supported
            && semantic.element.owning_process == request.target
            && !request.semantic_known_ineffective
    })
}

/// The journal descriptor a dispatch of `request` reserves its entry under.
pub fn actuation_descriptor(
    request: &DispatchRequest,
) -> Result<ComputerPlaneDescriptor, DispatchError> {
    let capability = ComputerCapability::parse(&request.row.capability_id)
        .ok_or(DispatchError::InvalidRequest)?;
    let containment = if semantic_delivery_selected(request) {
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

/// Reserve the journal entry a dispatch of `request` will use, before the
/// blocking worker starts, so the entry exists whatever that worker later
/// does. An observation reserves nothing, as in [`Dispatcher::dispatch`].
pub fn reserve_actuation_ahead<R, T, S>(
    token: &mut crate::audit::AuditToken<R, T, S>,
    identity: JournalIdentity,
    request: &DispatchRequest,
) -> Result<(), DispatchError>
where
    R: cerebellum_core::journal::redaction::Redactor,
    T: cerebellum_core::journal::severity::SeverityTaxonomy,
    S: cerebellum_core::journal::storage::JournalStorage,
{
    if request.row.action_kind == ActionKind::Observe {
        return Ok(());
    }
    token
        .reserve_ahead(identity, actuation_descriptor(request)?)
        .map_err(|_| DispatchError::AuditUnavailable)
}

pub struct Dispatcher<'a, D> {
    cancelled: &'a dyn Fn() -> bool,
    driver: D,
    trace: Vec<DispatchPhase>,
    last_observed_abort: Option<AbortDecision>,
    last_bracket: Option<BracketReport>,
    typing_interval: std::time::Duration,
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

impl<'a, D> Dispatcher<'a, D> {
    pub fn new(driver: D, cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            driver,
            cancelled,
            trace: Vec::new(),
            last_observed_abort: None,
            last_bracket: None,
            typing_interval: std::time::Duration::ZERO,
        }
    }

    /// Set the per-process text cadence without slowing chords or releases.
    pub fn with_typing_interval(mut self, interval: std::time::Duration) -> Self {
        self.typing_interval = interval;
        self
    }

    /// What the last dispatch's fronting bracket did, whatever the dispatch
    /// returned. A caller needs it even from a refusal: a bracket that
    /// stopped may still have left another application in front.
    pub fn last_bracket(&self) -> Option<&BracketReport> {
        self.last_bracket.as_ref()
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

impl<D: PlatformDriver> Dispatcher<'_, D> {
    pub fn dispatch<A: ActuationAudit>(
        &mut self,
        audit: &mut A,
        journal_identity: JournalIdentity,
        request: DispatchRequest,
    ) -> Result<DispatchReport, DispatchError> {
        self.last_observed_abort = None;
        self.last_bracket = None;
        let mut audit_state = if request.row.action_kind == ActionKind::Observe {
            None
        } else {
            let descriptor = Self::actuation_descriptor(&request)?;
            let handle = audit
                .reserve_actuation(journal_identity, descriptor.clone())
                .map_err(|_| DispatchError::AuditUnavailable)?;
            Some(ActuationAuditState::reserved(handle, descriptor))
        };

        let result = self.dispatch_inner(audit, audit_state.as_mut(), request);
        if let Err(ref refusal) = result {
            if let Some(state) = audit_state
                .as_mut()
                .filter(|state| state.needs_no_action_terminal())
            {
                if audit.finalize_no_action(state.handle, refusal).is_err() {
                    state.transition_failed = true;
                    return Err(DispatchError::AuditUnavailable);
                }
                state.finalized = true;
            }
        }
        result
    }

    fn dispatch_inner<A: ActuationAudit>(
        &mut self,
        audit: &mut A,
        audit_state: Option<&mut ActuationAuditState>,
        mut request: DispatchRequest,
    ) -> Result<DispatchReport, DispatchError> {
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
        let once_dispatch_token = request.once_dispatch_token.take();

        let pre_fronting = if input {
            self.driver.fronting_snapshot(&request.target).ok()
        } else {
            None
        };
        if input && !request.row.global_none_authorized {
            return Err(DispatchError::IdentityVerificationUnavailable);
        }

        let (delivery_primitive, platform_result, focus) =
            self.deliver(audit, audit_state, &request, once_dispatch_token)?;

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
            // Judge a temporary front against the bound used to run it.
            // Dispatches without a bracket keep the frozen row's bound.
            let maximum_interval_ms = request
                .fronting_bracket
                .map_or(request.row.maximum_fronting_bracket_interval_ms, |plan| {
                    plan.maximum_interval_ms
                });
            Some(crate::platform::containment::compare_fronting(
                &request.target,
                pre_fronting,
                post_fronting,
                request.now_ms,
                request.row.fronting_observation_window_ms,
                maximum_interval_ms,
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
        semantic_delivery_selected(request)
    }

    fn actuation_descriptor(
        request: &DispatchRequest,
    ) -> Result<ComputerPlaneDescriptor, DispatchError> {
        actuation_descriptor(request)
    }

    fn journal_no_action<A: ActuationAudit>(
        audit: &mut A,
        journal_identity: JournalIdentity,
        request: &DispatchRequest,
        refusal: &DispatchError,
    ) -> Result<(), DispatchError> {
        let descriptor = Self::actuation_descriptor(request)?;
        let handle = audit
            .reserve_actuation(journal_identity, descriptor)
            .map_err(|_| DispatchError::AuditUnavailable)?;
        audit
            .finalize_no_action(handle, refusal)
            .map_err(|_| DispatchError::AuditUnavailable)?;
        Ok(())
    }

    pub fn dispatch_sequence<A: ActuationAudit>(
        &mut self,
        audit: &mut A,
        journal_identity: &JournalIdentity,
        requests: impl IntoIterator<Item = DispatchRequest>,
    ) -> Result<SequenceDispatchReport, DispatchError> {
        let mut completed = Vec::new();
        let mut previous_post_at_ms = None;
        for request in requests {
            if request.mode == DispatchMode::Observed {
                if let Some(previous) = previous_post_at_ms {
                    if request.now_ms.saturating_sub(previous)
                        < request.row.maximum_seize_detection_latency_ms as u64
                    {
                        let abort = AbortDecision {
                            reason: AbortReason::SeizeLatencyBoundExceeded,
                            stopped_action_index: completed.len(),
                            detection_latency_ms: None,
                            platform_delivery_latency_ms: None,
                            sourced_input_kind: None,
                            maximum_detection_latency_ms: request
                                .row
                                .maximum_seize_detection_latency_ms,
                            queued_posts_cancelled: 0,
                        };
                        let refusal = Self::dispatch_error_for_abort(abort);
                        Self::journal_no_action(
                            audit,
                            journal_identity.clone(),
                            &request,
                            &refusal,
                        )?;
                        return Ok(SequenceDispatchReport {
                            completed,
                            abort: Some(abort),
                        });
                    }
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
                    completed.push(report);
                }
                Err(_) if self.last_observed_abort.is_some() => {
                    return Ok(SequenceDispatchReport {
                        completed,
                        abort: self.last_observed_abort,
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(SequenceDispatchReport {
            completed,
            abort: None,
        })
    }

    fn dispatch_error_for_abort(abort: AbortDecision) -> DispatchError {
        match abort.reason {
            AbortReason::ObserverUnavailable => DispatchError::ObserverUnavailable,
            AbortReason::SeizeLatencyBoundExceeded => DispatchError::SeizeLatencyBoundExceeded,
            AbortReason::IdleGateRefused(refusal) => DispatchError::IdleGateRefused(refusal),
            AbortReason::FocusMismatch => DispatchError::TargetFocusMismatch,
            AbortReason::UserSeizedControl => DispatchError::UserSeizedControl {
                sourced_input_kind: abort.sourced_input_kind,
            },
        }
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
        // addressable in its own right, which is how computer.takeover_move
        // and computer.takeover_drag are frozen. Without one of those, a
        // coordinate is an assertion nothing has grounded.
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

    fn deliver<A: ActuationAudit>(
        &mut self,
        audit: &mut A,
        mut audit_state: Option<&mut ActuationAuditState>,
        request: &DispatchRequest,
        once_dispatch_token: Option<OnceDispatchToken>,
    ) -> Result<
        (
            DeliveryPrimitive,
            PlatformDispatchResult,
            Option<FocusEvidence>,
        ),
        DispatchError,
    > {
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
                        self.finalize_audit_outcome(
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
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                                abort: None,
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
        let action = if request.mode == DispatchMode::Background {
            self.driver
                .per_process_transport(&synthetic.action)
                .map_or_else(
                    || action.clone(),
                    |route| format!("{action} via {}", route.journal_name()),
                )
        } else {
            action
        };
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
                let state = audit_state
                    .as_deref_mut()
                    .ok_or(DispatchError::AuditUnavailable)?;
                Self::commit_audit_intent(audit, state, &intent)?;
                if let Some(plan) = request.fronting_bracket {
                    let result = self.deliver_fronted(audit, state, request, synthetic, plan)?;
                    self.trace.push(DispatchPhase::PerPidDispatch);
                    return Ok((DeliveryPrimitive::PerPidSynthetic, result, None));
                }
                let cancelled = self.cancelled;
                let stopped = || cancelled() || audit.mutation_stopped();
                let result = match self.driver.dispatch_per_pid_paced(
                    synthetic,
                    self.typing_interval,
                    &stopped,
                ) {
                    Ok(result) => {
                        self.finalize_audit_outcome(
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
                            DriverError::SyntheticDispatchFailed(failure)
                                if failure.refusal == ProcessEventRefusal::Cancelled =>
                            {
                                DispatchError::Cancelled {
                                    posts_returned: failure.posts_returned,
                                    held_state: failure.held_state,
                                }
                            }
                            DriverError::SyntheticDispatchFailed(failure) => {
                                DispatchError::SyntheticSequenceFailed {
                                    posts_returned: failure.posts_returned,
                                    refusal: failure.refusal,
                                    held_state: failure.held_state,
                                }
                            }
                            _ => DispatchError::SyntheticUnavailable,
                        };
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &match &refusal {
                                DispatchError::Cancelled {
                                    posts_returned,
                                    held_state,
                                } => ActuationOutcome::Cancelled {
                                    posts_returned: *posts_returned,
                                    held_state: *held_state,
                                },
                                _ => ActuationOutcome::Refused {
                                    refusal: refusal.clone(),
                                    abort: None,
                                },
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
                let token = once_dispatch_token.ok_or(DispatchError::AttendanceUnavailable)?;
                if !synthetic
                    .action
                    .takeover_action()
                    .is_some_and(|action| token.admits(action))
                {
                    return Err(DispatchError::AttendanceUnavailable);
                }
                let state = audit_state.ok_or(DispatchError::AuditUnavailable)?;
                Self::commit_audit_intent(audit, state, &intent)?;
                let cancelled = self.cancelled;
                let stopped = || cancelled() || audit.mutation_stopped();
                let result = match self.driver.dispatch_global(
                    GlobalDispatchRequest {
                        synthetic,
                        once_dispatch_token: token,
                        maximum_seize_detection_latency_ms: request
                            .row
                            .maximum_seize_detection_latency_ms,
                        minimum_inter_post_interval_ms: request.row.minimum_inter_post_interval_ms,
                    },
                    &stopped,
                ) {
                    Ok(result) => {
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::HandlerReturned {
                                unreadable_subtrees: result.unreadable_subtrees,
                            },
                        )?;
                        result
                    }
                    Err(DriverError::SyntheticDispatchFailed(failure))
                        if failure.refusal == ProcessEventRefusal::Cancelled =>
                    {
                        let refusal = DispatchError::Cancelled {
                            posts_returned: failure.posts_returned,
                            held_state: failure.held_state,
                        };
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Cancelled {
                                posts_returned: failure.posts_returned,
                                held_state: failure.held_state,
                            },
                        )?;
                        return Err(refusal);
                    }
                    Err(DriverError::ObservedSequenceFailed { abort, failure }) => {
                        let failure = *failure;
                        self.last_observed_abort = Some(abort);
                        let refusal = DispatchError::SyntheticSequenceFailed {
                            posts_returned: failure.posts_returned,
                            refusal: failure.refusal,
                            held_state: failure.held_state,
                        };
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                                abort: Some(abort),
                            },
                        )?;
                        return Err(refusal);
                    }
                    Err(DriverError::SyntheticDispatchFailed(failure)) => {
                        let refusal = DispatchError::SyntheticSequenceFailed {
                            posts_returned: failure.posts_returned,
                            refusal: failure.refusal,
                            held_state: failure.held_state,
                        };
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                                abort: None,
                            },
                        )?;
                        return Err(refusal);
                    }
                    Err(DriverError::ObservedDispatchAborted(abort)) => {
                        self.last_observed_abort = Some(abort);
                        let refusal = Self::dispatch_error_for_abort(abort);
                        // The whole stop decision goes to the journal, and only
                        // to the journal. The caller's refusal keeps the two
                        // fields the action vocabulary declares for it
                        // (`user_seized_control` plus which source seized);
                        // anything else added here would be stripped from the
                        // reply by result-schema enforcement before it left the
                        // module, so the numbers an operator needs afterwards --
                        // how long detection took, which action stopped, how
                        // many queued posts were cancelled -- are readable from
                        // the audit record rather than from the wire.
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                                abort: Some(abort),
                            },
                        )?;
                        return Err(refusal);
                    }
                    Err(_) => {
                        let refusal = DispatchError::SyntheticUnavailable;
                        self.finalize_audit_outcome(
                            audit,
                            state,
                            &ActuationOutcome::Refused {
                                refusal: refusal.clone(),
                                abort: None,
                            },
                        )?;
                        return Err(refusal);
                    }
                };
                self.trace.push(DispatchPhase::GlobalDispatch);
                Ok((DeliveryPrimitive::GlobalSynthetic, result, None))
            }
        }
    }

    /// Deliver through a fronting bracket, and journal how it ended.
    ///
    /// The bracket's report is kept whatever happens, because a bracket that
    /// stopped can still have left another application in front, and the
    /// caller must be able to say so.
    fn deliver_fronted<A: ActuationAudit>(
        &mut self,
        audit: &mut A,
        state: &mut ActuationAuditState,
        request: &DispatchRequest,
        synthetic: SyntheticDispatchRequest,
        plan: FrontingBracketPlan,
    ) -> Result<PlatformDispatchResult, DispatchError> {
        let cancelled = self.cancelled;
        let stopped = || cancelled() || audit.mutation_stopped();
        let fronted = self.driver.dispatch_fronted(
            FrontedDispatchRequest {
                synthetic,
                maximum_interval_ms: plan.maximum_interval_ms,
                maximum_seize_detection_latency_ms: request.row.maximum_seize_detection_latency_ms,
            },
            &stopped,
        );
        let report = match fronted {
            Ok(report) => report,
            Err(_) => {
                let refusal = DispatchError::SyntheticUnavailable;
                self.finalize_audit_outcome(
                    audit,
                    state,
                    &ActuationOutcome::Refused {
                        refusal: refusal.clone(),
                        abort: None,
                    },
                )?;
                return Err(refusal);
            }
        };
        self.last_bracket = Some(report.clone());
        let refusal = match &report.stop {
            None => None,
            Some(BracketStop::Aborted(abort)) => {
                self.last_observed_abort = Some(*abort);
                Some((Self::dispatch_error_for_abort(*abort), Some(*abort)))
            }
            Some(BracketStop::Cancelled) => Some((
                DispatchError::Cancelled {
                    posts_returned: report.posts_returned,
                    held_state: HeldStateDisposition::NoneHeld,
                },
                None,
            )),
            Some(BracketStop::PostFailed(failure)) => Some((
                if failure.refusal == ProcessEventRefusal::Cancelled {
                    DispatchError::Cancelled {
                        posts_returned: report.posts_returned,
                        held_state: failure.held_state,
                    }
                } else {
                    DispatchError::SyntheticSequenceFailed {
                        posts_returned: report.posts_returned,
                        refusal: failure.refusal.clone(),
                        held_state: failure.held_state,
                    }
                },
                None,
            )),
            Some(BracketStop::PreviousUnknown | BracketStop::FrontFailed) => {
                Some((DispatchError::FrontingFailed, None))
            }
            Some(BracketStop::ObserverUnavailable) => {
                Some((DispatchError::ObserverUnavailable, None))
            }
            Some(BracketStop::BoundExceeded) => Some((DispatchError::FrontingBoundExceeded, None)),
            Some(BracketStop::RestoreFailed) => Some((DispatchError::FrontingRestoreFailed, None)),
        };
        match refusal {
            None => {
                let result = PlatformDispatchResult {
                    accepted_by_platform: report.posts_returned > 0,
                    effect_status: EffectStatus::EffectIndeterminate,
                    unreadable_subtrees: 0,
                    delivery_posts_returned: report.posts_returned,
                    delivery_generation_verifications: report.generation_verifications,
                };
                self.finalize_audit_outcome(
                    audit,
                    state,
                    &ActuationOutcome::HandlerReturned {
                        unreadable_subtrees: 0,
                    },
                )?;
                Ok(result)
            }
            Some((refusal, abort)) => {
                self.finalize_audit_outcome(
                    audit,
                    state,
                    &match &refusal {
                        DispatchError::Cancelled {
                            posts_returned,
                            held_state,
                        } => ActuationOutcome::Cancelled {
                            posts_returned: *posts_returned,
                            held_state: *held_state,
                        },
                        _ => ActuationOutcome::Refused {
                            refusal: refusal.clone(),
                            abort,
                        },
                    },
                )?;
                Err(refusal)
            }
        }
    }

    fn commit_audit_intent<A: ActuationAudit>(
        audit: &mut A,
        state: &mut ActuationAuditState,
        intent: &ActuationIntent,
    ) -> Result<(), DispatchError> {
        if state.token.is_some() || state.finalized || state.transition_failed {
            return Err(DispatchError::AuditUnavailable);
        }
        // The computer gate point. The call may have been stopped while this
        // worker was busy; from then on no intent is committed and nothing is
        // sent, and the dispatch closes its reservation as a no-action.
        if !audit.begin_mutation() {
            return Err(DispatchError::DispatchStopped);
        }
        match audit.commit_intent(state.handle, &state.descriptor, intent) {
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

    fn finalize_audit_outcome<A: ActuationAudit>(
        &mut self,
        audit: &mut A,
        state: &mut ActuationAuditState,
        outcome: &ActuationOutcome,
    ) -> Result<(), DispatchError> {
        let token = state.token.ok_or(DispatchError::AuditUnavailable)?;
        let routes = self.driver.take_input_route_evidence();
        match audit.finalize_outcome(token, outcome, &routes) {
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
                SemanticDriverError::ActionUnsupported { intent, platform } => {
                    DispatchError::SemanticActionUnsupported { intent, platform }
                }
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
            DriverError::SessionNotInspectable(session) => {
                DispatchError::SessionNotInspectable { session }
            }
            DriverError::WindowVisibilityUnknown { pid } => {
                DispatchError::WindowVisibilityUnknown { pid }
            }
            DriverError::Unsupported(_)
            | DriverError::InvalidRequest(_)
            | DriverError::StartupRefused(_)
            | DriverError::EventConstructionFailed(_)
            | DriverError::SyntheticDispatchFailed(_)
            | DriverError::ObservedDispatchAborted(_) => DispatchError::SemanticPathUnavailable,
            DriverError::ObservedSequenceFailed { .. } => DispatchError::SemanticPathUnavailable,
        }
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
pub type DispatchController<'a, D> = Dispatcher<'a, D>;
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

#[cfg(test)]
mod idle_refusal_wire_tests {
    use super::*;
    use crate::platform::{IdleUnreadable, PlatformNeutralTestDriver};

    /// The idle gate's two refusals reach the wire under their own codes,
    /// carrying their numbers, and neither is "observer_unavailable".
    ///
    /// The first version of this mapping folded IdleGateRefused into
    /// ObserverUnavailable so an exhaustive match would compile. An operator
    /// reading that would check the observer; the remedy is to wait for the
    /// user to step away. Asserted here at the code, because the only
    /// production path is platform-gated; this test prevents a future match
    /// from compiling after it maps either idle refusal to the observer error.
    #[test]
    fn every_observed_abort_reason_maps_to_its_own_dispatch_error() {
        let abort = |reason| AbortDecision {
            reason,
            stopped_action_index: 0,
            detection_latency_ms: None,
            platform_delivery_latency_ms: None,
            sourced_input_kind: None,
            maximum_detection_latency_ms: 50,
            queued_posts_cancelled: 0,
        };
        let errors = [
            Dispatcher::<PlatformNeutralTestDriver>::dispatch_error_for_abort(abort(
                AbortReason::ObserverUnavailable,
            )),
            Dispatcher::<PlatformNeutralTestDriver>::dispatch_error_for_abort(abort(
                AbortReason::SeizeLatencyBoundExceeded,
            )),
            Dispatcher::<PlatformNeutralTestDriver>::dispatch_error_for_abort(abort(
                AbortReason::IdleGateRefused(IdleGateRefusal::Unreadable(
                    IdleUnreadable::TableUnavailable,
                )),
            )),
            Dispatcher::<PlatformNeutralTestDriver>::dispatch_error_for_abort(abort(
                AbortReason::FocusMismatch,
            )),
            Dispatcher::<PlatformNeutralTestDriver>::dispatch_error_for_abort(abort(
                AbortReason::UserSeizedControl,
            )),
        ];
        let codes: std::collections::BTreeSet<_> =
            errors.iter().map(DispatchError::reason_code).collect();
        assert_eq!(
            codes.len(),
            errors.len(),
            "two observed abort reasons collapsed to one caller remedy: {errors:?}"
        );
    }

    #[test]
    fn idle_refusals_reach_the_wire_under_their_own_codes_with_their_numbers() {
        let below = DispatchError::IdleGateRefused(IdleGateRefusal::BelowThreshold {
            threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
            hid_idle_ms: 320,
            user_idle_ms: 40,
        });
        let unreadable = DispatchError::IdleGateRefused(IdleGateRefusal::Unreadable(
            IdleUnreadable::TableUnavailable,
        ));

        assert_eq!(below.reason_code(), "not_idle");
        assert_eq!(unreadable.reason_code(), "idle_unreadable");
        for refusal in [&below, &unreadable] {
            assert_ne!(
                refusal.reason_code(),
                DispatchError::ObserverUnavailable.reason_code(),
                "an idle refusal was reported as the observer being unavailable: {refusal:?}"
            );
        }

        // The numbers survive serialization: this is what the wire carries.
        let json = serde_json::to_value(&below).expect("serializes");
        let text = json.to_string();
        assert!(text.contains("1000"), "threshold missing from {text}");
        assert!(text.contains("320"), "raw HID idle missing from {text}");
        assert!(text.contains("40"), "user idle missing from {text}");
        assert!(
            text.contains("hid_idle_ms"),
            "raw HID idle missing from {text}"
        );
        assert!(
            text.contains("user_idle_ms"),
            "user idle missing from {text}"
        );
    }
}
