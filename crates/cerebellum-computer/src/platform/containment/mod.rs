//! Identity-bound containment evidence for computer-plane input.
//!
//! This module intentionally does not post events.  It evaluates the evidence
//! required before a dispatcher is allowed to claim a containment rung.  The
//! dispatcher can therefore use the same result for authorization, auditing,
//! and final result construction without treating an API call as proof.

use super::{ActionKind, FrontingComparison, FrontingSnapshot, FrontingWindow, ProcessGrant};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const PROCESS_IDENTITY_PRIMITIVE_REVISION: &str = "process_identity_primitive-v1";
pub const MAXIMUM_IDENTITY_CHECK_TO_DISPATCH_INTERVAL_MS: u64 = 5;
pub const MAXIMUM_FRONTING_BRACKET_INTERVAL_MS: u64 = 100;

/// The two evidence encodings permitted by the v1 identity contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityEvidenceKind {
    Timestamp,
    KernelVouched,
}

/// Clock provenance is part of timestamp identity evidence.  A timestamp from
/// an application-controlled clock is not a process-generation discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClockSemantics {
    KernelSourced,
    UserSourced,
    Unknown,
}

/// Typed process-generation evidence.  The timestamp and kernel-vouched forms
/// are deliberately separate so one cannot be relabeled as the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessIdentityEvidence {
    Timestamp {
        process_start_time: u64,
        process_start_time_resolution: u64,
        clock_semantics: IdentityClockSemantics,
    },
    KernelVouched {
        kernel_generation_evidence: String,
    },
}

pub type IdentityEvidence = ProcessIdentityEvidence;

impl ProcessIdentityEvidence {
    /// Construct timestamp evidence.  Resolution is expressed in nanoseconds.
    pub fn timestamp(process_start_time: u64, resolution_ns: u64) -> Self {
        Self::Timestamp {
            process_start_time,
            process_start_time_resolution: resolution_ns,
            clock_semantics: IdentityClockSemantics::KernelSourced,
        }
    }

    pub fn timestamp_with_clock(
        process_start_time: u64,
        resolution_ns: u64,
        clock_semantics: IdentityClockSemantics,
    ) -> Self {
        Self::Timestamp {
            process_start_time,
            process_start_time_resolution: resolution_ns,
            clock_semantics,
        }
    }

    pub fn kernel_vouched(value: impl Into<String>) -> Self {
        Self::KernelVouched {
            kernel_generation_evidence: value.into(),
        }
    }

    pub fn kind(&self) -> IdentityEvidenceKind {
        match self {
            Self::Timestamp { .. } => IdentityEvidenceKind::Timestamp,
            Self::KernelVouched { .. } => IdentityEvidenceKind::KernelVouched,
        }
    }

    fn present(&self) -> bool {
        match self {
            Self::Timestamp {
                process_start_time_resolution,
                ..
            } => *process_start_time_resolution != 0,
            Self::KernelVouched {
                kernel_generation_evidence,
            } => !kernel_generation_evidence.is_empty(),
        }
    }
}

/// The requirement attached to every v1 row that can earn a structural rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDiscriminationRequirement {
    GenerationDiscriminating,
}

/// Discrimination declared by the selected primitive.  `PidOnly` and
/// `Unknown` are retained in the closed model because they must fail closed,
/// rather than being silently upgraded to generation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDiscrimination {
    GenerationDiscriminating,
    PidOnly,
    Inadequate,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAtomicBinding {
    Atomic,
    NonAtomic,
}

impl IdentityAtomicBinding {
    pub fn is_atomic(self) -> bool {
        matches!(self, Self::Atomic)
    }
}

/// A process identity observed at grant or dispatch time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentityObservation {
    pub pid: u32,
    pub bundle_identity: String,
    pub evidence: ProcessIdentityEvidence,
}

impl ProcessIdentityObservation {
    pub fn new(
        pid: u32,
        bundle_identity: impl Into<String>,
        evidence: ProcessIdentityEvidence,
    ) -> Self {
        Self {
            pid,
            bundle_identity: bundle_identity.into(),
            evidence,
        }
    }

    pub fn from_grant(grant: &ProcessGrant, evidence: ProcessIdentityEvidence) -> Self {
        Self::new(grant.pid, grant.bundle_identity.clone(), evidence)
    }

    fn valid(&self) -> bool {
        self.pid != 0 && !self.bundle_identity.is_empty() && self.evidence.present()
    }
}

/// The grant-time identity capture.  The legacy string in `ProcessGrant` is
/// retained for wire compatibility, but this typed evidence is what the pinned
/// primitive compares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantIdentityBinding {
    pub grant: ProcessGrant,
    pub evidence: ProcessIdentityEvidence,
    pub captured_at_ms: u64,
}

pub type GrantBinding = GrantIdentityBinding;

impl GrantIdentityBinding {
    pub fn new(
        grant: ProcessGrant,
        evidence: ProcessIdentityEvidence,
        captured_at_ms: u64,
    ) -> Result<Self, IdentityPrimitiveError> {
        grant
            .validate()
            .map_err(|_| IdentityPrimitiveError::InvalidGrant)?;
        if !evidence.present() {
            return Err(IdentityPrimitiveError::MissingEvidence);
        }
        Ok(Self {
            grant,
            evidence,
            captured_at_ms,
        })
    }
}

/// The manifest-bound process identity primitive.  There is no implicit
/// primitive: callers must construct the pinned declaration or receive an
/// incompatibility result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentityPrimitive {
    pub revision: String,
    pub evidence_kind: IdentityEvidenceKind,
    pub declared_discrimination: IdentityDiscrimination,
    /// Timestamp resolution in nanoseconds, when the primitive uses timestamps.
    pub timestamp_resolution: Option<u64>,
    pub clock_semantics: Option<IdentityClockSemantics>,
    pub arbitrary_target_applicable: bool,
    pub target_controlled: bool,
    pub per_dispatch_cost_us: u64,
    pub identity_to_delivery_binding: IdentityAtomicBinding,
}

impl ProcessIdentityPrimitive {
    pub fn pinned_v1() -> Self {
        Self {
            revision: PROCESS_IDENTITY_PRIMITIVE_REVISION.to_string(),
            evidence_kind: IdentityEvidenceKind::KernelVouched,
            declared_discrimination: IdentityDiscrimination::GenerationDiscriminating,
            timestamp_resolution: None,
            clock_semantics: None,
            arbitrary_target_applicable: true,
            target_controlled: false,
            per_dispatch_cost_us: 1,
            identity_to_delivery_binding: IdentityAtomicBinding::NonAtomic,
        }
    }

    pub fn timestamp_v1(resolution_ns: u64, atomic: IdentityAtomicBinding) -> Self {
        Self {
            revision: PROCESS_IDENTITY_PRIMITIVE_REVISION.to_string(),
            evidence_kind: IdentityEvidenceKind::Timestamp,
            declared_discrimination: IdentityDiscrimination::GenerationDiscriminating,
            timestamp_resolution: Some(resolution_ns),
            clock_semantics: Some(IdentityClockSemantics::KernelSourced),
            arbitrary_target_applicable: true,
            target_controlled: false,
            per_dispatch_cost_us: 1,
            identity_to_delivery_binding: atomic,
        }
    }

    pub fn with_revision(mut self, revision: impl Into<String>) -> Self {
        self.revision = revision.into();
        self
    }

    pub fn with_discrimination(mut self, discrimination: IdentityDiscrimination) -> Self {
        self.declared_discrimination = discrimination;
        self
    }

    pub fn with_arbitrary_target_applicability(mut self, applicable: bool) -> Self {
        self.arbitrary_target_applicable = applicable;
        self
    }

    pub fn with_target_controlled(mut self, target_controlled: bool) -> Self {
        self.target_controlled = target_controlled;
        self
    }

    pub fn with_identity_to_delivery_binding(mut self, binding: IdentityAtomicBinding) -> Self {
        self.identity_to_delivery_binding = binding;
        self
    }

    pub fn compatibility(
        &self,
        requirement: IdentityDiscriminationRequirement,
        evidence: &ProcessIdentityEvidence,
    ) -> IdentityCompatibilityEvidence {
        let mut reason = None;
        if self.revision != PROCESS_IDENTITY_PRIMITIVE_REVISION {
            reason = Some(IdentityCompatibilityReason::RevisionMismatch);
        } else if self.evidence_kind != evidence.kind() {
            reason = Some(IdentityCompatibilityReason::EvidenceKindMismatch);
        } else if !self.arbitrary_target_applicable {
            reason = Some(IdentityCompatibilityReason::NotApplicableToArbitraryTarget);
        } else if self.target_controlled {
            reason = Some(IdentityCompatibilityReason::TargetControlledEvidence);
        } else if !matches!(
            (requirement, self.declared_discrimination),
            (
                IdentityDiscriminationRequirement::GenerationDiscriminating,
                IdentityDiscrimination::GenerationDiscriminating
            )
        ) {
            reason = Some(IdentityCompatibilityReason::InadequateDiscrimination);
        } else if !evidence.present() {
            reason = Some(IdentityCompatibilityReason::EvidenceUnavailable);
        } else if let ProcessIdentityEvidence::Timestamp {
            process_start_time_resolution,
            clock_semantics,
            ..
        } = evidence
        {
            let declared_resolution = self.timestamp_resolution.unwrap_or(u64::MAX);
            if *clock_semantics != IdentityClockSemantics::KernelSourced
                || self.clock_semantics != Some(IdentityClockSemantics::KernelSourced)
            {
                reason = Some(IdentityCompatibilityReason::TimestampClockNotKernelSourced);
            } else if *process_start_time_resolution > 1_000
                || declared_resolution > 1_000
                || *process_start_time_resolution > declared_resolution
            {
                // A microsecond-or-finer kernel clock is the v1 minimum.  The
                // comparison is against nanoseconds to avoid unit ambiguity.
                reason = Some(IdentityCompatibilityReason::TimestampResolutionTooCoarse);
            }
        }

        IdentityCompatibilityEvidence {
            compatible: reason.is_none(),
            reason,
            primitive_revision: self.revision.clone(),
            evidence_kind: self.evidence_kind,
            requirement,
            declared_discrimination: self.declared_discrimination,
            arbitrary_target_applicable: self.arbitrary_target_applicable,
            target_controlled: self.target_controlled,
            per_dispatch_cost_us: self.per_dispatch_cost_us,
        }
    }

    pub fn capture_grant(
        &self,
        grant: ProcessGrant,
        evidence: ProcessIdentityEvidence,
        captured_at_ms: u64,
    ) -> Result<GrantIdentityBinding, IdentityPrimitiveError> {
        grant
            .validate()
            .map_err(|_| IdentityPrimitiveError::InvalidGrant)?;
        let compatibility = self.compatibility(
            IdentityDiscriminationRequirement::GenerationDiscriminating,
            &evidence,
        );
        if !compatibility.compatible {
            return Err(IdentityPrimitiveError::IncompatibleGrant(compatibility));
        }
        GrantIdentityBinding::new(grant, evidence, captured_at_ms)
    }

    pub fn verify(
        &self,
        grant: &GrantIdentityBinding,
        observed: &ProcessIdentityObservation,
        checked_at_ms: u64,
        requirement: IdentityDiscriminationRequirement,
    ) -> IdentityCheckEvidence {
        self.verify_for_dispatch(grant, observed, checked_at_ms, None, None, requirement)
    }

    pub fn verify_for_dispatch(
        &self,
        grant: &GrantIdentityBinding,
        observed: &ProcessIdentityObservation,
        checked_at_ms: u64,
        dispatch_at_ms: Option<u64>,
        maximum_interval_ms: Option<u64>,
        requirement: IdentityDiscriminationRequirement,
    ) -> IdentityCheckEvidence {
        let grant_compatibility = self.compatibility(requirement, &grant.evidence);
        let observed_compatibility = self.compatibility(requirement, &observed.evidence);
        let compatibility = if !grant_compatibility.compatible {
            grant_compatibility
        } else if !observed_compatibility.compatible {
            observed_compatibility
        } else {
            grant_compatibility
        };

        let tuple_matches = observed.valid().then(|| {
            grant.grant.pid == observed.pid
                && grant.grant.bundle_identity == observed.bundle_identity
                && grant.evidence == observed.evidence
        });
        let mut status = if !compatibility.compatible {
            IdentityVerificationStatus::Inadequate
        } else if !observed.valid() {
            IdentityVerificationStatus::Unavailable
        } else if tuple_matches == Some(true) {
            IdentityVerificationStatus::Matched
        } else {
            // Once the primitive has supplied compatible, authoritative
            // evidence, a tuple difference is a definitive replacement.
            IdentityVerificationStatus::Mismatch
        };

        let interval = dispatch_at_ms.and_then(|dispatch| dispatch.checked_sub(checked_at_ms));
        if status != IdentityVerificationStatus::Mismatch {
            if let Some(dispatch) = dispatch_at_ms {
                if dispatch < checked_at_ms {
                    status = IdentityVerificationStatus::Indeterminate;
                } else if let Some(maximum) = maximum_interval_ms {
                    if interval.is_none() || interval > Some(maximum) {
                        status = IdentityVerificationStatus::Stale;
                    }
                }
            }
        }

        IdentityCheckEvidence {
            status,
            grant_tuple_matches: tuple_matches,
            compatibility,
            primitive_kind: self.evidence_kind,
            declared_discrimination: self.declared_discrimination,
            identity_discrimination_requirement: requirement,
            check_time_ms: Some(checked_at_ms),
            dispatch_time_ms: dispatch_at_ms,
            measured_check_to_dispatch_interval_ms: interval,
            maximum_identity_check_to_dispatch_interval_ms: maximum_interval_ms,
            identity_to_delivery_binding: self.identity_to_delivery_binding,
            process_exit_watcher_hint: ProcessExitWatcherHint::Unavailable,
        }
    }

    /// Add the dispatch seam's timing fact without changing the identity
    /// comparison.  Non-atomic delivery remains explicitly disclosed.
    pub fn bind_identity_to_delivery(
        &self,
        grant: &GrantIdentityBinding,
        check: IdentityCheckEvidence,
        delivery_observation: Option<&ProcessIdentityObservation>,
        dispatch_at_ms: u64,
        maximum_interval_ms: u64,
    ) -> IdentityDeliveryEvidence {
        let identity_check =
            self.record_dispatch_timing(check, dispatch_at_ms, maximum_interval_ms);
        let same_at_delivery = delivery_observation.map(|observed| {
            observed.valid()
                && observed.pid == grant.grant.pid
                && observed.bundle_identity == grant.grant.bundle_identity
                && observed.evidence == grant.evidence
        });
        let outcome = if identity_check.status != IdentityVerificationStatus::Matched {
            IdentityDeliveryOutcome::NotAuthorized
        } else if self.identity_to_delivery_binding.is_atomic() {
            if same_at_delivery == Some(false) {
                IdentityDeliveryOutcome::ReplacementBlocked
            } else {
                IdentityDeliveryOutcome::BoundToGrant
            }
        } else if same_at_delivery == Some(false) {
            IdentityDeliveryOutcome::NonAtomicReplacementObserved
        } else {
            IdentityDeliveryOutcome::NonAtomicRaceUnproven
        };
        IdentityDeliveryEvidence {
            outcome,
            dispatch_time_ms: identity_check.dispatch_time_ms,
            measured_check_to_dispatch_interval_ms: identity_check
                .measured_check_to_dispatch_interval_ms,
            atomic_binding: self.identity_to_delivery_binding,
            identity_check,
        }
    }

    pub fn record_dispatch_timing(
        &self,
        mut evidence: IdentityCheckEvidence,
        dispatch_at_ms: u64,
        maximum_interval_ms: u64,
    ) -> IdentityCheckEvidence {
        evidence.dispatch_time_ms = Some(dispatch_at_ms);
        evidence.maximum_identity_check_to_dispatch_interval_ms = Some(maximum_interval_ms);
        evidence.measured_check_to_dispatch_interval_ms = evidence
            .check_time_ms
            .and_then(|checked| dispatch_at_ms.checked_sub(checked));
        if evidence.status == IdentityVerificationStatus::Matched
            && evidence
                .measured_check_to_dispatch_interval_ms
                .is_none_or(|interval| interval > maximum_interval_ms)
        {
            evidence.status = IdentityVerificationStatus::Stale;
        }
        evidence
    }
}

impl Default for ProcessIdentityPrimitive {
    fn default() -> Self {
        Self::pinned_v1()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCompatibilityReason {
    RevisionMismatch,
    EvidenceKindMismatch,
    NotApplicableToArbitraryTarget,
    TargetControlledEvidence,
    InadequateDiscrimination,
    EvidenceUnavailable,
    TimestampClockNotKernelSourced,
    TimestampResolutionTooCoarse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCompatibilityEvidence {
    pub compatible: bool,
    pub reason: Option<IdentityCompatibilityReason>,
    pub primitive_revision: String,
    pub evidence_kind: IdentityEvidenceKind,
    pub requirement: IdentityDiscriminationRequirement,
    pub declared_discrimination: IdentityDiscrimination,
    pub arbitrary_target_applicable: bool,
    pub target_controlled: bool,
    pub per_dispatch_cost_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityVerificationStatus {
    Matched,
    Mismatch,
    Unavailable,
    Stale,
    Indeterminate,
    Inadequate,
}

impl IdentityVerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Mismatch => "mismatch",
            Self::Unavailable => "unavailable",
            Self::Stale => "stale",
            Self::Indeterminate => "indeterminate",
            Self::Inadequate => "inadequate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessExitWatcherHint {
    Alive,
    Exited,
    Unavailable,
}

/// Result of binding the identity check to the actual delivery seam.  This is
/// separate from the comparison because a non-atomic primitive can only
/// disclose, not eliminate, a replacement race after the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDeliveryOutcome {
    BoundToGrant,
    ReplacementBlocked,
    NonAtomicRaceUnproven,
    NonAtomicReplacementObserved,
    NotAuthorized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityDeliveryEvidence {
    pub outcome: IdentityDeliveryOutcome,
    pub identity_check: IdentityCheckEvidence,
    pub dispatch_time_ms: Option<u64>,
    pub measured_check_to_dispatch_interval_ms: Option<u64>,
    pub atomic_binding: IdentityAtomicBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCheckEvidence {
    pub status: IdentityVerificationStatus,
    pub grant_tuple_matches: Option<bool>,
    pub compatibility: IdentityCompatibilityEvidence,
    pub primitive_kind: IdentityEvidenceKind,
    pub declared_discrimination: IdentityDiscrimination,
    pub identity_discrimination_requirement: IdentityDiscriminationRequirement,
    pub check_time_ms: Option<u64>,
    pub dispatch_time_ms: Option<u64>,
    pub measured_check_to_dispatch_interval_ms: Option<u64>,
    pub maximum_identity_check_to_dispatch_interval_ms: Option<u64>,
    pub identity_to_delivery_binding: IdentityAtomicBinding,
    pub process_exit_watcher_hint: ProcessExitWatcherHint,
}

impl IdentityCheckEvidence {
    pub fn matched(primitive: &ProcessIdentityPrimitive, checked_at_ms: u64) -> Self {
        let evidence = match primitive.evidence_kind {
            IdentityEvidenceKind::Timestamp => ProcessIdentityEvidence::timestamp(1, 1_000),
            IdentityEvidenceKind::KernelVouched => {
                ProcessIdentityEvidence::kernel_vouched("test-evidence")
            }
        };
        let compatibility = primitive.compatibility(
            IdentityDiscriminationRequirement::GenerationDiscriminating,
            &evidence,
        );
        Self {
            status: IdentityVerificationStatus::Matched,
            grant_tuple_matches: Some(true),
            compatibility,
            primitive_kind: primitive.evidence_kind,
            declared_discrimination: primitive.declared_discrimination,
            identity_discrimination_requirement:
                IdentityDiscriminationRequirement::GenerationDiscriminating,
            check_time_ms: Some(checked_at_ms),
            dispatch_time_ms: None,
            measured_check_to_dispatch_interval_ms: None,
            maximum_identity_check_to_dispatch_interval_ms: None,
            identity_to_delivery_binding: primitive.identity_to_delivery_binding,
            process_exit_watcher_hint: ProcessExitWatcherHint::Unavailable,
        }
    }

    pub fn with_process_exit_watcher_hint(mut self, hint: ProcessExitWatcherHint) -> Self {
        self.process_exit_watcher_hint = hint;
        self
    }

    pub fn unavailable(primitive: &ProcessIdentityPrimitive, checked_at_ms: Option<u64>) -> Self {
        let evidence = if primitive.evidence_kind == IdentityEvidenceKind::Timestamp {
            ProcessIdentityEvidence::timestamp(1, 1_000)
        } else {
            ProcessIdentityEvidence::kernel_vouched("unavailable")
        };
        Self {
            status: IdentityVerificationStatus::Unavailable,
            grant_tuple_matches: None,
            compatibility: primitive.compatibility(
                IdentityDiscriminationRequirement::GenerationDiscriminating,
                &evidence,
            ),
            primitive_kind: primitive.evidence_kind,
            declared_discrimination: primitive.declared_discrimination,
            identity_discrimination_requirement:
                IdentityDiscriminationRequirement::GenerationDiscriminating,
            check_time_ms: checked_at_ms,
            dispatch_time_ms: None,
            measured_check_to_dispatch_interval_ms: None,
            maximum_identity_check_to_dispatch_interval_ms: None,
            identity_to_delivery_binding: primitive.identity_to_delivery_binding,
            process_exit_watcher_hint: ProcessExitWatcherHint::Unavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityPrimitiveError {
    InvalidGrant,
    MissingEvidence,
    IncompatibleGrant(IdentityCompatibilityEvidence),
}

impl fmt::Display for IdentityPrimitiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrant => write!(f, "invalid process grant"),
            Self::MissingEvidence => write!(f, "process identity evidence is unavailable"),
            Self::IncompatibleGrant(_) => write!(f, "grant identity primitive is incompatible"),
        }
    }
}
impl std::error::Error for IdentityPrimitiveError {}

/// Closed reason vocabulary for the three fronting comparison states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontingReason {
    FrontmostApplicationChanged,
    TargetBecameFrontmost,
    TargetWindowRaised,
    TargetWindowCreated,
    TargetWindowDestroyed,
    ComparisonUnavailable,
}

impl FrontingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrontmostApplicationChanged => "frontmost_application_changed",
            Self::TargetBecameFrontmost => "target_became_frontmost",
            Self::TargetWindowRaised => "target_window_raised",
            Self::TargetWindowCreated => "target_window_created",
            Self::TargetWindowDestroyed => "target_window_destroyed",
            Self::ComparisonUnavailable => "comparison_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontingComparisonEvidence {
    pub pre_snapshot: Option<FrontingSnapshot>,
    pub post_snapshot: Option<FrontingSnapshot>,
    pub comparison: FrontingComparison,
    pub reasons: Vec<FrontingReason>,
    pub declared_observation_window_ms: u64,
    pub measured_bracket_interval_ms: Option<u64>,
    pub maximum_fronting_bracket_interval_ms: u64,
    pub bracketed_observation: bool,
}

impl FrontingComparisonEvidence {
    pub fn unchanged(&self) -> bool {
        self.comparison == FrontingComparison::Unchanged
            && self.reasons.is_empty()
            && self
                .measured_bracket_interval_ms
                .is_some_and(|interval| interval <= self.maximum_fronting_bracket_interval_ms)
    }

    pub fn reason(&self) -> Option<FrontingReason> {
        self.reasons.first().copied()
    }
}

/// Compare the two required bracket snapshots.  All timing failures are
/// represented as `indeterminate`; callers must never turn missing evidence
/// into an unchanged comparison.
pub fn compare_fronting(
    target: &ProcessGrant,
    pre_snapshot: Option<FrontingSnapshot>,
    post_snapshot: Option<FrontingSnapshot>,
    dispatch_committed_at_ms: u64,
    observation_window_ms: u64,
    maximum_bracket_interval_ms: u64,
) -> FrontingComparisonEvidence {
    let measured_bracket_interval_ms = pre_snapshot
        .as_ref()
        .zip(post_snapshot.as_ref())
        .and_then(|(pre, post)| post.captured_at_ms.checked_sub(pre.captured_at_ms));
    let mut result = FrontingComparisonEvidence {
        pre_snapshot,
        post_snapshot,
        comparison: FrontingComparison::Indeterminate,
        reasons: vec![FrontingReason::ComparisonUnavailable],
        declared_observation_window_ms: observation_window_ms,
        measured_bracket_interval_ms,
        maximum_fronting_bracket_interval_ms: maximum_bracket_interval_ms,
        bracketed_observation: true,
    };

    let Some(pre) = result.pre_snapshot.as_ref() else {
        result.reasons = vec![FrontingReason::ComparisonUnavailable];
        return result;
    };
    let Some(post) = result.post_snapshot.as_ref() else {
        result.reasons = vec![FrontingReason::ComparisonUnavailable];
        return result;
    };

    let expected_post_time = dispatch_committed_at_ms.checked_add(observation_window_ms);
    if pre.captured_at_ms > dispatch_committed_at_ms {
        result.reasons = vec![FrontingReason::ComparisonUnavailable];
        return result;
    }
    if expected_post_time.is_none_or(|expected| post.captured_at_ms < expected) {
        result.reasons = vec![FrontingReason::ComparisonUnavailable];
        return result;
    }
    if expected_post_time.is_none_or(|expected| post.captured_at_ms > expected) {
        result.reasons = vec![FrontingReason::ComparisonUnavailable];
        return result;
    }
    if measured_bracket_interval_ms.is_none_or(|interval| interval > maximum_bracket_interval_ms) {
        result.reasons = vec![FrontingReason::ComparisonUnavailable];
        return result;
    }

    if !pre.completeness || !post.completeness {
        result.reasons = vec![FrontingReason::ComparisonUnavailable];
        return result;
    }
    let Some(reason) = validate_snapshot_pair(target, pre, post) else {
        result.comparison = FrontingComparison::Unchanged;
        result.reasons.clear();
        return result;
    };

    if matches!(
        reason,
        FrontingReason::FrontmostApplicationChanged
            | FrontingReason::TargetBecameFrontmost
            | FrontingReason::TargetWindowRaised
            | FrontingReason::TargetWindowCreated
            | FrontingReason::TargetWindowDestroyed
    ) {
        result.comparison = FrontingComparison::DowngradeDetected;
    } else {
        result.comparison = FrontingComparison::Indeterminate;
    }
    result.reasons = vec![reason];
    result
}

fn validate_snapshot_pair(
    target: &ProcessGrant,
    pre: &FrontingSnapshot,
    post: &FrontingSnapshot,
) -> Option<FrontingReason> {
    if pre.frontmost_application_identity.is_none()
        || post.frontmost_application_identity.is_none()
        || has_missing_window_fields(&pre.target_windows)
        || has_missing_window_fields(&post.target_windows)
    {
        return Some(FrontingReason::ComparisonUnavailable);
    }
    if has_duplicate_window_ids(&pre.target_windows)
        || has_duplicate_window_ids(&post.target_windows)
    {
        return Some(FrontingReason::ComparisonUnavailable);
    }
    if pre
        .target_windows
        .iter()
        .chain(post.target_windows.iter())
        .any(|window| window.owning_process_generation != target.process_generation_evidence)
    {
        return Some(FrontingReason::ComparisonUnavailable);
    }

    let pre_frontmost = pre
        .frontmost_application_identity
        .as_deref()
        .unwrap_or_default();
    let post_frontmost = post
        .frontmost_application_identity
        .as_deref()
        .unwrap_or_default();
    if pre_frontmost != post_frontmost {
        if post_frontmost == target.bundle_identity && pre_frontmost != target.bundle_identity {
            return Some(FrontingReason::TargetBecameFrontmost);
        }
        return Some(FrontingReason::FrontmostApplicationChanged);
    }

    let pre_windows: BTreeMap<_, _> = pre
        .target_windows
        .iter()
        .map(|window| (window.observation_window_id.as_str(), window))
        .collect();
    let post_windows: BTreeMap<_, _> = post
        .target_windows
        .iter()
        .map(|window| (window.observation_window_id.as_str(), window))
        .collect();

    if pre_windows.keys().any(|id| !post_windows.contains_key(id)) {
        return Some(FrontingReason::TargetWindowDestroyed);
    }
    if post_windows.keys().any(|id| !pre_windows.contains_key(id)) {
        return Some(FrontingReason::TargetWindowCreated);
    }

    for (id, before) in &pre_windows {
        let Some(after) = post_windows.get(id) else {
            return Some(FrontingReason::ComparisonUnavailable);
        };
        if before.owning_process_generation != after.owning_process_generation {
            return Some(FrontingReason::ComparisonUnavailable);
        }
        if before.activation_state != after.activation_state {
            return Some(FrontingReason::TargetWindowRaised);
        }
        // The frozen schema uses a normalized relative z-order.  Any change
        // means the target window was reordered and is therefore not a
        // structural, background-only observation anymore.
        if before.z_order != after.z_order {
            return Some(FrontingReason::TargetWindowRaised);
        }
    }
    None
}

fn has_missing_window_fields(windows: &[FrontingWindow]) -> bool {
    windows.iter().any(|window| {
        window.observation_window_id.is_empty()
            || window.owning_process_generation.is_empty()
            || window.activation_state.is_empty()
    })
}

fn has_duplicate_window_ids(windows: &[FrontingWindow]) -> bool {
    let mut ids = BTreeSet::new();
    windows
        .iter()
        .any(|window| !ids.insert(window.observation_window_id.as_str()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryPrimitive {
    SemanticAccessibility,
    PerPidSynthetic,
    GlobalSynthetic,
    None,
}

pub type ContainmentDeliveryPrimitive = DeliveryPrimitive;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentRung {
    SemanticElement,
    PidStructural,
    GlobalNone,
}

impl ContainmentRung {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SemanticElement => "semantic_element",
            Self::PidStructural => "pid_structural",
            Self::GlobalNone => "global_none",
        }
    }
}

/// Evidence supplied by a dispatcher for one attempted input action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentEvidence {
    pub input_action: bool,
    pub action_kind: ActionKind,
    pub delivery_primitive: DeliveryPrimitive,
    pub coordinate_addressed: bool,
    pub identity: Option<IdentityCheckEvidence>,
    pub fronting: Option<FrontingComparisonEvidence>,
    pub global_none_authorized: bool,
}

impl ContainmentEvidence {
    pub fn input(
        action_kind: ActionKind,
        delivery_primitive: DeliveryPrimitive,
        coordinate_addressed: bool,
        identity: Option<IdentityCheckEvidence>,
        fronting: Option<FrontingComparisonEvidence>,
        global_none_authorized: bool,
    ) -> Self {
        Self {
            input_action: true,
            action_kind,
            delivery_primitive,
            coordinate_addressed,
            identity,
            fronting,
            global_none_authorized,
        }
    }

    pub fn non_input(action_kind: ActionKind) -> Self {
        Self {
            input_action: false,
            action_kind,
            delivery_primitive: DeliveryPrimitive::None,
            coordinate_addressed: false,
            identity: None,
            fronting: None,
            global_none_authorized: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentForfeitureReason {
    CoordinateAddressed,
    NonStructuralDelivery,
    IdentityUnavailable,
    IdentityStale,
    IdentityIndeterminate,
    IdentityInadequate,
    IdentityBoundExceeded,
    FrontingDowngradeDetected,
    FrontingIndeterminate,
    FrontingBoundExceeded,
    FrontingUnavailable,
}

impl ContainmentForfeitureReason {
    /// The stable wire spelling. Callers branch on these, so they are written
    /// out rather than derived from the variant name -- a rename should be a
    /// deliberate wire change rather than a side effect of tidying an enum.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoordinateAddressed => "coordinate_addressed",
            Self::NonStructuralDelivery => "non_structural_delivery",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::IdentityStale => "identity_stale",
            Self::IdentityIndeterminate => "identity_indeterminate",
            Self::IdentityInadequate => "identity_inadequate",
            Self::IdentityBoundExceeded => "identity_bound_exceeded",
            Self::FrontingDowngradeDetected => "fronting_downgrade_detected",
            Self::FrontingIndeterminate => "fronting_indeterminate",
            Self::FrontingBoundExceeded => "fronting_bound_exceeded",
            Self::FrontingUnavailable => "fronting_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentFinalization {
    /// `Some` is required for every input row and `None` is required for every
    /// non-input row.
    pub containment_rung: Option<ContainmentRung>,
    /// Whether the target was verifiably fronted across the dispatch bracket.
    ///
    /// Its own fact rather than a containment input. False here does not mean
    /// the action escaped its process -- per-pid delivery cannot -- it means the
    /// window that received the input inside that process is not pinned down.
    /// Recording it separately is what lets an auditor read "delivered per-pid,
    /// target not fronted" without either half being implied by the other.
    pub fronting_stable: bool,
    pub input_action: bool,
    pub dispatch_permitted: bool,
    pub forfeiture_reason: Option<ContainmentForfeitureReason>,
    pub identity: Option<IdentityCheckEvidence>,
    pub fronting: Option<FrontingComparisonEvidence>,
    pub delivery_primitive: DeliveryPrimitive,
}

impl ContainmentFinalization {
    pub fn rung(&self) -> Option<ContainmentRung> {
        self.containment_rung
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentRefusalCode {
    GrantIdentityMismatch,
    IdentityVerificationUnavailable,
}

impl fmt::Display for ContainmentRefusalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl ContainmentRefusalCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GrantIdentityMismatch => "grant_identity_mismatch",
            Self::IdentityVerificationUnavailable => "identity_verification_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentRefusal {
    pub code: ContainmentRefusalCode,
    pub forfeiture_reason: Option<ContainmentForfeitureReason>,
    pub identity: Option<IdentityCheckEvidence>,
    pub fronting: Option<FrontingComparisonEvidence>,
}

impl fmt::Display for ContainmentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())
    }
}
impl std::error::Error for ContainmentRefusal {}

/// Finalize exactly one rung for an input row.  A structural candidate that
/// loses identity or fronting evidence can only fall to `global_none` when the
/// caller has independently authorized that severity.
#[allow(clippy::result_large_err)]
pub fn finalize_containment(
    evidence: ContainmentEvidence,
) -> Result<ContainmentFinalization, ContainmentRefusal> {
    if !evidence.input_action || evidence.action_kind == ActionKind::Observe {
        return Ok(ContainmentFinalization {
            containment_rung: None,
            fronting_stable: false,
            input_action: false,
            dispatch_permitted: true,
            forfeiture_reason: None,
            identity: None,
            fronting: None,
            delivery_primitive: DeliveryPrimitive::None,
        });
    }

    if let Some(identity) = evidence.identity.as_ref() {
        if identity.status == IdentityVerificationStatus::Mismatch
            || (identity.grant_tuple_matches == Some(false) && identity.compatibility.compatible)
        {
            return Err(ContainmentRefusal {
                code: ContainmentRefusalCode::GrantIdentityMismatch,
                forfeiture_reason: None,
                identity: evidence.identity,
                fronting: evidence.fronting,
            });
        }
    }

    if evidence.coordinate_addressed
        || matches!(
            evidence.delivery_primitive,
            DeliveryPrimitive::GlobalSynthetic | DeliveryPrimitive::None
        )
    {
        let forfeiture_reason = if evidence.coordinate_addressed {
            ContainmentForfeitureReason::CoordinateAddressed
        } else {
            ContainmentForfeitureReason::NonStructuralDelivery
        };
        let fronting_stable = evidence
            .fronting
            .as_ref()
            .is_some_and(FrontingComparisonEvidence::unchanged);
        if evidence.global_none_authorized {
            return Ok(ContainmentFinalization {
                containment_rung: Some(ContainmentRung::GlobalNone),
                fronting_stable,
                input_action: true,
                dispatch_permitted: true,
                forfeiture_reason: Some(forfeiture_reason),
                identity: evidence.identity,
                fronting: evidence.fronting,
                delivery_primitive: evidence.delivery_primitive,
            });
        }
        return Err(ContainmentRefusal {
            code: ContainmentRefusalCode::IdentityVerificationUnavailable,
            forfeiture_reason: Some(forfeiture_reason),
            identity: evidence.identity,
            fronting: evidence.fronting,
        });
    }

    let mut forfeiture_reason = None;
    let structural_identity_ok = match evidence.identity.as_ref() {
        Some(identity)
            if identity.status == IdentityVerificationStatus::Matched
                && identity.compatibility.compatible
                && identity.grant_tuple_matches == Some(true) =>
        {
            if let Some(maximum) = identity.maximum_identity_check_to_dispatch_interval_ms {
                if identity
                    .measured_check_to_dispatch_interval_ms
                    .is_none_or(|interval| interval > maximum)
                {
                    set_forfeiture_reason(
                        &mut forfeiture_reason,
                        ContainmentForfeitureReason::IdentityBoundExceeded,
                    );
                    false
                } else {
                    true
                }
            } else {
                // A structural row cannot rely on an absent immutable bound.
                set_forfeiture_reason(
                    &mut forfeiture_reason,
                    ContainmentForfeitureReason::IdentityUnavailable,
                );
                false
            }
        }
        Some(identity) => {
            set_forfeiture_reason(
                &mut forfeiture_reason,
                match identity.status {
                    IdentityVerificationStatus::Unavailable => {
                        ContainmentForfeitureReason::IdentityUnavailable
                    }
                    IdentityVerificationStatus::Stale => ContainmentForfeitureReason::IdentityStale,
                    IdentityVerificationStatus::Indeterminate => {
                        ContainmentForfeitureReason::IdentityIndeterminate
                    }
                    IdentityVerificationStatus::Inadequate => {
                        ContainmentForfeitureReason::IdentityInadequate
                    }
                    IdentityVerificationStatus::Matched | IdentityVerificationStatus::Mismatch => {
                        ContainmentForfeitureReason::IdentityInadequate
                    }
                },
            );
            false
        }
        None => {
            set_forfeiture_reason(
                &mut forfeiture_reason,
                ContainmentForfeitureReason::IdentityUnavailable,
            );
            false
        }
    };

    // Fronting is measured and RECORDED, never charged against containment.
    //
    // `unchanged()` is a composite judgement -- comparison unchanged, no
    // reasons raised, and the measured bracket inside its bound -- so keeping it
    // as a stored fact saves every reader recomputing it, and saves them
    // disagreeing about it.
    //
    // Absent evidence records as not-stable rather than as unknown, which is the
    // conservative reading of a fact and costs nothing now that it cannot lower
    // a rung. What it must never become again is a forfeiture: see below.
    let fronting_stable = evidence
        .fronting
        .as_ref()
        .is_some_and(FrontingComparisonEvidence::unchanged);

    // Fronting does NOT gate a structural rung, deliberately.
    //
    // The rung claims containment TO a process. Per-pid delivery guarantees that
    // by mechanism: the events are posted to a pid and cannot arrive anywhere
    // else, whatever holds focus. Semantic actuation likewise invokes a named
    // element through the accessibility API rather than through whatever is
    // frontmost.
    //
    // Requiring fronting here was a rule written for GLOBAL dispatch, where
    // fronting verification IS the containment argument because events go to
    // whoever holds focus. Applied to the modes that exist to make fronting
    // irrelevant it inverts: it penalised exactly the case per-pid was built
    // for, and reported global_none -- "this action was uncontained" -- for an
    // action measured not to steal focus. That is an untrue statement about
    // mechanism used to express a true concern about visibility.
    //
    // The concern is real and keeps an honest home: fronting is recorded as its
    // own fact on this finalization, so a caller and an auditor can both see
    // "delivered per-pid, target not fronted". What fronting genuinely bears on
    // is precision WITHIN the process -- which window received a keystroke --
    // and that is not what the rung asserts.
    let structural_rung = if !evidence.coordinate_addressed && structural_identity_ok {
        match evidence.delivery_primitive {
            DeliveryPrimitive::SemanticAccessibility => Some(ContainmentRung::SemanticElement),
            DeliveryPrimitive::PerPidSynthetic => Some(ContainmentRung::PidStructural),
            DeliveryPrimitive::GlobalSynthetic | DeliveryPrimitive::None => {
                set_forfeiture_reason(
                    &mut forfeiture_reason,
                    ContainmentForfeitureReason::NonStructuralDelivery,
                );
                None
            }
        }
    } else if evidence.coordinate_addressed {
        set_forfeiture_reason(
            &mut forfeiture_reason,
            ContainmentForfeitureReason::CoordinateAddressed,
        );
        None
    } else {
        None
    };

    if let Some(rung) = structural_rung {
        return Ok(ContainmentFinalization {
            containment_rung: Some(rung),
            fronting_stable,
            input_action: true,
            dispatch_permitted: true,
            forfeiture_reason: None,
            identity: evidence.identity,
            fronting: evidence.fronting,
            delivery_primitive: evidence.delivery_primitive,
        });
    }

    if evidence.global_none_authorized {
        Ok(ContainmentFinalization {
            containment_rung: Some(ContainmentRung::GlobalNone),
            fronting_stable,
            input_action: true,
            dispatch_permitted: true,
            forfeiture_reason,
            identity: evidence.identity,
            fronting: evidence.fronting,
            delivery_primitive: evidence.delivery_primitive,
        })
    } else {
        Err(ContainmentRefusal {
            code: ContainmentRefusalCode::IdentityVerificationUnavailable,
            forfeiture_reason,
            identity: evidence.identity,
            fronting: evidence.fronting,
        })
    }
}

fn set_forfeiture_reason(
    slot: &mut Option<ContainmentForfeitureReason>,
    reason: ContainmentForfeitureReason,
) {
    if slot.is_none() {
        *slot = Some(reason);
    }
}

#[allow(clippy::result_large_err)]
pub fn finalize_input_containment(
    delivery_primitive: DeliveryPrimitive,
    coordinate_addressed: bool,
    identity: Option<IdentityCheckEvidence>,
    fronting: Option<FrontingComparisonEvidence>,
    global_none_authorized: bool,
) -> Result<ContainmentFinalization, ContainmentRefusal> {
    finalize_containment(ContainmentEvidence::input(
        ActionKind::Compose,
        delivery_primitive,
        coordinate_addressed,
        identity,
        fronting,
        global_none_authorized,
    ))
}

pub fn finalize_non_input_containment(action_kind: ActionKind) -> ContainmentFinalization {
    finalize_containment(ContainmentEvidence::non_input(action_kind))
        .expect("non-input containment finalization cannot be refused")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::FrontingWindow;

    fn grant() -> ProcessGrant {
        ProcessGrant {
            pid: 42,
            bundle_identity: "com.example.Target".into(),
            process_generation_evidence: "gen-1".into(),
        }
    }

    fn fronting(at: u64, z_order: i32) -> FrontingSnapshot {
        FrontingSnapshot {
            captured_at_ms: at,
            frontmost_application_identity: Some("com.example.Other".into()),
            target_windows: vec![FrontingWindow {
                observation_window_id: "window-1".into(),
                owning_process_generation: "gen-1".into(),
                activation_state: "inactive".into(),
                z_order,
            }],
            completeness: true,
        }
    }

    fn matched_identity() -> IdentityCheckEvidence {
        let primitive = ProcessIdentityPrimitive::pinned_v1();
        let grant = primitive
            .capture_grant(grant(), ProcessIdentityEvidence::kernel_vouched("gen-1"), 0)
            .unwrap();
        primitive.verify_for_dispatch(
            &grant,
            &ProcessIdentityObservation::new(
                42,
                "com.example.Target",
                ProcessIdentityEvidence::kernel_vouched("gen-1"),
            ),
            10,
            Some(12),
            Some(5),
            IdentityDiscriminationRequirement::GenerationDiscriminating,
        )
    }

    #[test]
    fn definitive_replacement_is_a_closed_refusal() {
        let primitive = ProcessIdentityPrimitive::pinned_v1();
        let grant = primitive
            .capture_grant(grant(), ProcessIdentityEvidence::kernel_vouched("gen-1"), 0)
            .unwrap();
        let check = primitive.verify_for_dispatch(
            &grant,
            &ProcessIdentityObservation::new(
                42,
                "com.example.Target",
                ProcessIdentityEvidence::kernel_vouched("gen-2"),
            ),
            10,
            Some(11),
            Some(5),
            IdentityDiscriminationRequirement::GenerationDiscriminating,
        );
        assert_eq!(check.status, IdentityVerificationStatus::Mismatch);
        let error = finalize_input_containment(
            DeliveryPrimitive::PerPidSynthetic,
            false,
            Some(check),
            None,
            true,
        )
        .unwrap_err();
        assert_eq!(error.code.as_str(), "grant_identity_mismatch");
    }

    #[test]
    fn timestamp_with_coarse_or_user_controlled_evidence_is_inadequate() {
        let primitive =
            ProcessIdentityPrimitive::timestamp_v1(1_000, IdentityAtomicBinding::NonAtomic);
        let coarse = ProcessIdentityEvidence::timestamp_with_clock(
            1,
            10_000,
            IdentityClockSemantics::KernelSourced,
        );
        assert!(
            !primitive
                .compatibility(
                    IdentityDiscriminationRequirement::GenerationDiscriminating,
                    &coarse
                )
                .compatible
        );
        let user_clock = ProcessIdentityEvidence::timestamp_with_clock(
            1,
            1_000,
            IdentityClockSemantics::UserSourced,
        );
        assert!(
            !primitive
                .compatibility(
                    IdentityDiscriminationRequirement::GenerationDiscriminating,
                    &user_clock
                )
                .compatible
        );
    }

    #[test]
    fn fronting_is_bracketed_and_downgrades_on_a_raise() {
        let evidence = compare_fronting(
            &grant(),
            Some(fronting(0, 3)),
            Some(fronting(100, 1)),
            0,
            100,
            100,
        );
        assert_eq!(evidence.comparison, FrontingComparison::DowngradeDetected);
        assert_eq!(evidence.reason(), Some(FrontingReason::TargetWindowRaised));
        assert_eq!(evidence.measured_bracket_interval_ms, Some(100));
    }

    #[test]
    fn structural_rung_requires_identity_timing_and_fronting_bounds() {
        let identity = matched_identity();
        let fronting = compare_fronting(
            &grant(),
            Some(fronting(0, 1)),
            Some(fronting(100, 1)),
            0,
            100,
            100,
        );
        let result = finalize_input_containment(
            DeliveryPrimitive::PerPidSynthetic,
            false,
            Some(identity),
            Some(fronting),
            false,
        )
        .unwrap();
        assert_eq!(
            result.containment_rung,
            Some(ContainmentRung::PidStructural)
        );
        assert!(!result
            .identity
            .unwrap()
            .identity_to_delivery_binding
            .is_atomic());
    }

    #[test]
    fn non_input_rows_never_receive_a_rung() {
        let result = finalize_non_input_containment(ActionKind::Observe);
        assert_eq!(result.containment_rung, None);
        assert!(!result.input_action);
    }
}
