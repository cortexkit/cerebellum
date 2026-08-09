//! Attendance evidence used by the dispatch seam.
//!
//! A grant identifies a target; it does not prove that a human can still stop
//! the operation.  This module keeps the renewable lease and the conversation
//! stop path explicit so a dispatcher cannot accidentally treat a recent action
//! or an open process as attendance.

use crate::platform::{AttendancePreconditionResult, ProcessGrant};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttendanceLease {
    pub conversation_id: String,
    pub target: ProcessGrant,
    pub responsible_process: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub lease_generation: String,
    pub monotonic_clock_domain: String,
}

impl AttendanceLease {
    pub fn new(
        conversation_id: impl Into<String>,
        target: ProcessGrant,
        responsible_process: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
        lease_generation: impl Into<String>,
        monotonic_clock_domain: impl Into<String>,
    ) -> Result<Self, AttendanceError> {
        let lease = Self {
            conversation_id: conversation_id.into(),
            target,
            responsible_process: responsible_process.into(),
            issued_at_ms,
            expires_at_ms,
            lease_generation: lease_generation.into(),
            monotonic_clock_domain: monotonic_clock_domain.into(),
        };
        lease.validate_shape()?;
        Ok(lease)
    }

    pub fn validate_shape(&self) -> Result<(), AttendanceError> {
        self.target
            .validate()
            .map_err(|_| AttendanceError::InvalidLease)?;
        if self.conversation_id.is_empty()
            || self.responsible_process.is_empty()
            || self.lease_generation.is_empty()
            || self.monotonic_clock_domain.is_empty()
            || self.expires_at_ms <= self.issued_at_ms
        {
            return Err(AttendanceError::InvalidLease);
        }
        Ok(())
    }

    pub fn check(
        &self,
        conversation_id: &str,
        target: &ProcessGrant,
        responsible_process: &str,
        now_ms: u64,
        maximum_age_ms: u64,
    ) -> AttendanceCheckEvidence {
        let age_ms = now_ms.saturating_sub(self.issued_at_ms);
        // Ordered so the answer names the FIRST thing that is wrong, and so the
        // identity mismatches are decided before the time ones: a lease held for
        // another conversation is not made acceptable by being fresh, and
        // reporting it as merely stale would invite a renewal that hands this
        // conversation someone else's attendance.
        let outcome = if self.validate_shape().is_err() {
            AttendanceOutcome::Malformed
        } else if self.conversation_id != conversation_id {
            AttendanceOutcome::WrongConversation
        } else if self.target != *target {
            AttendanceOutcome::WrongTarget
        } else if self.responsible_process != responsible_process {
            AttendanceOutcome::WrongResponsibleProcess
        } else if now_ms < self.issued_at_ms {
            AttendanceOutcome::IssuedInTheFuture
        } else if now_ms >= self.expires_at_ms {
            AttendanceOutcome::Expired
        } else if age_ms > maximum_age_ms {
            AttendanceOutcome::TooOldForThisAction
        } else {
            AttendanceOutcome::Current
        };
        AttendanceCheckEvidence {
            outcome,
            check_time_ms: now_ms,
            lease_generation: Some(self.lease_generation.clone()),
            age_ms: Some(age_ms),
            expires_at_ms: Some(self.expires_at_ms),
            maximum_age_ms,
            atomic_enforcement: false,
        }
    }

    pub fn renew(
        &self,
        issued_at_ms: u64,
        expires_at_ms: u64,
        lease_generation: impl Into<String>,
    ) -> Result<Self, AttendanceError> {
        Self::new(
            self.conversation_id.clone(),
            self.target.clone(),
            self.responsible_process.clone(),
            issued_at_ms,
            expires_at_ms,
            lease_generation,
            self.monotonic_clock_domain.clone(),
        )
    }
}

/// Why a lease does or does not authorize the action being attempted.
///
/// Kept apart rather than reduced to a yes/no because the remedies differ and
/// two of them are opposites: a lease that has merely aged out should be renewed
/// and the action retried, while one belonging to another conversation must
/// never be renewed into this one. A caller told only that the check failed
/// cannot choose between them, and the plausible guess is the unsafe one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttendanceOutcome {
    /// The lease covers this action now.
    Current,
    /// The lease is internally inconsistent, so it evidences nothing.
    Malformed,
    /// Held for a different conversation. Never renewable into this one.
    WrongConversation,
    /// Held for a different target process.
    WrongTarget,
    /// Issued against a different responsible process.
    WrongResponsibleProcess,
    /// Issued after the moment being checked, so the clocks disagree and no
    /// age computed from it means anything.
    IssuedInTheFuture,
    /// Past its expiry. Renewable.
    Expired,
    /// Still live, but older than this particular action tolerates. Renewable,
    /// and distinct from expiry because the lease is valid for other actions.
    TooOldForThisAction,
}

impl AttendanceOutcome {
    /// Whether a fresh lease for the same conversation and target would admit
    /// the action.
    ///
    /// False for the identity mismatches, where renewing would replace a
    /// question about authority with a newer lease that answers a different one.
    pub const fn is_renewable(self) -> bool {
        matches!(self, Self::Expired | Self::TooOldForThisAction)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttendanceCheckEvidence {
    pub outcome: AttendanceOutcome,
    pub check_time_ms: u64,
    pub lease_generation: Option<String>,
    pub age_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub maximum_age_ms: u64,
    pub atomic_enforcement: bool,
}

impl AttendanceCheckEvidence {
    pub fn from_platform(
        result: AttendancePreconditionResult,
        check_time_ms: u64,
        maximum_age_ms: u64,
    ) -> Self {
        Self {
            // The driver answers with a boolean, so its refusals arrive already
            // collapsed and this cannot recover which one applied. Reported as
            // Malformed rather than as a specific cause, because naming one
            // would attribute a reason the driver never gave.
            outcome: if result.valid {
                AttendanceOutcome::Current
            } else {
                AttendanceOutcome::Malformed
            },
            check_time_ms,
            lease_generation: result.lease_generation,
            age_ms: result.age_ms,
            expires_at_ms: None,
            maximum_age_ms,
            atomic_enforcement: false,
        }
    }

    /// Whether the lease admits the action.
    pub const fn valid(&self) -> bool {
        matches!(self.outcome, AttendanceOutcome::Current)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttendanceDispatchEvidence {
    pub check: AttendanceCheckEvidence,
    pub dispatch_time_ms: u64,
    pub measured_check_to_dispatch_interval_ms: Option<u64>,
    pub maximum_check_to_dispatch_interval_ms: u64,
    pub stop_path_live: bool,
}

impl AttendanceDispatchEvidence {
    pub fn within_bound(&self) -> bool {
        self.check.valid()
            && self.stop_path_live
            && self
                .check
                .expires_at_ms
                .is_none_or(|expires_at| self.dispatch_time_ms < expires_at)
            && self
                .measured_check_to_dispatch_interval_ms
                .is_some_and(|interval| interval <= self.maximum_check_to_dispatch_interval_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttendanceRequirement {
    None,
    Background,
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttendanceContext {
    pub requirement: AttendanceRequirement,
    pub conversation_id: String,
    pub target: ProcessGrant,
    pub responsible_process: String,
    pub stop_path_live: bool,
    pub lease: Option<AttendanceLease>,
    pub check_time_ms: u64,
    pub dispatch_time_ms: u64,
    pub maximum_lease_age_ms: u64,
    pub maximum_check_to_dispatch_interval_ms: u64,
    pub atomic_enforcement: bool,
}

impl AttendanceContext {
    pub fn none(target: ProcessGrant, at_ms: u64) -> Self {
        Self {
            requirement: AttendanceRequirement::None,
            conversation_id: String::new(),
            target,
            responsible_process: String::new(),
            stop_path_live: true,
            lease: None,
            check_time_ms: at_ms,
            dispatch_time_ms: at_ms,
            maximum_lease_age_ms: 0,
            maximum_check_to_dispatch_interval_ms: 0,
            atomic_enforcement: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn background(
        conversation_id: impl Into<String>,
        target: ProcessGrant,
        responsible_process: impl Into<String>,
        lease: AttendanceLease,
        check_time_ms: u64,
        dispatch_time_ms: u64,
        maximum_lease_age_ms: u64,
        maximum_check_to_dispatch_interval_ms: u64,
        stop_path_live: bool,
    ) -> Self {
        Self {
            requirement: AttendanceRequirement::Background,
            conversation_id: conversation_id.into(),
            target,
            responsible_process: responsible_process.into(),
            stop_path_live,
            lease: Some(lease),
            check_time_ms,
            dispatch_time_ms,
            maximum_lease_age_ms,
            maximum_check_to_dispatch_interval_ms,
            atomic_enforcement: false,
        }
    }

    pub fn observed(
        conversation_id: impl Into<String>,
        target: ProcessGrant,
        responsible_process: impl Into<String>,
        check_time_ms: u64,
        dispatch_time_ms: u64,
        stop_path_live: bool,
    ) -> Self {
        Self {
            requirement: AttendanceRequirement::Observed,
            conversation_id: conversation_id.into(),
            target,
            responsible_process: responsible_process.into(),
            stop_path_live,
            lease: None,
            check_time_ms,
            dispatch_time_ms,
            maximum_lease_age_ms: 0,
            maximum_check_to_dispatch_interval_ms: 0,
            atomic_enforcement: false,
        }
    }

    pub fn with_atomic_enforcement(mut self, atomic: bool) -> Self {
        self.atomic_enforcement = atomic;
        self
    }

    pub fn validate_local(&self) -> Result<AttendanceDispatchEvidence, AttendanceError> {
        if !self.stop_path_live {
            return Err(AttendanceError::StopPathUnavailable);
        }
        if self.requirement == AttendanceRequirement::Observed
            && (self.conversation_id.is_empty()
                || self.responsible_process.is_empty()
                || self.target.validate().is_err())
        {
            return Err(AttendanceError::BindingMismatch);
        }
        let check = match self.requirement {
            AttendanceRequirement::None | AttendanceRequirement::Observed => {
                AttendanceCheckEvidence {
                    // No lease is required, so nothing about one is being
                    // reported: this records that the requirement was met, not
                    // that a lease was examined.
                    outcome: AttendanceOutcome::Current,
                    check_time_ms: self.check_time_ms,
                    lease_generation: None,
                    age_ms: None,
                    expires_at_ms: None,
                    maximum_age_ms: self.maximum_lease_age_ms,
                    atomic_enforcement: self.atomic_enforcement,
                }
            }
            AttendanceRequirement::Background => self
                .lease
                .as_ref()
                .ok_or(AttendanceError::LeaseUnavailable)?
                .check(
                    &self.conversation_id,
                    &self.target,
                    &self.responsible_process,
                    self.check_time_ms,
                    self.maximum_lease_age_ms,
                ),
        };
        let measured = self.dispatch_time_ms.checked_sub(self.check_time_ms);
        let evidence = AttendanceDispatchEvidence {
            check,
            dispatch_time_ms: self.dispatch_time_ms,
            measured_check_to_dispatch_interval_ms: measured,
            maximum_check_to_dispatch_interval_ms: self.maximum_check_to_dispatch_interval_ms,
            stop_path_live: self.stop_path_live,
        };
        if self.requirement != AttendanceRequirement::None
            && (!evidence.check.valid()
                || !evidence.stop_path_live
                || evidence
                    .check
                    .expires_at_ms
                    .is_some_and(|expires_at| evidence.dispatch_time_ms >= expires_at))
        {
            return Err(AttendanceError::LeaseExpired);
        }
        if self.requirement != AttendanceRequirement::None
            && !self.atomic_enforcement
            && !evidence.within_bound()
        {
            return Err(AttendanceError::CheckToDispatchBoundExceeded);
        }
        Ok(evidence)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttendanceError {
    InvalidLease,
    LeaseUnavailable,
    LeaseExpired,
    BindingMismatch,
    StopPathUnavailable,
    ProviderUnavailable,
    CheckToDispatchBoundExceeded,
}

impl fmt::Display for AttendanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLease => "attendance_unavailable",
            Self::LeaseUnavailable => "attendance_unavailable",
            Self::LeaseExpired => "attendance_unavailable",
            Self::BindingMismatch => "attendance_unavailable",
            Self::StopPathUnavailable => "attendance_unavailable",
            Self::ProviderUnavailable => "attendance_unavailable",
            Self::CheckToDispatchBoundExceeded => "attendance_unavailable",
        })
    }
}

impl std::error::Error for AttendanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUED: u64 = 1_000;
    const EXPIRES: u64 = 11_000;
    const MAX_AGE: u64 = 5_000;

    fn target() -> ProcessGrant {
        ProcessGrant {
            pid: 4242,
            bundle_identity: "com.example.app".to_string(),
            process_generation_evidence: "1700000000000000".to_string(),
        }
    }

    fn lease() -> AttendanceLease {
        AttendanceLease::new(
            "conversation-1",
            target(),
            "ck-subc",
            ISSUED,
            EXPIRES,
            "generation-1",
            "monotonic-1",
        )
        .expect("a well-formed lease")
    }

    fn outcome_at(now_ms: u64, maximum_age_ms: u64) -> AttendanceOutcome {
        lease()
            .check(
                "conversation-1",
                &target(),
                "ck-subc",
                now_ms,
                maximum_age_ms,
            )
            .outcome
    }

    /// A lease covering the action reports so.
    ///
    /// The accepting case, asserted because every other test here asserts a
    /// refusal: without it the check could refuse everything and they would all
    /// still pass.
    #[test]
    fn a_lease_covering_the_action_is_current() {
        assert_eq!(
            outcome_at(ISSUED + 1_000, MAX_AGE),
            AttendanceOutcome::Current
        );
    }

    /// Each way a lease can fail to cover the action is reported as itself.
    ///
    /// The distinction is what the caller acts on: two of these are renewable
    /// and the rest are not, so a single refusal would leave it to guess, and
    /// the guess that looks reasonable (renew and retry) is the unsafe one for
    /// the identity mismatches.
    #[test]
    fn every_way_a_lease_fails_is_reported_as_itself() {
        let held = lease();
        let at = ISSUED + 1_000;

        assert_eq!(
            held.check("another-conversation", &target(), "ck-subc", at, MAX_AGE)
                .outcome,
            AttendanceOutcome::WrongConversation
        );

        let mut other_target = target();
        other_target.pid = 9999;
        assert_eq!(
            held.check("conversation-1", &other_target, "ck-subc", at, MAX_AGE)
                .outcome,
            AttendanceOutcome::WrongTarget
        );

        assert_eq!(
            held.check("conversation-1", &target(), "other-launcher", at, MAX_AGE)
                .outcome,
            AttendanceOutcome::WrongResponsibleProcess
        );

        assert_eq!(
            outcome_at(ISSUED - 1, MAX_AGE),
            AttendanceOutcome::IssuedInTheFuture
        );
        assert_eq!(outcome_at(EXPIRES, MAX_AGE), AttendanceOutcome::Expired);

        // Inside the lease's own window, but older than this action tolerates.
        assert_eq!(
            outcome_at(ISSUED + MAX_AGE + 1, MAX_AGE),
            AttendanceOutcome::TooOldForThisAction
        );
    }

    /// Only the time-based failures may be answered by renewing.
    ///
    /// Renewing after an identity mismatch would replace a question about
    /// authority with a fresh lease that answers a different one — the caller
    /// would hold a valid lease for a conversation or target it was never
    /// granted.
    #[test]
    fn only_the_time_based_failures_are_renewable() {
        for renewable in [
            AttendanceOutcome::Expired,
            AttendanceOutcome::TooOldForThisAction,
        ] {
            assert!(renewable.is_renewable(), "{renewable:?}");
        }
        for refused in [
            AttendanceOutcome::Current,
            AttendanceOutcome::Malformed,
            AttendanceOutcome::WrongConversation,
            AttendanceOutcome::WrongTarget,
            AttendanceOutcome::WrongResponsibleProcess,
            AttendanceOutcome::IssuedInTheFuture,
        ] {
            assert!(!refused.is_renewable(), "{refused:?}");
        }
    }

    /// A mismatch of identity outranks a mismatch of time.
    ///
    /// A lease held for another conversation and also expired must report the
    /// conversation, because the other order invites a renewal that hands this
    /// conversation someone else's attendance.
    #[test]
    fn an_identity_mismatch_outranks_an_expiry() {
        let evidence = lease().check(
            "another-conversation",
            &target(),
            "ck-subc",
            EXPIRES + 1_000,
            MAX_AGE,
        );
        assert_eq!(evidence.outcome, AttendanceOutcome::WrongConversation);
        assert!(!evidence.outcome.is_renewable());
    }

    /// A driver's boolean refusal is not reported as a specific cause.
    ///
    /// The platform answers yes or no, so the cause is already lost when it
    /// arrives. Naming one here would attribute a reason the driver never gave.
    #[test]
    fn a_driver_refusal_claims_no_particular_cause() {
        let refused = AttendanceCheckEvidence::from_platform(
            AttendancePreconditionResult {
                valid: false,
                lease_generation: None,
                age_ms: None,
            },
            ISSUED,
            MAX_AGE,
        );
        assert_eq!(refused.outcome, AttendanceOutcome::Malformed);
        assert!(!refused.valid());
        assert!(!refused.outcome.is_renewable());
    }
}
