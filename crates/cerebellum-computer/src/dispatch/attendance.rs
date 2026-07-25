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
        let valid = self.validate_shape().is_ok()
            && self.conversation_id == conversation_id
            && self.target == *target
            && self.responsible_process == responsible_process
            && now_ms >= self.issued_at_ms
            && now_ms < self.expires_at_ms
            && age_ms <= maximum_age_ms;
        AttendanceCheckEvidence {
            valid,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttendanceCheckEvidence {
    pub valid: bool,
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
            valid: result.valid,
            check_time_ms,
            lease_generation: result.lease_generation,
            age_ms: result.age_ms,
            expires_at_ms: None,
            maximum_age_ms,
            atomic_enforcement: false,
        }
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
        self.check.valid
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
                    valid: true,
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
            && (!evidence.check.valid
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
