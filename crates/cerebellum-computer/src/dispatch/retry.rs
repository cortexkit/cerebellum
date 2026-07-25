//! Retry, reconciliation, and consent-gated escalation policy.
//!
//! A delivery that may have committed is never repeated merely because its API
//! returned an error.  Reconciliation or a row-specific deduplication key must
//! establish that another attempt is safe.

use crate::platform::RetryClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptDisposition {
    NotAttempted,
    Committed,
    MayHaveCommitted,
    NoEffectObserved,
    EffectObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationResult {
    EffectObserved,
    NoEffectObserved,
    EffectIndeterminate,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDecision {
    ReResolveStaleElement,
    RetryIdempotent,
    RetryDeduplicated,
    RetryAfterNoEffect,
    DoNotRetry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptLedger {
    committed_ids: BTreeSet<String>,
    attempted_ids: BTreeSet<String>,
}

impl AttemptLedger {
    pub fn new() -> Self {
        Self {
            committed_ids: BTreeSet::new(),
            attempted_ids: BTreeSet::new(),
        }
    }

    pub fn record(&mut self, attempt_id: impl Into<String>, disposition: AttemptDisposition) {
        let id = attempt_id.into();
        self.attempted_ids.insert(id.clone());
        if matches!(
            disposition,
            AttemptDisposition::Committed | AttemptDisposition::EffectObserved
        ) {
            self.committed_ids.insert(id);
        }
    }

    pub fn may_repeat(&self, attempt_id: &str) -> bool {
        !self.committed_ids.contains(attempt_id)
    }

    pub fn was_attempted(&self, attempt_id: &str) -> bool {
        self.attempted_ids.contains(attempt_id)
    }
}

impl Default for AttemptLedger {
    fn default() -> Self {
        Self::new()
    }
}

pub fn retry_decision(
    class: RetryClass,
    disposition: AttemptDisposition,
    reconciliation: ReconciliationResult,
    deduplication_key: Option<&str>,
    ledger: &AttemptLedger,
    attempt_id: &str,
) -> RetryDecision {
    if matches!(
        disposition,
        AttemptDisposition::Committed | AttemptDisposition::EffectObserved
    ) || (disposition == AttemptDisposition::MayHaveCommitted
        && reconciliation != ReconciliationResult::NoEffectObserved)
    {
        return RetryDecision::DoNotRetry;
    }
    if ledger.was_attempted(attempt_id) && !ledger.may_repeat(attempt_id) {
        return RetryDecision::DoNotRetry;
    }
    match class {
        RetryClass::NeverAutomaticRetry => RetryDecision::DoNotRetry,
        RetryClass::Idempotent => RetryDecision::RetryIdempotent,
        RetryClass::Deduplicated if deduplication_key.is_some_and(|key| !key.is_empty()) => {
            RetryDecision::RetryDeduplicated
        }
        RetryClass::ReconcileBeforeRetry
            if reconciliation == ReconciliationResult::NoEffectObserved =>
        {
            RetryDecision::RetryAfterNoEffect
        }
        RetryClass::Deduplicated | RetryClass::ReconcileBeforeRetry => RetryDecision::DoNotRetry,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    Granted,
    Refused,
}

pub trait EscalationConsent {
    fn request_consent(&mut self, escalation_id: &str) -> ConsentDecision;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationAttempt {
    pub escalation_id: String,
    pub background_attempt_id: String,
    pub observed_attempt_id: Option<String>,
    pub consent: ConsentDecision,
    pub prior_disposition: AttemptDisposition,
    pub reconciliation: ReconciliationResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationError {
    ConsentRefused,
    RetryUnsafe,
    MissingEscalationId,
}

impl EscalationError {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ConsentRefused => "background_unsupported_target",
            Self::RetryUnsafe => "target_busy",
            Self::MissingEscalationId => "invalid_request",
        }
    }
}

pub fn authorize_escalation<C: EscalationConsent>(
    consent: &mut C,
    escalation_id: impl Into<String>,
    background_attempt_id: impl Into<String>,
    prior_disposition: AttemptDisposition,
    reconciliation: ReconciliationResult,
    retry_class: RetryClass,
    ledger: &AttemptLedger,
) -> Result<EscalationAttempt, EscalationError> {
    let escalation_id = escalation_id.into();
    let background_attempt_id = background_attempt_id.into();
    if escalation_id.is_empty() || background_attempt_id.is_empty() {
        return Err(EscalationError::MissingEscalationId);
    }
    let decision = retry_decision(
        retry_class,
        prior_disposition,
        reconciliation,
        None,
        ledger,
        &background_attempt_id,
    );
    if matches!(decision, RetryDecision::DoNotRetry) {
        return Err(EscalationError::RetryUnsafe);
    }
    if consent.request_consent(&escalation_id) != ConsentDecision::Granted {
        return Err(EscalationError::ConsentRefused);
    }
    let observed_attempt_id = format!("{escalation_id}:observed");
    Ok(EscalationAttempt {
        escalation_id,
        background_attempt_id,
        observed_attempt_id: Some(observed_attempt_id),
        consent: ConsentDecision::Granted,
        prior_disposition,
        reconciliation,
    })
}
