//! Expected-post-condition serialization and single-shot effect observation.
//!
//! Platform delivery success is not an effect claim.  The predicate is frozen
//! and serialized before the delivery call; observation is then attempted once
//! with the row's deadline and produces one of the three closed statuses.

use crate::dispatch::post_condition::PostCondition;
use crate::platform::{EffectObservationRequest, EffectStatus, PlatformDriver};
use serde::{Deserialize, Serialize};
use std::fmt;

/// What an action claims will be observably true once it has taken effect.
///
/// The condition is drawn from a closed vocabulary rather than written as free
/// text. An observer handed text it does not recognise cannot say whether the
/// condition held, and the honest answer it must give -- indeterminate -- is
/// indistinguishable from an action that genuinely could not be observed. So an
/// undecidable condition is unconstructible rather than discovered at
/// observation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPostCondition {
    pub schema_id: String,
    pub condition: PostCondition,
}

impl ExpectedPostCondition {
    pub fn new(schema_id: impl Into<String>, condition: PostCondition) -> Self {
        Self {
            schema_id: schema_id.into(),
            condition,
        }
    }

    /// The element this condition will be checked against.
    pub fn element_identifier(&self) -> &str {
        self.condition.element_identifier()
    }

    pub fn serialize_before_dispatch(&self) -> Result<Vec<u8>, EffectError> {
        if self.schema_id.is_empty() {
            return Err(EffectError::PredicateUndeclarable);
        }
        serde_json::to_vec(self).map_err(|_| EffectError::PredicateUndeclarable)
    }

    pub fn observation_request(
        &self,
        target: &crate::platform::ProcessGrant,
        serialized: &[u8],
        deadline_ms: u32,
    ) -> Result<EffectObservationRequest, EffectError> {
        Ok(EffectObservationRequest {
            target: target.clone(),
            predicate: String::from_utf8(serialized.to_vec())
                .map_err(|_| EffectError::PredicateUndeclarable)?,
            deadline_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectObservationPolicy {
    pub deadline_ms: u32,
    pub allow_indeterminate: bool,
}

impl Default for EffectObservationPolicy {
    fn default() -> Self {
        Self {
            deadline_ms: 1_000,
            allow_indeterminate: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectEvidence {
    pub predicate_bytes: Vec<u8>,
    pub observation_method: Option<String>,
    pub deadline_ms: u32,
    pub status: EffectStatus,
    pub failure_reason: Option<String>,
    pub observation_attempts: u8,
}

impl EffectEvidence {
    pub fn observe_serialized<D: PlatformDriver>(
        driver: &mut D,
        target: &crate::platform::ProcessGrant,
        predicate: &ExpectedPostCondition,
        predicate_bytes: Vec<u8>,
        policy: &EffectObservationPolicy,
    ) -> Result<Self, EffectError> {
        let request =
            predicate.observation_request(target, &predicate_bytes, policy.deadline_ms)?;
        let result = match driver.observe_effect(request) {
            Ok(result) => result,
            Err(_) if policy.allow_indeterminate => {
                return Ok(Self {
                    predicate_bytes,
                    observation_method: None,
                    deadline_ms: policy.deadline_ms,
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("observation_primitive_unavailable".to_string()),
                    observation_attempts: 1,
                })
            }
            Err(_) => return Err(EffectError::ObservationUnavailable),
        };
        if result.status == EffectStatus::EffectIndeterminate && !policy.allow_indeterminate {
            return Err(EffectError::ObservationUnavailable);
        }
        Ok(Self {
            predicate_bytes,
            observation_method: Some("platform".to_string()),
            deadline_ms: policy.deadline_ms,
            status: result.status,
            failure_reason: result.failure_reason,
            observation_attempts: 1,
        })
    }

    pub fn observe<D: PlatformDriver>(
        driver: &mut D,
        target: &crate::platform::ProcessGrant,
        predicate: &ExpectedPostCondition,
        policy: &EffectObservationPolicy,
    ) -> Result<Self, EffectError> {
        let bytes = predicate.serialize_before_dispatch()?;
        Self::observe_serialized(driver, target, predicate, bytes, policy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectError {
    PredicateUndeclarable,
    ObservationUnavailable,
}

impl fmt::Display for EffectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PredicateUndeclarable => "post_condition_undeclarable",
            Self::ObservationUnavailable => "observation_primitive_unavailable",
        })
    }
}

impl std::error::Error for EffectError {}
