//! Closed connector test-plan and evidence artifacts.
//!
//! S2 does not perform network I/O.  It validates the immutable release
//! evidence and exposes a pure eligibility result; S4 consumes the custody
//! admission proof and applies the selected connector policy at runtime.

use super::custody::{canonical_json_bytes, sha256_hex, valid_digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const EVIDENCE_SCHEMA: &str = "ck-browser-connector-evidence/v1";
pub const TEST_PLAN_SCHEMA: &str = "ck-browser-connector-test-plan/v1";

pub const REQUIREMENTS: &[&str] = &[
    "NET-ADDRESS-CANONICALIZATION",
    "NET-ADDRESS-CLASSIFICATION",
    "NET-ALLOWED-CANDIDATE-SELECTION",
    "NET-BYPASS-SUITE",
    "NET-CONNECTOR-DNS",
    "NET-CUSTODY-ARGS",
    "NET-CUSTODY-BINARY",
    "NET-DNS-CHANGE-RECHECK",
    "NET-DOWNLOAD-BLOCK",
    "NET-EXACT-PEER-BINDING",
    "NET-NO-DIRECT-FALLBACK",
    "NET-REDIRECT-RECHECK",
    "NET-REQUEST-CLASS-COVERAGE",
    "NET-RETRY-RECHECK",
    "NET-SUBRESOURCE-RECORD-ONLY",
    "NET-TOPLEVEL-ORIGIN-GATE",
    "NET-TRANSPORT-COALESCING",
    "NET-TRANSPORT-REUSE",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorTestPlan {
    pub schema: String,
    pub test_plan_revision: String,
    pub cases: Vec<TestPlanCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestPlanCase {
    pub case_id: String,
    pub requirement_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorEvidence {
    pub schema: String,
    pub custody_sha256: String,
    pub address_policy_sha256: String,
    pub runner_revision: String,
    pub test_plan_sha256: String,
    pub case_results: Vec<EvidenceCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCaseResult {
    pub case_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    InvalidJson,
    NonCanonical,
    UnknownOrMissingField,
    InvalidField(&'static str),
    DigestMismatch,
}

fn parse_canonical<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ArtifactError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ArtifactError::InvalidJson)?;
    if canonical_json_bytes(&value) != bytes {
        return Err(ArtifactError::NonCanonical);
    }
    serde_json::from_value(value).map_err(|_| ArtifactError::UnknownOrMissingField)
}

fn valid_revision(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "placeholder" | "tbd" | "unknown"
        )
}

fn valid_id(value: &str) -> bool {
    (1..=256).contains(&value.len())
}

impl ConnectorTestPlan {
    pub fn parse(bytes: &[u8]) -> Result<Self, ArtifactError> {
        let plan: Self = parse_canonical(bytes)?;
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != TEST_PLAN_SCHEMA {
            return Err(ArtifactError::InvalidField("schema"));
        }
        if !valid_revision(&self.test_plan_revision) {
            return Err(ArtifactError::InvalidField("test_plan_revision"));
        }
        let mut previous: Option<String> = None;
        let mut seen = BTreeSet::new();
        let mut covered = BTreeSet::new();
        for case in &self.cases {
            if !valid_id(&case.case_id) || !seen.insert(case.case_id.clone()) {
                return Err(ArtifactError::InvalidField("cases"));
            }
            if previous
                .as_deref()
                .is_some_and(|old| old.as_bytes() >= case.case_id.as_bytes())
            {
                return Err(ArtifactError::InvalidField("cases"));
            }
            previous = Some(case.case_id.clone());
            if case.requirement_ids.is_empty() {
                return Err(ArtifactError::InvalidField("requirement_ids"));
            }
            let mut old: Option<String> = None;
            let mut local = BTreeSet::new();
            for requirement in &case.requirement_ids {
                if !REQUIREMENTS.contains(&requirement.as_str())
                    || !local.insert(requirement.clone())
                {
                    return Err(ArtifactError::InvalidField("requirement_ids"));
                }
                if old
                    .as_deref()
                    .is_some_and(|previous| previous.as_bytes() >= requirement.as_bytes())
                {
                    return Err(ArtifactError::InvalidField("requirement_ids"));
                }
                old = Some(requirement.clone());
                covered.insert(requirement.clone());
            }
        }
        if REQUIREMENTS
            .iter()
            .any(|requirement| !covered.contains(*requirement))
        {
            return Err(ArtifactError::InvalidField("cases"));
        }
        if !self.cases.iter().any(|case| {
            case.requirement_ids
                .iter()
                .any(|id| id == "NET-CUSTODY-BINARY")
                && case
                    .requirement_ids
                    .iter()
                    .any(|id| id == "NET-NO-DIRECT-FALLBACK")
        }) {
            return Err(ArtifactError::InvalidField("cases"));
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(&serde_json::to_value(self).expect("plan serializes"))
    }
}

impl ConnectorEvidence {
    pub fn parse(bytes: &[u8]) -> Result<Self, ArtifactError> {
        let evidence: Self = parse_canonical(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != EVIDENCE_SCHEMA {
            return Err(ArtifactError::InvalidField("schema"));
        }
        for (field, value) in [
            ("custody_sha256", &self.custody_sha256),
            ("address_policy_sha256", &self.address_policy_sha256),
            ("test_plan_sha256", &self.test_plan_sha256),
        ] {
            if !valid_digest(value) {
                return Err(ArtifactError::InvalidField(field));
            }
        }
        if !valid_revision(&self.runner_revision) {
            return Err(ArtifactError::InvalidField("runner_revision"));
        }
        let mut previous: Option<String> = None;
        let mut seen = BTreeSet::new();
        for result in &self.case_results {
            if !valid_id(&result.case_id)
                || !seen.insert(result.case_id.clone())
                || result.outcome != "pass"
            {
                return Err(ArtifactError::InvalidField("case_results"));
            }
            if previous
                .as_deref()
                .is_some_and(|old| old.as_bytes() >= result.case_id.as_bytes())
            {
                return Err(ArtifactError::InvalidField("case_results"));
            }
            previous = Some(result.case_id.clone());
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(&serde_json::to_value(self).expect("evidence serializes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSelection<'a> {
    pub evidence: &'a ConnectorEvidence,
    pub test_plan: &'a ConnectorTestPlan,
    pub selected_evidence_sha256: &'a str,
    pub selected_custody_sha256: &'a str,
    pub selected_address_policy_sha256: &'a str,
    pub selected_runner_revision: &'a str,
    pub selected_test_plan_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceEligibility {
    pub eligible: bool,
    pub reasons: Vec<&'static str>,
}

impl EvidenceEligibility {
    pub fn passed(&self) -> bool {
        self.eligible
    }
}

/// Pure, capability-relative connector evidence gate.  Every common CDP-backed
/// capability consumes this result; no capability can opt out of connector
/// evidence or replace it with a boolean approval flag.
pub fn connector_evidence_eligibility(selection: &EvidenceSelection<'_>) -> EvidenceEligibility {
    let mut reasons = Vec::new();
    if selection.evidence.validate().is_err() {
        reasons.push("malformed_evidence");
    }
    if selection.test_plan.validate().is_err() {
        reasons.push("malformed_test_plan");
    }
    if selection.evidence.digest() != selection.selected_evidence_sha256 {
        reasons.push("evidence_digest_mismatch");
    }
    if selection.test_plan.digest() != selection.selected_test_plan_sha256 {
        reasons.push("test_plan_digest_mismatch");
    }
    if selection.evidence.custody_sha256 != selection.selected_custody_sha256 {
        reasons.push("custody_digest_mismatch");
    }
    if selection.evidence.address_policy_sha256 != selection.selected_address_policy_sha256 {
        reasons.push("address_policy_digest_mismatch");
    }
    if selection.evidence.runner_revision != selection.selected_runner_revision {
        reasons.push("runner_revision_mismatch");
    }
    if selection.evidence.test_plan_sha256 != selection.selected_test_plan_sha256 {
        reasons.push("evidence_plan_mismatch");
    }
    let expected: Vec<_> = selection
        .test_plan
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect();
    let actual: Vec<_> = selection
        .evidence
        .case_results
        .iter()
        .map(|case| case.case_id.as_str())
        .collect();
    if expected != actual {
        reasons.push("case_set_mismatch");
    }
    EvidenceEligibility {
        eligible: reasons.is_empty(),
        reasons,
    }
}

pub fn verify_connector_evidence(
    selection: &EvidenceSelection<'_>,
) -> Result<(), EvidenceEligibility> {
    let eligibility = connector_evidence_eligibility(selection);
    if eligibility.eligible {
        Ok(())
    } else {
        Err(eligibility)
    }
}

/// A small adapter useful to S4: proofs are accepted only for the exact child
/// and generation that custody verified.  It deliberately does not authorize
/// a request; attribution and address policy remain S4 responsibilities.
pub fn admission_proof_is_current(
    proof: &super::custody::ConnectorAdmissionProof,
    process_id: u64,
    generation: u64,
    custody_sha256: &str,
) -> bool {
    proof.process_id() == process_id
        && proof.generation() == generation
        && proof.custody_digest() == custody_sha256
}
