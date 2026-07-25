//! Immutable extraction-corpus and evidence validation for AX/DOM routes.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::custody::{canonical_json_bytes, valid_digest};

pub const CORPUS_SCHEMA: &str = "ck-browser-extraction-corpus/v1";
pub const EVIDENCE_SCHEMA: &str = "ck-browser-extraction-evidence/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionCase {
    pub case_id: String,
    pub mode: String,
    pub content_schema: String,
    pub expected_content: String,
    pub expected_truncated: bool,
    pub expected_refs_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionCorpus {
    pub schema: String,
    pub corpus_revision: String,
    pub cases: Vec<ExtractionCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionEvidenceCase {
    pub case_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionEvidence {
    pub schema: String,
    pub corpus_sha256: String,
    pub custody_sha256: String,
    pub runner_revision: String,
    pub case_results: Vec<ExtractionEvidenceCase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionError {
    InvalidJson,
    NonCanonical,
    WrongSchema,
    InvalidDigest,
    InvalidRevision,
    InvalidCase,
    DuplicateCase,
    UnsortedCases,
    EvidenceMismatch,
}
impl fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExtractionError {}

impl ExtractionCorpus {
    pub fn parse(bytes: &[u8]) -> Result<Self, ExtractionError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| ExtractionError::InvalidJson)?;
        if canonical_json_bytes(&value) != bytes {
            return Err(ExtractionError::NonCanonical);
        }
        let corpus: Self =
            serde_json::from_value(value).map_err(|_| ExtractionError::InvalidJson)?;
        corpus.validate()?;
        Ok(corpus)
    }
    pub fn validate(&self) -> Result<(), ExtractionError> {
        if self.schema != CORPUS_SCHEMA
            || self.corpus_revision.is_empty()
            || self.corpus_revision.len() > 256
        {
            return Err(ExtractionError::WrongSchema);
        }
        validate_cases(&self.cases)
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(&serde_json::to_value(self).expect("corpus serializes"))
    }
    pub fn digest(&self) -> String {
        crate::custody::sha256_hex(&self.canonical_bytes())
    }
}

impl ExtractionEvidence {
    pub fn parse(bytes: &[u8]) -> Result<Self, ExtractionError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| ExtractionError::InvalidJson)?;
        if canonical_json_bytes(&value) != bytes {
            return Err(ExtractionError::NonCanonical);
        }
        let evidence: Self =
            serde_json::from_value(value).map_err(|_| ExtractionError::InvalidJson)?;
        evidence.validate()?;
        Ok(evidence)
    }
    pub fn validate(&self) -> Result<(), ExtractionError> {
        if self.schema != EVIDENCE_SCHEMA
            || !valid_digest(&self.corpus_sha256)
            || !valid_digest(&self.custody_sha256)
            || self.runner_revision.is_empty()
            || self.runner_revision.len() > 256
        {
            return Err(ExtractionError::InvalidDigest);
        }
        let ids = self
            .case_results
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>();
        let mut unique = BTreeSet::new();
        if ids.iter().any(|id| id.is_empty() || !unique.insert(*id)) {
            return Err(ExtractionError::DuplicateCase);
        }
        if ids.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(ExtractionError::UnsortedCases);
        }
        if self.case_results.iter().any(|case| case.outcome != "pass") {
            return Err(ExtractionError::EvidenceMismatch);
        }
        Ok(())
    }
    pub fn eligible_for(
        &self,
        corpus: &ExtractionCorpus,
        custody_sha256: &str,
        expected_runner: &str,
    ) -> bool {
        if self.validate().is_err()
            || corpus.validate().is_err()
            || self.corpus_sha256 != corpus.digest()
            || self.custody_sha256 != custody_sha256
            || self.runner_revision != expected_runner
        {
            return false;
        }
        let expected = corpus
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>();
        let actual = self
            .case_results
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>();
        expected == actual
    }
}

fn validate_cases(cases: &[ExtractionCase]) -> Result<(), ExtractionError> {
    let mut unique = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for case in cases {
        if case.case_id.is_empty() || !unique.insert(case.case_id.as_str()) {
            return Err(ExtractionError::DuplicateCase);
        }
        if previous.is_some_and(|previous| previous > case.case_id.as_str()) {
            return Err(ExtractionError::UnsortedCases);
        }
        if !matches!(case.mode.as_str(), "ax" | "dom_full") || case.content_schema.is_empty() {
            return Err(ExtractionError::InvalidCase);
        }
        previous = Some(case.case_id.as_str());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_rejects_unsorted_and_duplicate_case_ids() {
        let corpus = ExtractionCorpus {
            schema: CORPUS_SCHEMA.into(),
            corpus_revision: "r1".into(),
            cases: vec![
                ExtractionCase {
                    case_id: "b".into(),
                    mode: "ax".into(),
                    content_schema: "x".into(),
                    expected_content: String::new(),
                    expected_truncated: false,
                    expected_refs_truncated: false,
                },
                ExtractionCase {
                    case_id: "a".into(),
                    mode: "ax".into(),
                    content_schema: "x".into(),
                    expected_content: String::new(),
                    expected_truncated: false,
                    expected_refs_truncated: false,
                },
            ],
        };
        assert_eq!(corpus.validate(), Err(ExtractionError::UnsortedCases));
    }
}
