//! Closed, plane-neutral severity taxonomy policy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Normalized effect domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Read,
    Mutate,
    Authorize,
}

/// Normalized isolation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationClass {
    ResourceScoped,
    OwnerScoped,
    Uncontained,
}

/// Normalized observation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityClass {
    HumanObserved,
    HumanUnobserved,
}

/// The complete normalized taxonomy input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityInputs {
    pub effect_class: EffectClass,
    pub isolation_class: IsolationClass,
    pub observability_class: ObservabilityClass,
}

/// The taxonomy output preserved by plane adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityRecord {
    pub tier: u8,
    pub credential: bool,
    pub financial: bool,
}

/// A validated total lookup table.
pub trait SeverityTaxonomy {
    fn version(&self) -> &str;
    fn digest(&self) -> &str;
    fn resolve(&self, inputs: SeverityInputs) -> Option<SeverityRecord>;
}

impl SeverityTaxonomy for () {
    fn version(&self) -> &str {
        "unavailable"
    }

    fn digest(&self) -> &str {
        "unavailable"
    }

    fn resolve(&self, _inputs: SeverityInputs) -> Option<SeverityRecord> {
        None
    }
}

impl<T: SeverityTaxonomy + ?Sized> SeverityTaxonomy for Box<T> {
    fn version(&self) -> &str {
        (**self).version()
    }

    fn digest(&self) -> &str {
        (**self).digest()
    }

    fn resolve(&self, inputs: SeverityInputs) -> Option<SeverityRecord> {
        (**self).resolve(inputs)
    }
}

/// Failure while validating a taxonomy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaxonomyError {
    EmptyVersion,
    MissingInput,
    DuplicateInput,
    InvalidDigest,
}

/// An immutable, versioned total taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSeverityTaxonomy {
    version: String,
    digest: String,
    table: BTreeMap<SeverityInputs, SeverityRecord>,
}

impl ValidatedSeverityTaxonomy {
    /// Build a taxonomy from the complete set of closed input tuples.
    pub fn new(
        version: impl Into<String>,
        entries: impl IntoIterator<Item = (SeverityInputs, SeverityRecord)>,
    ) -> Result<Self, TaxonomyError> {
        let version = version.into();
        if version.trim().is_empty() {
            return Err(TaxonomyError::EmptyVersion);
        }
        let mut table = BTreeMap::new();
        for (inputs, output) in entries {
            if table.insert(inputs, output).is_some() {
                return Err(TaxonomyError::DuplicateInput);
            }
        }
        if table.len() != 18 {
            return Err(TaxonomyError::MissingInput);
        }
        let digest = taxonomy_digest(&version, &table);
        Ok(Self {
            version,
            digest,
            table,
        })
    }

    pub fn table(&self) -> &BTreeMap<SeverityInputs, SeverityRecord> {
        &self.table
    }
}

impl SeverityTaxonomy for ValidatedSeverityTaxonomy {
    fn version(&self) -> &str {
        &self.version
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    fn resolve(&self, inputs: SeverityInputs) -> Option<SeverityRecord> {
        self.table.get(&inputs).copied()
    }
}

/// Compute the lowercase SHA-256 digest over the canonical ordered table.
pub fn taxonomy_digest(version: &str, table: &BTreeMap<SeverityInputs, SeverityRecord>) -> String {
    #[derive(Serialize)]
    struct CanonicalInput {
        effect_class: EffectClass,
        isolation_class: IsolationClass,
        observability_class: ObservabilityClass,
    }

    #[derive(Serialize)]
    struct CanonicalOutput {
        credential: bool,
        financial: bool,
        tier: u8,
    }

    #[derive(Serialize)]
    struct CanonicalRow {
        inputs: CanonicalInput,
        output: CanonicalOutput,
    }

    #[derive(Serialize)]
    struct CanonicalTaxonomy {
        effect_class: [&'static str; 3],
        isolation_class: [&'static str; 3],
        observability_class: [&'static str; 2],
        table: Vec<CanonicalRow>,
        version: String,
    }

    let table = table
        .iter()
        .map(|(inputs, output)| CanonicalRow {
            inputs: CanonicalInput {
                effect_class: inputs.effect_class,
                isolation_class: inputs.isolation_class,
                observability_class: inputs.observability_class,
            },
            output: CanonicalOutput {
                credential: output.credential,
                financial: output.financial,
                tier: output.tier,
            },
        })
        .collect();
    let value = CanonicalTaxonomy {
        effect_class: ["read", "mutate", "authorize"],
        isolation_class: ["resource_scoped", "owner_scoped", "uncontained"],
        observability_class: ["human_observed", "human_unobserved"],
        table,
        version: version.to_string(),
    };
    let bytes = serde_json::to_vec(&value).expect("taxonomy shape serializes");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
