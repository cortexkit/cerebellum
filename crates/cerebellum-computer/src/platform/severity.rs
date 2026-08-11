//! The computer plane's action-severity table.
//!
//! Severity is what a decision plane reads to judge how consequential an action
//! is. It is a function of three things: what the action does, how contained it
//! is, and whether a person is watching. The table is total over all eighteen
//! combinations, because a missing row is an action nobody can score, and a
//! score that cannot be produced is worse than a high one.
//!
//! THE TIER NUMBERS ARE DEFINED ELSEWHERE AND THE MAPPING IS DEFINED HERE. The
//! `ck-action-severity/v1` scale (1 observe through 5 actuate) is shared with
//! other modules, so this table names that schema rather than restating what a
//! tier means; a second definition is how two readers come to disagree about
//! tier 4 while both believe they comply. Which tier a computer action lands on
//! depends on containment distinctions that exist only in this plane, so the
//! mapping is authored here and pinned by digest.
//!
//! `credential` and `financial` are false in every row because this plane has no
//! field-level classifier: an application's controls carry no attribute saying a
//! text field holds a password. The artifact therefore declares
//! `field_classification: "unavailable"`, so a consumer reads those flags as
//! UNCLASSIFIED rather than as checked-and-absent. A table produced by a plane
//! that DOES classify would declare its method instead, and the same `false`
//! would then be a finding rather than a gap.

use std::collections::BTreeMap;

use cerebellum_core::journal::{
    EffectClass, IsolationClass, ObservabilityClass, SeverityInputs, SeverityRecord,
    ValidatedSeverityTaxonomy,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The frozen artifact, embedded so the running module and the pinned digest
/// describe the same bytes.
pub const COMPUTER_ACTION_SEVERITY_ARTIFACT: &[u8] =
    include_bytes!("../../resources/computer_action_severity-v1.json");

/// The digest of the artifact this build was compiled against.
pub const COMPUTER_ACTION_SEVERITY_SHA256: &str =
    "979078fb68eac399689064fc268b74492210c1845fb4c258949d95f64766e196";

/// The schema whose tier numbers this table is expressed in.
///
/// Named rather than restated. The scale is shared with other modules, and a
/// local redefinition of it would drift from the original without either copy
/// looking wrong.
pub const FLEET_SEVERITY_SCHEMA_ID: &str = "ck-action-severity/v1";

/// This plane's revision of the mapping.
pub const COMPUTER_ACTION_SEVERITY_REVISION: &str = "computer_action_severity-v1";

/// How the `credential` and `financial` fields in this table were established.
///
/// `unavailable` says no classifier ran, so the flags carry no finding. A table
/// whose producer can classify declares its method instead, and the identical
/// `false` then means checked-and-absent. Without the declaration those two are
/// indistinguishable to every consumer.
pub const FIELD_CLASSIFICATION_UNAVAILABLE: &str = "unavailable";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeverityArtifactError {
    Json(String),
    DigestMismatch {
        expected: String,
        computed: String,
    },
    WrongSchema(String),
    WrongRevision(String),
    /// The table does not say how its classification fields were established.
    ///
    /// Refused rather than assumed, because assuming either answer is wrong in a
    /// different direction: assuming a classifier ran reports unchecked fields
    /// as verified, and assuming none ran discards a real result.
    MissingFieldClassification,
    MalformedRow(String),
    UnknownEffectClass(String),
    UnknownIsolationClass(String),
    UnknownObservabilityClass(String),
    /// A tier outside the 1..=5 scale.
    TierOutOfRange(u64),
    /// The table is not total. Carries the count so the failure names the gap.
    Incomplete(usize),
    Taxonomy(String),
}

impl std::fmt::Display for SeverityArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(detail) => write!(formatter, "the severity artifact is not JSON: {detail}"),
            Self::DigestMismatch { expected, computed } => write!(
                formatter,
                "the severity artifact does not match its pin: expected {expected}, computed \
                 {computed}"
            ),
            Self::WrongSchema(found) => write!(
                formatter,
                "the severity artifact declares schema {found}, not {FLEET_SEVERITY_SCHEMA_ID}"
            ),
            Self::WrongRevision(found) => write!(
                formatter,
                "the severity artifact declares revision {found}, not \
                 {COMPUTER_ACTION_SEVERITY_REVISION}"
            ),
            Self::MissingFieldClassification => write!(
                formatter,
                "the severity artifact does not declare how its credential and financial fields \
                 were established"
            ),
            Self::MalformedRow(detail) => {
                write!(formatter, "a severity row is malformed: {detail}")
            }
            Self::UnknownEffectClass(found) => {
                write!(formatter, "unknown effect class {found}")
            }
            Self::UnknownIsolationClass(found) => {
                write!(formatter, "unknown isolation class {found}")
            }
            Self::UnknownObservabilityClass(found) => {
                write!(formatter, "unknown observability class {found}")
            }
            Self::TierOutOfRange(tier) => write!(
                formatter,
                "tier {tier} is outside the {FLEET_SEVERITY_SCHEMA_ID} scale of 1 to 5"
            ),
            Self::Incomplete(count) => write!(
                formatter,
                "the severity table has {count} rows and must have 18, one per combination"
            ),
            Self::Taxonomy(detail) => {
                write!(formatter, "the severity table was rejected: {detail}")
            }
        }
    }
}

/// The digest of the artifact as it exists in this build.
pub fn computed_severity_sha256() -> String {
    let digest = Sha256::digest(COMPUTER_ACTION_SEVERITY_ARTIFACT);
    digest.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Load the severity table, refusing anything that does not match its pin.
///
/// The digest is checked before the contents are interpreted. A table that
/// changed without its pin changing is one whose provenance is unknown, and
/// severity is exactly the input where a silently altered value would be
/// believed.
pub fn load_severity_taxonomy() -> Result<ValidatedSeverityTaxonomy, SeverityArtifactError> {
    let computed = computed_severity_sha256();
    if computed != COMPUTER_ACTION_SEVERITY_SHA256 {
        return Err(SeverityArtifactError::DigestMismatch {
            expected: COMPUTER_ACTION_SEVERITY_SHA256.to_string(),
            computed,
        });
    }
    parse_severity_taxonomy(COMPUTER_ACTION_SEVERITY_ARTIFACT)
}

/// Parse a severity table from bytes, without consulting the pin.
///
/// Separate from [`load_severity_taxonomy`] so the parsing rules can be tested
/// against constructed input. Nothing in production should call this with bytes
/// that did not come from the pinned artifact.
pub fn parse_severity_taxonomy(
    bytes: &[u8],
) -> Result<ValidatedSeverityTaxonomy, SeverityArtifactError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| SeverityArtifactError::Json(error.to_string()))?;

    let schema = value["schema_id"].as_str().unwrap_or_default();
    if schema != FLEET_SEVERITY_SCHEMA_ID {
        return Err(SeverityArtifactError::WrongSchema(schema.to_string()));
    }
    let revision = value["revision"].as_str().unwrap_or_default();
    if revision != COMPUTER_ACTION_SEVERITY_REVISION {
        return Err(SeverityArtifactError::WrongRevision(revision.to_string()));
    }
    match value["field_classification"].as_str() {
        Some(FIELD_CLASSIFICATION_UNAVAILABLE) => {}
        _ => return Err(SeverityArtifactError::MissingFieldClassification),
    }

    let rows = value["rows"]
        .as_array()
        .ok_or_else(|| SeverityArtifactError::MalformedRow("rows is not an array".to_string()))?;

    let mut table: BTreeMap<SeverityInputs, SeverityRecord> = BTreeMap::new();
    for row in rows {
        let effect_class = match row["effect_class"].as_str() {
            Some("read") => EffectClass::Read,
            Some("mutate") => EffectClass::Mutate,
            Some("authorize") => EffectClass::Authorize,
            other => {
                return Err(SeverityArtifactError::UnknownEffectClass(
                    other.unwrap_or("absent").to_string(),
                ))
            }
        };
        let isolation_class = match row["isolation_class"].as_str() {
            Some("resource_scoped") => IsolationClass::ResourceScoped,
            Some("owner_scoped") => IsolationClass::OwnerScoped,
            Some("uncontained") => IsolationClass::Uncontained,
            other => {
                return Err(SeverityArtifactError::UnknownIsolationClass(
                    other.unwrap_or("absent").to_string(),
                ))
            }
        };
        let observability_class = match row["observability_class"].as_str() {
            Some("human_observed") => ObservabilityClass::HumanObserved,
            Some("human_unobserved") => ObservabilityClass::HumanUnobserved,
            other => {
                return Err(SeverityArtifactError::UnknownObservabilityClass(
                    other.unwrap_or("absent").to_string(),
                ))
            }
        };
        let tier = row["tier"].as_u64().ok_or_else(|| {
            SeverityArtifactError::MalformedRow("a row has no integer tier".to_string())
        })?;
        if !(1..=5).contains(&tier) {
            return Err(SeverityArtifactError::TierOutOfRange(tier));
        }
        let credential = row["credential"].as_bool().ok_or_else(|| {
            SeverityArtifactError::MalformedRow("a row has no credential flag".to_string())
        })?;
        let financial = row["financial"].as_bool().ok_or_else(|| {
            SeverityArtifactError::MalformedRow("a row has no financial flag".to_string())
        })?;

        table.insert(
            SeverityInputs {
                effect_class,
                isolation_class,
                observability_class,
            },
            SeverityRecord {
                tier: tier as u8,
                credential,
                financial,
            },
        );
    }

    // Checked here as well as by the constructor so the failure names the gap
    // rather than reporting a generic rejection.
    if table.len() != 18 {
        return Err(SeverityArtifactError::Incomplete(table.len()));
    }

    ValidatedSeverityTaxonomy::new(COMPUTER_ACTION_SEVERITY_REVISION, table)
        .map_err(|error| SeverityArtifactError::Taxonomy(format!("{error:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(effect: EffectClass, isolation: IsolationClass, observed: bool) -> u8 {
        use cerebellum_core::journal::SeverityTaxonomy;
        load_severity_taxonomy()
            .expect("the pinned artifact loads")
            .resolve(SeverityInputs {
                effect_class: effect,
                isolation_class: isolation,
                observability_class: if observed {
                    ObservabilityClass::HumanObserved
                } else {
                    ObservabilityClass::HumanUnobserved
                },
            })
            .expect("the table is total")
            .tier
    }

    /// The pinned artifact loads and covers every combination.
    #[test]
    fn the_pinned_table_loads_and_is_total() {
        use cerebellum_core::journal::SeverityTaxonomy;
        let taxonomy = load_severity_taxonomy().expect("the pinned artifact loads");
        assert_eq!(taxonomy.table().len(), 18);
        assert_eq!(taxonomy.version(), COMPUTER_ACTION_SEVERITY_REVISION);
    }

    /// A more contained action earns a lower tier.
    ///
    /// Addressing a specific element is stronger than addressing a coordinate
    /// inside one application, which is stronger than addressing the screen.
    ///
    /// Asserted as exact tiers rather than as an ordering, because an ordering
    /// still holds when every value is wrong by the same amount.
    #[test]
    fn a_stronger_containment_rung_earns_a_lower_tier() {
        assert_eq!(
            tier(EffectClass::Mutate, IsolationClass::ResourceScoped, false),
            2
        );
        assert_eq!(
            tier(EffectClass::Mutate, IsolationClass::OwnerScoped, false),
            3
        );
        assert_eq!(
            tier(EffectClass::Mutate, IsolationClass::Uncontained, false),
            4
        );
    }

    /// Reading beyond the granted application costs a tier.
    ///
    /// A whole-display capture reads windows the grant never named, so it floors
    /// above a scoped read even though both only observe.
    #[test]
    fn an_uncontained_read_floors_above_a_scoped_one() {
        assert_eq!(
            tier(EffectClass::Read, IsolationClass::ResourceScoped, false),
            1
        );
        assert_eq!(
            tier(EffectClass::Read, IsolationClass::OwnerScoped, false),
            1
        );
        assert_eq!(
            tier(EffectClass::Read, IsolationClass::Uncontained, false),
            2
        );
    }

    /// A watching human discounts the reversible tiers and NOTHING above them.
    ///
    /// Asserted from both sides of the boundary, because the two halves have
    /// different reasons and a test covering one reads as covering both.
    ///
    /// The tiers describe EFFECTS. Tier 4 means intervention after the fact
    /// cannot undo what happened, and an audience changes whether something is
    /// noticed rather than whether it can be undone. Discounting there would
    /// give a durable effect the number that means reversible, so any consumer
    /// selecting on that number would admit it.
    #[test]
    fn observation_discounts_the_reversible_tiers_but_never_the_durable_ones() {
        // Below the boundary: the discount applies.
        assert_eq!(
            tier(EffectClass::Mutate, IsolationClass::ResourceScoped, true),
            1
        );
        assert_eq!(
            tier(EffectClass::Mutate, IsolationClass::OwnerScoped, true),
            2
        );
        assert_eq!(
            tier(EffectClass::Read, IsolationClass::Uncontained, true),
            1
        );

        // At and above it: watching changes nothing.
        assert_eq!(
            tier(EffectClass::Mutate, IsolationClass::Uncontained, true),
            tier(EffectClass::Mutate, IsolationClass::Uncontained, false),
            "a durable effect was discounted because someone was watching"
        );
        assert_eq!(
            tier(EffectClass::Mutate, IsolationClass::Uncontained, true),
            4
        );
        assert_eq!(
            tier(EffectClass::Authorize, IsolationClass::Uncontained, true),
            5
        );
        assert_eq!(
            tier(EffectClass::Authorize, IsolationClass::ResourceScoped, true),
            5
        );
    }

    /// No tier falls below the vocabulary's floor.
    #[test]
    fn every_tier_is_inside_the_fleet_vocabulary() {
        let taxonomy = load_severity_taxonomy().expect("the pinned artifact loads");
        for (inputs, record) in taxonomy.table() {
            assert!(
                (1..=5).contains(&record.tier),
                "{inputs:?} resolves to tier {} outside 1..=5",
                record.tier
            );
        }
    }

    /// Every classification field is unset, and the table says why.
    ///
    /// The declaration is the point rather than the values: a consumer reading
    /// `credential: false` cannot otherwise tell whether a classifier checked
    /// and found nothing or whether none ran. This plane has none, and saying so
    /// is what stops the absence being read as a finding.
    #[test]
    fn classification_fields_are_declared_unavailable_rather_than_verified_absent() {
        let value: Value =
            serde_json::from_slice(COMPUTER_ACTION_SEVERITY_ARTIFACT).expect("the artifact parses");
        assert_eq!(
            value["field_classification"].as_str(),
            Some(FIELD_CLASSIFICATION_UNAVAILABLE)
        );

        let taxonomy = load_severity_taxonomy().expect("the pinned artifact loads");
        for (inputs, record) in taxonomy.table() {
            assert!(
                !record.credential && !record.financial,
                "{inputs:?} claims a classification this plane cannot establish"
            );
        }
    }

    /// A table without the declaration is refused rather than assumed either way.
    #[test]
    fn a_table_that_does_not_say_how_it_classified_is_refused() {
        let mut value: Value =
            serde_json::from_slice(COMPUTER_ACTION_SEVERITY_ARTIFACT).expect("the artifact parses");
        value["field_classification"] = Value::Null;
        let bytes = serde_json::to_vec(&value).expect("re-encodes");
        assert_eq!(
            parse_severity_taxonomy(&bytes),
            Err(SeverityArtifactError::MissingFieldClassification)
        );
    }

    /// An incomplete table is refused, and the refusal names the gap.
    ///
    /// A missing row is an action nobody can score. Refusing the whole table is
    /// the fail-closed answer: the alternative is a lookup that returns nothing
    /// for one combination, which a caller meets only when that combination
    /// occurs.
    #[test]
    fn an_incomplete_table_is_refused() {
        let mut value: Value =
            serde_json::from_slice(COMPUTER_ACTION_SEVERITY_ARTIFACT).expect("the artifact parses");
        let rows = value["rows"].as_array_mut().expect("rows");
        rows.pop();
        let bytes = serde_json::to_vec(&value).expect("re-encodes");
        assert_eq!(
            parse_severity_taxonomy(&bytes),
            Err(SeverityArtifactError::Incomplete(17))
        );
    }

    /// A tier outside the fleet vocabulary is refused.
    #[test]
    fn a_tier_outside_the_vocabulary_is_refused() {
        let mut value: Value =
            serde_json::from_slice(COMPUTER_ACTION_SEVERITY_ARTIFACT).expect("the artifact parses");
        value["rows"][0]["tier"] = Value::from(9);
        let bytes = serde_json::to_vec(&value).expect("re-encodes");
        assert_eq!(
            parse_severity_taxonomy(&bytes),
            Err(SeverityArtifactError::TierOutOfRange(9))
        );
    }

    /// The artifact on disk matches the digest this build was compiled against.
    ///
    /// The failure names the digest to write and where it goes, since the value
    /// is otherwise only obtainable by computing it separately.
    #[test]
    fn the_artifact_matches_its_pin() {
        let computed = computed_severity_sha256();
        assert_eq!(
            computed, COMPUTER_ACTION_SEVERITY_SHA256,
            "the severity artifact changed. If the change was deliberate, set \
             COMPUTER_ACTION_SEVERITY_SHA256 in crates/cerebellum-computer/src/platform/severity.rs \
             to {computed}"
        );
    }
}
