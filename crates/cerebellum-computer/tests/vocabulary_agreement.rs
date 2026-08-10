//! The frozen vocabulary and the code that decides the same things must agree.
//!
//! Several fields in `computer_action_vocabulary-v1.json` state a rule that a
//! hand-written function also states. Validation checks those fields are
//! PRESENT and never reads them, so the two statements can drift apart with
//! nothing failing: the file is the contract and the function is what runs.
//!
//! This compares them. It is the whole value of freezing a vocabulary — a
//! digest over a file nobody consults pins a document rather than a behaviour.

use std::collections::BTreeSet;

use cerebellum_computer::grounding::{GroundingPath, GroundingPolicy, GroundingRequirement};
use serde_json::Value;

const VOCABULARY: &str = include_str!("../resources/computer_action_vocabulary-v1.json");

/// The element-resolution paths a row authorizes.
///
/// The file's vocabulary is broader than the code's: it also names
/// `process_grant`, `coordinate`, `target_windows` and `display`, which say how
/// a target is addressed when it is NOT an element. Those are dropped here
/// rather than treated as unknown, because a row naming only those is a row
/// with nothing to ground.
fn element_paths(row: &Value) -> BTreeSet<GroundingPath> {
    row["eligible_grounding_paths"]
        .as_array()
        .expect("every row lists its grounding paths")
        .iter()
        .filter_map(|path| match path.as_str() {
            Some("accessibility_element") => Some(GroundingPath::AccessibilityElement),
            Some("pixel") => Some(GroundingPath::Pixel),
            Some("set_of_marks") => Some(GroundingPath::SetOfMarks),
            _ => None,
        })
        .collect()
}

/// The one capability where the file and the code deliberately disagree today.
///
/// The frozen row authorizes `accessibility_element` for `computer.drag` and
/// the code grounds it on nothing. The row is internally coherent — grounding
/// says how a target is RESOLVED and `semantic_path: none` says how it is
/// ACTED ON, so a drag may start from an element and still actuate
/// synthetically — and the code collapses the two, which makes every drag
/// coordinate-addressed and therefore maximally severe.
///
/// Recorded rather than resolved because drag is the only durably mutating
/// action, is gated on explicit review, and has no dispatch path at all yet.
/// Picking a side quietly would settle a gated question by editing a test.
///
/// WHOEVER IMPLEMENTS DRAG RESOLVES THIS FIRST: either the code gains element
/// grounding for it, or the row drops the path. Deleting this exception without
/// doing one of those puts the two statements back out of agreement silently.
const KNOWN_DISAGREEMENT: &str = "computer.drag";

/// Every capability grounds the way the frozen vocabulary says it does.
#[test]
fn the_code_grounds_each_capability_the_way_the_vocabulary_says() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let rows = vocabulary["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 8, "the vocabulary is frozen at eight rows");

    let mut disagreements = Vec::new();
    for row in rows {
        let capability = row["capability_id"].as_str().expect("a capability id");
        let authorized = element_paths(row);
        let implemented = match GroundingPolicy::for_capability(capability) {
            GroundingRequirement::Grounded(policy) => policy.eligible_paths,
            GroundingRequirement::NotGrounded => BTreeSet::new(),
            GroundingRequirement::UnknownCapability => {
                panic!("{capability} is in the frozen vocabulary and the code does not serve it")
            }
        };

        if capability == KNOWN_DISAGREEMENT {
            // Asserted rather than skipped, so the exception stops applying the
            // moment the disagreement is resolved rather than lingering as a
            // permanent hole in the check.
            assert_ne!(
                authorized, implemented,
                "{capability} now agrees; remove it from KNOWN_DISAGREEMENT"
            );
            continue;
        }
        if authorized != implemented {
            disagreements.push(format!(
                "{capability}: the vocabulary authorizes {authorized:?}, the code resolves \
                 {implemented:?}"
            ));
        }
    }

    assert!(
        disagreements.is_empty(),
        "the frozen vocabulary and the grounding code disagree:\n  {}",
        disagreements.join("\n  ")
    );
}

/// Every capability the vocabulary names is one the code serves.
///
/// The other direction of the same question: the test above compares HOW each
/// capability grounds, and this one catches a row the code has never heard of,
/// which would otherwise surface only when a caller asked for it.
#[test]
fn the_code_serves_every_capability_the_vocabulary_names() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    for row in vocabulary["rows"].as_array().expect("rows") {
        let capability = row["capability_id"].as_str().expect("a capability id");
        assert!(
            !matches!(
                GroundingPolicy::for_capability(capability),
                GroundingRequirement::UnknownCapability
            ),
            "{capability} is frozen in the vocabulary and unknown to the code"
        );
    }
}
