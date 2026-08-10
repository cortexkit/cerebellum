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

use cerebellum_computer::{
    audit::{AuditCapabilityGate, ComputerCapability},
    dispatch::FrozenDispatchRow,
    grounding::{
        ContainmentRung, GroundingPath, GroundingPolicy, GroundingRequirement,
        GroundingResolutionPath,
    },
    platform::{
        CapabilityAdvertisementContext, ImmutableReleaseInputs, MacOs26PlatformDriver,
        PermissionLivenessReport, PermissionService,
    },
};
use serde_json::Value;

const VOCABULARY: &str = include_str!("../resources/computer_action_vocabulary-v1.json");

/// These frozen fields have no per-capability code counterpart to compare.
///
/// `attendance_requirement` uses a different runtime vocabulary without a
/// bridge, and `review_requirement` is only represented by broad release gates.
/// The freeze therefore pins document values for them until code exposes the
/// same per-capability rules.
const _FROZEN_FIELDS_WITHOUT_CODE_COUNTERPART: [&str; 2] =
    ["attendance_requirement", "review_requirement"];

/// The element-resolution paths a row authorizes.
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

/// Whether the frozen row permits a target to be addressed directly by coordinate.
fn coordinate_addressable(row: &Value) -> bool {
    row["eligible_grounding_paths"]
        .as_array()
        .expect("every row lists its grounding paths")
        .iter()
        .any(|path| path.as_str() == Some("coordinate"))
}

/// The synthetic delivery paths a row authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SyntheticPath {
    PerPid,
    Global,
}

fn synthetic_paths(row: &Value) -> BTreeSet<SyntheticPath> {
    row["synthetic_paths"]
        .as_array()
        .expect("every row lists its synthetic paths")
        .iter()
        .map(|path| match path.as_str() {
            Some("per_pid") => SyntheticPath::PerPid,
            Some("global") => SyntheticPath::Global,
            Some(path) => panic!("{path} is not a frozen synthetic path"),
            None => panic!("every synthetic path is a string"),
        })
        .collect()
}

fn implemented_synthetic_paths(capability: &str) -> BTreeSet<SyntheticPath> {
    let row = FrozenDispatchRow::for_capability(capability)
        .expect("every vocabulary capability has a dispatch row");
    let mut paths = BTreeSet::new();
    if row.synthetic_background_supported {
        paths.insert(SyntheticPath::PerPid);
    }
    if row.synthetic_observed_supported {
        paths.insert(SyntheticPath::Global);
    }
    paths
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditObligation {
    None,
    Required,
}

fn frozen_audit_obligation(row: &Value) -> AuditObligation {
    match row["audit_obligation"].as_str() {
        Some("none") => AuditObligation::None,
        Some("required_before_dispatch") | Some("required_before_result") => {
            AuditObligation::Required
        }
        Some(obligation) => panic!("{obligation} is not a frozen audit obligation"),
        None => panic!("every audit obligation is a string"),
    }
}

fn code_requires_wait_audit() -> AuditObligation {
    let gate = AuditCapabilityGate {
        journal_available: true,
        severity_available: true,
        custody_available: false,
        clock_available: false,
        grant_authority_available: false,
        redactor_available: false,
    };
    if gate.advertised(ComputerCapability::Wait) {
        AuditObligation::Required
    } else {
        AuditObligation::None
    }
}

fn frozen_permission_services(row: &Value) -> Vec<PermissionService> {
    row["required_permission_services"]
        .as_array()
        .expect("every row lists its permission services")
        .iter()
        .map(|service| match service.as_str() {
            Some("accessibility") => PermissionService::Accessibility,
            Some("post_event") => PermissionService::PostEvent,
            Some("input_monitoring") => PermissionService::InputMonitoring,
            Some("screen_recording") => PermissionService::ScreenRecording,
            Some(service) => panic!("{service} is not a frozen permission service"),
            None => panic!("every permission service is a string"),
        })
        .collect()
}

fn code_permission_services(capability: &str) -> Vec<PermissionService> {
    let driver = MacOs26PlatformDriver::default();
    let context = CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs::default(),
        permissions: PermissionLivenessReport::default(),
        startup: driver.startup_probe().clone(),
    };
    driver
        .declarations(&context)
        .into_iter()
        .find(|declaration| declaration.capability_id == capability)
        .expect("every vocabulary capability has a platform declaration")
        .required_permissions
}

/// Every capability resolves elements, permits coordinates, and authorizes
/// pixel fallback exactly as the frozen vocabulary says. This protects the
/// distinction between element evidence and target-addressing modes, which the
/// schema validator preserves without interpreting.
#[test]
fn grounding_rules_agree_with_the_frozen_vocabulary() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let rows = vocabulary["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 8, "the vocabulary is frozen at eight rows");

    let mut disagreements = Vec::new();
    for row in rows {
        let capability = row["capability_id"].as_str().expect("a capability id");
        let authorized_elements = element_paths(row);
        let authorized_coordinate = coordinate_addressable(row);
        let authorized_pixel_fallback = row["pixel_fallback_eligible"]
            .as_bool()
            .expect("every row states pixel fallback eligibility");
        let (implemented_elements, implemented_pixel_fallback) =
            match GroundingPolicy::for_capability(capability) {
                GroundingRequirement::Grounded(policy)
                | GroundingRequirement::ElementOrCoordinateAddressed(policy) => {
                    (policy.eligible_paths, policy.pixel_fallback_eligible)
                }
                GroundingRequirement::NotGrounded => (BTreeSet::new(), false),
                GroundingRequirement::UnknownCapability => {
                    panic!(
                        "{capability} is in the frozen vocabulary and the code does not serve it"
                    )
                }
            };
        let implemented_coordinate =
            GroundingPolicy::coordinate_addressable_for_capability(capability)
                .expect("every vocabulary capability has an addressing rule");

        if authorized_elements != implemented_elements
            || authorized_coordinate != implemented_coordinate
            || authorized_pixel_fallback != implemented_pixel_fallback
        {
            disagreements.push(format!(
                "{capability}: vocabulary elements {authorized_elements:?}, coordinate \
                 {authorized_coordinate}, pixel fallback {authorized_pixel_fallback}; code elements \
                 {implemented_elements:?}, coordinate {implemented_coordinate}, pixel fallback \
                 {implemented_pixel_fallback}"
            ));
        }
    }

    assert!(
        disagreements.is_empty(),
        "the frozen vocabulary and grounding code disagree:\n  {}",
        disagreements.join("\n  ")
    );
}

/// A drag records whether it used an element or a coordinate, because only the
/// element path can be revalidated by what moved while coordinate addressing is
/// necessarily recorded at the weakest containment rung.
#[test]
fn drag_preserves_the_actual_grounding_path_for_containment() {
    let requirement = GroundingPolicy::for_capability("computer.drag");
    let element_policy = GroundingPolicy {
        eligible_paths: [GroundingPath::AccessibilityElement].into_iter().collect(),
        pixel_fallback_eligible: false,
        ..GroundingPolicy::default()
    };

    assert_eq!(
        requirement.resolution_path(true),
        Some(GroundingResolutionPath::Element(element_policy))
    );
    assert_eq!(
        requirement.resolution_path(false),
        Some(GroundingResolutionPath::CoordinateAddressed {
            containment_rung: ContainmentRung::GlobalNone,
        })
    );
}

/// The frozen synthetic path lists match the dispatch row booleans, preventing
/// a capability from advertising per-PID or global delivery the dispatcher will
/// not perform.
#[test]
fn synthetic_paths_agree_with_the_frozen_vocabulary() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    for row in vocabulary["rows"].as_array().expect("rows") {
        let capability = row["capability_id"].as_str().expect("a capability id");
        assert_eq!(
            implemented_synthetic_paths(capability),
            synthetic_paths(row),
            "{capability} has different frozen and implemented synthetic paths"
        );
    }
}

/// The wait row's audit exception remains explicit: the frozen vocabulary says
/// it has no audit obligation, while the fail-closed advertisement gate requires
/// a durable journal obligation. This must fail when the two statements agree.
#[test]
fn known_wait_audit_obligation_disagreement_remains_asserted() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let wait = vocabulary["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["capability_id"].as_str() == Some("computer.wait"))
        .expect("the frozen vocabulary contains wait");
    let frozen = frozen_audit_obligation(wait);
    let implemented = code_requires_wait_audit();

    assert_eq!(frozen, AuditObligation::None);
    assert_ne!(
        frozen, implemented,
        "wait audit obligations now agree; remove this asserted exception"
    );
    assert_eq!(implemented, AuditObligation::Required);
}

/// Platform declarations require exactly the permission services each frozen
/// row lists. Deriving them from the vocabulary is what keeps a missing service
/// (for example input monitoring) from being something the driver never probes
/// for and never reports as absent.
#[test]
fn permission_services_agree_with_the_frozen_vocabulary() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    for row in vocabulary["rows"].as_array().expect("rows") {
        let capability = row["capability_id"].as_str().expect("a capability id");
        assert_eq!(
            code_permission_services(capability),
            frozen_permission_services(row),
            "{capability} has different frozen and declared permission services"
        );
    }
}

/// Every capability the vocabulary names is one the code serves, so a frozen
/// row cannot silently describe an action that grounding refuses as unknown.
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
