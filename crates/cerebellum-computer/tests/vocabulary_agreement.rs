//! The frozen vocabulary and the code that decides the same things must agree.
//!
//! Several fields in `computer_action_vocabulary-v7.json` state a rule that a
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
        capability_declarations, vocabulary::required_permission_services,
        CapabilityAdvertisementContext, DispatchMode, ImmutableReleaseInputs, PermissionLiveness,
        PermissionLivenessReport, PermissionProbeResult, PermissionService, StartupCapabilityProbe,
        SupportState, VocabularyDigestInputs, COMPUTER_ACTION_VOCABULARY_SHA256,
    },
};
use serde_json::Value;

const VOCABULARY: &str = include_str!("../resources/computer_action_vocabulary-v7.json");

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

/// When a row's audit record must exist relative to the action.
///
/// The two required forms are DIFFERENT GUARANTEES and are kept apart. Before
/// dispatch means the intent is recorded before the machine changes, so an
/// action that crashes mid-flight still left a statement that it was about to
/// happen. Before result means the observation is accounted for before anyone
/// is told about it, which is weaker: nothing was going to change anyway.
///
/// Collapsing them would let a row be implemented with the wrong one and still
/// report agreement — and the wrong one for an actuating row is the weaker one,
/// which is the direction a mistake naturally takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditObligation {
    None,
    RequiredBeforeDispatch,
    RequiredBeforeResult,
}

fn frozen_audit_obligation(row: &Value) -> AuditObligation {
    match row["audit_obligation"].as_str() {
        Some("none") => AuditObligation::None,
        Some("required_before_dispatch") => AuditObligation::RequiredBeforeDispatch,
        Some("required_before_result") => AuditObligation::RequiredBeforeResult,
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
        // The gate answers whether an audit is required at all, and cannot say
        // WHEN. Waiting changes nothing, so before-result is the only form its
        // obligation could take; a row that actuates would need the ordering
        // read from its dispatch path rather than from this gate.
        AuditObligation::RequiredBeforeResult
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
    required_permission_services(capability)
        .expect("every vocabulary capability has a platform declaration")
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
    assert_eq!(implemented, AuditObligation::RequiredBeforeResult);
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
/// capability row cannot silently describe a dispatch path that grounding refuses
/// as unknown. Per-action admission is fenced separately against the action catalog.
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

/// The two required audit obligations stay distinct from one another.
///
/// Six rows require a record BEFORE DISPATCH and one requires it before the
/// RESULT, and those are different guarantees: the first says the intent was
/// written down before the machine changed, so an action that dies mid-flight
/// still left a statement it was about to happen; the second only says an
/// observation was accounted for before anyone was told, which costs nothing
/// because nothing was going to change.
///
/// Asserted because a reader who sees two names for "an audit is required" has
/// every reason to simplify them into one, and the collapse is invisible: every
/// row still reports agreement, and the first implementation of an actuating
/// row would be free to take the weaker ordering.
#[test]
fn the_two_required_audit_obligations_are_not_interchangeable() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");

    let mut before_dispatch = 0;
    let mut before_result = 0;
    for row in vocabulary["rows"].as_array().expect("rows") {
        match frozen_audit_obligation(row) {
            AuditObligation::RequiredBeforeDispatch => before_dispatch += 1,
            AuditObligation::RequiredBeforeResult => before_result += 1,
            AuditObligation::None => {}
        }
    }

    assert_ne!(
        AuditObligation::RequiredBeforeDispatch,
        AuditObligation::RequiredBeforeResult,
        "the two required obligations compare equal, so no row can be checked \
         against the ordering it was frozen with"
    );

    // Absolute counts rather than "at least one of each": a mapping that sent
    // every row to the same variant would satisfy a presence check.
    assert_eq!(
        before_dispatch, 6,
        "six actuating rows must record intent before the machine changes"
    );
    assert_eq!(
        before_result, 1,
        "only the observing row may account for its record after the fact"
    );
}

/// computer.scroll declares a semantic path that nothing implements.
///
/// The frozen row says `semantic_path: ax_scroll_position`, and `AxAction` has
/// eight members with no scroll among them. So scroll can be GROUNDED on an
/// accessibility element but never DISPATCHED semantically: it always goes out
/// as synthetic input and can never claim the strongest containment rung.
///
/// Asserted rather than fixed, and asserted rather than left silent. The
/// vocabulary is a published artifact, so a caller reading that column would
/// conclude scroll can be actuated semantically -- and the honest place to
/// correct that is here, where the divergence is stated and the reason is next
/// to it.
///
/// WHY NOT JUST ADD THE ACTION. Real applications do advertise
/// AXScrollUpByPage and friends, so the member could exist. Two arguments
/// against, and neither is settled by wanting the better containment rung:
/// every member added to a closed action vocabulary widens what a caller may
/// ask any application to perform, and a page-scroll moves the viewport by an
/// amount the APPLICATION chooses, so the post-condition cannot be stated the
/// way a press's can. Deciding that is a vocabulary revision with a review
/// behind it, not a patch.
///
/// If a future revision adds scroll to AxAction, this test fails and should be
/// deleted rather than adjusted -- its whole purpose is to mark a gap that is
/// currently deliberate.
#[test]
fn scroll_declares_a_semantic_path_that_no_action_implements() {
    let vocabulary: serde_json::Value = serde_json::from_str(include_str!(
        "../resources/computer_action_vocabulary-v7.json"
    ))
    .expect("the frozen vocabulary parses");
    let scroll = vocabulary["rows"]
        .as_array()
        .expect("rows is an array")
        .iter()
        .find(|row| row["capability_id"] == "computer.scroll")
        .expect("computer.scroll is a frozen row");
    assert_eq!(
        scroll["semantic_path"], "ax_scroll_position",
        "this test exists because the row CLAIMS a semantic path; if that claim \
         changed, the divergence it documents is gone"
    );

    // The claim's counterpart. Named as literals rather than read from the enum,
    // so removing a member cannot quietly satisfy this by shrinking the set it
    // is compared against.
    let implemented = [
        "AXPress",
        "AXIncrement",
        "AXDecrement",
        "AXConfirm",
        "AXCancel",
        "AXShowMenu",
        "AXShowAlternateUI",
        "AXShowDefaultUI",
    ];
    assert!(
        !implemented.iter().any(|name| name.contains("Scroll")),
        "an AxAction now implements scrolling, so the declared semantic path is \
         no longer a gap: delete this test rather than adjusting it"
    );
}

/// Background support is claimed per synthetic event class, not per platform.
///
/// Measured on macOS 26 against a native application with the target
/// backgrounded and focus sampled throughout: a keystroke posted to the pid
/// lands, and a drag posted to the same pid has no effect even with the target
/// frontmost, while the SAME constructed events posted globally do select. The
/// events are right; the per-process path does not carry pointer events.
///
/// So a pointer row must not claim background support. It is not broken -- it is
/// deliverable through the global path, which seizes the shared cursor and is
/// the authority this module calls observed mode, deliberately unbuilt. Claiming
/// Supported would offer a caller a background capability that cannot deliver.
///
/// Asserted because the claim is invisible from the code that makes it: the
/// field is a constant expression, and every test that reads a declaration
/// would pass whichever value it held.
#[test]
fn only_keyboard_rows_claim_background_synthetic_support() {
    // Release inputs and permissions are irrelevant here: the claim under test
    // is a property of the ROW, and gating it behind a bound context would make
    // the test fail for reasons that have nothing to do with event classes.
    let context = CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs::default(),
        permissions: PermissionLivenessReport::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let declarations = capability_declarations(&context, true);

    for declaration in &declarations {
        let id = declaration.capability_id.as_str();
        let pointer = matches!(
            id,
            "computer.click" | "computer.move" | "computer.scroll" | "computer.drag"
        );
        let keyboard = matches!(id, "computer.type" | "computer.keys");
        if pointer {
            assert_eq!(
                declaration.synthetic_background,
                SupportState::Unsupported,
                "{id} claims background synthetic support, but per-process delivery does not \
                 carry pointer events"
            );
        } else if keyboard {
            assert_eq!(
                declaration.synthetic_background,
                SupportState::Supported,
                "{id} is keyboard-delivered and was measured to land in a backgrounded target"
            );
        }
    }

    // Both arms must have had something to check. A rename that emptied either
    // set would leave every assertion above unexecuted and the test green.
    let pointer_rows = declarations
        .iter()
        .filter(|d| {
            matches!(
                d.capability_id.as_str(),
                "computer.click" | "computer.move" | "computer.scroll" | "computer.drag"
            )
        })
        .count();
    let keyboard_rows = declarations
        .iter()
        .filter(|d| matches!(d.capability_id.as_str(), "computer.type" | "computer.keys"))
        .count();
    assert_eq!(pointer_rows, 4, "the pointer rows are not all present");
    assert_eq!(keyboard_rows, 2, "the keyboard rows are not all present");
}

/// A row claims semantic support only where an AxAction implements its path.
///
/// The frozen vocabulary names three semantic paths: click -> ax_press,
/// type -> ax_value, scroll -> ax_scroll_position. Only the first exists.
/// AxAction has eight members and none of them sets a value or scrolls, and
/// dispatch has no semantic route for either capability, so those two rows
/// were claiming a delivery path that cannot be taken.
///
/// The declaration used to mirror the artifact -- Supported wherever the row
/// named anything other than none -- which made it restate what the row WANTS
/// rather than what the driver can do. That is the same shape as a frozen
/// column nothing verifies: the claim and its subject never meet.
///
/// The implemented set is a literal here rather than read from AxAction,
/// because deriving it from the enum would let a member's removal satisfy this
/// test by shrinking what it compares against.
#[test]
fn semantic_support_is_claimed_only_where_an_action_implements_it() {
    const IMPLEMENTED_SEMANTIC_PATHS: [&str; 1] = ["ax_press"];

    let vocabulary: serde_json::Value = serde_json::from_str(include_str!(
        "../resources/computer_action_vocabulary-v7.json"
    ))
    .expect("the frozen vocabulary parses");
    let rows = vocabulary["rows"].as_array().expect("rows is an array");

    let context = CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs::default(),
        permissions: PermissionLivenessReport::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let declarations = capability_declarations(&context, true);

    let mut claimed = 0;
    for declaration in &declarations {
        let row = rows
            .iter()
            .find(|row| row["capability_id"] == declaration.capability_id.as_str())
            .expect("every declaration has a frozen row");
        let declared_path = row["semantic_path"].as_str().unwrap_or("none");
        let implemented = IMPLEMENTED_SEMANTIC_PATHS.contains(&declared_path);
        if implemented {
            claimed += 1;
        }
        assert_eq!(
            declaration.semantic_path == SupportState::Supported,
            implemented,
            "{} declares semantic path {declared_path:?}, which is {}implemented, but claims {:?}",
            declaration.capability_id,
            if implemented { "" } else { "NOT " },
            declaration.semantic_path
        );
    }

    // At least one row must genuinely claim it, or the assertion above is
    // satisfied by everything being Unsupported and proves nothing.
    assert_eq!(
        claimed, 1,
        "exactly one row should claim an implemented semantic path"
    );
}

/// Every release input bound and every permission live.
///
/// Named because two tests need it and because the reason it exists is easy to
/// lose: a default context refuses almost everything, so a test built on one
/// cannot distinguish its own subject from the refusal that was already there.
fn fully_bound_context() -> CapabilityAdvertisementContext {
    let inputs = ImmutableReleaseInputs {
        attendance_contract_owner: Some("fixture-owner".to_string()),
        attendance_contract_revision: Some("fixture-attendance-v1".to_string()),
        input_review_revision: Some("fixture-input-review-v1".to_string()),
        capture_review_revision: Some("fixture-capture-review-v1".to_string()),
        semantic_actuation_review_revision: Some("fixture-semantic-review-v1".to_string()),
        release_signing_topology_revision: Some("fixture-topology-v1".to_string()),
        vocabulary_digests: VocabularyDigestInputs {
            manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
            source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
            computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
        },
    };
    let permissions = PermissionLivenessReport::from_results(
        [
            PermissionService::Accessibility,
            PermissionService::InputMonitoring,
            PermissionService::ScreenRecording,
            PermissionService::PostEvent,
        ]
        .into_iter()
        .map(|service| PermissionProbeResult {
            service,
            liveness: PermissionLiveness::Live,
            responsible_process: String::new(),
            off_main: true,
        })
        .collect::<Vec<_>>(),
    );
    CapabilityAdvertisementContext {
        startup: StartupCapabilityProbe {
            permissions: permissions.clone(),
            ..StartupCapabilityProbe::default()
        },
        inputs,
        permissions,
    }
}

/// An actuating row is advertised only if something can deliver it.
///
/// Every other gate answers whether we are ALLOWED to serve a row. None asks
/// whether anything can carry it, and those came apart when the per-process
/// path turned out not to deliver pointer events: scroll, move and drag have no
/// semantic action, no working background path, and an observed path whose
/// driver refuses because global posting was never approved. Binding the input
/// review key would have advertised three capabilities that cannot deliver.
///
/// The two observing rows declare no delivery paths in the frozen vocabulary --
/// they read rather than actuate -- so the requirement does not apply to them,
/// and this asserts that exemption rather than leaving it implied.
#[test]
fn an_actuating_row_is_advertised_only_with_a_working_delivery_path() {
    // EVERY release input bound and every permission live, so the delivery-path
    // rule is the ONLY thing that can withhold a row.
    //
    // A default context withholds scroll, move and drag anyway -- the input
    // review key is unbound -- so the assertions below would hold whether or not
    // the rule existed. Measured: with a default context, deleting the rule from
    // production leaves this test green. The fixture has to make the refusal come
    // from the property under test rather than from a state that refuses
    // everything.
    let context = fully_bound_context();
    let declarations = capability_declarations(&context, true);
    assert!(
        declarations
            .iter()
            .any(|declaration| declaration.advertised),
        "the fixture withholds every row, so it cannot show that any particular \
         one is withheld for the reason under test"
    );

    let vocabulary: serde_json::Value = serde_json::from_str(include_str!(
        "../resources/computer_action_vocabulary-v7.json"
    ))
    .expect("the frozen vocabulary parses");
    let rows = vocabulary["rows"].as_array().expect("rows is an array");

    let mut actuating = 0;
    let mut observing = 0;
    for declaration in &declarations {
        let row = rows
            .iter()
            .find(|row| row["capability_id"] == declaration.capability_id.as_str())
            .expect("every declaration has a frozen row");
        let declares_paths = row["semantic_path"].as_str().unwrap_or("none") != "none"
            || !row["synthetic_paths"]
                .as_array()
                .map(Vec::is_empty)
                .unwrap_or(true);

        if !declares_paths {
            observing += 1;
            continue;
        }
        actuating += 1;

        let deliverable = declaration.semantic_path == SupportState::Supported
            || declaration.synthetic_background == SupportState::Supported;
        if !deliverable {
            assert!(
                !declaration.advertised,
                "{} has no deliverable path yet is advertised",
                declaration.capability_id
            );
        }
    }

    // Both populations must be non-empty, or the loop above asserts nothing.
    assert_eq!(actuating, 6, "the actuating rows are not all present");
    assert_eq!(observing, 2, "the observing rows are not all present");
}

/// A row's observed-path claim agrees with the dispatch modes beside it.
///
/// These are two statements about the same question -- can this row be carried
/// in observed mode -- sitting in one struct, and they disagreed: screenshot and
/// wait carry no dispatch modes because they read rather than actuate, and the
/// observed field claimed ConsentGated for them anyway. A consent-gated path for
/// a capability that dispatches nothing.
///
/// Fixed by deriving one from the other rather than by correcting the value, so
/// a future row cannot reintroduce the disagreement. This asserts the property
/// that derivation is supposed to guarantee, because a derivation is only as
/// durable as something checking it stayed one.
#[test]
fn the_observed_claim_and_the_dispatch_modes_agree() {
    let context = fully_bound_context();
    let declarations = capability_declarations(&context, true);

    let mut with_observed = 0;
    let mut without = 0;
    for declaration in &declarations {
        let claims_observed = declaration.synthetic_observed != SupportState::Unsupported;
        let has_observed_mode = declaration.dispatch_modes.contains(&DispatchMode::Observed);
        assert_eq!(
            claims_observed, has_observed_mode,
            "{} claims observed support {:?} while its dispatch modes are {:?}",
            declaration.capability_id, declaration.synthetic_observed, declaration.dispatch_modes
        );
        if has_observed_mode {
            with_observed += 1;
        } else {
            without += 1;
        }
    }

    // Both sides must occur, or the equality above is satisfied by one uniform
    // answer and proves nothing about the agreement.
    assert_eq!(with_observed, 6, "the rows with an observed mode changed");
    assert_eq!(without, 2, "the rows without one changed");
}
