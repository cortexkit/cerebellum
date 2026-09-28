//! The frozen vocabulary and the code that decides the same things must agree.
//!
//! Several fields in the frozen computer action vocabulary state a rule that a
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

const VOCABULARY: &str = include_str!("../resources/computer_action_vocabulary-v13.json");

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
    assert_eq!(rows.len(), 10, "the vocabulary is frozen at ten rows");

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

/// A pointer drag names points, never an element, so nothing grounds it and it
/// is addressed by coordinate: its containment is recorded at the weakest rung
/// rather than at an element rung a pixel match could only pretend to.
#[test]
fn a_takeover_drag_is_coordinate_addressed_and_grounds_nothing() {
    assert_eq!(
        GroundingPolicy::for_capability("computer.takeover_drag"),
        GroundingRequirement::NotGrounded
    );
    assert_eq!(
        GroundingPolicy::coordinate_addressable_for_capability("computer.takeover_drag"),
        Some(true)
    );
    assert_eq!(
        GroundingRequirement::ElementOrCoordinateAddressed(GroundingPolicy::default())
            .resolution_path(false),
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
/// Eight rows require a record BEFORE DISPATCH and one requires it before the
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
        before_dispatch, 8,
        "eight actuating rows must record intent before the machine changes"
    );
    assert_eq!(
        before_result, 1,
        "only the state read, whose image passes through capture custody, may \
         account for its record after the fact"
    );
}

/// No row declares a semantic scroll path, because nothing implements one.
///
/// `AxAction` has eight members with no scroll among them, so a row naming
/// `ax_scroll_position` would tell a caller reading the published artifact that
/// scrolling can be actuated semantically when it always goes out as synthetic
/// input. The pointer scroll row is global synthetic only and says so.
///
/// WHY NOT JUST ADD THE ACTION. Real applications do advertise
/// AXScrollUpByPage and friends, so the member could exist. Two arguments
/// against, and neither is settled by wanting the better containment rung:
/// every member added to a closed action vocabulary widens what a caller may
/// ask any application to perform, and a page-scroll moves the viewport by an
/// amount the APPLICATION chooses, so the post-condition cannot be stated the
/// way a press's can. Deciding that is a vocabulary revision with a review
/// behind it, not a patch.
#[test]
fn no_row_declares_a_semantic_scroll_path() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    for row in vocabulary["rows"].as_array().expect("rows is an array") {
        assert_ne!(
            row["semantic_path"], "ax_scroll_position",
            "{} claims a semantic scroll path that no action implements",
            row["capability_id"]
        );
    }
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
        "an AxAction now implements scrolling, so a semantic scroll path is no \
         longer a gap: revisit this test"
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
/// deliverable through the separately gated global path, which seizes the
/// shared cursor and is the authority this module calls observed mode. Claiming
/// background Supported would offer a caller a per-process capability that
/// cannot deliver.
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
            "computer.takeover_move" | "computer.takeover_drag" | "computer.takeover_scroll"
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
                "computer.takeover_move" | "computer.takeover_drag" | "computer.takeover_scroll"
            )
        })
        .count();
    let keyboard_rows = declarations
        .iter()
        .filter(|d| matches!(d.capability_id.as_str(), "computer.type" | "computer.keys"))
        .count();
    assert_eq!(pointer_rows, 3, "the pointer rows are not all present");
    assert_eq!(keyboard_rows, 2, "the keyboard rows are not all present");
}

/// No row claims semantic support while nothing serves a semantic path.
///
/// The press rows name ax_press and write_text names ax_value, and neither is
/// reachable yet: pressing a retained element and writing an element's value
/// need a retained-handle store and an attribute-write call the platform layer
/// does not have. A declaration that mirrored the artifact -- Supported
/// wherever the row named anything other than none -- would restate what the
/// row WANTS rather than what the driver can do, which is the same shape as a
/// frozen column nothing verifies: the claim and its subject never meet.
///
/// Every row is checked against the literal answer, so a row that starts
/// claiming support fails here by name.
#[test]
fn semantic_support_is_claimed_only_where_something_serves_it() {
    let context = CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs::default(),
        permissions: PermissionLivenessReport::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let declarations = capability_declarations(&context, true);
    assert_eq!(declarations.len(), 10, "every row was checked");
    for declaration in &declarations {
        assert_eq!(
            declaration.semantic_path,
            SupportState::Unsupported,
            "{} claims a semantic path nothing serves",
            declaration.capability_id
        );
    }
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
        global_dispatch_review_revision: Some("fixture-global-review-v1".to_string()),
        capture_review_revision: Some("fixture-capture-review-v1".to_string()),
        semantic_actuation_review_revision: Some("fixture-semantic-review-v1".to_string()),
        windows_actuation_review_revision: Some("fixture-windows-review-v1".to_string()),
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
/// path turned out not to deliver pointer events: the pointer rows have no
/// semantic action, no working background path, and an observed path whose
/// driver refuses because global posting was never approved. Binding the input
/// review key would have advertised capabilities that cannot deliver.
///
/// The two observing rows declare no delivery paths in the frozen vocabulary --
/// they read rather than actuate -- so the requirement does not apply to them,
/// and this asserts that exemption rather than leaving it implied.
#[test]
fn an_actuating_row_is_advertised_only_with_a_working_delivery_path() {
    // EVERY release input bound and every permission live, so the delivery-path
    // rule is the ONLY thing that can withhold a row.
    //
    // A default context withholds the actuating rows anyway -- the input
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

    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
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
            || declaration.synthetic_background == SupportState::Supported
            || declaration.dispatch_modes.contains(&DispatchMode::Observed);
        if !deliverable {
            assert!(
                !declaration.advertised,
                "{} has no deliverable path yet is advertised",
                declaration.capability_id
            );
        }
    }

    // Both populations must be non-empty, or the loop above asserts nothing.
    assert_eq!(actuating, 8, "the actuating rows are not all present");
    assert_eq!(observing, 2, "the observing rows are not all present");
}

/// A row's observed-path claim agrees with the dispatch modes beside it.
///
/// These are two statements about the same question -- can this row be carried
/// in observed mode -- sitting in one struct, and they once disagreed: the
/// observing rows carry no observed dispatch mode because they read rather than
/// actuate, and the observed field claimed ConsentGated for them anyway. A consent-gated path for
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
    assert_eq!(with_observed, 5, "the rows with an observed mode changed");
    assert_eq!(without, 5, "the rows without one changed");
}

#[test]
fn posts_returned_is_declared_on_every_synthetic_row() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).unwrap();
    for id in [
        "computer.type",
        "computer.keys",
        "computer.takeover_move",
        "computer.takeover_drag",
        "computer.takeover_scroll",
    ] {
        let row = vocabulary["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["capability_id"] == id)
            .unwrap();
        assert_eq!(
            row["result_schema"]["properties"]["posts_returned"]["type"], "integer",
            "{id}"
        );
        assert!(
            !row["result_schema"]["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("posts_returned".into())),
            "{id}"
        );
    }
}
