use std::collections::BTreeSet;

use cerebellum::{
    build_manifest_with_computer_plane, computer_release_evidence,
    computer_release_evidence_with_exercised_rows, ComputerAdvertisementScope,
    ComputerCapabilityAdvertisementContext, ComputerGateOutcome, ComputerReleaseInputs,
};
#[cfg(target_os = "linux")]
use cerebellum_computer::platform::LinuxReleaseInputs;
use cerebellum_computer::platform::{
    capability_declarations, PermissionLiveness, PermissionLivenessReport, PermissionProbeResult,
    PermissionService, StartupCapabilityProbe, VocabularyDigestInputs,
    COMPUTER_ACTION_VOCABULARY_SHA256,
};
use subc_protocol::manifest::{ProviderRole, Tool};

#[cfg(target_os = "linux")]
const RELEASE_GATE_COUNT: usize = 22;
#[cfg(not(target_os = "linux"))]
const RELEASE_GATE_COUNT: usize = 16;

fn valid_inputs() -> ComputerReleaseInputs {
    ComputerReleaseInputs {
        takeover_pointer_fronting_review_revision: Some(
            "fixture-pointer-fronting-review-v1".into(),
        ),
        attendance_contract_owner: Some("fixture-attendance-owner".into()),
        attendance_contract_revision: Some("fixture-attendance-contract-v1".into()),
        input_review_revision: Some("fixture-input-review-v1".into()),
        global_dispatch_review_revision: Some("fixture-global-dispatch-review-v1".into()),
        capture_review_revision: Some("fixture-capture-review-v1".into()),
        semantic_actuation_review_revision: Some("fixture-semantic-actuation-review-v1".into()),
        app_state_review_revision: Some("fixture-app-state-review-v1".into()),
        element_addressed_review_revision: Some("fixture-element-addressed-review-v1".into()),
        takeover_dispatch_review_revision: Some("fixture-takeover-dispatch-review-v1".into()),
        app_use_fronting_review_revision: Some("fixture-app-use-fronting-review-v1".into()),
        windows_actuation_review_revision: Some("fixture-windows-actuation-review-v1".into()),
        release_signing_topology_revision: Some("fixture-signing-topology-v1".into()),
        #[cfg(target_os = "linux")]
        linux: LinuxReleaseInputs {
            app_identity: Some("fixture-app-identity-review-v1".into()),
            semantic: Some("fixture-semantic-review-v1".into()),
            launch: Some("fixture-launch-review-v1".into()),
            x11_capture: Some("fixture-x11-capture-review-v1".into()),
            x11_fronting: Some("fixture-x11-fronting-review-v1".into()),
            x11_takeover: Some("fixture-x11-takeover-review-v1".into()),
        },
        vocabulary_digests: VocabularyDigestInputs {
            manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
            source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
            computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
        },
        ..Default::default()
    }
}

/// Every permission live except accessibility, which reads as `accessibility`.
fn startup_with_accessibility(accessibility: PermissionLiveness) -> StartupCapabilityProbe {
    StartupCapabilityProbe {
        os_major: 26,
        private_envelope_recognized: true,
        permissions: PermissionLivenessReport::from_results(
            [
                (PermissionService::ScreenRecording, PermissionLiveness::Live),
                (PermissionService::Accessibility, accessibility),
                (PermissionService::PostEvent, PermissionLiveness::Live),
                (PermissionService::InputMonitoring, PermissionLiveness::Live),
            ]
            .into_iter()
            .map(|(service, liveness)| PermissionProbeResult {
                service,
                liveness,
                responsible_process: "ck-subc".into(),
                off_main: true,
            }),
        ),
        ..Default::default()
    }
}

fn valid_context() -> ComputerCapabilityAdvertisementContext {
    let startup = startup_with_accessibility(PermissionLiveness::Live);
    ComputerCapabilityAdvertisementContext {
        inputs: valid_inputs(),
        permissions: startup.permissions.clone(),
        startup,
    }
}

#[test]
fn vocabulary_digest_mismatch_keeps_the_release_closed() {
    let mut context = valid_context();
    context.inputs.vocabulary_digests.source_lock_digest =
        cerebellum_computer::platform::implementation_source_lock_digest();
    let bound = computer_release_evidence(&context);
    assert_eq!(
        bound.gate_outcomes,
        vec![ComputerGateOutcome::Pass; RELEASE_GATE_COUNT]
    );
    assert_eq!(available_capabilities(&context), bound_advertised_rows());

    // A stale source lock is an implementation failure, not a missing
    // release input; a fully bound driver must withhold every row anyway.
    context.inputs.vocabulary_digests.source_lock_digest = Some("0".repeat(64));
    let mismatch = computer_release_evidence(&context);
    let failures: Vec<_> = mismatch
        .gate_outcomes
        .iter()
        .filter(|outcome| **outcome != ComputerGateOutcome::Pass)
        .cloned()
        .collect();
    assert_eq!(mismatch.gate_outcomes.len(), bound.gate_outcomes.len());
    assert_eq!(
        failures,
        [ComputerGateOutcome::ImplementationFailure {
            gate: "vocabulary_source_lock_digest".into(),
        }]
    );
    assert!(mismatch.gate_admitted_capabilities.is_empty());
    assert!(mismatch.advertised_capabilities.is_empty());
    assert!(available_capabilities(&context).is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn tonights_all_live_computer_use_definition_is_byte_identical() {
    let mut context = valid_context();
    // Live permissions must not change the historical definition while the
    // new review is unbound, even when every other release binding is present.
    context.inputs.takeover_pointer_fronting_review_revision = None;
    let manifest = build_manifest_with_computer_plane("cerebellum", &context);
    let tool = tools(&manifest)
        .into_iter()
        .find(|tool| tool.name == "computer_use")
        .unwrap();
    // The fixture holds the deliberately minted all-live computer_use definition. Compare it byte for byte so the expected value does not come from
    // the builder under test.
    assert_eq!(
        serde_json::to_vec(tool).unwrap(),
        include_bytes!("../fixtures/computer-use-all-live.json")
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn no_app_identity_support_means_no_computer_advertisement() {
    let context = valid_context();
    #[cfg(target_os = "linux")]
    let context = {
        let mut context = context;
        context.inputs.linux.app_identity = None;
        context
    };
    let evidence = computer_release_evidence(&context);
    assert_eq!(evidence.gate_outcomes.len(), RELEASE_GATE_COUNT);
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        evidence.gate_outcomes,
        vec![ComputerGateOutcome::Pass; RELEASE_GATE_COUNT]
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        evidence
            .gate_outcomes
            .iter()
            .filter(|gate| **gate != ComputerGateOutcome::Pass)
            .cloned()
            .collect::<Vec<_>>(),
        [ComputerGateOutcome::MissingExternalInput {
            gate: LinuxReleaseInputs::IDENTITY.into()
        }]
    );
    assert_eq!(evidence.canonical_row_count, 13);
    assert!(
        evidence.advertised_capabilities.is_empty(),
        "release bindings cannot supply the missing production app identity reader: {:?}",
        evidence.advertised_capabilities
    );
    assert!(evidence.gate_admitted_capabilities.is_empty());
    assert_eq!(
        evidence.scope,
        ComputerAdvertisementScope::EmptyRuntimeAdvertisement
    );
    assert_eq!(evidence.advertised_row_count, 0);
    let manifest = build_manifest_with_computer_plane("cerebellum", &context);
    assert!(tools(&manifest)
        .iter()
        .all(|tool| tool.name != "computer_use" && !tool.name.starts_with("computer.")));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn computer_tools_have_no_dispatch_route_without_a_production_plane() {
    let dispatchable: Vec<_> = bound_advertised_rows()
        .into_iter()
        .chain(["computer_use"])
        .filter_map(cerebellum::dispatchable_tool)
        .collect();
    assert!(dispatchable.is_empty(), "dispatchable: {dispatchable:?}");
}

fn available_capabilities(context: &ComputerCapabilityAdvertisementContext) -> Vec<String> {
    capability_declarations(context, true)
        .into_iter()
        .filter(|declaration| declaration.advertised)
        .map(|declaration| declaration.capability_id)
        .collect()
}

/// Rows admitted by the platform's reviews and its recorded recovery measurement.
fn bound_advertised_rows() -> Vec<&'static str> {
    vec![
        "computer.read_state",
        "computer.press_element",
        #[cfg(not(target_os = "linux"))]
        "computer.press_point",
        "computer.write_text",
        "computer.type",
        "computer.keys",
        "computer.takeover_move",
        #[cfg(not(target_os = "linux"))]
        "computer.takeover_click",
        #[cfg(not(target_os = "linux"))]
        "computer.takeover_drag",
        "computer.takeover_scroll",
        "computer.wait",
        "computer.list_apps",
        "computer.open_app",
    ]
}

/// Every runnable bound row but the named ones, in artifact order.
fn bound_advertised_rows_but(withheld: &[&str]) -> Vec<&'static str> {
    bound_advertised_rows()
        .into_iter()
        .filter(|row| !withheld.contains(row))
        .collect()
}

const TAKEOVER_ROWS: &[&str] = &[
    "computer.takeover_move",
    #[cfg(not(target_os = "linux"))]
    "computer.takeover_click",
    #[cfg(not(target_os = "linux"))]
    "computer.takeover_drag",
    "computer.takeover_scroll",
];

fn tools(manifest: &subc_protocol::manifest::ModuleManifest) -> Vec<&Tool> {
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("computer integration must retain the tool provider role")
    };
    tools.iter().collect()
}

fn assert_manifest_routes(manifest: &subc_protocol::manifest::ModuleManifest) {
    #[cfg(not(target_os = "linux"))]
    for tool in tools(manifest) {
        assert_eq!(
            cerebellum::dispatchable_tool(&tool.name),
            Some(tool.name.as_str()),
            "{} is advertised but dispatch would reject it as an unknown method",
            tool.name
        );
    }
    // The fixture's attestations are not the compiler's. Linux checks the
    // handler registry and flat translation without binding release keys.
    #[cfg(target_os = "linux")]
    {
        use cerebellum::{computer_capability::servable, flat_tools};
        let tools = tools(manifest);
        let mut granular = BTreeSet::new();
        let mut flat_routes = BTreeSet::new();
        for tool in tools {
            if tool.name == flat_tools::COMPUTER_USE {
                let actions = tool.schema["properties"]["action"]["enum"]
                    .as_array()
                    .expect("computer_use lists its supported actions");
                assert!(!actions.is_empty());
                for action in actions {
                    let translated =
                        flat_tools::translate_computer(&serde_json::json!({"action": action}))
                            .expect("an advertised action must translate");
                    let flat_tools::FlatDispatch::Computer { capability, .. } = translated else {
                        panic!("computer_use action {action} did not translate to a computer row");
                    };
                    assert!(
                        servable(&capability).is_some(),
                        "no handler for {capability}"
                    );
                    assert!(
                        flat_routes.insert(capability.clone()),
                        "duplicate flat route for {capability}"
                    );
                }
            } else {
                assert!(
                    servable(&tool.name).is_some(),
                    "no handler for {}",
                    tool.name
                );
                assert!(
                    granular.insert(tool.name.clone()),
                    "duplicate tool {}",
                    tool.name
                );
            }
        }
        assert_eq!(flat_routes, granular, "flat and granular routes must agree");
    }
}

#[test]
fn empty_runtime_advertisement_reports_every_frozen_row_without_functional_claim() {
    let context = ComputerCapabilityAdvertisementContext {
        inputs: ComputerReleaseInputs::default(),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let evidence = computer_release_evidence(&context);
    assert_eq!(evidence.frozen_row_count, 13);
    assert_eq!(evidence.canonical_row_count, 13);
    assert_eq!(evidence.advertised_row_count, 0);
    assert_eq!(evidence.exercised_row_count, 0);
    assert_eq!(
        evidence.scope,
        ComputerAdvertisementScope::EmptyRuntimeAdvertisement
    );
    assert!(!evidence.functional_computer_plane);
    assert!(
        tools(&build_manifest_with_computer_plane("cerebellum", &context))
            .iter()
            .all(|tool| !tool.name.starts_with("computer."))
    );
}

#[test]
fn complete_immutable_pins_advertise_only_canonical_runtime_rows_and_keep_zero_exercise_honest() {
    let context = valid_context();
    let evidence = computer_release_evidence(&context);

    // Driver declarations establish the reviewed rows. The module must also
    // route each one it advertises and withhold platforms with no wired plane.
    assert_eq!(available_capabilities(&context), bound_advertised_rows());
    assert_eq!(
        evidence.gate_admitted_capabilities,
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            bound_advertised_rows()
        } else {
            vec![]
        }
    );

    // Everything advertised can be dispatched. The advertised set is DERIVED
    // from the dispatchable one rather than compared against it, so a capability
    // cannot be offered that dispatch would reject as an unknown method.
    let manifest = build_manifest_with_computer_plane("cerebellum", &context);
    let computer_tools: Vec<String> = tools(&manifest)
        .into_iter()
        .filter(|tool| tool.name.starts_with("computer."))
        .map(|tool| tool.name.clone())
        .collect();
    assert_manifest_routes(&manifest);

    assert_eq!(evidence.frozen_row_count, 13);
    assert_eq!(evidence.advertised_capabilities, computer_tools);

    // Full bindings still do not admit Linux point presses or unmeasured down
    // gestures. Only the macOS fixture advertises every frozen row.
    //
    // This is a release-visible claim: it says what a caller can do on the
    // computer plane rather than only what it declares. Changing this
    // expectation means changing what the module tells the fleet it can do,
    // which is why the scope is asserted exactly rather than as "not empty".
    assert_eq!(
        evidence.scope,
        if cfg!(target_os = "macos") {
            ComputerAdvertisementScope::AllFrozenRows
        } else if cfg!(target_os = "linux") {
            ComputerAdvertisementScope::PartialRuntimeAdvertisement
        } else {
            ComputerAdvertisementScope::EmptyRuntimeAdvertisement
        }
    );
    assert_eq!(
        computer_tools,
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            bound_advertised_rows()
        } else {
            vec![]
        },
        "the advertised set must match the platform's release and dispatch support"
    );
    assert_eq!(evidence.exercised_row_count, 0);
    assert!(!evidence.functional_computer_plane);
    assert!(!computer_release_evidence_with_exercised_rows(&context, 0).functional_computer_plane);

    // A functional plane needs BOTH an advertised row and an exercised one, so
    // both halves are asserted: either alone is a claim the other does not
    // support.
    assert_eq!(
        computer_release_evidence_with_exercised_rows(&context, 1).functional_computer_plane,
        cfg!(any(target_os = "macos", target_os = "linux"))
    );

    // Advertising without exercising is not a functional claim. This is the
    // half that matters: a module that offered capabilities nobody had run
    // would otherwise report itself working on the strength of its own manifest.
    assert!(!computer_release_evidence_with_exercised_rows(&context, 0).functional_computer_plane);

    // And exercising against an empty advertisement is not one either, which is
    // what this line asserted before either half was reachable.
    let empty = ComputerCapabilityAdvertisementContext {
        inputs: ComputerReleaseInputs::default(),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    assert!(!computer_release_evidence_with_exercised_rows(&empty, 1).functional_computer_plane);
}

/// Unbinding the platform's keystroke review withdraws keystrokes, and no
/// retired or unserved capability is offered even with all reviews bound.
#[test]
fn caller_manifest_requires_the_input_review_to_advertise_keystrokes() {
    let advertised = |context: &ComputerCapabilityAdvertisementContext| {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            tools(&build_manifest_with_computer_plane("cerebellum", context))
                .into_iter()
                .map(|tool| tool.name.clone())
                .collect::<BTreeSet<_>>()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            available_capabilities(context)
                .into_iter()
                .collect::<BTreeSet<_>>()
        }
    };

    let bound = valid_context();
    let offered = advertised(&bound);
    assert!(offered.contains("computer.type"), "{offered:?}");
    assert!(offered.contains("computer.keys"), "{offered:?}");
    assert!(offered.contains("computer.read_state"), "{offered:?}");
    for served in [
        "computer.press_element",
        #[cfg(not(target_os = "linux"))]
        "computer.press_point",
        "computer.write_text",
        "computer.takeover_move",
        #[cfg(not(target_os = "linux"))]
        "computer.takeover_click",
        #[cfg(not(target_os = "linux"))]
        "computer.takeover_drag",
        "computer.takeover_scroll",
    ] {
        assert!(
            offered.contains(served),
            "{served} was not offered: {offered:?}"
        );
    }
    for never in [
        "computer.click",
        "computer.screenshot",
        "computer.move",
        "computer.drag",
        "computer.scroll",
    ] {
        assert!(!offered.contains(never), "{never} was offered");
    }

    let mut unreviewed = bound;
    set_keystroke_review(&mut unreviewed.inputs, None);
    let offered = advertised(&unreviewed);
    assert!(
        !offered.contains("computer.type") && !offered.contains("computer.keys"),
        "the caller manifest offered keystrokes without their review: {offered:?}"
    );
}

fn set_keystroke_review(inputs: &mut ComputerReleaseInputs, value: Option<String>) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        inputs.linux.x11_fronting = value;
        LinuxReleaseInputs::FRONTING
    }
    #[cfg(not(target_os = "linux"))]
    {
        inputs.input_review_revision = value;
        "input_review_revision"
    }
}

/// A suppressed capability says which condition suppressed it.
///
/// The reason names a missing build input. Permission state must never be a
/// suppression reason; its distinct states are returned at the wire instead.
///
/// Each case is produced by spoiling exactly one condition of an otherwise
/// valid context, so the reason is attributable to the clause under test rather
/// than to whichever check happens to run first.
#[test]
fn a_suppressed_capability_names_the_condition_that_suppressed_it() {
    let declaration_reason = |context: &ComputerCapabilityAdvertisementContext| {
        capability_declarations(context, true)
            .into_iter()
            .find(|declaration| declaration.capability_id == "computer.keys")
            .expect("the frozen rows always include keys")
            .suppression_reason
    };

    // The permissions are granted and every input present, so nothing is
    // suppressed. Without this the cases below would all pass against a
    // capability that is never advertised for some fourth reason.
    assert_eq!(declaration_reason(&valid_context()), None);

    let mut missing_input_review = valid_context();
    set_keystroke_review(&mut missing_input_review.inputs, None);
    assert_eq!(
        declaration_reason(&missing_input_review),
        Some(
            if cfg!(target_os = "linux") {
                "route_not_reviewed"
            } else {
                "synthetic input review revision is not bound"
            }
            .to_string()
        )
    );

    let mut permission_denied = valid_context();
    let denied = startup_with_accessibility(PermissionLiveness::Unavailable);
    permission_denied.permissions = denied.permissions.clone();
    permission_denied.startup = denied;
    assert_eq!(declaration_reason(&permission_denied), None);

    // Neither a denied grant nor an unresolved reading changes advertisement.
    // The wire admission matrix asserts their distinct refusal states.
    let mut permission_unresolved = valid_context();
    let unresolved = StartupCapabilityProbe {
        os_major: 26,
        private_envelope_recognized: true,
        permissions: PermissionLivenessReport::default(),
        ..Default::default()
    };
    permission_unresolved.permissions = unresolved.permissions.clone();
    permission_unresolved.startup = unresolved;
    assert_eq!(declaration_reason(&permission_unresolved), None);
}

/// The advertisement context reports what the system says, not a placeholder.
///
/// The context is what the module sends on HELLO, and its permission half used
/// to be supplied empty, so every service resolved to unknown regardless of what
/// the machine had granted. That is indistinguishable from a machine that has
/// granted nothing, which is why it went unnoticed.
///
/// Asserted as an agreement with a direct query rather than as a particular
/// answer, so it holds on a machine in either permission state and fails only
/// if the context stops reflecting the system.
#[cfg(target_os = "macos")]
#[test]
fn the_advertisement_context_reflects_this_system() {
    let context = cerebellum::default_computer_context();
    let granted = cerebellum_computer::platform::native::probe_permissions()
        .iter()
        .any(|result| {
            result.service == PermissionService::ScreenRecording
                && result.liveness == PermissionLiveness::Live
        });

    let reported = context
        .permissions
        .state(PermissionService::ScreenRecording);
    if granted {
        assert_eq!(
            reported,
            PermissionLiveness::Live,
            "the system grants screen recording and the context does not say so"
        );
    } else {
        assert_ne!(
            reported,
            PermissionLiveness::Live,
            "the context claims a grant the system does not report"
        );
    }
}

/// Every tool the module offers in its manifest can actually be served.
///
/// The manifest and the dispatcher are built from separate lists, so a tool can
/// be added to one and not the other. Offering a caller something it cannot use
/// is worse than not offering it, because the caller has no way to tell the
/// difference until it tries.
///
/// The check runs against the context the module really ships, and also against
/// a context with every release identifier supplied, because that is the change
/// that would create a mismatch. A development build binds no review, so it may
/// advertise nothing at all; the fully bound context exercises the handler
/// routes on macOS and Linux without binding real reviews.
#[test]
fn every_shipped_advertisement_can_be_dispatched() {
    let shipped =
        build_manifest_with_computer_plane("cerebellum", &cerebellum::default_computer_context());
    let bound = build_manifest_with_computer_plane("cerebellum", &valid_context());
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        assert!(
            !tools(&bound).is_empty(),
            "an empty manifest would satisfy this vacuously"
        );
    } else {
        assert!(
            tools(&bound).is_empty(),
            "no app identity reader means no production computer tools"
        );
    }
    for manifest in [&shipped, &bound] {
        assert_manifest_routes(manifest);
    }
}

#[test]
fn every_missing_pin_is_reported_as_external_input_and_suppresses_affected_advertisement() {
    let complete = valid_context();
    assert_eq!(
        computer_release_evidence(&complete).gate_outcomes,
        vec![ComputerGateOutcome::Pass; RELEASE_GATE_COUNT],
        "the complete fixture must prove the passing direction before it is spoiled"
    );

    let fields = [
        "attendance_contract_owner",
        "attendance_contract_revision",
        "input_review_revision",
        "global_dispatch_review_revision",
        "capture_review_revision",
        "semantic_actuation_review_revision",
        "windows_actuation_review_revision",
        "app_state_review_revision",
        "element_addressed_review_revision",
        "takeover_dispatch_review_revision",
        "takeover_pointer_fronting_review_revision",
        "app_use_fronting_review_revision",
        "release_signing_topology_revision",
        "vocabulary_manifest_digest",
        "vocabulary_source_lock_digest",
        "vocabulary_computed_artifact_digest",
        #[cfg(target_os = "linux")]
        LinuxReleaseInputs::IDENTITY,
        #[cfg(target_os = "linux")]
        LinuxReleaseInputs::SEMANTIC,
        #[cfg(target_os = "linux")]
        LinuxReleaseInputs::LAUNCH,
        #[cfg(target_os = "linux")]
        LinuxReleaseInputs::CAPTURE,
        #[cfg(target_os = "linux")]
        LinuxReleaseInputs::FRONTING,
        #[cfg(target_os = "linux")]
        LinuxReleaseInputs::TAKEOVER,
    ];
    for gate in fields {
        let mut inputs = complete.inputs.clone();
        match gate {
            "attendance_contract_owner" => inputs.attendance_contract_owner = None,
            "attendance_contract_revision" => inputs.attendance_contract_revision = None,
            "input_review_revision" => inputs.input_review_revision = None,
            "global_dispatch_review_revision" => inputs.global_dispatch_review_revision = None,
            "capture_review_revision" => inputs.capture_review_revision = None,
            "semantic_actuation_review_revision" => {
                inputs.semantic_actuation_review_revision = None
            }
            "windows_actuation_review_revision" => inputs.windows_actuation_review_revision = None,
            "app_state_review_revision" => inputs.app_state_review_revision = None,
            "element_addressed_review_revision" => inputs.element_addressed_review_revision = None,
            "takeover_dispatch_review_revision" => inputs.takeover_dispatch_review_revision = None,
            "takeover_pointer_fronting_review_revision" => {
                inputs.takeover_pointer_fronting_review_revision = None
            }
            "app_use_fronting_review_revision" => inputs.app_use_fronting_review_revision = None,
            "release_signing_topology_revision" => inputs.release_signing_topology_revision = None,
            "vocabulary_manifest_digest" => inputs.vocabulary_digests.manifest_digest = None,
            "vocabulary_source_lock_digest" => inputs.vocabulary_digests.source_lock_digest = None,
            "vocabulary_computed_artifact_digest" => {
                inputs.vocabulary_digests.computed_artifact_digest = None
            }
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::IDENTITY => inputs.linux.app_identity = None,
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::SEMANTIC => inputs.linux.semantic = None,
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::LAUNCH => inputs.linux.launch = None,
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::CAPTURE => inputs.linux.x11_capture = None,
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::FRONTING => inputs.linux.x11_fronting = None,
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::TAKEOVER => inputs.linux.x11_takeover = None,
            _ => unreachable!(),
        }
        let context = ComputerCapabilityAdvertisementContext {
            inputs,
            permissions: complete.permissions.clone(),
            startup: complete.startup.clone(),
        };
        let evidence = computer_release_evidence(&context);
        let failed: Vec<_> = evidence
            .gate_outcomes
            .iter()
            .filter(|outcome| **outcome != ComputerGateOutcome::Pass)
            .cloned()
            .collect();
        assert_eq!(
            failed,
            [ComputerGateOutcome::MissingExternalInput {
                gate: gate.to_string(),
            }],
            "only missing pin {gate} must remain externally unresolved"
        );
        let admitted = available_capabilities(&context);
        #[cfg(target_os = "linux")]
        assert_eq!(evidence.advertised_capabilities, admitted, "{gate}");
        match gate {
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::IDENTITY | "release_signing_topology_revision" => {
                assert!(admitted.is_empty(), "{gate} governs every Linux row")
            }
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::SEMANTIC => assert_eq!(admitted, ["computer.open_app"], "{gate}"),
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::LAUNCH => assert_eq!(
                admitted,
                bound_advertised_rows_but(&["computer.open_app"]),
                "{gate}"
            ),
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::CAPTURE | LinuxReleaseInputs::TAKEOVER => assert_eq!(
                admitted,
                bound_advertised_rows_but(TAKEOVER_ROWS),
                "{gate} governs the takeover rows"
            ),
            #[cfg(target_os = "linux")]
            "input_review_revision"
            | "app_state_review_revision"
            | "element_addressed_review_revision"
            | "takeover_dispatch_review_revision"
            | "global_dispatch_review_revision" => assert_eq!(
                admitted,
                bound_advertised_rows(),
                "{gate} does not govern Linux rows"
            ),
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::FRONTING => assert_eq!(
                admitted,
                bound_advertised_rows_but(&["computer.type", "computer.keys"]),
                "{gate} governs the keystroke rows"
            ),
            "takeover_pointer_fronting_review_revision" => {
                assert!(cerebellum::takeover_pointer_fronting_admitted(
                    &complete.inputs
                ));
                assert!(!cerebellum::takeover_pointer_fronting_admitted(
                    &context.inputs
                ));
                let mut legacy = bound_advertised_rows();
                legacy.retain(|row| *row != "computer.takeover_click");
                assert_eq!(
                    admitted, legacy,
                    "unbound drag retains its legacy frontmost-only route; click remains withheld"
                );
            }
            "attendance_contract_owner" | "attendance_contract_revision" => {
                assert_eq!(
                    admitted,
                    bound_advertised_rows_but(&["computer.type", "computer.keys"]),
                    "{gate} governs the keystroke rows"
                )
            }
            #[cfg(not(target_os = "linux"))]
            "input_review_revision" => assert_eq!(
                admitted,
                bound_advertised_rows_but(&["computer.type", "computer.keys"]),
                "{gate} governs the keystroke rows"
            ),
            #[cfg(not(target_os = "linux"))]
            "release_signing_topology_revision" => assert_eq!(
                admitted,
                vec!["computer.wait"],
                "{gate} governs every reviewed row"
            ),
            #[cfg(not(target_os = "linux"))]
            "app_state_review_revision" => assert_eq!(
                admitted,
                bound_advertised_rows_but(&[
                    "computer.read_state",
                    "computer.list_apps",
                    "computer.open_app"
                ]),
                "{gate} governs the state read and the application list"
            ),
            #[cfg(not(target_os = "linux"))]
            "element_addressed_review_revision" => assert_eq!(
                admitted,
                bound_advertised_rows_but(&[
                    "computer.press_element",
                    "computer.press_point",
                    "computer.write_text",
                    "computer.open_app"
                ]),
                "{gate} governs the element presses, writes and app launch"
            ),
            // Both reviews govern the takeover rows and nothing else. The
            // takeover review also admits bringing a background application
            // forward for keystrokes, but that is checked when a keystroke is
            // served: without it the keystroke rows are still advertised and
            // still serve an application that is already frontmost.
            #[cfg(not(target_os = "linux"))]
            "takeover_dispatch_review_revision" | "global_dispatch_review_revision" => {
                assert_eq!(
                    admitted,
                    bound_advertised_rows_but(TAKEOVER_ROWS),
                    "{gate} governs the takeover rows alone"
                )
            }
            // No served row is reviewed under these any more, so withholding
            // one withholds nothing.
            // The app-use review admits fronting and preview capture inside
            // rows other reviews admit; it governs no row of its own.
            "capture_review_revision"
            | "semantic_actuation_review_revision"
            | "windows_actuation_review_revision"
            | "app_use_fronting_review_revision" => assert_eq!(
                admitted,
                available_capabilities(&complete),
                "{gate} governs no served row"
            ),
            _ => assert!(
                admitted.is_empty(),
                "common missing pin {gate} must suppress rows"
            ),
        }
    }
}

#[test]
fn supplied_placeholder_external_pin_is_an_implementation_failure_not_an_unresolved_input() {
    for invalid_value in ["placeholder", "tbd", "unknown"] {
        let mut inputs = valid_inputs();
        let key = set_keystroke_review(&mut inputs, Some(invalid_value.into()));
        let context = ComputerCapabilityAdvertisementContext {
            inputs,
            permissions: valid_context().permissions,
            startup: valid_context().startup,
        };
        let evidence = computer_release_evidence(&context);
        let actual = evidence.gate_outcomes.iter().find(|outcome| {
            matches!(
                outcome,
                ComputerGateOutcome::ImplementationFailure { gate }
                    if gate == key
            )
        });
        assert_eq!(
            actual,
            Some(&ComputerGateOutcome::ImplementationFailure {
                gate: key.to_string(),
            }),
            "{invalid_value} must not be accepted as a review attestation"
        );
        assert_eq!(
            evidence.gate_outcomes.iter().find(|outcome| matches!(outcome, ComputerGateOutcome::MissingExternalInput { gate } if gate == key)),
            None,
            "a supplied {invalid_value} value must not be classified as an absent review"
        );
        assert!(!evidence
            .gate_admitted_capabilities
            .iter()
            .any(|id| id == "computer.type" || id == "computer.keys"));
    }
}

/// The platform's two takeover reviews are independently necessary with
/// every other input bound. Removing either one withdraws every otherwise
/// advertised takeover row from declarations, release evidence and the manifest.
#[test]
fn the_takeover_rows_need_both_reviews_each_proved_by_isolation() {
    // Positive admission of every pointer row proves the missing-review negatives below.
    let bound = valid_context();
    let admitted = computer_release_evidence(&bound).gate_admitted_capabilities;
    for &row in TAKEOVER_ROWS {
        assert!(available_capabilities(&bound).contains(&row.to_string()));
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert!(admitted.contains(&row.to_string()), "{row}: {admitted:?}");
        }
    }

    #[cfg(target_os = "linux")]
    let reviews = [
        (LinuxReleaseInputs::CAPTURE, "route_not_reviewed"),
        (LinuxReleaseInputs::TAKEOVER, "route_not_reviewed"),
    ];
    #[cfg(not(target_os = "linux"))]
    let reviews = [
        (
            "global_dispatch_review_revision",
            "global dispatch review revision is not bound",
        ),
        (
            "takeover_dispatch_review_revision",
            "takeover dispatch review revision is not bound",
        ),
    ];
    for (gate, reason) in reviews {
        let mut inputs = valid_inputs();
        match gate {
            "global_dispatch_review_revision" => inputs.global_dispatch_review_revision = None,
            "takeover_dispatch_review_revision" => inputs.takeover_dispatch_review_revision = None,
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::CAPTURE => inputs.linux.x11_capture = None,
            #[cfg(target_os = "linux")]
            LinuxReleaseInputs::TAKEOVER => inputs.linux.x11_takeover = None,
            _ => unreachable!(),
        }
        let context = ComputerCapabilityAdvertisementContext {
            inputs,
            permissions: bound.permissions.clone(),
            startup: bound.startup.clone(),
        };

        for declaration in capability_declarations(&context, true)
            .into_iter()
            .filter(|declaration| TAKEOVER_ROWS.contains(&declaration.capability_id.as_str()))
        {
            assert!(!declaration.advertised, "{gate}: {declaration:?}");
            assert_eq!(
                declaration.suppression_reason.as_deref(),
                Some(reason),
                "{gate}: {}",
                declaration.capability_id
            );
        }
        let evidence = computer_release_evidence(&context);
        assert_eq!(
            evidence
                .gate_outcomes
                .iter()
                .filter(|outcome| **outcome != ComputerGateOutcome::Pass)
                .cloned()
                .collect::<Vec<_>>(),
            [ComputerGateOutcome::MissingExternalInput {
                gate: gate.to_string(),
            }],
            "{gate} must be the only unresolved input"
        );
        for &row in TAKEOVER_ROWS {
            assert!(
                !evidence
                    .gate_admitted_capabilities
                    .contains(&row.to_string()),
                "{gate}: {row} was admitted"
            );
            assert!(
                tools(&build_manifest_with_computer_plane("cerebellum", &context))
                    .iter()
                    .all(|tool| tool.name != row),
                "{gate}: {row} was in the manifest"
            );
        }
        // The rest of the served surface is untouched by either review.
        assert_eq!(
            available_capabilities(&context),
            bound_advertised_rows_but(TAKEOVER_ROWS),
            "{gate}"
        );
    }
}

/// Every read of an application's accessibility tree is withdrawn by one key.
///
/// The wait polls the same tree read_state reads, under the same app grant, so
/// it must not stay advertised when that review is unbound: otherwise a build
/// placed with the key unbound would still read trees, with no key left that
/// withdraws it. The list of running applications a caller picks a target
/// from is part of the same reviewed surface, so the key withdraws it too.
#[test]
fn every_tree_read_is_withdrawn_by_its_platform_review() {
    const TREE_READS: [&str; 3] = ["computer.read_state", "computer.wait", "computer.list_apps"];
    let bound = valid_context();
    let mut inputs = valid_inputs();
    #[cfg(target_os = "linux")]
    {
        inputs.linux.semantic = None;
    }
    #[cfg(not(target_os = "linux"))]
    {
        inputs.app_state_review_revision = None;
    }
    let unbound = ComputerCapabilityAdvertisementContext {
        inputs,
        permissions: bound.permissions.clone(),
        startup: bound.startup.clone(),
    };

    let with_key = computer_release_evidence(&bound).gate_admitted_capabilities;
    let without_key = computer_release_evidence(&unbound).gate_admitted_capabilities;
    let manifest_without_key = build_manifest_with_computer_plane("cerebellum", &unbound);
    for row in TREE_READS {
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert!(with_key.contains(&row.to_string()), "{row}: {with_key:?}");
        }
        assert!(
            !without_key.contains(&row.to_string()),
            "{row} was admitted without its review: {without_key:?}"
        );
        assert!(
            tools(&manifest_without_key)
                .iter()
                .all(|tool| tool.name != row),
            "{row} was in the manifest without its review"
        );
    }
    // The key withdraws tree reads and app launch, which resolves its bundle
    // from the same reviewed application inventory, but nothing else.
    if cfg!(target_os = "macos") {
        let expected: Vec<String> = with_key
            .iter()
            .filter(|row| {
                !TREE_READS.contains(&row.as_str()) && row.as_str() != "computer.open_app"
            })
            .cloned()
            .collect();
        assert_eq!(without_key, expected);
    }
    #[cfg(target_os = "linux")]
    assert_eq!(
        without_key,
        ["computer.open_app"],
        "launch has its own Linux review"
    );
}
