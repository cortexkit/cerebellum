use std::collections::BTreeSet;

use cerebellum::{
    build_manifest_with_computer_plane, computer_release_evidence,
    computer_release_evidence_with_exercised_rows, ComputerAdvertisementScope,
    ComputerCapabilityAdvertisementContext, ComputerGateOutcome, ComputerReleaseInputs,
};
use cerebellum_computer::platform::{
    capability_declarations, PermissionLiveness, PermissionLivenessReport, PermissionProbeResult,
    PermissionService, StartupCapabilityProbe, VocabularyDigestInputs,
    COMPUTER_ACTION_VOCABULARY_SHA256,
};
use subc_protocol::manifest::{ProviderRole, Tool};

fn valid_inputs() -> ComputerReleaseInputs {
    ComputerReleaseInputs {
        attendance_contract_owner: Some("fixture-attendance-owner".into()),
        attendance_contract_revision: Some("fixture-attendance-contract-v1".into()),
        input_review_revision: Some("fixture-input-review-v1".into()),
        global_dispatch_review_revision: Some("fixture-global-dispatch-review-v1".into()),
        capture_review_revision: Some("fixture-capture-review-v1".into()),
        semantic_actuation_review_revision: Some("fixture-semantic-actuation-review-v1".into()),
        app_state_review_revision: Some("fixture-app-state-review-v1".into()),
        element_addressed_review_revision: Some("fixture-element-addressed-review-v1".into()),
        takeover_dispatch_review_revision: Some("fixture-takeover-dispatch-review-v1".into()),
        windows_actuation_review_revision: Some("fixture-windows-actuation-review-v1".into()),
        release_signing_topology_revision: Some("fixture-signing-topology-v1".into()),
        vocabulary_digests: VocabularyDigestInputs {
            manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
            source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
            computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
        },
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

fn available_capabilities(context: &ComputerCapabilityAdvertisementContext) -> Vec<String> {
    capability_declarations(context, true)
        .into_iter()
        .filter(|declaration| declaration.advertised)
        .map(|declaration| declaration.capability_id)
        .collect()
}

/// Every current row, in artifact order: each has a wire handler.
fn every_served_row() -> Vec<&'static str> {
    vec![
        "computer.read_state",
        "computer.press_element",
        "computer.press_point",
        "computer.write_text",
        "computer.type",
        "computer.keys",
        "computer.takeover_move",
        "computer.takeover_drag",
        "computer.takeover_scroll",
        "computer.wait",
    ]
}

/// Every current row but the named ones, in artifact order.
fn every_served_row_but(withheld: &[&str]) -> Vec<&'static str> {
    every_served_row()
        .into_iter()
        .filter(|row| !withheld.contains(row))
        .collect()
}

const TAKEOVER_ROWS: [&str; 3] = [
    "computer.takeover_move",
    "computer.takeover_drag",
    "computer.takeover_scroll",
];

fn tools(manifest: &subc_protocol::manifest::ModuleManifest) -> Vec<&Tool> {
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("computer integration must retain the tool provider role")
    };
    tools.iter().collect()
}

#[test]
fn empty_runtime_advertisement_reports_every_frozen_row_without_functional_claim() {
    let context = ComputerCapabilityAdvertisementContext {
        inputs: ComputerReleaseInputs::default(),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let evidence = computer_release_evidence(&context);
    assert_eq!(evidence.frozen_row_count, 10);
    assert_eq!(evidence.canonical_row_count, 10);
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

    // Complete release identifiers with every permission live admit every row
    // with a wire handler: the state read, the element presses and write, the
    // two keystroke rows, the three takeover rows and wait. This was
    // originally asserted against the manifest, on the assumption that
    // advertisement is a function of the identifiers alone -- the assumption
    // that allowed a capability to be advertised which dispatch cannot serve.
    // Advertisement is now the conjunction of gate admission and
    // dispatchability, so the identifier half is asserted here and the manifest
    // half below.
    assert_eq!(available_capabilities(&context), every_served_row());
    assert_eq!(
        evidence.gate_admitted_capabilities,
        if cfg!(target_os = "macos") {
            every_served_row()
        } else {
            vec!["computer.wait"]
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
    assert!(computer_tools
        .iter()
        .all(|name| cerebellum::dispatchable_tool(name).is_some()));

    assert_eq!(evidence.frozen_row_count, 10);
    assert_eq!(evidence.advertised_capabilities, computer_tools);

    // The scope describes what is advertised rather than what the identifiers
    // admit. With every row now served, a macOS build carrying every review
    // advertises ALL of the frozen rows; elsewhere only wait is served, which
    // is PARTIAL.
    //
    // This is a release-visible claim: it says what a caller can do on the
    // computer plane rather than only what it declares. Changing this
    // expectation means changing what the module tells the fleet it can do,
    // which is why the scope is asserted exactly rather than as "not empty".
    assert_eq!(
        evidence.scope,
        if cfg!(target_os = "macos") {
            ComputerAdvertisementScope::AllFrozenRows
        } else {
            ComputerAdvertisementScope::PartialRuntimeAdvertisement
        }
    );
    assert_eq!(
        computer_tools,
        if cfg!(target_os = "macos") {
            every_served_row()
        } else {
            vec!["computer.wait"]
        },
        "the advertised set is no longer exactly the state read, the element actions, the \
         keystroke rows, the takeover rows and wait"
    );
    assert_eq!(evidence.exercised_row_count, 0);
    assert!(!evidence.functional_computer_plane);
    assert!(!computer_release_evidence_with_exercised_rows(&context, 0).functional_computer_plane);

    // A functional plane needs BOTH an advertised row and an exercised one, so
    // both halves are asserted: either alone is a claim the other does not
    // support.
    assert!(computer_release_evidence_with_exercised_rows(&context, 1).functional_computer_plane);

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

/// The keystroke rows are advertised under the input review and nothing
/// else, and no retired or unserved capability is ever offered, whatever is
/// bound.
#[test]
fn caller_manifest_requires_the_input_review_to_advertise_keystrokes() {
    let advertised = |context: &ComputerCapabilityAdvertisementContext| {
        #[cfg(target_os = "macos")]
        {
            tools(&build_manifest_with_computer_plane("cerebellum", context))
                .into_iter()
                .map(|tool| tool.name.clone())
                .collect::<BTreeSet<_>>()
        }
        #[cfg(not(target_os = "macos"))]
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
        "computer.press_point",
        "computer.write_text",
        "computer.takeover_move",
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
    unreviewed.inputs.input_review_revision = None;
    let offered = advertised(&unreviewed);
    assert!(
        !offered.contains("computer.type") && !offered.contains("computer.keys"),
        "the caller manifest offered keystrokes without their review: {offered:?}"
    );
}

/// A suppressed capability says which condition suppressed it.
///
/// The reason exists so an operator can tell a missing build input from an
/// ungranted permission: one is fixed by a release, the other by the person at
/// the machine. A single reason naming both leaves them to rule out the wrong
/// one by hand.
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
    missing_input_review.inputs.input_review_revision = None;
    assert_eq!(
        declaration_reason(&missing_input_review),
        Some("synthetic input review revision is not bound".to_string())
    );

    let mut permission_denied = valid_context();
    let denied = startup_with_accessibility(PermissionLiveness::Unavailable);
    permission_denied.permissions = denied.permissions.clone();
    permission_denied.startup = denied;
    assert_eq!(
        declaration_reason(&permission_denied),
        Some("Accessibility permission is not granted".to_string())
    );

    // An unresolved permission is a DIFFERENT case from a denied one: nothing
    // said no, the reading was never accepted. Reporting them alike would send
    // someone to the permission settings for a probe that ran in the wrong
    // place.
    let mut permission_unresolved = valid_context();
    let unresolved = StartupCapabilityProbe {
        os_major: 26,
        private_envelope_recognized: true,
        permissions: PermissionLivenessReport::default(),
    };
    permission_unresolved.permissions = unresolved.permissions.clone();
    permission_unresolved.startup = unresolved;
    assert_eq!(
        declaration_reason(&permission_unresolved),
        Some("Accessibility permission is not established".to_string())
    );
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
/// be added to one and not the other. The gap is not hypothetical here: the
/// computer-plane rows are added to the manifest once the release identifiers in
/// `default_computer_context` are filled in, while dispatch routes browser names
/// only -- so filling those in would advertise a capability that every call to
/// it rejects as an unknown method. Offering a caller something it cannot use is
/// worse than not offering it, because the caller has no way to tell the
/// difference until it tries.
///
/// The check runs against the context the module really ships rather than a
/// fully populated one, so it fails at the moment those identifiers are
/// supplied, which is the change that would create the mismatch.
#[test]
fn every_shipped_advertisement_can_be_dispatched() {
    let manifest =
        build_manifest_with_computer_plane("cerebellum", &cerebellum::default_computer_context());
    let advertised = tools(&manifest);
    assert!(
        !advertised.is_empty(),
        "an empty manifest would satisfy this vacuously"
    );
    for tool in advertised {
        assert_eq!(
            cerebellum::dispatchable_tool(&tool.name),
            Some(tool.name.as_str()),
            "{} is advertised but dispatch would reject it as an unknown method",
            tool.name
        );
    }
}

#[test]
fn every_missing_pin_is_reported_as_external_input_and_suppresses_affected_advertisement() {
    let complete = valid_context();
    assert_eq!(
        computer_release_evidence(&complete).gate_outcomes,
        vec![ComputerGateOutcome::Pass; 14],
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
        "release_signing_topology_revision",
        "vocabulary_manifest_digest",
        "vocabulary_source_lock_digest",
        "vocabulary_computed_artifact_digest",
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
            "release_signing_topology_revision" => inputs.release_signing_topology_revision = None,
            "vocabulary_manifest_digest" => inputs.vocabulary_digests.manifest_digest = None,
            "vocabulary_source_lock_digest" => inputs.vocabulary_digests.source_lock_digest = None,
            "vocabulary_computed_artifact_digest" => {
                inputs.vocabulary_digests.computed_artifact_digest = None
            }
            _ => unreachable!(),
        }
        let context = ComputerCapabilityAdvertisementContext {
            inputs,
            permissions: complete.permissions.clone(),
            startup: complete.startup.clone(),
        };
        let evidence = computer_release_evidence(&context);
        let actual = evidence.gate_outcomes.iter().find(|outcome| {
            matches!(
                outcome,
                ComputerGateOutcome::MissingExternalInput { gate: found } if found == gate
            )
        });
        assert_eq!(
            actual,
            Some(&ComputerGateOutcome::MissingExternalInput {
                gate: gate.to_string(),
            }),
            "missing pin {gate} must remain externally unresolved"
        );
        let admitted = available_capabilities(&context);
        match gate {
            "attendance_contract_owner"
            | "attendance_contract_revision"
            | "input_review_revision" => {
                assert_eq!(
                    admitted,
                    every_served_row_but(&["computer.type", "computer.keys"]),
                    "{gate} governs the keystroke rows"
                )
            }
            "release_signing_topology_revision" => assert_eq!(
                admitted,
                vec!["computer.wait"],
                "{gate} governs every reviewed row"
            ),
            "app_state_review_revision" => assert_eq!(
                admitted,
                every_served_row_but(&["computer.read_state"]),
                "{gate} governs the state read alone"
            ),
            "element_addressed_review_revision" => assert_eq!(
                admitted,
                every_served_row_but(&[
                    "computer.press_element",
                    "computer.press_point",
                    "computer.write_text"
                ]),
                "{gate} governs the element presses and writes alone"
            ),
            // Both reviews govern the takeover rows and nothing else. The
            // takeover review also admits bringing a background application
            // forward for keystrokes, but that is checked when a keystroke is
            // served: without it the keystroke rows are still advertised and
            // still serve an application that is already frontmost.
            "takeover_dispatch_review_revision" | "global_dispatch_review_revision" => {
                assert_eq!(
                    admitted,
                    every_served_row_but(&TAKEOVER_ROWS),
                    "{gate} governs the takeover rows alone"
                )
            }
            // No served row is reviewed under these any more, so withholding
            // one withholds nothing.
            "capture_review_revision"
            | "semantic_actuation_review_revision"
            | "windows_actuation_review_revision" => assert_eq!(
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
        inputs.input_review_revision = Some(invalid_value.into());
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
                    if gate == "input_review_revision"
            )
        });
        assert_eq!(
            actual,
            Some(&ComputerGateOutcome::ImplementationFailure {
                gate: "input_review_revision".to_string(),
            }),
            "{invalid_value} must not be accepted as a review attestation"
        );
        assert_eq!(
            evidence.gate_outcomes.iter().find(|outcome| matches!(outcome, ComputerGateOutcome::MissingExternalInput { gate } if gate == "input_review_revision")),
            None,
            "a supplied {invalid_value} value must not be classified as an absent review"
        );
        assert!(!evidence
            .gate_admitted_capabilities
            .iter()
            .any(|id| id == "computer.type" || id == "computer.keys"));
    }
}

/// The takeover rows need both the global-dispatch review and the takeover
/// review, each proved by isolation: with every other release input bound
/// and every permission live, leaving exactly one of the two unbound
/// withholds all three rows, from the declaration, the release gate and the
/// manifest, and each withheld row names that review as the reason.
#[test]
fn the_takeover_rows_need_both_reviews_each_proved_by_isolation() {
    // Everything bound admits them, so the refusals below are the gates'.
    let bound = valid_context();
    let admitted = computer_release_evidence(&bound).gate_admitted_capabilities;
    for row in TAKEOVER_ROWS {
        assert!(available_capabilities(&bound).contains(&row.to_string()));
        if cfg!(target_os = "macos") {
            assert!(admitted.contains(&row.to_string()), "{row}: {admitted:?}");
        }
    }

    for (gate, reason) in [
        (
            "global_dispatch_review_revision",
            "global dispatch review revision is not bound",
        ),
        (
            "takeover_dispatch_review_revision",
            "takeover dispatch review revision is not bound",
        ),
    ] {
        let mut inputs = valid_inputs();
        match gate {
            "global_dispatch_review_revision" => inputs.global_dispatch_review_revision = None,
            _ => inputs.takeover_dispatch_review_revision = None,
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
        assert!(
            evidence
                .gate_outcomes
                .contains(&ComputerGateOutcome::MissingExternalInput {
                    gate: gate.to_string(),
                }),
            "{gate} is not reported as an unresolved input"
        );
        for row in TAKEOVER_ROWS {
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
            every_served_row_but(&TAKEOVER_ROWS),
            "{gate}"
        );
    }
}
