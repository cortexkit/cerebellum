use std::collections::BTreeSet;

use cerebellum::{
    build_manifest_with_computer_plane, computer_release_evidence,
    computer_release_evidence_with_exercised_rows, ComputerAdvertisementScope,
    ComputerCapabilityAdvertisementContext, ComputerGateOutcome, ComputerReleaseInputs,
    CEREBELLUM_CORE_CONTRACT_REVISION, COMPUTER_ATTENDANCE_SCHEMA_ID, COMPUTER_C2_JOURNAL_REVISION,
    COMPUTER_C2_JOURNAL_SCHEMA_ID, COMPUTER_CAPTURE_LEAKAGE_REVISION,
    COMPUTER_PERMISSION_MATRIX_REVISION,
};
use cerebellum_computer::platform::{
    containment::PROCESS_IDENTITY_PRIMITIVE_REVISION, PermissionLiveness, PermissionProbeResult,
    PermissionService, StartupCapabilityProbe, StartupProbeInput, VocabularyDigestInputs,
    COMPUTER_ACTION_VOCABULARY_REVISION, COMPUTER_ACTION_VOCABULARY_SHA256,
};
use subc_protocol::manifest::{ProviderRole, Tool};

fn valid_inputs() -> ComputerReleaseInputs {
    ComputerReleaseInputs {
        computer_action_vocabulary_revision: Some(COMPUTER_ACTION_VOCABULARY_REVISION.into()),
        permission_matrix_revision: Some(COMPUTER_PERMISSION_MATRIX_REVISION.into()),
        process_identity_primitive_revision: Some(PROCESS_IDENTITY_PRIMITIVE_REVISION.into()),
        capture_residual_leakage_revision: Some(COMPUTER_CAPTURE_LEAKAGE_REVISION.into()),
        attendance_contract_owner: Some("attendance-owner".into()),
        attendance_contract_schema_id: Some(COMPUTER_ATTENDANCE_SCHEMA_ID.into()),
        attendance_contract_revision: Some("attendance-contract-v1".into()),
        input_review_revision: Some("input-review-v1".into()),
        capture_review_revision: Some("capture-review-v1".into()),
        release_signing_topology_revision: Some("signing-topology-v1".into()),
        cerebellum_core_contract_revision: Some(CEREBELLUM_CORE_CONTRACT_REVISION.into()),
        c2_journal_pin_schema_id: Some(COMPUTER_C2_JOURNAL_SCHEMA_ID.into()),
        c2_journal_pin_revision: Some(COMPUTER_C2_JOURNAL_REVISION.into()),
        vocabulary_digests: VocabularyDigestInputs {
            manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
            source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
            computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.into()),
        },
    }
}

fn valid_context() -> ComputerCapabilityAdvertisementContext {
    let startup = StartupCapabilityProbe::run(&StartupProbeInput {
        os_major: 26,
        private_envelope_revision: Some("skylight-macos26-v1".into()),
        resolved_private_symbols: ["SLEventPostToPid".into()].into_iter().collect(),
        permission_results: vec![PermissionProbeResult {
            service: PermissionService::ScreenRecording,
            liveness: PermissionLiveness::Live,
            responsible_process: "ck-subc".into(),
            off_main: true,
        }],
        responsible_process: Some("ck-subc".into()),
    });
    ComputerCapabilityAdvertisementContext {
        inputs: valid_inputs(),
        permissions: startup.permissions.clone(),
        startup,
    }
}

fn tools(manifest: &subc_protocol::manifest::ModuleManifest) -> Vec<&Tool> {
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("computer integration must retain the tool provider role")
    };
    tools.iter().collect()
}

#[test]
fn empty_runtime_advertisement_reports_frozen_eight_row_scope_without_functional_claim() {
    let context = ComputerCapabilityAdvertisementContext {
        inputs: ComputerReleaseInputs::default(),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::run(&StartupProbeInput {
            os_major: 26,
            private_envelope_revision: None,
            resolved_private_symbols: BTreeSet::new(),
            permission_results: Vec::new(),
            responsible_process: None,
        }),
    };
    let evidence = computer_release_evidence(&context);
    assert_eq!(evidence.frozen_row_count, 8);
    assert_eq!(evidence.canonical_row_count, 8);
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

    // Complete release identifiers admit exactly the two read-only rows. This
    // was originally asserted against the manifest, on the assumption that
    // advertisement is a function of the identifiers alone -- the assumption
    // that allowed a capability to be advertised which dispatch cannot serve.
    // Advertisement is now the conjunction of gate admission and
    // dispatchability, so the identifier half is asserted here and the manifest
    // half below.
    assert_eq!(
        evidence.gate_admitted_capabilities,
        vec!["computer.screenshot", "computer.wait"]
    );

    // No computer capability is dispatchable yet, so none is advertised. When
    // the first one is served, it appears here without this test changing.
    let manifest = build_manifest_with_computer_plane("cerebellum", &context);
    let computer_tools: Vec<String> = tools(&manifest)
        .into_iter()
        .filter(|tool| tool.name.starts_with("computer."))
        .map(|tool| tool.name.clone())
        .collect();
    assert!(computer_tools
        .iter()
        .all(|name| cerebellum::dispatchable_tool(name).is_some()));

    assert_eq!(evidence.frozen_row_count, 8);
    assert_eq!(evidence.advertised_capabilities, computer_tools);

    // The scope describes what is advertised, not what the identifiers admit,
    // so it is empty while nothing is dispatchable. It becomes partial when the
    // first computer capability can be served, and this assertion is the thing
    // that will fail then -- deliberately, because that is a release-visible
    // change in what the module claims and should be acknowledged rather than
    // absorbed.
    assert_eq!(
        evidence.scope,
        ComputerAdvertisementScope::EmptyRuntimeAdvertisement
    );
    assert_eq!(evidence.exercised_row_count, 0);
    assert!(!evidence.functional_computer_plane);
    assert!(!computer_release_evidence_with_exercised_rows(&context, 0).functional_computer_plane);

    // A functional plane needs an exercised row, and a row can only be
    // exercised once it is advertised. That case is unreachable while nothing
    // is dispatchable, so what is asserted here is the weaker half that still
    // holds: claiming exercised rows against an empty advertisement does not
    // produce a functional claim.
    assert!(!computer_release_evidence_with_exercised_rows(&context, 1).functional_computer_plane);
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
    let fields = [
        ("computer_action_vocabulary_revision", 0),
        ("cerebellum_core_contract_revision", 1),
        ("c2_journal_pin_schema_id", 2),
        ("c2_journal_pin_revision", 3),
        ("process_identity_primitive_revision", 4),
        ("capture_residual_leakage_revision", 5),
        ("permission_matrix_revision", 6),
        ("attendance_contract_owner", 7),
        ("attendance_contract_schema_id", 8),
        ("attendance_contract_revision", 9),
        ("input_review_revision", 10),
        ("capture_review_revision", 11),
        ("release_signing_topology_revision", 12),
        ("vocabulary_manifest_digest", 13),
        ("vocabulary_source_lock_digest", 14),
        ("vocabulary_computed_artifact_digest", 15),
    ];
    for (gate, _) in fields {
        let mut inputs = complete.inputs.clone();
        match gate {
            "computer_action_vocabulary_revision" => {
                inputs.computer_action_vocabulary_revision = None
            }
            "cerebellum_core_contract_revision" => inputs.cerebellum_core_contract_revision = None,
            "c2_journal_pin_schema_id" => inputs.c2_journal_pin_schema_id = None,
            "c2_journal_pin_revision" => inputs.c2_journal_pin_revision = None,
            "process_identity_primitive_revision" => {
                inputs.process_identity_primitive_revision = None
            }
            "capture_residual_leakage_revision" => inputs.capture_residual_leakage_revision = None,
            "permission_matrix_revision" => inputs.permission_matrix_revision = None,
            "attendance_contract_owner" => inputs.attendance_contract_owner = None,
            "attendance_contract_schema_id" => inputs.attendance_contract_schema_id = None,
            "attendance_contract_revision" => inputs.attendance_contract_revision = None,
            "input_review_revision" => inputs.input_review_revision = None,
            "capture_review_revision" => inputs.capture_review_revision = None,
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
        assert!(
            evidence.gate_outcomes.iter().any(|outcome| {
                matches!(
                    outcome,
                    ComputerGateOutcome::MissingExternalInput { gate: found } if found == gate
                )
            }),
            "missing pin {gate} must remain externally unresolved"
        );
        // Gate behaviour is asserted against the capabilities the GATES admit,
        // which is what this test is about. Advertisement additionally requires
        // that dispatch can serve the capability, and no computer capability is
        // dispatchable yet -- so reading the advertised set here would make every
        // gate look equally closed and prove nothing about which one closed.
        let advertised = evidence.gate_admitted_capabilities;
        if matches!(
            gate,
            "attendance_contract_owner"
                | "attendance_contract_schema_id"
                | "attendance_contract_revision"
                | "input_review_revision"
        ) {
            // These pins apply to the currently unadvertised input declarations;
            // the read-only rows remain available, while the affected input
            // capability is absent from the manifest.
            assert!(!advertised.iter().any(|id| id == "computer.click"));
            assert!(advertised.iter().any(|id| id == "computer.wait"));
        } else if matches!(
            gate,
            "process_identity_primitive_revision"
                | "capture_residual_leakage_revision"
                | "permission_matrix_revision"
                | "capture_review_revision"
                | "release_signing_topology_revision"
        ) {
            assert!(!advertised.iter().any(|id| id == "computer.screenshot"));
            assert!(advertised.iter().any(|id| id == "computer.wait"));
        } else {
            assert!(
                advertised.is_empty(),
                "common missing pin {gate} must suppress rows"
            );
        }
    }
}

#[test]
fn supplied_incompatible_pin_is_an_implementation_failure_not_an_unresolved_input() {
    let mut inputs = valid_inputs();
    inputs.c2_journal_pin_revision = Some("wrong-revision".into());
    let context = ComputerCapabilityAdvertisementContext {
        inputs,
        permissions: valid_context().permissions,
        startup: valid_context().startup,
    };
    let evidence = computer_release_evidence(&context);
    assert!(evidence.gate_outcomes.iter().any(|outcome| {
        matches!(
            outcome,
            ComputerGateOutcome::ImplementationFailure { gate } if gate == "c2_journal_pin_revision"
        )
    }));
    assert!(!evidence.gate_outcomes.iter().any(|outcome| {
        matches!(
            outcome,
            ComputerGateOutcome::MissingExternalInput { gate } if gate == "c2_journal_pin_revision"
        )
    }));
    assert!(
        tools(&build_manifest_with_computer_plane("cerebellum", &context))
            .iter()
            .all(|tool| !tool.name.starts_with("computer."))
    );
}
