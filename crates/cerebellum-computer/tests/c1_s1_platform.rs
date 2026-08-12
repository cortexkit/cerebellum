use std::collections::BTreeSet;

use cerebellum_computer::platform::{
    computed_vocabulary_sha256, validate_vocabulary, validate_vocabulary_digests,
    CapabilityAdvertisementContext, ImmutableReleaseInputs, MacOs26PlatformDriver,
    PermissionLiveness, PermissionLivenessReport, PermissionProbeResult, PermissionService,
    StartupProbeInput, VocabularyDigestInputs, COMPUTER_ACTION_VOCABULARY_SHA256,
};

#[test]
fn vocabulary_has_exactly_eight_rows_and_locked_digest() {
    let validated = validate_vocabulary().expect("frozen vocabulary must validate");
    assert_eq!(validated.row_count, 8);
    assert_eq!(validated.row_count, 8, "absolute row-count invariant");
    assert_eq!(validated.sha256, COMPUTER_ACTION_VOCABULARY_SHA256);
    assert_eq!(
        computed_vocabulary_sha256(),
        COMPUTER_ACTION_VOCABULARY_SHA256
    );
}

#[test]
fn vocabulary_requires_all_three_digest_sources() {
    let digest = computed_vocabulary_sha256();
    let inputs = VocabularyDigestInputs {
        manifest_digest: Some(digest.clone()),
        source_lock_digest: Some(digest.clone()),
        computed_artifact_digest: Some(digest),
    };
    validate_vocabulary_digests(&inputs).expect("manifest, source lock, and artifact must agree");
    assert!(validate_vocabulary_digests(&VocabularyDigestInputs::default()).is_err());
}

#[test]
fn startup_probe_is_fail_closed_for_private_envelope_and_permission_liveness() {
    // The grant is attributed to the launching process rather than to this
    // module, so the fixture names a launcher. A fixture naming the module
    // would agree with any code that assumed the same thing.
    let input = StartupProbeInput {
        os_major: 26,
        private_envelope_revision: Some("skylight-macos26-v1".to_string()),
        resolved_private_symbols: ["SLEventPostToPid".to_string()].into_iter().collect(),
        permission_results: vec![PermissionProbeResult {
            service: PermissionService::ScreenRecording,
            liveness: PermissionLiveness::Live,
            responsible_process: "ck-subc".to_string(),
            off_main: true,
        }],
        responsible_process: Some("ck-subc".to_string()),
    };
    let driver = MacOs26PlatformDriver::new(&input);
    assert!(driver.startup_probe().private_envelope_recognized);
    assert_eq!(
        driver
            .startup_probe()
            .permissions
            .state(PermissionService::ScreenRecording),
        PermissionLiveness::Live
    );

    let unresolved = ImmutableReleaseInputs {
        vocabulary_digests: VocabularyDigestInputs {
            manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
            source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
            computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
        },
        ..ImmutableReleaseInputs::default()
    };
    let declarations = driver.declarations(&CapabilityAdvertisementContext {
        inputs: unresolved,
        permissions: PermissionLivenessReport::default(),
        startup: driver.startup_probe().clone(),
    });
    assert_eq!(declarations.len(), 8);
    assert_eq!(
        declarations
            .iter()
            .filter(|declaration| declaration.advertised)
            .count(),
        1
    );
    assert!(declarations.iter().any(|declaration| {
        declaration.capability_id == "computer.wait" && declaration.advertised
    }));
    assert!(declarations
        .iter()
        .filter(|declaration| declaration.capability_id != "computer.wait")
        .all(|declaration| !declaration.advertised));
}

/// A grant belonging to some other process is not evidence about ours.
///
/// The probe filters by the process the system attributes grants to, so a
/// result naming a different one is discarded and the service reads as
/// unresolved. Without this, the filter could be deleted and every existing
/// case would still pass, because they all supply a matching process.
#[test]
fn a_grant_attributed_to_another_process_is_not_counted() {
    let input = StartupProbeInput {
        os_major: 26,
        private_envelope_revision: None,
        resolved_private_symbols: Default::default(),
        permission_results: vec![PermissionProbeResult {
            service: PermissionService::ScreenRecording,
            liveness: PermissionLiveness::Live,
            responsible_process: "some-other-launcher".to_string(),
            off_main: true,
        }],
        responsible_process: Some("ck-subc".to_string()),
    };
    let driver = MacOs26PlatformDriver::new(&input);
    assert_eq!(
        driver
            .startup_probe()
            .permissions
            .state(PermissionService::ScreenRecording),
        PermissionLiveness::Unresolved
    );
}

/// Until the attribution is established, no grant can be credited to us.
///
/// Not knowing which process holds our grants is different from knowing and
/// finding no match, but both must refuse: a live result cannot be counted
/// when there is nothing to check it against.
///
/// The results deliberately name DIFFERENT processes, one of them this module.
/// A single name would let the check pass for the wrong reason, since a
/// substituted default would discard a result naming anything else and reach
/// the same answer by filtering rather than by refusing.
#[test]
fn an_unestablished_attribution_counts_no_grant_at_all() {
    let input = StartupProbeInput {
        os_major: 26,
        private_envelope_revision: None,
        resolved_private_symbols: Default::default(),
        permission_results: vec![
            PermissionProbeResult {
                service: PermissionService::ScreenRecording,
                liveness: PermissionLiveness::Live,
                responsible_process: "ck-subc".to_string(),
                off_main: true,
            },
            PermissionProbeResult {
                service: PermissionService::Accessibility,
                liveness: PermissionLiveness::Live,
                responsible_process: "cerebellum-computer".to_string(),
                off_main: true,
            },
        ],
        responsible_process: None,
    };
    let driver = MacOs26PlatformDriver::new(&input);
    for service in [
        PermissionService::ScreenRecording,
        PermissionService::Accessibility,
    ] {
        assert_eq!(
            driver.startup_probe().permissions.state(service),
            PermissionLiveness::Unresolved,
            "{service:?} was credited without an established attribution"
        );
    }
}

#[test]
fn observed_move_is_the_only_global_cursor_capability_in_the_skeleton() {
    let driver = MacOs26PlatformDriver::default();
    let context = CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs::default(),
        permissions: PermissionLivenessReport::default(),
        startup: driver.startup_probe().clone(),
    };
    let declarations = driver.declarations(&context);
    let move_declaration = declarations
        .iter()
        .find(|item| item.capability_id == "computer.move")
        .unwrap();
    assert_eq!(move_declaration.dispatch_modes.len(), 1);
    assert_eq!(
        move_declaration.dispatch_modes[0],
        cerebellum_computer::platform::DispatchMode::Observed
    );
    let ids: BTreeSet<_> = declarations
        .iter()
        .map(|item| item.capability_id.as_str())
        .collect();
    assert_eq!(ids.len(), 8);
}
