use std::collections::BTreeSet;

use serde_json::{json, Value};

const VOCABULARY: &str = include_str!("../resources/computer_action_vocabulary-v5.json");

use cerebellum_computer::platform::{
    attributed_permission_liveness, capability_declarations, computed_vocabulary_sha256,
    implementation_source_lock_digest, validate_vocabulary, validate_vocabulary_digests,
    CapabilityAdvertisementContext, ImmutableReleaseInputs, PermissionLiveness,
    PermissionLivenessProbe, PermissionLivenessReport, PermissionProbeResult, PermissionService,
    StartupCapabilityProbe, VocabularyDigestInputs, COMPUTER_ACTION_VOCABULARY_SHA256,
};
#[cfg(target_os = "macos")]
use cerebellum_computer::platform::{MacOs26PlatformDriver, StartupProbeInput};

#[test]
fn vocabulary_has_exactly_eight_rows_and_locked_digest() {
    let validated = validate_vocabulary().expect("frozen vocabulary must validate");
    assert_eq!(validated.revision, "computer_action_vocabulary-v5");
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
fn implementation_source_lock_digest_matches_the_v5_artifact() {
    assert_eq!(
        implementation_source_lock_digest().as_deref(),
        Some(COMPUTER_ACTION_VOCABULARY_SHA256)
    );
}

#[test]
fn computer_click_action_is_optional_and_closed_to_press_and_cancel() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let click = vocabulary["rows"]
        .as_array()
        .expect("the vocabulary has rows")
        .iter()
        .find(|row| row["capability_id"] == "computer.click")
        .expect("the vocabulary contains computer.click");
    let request = &click["request_schema"];

    assert_eq!(
        request["properties"]["action"]["enum"],
        json!(["AXPress", "AXCancel"])
    );
    assert!(
        !request["required"]
            .as_array()
            .expect("the request schema names required fields")
            .contains(&json!("action")),
        "omitting action must preserve the historical AXPress default"
    );
}

#[test]
fn macos_action_catalog_matches_the_authored_table() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let click = vocabulary["rows"]
        .as_array()
        .expect("the vocabulary has rows")
        .iter()
        .find(|row| row["capability_id"] == "computer.click")
        .expect("the vocabulary contains computer.click");
    let catalog = &click["request_schema"]["properties"]["action"]["catalog"];

    assert_eq!(
        catalog["entries"],
        json!([
            {"action":"AXPress","disruption_level":2,"level_evidence":"measured","served":true},
            {"action":"AXCancel","disruption_level":2,"level_evidence":"doc_derived","served":true},
            {"action":"AXConfirm","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXPick","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXShowMenu","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXShowAlternateUI","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXShowDefaultUI","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXRaise","disruption_level":4,"level_evidence":"doc_derived","served":false},
            {"action":"AXIncrement","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXDecrement","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXDelete","disruption_level":4,"level_evidence":"conservative_default","served":false},
            {"action":"AXScrollToVisible","disruption_level":4,"level_evidence":"conservative_default","served":false},
        ])
    );
    assert_eq!(
        catalog["demotion_rule"],
        "An unserved conservative default MUST be measured in the same migration that first serves it. There is no serve-at-4-and-measure-later path: without this, the laundering risk returns as schedule pressure — a shipped action sitting at a conservative level with the measurement owed and nothing forcing it."
    );
}

#[test]
fn every_unserved_macos_action_is_absent_from_the_admitted_set() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let click = vocabulary["rows"]
        .as_array()
        .expect("the vocabulary has rows")
        .iter()
        .find(|row| row["capability_id"] == "computer.click")
        .expect("the vocabulary contains computer.click");
    let action = &click["request_schema"]["properties"]["action"];
    let admitted = action["enum"]
        .as_array()
        .expect("the admitted actions are an enum");
    let entries = action["catalog"]["entries"]
        .as_array()
        .expect("the action catalog has entries");

    for entry in entries {
        if entry["served"] == false {
            let name = entry["action"].as_str().expect("an action name");
            assert!(
                !admitted.contains(&json!(name)),
                "unserved action {name} is present in the admitted set"
            );
        }
    }
}

#[test]
fn click_query_and_wait_settle_markers_are_closed_to_v5_values() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let rows = vocabulary["rows"].as_array().expect("rows");
    let click = rows
        .iter()
        .find(|row| row["capability_id"] == "computer.click")
        .expect("click");
    let wait = rows
        .iter()
        .find(|row| row["capability_id"] == "computer.wait")
        .expect("wait");
    let screenshot = rows
        .iter()
        .find(|row| row["capability_id"] == "computer.screenshot")
        .expect("screenshot");
    let click_request = &click["request_schema"];
    let click_result = &click["result_schema"];
    let post_action_query = &click_request["properties"]["post_action_query"];
    let post_action_state = &click_result["properties"]["post_action_state"];

    assert!(!click_request["required"]
        .as_array()
        .expect("click required fields")
        .contains(&json!("post_action_query")));
    assert_eq!(post_action_query["properties"]["elements"]["maxItems"], 8);
    assert_eq!(
        post_action_query["properties"]["attributes"]["items"]["enum"],
        json!(["presence", "focused", "enabled", "value"])
    );
    assert_eq!(
        post_action_state["required"],
        json!([
            "status",
            "elements",
            "read_after_action_ms",
            "unreadable_subtrees"
        ])
    );
    assert_eq!(
        post_action_state["properties"]["status"]["enum"],
        json!([
            "read",
            "target_gone",
            "tree_unreadable",
            "deadline_exceeded"
        ])
    );
    assert!(click_result["required"]
        .as_array()
        .expect("click result required fields")
        .contains(&json!("unreadable_subtrees")));
    assert_eq!(
        wait["result_schema"]["properties"]["outcome"]["enum"],
        json!(["predicate_satisfied", "timeout", "indeterminate"])
    );
    assert_eq!(
        wait["result_schema"]["properties"]["settle_path"]["enum"],
        json!(["poll_with_deadline"])
    );
    assert_eq!(
        screenshot["request_schema"]["properties"]["region"]["description"],
        "Rectangle cropped from the target window in the window's own pixels, with a top-left origin; single-window capture honors this rectangle."
    );
}

#[cfg(target_os = "macos")]
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
    let report = PermissionLivenessProbe {
        responsible_process: "ck-subc".to_string(),
    }
    .run(&[PermissionProbeResult {
        service: PermissionService::ScreenRecording,
        liveness: PermissionLiveness::Live,
        responsible_process: "some-other-launcher".to_string(),
        off_main: true,
    }]);
    assert_eq!(
        report.state(PermissionService::ScreenRecording),
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
    let results = [
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
    ];
    let report = attributed_permission_liveness(None, &results);
    for service in [
        PermissionService::ScreenRecording,
        PermissionService::Accessibility,
    ] {
        assert_eq!(
            report.state(service),
            PermissionLiveness::Unresolved,
            "{service:?} was credited without an established attribution"
        );
    }
}

#[test]
fn observed_move_is_the_only_global_cursor_capability_in_the_skeleton() {
    let context = CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs::default(),
        permissions: PermissionLivenessReport::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let declarations = capability_declarations(&context, false, true);
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
