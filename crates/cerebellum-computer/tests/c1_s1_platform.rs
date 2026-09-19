use std::collections::BTreeSet;

use cerebellum_computer::platform::{
    attributed_permission_liveness, canonical_json_bytes, capability_declarations,
    computed_vocabulary_sha256, delivered_semantic_action, implementation_source_lock_digest,
    validate_vocabulary, validate_vocabulary_digests, CapabilityAdvertisementContext,
    ImmutableReleaseInputs, PermissionLiveness, PermissionLivenessProbe, PermissionLivenessReport,
    PermissionProbeResult, PermissionService, SemanticActionIntent, SemanticActionPlatform,
    StartupCapabilityProbe, VocabularyDigestInputs, COMPUTER_ACTION_VOCABULARY_REVISION,
    COMPUTER_ACTION_VOCABULARY_SHA256,
};
#[cfg(target_os = "macos")]
use cerebellum_computer::platform::{MacOs26PlatformDriver, StartupProbeInput};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const VOCABULARY: &str = include_str!("../resources/computer_action_vocabulary-v10.json");
const V7_ARTIFACT_SHA256: &str = "6548025a7f99bf0984651d0345a962baf792d9428274e8f262542509e61674af";
const SYNTHETIC_CAPABILITIES: [&str; 5] = [
    "computer.type",
    "computer.keys",
    "computer.scroll",
    "computer.move",
    "computer.drag",
];
const SYNTHETIC_REFUSAL_FIELDS: [&str; 4] = ["chord", "field", "reason", "remedy"];

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn vocabulary_has_exactly_eight_rows_and_locked_digest() {
    let validated = validate_vocabulary().expect("frozen vocabulary must validate");
    assert_eq!(validated.revision, "computer_action_vocabulary-v10");
    assert_eq!(validated.row_count, 8);
    assert_eq!(validated.row_count, 8, "absolute row-count invariant");
    assert_eq!(validated.sha256, COMPUTER_ACTION_VOCABULARY_SHA256);
    assert_eq!(
        computed_vocabulary_sha256(),
        COMPUTER_ACTION_VOCABULARY_SHA256
    );
}

#[test]
fn every_repository_vocabulary_mirror_names_the_current_revision() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    // Git enumerates repository inputs, including new untracked files. Its ignore
    // rules exclude build outputs and local state, which are not source mirrors.
    // No source directory, extension, or individual mirror is exempted.
    let listing = std::process::Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(root)
        .output()
        .expect("enumerate repository files");
    assert!(
        listing.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let listing = String::from_utf8(listing.stdout).expect("UTF-8 repository paths");
    let paths: BTreeSet<_> = listing
        .split('\0')
        .filter(|path| !path.is_empty())
        .collect();
    // Assemble the search token so the scanner does not mistake its own pattern
    // for an artifact reference with a missing revision number.
    let prefix = concat!("computer_action_vocabulary", "-v").as_bytes();
    let mut mirrors = BTreeSet::new();
    let mut references = 0;
    let mut stale = Vec::new();
    for path in paths {
        let bytes = match std::fs::read(root.join(path)) {
            Ok(bytes) => bytes,
            // An unstaged deletion still appears in the index but is no longer
            // a live mirror; the next mint intentionally removes the old artifact.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("cannot inspect {path}: {error}"),
        };
        for (offset, _) in bytes
            .windows(prefix.len())
            .enumerate()
            .filter(|(_, window)| *window == prefix)
        {
            mirrors.insert(path);
            references += 1;
            let end = offset
                + prefix.len()
                + bytes[offset + prefix.len()..]
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .count();
            let found = &bytes[offset..end];
            if found != COMPUTER_ACTION_VOCABULARY_REVISION.as_bytes() {
                let line = bytes[..offset]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count()
                    + 1;
                stale.push(format!("{path}:{line}: {}", String::from_utf8_lossy(found)));
            }
        }
    }
    assert!(
        !mirrors.is_empty(),
        "repository scan found no vocabulary mirrors"
    );
    println!(
        "{} mirror files, {references} revision references: {mirrors:?}",
        mirrors.len()
    );
    assert!(
        stale.is_empty(),
        "vocabulary mirrors must name {COMPUTER_ACTION_VOCABULARY_REVISION}:\n{}",
        stale.join("\n")
    );
}

// Historical digest tests reconstruct old documents, not live artifact mirrors.
// Build their revision labels from the shared stem rather than embedding stale
// artifact names that would be indistinguishable from forgotten live references.
fn historical_revision(revision: u32) -> Value {
    let (stem, _) = COMPUTER_ACTION_VOCABULARY_REVISION
        .rsplit_once("-v")
        .unwrap();
    json!(format!("{stem}-v{revision}"))
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
fn implementation_source_lock_digest_matches_the_v8_artifact() {
    assert_eq!(
        implementation_source_lock_digest().as_deref(),
        Some(COMPUTER_ACTION_VOCABULARY_SHA256)
    );
}

#[test]
fn every_synthetic_row_declares_all_refusal_fields_without_requiring_them() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let mut checked = 0;
    for row in vocabulary["rows"].as_array().expect("rows") {
        let capability = row["capability_id"]
            .as_str()
            .expect("every row has a capability id");
        if !SYNTHETIC_CAPABILITIES.contains(&capability) {
            continue;
        }
        checked += 1;
        let properties = row["result_schema"]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{capability} has result properties"));
        let required = row["result_schema"]["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{capability} has result required fields"));
        for field in SYNTHETIC_REFUSAL_FIELDS {
            let property = properties
                .get(field)
                .unwrap_or_else(|| panic!("{capability} does not declare result field {field}"));
            assert_eq!(
                property["type"], "string",
                "{capability}.{field} must be a string"
            );
            let description = property["description"]
                .as_str()
                .unwrap_or_else(|| panic!("{capability}.{field} needs a description"));
            assert!(
                !description.is_empty(),
                "{capability}.{field} has an empty description"
            );
            assert!(
                !required.iter().any(|name| name.as_str() == Some(field)),
                "{capability}.{field} must remain optional"
            );
            if field == "chord" {
                assert!(
                    description.contains("hard-blocklist"),
                    "{capability}.chord does not mention the upcoming hard-blocklist slice"
                );
            }
        }
    }
    assert_eq!(
        checked,
        SYNTHETIC_CAPABILITIES.len(),
        "the five synthetic rows were not all checked"
    );
}

#[test]
fn v8_only_adds_refusal_fields_to_the_five_synthetic_rows() {
    let mut before = recreated_v8();
    before["revision"] = historical_revision(7);
    for row in before["rows"].as_array_mut().expect("rows") {
        let capability = row["capability_id"]
            .as_str()
            .expect("every row has a capability id")
            .to_owned();
        if SYNTHETIC_CAPABILITIES.contains(&capability.as_str()) {
            let properties = row["result_schema"]["properties"]
                .as_object_mut()
                .unwrap_or_else(|| panic!("{capability} has result properties"));
            for field in SYNTHETIC_REFUSAL_FIELDS {
                properties.remove(field);
            }
        }
    }
    let recreated_v7 = canonical_json_bytes(&before).expect("the recreated v7 is canonical");
    assert_eq!(
        hex_digest(&recreated_v7),
        V7_ARTIFACT_SHA256,
        "v8 changed a row or field outside the five synthetic refusal additions"
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
        json!(["press", "cancel"])
    );
    assert!(
        !request["required"]
            .as_array()
            .expect("the request schema names required fields")
            .contains(&json!("action")),
        "omitting action must preserve the historical press default"
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
    let admitted_platform_actions = action["enum"]
        .as_array()
        .expect("the admitted actions are an enum")
        .iter()
        .map(|name| {
            let intent = SemanticActionIntent::from_wire_name(
                name.as_str().expect("an admitted intent is a string"),
            )
            .expect("the wire enum contains only known intents");
            json!(
                delivered_semantic_action(SemanticActionPlatform::MacOs, intent)
                    .expect("macOS serves every admitted click intent")
            )
        })
        .collect::<Vec<_>>();
    let entries = action["catalog"]["entries"]
        .as_array()
        .expect("the action catalog has entries");

    for entry in entries {
        if entry["served"] == false {
            let name = entry["action"].as_str().expect("an action name");
            assert!(
                !admitted_platform_actions.contains(&json!(name)),
                "unserved action {name} is present in the admitted set"
            );
        }
    }
}

#[test]
fn click_query_and_wait_settle_markers_are_closed_to_v10_values() {
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
        json!([
            "predicate_satisfied",
            "timeout",
            "indeterminate",
            "cancelled"
        ])
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
    let declarations = capability_declarations(&context, true);
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

fn recreated_v9() -> Value {
    let mut before: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    before["revision"] = historical_revision(9);
    let wait = before["rows"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["capability_id"] == "computer.wait")
        .unwrap();
    let properties = wait["result_schema"]["properties"].as_object_mut().unwrap();
    properties.remove("attempts");
    properties["outcome"]
        .as_object_mut()
        .unwrap()
        .remove("description");
    properties["outcome"]["enum"]
        .as_array_mut()
        .unwrap()
        .retain(|v| v != "cancelled");
    before
}

#[test]
fn v10_only_adds_wait_cancellation_and_read_counts() {
    let bytes = canonical_json_bytes(&recreated_v9()).unwrap();
    assert_eq!(
        hex_digest(&bytes),
        "9018f851fa4af09a2b23d2675b14b9e11398c5cf4cfca20f51172dd609e7980c"
    );
}

fn recreated_v8() -> Value {
    let mut before = recreated_v9();
    before["revision"] = historical_revision(8);
    for row in before["rows"].as_array_mut().expect("rows") {
        let capability = row["capability_id"].as_str().unwrap().to_owned();
        if SYNTHETIC_CAPABILITIES.contains(&capability.as_str()) {
            row["result_schema"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("posts_returned");
        }
        if matches!(capability.as_str(), "computer.move" | "computer.drag") {
            row["result_schema"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("containment_rung");
        }
    }
    before
}

#[test]
fn v9_only_adds_sequence_counts_and_missing_containment_rungs() {
    let bytes = canonical_json_bytes(&recreated_v8()).unwrap();
    assert_eq!(
        hex_digest(&bytes),
        "39061e07424d404695e0da6b06e6ce732a60136361267d77562ad276c9b95906"
    );
}
