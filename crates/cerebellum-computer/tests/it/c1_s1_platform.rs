use std::collections::BTreeSet;

use super::vocabulary_mint;

use cerebellum_computer::platform::{
    attributed_permission_liveness, canonical_json_bytes, capability_declarations,
    computed_vocabulary_sha256, implementation_source_lock_digest, validate_vocabulary,
    validate_vocabulary_digests, CapabilityAdvertisementContext, ImmutableReleaseInputs,
    PermissionLiveness, PermissionLivenessProbe, PermissionLivenessReport, PermissionProbeResult,
    PermissionService, StartupCapabilityProbe, VocabularyDigestInputs,
    COMPUTER_ACTION_VOCABULARY_REVISION, COMPUTER_ACTION_VOCABULARY_SHA256,
};
#[cfg(target_os = "macos")]
use cerebellum_computer::platform::{MacOs26PlatformDriver, StartupProbeInput};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const VOCABULARY: &str = include_str!("../../resources/computer_action_vocabulary-v36.json");
const V33_ARTIFACT_SHA256: &str =
    "bec5b6cad004606960c684bafea3c7b219fc780cec9630158c29ff935833c849";
const V34_ARTIFACT_SHA256: &str =
    "7c36bfd082d83e1dd24db1fcf9110eb58c1ad2059aeea7b9b4068f7c9c0ab4bd";
const V35_ARTIFACT_SHA256: &str =
    "53779c253a1ceae727b8a19b1fe3bded97b88523ba33bfdb7630fb778877cfeb";
/// The digests of retained historical artifacts: operator-app refusal, image
/// handles and terminal-keystroke result envelopes, respectively.
const V30_ARTIFACT_SHA256: &str =
    "b0b9b5aab421dd5c5380ddfef0580168f485af8bc44a3b7991898b96d144a906";
const V31_ARTIFACT_SHA256: &str =
    "bfd49ebcfc9166f1ed41754ea7b9a18606567e046c1c2f6e8a9bce1ba2d07943";
const V32_ARTIFACT_SHA256: &str =
    "a848a0634cf825af7b02d5e1fd3f3af7c9bf2cde9673ada0a8cf746d8aac8b5e";
const V13_ARTIFACT_SHA256: &str =
    "df4dd2cae84214efad94c3e3ce83537abc284252c8375e49ba151afe416c62fc";
/// The digest of the v14 artifact, measured before v15 was minted.
const V14_ARTIFACT_SHA256: &str =
    "81084b233027765c4466b93247827bd2d5f488f479993b2b43dd0524346ba5a1";
const V7_ARTIFACT_SHA256: &str = "6548025a7f99bf0984651d0345a962baf792d9428274e8f262542509e61674af";
/// The digest of the v12 artifact, measured before v13 was minted.
const V12_ARTIFACT_SHA256: &str =
    "a820c3519c72bdedf0c7604f8f30531411d4538345e63fc160835aabcb422bfa";
/// The five rows v12 carried and v13 removed, exactly as v12 wrote them. The
/// delta chain needs them to rebuild v12, and they exist nowhere else now.
const RETIRED_V12_ROWS: &str = include_str!("../fixtures/v12_retired_rows.json");
/// The keystroke rows the current vocabulary serves.
const SYNTHETIC_CAPABILITIES: [&str; 2] = ["computer.type", "computer.keys"];
/// The five synthetic rows of revisions 8 through 12, which the historical
/// digest chain below subtracts from.
const HISTORICAL_SYNTHETIC_CAPABILITIES: [&str; 5] = [
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
fn vocabulary_has_exactly_thirteen_rows_and_locked_digest() {
    let validated = validate_vocabulary().expect("frozen vocabulary must validate");
    assert_eq!(validated.revision, COMPUTER_ACTION_VOCABULARY_REVISION);
    assert_eq!(validated.schema_id, "ck-computer-action-vocabulary/v2");
    assert_eq!(validated.row_count, 13, "absolute row-count invariant");
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
        // The retained frozen artifact is historical evidence, not an active mirror.
        // Pin its bytes before exempting only that exact path from the active scan.
        if path
            == format!(
                "crates/cerebellum-computer/resources/{}.json",
                historical_revision(13).as_str().unwrap()
            )
        {
            assert_eq!(hex_digest(&bytes), V13_ARTIFACT_SHA256);
            continue;
        }
        // Every other revision's artifact is history too, and is pinned the
        // same way rather than read as a live mirror: only the newest file
        // may name the current revision.
        if path.starts_with("crates/cerebellum-computer/resources/computer_action_vocabulary")
            && !path.ends_with(format!("{COMPUTER_ACTION_VOCABULARY_REVISION}.json").as_str())
        {
            let expected = if path.ends_with("v30.json") {
                V30_ARTIFACT_SHA256
            } else if path.ends_with("v31.json") {
                V31_ARTIFACT_SHA256
            } else if path.ends_with("v32.json") {
                V32_ARTIFACT_SHA256
            } else if path.ends_with("v33.json") {
                V33_ARTIFACT_SHA256
            } else if path.ends_with("v34.json") {
                V34_ARTIFACT_SHA256
            } else if path.ends_with("v35.json") {
                V35_ARTIFACT_SHA256
            } else {
                panic!("{path} is a vocabulary artifact with no pinned digest")
            };
            assert_eq!(hex_digest(&bytes), expected, "{path}");
            continue;
        }
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
fn implementation_source_lock_digest_matches_the_artifact() {
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
                    "{capability}.chord does not mention the hard-blocklist check"
                );
            }
        }
    }
    assert_eq!(
        checked,
        SYNTHETIC_CAPABILITIES.len(),
        "the keystroke rows were not all checked"
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
        if HISTORICAL_SYNTHETIC_CAPABILITIES.contains(&capability.as_str()) {
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
fn wait_settle_markers_are_closed_to_their_values() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let wait = vocabulary["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["capability_id"] == "computer.wait")
        .expect("wait");
    assert_eq!(
        wait["result_schema"]["properties"]["settle_path"]["enum"],
        json!(["poll_with_deadline"])
    );
    let outcomes = wait["result_schema"]["properties"]["outcome"]["enum"]
        .as_array()
        .expect("wait outcomes are closed");
    for outcome in [
        "predicate_satisfied",
        "timeout",
        "indeterminate",
        "cancelled",
    ] {
        assert!(outcomes.contains(&json!(outcome)), "{outcome}");
    }
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
    assert_eq!(declarations.len(), 13);
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
fn the_takeover_rows_are_the_only_observed_only_capabilities() {
    let context = CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs::default(),
        permissions: PermissionLivenessReport::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let declarations = capability_declarations(&context, true);
    let observed_only: Vec<_> = declarations
        .iter()
        .filter(|item| {
            item.dispatch_modes == [cerebellum_computer::platform::DispatchMode::Observed]
        })
        .map(|item| item.capability_id.as_str())
        .collect();
    assert_eq!(
        observed_only,
        [
            "computer.takeover_move",
            "computer.takeover_click",
            "computer.takeover_drag",
            "computer.takeover_scroll"
        ]
    );
    let ids: BTreeSet<_> = declarations
        .iter()
        .map(|item| item.capability_id.as_str())
        .collect();
    assert_eq!(ids.len(), 13);
}

fn recreated_v9() -> Value {
    // Built from v10 rather than from the shipped artifact, because the chain
    // subtracts one revision at a time. Starting from v11 would leave this
    // revision's addition standing and quietly change what every older digest
    // below is compared against.
    let mut before = recreated_v10();
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

/// v12 without its one addition: the element shape of the `windows` array.
fn recreated_v11() -> Value {
    let mut before: Value = recreated_v12();
    before["revision"] = historical_revision(11);
    let screenshot = before["rows"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["capability_id"] == "computer.screenshot")
        .unwrap();
    screenshot["result_schema"]["properties"]["windows"]
        .as_object_mut()
        .unwrap()
        .remove("items");
    before
}

/// v11 without its one addition: the window-enumeration disclosure.
fn recreated_v10() -> Value {
    let mut before: Value = recreated_v11();
    before["revision"] = historical_revision(10);
    let screenshot = before["rows"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["capability_id"] == "computer.screenshot")
        .unwrap();
    screenshot["result_schema"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("windows_enumeration");
    screenshot["result_schema"]["required"]
        .as_array_mut()
        .unwrap()
        .retain(|v| v != "windows_enumeration");
    before
}

/// v11 adds the window-enumeration disclosure and nothing else.
///
/// The digest on the right is v10's, measured before the mint. Subtracting the
/// one field must reproduce it exactly: if anything else moved -- a
/// description reworded, a row reordered, a number reformatted -- this fails,
/// which is the point of stating a revision's change as a subtraction rather
/// than as prose.
#[test]
fn v11_only_adds_the_window_enumeration_disclosure() {
    let bytes = canonical_json_bytes(&recreated_v10()).unwrap();
    assert_eq!(
        hex_digest(&bytes),
        "27b891258a29e2a392e971597901636137648febe3c0c40dc3718d7a4f44fd2a"
    );
}

/// v12 declares the element shape of `windows` and nothing else.
///
/// The digest on the right is v11's, measured before the mint. Subtracting the
/// one `items` schema must reproduce it exactly.
#[test]
fn v12_only_declares_the_windows_element_shape() {
    let bytes = canonical_json_bytes(&recreated_v11()).unwrap();
    assert_eq!(
        hex_digest(&bytes),
        "053e41a737daf472412987b745ef056c07ab8808b1b8bcd65c526ab9e6beaba4"
    );
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
        if HISTORICAL_SYNTHETIC_CAPABILITIES.contains(&capability.as_str()) {
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

fn row<'a>(vocabulary: &'a Value, id: &str) -> &'a Value {
    vocabulary["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["capability_id"] == id)
        .unwrap_or_else(|| panic!("the vocabulary carries {id}"))
}

fn row_mut<'a>(vocabulary: &'a mut Value, id: &str) -> &'a mut Value {
    vocabulary["rows"]
        .as_array_mut()
        .expect("rows")
        .iter_mut()
        .find(|row| row["capability_id"] == id)
        .unwrap_or_else(|| panic!("the vocabulary carries {id}"))
}

fn remove_properties(row: &mut Value, schema: &str, names: &[&str]) {
    let properties = row[schema]["properties"].as_object_mut().unwrap();
    for name in names {
        assert!(
            properties.remove(*name).is_some(),
            "{schema}.{name} is a v13 addition"
        );
    }
}

/// v13 without its changes: the v12 artifact, rebuilt from the shipped one.
///
/// Every change v13 makes is undone here by name. The five rows v13 removed
/// come back from a fixture holding them as v12 wrote them, since they exist
/// nowhere else now.
fn recreated_v12() -> Value {
    let mut v13 = recreated_v13();

    // Every retained row gained the screen-lock disclosure, and its outcome
    // description the sentence naming the screen_locked refusal. The keystroke
    // rows' outcome is replaced whole below; wait's keeps its v12 wording.
    for id in ["computer.type", "computer.keys", "computer.wait"] {
        remove_properties(
            row_mut(&mut v13, id),
            "result_schema",
            &["screen_lock_state"],
        );
    }
    let wait_outcome = &mut row_mut(&mut v13, "computer.wait")["result_schema"]["properties"]
        ["outcome"]["description"];
    let v12_description = wait_outcome
        .as_str()
        .unwrap()
        .split(" screen_locked means")
        .next()
        .unwrap()
        .to_owned();
    *wait_outcome = json!(v12_description);

    // The keystroke rows gained the consent envelope, the bundle-resolution
    // fields, the diff with its truncation and unreadable count, the focused
    // element, and their outcome a description of the v13 outcomes.
    for id in ["computer.type", "computer.keys"] {
        let keystroke = row_mut(&mut v13, id);
        remove_properties(
            keystroke,
            "result_schema",
            &[
                "ask_id",
                "grant_persisted",
                "bundle_identity",
                "instances",
                "unreadable",
                "changed",
                "added",
                "removed",
                "focused_element_id",
                "truncation",
                "unreadable_subtrees",
            ],
        );
        keystroke["result_schema"]["properties"]["outcome"] = json!({"type": "string"});
    }
    // type lost its parsed-and-unused replace_selection flag.
    let typing = row_mut(&mut v13, "computer.type");
    typing["request_schema"]["properties"]["replace_selection"] = json!({"type": "boolean"});
    typing["request_schema"]["required"] = json!(["target", "text", "replace_selection"]);
    // keys gained the fronting bound and the accessibility grant.
    let keys = row_mut(&mut v13, "computer.keys");
    keys["maximum_fronting_bracket_interval_ms"] = Value::Null;
    keys["required_permission_services"] = json!(["post_event", "input_monitoring"]);
    // wait gained the app field, the refusal fields and their outcomes.
    let wait = row_mut(&mut v13, "computer.wait");
    remove_properties(wait, "request_schema", &["app"]);
    wait["request_schema"]["required"] = json!(["predicate", "timeout_ms"]);
    remove_properties(
        wait,
        "result_schema",
        &[
            "field",
            "reason",
            "remedy",
            "ask_id",
            "grant_persisted",
            "bundle_identity",
            "instances",
            "unreadable",
        ],
    );
    wait["result_schema"]["properties"]["outcome"]["enum"]
        .as_array_mut()
        .unwrap()
        .truncate(4);
    wait["result_schema"]["required"] = json!(["outcome", "evidence", "settle_path"]);

    // Every v12 row carried its consent lease kind.
    for (id, kind, overrides) in [
        ("computer.type", "compose", json!({})),
        (
            "computer.keys",
            "compose",
            json!({"durable_chord": "mutate_durable"}),
        ),
        ("computer.wait", "observe", json!({})),
    ] {
        let retained = row_mut(&mut v13, id).as_object_mut().unwrap();
        retained.insert("action_kind".into(), json!(kind));
        retained.insert("action_kind_overrides".into(), overrides);
    }

    let retired: Vec<Value> = serde_json::from_str(RETIRED_V12_ROWS).expect("the fixture parses");
    let v12_rows: Vec<Value> = [
        "computer.click",
        "computer.type",
        "computer.keys",
        "computer.scroll",
        "computer.move",
        "computer.drag",
        "computer.screenshot",
        "computer.wait",
    ]
    .iter()
    .map(|id| {
        retired
            .iter()
            .find(|row| row["capability_id"] == *id)
            .unwrap_or_else(|| row(&v13, id))
            .clone()
    })
    .collect();
    json!({
        "schema_id": "ck-computer-action-vocabulary/v1",
        "revision": historical_revision(12),
        "rows": v12_rows,
    })
}

/// v13 makes exactly the changes `recreated_v12` undoes, and nothing else.
///
/// The digest on the right is v12's, measured before the mint. If anything
/// else moved -- a description reworded, a row reordered, a number
/// reformatted -- the rebuilt v12 would not reproduce it.
#[test]
fn v13_only_makes_the_changes_recreated_v12_undoes() {
    let bytes = canonical_json_bytes(&recreated_v12()).unwrap();
    assert_eq!(hex_digest(&bytes), V12_ARTIFACT_SHA256);
}

/// The shipped artifact is exactly what the generator produces from v12.
///
/// Together with the test above, which proves `recreated_v12` IS v12, this
/// pins the artifact to the generator input and its comments: nothing in
/// the artifact was edited by hand.
#[test]
fn the_minted_artifact_is_the_generator_output_from_v12() {
    let generated =
        vocabulary_mint::v13_from_v12(&recreated_v12(), historical_revision(13).as_str().unwrap());
    let generated =
        vocabulary_mint::v14_from_v13(&generated, historical_revision(14).as_str().unwrap());
    let generated =
        vocabulary_mint::v15_from_v14(&generated, historical_revision(15).as_str().unwrap());
    let generated =
        vocabulary_mint::v16_from_v15(&generated, historical_revision(16).as_str().unwrap());
    let generated =
        vocabulary_mint::v17_from_v16(&generated, historical_revision(17).as_str().unwrap());
    let generated =
        vocabulary_mint::v18_from_v17(&generated, historical_revision(18).as_str().unwrap());
    let generated =
        vocabulary_mint::v19_from_v18(&generated, historical_revision(19).as_str().unwrap());
    let generated =
        vocabulary_mint::v20_from_v19(&generated, historical_revision(20).as_str().unwrap());
    let generated =
        vocabulary_mint::v21_from_v20(&generated, historical_revision(21).as_str().unwrap());
    let generated =
        vocabulary_mint::v22_from_v21(&generated, historical_revision(22).as_str().unwrap());
    let generated =
        vocabulary_mint::v23_from_v22(&generated, historical_revision(23).as_str().unwrap());
    let generated =
        vocabulary_mint::v24_from_v23(&generated, historical_revision(24).as_str().unwrap());
    let generated =
        vocabulary_mint::v25_from_v24(&generated, historical_revision(25).as_str().unwrap());
    let generated =
        vocabulary_mint::v26_from_v25(&generated, historical_revision(26).as_str().unwrap());
    let generated =
        vocabulary_mint::v27_from_v26(&generated, historical_revision(27).as_str().unwrap());
    let generated =
        vocabulary_mint::v28_from_v27(&generated, historical_revision(28).as_str().unwrap());
    let generated =
        vocabulary_mint::v29_from_v28(&generated, historical_revision(29).as_str().unwrap());
    let generated =
        vocabulary_mint::v30_from_v29(&generated, historical_revision(30).as_str().unwrap());
    let generated =
        vocabulary_mint::v31_from_v30(&generated, historical_revision(31).as_str().unwrap());
    let generated =
        vocabulary_mint::v32_from_v31(&generated, historical_revision(32).as_str().unwrap());
    let generated =
        vocabulary_mint::v33_from_v32(&generated, historical_revision(33).as_str().unwrap());
    let generated =
        vocabulary_mint::v34_from_v33(&generated, historical_revision(34).as_str().unwrap());
    let generated =
        vocabulary_mint::v35_from_v34(&generated, historical_revision(35).as_str().unwrap());
    let generated = vocabulary_mint::v36_from_v35(&generated, COMPUTER_ACTION_VOCABULARY_REVISION);
    let bytes = canonical_json_bytes(&generated).unwrap();
    assert!(
        bytes == VOCABULARY.as_bytes(),
        "the shipped vocabulary differs from the generator output; regenerate it"
    );
    assert_eq!(
        generated["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["capability_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vocabulary_mint::V15_ROW_IDS
            .into_iter()
            .flat_map(|id| if id == "computer.takeover_move" {
                vec![id, "computer.takeover_click"]
            } else {
                vec![id]
            })
            .chain(["computer.open_app"])
            .collect::<Vec<_>>()
    );
}

/// Each new row is written for what it does, not copied from the row it
/// replaces.
///
/// The removed click row required post_event and input monitoring and
/// declared per-process and global synthetic paths. Copied onto read_state,
/// those would withhold a pure accessibility read on any machine with input
/// monitoring off, and stamp a pointer path onto a row that posts nothing.
/// Checked on the generator's own output, so a copied row fails here by name
/// before it can reach an artifact.
#[test]
fn read_state_and_write_text_are_authored_for_what_they_do() {
    let generated =
        vocabulary_mint::v13_from_v12(&recreated_v12(), COMPUTER_ACTION_VOCABULARY_REVISION);
    let read_state = row(&generated, "computer.read_state");
    assert_eq!(
        read_state["required_permission_services"],
        json!(["accessibility"])
    );
    assert_eq!(read_state["synthetic_paths"], json!([]));
    assert_eq!(read_state["semantic_path"], "none");
    assert_eq!(read_state["dispatch_modes"], json!(["background"]));
    assert_eq!(read_state["retry_class"], "idempotent");

    let write_text = row(&generated, "computer.write_text");
    assert_eq!(write_text["semantic_path"], "ax_value");
    assert_eq!(write_text["synthetic_paths"], json!([]));
    assert_eq!(
        write_text["required_permission_services"],
        json!(["accessibility"])
    );

    for id in ["computer.press_element", "computer.press_point"] {
        let press = row(&generated, id);
        assert_eq!(press["semantic_path"], "ax_press", "{id}");
        assert_eq!(press["synthetic_paths"], json!([]), "{id}");
        assert_eq!(
            press["required_permission_services"],
            json!(["accessibility"]),
            "{id}"
        );
    }
    for id in [
        "computer.takeover_move",
        "computer.takeover_drag",
        "computer.takeover_scroll",
    ] {
        let takeover = row(&generated, id);
        assert_eq!(takeover["synthetic_paths"], json!(["global"]), "{id}");
        assert_eq!(takeover["dispatch_modes"], json!(["observed"]), "{id}");
        assert_eq!(takeover["semantic_path"], "none", "{id}");
        assert_eq!(
            takeover["review_requirement"], "takeover_dispatch_review_revision",
            "{id}"
        );
    }
}

/// No row of the vocabulary equals another row, current or removed, once
/// its capability id is set aside.
#[test]
fn no_row_is_a_copy_of_another_row() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let retired: Vec<Value> = serde_json::from_str(RETIRED_V12_ROWS).expect("the fixture parses");
    let without_id_or_kind = |row: &Value| {
        let mut row = row.clone();
        let object = row.as_object_mut().unwrap();
        object.remove("capability_id");
        object.remove("action_kind");
        object.remove("action_kind_overrides");
        row
    };
    let rows: Vec<&Value> = vocabulary["rows"]
        .as_array()
        .unwrap()
        .iter()
        .chain(retired.iter())
        .collect();
    for (index, left) in rows.iter().enumerate() {
        for right in &rows[index + 1..] {
            assert_ne!(
                without_id_or_kind(left),
                without_id_or_kind(right),
                "{} is a copy of {}",
                left["capability_id"],
                right["capability_id"]
            );
        }
    }
}

/// wait names its application; keys fronts under the same bound as type and
/// reads the focused element through accessibility first.
#[test]
fn the_retained_rows_carry_their_v13_changes() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    let wait = row(&vocabulary, "computer.wait");
    assert_eq!(
        wait["request_schema"]["required"],
        json!(["app", "predicate", "timeout_ms"])
    );
    let keys = row(&vocabulary, "computer.keys");
    assert_eq!(keys["maximum_fronting_bracket_interval_ms"], 100);
    assert!(keys["required_permission_services"]
        .as_array()
        .unwrap()
        .contains(&json!("accessibility")));
    assert!(
        row(&vocabulary, "computer.type")["request_schema"]["properties"]
            .get("replace_selection")
            .is_none()
    );
}

/// Every row that can need consent declares the whole consent envelope, and
/// every row that parses input declares how it refuses bad input.
#[test]
fn every_row_declares_the_consent_envelope_and_the_invalid_request_fields() {
    let vocabulary: Value = serde_json::from_str(VOCABULARY).expect("the vocabulary parses");
    for row in vocabulary["rows"].as_array().unwrap() {
        let id = row["capability_id"].as_str().unwrap();
        let properties = row["result_schema"]["properties"].as_object().unwrap();
        for field in ["ask_id", "remedy", "field", "reason"] {
            assert!(properties.contains_key(field), "{id} lacks {field}");
        }
        if let Some(outcomes) = properties["outcome"]["enum"].as_array() {
            for outcome in [
                "consent_pending",
                "consent_denied",
                "consent_granted_not_executed",
                "consent_unavailable",
                "module_draining",
                "route_closed",
                "invalid_request",
            ] {
                assert!(outcomes.contains(&json!(outcome)), "{id} lacks {outcome}");
            }
            assert!(
                !outcomes.contains(&json!("capability_not_admitted")),
                "{id}: capability_not_admitted is a route error, not a capability result"
            );
        }
    }
}

/// Undo revision 15: the tree and diff arrays back in place of state_text,
/// subtree_element_id back in place of zoom, no target names, no element
/// targets, no diff cap word, no state_changed_by_person refusal, and no
/// list_apps row.
fn recreated_v14() -> Value {
    let mut vocabulary = recreated_v15();
    vocabulary["revision"] = historical_revision(14);
    assert_eq!(
        vocabulary["rows"].as_array_mut().unwrap().pop().unwrap()["capability_id"],
        "computer.list_apps"
    );
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let id = row["capability_id"].as_str().unwrap().to_string();
        let id = id.as_str();
        let properties = row["result_schema"]["properties"].as_object_mut().unwrap();
        // The state_changed_by_person refusal was the last revision 15
        // change applied, so it is the first removed.
        if vocabulary_mint::V15_PERSON_CHANGE_ROWS.contains(&id) {
            let outcome = properties["outcome"].as_object_mut().unwrap();
            let tokens = outcome["enum"].as_array_mut().unwrap();
            let before = tokens.len();
            tokens.retain(|word| word != vocabulary_mint::V15_PERSON_CHANGE_OUTCOME);
            assert_eq!(tokens.len(), before - 1, "{id}");
            let description = outcome["description"]
                .as_str()
                .unwrap()
                .strip_suffix(vocabulary_mint::V15_PERSON_CHANGE_ADDITION)
                .expect("state_changed_by_person is described")
                .to_owned();
            outcome.insert("description".into(), json!(description));
        }
        if vocabulary_mint::V15_NAMED_TARGET_ROWS.contains(&id) {
            assert!(properties.remove("candidates").is_some(), "{id}");
            assert!(properties.remove("target").is_some(), "{id}");
            let outcome = properties["outcome"].as_object_mut().unwrap();
            outcome["enum"].as_array_mut().unwrap().retain(|word| {
                !vocabulary_mint::V15_NAME_OUTCOMES.contains(&word.as_str().unwrap())
            });
            if id != "computer.read_state" {
                let description = outcome["description"]
                    .as_str()
                    .unwrap()
                    .strip_suffix(vocabulary_mint::V15_NAME_OUTCOMES_ADDITION)
                    .expect("the name outcomes are described")
                    .to_owned();
                outcome.insert("description".into(), json!(description));
            }
        }
        if vocabulary_mint::V15_ELEMENT_ROWS.contains(&id) {
            assert!(properties.remove("target").is_some(), "{id}");
            let outcome = properties["outcome"].as_object_mut().unwrap();
            assert_eq!(
                outcome["enum"].as_array_mut().unwrap().pop(),
                Some(json!("target_mismatch"))
            );
            let description = outcome["description"]
                .as_str()
                .unwrap()
                .strip_suffix(vocabulary_mint::V15_TARGET_MISMATCH_ADDITION)
                .expect("target_mismatch is described")
                .to_owned();
            outcome.insert("description".into(), json!(description));
            assert!(row["request_schema"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("target")
                .is_some());
        }
        let properties = row["result_schema"]["properties"].as_object_mut().unwrap();
        if vocabulary_mint::V15_DIFF_ROWS.contains(&id) {
            assert!(properties.remove("state_text").is_some(), "{id}");
            properties.extend(vocabulary_mint::v14_diff_fields());
            assert_eq!(
                properties["truncation"]["properties"]["reason"]["enum"]
                    .as_array_mut()
                    .unwrap()
                    .pop(),
                Some(json!("diff_cap_reached"))
            );
        }
        if id == "computer.read_state" {
            assert!(properties.remove("state_text").is_some());
            properties.insert("tree".into(), vocabulary_mint::v14_tree_field());
            let outcome = properties["outcome"].as_object_mut().unwrap();
            let description = outcome["description"].as_str().unwrap().replacen(
                vocabulary_mint::V15_READ_STATE_OUTCOME_START,
                vocabulary_mint::V14_READ_STATE_OUTCOME_START,
                1,
            );
            outcome.insert("description".into(), json!(description));
            let request = row["request_schema"]["properties"].as_object_mut().unwrap();
            assert!(request.remove("zoom").is_some());
            request.insert(
                "subtree_element_id".into(),
                vocabulary_mint::v14_subtree_field(),
            );
            request.insert(
                "text_filter".into(),
                vocabulary_mint::v14_text_filter_field(),
            );
        }
    }
    vocabulary
}

/// v15 makes exactly the changes `recreated_v14` undoes, and nothing else.
///
/// The digest on the right is v14's, measured before the mint.
#[test]
fn v15_only_makes_the_changes_recreated_v14_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v14()).unwrap()),
        V14_ARTIFACT_SHA256
    );
}

/// Restore the open keystroke outcomes and remove the read, image and web refusals.
fn recreated_v13() -> Value {
    let mut vocabulary: Value = recreated_v14();
    vocabulary["revision"] = historical_revision(13);
    for id in ["computer.keys", "computer.type"] {
        let properties = &mut row_mut(&mut vocabulary, id)["result_schema"]["properties"];
        properties["outcome"]
            .as_object_mut()
            .unwrap()
            .remove("enum");
        // Undo the not_dispatched effect status: its word, its description,
        // and the sentence it added to posts_returned.
        let status = properties["effect_status"].as_object_mut().unwrap();
        assert_eq!(
            status.remove("description"),
            Some(json!(vocabulary_mint::KEYSTROKE_EFFECT_STATUS_DESCRIPTION))
        );
        assert_eq!(
            status["enum"].as_array_mut().unwrap().pop(),
            Some(json!("not_dispatched"))
        );
        let posts = properties["posts_returned"]["description"]
            .as_str()
            .unwrap()
            .strip_suffix(vocabulary_mint::KEYSTROKE_POSTS_RETURNED_ADDITION)
            .expect("posts_returned carries the not_dispatched sentence")
            .to_owned();
        properties["posts_returned"]["description"] = json!(posts);
    }
    for (id, pointer, word) in [
        (
            "computer.read_state",
            "/result_schema/properties/outcome/enum",
            "audit_unavailable",
        ),
        (
            "computer.read_state",
            "/result_schema/properties/image_unavailable/properties/reason/enum",
            "window_covered_may_be_stale",
        ),
        (
            "computer.write_text",
            "/result_schema/properties/outcome/enum",
            "web_content_needs_type",
        ),
    ] {
        let tokens = row_mut(&mut vocabulary, id)
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap();
        assert_eq!(tokens.pop(), Some(json!(word)));
    }
    vocabulary
}

#[test]
fn v14_only_makes_the_changes_recreated_v13_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v13()).unwrap()),
        V13_ARTIFACT_SHA256
    );
}

/// A reader meeting an effect_status it does not know reads it as
/// effect_indeterminate, and the computer.type and computer.keys rows say so
/// in their effect_status description.
///
/// Nothing in this repository parses effect_status back out of a reply --
/// the model reading computer_use replies is the reader -- so the vector is a
/// fixture, and this pins it to the rule text the rows carry. The unknown
/// value must really be unknown to the rows, or the vector tests nothing.
#[test]
fn an_unknown_effect_status_is_read_as_indeterminate_by_rule() {
    let vector: Value =
        serde_json::from_str(include_str!("../fixtures/effect_status_unknown_value.json")).unwrap();
    assert_eq!(
        vector["reader_must_read_effect_status_as"],
        "effect_indeterminate"
    );
    let unknown = &vector["reply"]["effect_status"];
    let vocabulary: Value = serde_json::from_str(VOCABULARY).unwrap();
    for id in vector["capabilities"].as_array().unwrap() {
        let status =
            &row(&vocabulary, id.as_str().unwrap())["result_schema"]["properties"]["effect_status"];
        let statuses = status["enum"].as_array().unwrap();
        assert!(statuses.contains(&json!("not_dispatched")), "{id}");
        assert!(!statuses.contains(unknown), "{id} knows the vector's value");
        assert!(
            status["description"].as_str().unwrap().contains(
                "A reader that meets an effect_status value it does not know treats it as \
                 effect_indeterminate, never as not-run."
            ),
            "{id} does not state the reader rule"
        );
    }
    // write_text sets a value through accessibility rather than posting
    // keystrokes, so its effect_status enum does not gain not_dispatched.
    let write_text = &row(&vocabulary, "computer.write_text")["result_schema"]["properties"]
        ["effect_status"]["enum"];
    assert!(!write_text
        .as_array()
        .unwrap()
        .contains(&json!("not_dispatched")));
}

#[test]
fn v14_refusal_words_are_in_closed_enums_and_validate() {
    use cerebellum_computer::platform::vocabulary::validate_capability_result;
    for (id, outcome) in [
        ("computer.keys", "modifier_chord_needs_foreground"),
        ("computer.keys", "private_input_auth_failed"),
        ("computer.type", "private_input_auth_failed"),
        ("computer.read_state", "audit_unavailable"),
        ("computer.write_text", "web_content_needs_type"),
    ] {
        let vocabulary: Value = serde_json::from_str(VOCABULARY).unwrap();
        let row = vocabulary["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["capability_id"] == id)
            .unwrap();
        assert!(row["result_schema"]["properties"]["outcome"]["enum"]
            .as_array()
            .expect("outcome must be closed")
            .contains(&json!(outcome)));
        let mut reply = json!({"outcome": outcome});
        if id == "computer.keys" || id == "computer.type" {
            reply["containment_rung"] = json!("pid_structural");
            reply["effect_status"] = json!("effect_indeterminate");
            reply["target_fronted"] = json!(false);
        }
        validate_capability_result(id, &reply).unwrap();
    }
    validate_capability_result(
        "computer.read_state",
        &json!({
            "outcome": "completed", "state_text": "", "unreadable_subtrees": 0,
            "image_unavailable": {"reason": "window_covered_may_be_stale"}
        }),
    )
    .unwrap();
}

/// Remove observer_unavailable from press_element, press_point and write_text
/// and strip its description, reconstructing revision 15 exactly.
fn recreated_v15() -> Value {
    let mut vocabulary = recreated_v16();
    vocabulary["revision"] = historical_revision(15);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        if vocabulary_mint::V15_ELEMENT_ROWS.contains(&row["capability_id"].as_str().unwrap()) {
            let outcome = &mut row["result_schema"]["properties"]["outcome"];
            assert_eq!(
                outcome["enum"].as_array_mut().unwrap().pop(),
                Some(json!("observer_unavailable"))
            );
            let description = outcome["description"]
                .as_str()
                .unwrap()
                .strip_suffix(vocabulary_mint::V16_OBSERVER_ADDITION)
                .unwrap()
                .to_owned();
            outcome["description"] = json!(description);
        }
    }
    vocabulary
}

#[test]
fn v16_only_makes_the_changes_recreated_v15_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v15()).unwrap()),
        "671ab7a2017cb556448c42661dd5e1b8fcb3f3aa360c54ee291518c59c5fe5c4"
    );
}

/// Remove the optional consent-unavailable detail (reason, grant and grant_label)
/// added in revision 17, recovering the previous frozen vocabulary bytes.
fn recreated_v16() -> Value {
    let mut vocabulary: Value = recreated_v17();
    vocabulary["revision"] = historical_revision(16);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let schema = &mut row["result_schema"];
        if schema["properties"]["outcome"]["enum"]
            .as_array()
            .is_some_and(|values| values.contains(&json!("consent_unavailable")))
        {
            assert_eq!(
                schema["properties"]
                    .as_object_mut()
                    .unwrap()
                    .remove("detail"),
                Some(
                    json!({"type":"object","additionalProperties":false,"required":["reason","grant","grant_label"],"properties":{"reason":{"type":"string"},"grant":{"type":"string"},"grant_label":{"type":"string"}}})
                )
            );
        }
    }
    vocabulary
}

/// Remove `permission_missing`, `detail.permission` and `detail.state`, then
/// require `detail.reason`, `detail.grant` and `detail.grant_label` again for
/// the consent-only detail object.
fn recreated_v17() -> Value {
    let mut vocabulary = recreated_v18();
    vocabulary["revision"] = historical_revision(17);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        if row["required_permission_services"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            continue;
        }
        let schema = &mut row["result_schema"];
        assert_eq!(
            schema["properties"]["outcome"]["enum"]
                .as_array_mut()
                .unwrap()
                .pop(),
            Some(json!("permission_missing"))
        );
        let detail = &mut schema["properties"]["detail"];
        let properties = detail["properties"].as_object_mut().unwrap();
        assert_eq!(
            properties.remove("permission"),
            Some(
                json!({"type":"string","enum":["accessibility","screen_recording","input_monitoring"]})
            )
        );
        assert_eq!(
            properties.remove("state"),
            Some(
                json!({"type":"string","enum":["live","unavailable","granted_pending_relaunch","unresolved","probe_failed"]})
            )
        );
        if properties.is_empty() {
            schema["properties"]
                .as_object_mut()
                .unwrap()
                .remove("detail");
        } else {
            detail["required"] = json!(["reason", "grant", "grant_label"]);
        }
    }
    vocabulary
}

#[test]
fn v18_only_makes_the_changes_recreated_v17_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v17()).unwrap()),
        "3b7b6fc633fb5a35cd8e4fb5ef8da1c4d196fe43ab5295fb1be7c1e8cc1d746d"
    );
}

#[test]
fn v17_only_makes_the_changes_recreated_v16_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v16()).unwrap()),
        "c5e13e0f02eb666df554c7e2f73f86edcfee6f0b587c3b9cd09564856079cde5"
    );
}

/// Rebuild the previous inventory row and remove only the new launch row.
/// The pinned previous digest makes any unlisted change fail loudly.
fn recreated_v18() -> Value {
    let mut vocabulary = recreated_v19();
    vocabulary["revision"] = historical_revision(18);
    let rows = vocabulary["rows"].as_array_mut().unwrap();
    assert_eq!(rows.pop().unwrap()["capability_id"], "computer.open_app");
    let list = rows
        .iter_mut()
        .find(|row| row["capability_id"] == "computer.list_apps")
        .unwrap();
    *list = serde_json::from_str(include_str!("../fixtures/v18_list_apps.json")).unwrap();
    vocabulary
}

fn recreated_v19() -> Value {
    let mut vocabulary = recreated_v20();
    vocabulary["revision"] = historical_revision(19);
    let schemas: Value =
        serde_json::from_str(include_str!("../fixtures/v19_round_trip_schemas.json")).unwrap();
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        if let Some(previous) = schemas.get(row["capability_id"].as_str().unwrap()) {
            row["request_schema"] = previous["request_schema"].clone();
            row["result_schema"] = previous["result_schema"].clone();
        }
    }
    vocabulary
}

fn recreated_v20() -> Value {
    let mut vocabulary = recreated_v21();
    vocabulary["revision"] = historical_revision(20);
    let row = vocabulary["rows"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["capability_id"] == "computer.read_state")
        .unwrap();
    assert_eq!(
        row.as_object_mut()
            .unwrap()
            .remove("maximum_fronting_read_interval_ms"),
        Some(json!(300))
    );
    assert_eq!(
        row["result_schema"]["properties"]["outcome"]["enum"]
            .as_array_mut()
            .unwrap()
            .pop()
            .unwrap(),
        "state_changed_by_person"
    );
    row["request_schema"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("bring_to_front");
    row["result_schema"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("image_fronting");
    let unavailable = &mut row["result_schema"]["properties"]["image_unavailable"]["properties"];
    unavailable.as_object_mut().unwrap().remove("detail");
    for reason in [
        "restore_failed",
        "fronting_unavailable",
        "fronting_bound_exceeded",
        "image_needs_takeover",
    ] {
        assert_eq!(
            unavailable["reason"]["enum"]
                .as_array_mut()
                .unwrap()
                .pop()
                .unwrap(),
            reason
        );
    }
    vocabulary
}

#[test]
fn v21_only_makes_the_changes_recreated_v20_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v20()).unwrap()),
        "d56bbea03e117fc18bed6b9d6bfbd3437f277255219279a7e853b2979b6e4c7f"
    );
}

#[test]
fn v20_only_makes_the_changes_recreated_v19_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v19()).unwrap()),
        "695ce63f020973b79dd61e7fed23e52cf7aac58bf3650c4257abec4ca0245e33"
    );
}

#[test]
fn v19_only_makes_the_changes_recreated_v18_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v18()).unwrap()),
        "49ffd007a34982ae3a938c1b439274b270935facff8977f953c82bceb2475f4f"
    );
}

fn recreated_v21() -> Value {
    let mut vocabulary = recreated_v22();
    vocabulary["revision"] = historical_revision(21);
    let open = row_mut(&mut vocabulary, "computer.open_app");
    open["effect_observation"]["deadline_ms"] = json!(40000);
    open["result_schema"]["properties"]["outcome"]["description"] = json!("LaunchServices opens without activation; launched_no_window means no first window appeared within ten seconds after the process arrived.");
    remove_properties(open, "result_schema", &["usual_ready_ms", "launch_note"]);
    vocabulary
}

#[test]
fn v22_only_makes_the_changes_recreated_v21_undoes() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v21()).unwrap()),
        "cfe82e8302f59219cdb715aa6ff8743f4daf29e7918b7923e703342c7efc24a5"
    );
}

fn recreated_v22() -> Value {
    let mut vocabulary = recreated_v23();
    vocabulary["revision"] = historical_revision(22);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        row["result_schema"]["properties"]["outcome"]["enum"]
            .as_array_mut()
            .unwrap()
            .retain(|word| word != "queue_wait_expired");
    }
    vocabulary
}

#[test]
fn v23_only_adds_queue_expiry_to_the_recreated_v22_results() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v22()).unwrap()),
        "ba69cb7021353639ab6723578d2945dab5d7ceda0bb2756ec86e351a8bf7c6ae"
    );
}

fn recreated_v23() -> Value {
    let mut vocabulary = recreated_v24();
    vocabulary["revision"] = historical_revision(23);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let had_consent_detail_requirements = matches!(
            row["capability_id"].as_str().unwrap(),
            "computer.wait" | "computer.list_apps"
        );
        let had_effect_status = matches!(
            row["capability_id"].as_str().unwrap(),
            "computer.write_text" | "computer.type" | "computer.keys"
        );
        let properties = row["result_schema"]["properties"].as_object_mut().unwrap();
        for expected in [
            "blocking_capacity_exhausted",
            "target_busy",
            "dispatch_outcome_unknown",
            "action_deadline_exceeded",
        ] {
            assert_eq!(
                properties["outcome"]["enum"]
                    .as_array_mut()
                    .unwrap()
                    .pop()
                    .unwrap(),
                expected
            );
        }
        if !had_effect_status {
            properties.remove("effect_status").unwrap();
        }
        if had_consent_detail_requirements {
            properties["detail"]["required"] = json!(["reason", "grant", "grant_label"]);
        }
        let detail = properties["detail"]["properties"].as_object_mut().unwrap();
        for name in ["dispatched", "step", "call", "held_state"] {
            detail.remove(name).unwrap();
        }
        detail["reason"]
            .as_object_mut()
            .unwrap()
            .remove("description")
            .unwrap();
    }
    vocabulary
}

#[test]
fn v24_only_adds_bounded_call_evidence_to_the_recreated_v23_results() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v23()).unwrap()),
        "68fde428a263087692960d589de54117da77be4940fd5879085814f4620f53f7"
    );
}

/// v25 with its additions taken back out: the `matched_app` result field of
/// the name-resolving rows and the `list_apps` `text_filter` request field.
/// Each removal asserts the field was there, so a v25 that stopped adding one
/// is caught here as well as by the digest.
fn recreated_v24() -> Value {
    let mut vocabulary = recreated_v25();
    vocabulary["revision"] = historical_revision(24);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let capability = row["capability_id"].as_str().unwrap().to_string();
        if vocabulary_mint::NAME_RESOLVED_ROW_IDS.contains(&capability.as_str()) {
            row["result_schema"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("matched_app")
                .unwrap();
        }
        if capability == "computer.list_apps" {
            row["request_schema"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("text_filter")
                .unwrap();
        }
    }
    vocabulary
}

#[test]
fn v25_only_adds_partial_name_matching_and_the_list_filter_to_the_recreated_v24() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v24()).unwrap()),
        "79bd8bb5ac595bcd89f7a844b80abe54150f610e55d6cb2fe62e31d10ef83ba5"
    );
}

/// v26 with its additions taken back out: the
/// `point_in_another_window` outcome of each image-coordinate row and the
/// sentence that describes it. Each removal asserts what it removes was
/// there, so a v26 that stopped adding either is caught here as well as by
/// the digest.
fn recreated_v25() -> Value {
    let mut vocabulary = recreated_v26();
    vocabulary["revision"] = historical_revision(25);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let capability = row["capability_id"].as_str().unwrap().to_string();
        if !vocabulary_mint::IMAGE_COORDINATE_ROW_IDS.contains(&capability.as_str()) {
            continue;
        }
        let outcome = &mut row["result_schema"]["properties"]["outcome"];
        assert_eq!(
            outcome["enum"].as_array_mut().unwrap().pop().unwrap(),
            "point_in_another_window"
        );
        let description = outcome["description"].as_str().unwrap();
        let previous = description
            .strip_suffix(vocabulary_mint::POINT_IN_ANOTHER_WINDOW_DESCRIPTION)
            .and_then(|rest| rest.strip_suffix(' '))
            .unwrap_or_else(|| panic!("{capability} does not describe point_in_another_window"))
            .to_string();
        outcome["description"] = json!(previous);
    }
    vocabulary
}

#[test]
fn v26_only_adds_the_imaged_window_refusal_to_the_recreated_v25() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v25()).unwrap()),
        "db496b3e5f4e63096677239c1342a18b4e64034ad3046de657daeddcd799bbe6"
    );
}

/// v27 with its additions taken back out: the
/// `element_disabled` outcome of each press row and the sentence that
/// describes it. Each removal asserts what it removes was there, so a v27
/// that stopped adding either is caught here as well as by the digest.
fn recreated_v26() -> Value {
    let mut vocabulary = recreated_v27();
    vocabulary["revision"] = historical_revision(26);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let capability = row["capability_id"].as_str().unwrap().to_string();
        if !vocabulary_mint::PRESS_ROW_IDS.contains(&capability.as_str()) {
            continue;
        }
        let outcome = &mut row["result_schema"]["properties"]["outcome"];
        assert_eq!(
            outcome["enum"].as_array_mut().unwrap().pop().unwrap(),
            "element_disabled"
        );
        let description = outcome["description"].as_str().unwrap();
        let previous = description
            .strip_suffix(vocabulary_mint::ELEMENT_DISABLED_DESCRIPTION)
            .and_then(|rest| rest.strip_suffix(' '))
            .unwrap_or_else(|| panic!("{capability} does not describe element_disabled"))
            .to_string();
        outcome["description"] = json!(previous);
    }
    vocabulary
}

/// The recreated v26 is byte for byte the v26 that shipped: its digest is
/// the one v26's mirrors and source lock carried.
#[test]
fn v27_only_adds_the_disabled_element_refusal_to_the_recreated_v26() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v26()).unwrap()),
        "a683d08ade5a013b162db22dfa2d7f2244e6a6f95fce4f3fb5381ac4e20490b6"
    );
}

/// v28 with its additions taken back out: every row's
/// `config_invalid` outcome; each fronting row's `fronting`, `preview` and
/// `fronting_bound_exceeded` fields and its `not_fronted` outcome, plus
/// `restore_failed` where v27 lacked it; `open_app`'s
/// `state_changed_by_person`; `press_element`'s `bundle_identity`; and the
/// sentences describing the new outcomes. Each removal asserts what it
/// removes was there, so a v28 that stopped adding any of them is caught here
/// as well as by the digest.
fn recreated_v27() -> Value {
    let mut vocabulary = recreated_v28();
    vocabulary["revision"] = historical_revision(27);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let capability = row["capability_id"].as_str().unwrap().to_string();
        let fronting_row = vocabulary_mint::FRONTING_ROW_IDS.contains(&capability.as_str());
        let properties = row["result_schema"]["properties"].as_object_mut().unwrap();
        // The outcomes v28 appended to this row, last first.
        let mut appended = Vec::new();
        if capability == "computer.open_app" {
            appended.push("state_changed_by_person");
        }
        // The keystroke rows already answered restore_failed before v28.
        if fronting_row && !["computer.type", "computer.keys"].contains(&capability.as_str()) {
            appended.push("restore_failed");
        }
        if fronting_row {
            appended.push("not_fronted");
        }
        appended.push("config_invalid");
        let outcome = &mut properties["outcome"];
        for expected in appended {
            assert_eq!(
                outcome["enum"].as_array_mut().unwrap().pop().unwrap(),
                expected,
                "{capability}"
            );
        }
        let mut addition = vocabulary_mint::CONFIG_INVALID_DESCRIPTION.to_string();
        if fronting_row {
            addition = format!(
                "{addition} {}",
                vocabulary_mint::FRONTING_OUTCOMES_DESCRIPTION
            );
        }
        let description = outcome["description"].as_str().unwrap();
        let previous = description
            .strip_suffix(addition.as_str())
            .and_then(|rest| rest.strip_suffix(' '))
            .unwrap_or_else(|| panic!("{capability} does not describe the v28 outcomes"))
            .to_string();
        outcome["description"] = json!(previous);
        if fronting_row {
            for (field, schema) in [
                ("fronting", vocabulary_mint::v28_fronting_field()),
                ("preview", vocabulary_mint::v28_preview_field()),
                (
                    "fronting_bound_exceeded",
                    vocabulary_mint::v28_fronting_bound_exceeded_field(),
                ),
            ] {
                assert_eq!(
                    properties.remove(field),
                    Some(schema),
                    "{capability}.{field}"
                );
            }
        } else {
            for field in ["fronting", "preview", "fronting_bound_exceeded"] {
                assert!(!properties.contains_key(field), "{capability}.{field}");
            }
        }
        if capability == "computer.press_element" {
            assert_eq!(
                properties.remove("bundle_identity"),
                Some(vocabulary_mint::v28_press_element_bundle_identity_field())
            );
        }
    }
    vocabulary
}

/// The recreated v27 is byte for byte the v27 that shipped: its digest is
/// the one v27's mirrors and source lock carried.
#[test]
fn v28_only_adds_app_use_and_fronting_replies_to_the_recreated_v27() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v27()).unwrap()),
        "54aff871c6fcc4c18b5dfd3ebe272ab86c3724f5264a763a29ef63fe454cb2df"
    );
}

/// Within the rows, v28 changes only `result_schema`s; the document's
/// `revision` is the one other value that moves. The advertised
/// `computer_use` definition is built from each row's `request_schema`, so
/// those must keep their exact bytes, and every other row field is what
/// `validate_row` checks, so it must not move either.
#[test]
fn v28_changes_only_result_schemas() {
    let previous = recreated_v27();
    let current = recreated_v28();
    let previous_rows = previous["rows"].as_array().unwrap();
    let current_rows = current["rows"].as_array().unwrap();
    assert_eq!(previous_rows.len(), current_rows.len());
    for (before, after) in previous_rows.iter().zip(current_rows) {
        let id = after["capability_id"].as_str().unwrap();
        assert_eq!(
            canonical_json_bytes(&before["request_schema"]).unwrap(),
            canonical_json_bytes(&after["request_schema"]).unwrap(),
            "{id} request_schema"
        );
        let mut before = before.clone();
        let mut after = after.clone();
        before.as_object_mut().unwrap().remove("result_schema");
        after.as_object_mut().unwrap().remove("result_schema");
        assert_eq!(before, after, "{id} changed outside its result_schema");
    }
    let image_fronting = |vocabulary: &Value| {
        row(vocabulary, "computer.read_state")["result_schema"]["properties"]["image_fronting"]
            .clone()
    };
    assert_eq!(image_fronting(&previous), image_fronting(&current));
    let mut previous = previous;
    let mut current = current;
    previous.as_object_mut().unwrap().remove("rows");
    current.as_object_mut().unwrap().remove("rows");
    previous["revision"] = current["revision"].clone();
    assert_eq!(
        previous, current,
        "a document field other than revision changed"
    );
}

/// v29 with its one addition taken back out: the
/// `target_not_read` reason at the end of each fronting row's
/// `fronting.not_fronted_reason`. Each removal asserts the reason was there,
/// so a v29 that stopped adding it to any fronting row is caught here as
/// well as by the digest.
fn recreated_v28() -> Value {
    let mut vocabulary = recreated_v29();
    vocabulary["revision"] = historical_revision(28);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let capability = row["capability_id"].as_str().unwrap().to_string();
        let properties = &mut row["result_schema"]["properties"];
        if !vocabulary_mint::FRONTING_ROW_IDS.contains(&capability.as_str()) {
            assert!(properties.get("fronting").is_none(), "{capability}");
            continue;
        }
        let reasons = properties["fronting"]["properties"]["not_fronted_reason"]["enum"]
            .as_array_mut()
            .unwrap();
        assert_eq!(
            reasons.pop().unwrap(),
            vocabulary_mint::TARGET_NOT_READ,
            "{capability}"
        );
    }
    vocabulary
}

/// The recreated v28 is byte for byte the v28 that shipped: its digest is
/// the one v28's mirrors and source lock carried.
#[test]
fn v29_only_adds_the_target_not_read_reason_to_the_recreated_v28() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v28()).unwrap()),
        "8d94a0a6ea65d41080b8866ec788244d3d1f0ff425a8bd8d845d0a4abe4a0b65"
    );
}

/// v29 changes nothing outside the rows' `result_schema`s, and inside them
/// only the `fronting.not_fronted_reason` enum of the fronting rows. The
/// advertised `computer_use` definition is built from each row's
/// `request_schema`, so those keep their exact bytes.
#[test]
fn v29_changes_only_the_not_fronted_reasons() {
    let previous = recreated_v28();
    let current = recreated_v29();
    let previous_rows = previous["rows"].as_array().unwrap();
    let current_rows = current["rows"].as_array().unwrap();
    assert_eq!(previous_rows.len(), current_rows.len());
    for (before, after) in previous_rows.iter().zip(current_rows) {
        let id = after["capability_id"].as_str().unwrap();
        assert_eq!(
            canonical_json_bytes(&before["request_schema"]).unwrap(),
            canonical_json_bytes(&after["request_schema"]).unwrap(),
            "{id} request_schema"
        );
        let mut before = before.clone();
        let mut after = after.clone();
        for row in [&mut before, &mut after] {
            if let Some(fronting) = row["result_schema"]["properties"].get_mut("fronting") {
                fronting["properties"]["not_fronted_reason"]["enum"] = json!([]);
            }
        }
        assert_eq!(before, after, "{id} changed outside not_fronted_reason");
    }
    let mut previous = previous;
    let mut current = current;
    previous.as_object_mut().unwrap().remove("rows");
    current.as_object_mut().unwrap().remove("rows");
    previous["revision"] = current["revision"].clone();
    assert_eq!(
        previous, current,
        "a document field other than revision changed"
    );
}

/// The recreated v31 with its one addition taken back out:
/// `computer.read_state`'s `image_handle`. The removal asserts the field was
/// there, so a v31 that stopped adding it is caught here as well as by the
/// digest.
fn recreated_v30() -> Value {
    let mut vocabulary = recreated_v31();
    vocabulary["revision"] = historical_revision(30);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let capability = row["capability_id"].as_str().unwrap().to_string();
        let properties = row["result_schema"]["properties"].as_object_mut().unwrap();
        if capability == "computer.read_state" {
            assert_eq!(
                properties.remove("image_handle"),
                Some(vocabulary_mint::v31_read_state_image_handle_field()),
                "{capability}.image_handle"
            );
        } else {
            assert!(!properties.contains_key("image_handle"), "{capability}");
        }
    }
    vocabulary
}

/// The recreated v30 is byte for byte the v30 that shipped: its digest is the
/// one v30's mirrors and source lock carried.
#[test]
fn v31_only_adds_read_states_image_handle_to_the_recreated_v30() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v30()).unwrap()),
        "b0b9b5aab421dd5c5380ddfef0580168f485af8bc44a3b7991898b96d144a906"
    );
}

/// v31 changes nothing outside the rows' `result_schema`s, and inside them
/// only `read_state`'s new `image_handle`. The advertised `computer_use`
/// definition is built from each row's `request_schema`, so those keep their
/// exact bytes, and every other row field is what `validate_row` checks.
#[test]
fn v31_changes_only_read_states_image_handle() {
    let previous = recreated_v30();
    let current = recreated_v31();
    let previous_rows = previous["rows"].as_array().unwrap();
    let current_rows = current["rows"].as_array().unwrap();
    assert_eq!(previous_rows.len(), current_rows.len());
    for (before, after) in previous_rows.iter().zip(current_rows) {
        let id = after["capability_id"].as_str().unwrap();
        assert_eq!(
            canonical_json_bytes(&before["request_schema"]).unwrap(),
            canonical_json_bytes(&after["request_schema"]).unwrap(),
            "{id} request_schema"
        );
        let mut before = before.clone();
        let mut after = after.clone();
        for row in [&mut before, &mut after] {
            row["result_schema"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("image_handle");
        }
        assert_eq!(before, after, "{id} changed outside image_handle");
    }
    let mut previous = previous;
    let mut current = current;
    previous.as_object_mut().unwrap().remove("rows");
    current.as_object_mut().unwrap().remove("rows");
    previous["revision"] = current["revision"].clone();
    assert_eq!(
        previous, current,
        "a document field other than revision changed"
    );
}

/// Removing the terminal alternatives recovers the exact ordinary schemas
/// carried by v31, whose independently pinned digest guards the reconstruction.
fn recreated_v31() -> Value {
    let mut vocabulary = recreated_v32();
    vocabulary["revision"] = historical_revision(31);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        if SYNTHETIC_CAPABILITIES.contains(&row["capability_id"].as_str().unwrap()) {
            let alternatives = row["result_schema"]
                .as_object_mut()
                .unwrap()
                .remove("anyOf")
                .unwrap();
            assert_eq!(alternatives.as_array().unwrap().len(), 3);
            row["result_schema"] = alternatives[0].clone();
        }
    }
    vocabulary
}

#[test]
fn v32_recreates_the_pinned_v31() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v31()).unwrap()),
        V31_ARTIFACT_SHA256
    );
}

#[test]
fn v32_changes_only_keystroke_result_schemas() {
    let previous = recreated_v31();
    let mut current = recreated_v32();
    let generated =
        vocabulary_mint::v32_from_v31(&previous, historical_revision(32).as_str().unwrap());
    assert_eq!(current, generated);
    for (before, after) in previous["rows"]
        .as_array()
        .unwrap()
        .iter()
        .zip(current["rows"].as_array_mut().unwrap())
    {
        if SYNTHETIC_CAPABILITIES.contains(&before["capability_id"].as_str().unwrap()) {
            assert_ne!(before["result_schema"], after["result_schema"]);
            after["result_schema"] = before["result_schema"].clone();
        }
        assert_eq!(
            before, after,
            "{} changed outside its result schema",
            before["capability_id"]
        );
    }
    current["revision"] = previous["revision"].clone();
    assert_eq!(previous, current);
}

/// Remove only the optional diagnostic to recover the independently pinned v32.
fn recreated_v32() -> Value {
    fn remove(schema: &mut Value) {
        assert_eq!(
            schema["properties"]["detail"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("development_build_check"),
            Some(vocabulary_mint::v33_development_build_check_field())
        );
        if let Some(branches) = schema.get_mut("anyOf").and_then(Value::as_array_mut) {
            for branch in branches {
                if branch["properties"]["outcome"]["enum"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(vocabulary_mint::AUTHORIZATION_DENIED))
                {
                    remove(branch);
                }
            }
        }
    }
    let mut vocabulary = recreated_v33();
    vocabulary["revision"] = historical_revision(32);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        if row["capability_id"] != "computer.list_apps" {
            remove(&mut row["result_schema"]);
        }
    }
    vocabulary
}

#[test]
fn v33_only_adds_the_optional_development_diagnostic_to_results() {
    let previous = recreated_v32();
    assert_eq!(
        hex_digest(&canonical_json_bytes(&previous).unwrap()),
        V32_ARTIFACT_SHA256
    );
    let current = recreated_v33();
    assert_eq!(
        current,
        vocabulary_mint::v33_from_v32(&previous, historical_revision(33).as_str().unwrap())
    );
    for (before, after) in previous["rows"]
        .as_array()
        .unwrap()
        .iter()
        .zip(current["rows"].as_array().unwrap())
    {
        assert_eq!(before["request_schema"], after["request_schema"]);
        let mut after = after.clone();
        after["result_schema"] = before["result_schema"].clone();
        assert_eq!(*before, after, "only result schemas may change");
    }
}

/// Explicit writer for the content revision; ordinary test runs never write artifacts.
#[test]
#[ignore = "artifact-writing generator; run explicitly with --ignored --exact"]
fn mint_current_vocabulary_artifact() {
    let resources = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources");
    let revision = COMPUTER_ACTION_VOCABULARY_REVISION;
    let generated = vocabulary_mint::v36_from_v35(&historical_v35(), revision);
    let bytes = canonical_json_bytes(&generated).unwrap();
    std::fs::write(resources.join(format!("{revision}.json")), &bytes).unwrap();
    println!(
        "minted {} bytes; sha256 {}",
        bytes.len(),
        hex_digest(&bytes)
    );
}

/// The shipped artifact with v30's addition taken back out from the recreated
/// v30: the `authorization_denied` outcome at the end of every row's outcome
/// enum but `list_apps`'s, and the sentence describing it at the end of that
/// row's outcome description. Each removal asserts what it removes was there,
/// so a v30 that stopped adding it to any row is caught here as well as by the
/// digest.
fn recreated_v29() -> Value {
    let mut vocabulary = recreated_v30();
    vocabulary["revision"] = historical_revision(29);
    for row in vocabulary["rows"].as_array_mut().unwrap() {
        let capability = row["capability_id"].as_str().unwrap().to_string();
        let outcome = &mut row["result_schema"]["properties"]["outcome"];
        let choices = outcome["enum"].as_array_mut().unwrap();
        if capability == "computer.list_apps" {
            assert!(
                !choices.contains(&json!(vocabulary_mint::AUTHORIZATION_DENIED)),
                "list_apps leaves operator apps out rather than refusing"
            );
            continue;
        }
        assert_eq!(
            choices.pop().unwrap(),
            vocabulary_mint::AUTHORIZATION_DENIED,
            "{capability}"
        );
        let description = outcome["description"].as_str().unwrap();
        let earlier = description
            .strip_suffix(vocabulary_mint::OPERATOR_APP_BLOCKED_DESCRIPTION)
            .and_then(|rest| rest.strip_suffix(' '))
            .unwrap_or_else(|| panic!("{capability} does not describe authorization_denied"))
            .to_string();
        outcome["description"] = json!(earlier);
    }
    vocabulary
}

/// The recreated v29 is byte for byte the v29 that shipped: its digest is
/// the one v29's mirrors and source lock carried.
#[test]
fn v30_only_adds_the_operator_app_refusal_to_the_recreated_v29() {
    assert_eq!(
        hex_digest(&canonical_json_bytes(&recreated_v29()).unwrap()),
        "f82a0c2d60923f20ce5db0f55948309c492da536a73a253336c12e1ce2af699c"
    );
}

/// v30 changes nothing outside the rows' `result_schema`s, and inside them
/// only the `outcome` enum and its description. The advertised
/// `computer_use` definition is built from each row's `request_schema`, so
/// those keep their exact bytes.
#[test]
fn v30_changes_only_the_outcomes() {
    let previous = recreated_v29();
    let current = recreated_v30();
    let previous_rows = previous["rows"].as_array().unwrap();
    let current_rows = current["rows"].as_array().unwrap();
    assert_eq!(previous_rows.len(), current_rows.len());
    for (before, after) in previous_rows.iter().zip(current_rows) {
        let id = after["capability_id"].as_str().unwrap();
        assert_eq!(
            canonical_json_bytes(&before["request_schema"]).unwrap(),
            canonical_json_bytes(&after["request_schema"]).unwrap(),
            "{id} request_schema"
        );
        let mut before = before.clone();
        let mut after = after.clone();
        for row in [&mut before, &mut after] {
            row["result_schema"]["properties"]["outcome"] = json!({});
        }
        assert_eq!(before, after, "{id} changed outside its outcome");
    }
    let mut previous = previous;
    let mut current = current;
    previous.as_object_mut().unwrap().remove("rows");
    current.as_object_mut().unwrap().remove("rows");
    previous["revision"] = current["revision"].clone();
    assert_eq!(
        previous, current,
        "a document field other than revision changed"
    );
}

fn recreated_v33() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join(format!(
            "{}.json",
            historical_revision(33).as_str().unwrap()
        ));
    let previous: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        hex_digest(&canonical_json_bytes(&previous).unwrap()),
        V33_ARTIFACT_SHA256
    );
    let mut current = recreated_v34();
    current["revision"] = historical_revision(33);
    let rows = current["rows"].as_array_mut().unwrap();
    let click = rows
        .iter()
        .position(|row| row["capability_id"] == "computer.takeover_click")
        .unwrap();
    assert_eq!(rows[click - 1]["capability_id"], "computer.takeover_move");
    rows.remove(click);
    for row in rows.iter_mut().filter(|row| {
        row["capability_id"]
            .as_str()
            .unwrap()
            .starts_with("computer.takeover_")
    }) {
        *row = previous["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|old| old["capability_id"] == row["capability_id"])
            .unwrap()
            .clone();
    }
    assert_eq!(
        hex_digest(&canonical_json_bytes(&current).unwrap()),
        V33_ARTIFACT_SHA256
    );
    current
}

#[test]
fn v34_only_adds_click_and_the_pointer_fronting_contract() {
    let previous = recreated_v33();
    let current = recreated_v34();
    assert_eq!(
        current,
        vocabulary_mint::v34_from_v33(&previous, historical_revision(34).as_str().unwrap())
    );
}

fn recreated_v34() -> Value {
    fn remove_reason(value: &mut Value) {
        match value {
            Value::Object(object) => object.values_mut().for_each(remove_reason),
            Value::Array(values) => {
                values.retain(|value| value != "running_app_list_unavailable");
                values.iter_mut().for_each(remove_reason);
            }
            _ => {}
        }
    }
    let mut current = historical_v35();
    current["revision"] = historical_revision(34);
    remove_reason(&mut current);
    let previous: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join(format!(
                    "{}.json",
                    historical_revision(34).as_str().unwrap()
                )),
        )
        .unwrap(),
    )
    .unwrap();
    let before = previous["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["capability_id"] == "computer.keys")
        .unwrap();
    let keys = current["rows"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["capability_id"] == "computer.keys")
        .unwrap();
    let schema = &mut keys["result_schema"];
    let branches = schema["anyOf"].as_array_mut().unwrap();
    assert_eq!(
        branches.len(),
        before["result_schema"]["anyOf"].as_array().unwrap().len() + 2
    );
    let unconfirmed = branches.pop().unwrap();
    let confirmed = branches.pop().unwrap();
    assert_eq!(
        unconfirmed["properties"]["outcome"]["enum"],
        json!(["delivery_unconfirmed", "audit_unavailable"])
    );
    assert_eq!(
        confirmed["properties"]["outcome"]["enum"],
        json!(["completed"])
    );
    for (field, word) in [
        ("outcome", "completed"),
        ("containment_rung", "semantic_element"),
    ] {
        if !before["result_schema"]["properties"][field]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!(word))
        {
            let words = schema["properties"][field]["enum"].as_array_mut().unwrap();
            let old_len = words.len();
            words.retain(|value| value != word);
            assert_eq!(words.len() + 1, old_len);
        }
    }
    assert_eq!(
        hex_digest(&canonical_json_bytes(&current).unwrap()),
        "7c36bfd082d83e1dd24db1fcf9110eb58c1ad2059aeea7b9b4068f7c9c0ab4bd"
    );
    current
}

#[test]
fn v35_only_adds_running_list_failure_and_semantic_select_all_results() {
    assert_eq!(
        historical_v35(),
        vocabulary_mint::v35_from_v34(&recreated_v34(), historical_revision(35).as_str().unwrap())
    );
}

fn historical_v35() -> Value {
    let resources = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources");
    let revision = historical_revision(35);
    let bytes = std::fs::read(resources.join(format!("{}.json", revision.as_str().unwrap())))
        .expect("read the historical v35 artifact");
    assert_eq!(hex_digest(&bytes), V35_ARTIFACT_SHA256);
    serde_json::from_slice(&bytes).expect("v35 is valid JSON")
}

#[test]
fn semantic_select_all_results_never_claim_posts_or_fronting() {
    use cerebellum_computer::platform::vocabulary::validate_capability_result;
    let success = json!({"outcome":"completed","effect_status":"effect_observed","target_fronted":false,"containment_rung":"semantic_element","posts_returned":0});
    validate_capability_result("computer.keys", &success).unwrap();
    for (field, value) in [
        ("target_fronted", json!(true)),
        ("posts_returned", json!(1)),
        ("effect_status", json!("effect_indeterminate")),
        ("fronting", json!({})),
    ] {
        let mut invalid = success.clone();
        invalid[field] = value;
        assert!(
            validate_capability_result("computer.keys", &invalid).is_err(),
            "{invalid}"
        );
    }
    let mut unconfirmed = success;
    unconfirmed["outcome"] = json!("delivery_unconfirmed");
    unconfirmed["effect_status"] = json!("effect_indeterminate");
    assert!(validate_capability_result("computer.keys", &unconfirmed).is_err());
    unconfirmed["remedy"] =
        json!("Selecting all again is safe; nothing was posted or brought forward.");
    validate_capability_result("computer.keys", &unconfirmed).unwrap();
}
