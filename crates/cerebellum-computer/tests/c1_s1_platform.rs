use std::collections::BTreeSet;

mod vocabulary_mint;

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

const VOCABULARY: &str = include_str!("../resources/computer_action_vocabulary-v14.json");
const V13_ARTIFACT_SHA256: &str =
    "df4dd2cae84214efad94c3e3ce83537abc284252c8375e49ba151afe416c62fc";
const V7_ARTIFACT_SHA256: &str = "6548025a7f99bf0984651d0345a962baf792d9428274e8f262542509e61674af";
/// The digest of the v12 artifact, measured before v13 was minted.
const V12_ARTIFACT_SHA256: &str =
    "a820c3519c72bdedf0c7604f8f30531411d4538345e63fc160835aabcb422bfa";
/// The five rows v12 carried and v13 removed, exactly as v12 wrote them. The
/// delta chain needs them to rebuild v12, and they exist nowhere else now.
const RETIRED_V12_ROWS: &str = include_str!("fixtures/v12_retired_rows.json");
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
fn vocabulary_has_exactly_ten_rows_and_locked_digest() {
    let validated = validate_vocabulary().expect("frozen vocabulary must validate");
    assert_eq!(validated.revision, COMPUTER_ACTION_VOCABULARY_REVISION);
    assert_eq!(validated.schema_id, "ck-computer-action-vocabulary/v2");
    assert_eq!(validated.row_count, 10, "absolute row-count invariant");
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
    assert_eq!(declarations.len(), 10);
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
            "computer.takeover_drag",
            "computer.takeover_scroll"
        ]
    );
    let ids: BTreeSet<_> = declarations
        .iter()
        .map(|item| item.capability_id.as_str())
        .collect();
    assert_eq!(ids.len(), 10);
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
    let generated = vocabulary_mint::v14_from_v13(&generated, COMPUTER_ACTION_VOCABULARY_REVISION);
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
        vocabulary_mint::V13_ROW_IDS
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

/// Undo only the two closed-enum additions; open keystroke outcomes need no artifact change.
fn recreated_v13() -> Value {
    let mut vocabulary: Value = serde_json::from_str(VOCABULARY).unwrap();
    vocabulary["revision"] = historical_revision(13);
    for (id, pointer, word) in [
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

#[test]
fn v14_refusal_words_validate_in_their_declared_fields() {
    use cerebellum_computer::platform::vocabulary::validate_capability_result;
    for (id, outcome) in [
        ("computer.keys", "modifier_chord_needs_foreground"),
        ("computer.keys", "private_input_auth_failed"),
        ("computer.type", "private_input_auth_failed"),
        ("computer.write_text", "web_content_needs_type"),
    ] {
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
            "outcome": "completed", "tree": "", "unreadable_subtrees": 0,
            "image_unavailable": {"reason": "window_covered_may_be_stale"}
        }),
    )
    .unwrap();
}
