//! Byte goldens for `private_content.query`: the request Broca sends and the
//! reply cerebellum returns, captured at the production `handle_frame` entry
//! point rather than assembled from an expected JSON object.
//!
//! The marked case seeds its mark the way production does: an owned-browser
//! snapshot of a page read while the profile holds login evidence, which the
//! reply path records as `signed_in_site`. No screen text, image, or login
//! secret leaves the fixture: only the query request and its answer are
//! pinned.

use std::collections::HashMap;
use std::sync::Arc;

use cerebellum::browser::navigation::BrowserSnapshotObservation;
use cerebellum::browser_config::BrowserConfig;
use cerebellum::browser_session::*;
use cerebellum::snapshot_store::{AxRecord, CommittedDocument, SnapshotKind};
use cerebellum::{handle_frame_for_test, handle_tool_request_for_test_with_planes};
use cerebellum::{JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget};

fn directory() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/private-content-query-v1")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn frame(frame: &Frame) -> Value {
    let mut bytes = frame.header.encode().to_vec();
    bytes.extend_from_slice(&frame.body);
    json!({
        "type": format!("{:?}", frame.header.ty),
        "channel": frame.header.channel, "epoch": frame.header.epoch,
        "corr": frame.header.corr, "body_length": frame.body.len(),
        "body_utf8": std::str::from_utf8(&frame.body).unwrap(),
        "wire_hex": hex(&bytes),
    })
}

/// Compare a captured exchange with its pinned file. With
/// `CEREBELLUM_WRITE_PRIVATE_CONTENT_QUERY_VECTORS` set, rewrite the file and
/// the checksums first, for a deliberate contract change.
fn check(case: &str, state: &str, request: &Frame, reply: &Frame) {
    assert_eq!(reply.header.ty, FrameType::Response);
    let value = json!({
        "contract": "private-content-query-v1", "case": case, "state": state,
        "principal": "reserved:broca",
        "request": frame(request), "reply": frame(reply),
    });
    assert_private_text_absent(&value);
    let bytes = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
    let dir = directory();
    let path = dir.join(format!("{case}.json"));
    // Parallel cases must not publish checksums describing a half-written
    // sibling.
    static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _write = WRITE.lock().unwrap();
    if std::env::var_os("CEREBELLUM_WRITE_PRIVATE_CONTENT_QUERY_VECTORS").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::write(dir.join("SHA256SUMS"), sums()).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        bytes,
        "{case} wire bytes changed"
    );
}

fn sums() -> String {
    let mut files: Vec<_> = std::fs::read_dir(directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "SHA256SUMS")
        .collect();
    files.sort();
    files
        .iter()
        .map(|path| {
            format!(
                "{}  {}\n",
                hex(&Sha256::digest(std::fs::read(path).unwrap())),
                path.file_name().unwrap().to_str().unwrap()
            )
        })
        .collect()
}

fn assert_private_text_absent(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                assert!(
                    ![
                        "state_text",
                        "page_text",
                        "dom_text",
                        "html",
                        "text",
                        "title",
                        "label",
                        "value",
                        "records",
                        "png_base64"
                    ]
                    .contains(&key.as_str()),
                    "private screen/page content field: {key}"
                );
                if key == "body_utf8" {
                    let text = value.as_str().unwrap();
                    if !text.is_empty() {
                        assert_private_text_absent(&serde_json::from_str::<Value>(text).unwrap());
                    }
                } else {
                    assert_private_text_absent(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_private_text_absent(value);
            }
        }
        Value::String(text) => {
            assert!(
                !["/Users/", "/private/", "/tmp/", "/.t/"]
                    .iter()
                    .any(|prefix| text.contains(prefix)),
                "vectors must not contain machine-local paths"
            );
            if let Ok(nested) = serde_json::from_str::<Value>(text) {
                if nested.is_object() || nested.is_array() {
                    assert_private_text_absent(&nested);
                }
            }
        }
        _ => {}
    }
}

struct Process;

impl OwnedBrowserProcess for Process {
    fn generation_matches(&self) -> bool {
        true
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_for_exit(&mut self, _: std::time::Duration) -> Result<bool, ProcessControlFailure> {
        Ok(true)
    }
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn committed_document(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        Ok(CommittedDocument::new(
            "https://example.com/",
            1,
            "vector-loader",
        ))
    }
    fn snapshot_classified(
        &mut self,
        _: &str,
        _: SnapshotKind,
        _: u64,
        _: &str,
        _: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        Ok(BrowserSnapshotObservation {
            records: vec![AxRecord {
                depth: 0,
                role: "StaticText".into(),
                name: "Vector seeding page".into(),
                value: None,
                reference: None,
            }],
            dom_text: None,
            refs: Vec::new(),
            ax_truncated: false,
            refs_truncated: false,
            facts: HashMap::new(),
        })
    }
}

struct Cleanup;

impl SessionCleanup for Cleanup {
    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        Ok(SessionCleanupOutcome::Complete)
    }
}

/// Drives the real management handler for the three pinned cases and compares
/// the exact request and reply bytes.
#[tokio::test]
#[cfg(any(not(windows), feature = "windows-browser-release"))] // Needs the Windows browser release key.
async fn private_content_query_wire_shapes_match_their_goldens() {
    let config = BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 1000,
        termination_grace_period_ms: 1000,
        browser_idle_timeout_ms: 60_000,
        browser_exit_observation_deadline_ms: 1000,
        navigation_settle_deadline_ms: 1000,
    };
    let signed_in = Arc::new(cerebellum::browser_signed_in::SignedInDomains::default());
    let mut planes = Planes::with_browser_state(
        Arc::new(HealthState::new()),
        Some(config.clone()),
        JournalPersistence::Isolated,
        None,
        Some(Arc::clone(&signed_in)),
    );
    let (writer, mut output) = tokio::sync::mpsc::channel(8);
    let tool = |args: Value, corr| {
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            7,
            1,
            corr,
            serde_json::to_vec(&json!({"name":"browser_use","arguments":args})).unwrap(),
        )
        .unwrap()
    };
    // A status call binds the tool route, so the fixture can read whose
    // conversation is about to hold login evidence.
    handle_tool_request_for_test_with_planes(tool(json!({"action":"status"}), 1), &writer, &planes)
        .await
        .unwrap();
    output.recv().await.unwrap();
    let facts = planes.routes.accepted_bind_for_test(7, 1).unwrap();
    let marked_scope = facts.identity.conversation_key.clone();
    signed_in
        .record(
            &facts.identity.agent_project_id,
            &cerebellum::browser_signed_in::SignedInDomains::profile_name(&facts.identity),
            "https://accounts.example.net",
        )
        .unwrap();
    assert!(matches!(
        planes
            .sessions
            .acquire_launch_slot(&facts.identity.conversation_key),
        LaunchSlot::Acquired { .. }
    ));
    planes
        .sessions
        .establish_ready(
            &facts.identity.conversation_key,
            facts.identity.profile_disposition,
            &config,
            planes.lease_clock.as_ref(),
            Box::new(Process),
            Box::new(Cleanup),
        )
        .unwrap();
    planes.browser = Arc::new(
        cerebellum::browser::BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            planes.lease_clock.clone(),
            1000,
        )
        .with_grants_installed(cerebellum::authorization::GrantStore::new([
            cerebellum::authorization::ActionGrant::for_conversation(
                "vector",
                1,
                facts.identity.conversation_key.clone(),
                cerebellum::authorization::Severity::new(1, false, false),
                ["https://example.com"],
            ),
        ]))
        .with_in_memory_journal(cerebellum::journal::JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 64_000,
        }),
    );
    planes
        .browser
        .open_context(facts.identity.clone())
        .await
        .unwrap();
    // The snapshot carries page text while the profile holds login evidence,
    // so the reply path records a `signed_in_site` mark for this scope.
    handle_tool_request_for_test_with_planes(
        tool(json!({"action":"snapshot"}), 2),
        &writer,
        &planes,
    )
    .await
    .unwrap();
    let snapshot: Value = serde_json::from_slice(&output.recv().await.unwrap().body).unwrap();
    assert_eq!(snapshot["outcome"], "ok");
    assert!(snapshot["state_text"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));

    // Bind Broca's management route through the production control path.
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 9,
        epoch: 1,
        principal: Some(subc_protocol::Principal::Reserved {
            module_id: "broca".into(),
        }),
        identity: BindIdentity::new("fixture", "session"),
        admission_facts: None,
        consumer_capabilities: None,
        target: RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
        scope: None,
        role_versions: None,
        call_mode: None,
    };
    let frame = |channel, corr, body: Value| {
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            if channel == 0 { 0 } else { 1 },
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    };
    handle_frame_for_test(
        frame(0, 3, serde_json::to_value(bind).unwrap()),
        &writer,
        &planes,
    )
    .await
    .unwrap();
    let bound = output.recv().await.unwrap();
    assert_eq!(bound.header.ty, FrameType::Response);

    let query = |corr, params: Value| {
        frame(
            9,
            corr,
            json!({"method": "private_content.query", "params": params}),
        )
    };

    let request = query(11, json!({"scope_ref": marked_scope}));
    handle_frame_for_test(request.clone(), &writer, &planes)
        .await
        .unwrap();
    let reply = output.recv().await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        json!({"private_content": true, "sources": ["signed_in_site"]})
    );
    check(
        "success-marked",
        "the snapshotted scope read a signed-in page",
        &request,
        &reply,
    );

    let request = query(12, json!({"scope_ref": "unmarked-scope"}));
    handle_frame_for_test(request.clone(), &writer, &planes)
        .await
        .unwrap();
    let reply = output.recv().await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        json!({"private_content": false, "sources": []})
    );
    check(
        "success-unmarked",
        "no scope read private content",
        &request,
        &reply,
    );

    // The first live call sent `owner` beside `scope_ref`: an unknown field is
    // refused, naming it, and the refusal shape below is what callers pin.
    let request = query(
        13,
        json!({"scope_ref": marked_scope, "owner": "reserved:broca"}),
    );
    handle_frame_for_test(request.clone(), &writer, &planes)
        .await
        .unwrap();
    let reply = output.recv().await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        json!({
            "outcome": "invalid_request",
            "context": Value::Null,
            "session": Value::Null,
            "detail": {"field": "owner", "reason_code": "unknown_field"},
        })
    );
    check(
        "unknown-field",
        "the live call's extra owner parameter is refused",
        &request,
        &reply,
    );

    let pinned = std::fs::read_to_string(directory().join("SHA256SUMS")).unwrap();
    assert_eq!(pinned, sums());
    let names: Vec<&str> = pinned
        .lines()
        .map(|line| line.split_once("  ").unwrap().1)
        .collect();
    assert_eq!(
        names,
        [
            "README.md",
            "success-marked.json",
            "success-unmarked.json",
            "unknown-field.json"
        ]
    );
}
