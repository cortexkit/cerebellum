//! Byte goldens captured by compiling fb3cecc2911359d77ac8447ce90f3c2e37bde419,
//! before the user-target adapter was added. Keep the captured bytes fixed;
//! changing own-browser behavior must not silently regenerate this baseline.

use std::collections::HashMap;
use std::sync::Arc;

use cerebellum::browser::navigation::BrowserSnapshotObservation;
use cerebellum::browser_config::BrowserConfig;
use cerebellum::browser_session::*;
use cerebellum::snapshot_store::{AxRecord, CommittedDocument, SnapshotKind};
use cerebellum::{handle_tool_request_for_test_with_planes, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use subc_protocol::{Flags, Frame, FrameType, Priority};

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
            "golden-loader",
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
                name: "Golden page".into(),
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

async fn reply(args: Value, ready: bool) -> Vec<u8> {
    let config = BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 1000,
        termination_grace_period_ms: 1000,
        browser_idle_timeout_ms: 60000,
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
    let frame = |args: Value, corr| {
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
    if ready {
        handle_tool_request_for_test_with_planes(
            frame(json!({"action":"status"}), 1),
            &writer,
            &planes,
        )
        .await
        .unwrap();
        output.recv().await.unwrap();
        let facts = planes.routes.accepted_bind_for_test(7, 1).unwrap();
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
                    "golden",
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
    }
    handle_tool_request_for_test_with_planes(frame(args, 2), &writer, &planes)
        .await
        .unwrap();
    let response = output.recv().await.unwrap().body;
    if ready {
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["outcome"],
            "ok",
            "snapshot success fixture"
        );
        let scope = planes
            .routes
            .accepted_bind_for_test(7, 1)
            .unwrap()
            .identity
            .conversation_key;
        let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
            route_channel: 9,
            epoch: 1,
            principal: Some(subc_protocol::Principal::Reserved {
                module_id: "broca".into(),
            }),
            identity: subc_protocol::BindIdentity::new("/fixture", "fixture", "session"),
            admission_facts: None,
            consumer_capabilities: None,
            target: subc_protocol::RouteTarget::ManagementSurface {
                module_id: "cerebellum".into(),
            },
            scope: None,
            role_versions: None,
            call_mode: None,
        };
        for (channel, body) in [
            (0, serde_json::to_value(bind).unwrap()),
            (
                9,
                json!({"method":"private_content.query", "params":{"scope_ref":scope}}),
            ),
        ] {
            let frame = Frame::build(
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                channel,
                if channel == 0 { 0 } else { 1 },
                3,
                serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
            cerebellum::handle_frame_for_test(frame, &writer, &planes)
                .await
                .unwrap();
            let reply = output.recv().await.unwrap();
            assert_eq!(reply.header.ty, FrameType::Response);
            if channel == 9 {
                assert_eq!(
                    serde_json::from_slice::<Value>(&reply.body).unwrap(),
                    json!({"private_content":true,"sources":["signed_in_site"]})
                );
            }
        }
    }
    response
}

/// Snapshot ids carry a random per-context nonce, so an id never repeats
/// across browsers or module restarts and no recorded reply can reproduce one.
/// Where the golden has a `snapshot_id`, swap the reply's id for the golden's
/// at the two places a snapshot reply prints it: the top-level `snapshot_id`
/// field and the `state_text` header line. Every other byte is still compared.
fn with_golden_snapshot_id(reply: Vec<u8>, golden: &str) -> Vec<u8> {
    let golden: Value = serde_json::from_str(golden).unwrap();
    let Some(golden_id) = golden.get("snapshot_id").and_then(Value::as_str) else {
        return reply;
    };
    let mut value: Value = serde_json::from_slice(&reply).unwrap();
    // The swap re-serializes the reply, which is only byte-faithful when the
    // reply's bytes are already exactly what serialization produces.
    assert_eq!(
        serde_json::to_vec(&value).unwrap(),
        reply,
        "the reply does not re-serialize to its own bytes"
    );
    let id = value
        .get("snapshot_id")
        .and_then(Value::as_str)
        .expect("the golden has a snapshot_id and the reply has none")
        .to_string();
    assert!(
        id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "the reply's snapshot_id is not 32 lowercase hex characters: {id}"
    );
    value["snapshot_id"] = json!(golden_id);
    let text = value["state_text"]
        .as_str()
        .expect("a snapshot reply has state_text");
    let (header, rest) = text
        .split_once('\n')
        .expect("state_text starts with a header line");
    let site = header
        .strip_suffix(&format!(" · snapshot {id}"))
        .expect("the state_text header names the reply's snapshot id");
    value["state_text"] = json!(format!("{site} · snapshot {golden_id}\n{rest}"));
    serde_json::to_vec(&value).unwrap()
}

#[tokio::test]
async fn own_replies_are_byte_identical_to_the_pre_user_build() {
    let cases = [
        (json!({"action":"status"}), false),
        (json!({"action":"snapshot"}), true),
        (json!({"action":"navigate"}), false),
        (json!({"action":"snapshot","unexpected":true}), false),
        (json!({"action":"close"}), false),
    ];
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/browser_own_pre_user.json");
    let goldens: Vec<String> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(goldens.len(), cases.len());
    for ((args, ready), golden) in cases.into_iter().zip(goldens) {
        assert_eq!(
            with_golden_snapshot_id(reply(args.clone(), ready).await, &golden),
            golden.as_bytes()
        );
        let mut own = args;
        own["browser"] = json!("own");
        assert_eq!(
            with_golden_snapshot_id(reply(own, ready).await, &golden),
            golden.as_bytes()
        );
    }
    println!("compared 10 own replies against 5 pre-user-build byte goldens");
}
