//! Real tool frames over a scripted desk: no OS launch or permission request.

#![cfg(target_os = "macos")]

use super::*;
use cerebellum_computer::app_state::source::InstalledApp;
use cerebellum_core::journal::{InMemoryJournalStorage, JournalConfig};
use std::time::Duration;
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};

#[allow(dead_code)]
mod support {
    use crate as cerebellum;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/it/support/computer.rs"
    ));
}

fn installed(name: &str, bundle: &str) -> InstalledApp {
    InstalledApp {
        name: name.into(),
        bundle_identity: bundle.into(),
        path: std::path::PathBuf::from(format!("/Applications/{name}.app")),
    }
}

fn rig() -> (crate::Planes, support::Desk, InMemoryJournalStorage) {
    rig_with_lock(false)
}

fn rig_with_lock(locked: bool) -> (crate::Planes, support::Desk, InMemoryJournalStorage) {
    use cerebellum_computer::capture_custody::*;
    let mut planes = crate::Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    let desk = support::Desk::new(Vec::new());
    desk.state().installed.apps = vec![installed("Safari", "com.apple.Safari")];
    planes.management = Arc::new(crate::management::ManagementPlane::new(Arc::new(
        support::Fixed(cerebellum_computer::platform::TargetResolution::NotRunning),
    )));
    let storage = InMemoryJournalStorage::new();
    let custody = CaptureCustody::new(
        CustodyBounds {
            maximum_verification_duration_ms: 5000,
            maximum_pin_lifetime_ms: 30000,
            maximum_concurrently_pinned_artifacts: 8,
            maximum_total_pinned_artifact_bytes: 64 * 1024 * 1024,
            maximum_custody_attachment_bytes: 16 * 1024 * 1024,
        },
        InMemoryGrantAuthority::default(),
        InMemoryCustodyStorage::new(),
    )
    .unwrap();
    let audit = ComputerAudit::new(
        cerebellum_computer::audit::redaction::ExcludeApplicationText,
        cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
        JournalConfig {
            journal_retention_bytes: 8 * 1024 * 1024,
            journal_max_entry_bytes: 64 * 1024,
        },
        crate::PlaneJournalStorage::InMemory(storage.clone()),
        custody,
    )
    .unwrap();
    planes.computer = Ok(Arc::new(
        ComputerPlane::with_synthetic_driver(audit, NativeComputerPlatformDriver::default)
            .with_session_lock_for_test(Some(locked))
            .with_app_state_source(desk.source()),
    ));
    // Permissions deliberately absent: inventory, LaunchServices and public
    // window metadata require none and must not ask the OS to grant anything.
    planes.computer_admitted = Arc::new(
        [
            "computer.open_app".to_string(),
            "computer.list_apps".to_string(),
        ]
        .into(),
    );
    planes.routes.insert(9,3,crate::AcceptedBindFacts::from_bind(&subc_protocol::BindIdentity::new("/test/project","test","test-session"),crate::session_caller_principal_for_test(),Some(&json!({"agentProjectId":"test-project","sessionKind":"primary","effectiveCapabilityScope":["*"]})),Some(&["elicitation".into()]),&subc_protocol::RouteTarget::ToolProvider { module_id:"cerebellum".into() }));
    (planes, desk, storage)
}

async fn wire(planes: &crate::Planes, action: &str, arguments: Value) -> (Value, usize) {
    let request = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false), 9, 3, 71, serde_json::to_vec(&json!({"name":"computer_use","arguments":{"action":action, "target":arguments.get("target").cloned().unwrap_or(Value::Null)}})).unwrap()).unwrap();
    // list_apps accepts no target, including null.
    let request = if action == "list_apps" {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            9,
            3,
            71,
            serde_json::to_vec(&json!({"name":"computer_use","arguments":{"action":action}}))
                .unwrap(),
        )
        .unwrap()
    } else {
        request
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame_for_test(request, &tx, planes)
        .await
        .unwrap();
    let mut questions = 0;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let value: Value = serde_json::from_slice(&frame.body).unwrap();
        if frame.header.ty == FrameType::Request {
            questions += 1;
            assert!(value.to_string().contains("app"), "{value}");
            let answer = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
                serde_json::to_vec(&json!({"decision":"allow_conversation"})).unwrap(),
            )
            .unwrap();
            crate::handle_frame_for_test(answer, &tx, planes)
                .await
                .unwrap();
        } else {
            assert_eq!(frame.header.ty, FrameType::Response, "{value}");
            return (value, questions);
        }
    }
}

#[tokio::test]
async fn open_app_first_use_asks_and_granted_launch_does_not_activate() {
    let (planes, desk, _) = rig();
    let (first, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(questions, 1);
    assert_eq!(first["outcome"], "launched", "{first}");
    let (second, questions) = wire(&planes, "open_app", json!({"target":"com.apple.Safari"})).await;
    assert_eq!(questions, 0);
    assert_eq!(second["outcome"], "launched", "{second}");
    let state = desk.state();
    assert_eq!(state.opens.len(), 2);
    assert!(state.opens.iter().all(|bounds| !bounds.activates));
    assert_eq!(state.opens[0].process_timeout, Duration::from_secs(30));
    assert_eq!(state.opens[0].window_timeout, Duration::from_secs(10));
}

#[tokio::test]
async fn open_app_unsigned_and_ad_hoc_bundles_refuse_before_consent() {
    let (planes, desk, _) = rig();
    for ad_hoc in [false, true] {
        {
            let mut state = desk.state();
            let signature = state.signature.as_mut().unwrap();
            signature.signed = ad_hoc;
            signature.ad_hoc = ad_hoc;
        }
        let (reply, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
        assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
        assert_eq!(questions, 0);
        assert!(desk.state().opens.is_empty());
    }
}

#[tokio::test]
async fn open_app_ambiguous_name_lists_candidates_without_launching() {
    let (planes, desk, _) = rig();
    desk.state().installed.apps = vec![
        installed("Editor", "com.one.Editor"),
        installed("Editor", "com.two.Editor"),
    ];
    let (reply, questions) = wire(&planes, "open_app", json!({"target":"Editor"})).await;
    assert_eq!(reply["outcome"], "ambiguous_app", "{reply}");
    assert_eq!(
        reply["candidates"],
        json!([{"name":"Editor","bundle_identity":"com.one.Editor"},{"name":"Editor","bundle_identity":"com.two.Editor"}])
    );
    assert_eq!(questions, 0);
    assert!(desk.state().opens.is_empty());
}

#[tokio::test]
async fn open_app_already_running_and_window_timeout_are_disclosed() {
    let (planes, desk, _) = rig();
    desk.state().opened.already_running = true;
    let (reply, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(reply["outcome"], "already_running", "{reply}");
    assert_eq!(reply["has_window"], true);
    assert_eq!(reply["pid"], support::grant().pid);
    {
        let mut state = desk.state();
        state.opened.already_running = false;
        state.opened.has_window = false;
    }
    let (reply, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(questions, 0);
    assert_eq!(reply["outcome"], "launched_no_window", "{reply}");
    assert_eq!(reply["has_window"], false);
}

#[tokio::test]
async fn open_app_discloses_an_app_that_fronts_itself() {
    let (planes, desk, _) = rig();
    for frontmost in [true, false] {
        desk.state().opened.frontmost = frontmost;
        let (reply, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
        assert_eq!(reply["outcome"], "launched", "{reply}");
        assert_eq!(reply["frontmost"], frontmost, "{reply}");
    }
}

#[tokio::test]
async fn list_apps_orders_caps_and_discloses_partial_inventory() {
    let (planes, desk, _) = rig();
    {
        let mut state = desk.state();
        state.installed.apps = vec![
            installed("Zulu", "com.zulu"),
            installed("Alpha", "com.alpha"),
            installed("Safari", "com.apple.Safari"),
        ];
    }
    let (reply, questions) = wire(&planes, "list_apps", json!({})).await;
    assert_eq!(questions, 0);
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["installed_list"], "complete");
    assert_eq!(reply["truncated"], false);
    assert_eq!(reply["apps"][0]["running"], true);
    assert_eq!(reply["apps"][1]["name"], "Alpha");
    assert_eq!(reply["apps"][2]["name"], "Zulu");
    assert!(reply["apps"][1].get("pid").is_none());
    assert_eq!(reply["apps"][1]["frontmost"], false);
    assert!(reply["state_text"]
        .as_str()
        .unwrap()
        .contains("installed (not running):\nAlpha"));
    {
        let mut state = desk.state();
        state.installed.complete = false;
        state.installed.apps = (0..600)
            .rev()
            .map(|n| installed(&format!("App{n:03}"), &format!("com.app{n}")))
            .collect();
    }
    let (reply, _) = wire(&planes, "list_apps", json!({})).await;
    assert_eq!(reply["apps"].as_array().unwrap().len(), 500);
    assert_eq!(reply["truncated"], true);
    assert_eq!(reply["installed_list"], "partial");
    assert_eq!(reply["apps"][1]["name"], "App000");
    assert_eq!(reply["apps"][499]["name"], "App498");
}

#[tokio::test]
async fn open_app_journal_keeps_planted_name_only_in_app() {
    const PLANTED: &str = "SecretAppName9d2c";
    let (planes, desk, storage) = rig();
    desk.state().installed.apps[0].name = PLANTED.into();
    let (reply, _) = wire(&planes, "open_app", json!({"target":PLANTED})).await;
    assert_eq!(reply["outcome"], "launched", "{reply}");
    let durable = storage.load().unwrap();
    fn expand(value: &mut Value) {
        match value {
            Value::String(text) => {
                if let Ok(bytes) = cerebellum_core::serde_base64::decode(text) {
                    if let Ok(decoded) = serde_json::from_slice::<Value>(&bytes) {
                        *value = decoded;
                        expand(value);
                    }
                }
            }
            Value::Object(object) => {
                for child in object.values_mut() {
                    expand(child);
                }
            }
            Value::Array(values) => {
                let bytes: Option<Vec<u8>> = values
                    .iter()
                    .map(|value| value.as_u64().and_then(|n| u8::try_from(n).ok()))
                    .collect();
                if let Some(decoded) =
                    bytes.and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                {
                    *value = decoded;
                    expand(value);
                } else {
                    for child in values {
                        expand(child);
                    }
                }
            }
            _ => {}
        }
    }
    let mut journal = serde_json::to_value(&durable).unwrap();
    expand(&mut journal);
    // The positive control proves the scanner reaches the stored outcome.
    assert!(journal.to_string().contains(PLANTED), "{journal}");
    fn strip_app(value: &mut Value) {
        match value {
            Value::Object(object) => {
                object.remove("app");
                for child in object.values_mut() {
                    strip_app(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    strip_app(child);
                }
            }
            _ => {}
        }
    }
    strip_app(&mut journal);
    assert!(!journal.to_string().contains(PLANTED), "{journal}");
}

#[tokio::test]
async fn open_app_locked_screen_refuses_before_consent_or_launch() {
    let (planes, desk, _) = rig_with_lock(true);
    let (reply, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(reply["outcome"], "screen_locked", "{reply}");
    assert_eq!(questions, 0);
    assert!(desk.state().opens.is_empty());
}

#[tokio::test]
async fn open_app_partial_inventory_cannot_certify_a_unique_name() {
    let (planes, desk, _) = rig();
    desk.state().installed.complete = false;
    let (reply, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(reply["outcome"], "installed_list_partial", "{reply}");
    assert_eq!(reply["installed_list"], "partial");
    assert_eq!(questions, 0);
    assert!(desk.state().opens.is_empty());
}
