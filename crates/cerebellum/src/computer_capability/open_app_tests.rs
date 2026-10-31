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
    rig_with_history(locked, crate::open_app_history::LaunchHistory::in_memory())
}

fn rig_with_history(
    locked: bool,
    history: crate::open_app_history::LaunchHistory,
) -> (crate::Planes, support::Desk, InMemoryJournalStorage) {
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
        ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::Withhold,
            NativeComputerPlatformDriver::default,
        )
        .with_launch_history(history)
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
    planes.routes.insert(9,3,crate::AcceptedBindFacts::from_bind(&subc_protocol::BindIdentity::new("test", "test-session"),crate::session_caller_principal_for_test(),Some(&json!({"agentProjectId":"test-project","sessionKind":"primary","effectiveCapabilityScope":["*"]})),Some(&["elicitation".into()]),&subc_protocol::RouteTarget::ToolProvider { module_id:"cerebellum".into() }));
    let planes = crate::computer_grants::tests::CardService::install(planes, 9, 3);
    (planes, desk, storage)
}

async fn wire(planes: &crate::Planes, action: &str, arguments: Value) -> (Value, usize) {
    wire_with_decision(planes, action, arguments, "allow_30m").await
}

async fn wire_with_decision(
    planes: &crate::Planes,
    action: &str,
    arguments: Value,
    decision: &str,
) -> (Value, usize) {
    let mut arguments = arguments;
    arguments["action"] = json!(action);
    let request = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        71,
        serde_json::to_vec(&json!({"name":"computer_use","arguments":arguments})).unwrap(),
    )
    .unwrap();
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
        let service = planes.consent_test.as_ref().unwrap();
        tokio::select! {
            question = service.card(9, 3) => {
                questions += 1;
                let value: Value = serde_json::from_slice(&question.body).unwrap();
                assert!(value.to_string().contains("app"), "{value}");
                assert!(service.answer(question.header.corr, crate::cingulate_client::ScriptedAnswer::Answered(json!({"decision":decision}))));
            }
            frame = rx.recv() => {
                let frame = frame.unwrap();
                let value: Value = serde_json::from_slice(&frame.body).unwrap();
                assert_eq!(frame.header.ty, FrameType::Response, "{value}");
                return (value, questions);
            }
        }
    }
}

#[tokio::test]
async fn open_app_refuses_unregistered_and_forbidden_schemes_by_name() {
    let (planes, desk, _) = rig();
    desk.state().url_schemes = vec![
        "x-apple.systempreferences".into(),
        "file".into(),
        "https".into(),
        "http".into(),
    ];
    for scheme in ["unregistered", "file", "http", "https"] {
        let (reply, questions) = wire(
            &planes,
            "open_app",
            json!({"target":"Safari", "url":format!("{scheme}:synthetic-page")}),
        )
        .await;
        assert_eq!(reply["outcome"], "url_scheme_refused", "{reply}");
        assert_eq!(reply["scheme"], scheme);
        assert!(reply["remedy"].as_str().unwrap().contains(scheme));
        assert!(reply["remedy"].as_str().unwrap().starts_with("On macOS, "));
        assert_eq!(questions, 0);
    }
    assert!(desk.state().opens.is_empty());
}

#[tokio::test]
async fn open_app_registered_page_keeps_consent_signer_and_no_activation() {
    let (planes, desk, _) = rig();
    desk.state().url_schemes = vec!["x-apple.systempreferences".into()];
    let url = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";
    let (reply, questions) = wire(&planes, "open_app", json!({"target":"Safari", "url":url})).await;
    assert_eq!(reply["outcome"], "launched", "{reply}");
    assert_eq!(questions, 1);
    assert_eq!(desk.state().opened_urls, [url]);
    assert!(!desk.state().opens[0].activates);
    desk.state().signature.as_mut().unwrap().ad_hoc = true;
    let (reply, questions) = wire(&planes, "open_app", json!({"target":"Safari", "url":url})).await;
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert_eq!(questions, 0);
    assert_eq!(desk.state().opened_urls.len(), 1);
}

#[tokio::test]
async fn open_app_first_use_asks_and_granted_launch_does_not_activate() {
    let (planes, desk, _) = rig();
    let (first, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(questions, 1);
    assert_eq!(first["outcome"], "launched", "{first}");
    assert_eq!(first["installed_list"], "complete");
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
        assert_eq!(reply["remedy"], "On macOS, the installed application must carry a valid, non-ad-hoc signature before it can be launched");
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
    for complete in [true, false] {
        desk.state().installed.complete = complete;
        let (reply, questions) = wire(&planes, "open_app", json!({"target":"Editor"})).await;
        assert_eq!(reply["outcome"], "ambiguous_app", "{reply}");
        assert_eq!(reply["remedy"], "several installed applications match; use a unique app identity (a bundle id on macOS; duplicate installations must be removed or renamed)");
        assert_eq!(
            reply["installed_list"],
            if complete { "complete" } else { "partial" }
        );
        assert_eq!(
            reply["candidates"],
            json!([{"name":"Editor","bundle_identity":"com.one.Editor"},{"name":"Editor","bundle_identity":"com.two.Editor"}])
        );
        assert_eq!(questions, 0);
        assert!(desk.state().opens.is_empty());
    }
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
async fn open_app_partial_inventory_launches_a_unique_signer_approved_match() {
    let (planes, desk, _) = rig();
    desk.state().installed.complete = false;
    let (reply, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(reply["outcome"], "launched", "{reply}");
    assert_eq!(reply["installed_list"], "partial");
    assert_eq!(questions, 1);
    assert_eq!(desk.state().opens.len(), 1);
    assert!(!desk.state().opens[0].activates);
}

#[tokio::test]
async fn open_app_partial_inventory_missing_match_discloses_unreadable_part() {
    let (planes, desk, _) = rig();
    for complete in [true, false] {
        desk.state().installed.complete = complete;
        let (reply, questions) = wire(&planes, "open_app", json!({"target":"Missing"})).await;
        assert_eq!(reply["outcome"], "no_installed_app_named", "{reply}");
        assert!(reply["remedy"]
            .as_str()
            .unwrap()
            .contains("app identity (a bundle id on macOS)"));
        assert_eq!(
            reply["installed_list"],
            if complete { "complete" } else { "partial" }
        );
        if !complete {
            assert!(
                reply["remedy"]
                    .as_str()
                    .unwrap()
                    .contains("may be in the unreadable part"),
                "{reply}"
            );
        }
        assert_eq!(questions, 0);
        assert!(desk.state().opens.is_empty());
    }
}

#[tokio::test]
async fn open_app_slow_retry_learns_timeout_and_reports_usual_readiness() {
    let (planes, desk, _) = rig();
    // A previous ready launch supplies a median; the next cold start times out.
    desk.state().opened.first_window_ms = Some(30_000);
    let (ready, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(ready["outcome"], "launched", "{ready}");
    assert!(ready.get("usual_ready_ms").is_none());
    desk.state().open_error = Some(cerebellum_computer::app_state::source::OpenAppError::TimedOut);
    let (timed_out, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(timed_out["outcome"], "launch_failed", "{timed_out}");
    assert_eq!(timed_out["usual_ready_ms"], 30_000);
    {
        let mut state = desk.state();
        state.open_error = None;
        state.opened.first_window_ms = Some(50_000);
    }
    let (retry, questions) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(retry["outcome"], "launched", "{retry}");
    assert_eq!(questions, 0);
    assert_eq!(retry["usual_ready_ms"], 30_000);
    assert!(retry["launch_note"]
        .as_str()
        .unwrap()
        .contains("slower than usual"));
    let state = desk.state();
    assert_eq!(state.opens[1].ready_timeout, Duration::from_secs(40));
    assert_eq!(state.opens[2].ready_timeout, Duration::from_secs(80));
    assert!(!state.opens[2].activates);
}

#[tokio::test]
async fn open_app_second_slow_launch_after_timeout_gets_a_longer_deadline() {
    let (planes, desk, _) = rig();
    {
        let mut state = desk.state();
        state.opened.has_window = false;
        state.opened.first_window_ms = None;
    }
    let (first, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(first["outcome"], "launched_no_window", "{first}");
    {
        let mut state = desk.state();
        state.opened.has_window = true;
        state.opened.first_window_ms = Some(50_000);
    }
    let (second, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(second["outcome"], "launched", "{second}");
    assert!(
        second.get("usual_ready_ms").is_none(),
        "a timeout budget is not an observed ready time: {second}"
    );
    assert!(second.get("launch_note").is_none());
    assert_eq!(desk.state().opens[1].ready_timeout, Duration::from_secs(80));
    desk.state().opened.first_window_ms = Some(75_000);
    let (third, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(third["outcome"], "launched", "{third}");
    assert_eq!(third["usual_ready_ms"], 50_000);
    assert!(third["launch_note"]
        .as_str()
        .unwrap()
        .contains("slower than usual"));
}

#[tokio::test]
async fn open_app_history_real_recording_path_excludes_planted_display_text_and_paths() {
    const SECRET: &str = "plantedlaunchsecret7b9a";
    let root = std::env::temp_dir().join(format!(
        "ck-open-app-leak-{}-{}",
        std::process::id(),
        crate::wall_clock_ms()
    ));
    let path = root.join("launches.json");
    let (planes, desk, _) = rig_with_history(
        false,
        crate::open_app_history::LaunchHistory::at(path.clone()),
    );
    {
        let mut state = desk.state();
        state.installed.apps[0].name = format!("Editor-{SECRET}");
        state.installed.apps[0].path = root.join(format!("{SECRET}.app"));
        state.window = Some((91, Some(format!("Document {SECRET}"))));
    }
    let scanner = |bytes: &[u8]| {
        bytes
            .windows(SECRET.len())
            .any(|part| part == SECRET.as_bytes())
    };
    let control = serde_json::to_vec(&json!({"name":format!("Editor-{SECRET}"),"title":format!("Document {SECRET}"),"path":format!("/{SECRET}.app")})).unwrap();
    assert!(
        scanner(&control),
        "the planted-string scanner must find its positive control"
    );
    assert!(!path.exists(), "opening the store must not create it");
    let (reply, _) = wire(
        &planes,
        "open_app",
        json!({"target":format!("Editor-{SECRET}")}),
    )
    .await;
    assert_eq!(reply["outcome"], "launched", "{reply}");
    assert_eq!(desk.state().opens.len(), 1);
    let bytes = std::fs::read(&path).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["apps"][0]["launches"].as_array().unwrap().len(), 1);
    assert_eq!(
        document["apps"][0]["launches"][0]["observation"]["first_window_ms"],
        100
    );
    assert!(
        !scanner(&bytes),
        "display text or a path leaked into launch history"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn open_app_history_read_and_write_failures_never_block_or_surface_on_wire() {
    let root = std::env::temp_dir().join(format!(
        "ck-open-app-store-failure-{}-{}",
        std::process::id(),
        crate::wall_clock_ms()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("history.json");
    std::fs::write(&path, b"corrupt history").unwrap();
    let (planes, desk, _) = rig_with_history(
        false,
        crate::open_app_history::LaunchHistory::at(path.clone()),
    );
    let (reply, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(reply["outcome"], "launched", "{reply}");
    assert!(reply.get("usual_ready_ms").is_none());
    assert_eq!(
        desk.state().opens[0],
        cerebellum_computer::app_state::source::OpenAppBounds::default()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt history");
    std::fs::remove_file(&path).unwrap();
    let history = crate::open_app_history::LaunchHistory::at(path.clone());
    // A directory planted after load makes the first atomic replacement fail.
    std::fs::create_dir(&path).unwrap();
    let (planes, desk, _) = rig_with_history(false, history);
    for _ in 0..2 {
        let (reply, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
        assert_eq!(reply["outcome"], "launched", "{reply}");
        assert!(reply.get("usual_ready_ms").is_none());
        assert!(reply.get("launch_note").is_none());
    }
    assert!(desk
        .state()
        .opens
        .iter()
        .all(|bounds| *bounds == cerebellum_computer::app_state::source::OpenAppBounds::default()));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn open_app_refusals_do_not_create_or_replace_launch_history() {
    let root = std::env::temp_dir().join(format!(
        "ck-open-app-refusals-{}-{}",
        std::process::id(),
        crate::wall_clock_ms()
    ));
    let path = root.join("history.json");
    let (planes, desk, _) = rig_with_history(
        false,
        crate::open_app_history::LaunchHistory::at(path.clone()),
    );
    let (refused, _) = wire(
        &planes,
        "open_app",
        json!({"target":"Safari","url":"unregistered:page"}),
    )
    .await;
    assert_eq!(refused["outcome"], "url_scheme_refused", "{refused}");
    assert!(!path.exists());
    desk.state().opened.first_window_ms = Some(30_000);
    for _ in 0..3 {
        let (reply, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
        assert_eq!(reply["outcome"], "launched", "{reply}");
    }
    let recorded = std::fs::read(&path).unwrap();
    // More refusals than the retention limit must not displace real launches.
    for _ in 0..21 {
        let (reply, _) = wire(
            &planes,
            "open_app",
            json!({"target":"Safari","url":"unregistered:page"}),
        )
        .await;
        assert_eq!(reply["outcome"], "url_scheme_refused", "{reply}");
        assert!(reply.get("usual_ready_ms").is_none());
        assert!(reply.get("launch_note").is_none());
        assert_eq!(std::fs::read(&path).unwrap(), recorded);
    }
    let (denied_planes, denied_desk, _) = rig_with_history(
        false,
        crate::open_app_history::LaunchHistory::at(path.clone()),
    );
    let (denied, questions) = wire_with_decision(
        &denied_planes,
        "open_app",
        json!({"target":"Safari"}),
        "deny",
    )
    .await;
    assert_eq!(denied["outcome"], "consent_denied", "{denied}");
    assert_eq!(questions, 1);
    assert!(denied_desk.state().opens.is_empty());
    assert!(denied.get("usual_ready_ms").is_none());
    assert!(denied.get("launch_note").is_none());
    assert_eq!(std::fs::read(&path).unwrap(), recorded);
    desk.state().signature.as_mut().unwrap().ad_hoc = true;
    let (unsigned, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(unsigned["outcome"], "consent_unavailable", "{unsigned}");
    assert!(unsigned.get("usual_ready_ms").is_none());
    assert!(unsigned.get("launch_note").is_none());
    assert_eq!(std::fs::read(&path).unwrap(), recorded);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn open_app_url_readmission_failure_is_not_a_launch_history_sample() {
    let root = std::env::temp_dir().join(format!(
        "ck-open-app-readmission-{}-{}",
        std::process::id(),
        crate::wall_clock_ms()
    ));
    let path = root.join("history.json");
    let (planes, desk, _) = rig_with_history(
        false,
        crate::open_app_history::LaunchHistory::at(path.clone()),
    );
    let (ready, _) = wire(&planes, "open_app", json!({"target":"Safari"})).await;
    assert_eq!(ready["outcome"], "launched", "{ready}");
    let recorded = std::fs::read(&path).unwrap();
    {
        let mut state = desk.state();
        state.url_schemes = vec!["synthetic-editor".into()];
        // The bundle drops its registered scheme between admission and dispatch.
        state.url_schemes_after_read = Some(Vec::new());
    }
    let (refused, _) = wire(
        &planes,
        "open_app",
        json!({"target":"Safari","url":"synthetic-editor:page"}),
    )
    .await;
    assert_eq!(refused["outcome"], "launch_failed", "{refused}");
    assert_eq!(desk.state().opens.len(), 1);
    assert!(desk.state().opened_urls.is_empty());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        recorded,
        "URL readmission failed before any launch attempt; history must remain untouched"
    );
    assert!(refused.get("usual_ready_ms").is_none());
    assert!(refused.get("launch_note").is_none());
    std::fs::remove_dir_all(root).unwrap();
}
