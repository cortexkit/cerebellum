//! The applications no agent may use, refused by every action.
//!
//! A request from the Alfonso desktop app, or from the phone paired with it,
//! counts as the person's own action only while no agent can drive those
//! apps. These tests drive `ComputerPlane::serve` in withholding mode, so every
//! refusal shown here also passed its row's result schema, and they use a
//! resolver whose signature reader panics for any application but the
//! ordinary fixture one: an operator app that reached the grant path would
//! fail the test there rather than be refused by it.

use super::support;

use std::collections::HashMap;
use std::sync::Arc;

use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::computer_grants::{AppCode, ConsentContext};
use cerebellum::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::app_state::image::ImageMapping;
use cerebellum_computer::app_state::session::RegisteredImage;
use cerebellum_computer::app_state::source::{
    AppStateSource, InstalledApp, ReadBounds, RunningApp,
};
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{
    ProcessGrant, TargetResolution, UnreadableReason, UnsupportedPlatformDriver,
};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use serde_json::{json, Value};
use support::computer::{
    audit, focused_text_desk, grant, identity, live_permissions, relayed, Desk, InjectedCode,
    ScriptedCarrier, TestRedactor, GRANTEE, TARGET_BUNDLE_ID,
};

/// The Alfonso desktop app, running under its development identifier.
const ALFONSO: &str = "dev.cortexkit.alfonso";
const ALFONSO_PID: u32 = 7001;
/// An application whose bundle identity is nothing special but whose
/// executable is the Alfonso desktop app's.
const DISGUISED: &str = "com.example.Disguised";
const DISGUISED_PID: u32 = 7002;
/// iPhone Mirroring, through which an agent could press the phone app.
const MIRRORING: &str = "com.apple.ScreenContinuity";
const MIRRORING_PID: u32 = 7003;
/// Two applications whose process cannot be identified.
const UNREADABLE_ALFONSO: &str = "com.example.Mystery";
const UNREADABLE_ALFONSO_PID: u32 = 7004;
const UNREADABLE_OTHER: &str = "com.example.Unread";
const UNREADABLE_OTHER_PID: u32 = 7005;

fn process(bundle_identity: &str, pid: u32) -> ProcessGrant {
    ProcessGrant {
        pid,
        bundle_identity: bundle_identity.to_string(),
        process_generation_evidence: format!("generation-{pid}"),
    }
}

fn running(name: &str, bundle_identity: &str, pid: u32) -> RunningApp {
    RunningApp {
        name: name.into(),
        bundle_identity: bundle_identity.into(),
        pid,
        frontmost: false,
    }
}

fn installed(name: &str, bundle_identity: &str) -> InstalledApp {
    InstalledApp {
        name: name.into(),
        bundle_identity: bundle_identity.into(),
        path: std::path::PathBuf::from(format!("/Applications/{name}.app")),
        version: None,
        build_version: None,
    }
}

/// The desktop's processes. Only the ordinary fixture application has a
/// signature to read: asking for any other application's code means the
/// call reached the grant path, and the test fails there.
struct Desktop {
    processes: Vec<ProcessGrant>,
    unreadable: Vec<&'static str>,
    /// The applications whose signature can be read.
    signed: Vec<&'static str>,
}

impl Desktop {
    fn new() -> Self {
        Self {
            processes: vec![
                grant(),
                process(ALFONSO, ALFONSO_PID),
                process(DISGUISED, DISGUISED_PID),
                process(MIRRORING, MIRRORING_PID),
            ],
            unreadable: vec![UNREADABLE_ALFONSO, UNREADABLE_OTHER],
            signed: vec![TARGET_BUNDLE_ID],
        }
    }
}

impl TargetResolver for Desktop {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        if self.unreadable.contains(&bundle_identity) {
            return TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable);
        }
        self.processes
            .iter()
            .find(|process| process.bundle_identity == bundle_identity)
            .cloned()
            .map_or(TargetResolution::NotRunning, TargetResolution::Resolved)
    }

    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        self.processes
            .iter()
            .find(|process| process.pid == pid)
            .cloned()
    }

    fn app_code(&self, process: &ProcessGrant) -> Arc<dyn AppCode> {
        assert!(
            self.signed.contains(&process.bundle_identity.as_str()),
            "the grant path was consulted for {}",
            process.bundle_identity
        );
        Arc::new(InjectedCode::default())
    }
}

type Plane = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
    UnsupportedPlatformDriver,
>;

struct Rig {
    desk: Desk,
    plane: Plane,
    management: Arc<ManagementPlane>,
}

/// The executable each fixture process runs; the unreadable processes have
/// none that can be read.
fn executables() -> HashMap<u32, &'static str> {
    HashMap::from([
        (grant().pid, "Safari"),
        (ALFONSO_PID, "alfonso-desktop"),
        (DISGUISED_PID, "alfonso-desktop"),
        (MIRRORING_PID, "iPhone Mirroring"),
    ])
}

fn fixture() -> Rig {
    let desk = focused_text_desk();
    {
        let mut state = desk.state();
        let mut apps = state.running.take().unwrap_or_default();
        apps.extend([
            running("Alfonso", ALFONSO, ALFONSO_PID),
            running("Helper", DISGUISED, DISGUISED_PID),
            running("iPhone Mirroring", MIRRORING, MIRRORING_PID),
            running(
                "Alfonso Preview",
                UNREADABLE_ALFONSO,
                UNREADABLE_ALFONSO_PID,
            ),
            running("Notes", UNREADABLE_OTHER, UNREADABLE_OTHER_PID),
        ]);
        state.running = Some(apps);
        state.installed.apps = vec![
            installed("TextEdit", "com.apple.TextEdit"),
            installed("Alfonso", ALFONSO),
            installed("Approvals", "io.cortexkit.alfonso.desktop"),
        ];
    }
    let executables = executables();
    let plane =
        ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold)
            .with_permission_liveness(live_permissions())
            .with_app_state_source(desk.source())
            .with_process_executable_reader(move |process| {
                executables.get(&process.pid).map(|name| name.to_string())
            });
    Rig {
        desk,
        plane,
        management: Arc::new(ManagementPlane::new(Arc::new(Desktop::new()))),
    }
}

async fn serve(rig: &Rig, name: &str, arguments: &Value, consent: ConsentContext) -> Value {
    let clock = FakeClock::new();
    rig.plane
        .serve(
            servable(name).expect("the row is served"),
            arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::pending(),
                grantee: GRANTEE,
                identity: identity(),
                management: &rig.management,
                consent,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"))
}

/// Serve `name` and check it was refused as an operator app before anyone
/// was asked or anything was pressed, written or posted.
async fn assert_refused(rig: &Rig, name: &str, arguments: Value) {
    let carrier = ScriptedCarrier::answering(&["allow_30m"; 4]);
    let reply = serve(rig, name, &arguments, relayed(&carrier)).await;
    assert_eq!(reply["outcome"], "authorization_denied", "{name}: {reply}");
    assert_eq!(reply["reason"], "operator_app_blocked", "{name}: {reply}");
    let remedy = reply["remedy"].as_str().unwrap_or_default();
    assert!(
        remedy.contains("confirms the person's own actions")
            && remedy.contains("ask the person to act in the app themselves"),
        "{name}: {reply}"
    );
    if matches!(name, "computer.type" | "computer.keys") {
        assert_eq!(reply["effect_status"], "not_dispatched", "{name}: {reply}");
    }
    assert!(
        carrier.questions().is_empty(),
        "{name}: an operator-app call asked the person"
    );
    let desk = rig.desk.state();
    assert!(desk.presses.is_empty(), "{name}: pressed");
    assert!(desk.writes.is_empty(), "{name}: wrote");
    assert!(desk.opens.is_empty(), "{name}: launched");
}

fn image(rig: &Rig, process: &ProcessGrant) -> String {
    rig.management.app_state_sessions().register_window_image(
        &identity().conversation_key,
        RegisteredImage {
            bundle_identity: process.bundle_identity.clone(),
            pid: process.pid,
            process_generation: process.process_generation_evidence.clone(),
            width_px: 100,
            height_px: 100,
            mapping: ImageMapping::for_window((0.0, 0.0), (100.0, 100.0), (100, 100), (100, 100))
                .unwrap(),
        },
        1,
    )
}

/// An element id from a read of `process`, recorded straight into the
/// conversation's session.
fn element_of(rig: &Rig, process: &ProcessGrant) -> String {
    let raw = rig
        .desk
        .read_app_state(process, ReadBounds::default())
        .expect("the desk reads");
    let read =
        rig.management
            .app_state_sessions()
            .observe(&identity().conversation_key, process, &raw);
    read.roots[0].children[0]
        .element_id
        .clone()
        .expect("the text field is numbered")
}

#[tokio::test]
async fn a_target_named_by_app_identity_is_refused_by_every_named_row() {
    let rig = fixture();
    for target in [
        ALFONSO,
        "dev.cortexkit.alfonso.helper",
        "io.cortexkit.alfonso.desktop",
        MIRRORING,
    ] {
        for (name, arguments) in [
            ("computer.read_state", json!({"target": target})),
            ("computer.type", json!({"target": target, "text": "hi"})),
            ("computer.keys", json!({"target": target, "keys": ["s"]})),
            (
                "computer.wait",
                json!({"app": target, "predicate": {"kind": "element_present",
                    "element": {"Identifier": "ready"}}, "timeout_ms": 0}),
            ),
            (
                "computer.takeover_scroll",
                json!({"target": target, "axis": "vertical", "amount_lines": 1}),
            ),
            ("computer.open_app", json!({"target": target})),
        ] {
            assert_refused(&rig, name, arguments).await;
        }
    }
}

#[tokio::test]
async fn a_target_named_by_its_display_name_is_refused() {
    let rig = fixture();
    for target in ["Alfonso", "iPhone Mirroring", "iPhone"] {
        assert_refused(&rig, "computer.read_state", json!({"target": target})).await;
        assert_refused(
            &rig,
            "computer.keys",
            json!({"target": target, "keys": ["s"]}),
        )
        .await;
    }
}

/// The pid form: the bundle identity names nothing special, but the process
/// it resolves to runs the Alfonso desktop app's executable.
#[tokio::test]
async fn a_process_running_the_operator_executable_is_refused_whatever_its_identity() {
    let rig = fixture();
    assert_refused(&rig, "computer.read_state", json!({"target": DISGUISED})).await;
    assert_refused(&rig, "computer.read_state", json!({"target": "Helper"})).await;
    assert_refused(
        &rig,
        "computer.type",
        json!({"target": DISGUISED, "text": "hi"}),
    )
    .await;
}

#[tokio::test]
async fn an_element_or_image_read_from_an_operator_app_is_refused() {
    let rig = fixture();
    for blocked in [
        process(ALFONSO, ALFONSO_PID),
        process(DISGUISED, DISGUISED_PID),
    ] {
        let element = element_of(&rig, &blocked);
        assert_refused(
            &rig,
            "computer.press_element",
            json!({"element_id": element}),
        )
        .await;
        assert_refused(
            &rig,
            "computer.press_element",
            json!({"element_ids": [element]}),
        )
        .await;
        assert_refused(
            &rig,
            "computer.write_text",
            json!({"element_id": element, "text": "hi", "write_mode": "replace_value"}),
        )
        .await;
        let image = image(&rig, &blocked);
        assert_refused(
            &rig,
            "computer.press_point",
            json!({"image_id": image, "x": 1, "y": 1}),
        )
        .await;
    }
}

#[tokio::test]
async fn open_app_refuses_an_installed_operator_app_found_by_name() {
    let rig = fixture();
    // Neither name is itself an operator identity, and neither app runs; the
    // installed application each leads to is.
    assert_refused(&rig, "computer.open_app", json!({"target": "Approvals"})).await;
    assert_refused(&rig, "computer.open_app", json!({"target": ALFONSO})).await;
}

#[tokio::test]
async fn a_takeover_aimed_at_or_over_an_operator_app_is_refused_before_posting() {
    let point = json!({"x": 10, "y": 10});
    // The image shows an operator app.
    let rig = fixture();
    let blocked = image(&rig, &process(ALFONSO, ALFONSO_PID));
    assert_refused(
        &rig,
        "computer.takeover_move",
        json!({"image_id": blocked, "to": point}),
    )
    .await;
    assert_refused(
        &rig,
        "computer.takeover_drag",
        json!({"image_id": blocked, "from": point, "to": point}),
    )
    .await;

    // The image shows the ordinary application, but an operator app is
    // frontmost, where the real pointer goes.
    let rig = fixture();
    rig.desk.state().frontmost = Some(MIRRORING_PID);
    let ordinary = image(&rig, &grant());
    for (name, arguments) in [
        (
            "computer.takeover_move",
            json!({"image_id": ordinary, "to": point}),
        ),
        (
            "computer.takeover_drag",
            json!({"image_id": ordinary, "from": point, "to": point}),
        ),
        (
            "computer.takeover_scroll",
            json!({"target": TARGET_BUNDLE_ID, "axis": "vertical", "amount_lines": 1}),
        ),
    ] {
        assert_refused(&rig, name, arguments).await;
    }

    // The ordinary application is frontmost and imaged, but what is on top
    // at the point belongs to an operator app.
    let rig = fixture();
    {
        let mut desk = rig.desk.state();
        desk.topmost_window = Some(1);
        desk.system_wide_hit = Some((99, Some(ALFONSO_PID)));
    }
    let ordinary = image(&rig, &grant());
    assert_refused(
        &rig,
        "computer.takeover_move",
        json!({"image_id": ordinary, "to": point}),
    )
    .await;
    assert!(
        !rig.desk.state().hit_scopes.is_empty(),
        "the refusal came from the placement's hit test"
    );
}

#[tokio::test]
async fn an_unreadable_identity_is_refused_only_when_a_title_names_alfonso() {
    let rig = fixture();
    assert_refused(
        &rig,
        "computer.read_state",
        json!({"target": "Alfonso Preview"}),
    )
    .await;
    let carrier = ScriptedCarrier::answering(&[]);
    let reply = serve(
        &rig,
        "computer.read_state",
        &json!({"target": "Notes"}),
        relayed(&carrier),
    )
    .await;
    assert_eq!(reply["outcome"], "targets_unreadable", "{reply}");
    assert!(carrier.questions().is_empty());
}

/// A process whose executable cannot be read, with a focused window that
/// names Alfonso, is refused; the same process with an ordinary window is
/// not.
#[tokio::test]
async fn an_unreadable_executable_falls_back_to_the_window_title() {
    let quiet = "com.example.Quiet";
    let make = |title: &str| {
        let rig = fixture();
        rig.desk.state().window = Some((1, Some(title.to_string())));
        Rig {
            management: Arc::new(ManagementPlane::new(Arc::new(Desktop {
                processes: vec![grant(), process(quiet, 7006)],
                unreadable: Vec::new(),
                signed: vec![TARGET_BUNDLE_ID, quiet],
            }))),
            ..rig
        }
    };
    let rig = make("Alfonso");
    assert_refused(&rig, "computer.read_state", json!({"target": quiet})).await;
    let rig = make("Quiet notes");
    let carrier = ScriptedCarrier::answering(&["allow_30m"]);
    let reply = serve(
        &rig,
        "computer.read_state",
        &json!({"target": quiet}),
        relayed(&carrier),
    )
    .await;
    assert_ne!(reply["outcome"], "authorization_denied", "{reply}");
    assert_eq!(carrier.questions().len(), 1, "{reply}");
}

#[tokio::test]
async fn list_apps_leaves_operator_apps_out() {
    let rig = fixture();
    let reply = serve(
        &rig,
        "computer.list_apps",
        &json!({}),
        relayed(&ScriptedCarrier::answering(&[])),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    let listed: Vec<&str> = reply["apps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|app| app["bundle_identity"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        [UNREADABLE_OTHER, TARGET_BUNDLE_ID, "com.apple.TextEdit"],
        "{reply}"
    );
    let text = reply["state_text"].as_str().unwrap();
    assert!(
        !text.contains("lfonso") && !text.contains("Mirroring"),
        "{text}"
    );
}

#[tokio::test]
async fn an_ordinary_app_still_reaches_its_grant_question() {
    let rig = fixture();
    let carrier = ScriptedCarrier::answering(&["allow_30m"]);
    let reply = serve(
        &rig,
        "computer.read_state",
        &json!({"target": TARGET_BUNDLE_ID}),
        relayed(&carrier),
    )
    .await;
    assert_ne!(reply["outcome"], "authorization_denied", "{reply}");
    assert_eq!(carrier.questions().len(), 1, "{reply}");
}

#[tokio::test]
async fn each_refusal_is_recorded_in_the_refusal_ring() {
    let rig = fixture();
    assert_refused(&rig, "computer.read_state", json!({"target": ALFONSO})).await;
    assert_refused(&rig, "computer.read_state", json!({"target": "Helper"})).await;
    let history = rig
        .plane
        .refusal_history_for_test(GRANTEE)
        .await
        .expect("the refusals were recorded");
    assert_eq!(history.total_count, 2);
    let records: Vec<_> = history
        .records
        .iter()
        .map(|record| {
            (
                record.claimed_addressing.as_str(),
                record.reason.reason.as_str(),
            )
        })
        .collect();
    assert_eq!(
        records,
        [
            (ALFONSO, "operator_app_blocked"),
            ("Helper", "operator_app_blocked")
        ]
    );
}
