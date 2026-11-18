//! Development builds of the Alfonso desktop app, served through the plane.
//!
//! Only the agents in `DEV_BUILD_DRIVERS` may drive a development build, and
//! they do so with no card: the call is admitted as if an "always" app grant
//! were held, and nothing is stored. Every other agent, and every other kind
//! of caller acting for a driver, is refused it. The released app and iPhone
//! Mirroring stay refused for the drivers too, as does any application that
//! might be the released app because part of its identity cannot be read or
//! its signature belongs to the release team.
//!
//! The `serve_as` helper calls with a carrier that has no answers queued and
//! checks that no question was sent: an admitted call that asked one would
//! wait for an answer that never comes.

use super::operator_apps::{drives_development_builds, DEV_BUILD_DRIVERS, RELEASE_TEAM_ID};
use super::*;
use crate::agent_grants::GrantHolder;
use crate::computer_grants::{
    AlwaysOpenRoute, AppCode, AppIdentity, AppIdentityUnreadable, ConsentContext, GrantCaller,
    QuestionCarrier,
};
use crate::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::app_state::source::{ReadBounds, RunningApp};
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{ProcessGrant, TargetResolution, UnreadableReason};
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use std::collections::HashMap;

#[allow(dead_code)]
mod support {
    use crate as cerebellum;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/it/support/computer.rs"
    ));
}

use support::{InjectedCode, ScriptedCarrier};

type Plane = ComputerPlane<
    InMemoryCaptureBackend,
    support::TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
>;

/// CKDESK, the agent that develops the Alfonso desktop app.
const CKDESK: &str = "agent_16013c86";
/// Any other agent.
const OTHER_AGENT: &str = "agent_0badc0de";

/// One fixture process: what it claims, what it runs, and how it is signed.
struct App {
    bundle_identity: &'static str,
    pid: u32,
    name: &'static str,
    /// `None` when the executable cannot be read.
    executable: Option<&'static str>,
    signature: Result<AppIdentity, AppIdentityUnreadable>,
}

/// The development-build fixture; its process is signed ad hoc.
const DEV: &str = "dev.cortexkit.alfonso";
const DEV_PID: u32 = 7101;
/// The released app's identifier, running the development executable with
/// an ad-hoc signature: the identifier alone refuses it.
const RELEASED_BY_ID: &str = "io.cortexkit.alfonso.desktop";
/// An ordinary identifier running the development executable, signed by the
/// release team: the signature alone refuses it.
const RELEASED_BY_SIGNATURE: &str = "com.example.Signed";
/// An ordinary identifier, signed ad hoc, running the released executable:
/// the executable alone refuses it.
const RELEASED_BY_EXECUTABLE: &str = "com.example.Renamed";
/// A development identifier carrying the release team's signature.
const DEV_RELEASE_SIGNED: &str = "dev.cortexkit.alfonso.preview";
/// A development identifier whose process carries no signature at all.
const DEV_UNSIGNED: &str = "dev.cortexkit.alfonso.unsigned";
/// iPhone Mirroring.
const MIRRORING: &str = "com.apple.ScreenContinuity";
/// An application whose executable cannot be read, running under a name
/// that says Alfonso.
const UNIDENTIFIED: &str = "com.example.Mystery";
/// An application that cannot be resolved to a process at all, running
/// under a name that says Alfonso.
const UNRESOLVABLE: &str = "com.example.Unread";

fn ad_hoc() -> AppIdentity {
    AppIdentity {
        team_id: None,
        designated_requirement: "cdhash H\"0123456789abcdef0123456789abcdef01234567\"".into(),
        ad_hoc: true,
        apple_anchored: false,
    }
}

fn release_signed() -> AppIdentity {
    AppIdentity {
        team_id: Some(RELEASE_TEAM_ID.into()),
        designated_requirement: format!(
            "anchor apple generic and certificate leaf[subject.OU] = \"{RELEASE_TEAM_ID}\""
        ),
        ad_hoc: false,
        apple_anchored: false,
    }
}

fn apps() -> Vec<App> {
    let app = |bundle_identity, pid, name, executable, signature| App {
        bundle_identity,
        pid,
        name,
        executable,
        signature,
    };
    let fixture = support::grant();
    vec![
        app(
            support::TARGET_BUNDLE_ID,
            fixture.pid,
            "Safari",
            Some("Safari"),
            Ok(support::team_identity(support::FIXTURE_TEAM)),
        ),
        app(
            DEV,
            DEV_PID,
            "Alfonso",
            Some("alfonso-desktop"),
            Ok(ad_hoc()),
        ),
        app(
            RELEASED_BY_ID,
            7102,
            "Approvals",
            Some("alfonso-desktop"),
            Ok(ad_hoc()),
        ),
        app(
            RELEASED_BY_SIGNATURE,
            7103,
            "Signed Helper",
            Some("alfonso-desktop"),
            Ok(release_signed()),
        ),
        app(
            RELEASED_BY_EXECUTABLE,
            7104,
            "Renamed Helper",
            Some("Alfonso"),
            Ok(ad_hoc()),
        ),
        app(
            DEV_RELEASE_SIGNED,
            7105,
            "Preview",
            Some("alfonso-desktop"),
            Ok(release_signed()),
        ),
        app(
            DEV_UNSIGNED,
            7106,
            "Unsigned",
            Some("alfonso-desktop"),
            Err(AppIdentityUnreadable::Unsigned),
        ),
        app(
            MIRRORING,
            7107,
            "iPhone Mirroring",
            Some("iPhone Mirroring"),
            Ok(AppIdentity {
                team_id: None,
                designated_requirement: "anchor apple".into(),
                ad_hoc: false,
                apple_anchored: true,
            }),
        ),
        app(UNIDENTIFIED, 7108, "Alfonso Nightly", None, Ok(ad_hoc())),
    ]
}

fn process(app: &App) -> ProcessGrant {
    ProcessGrant {
        pid: app.pid,
        bundle_identity: app.bundle_identity.to_string(),
        process_generation_evidence: format!("generation-{}", app.pid),
    }
}

/// The desktop's processes, each signed as its fixture says. The process of
/// [`UNRESOLVABLE`] cannot be identified.
struct Desktop(Vec<App>);

impl Desktop {
    fn app(&self, pid: u32) -> Option<&App> {
        self.0.iter().find(|app| app.pid == pid)
    }
}

impl TargetResolver for Desktop {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        if bundle_identity == UNRESOLVABLE {
            return TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable);
        }
        self.0
            .iter()
            .find(|app| app.bundle_identity == bundle_identity)
            .map(process)
            .map_or(TargetResolution::NotRunning, TargetResolution::Resolved)
    }

    fn display_name(&self, grant: &ProcessGrant) -> Option<String> {
        self.app(grant.pid).map(|app| app.name.to_string())
    }

    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        self.app(pid).map(process)
    }

    fn app_code(&self, grant: &ProcessGrant) -> Arc<dyn AppCode> {
        let signature = self
            .app(grant.pid)
            .map_or(Err(AppIdentityUnreadable::Unsigned), |app| {
                app.signature.clone()
            });
        Arc::new(InjectedCode::new(signature))
    }
}

struct Rig {
    desk: support::Desk,
    plane: Plane,
    management: Arc<ManagementPlane>,
}

fn rig() -> Rig {
    let desk = support::focused_text_desk();
    {
        let mut state = desk.state();
        state.running = Some(
            apps()
                .iter()
                .map(|app| RunningApp {
                    name: app.name.into(),
                    bundle_identity: app.bundle_identity.into(),
                    pid: app.pid,
                    frontmost: false,
                })
                .chain([RunningApp {
                    name: "Alfonso Beta".into(),
                    bundle_identity: UNRESOLVABLE.into(),
                    pid: 7109,
                    frontmost: false,
                }])
                .collect(),
        );
    }
    let executables: HashMap<u32, &'static str> = apps()
        .iter()
        .filter_map(|app| Some((app.pid, app.executable?)))
        .collect();
    let plane = ComputerPlane::with_result_schema_enforcement(
        support::audit(),
        ResultSchemaEnforcement::Withhold,
    )
    .with_permission_liveness(support::live_permissions())
    .with_app_state_source(desk.source())
    .with_process_executable_reader(move |process| {
        executables.get(&process.pid).map(|name| name.to_string())
    });
    Rig {
        desk,
        plane,
        management: Arc::new(ManagementPlane::new(Arc::new(Desktop(apps())))),
    }
}

#[test]
fn development_snapshot_reports_a_clean_ad_hoc_signature_and_release_mismatch() {
    let desktop = Desktop(apps());
    let grant = desktop.process_for_pid(DEV_PID).unwrap();
    let management = ManagementPlane::new(Arc::new(desktop));
    let snapshot = super::operator_apps::development_build_snapshot(&management, &grant);
    assert_eq!(snapshot["pid"], DEV_PID);
    assert_eq!(snapshot["bundle_identity"], DEV);
    assert_eq!(snapshot["app_need_is_app"], true);
    assert_eq!(snapshot["identity"]["ok"]["team_id"], Value::Null);
    assert_eq!(snapshot["identity"]["ok"]["ad_hoc"], true);
    assert_eq!(
        snapshot["identity"]["ok"]["designated_requirement"],
        "cdhash H\"0123456789abcdef0123456789abcdef01234567\""
    );
    assert_eq!(
        snapshot["satisfies_release_requirement"],
        json!({"ok": false})
    );
    assert_eq!(
        snapshot["release_requirement"],
        "anchor apple generic and certificate leaf[subject.OU] = \"5R5846NBPW\""
    );
}

#[test]
fn development_snapshot_preserves_both_signature_errors_even_when_identity_fails() {
    let mut fixtures = apps();
    let app = fixtures.iter_mut().find(|app| app.pid == DEV_PID).unwrap();
    let detail = "signature reader: OSStatus -67050\npath: /Volumes/Test Disk/Alfonso.app";
    app.signature = Err(AppIdentityUnreadable::Failed {
        detail: detail.into(),
    });
    let grant = process(app);
    let management = ManagementPlane::new(Arc::new(Desktop(fixtures)));
    let snapshot = super::operator_apps::development_build_snapshot(&management, &grant);
    for field in ["identity", "satisfies_release_requirement"] {
        assert_eq!(snapshot[field]["detail"], detail);
        assert_eq!(
            snapshot[field]["error"],
            "Failed { detail: \"signature reader: OSStatus -67050\\npath: /Volumes/Test Disk/Alfonso.app\" }"
        );
    }
}

#[tokio::test]
async fn ckdesk_operator_refusal_reports_the_first_failed_development_check() {
    let rig = rig();
    for (target, condition, remedy_contains) in [
        (DEV_RELEASE_SIGNED, "release_signed", None),
        (
            DEV_UNSIGNED,
            "signature_unreadable",
            Some("couldn't verify this app's signature"),
        ),
        (RELEASED_BY_ID, "not_a_development_build", None),
        (
            UNIDENTIFIED,
            "title_fallback",
            Some("its name suggests it may be the released app"),
        ),
        (
            "Alfonso Beta",
            "process_unresolved",
            Some("couldn't identify this app's running process"),
        ),
    ] {
        let reply = rig
            .serve_as(
                &head(CKDESK),
                "computer.read_state",
                json!({"target":target}),
            )
            .await;
        assert_refused(&reply, target);
        if let Some(text) = remedy_contains {
            assert!(reply["remedy"].as_str().unwrap().contains(text), "{reply}");
        } else {
            assert_eq!(reply["remedy"], operator_apps::refusal()["remedy"]);
        }
        let check = &reply["detail"]["development_build_check"];
        assert_eq!(check["condition"], condition, "{target}: {reply}");
        match condition {
            "signature_unreadable" => assert_eq!(check["error_kind"], "Unsigned"),
            "not_a_development_build" => assert_eq!(check["classes"]["bundle_identity"], "always"),
            "title_fallback" => {
                assert_eq!(check["bundle_identity_present"], true);
                assert_eq!(check["executable_present"], false);
            }
            "process_unresolved" => {
                assert!(check["error"].is_string());
                assert_eq!(check["processes"], json!([{"pid":7109}]));
            }
            _ => {}
        }
    }
    assert!(rig.plane.result_schema_findings().is_empty());
}

#[tokio::test]
async fn unreadable_program_location_refuses_with_path_error_and_recovery() {
    const PATH: &str = "/Volumes/Test/AlfonsoReview.app/Contents/MacOS/alfonso-desktop";
    let mut rig = rig();
    rig.plane.process_executable = Arc::new(|_| {
        Err(operator_apps::ProgramLocationUnreadable {
            path: Some(PATH.into()),
            error: Some(std::io::ErrorKind::PermissionDenied),
            failed_read: None,
        })
    });
    let reply = rig
        .serve_as(&head(CKDESK), "computer.read_state", json!({"target": DEV}))
        .await;
    assert_refused(&reply, DEV);
    assert_eq!(
        reply["remedy"],
        format!("Cerebellum couldn't read the running app's program location at {PATH} to confirm it's a development build, so it treats the app as the released one. Run the development build from a location Cerebellum can read (an internal disk), then retry. Cerebellum checked the named app ({DEV}).")
    );
    assert_eq!(
        reply["detail"]["development_build_check"],
        json!({"condition":"executable_unreadable", "path":PATH, "error":"permission denied"})
    );
    assert!(rig.plane.result_schema_findings().is_empty());
}

#[tokio::test]
async fn every_action_rechecks_the_same_development_build_evidence() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut rig = rig();
    let readable = Arc::new(AtomicBool::new(true));
    let app_readable = Arc::clone(&readable);
    let original = Arc::clone(&rig.plane.process_executable);
    rig.plane.process_executable = Arc::new(move |process| {
        if process.pid == DEV_PID && !app_readable.load(Ordering::Relaxed) {
            return Err(operator_apps::ProgramLocationUnreadable {
                error: Some(std::io::ErrorKind::PermissionDenied),
                ..Default::default()
            });
        }
        original(process)
    });
    let ckdesk = head(CKDESK);
    let read = rig
        .serve_as(&ckdesk, "computer.read_state", json!({"target": DEV}))
        .await;
    assert_eq!(read["outcome"], "completed", "{read}");
    let element = rig.element_of(DEV);

    readable.store(false, Ordering::Relaxed);
    for (action, arguments, source) in [
        (
            "computer.read_state",
            json!({"target": DEV}),
            "the named app",
        ),
        (
            "computer.press_element",
            json!({"element_id": element}),
            "the element's app",
        ),
        (
            "computer.takeover_scroll",
            json!({"target": DEV,"axis":"vertical","amount_lines":15}),
            "the named app",
        ),
    ] {
        let reply = rig.serve_as(&ckdesk, action, arguments).await;
        assert_refused(&reply, action);
        assert_eq!(
            reply["detail"]["development_build_check"],
            json!({"condition":"executable_unreadable", "error":"permission denied"}),
            "{action}: {reply}"
        );
        assert!(
            reply["remedy"]
                .as_str()
                .unwrap()
                .ends_with(&format!("Cerebellum checked {source} ({DEV}).")),
            "{reply}"
        );
    }
    assert!(rig.plane.result_schema_findings().is_empty());
}

#[tokio::test]
async fn scroll_refusal_distinguishes_the_frontmost_app_and_the_app_under_the_pointer() {
    let mut rig = rig();
    let original = Arc::clone(&rig.plane.process_executable);
    rig.plane.process_executable = Arc::new(move |process| {
        if process.pid == DEV_PID {
            return Err(operator_apps::ProgramLocationUnreadable {
                failed_read: Some(
                    "confirm the program location still belonged to the same running process",
                ),
                ..Default::default()
            });
        }
        original(process)
    });
    for (hit, source) in [
        (None, "the frontmost app"),
        (Some((2, Some(DEV_PID))), "the app under the pointer"),
    ] {
        {
            let mut desk = rig.desk.state();
            desk.frontmost = Some(DEV_PID);
            desk.real_cursor = Some((10.0, 10.0));
            desk.system_wide_hit = hit;
        }
        let reply = rig
            .serve_as(
                &head(CKDESK),
                "computer.takeover_scroll",
                json!({"target":support::TARGET_BUNDLE_ID,"axis":"vertical","amount_lines":15}),
            )
            .await;
        assert_refused(&reply, source);
        assert_eq!(
            reply["detail"]["development_build_check"],
            json!({"condition":"executable_unreadable"})
        );
        let remedy = reply["remedy"].as_str().unwrap();
        assert!(
            remedy.contains(
                "confirm the program location still belonged to the same running process"
            ),
            "{reply}"
        );
        assert!(
            remedy.ends_with(&format!("Cerebellum checked {source} ({DEV}).")),
            "{reply}"
        );
    }
}

#[tokio::test]
async fn ckdesk_operator_refusal_retains_a_short_signature_reader_error() {
    let mut rig = rig();
    let mut fixtures = apps();
    fixtures
        .iter_mut()
        .find(|app| app.pid == DEV_PID)
        .unwrap()
        .signature = Err(AppIdentityUnreadable::Failed {
        detail: "SigningInformation(-67050)".into(),
    });
    rig.management = Arc::new(ManagementPlane::new(Arc::new(Desktop(fixtures))));
    let reply = rig
        .serve_as(&head(CKDESK), "computer.read_state", json!({"target": DEV}))
        .await;
    assert_refused(&reply, DEV);
    assert_eq!(
        reply["detail"]["development_build_check"],
        json!({
            "condition":"signature_unreadable", "error_kind":"Failed", "error":"SigningInformation(-67050)",
        })
    );
}

#[tokio::test]
async fn other_callers_operator_refusals_remain_byte_identical() {
    let rig = rig();
    let mut unattested = head(CKDESK);
    unattested.durable_identity_attested = false;
    let mut worker = head(CKDESK);
    worker.holder = Some(GrantHolder::Worker {
        agent_id: CKDESK.into(),
        scope_ref: "worker-scope".into(),
    });
    let expected = serde_json::to_vec(&json!({
        "outcome":"authorization_denied",
        "reason":"operator_app_blocked",
        "remedy":"The agent may not use this app, because it confirms the person's own actions; nothing was read or done in it, and nobody was asked. No agent may use it, so ask the person to act in the app themselves.",
        "screen_lock_state":"unknown",
    })).unwrap();
    for caller in [head(OTHER_AGENT), unattested, worker] {
        for target in [
            DEV,
            DEV_UNSIGNED,
            RELEASED_BY_ID,
            UNIDENTIFIED,
            "Alfonso Beta",
        ] {
            let reply = rig
                .serve_as(&caller, "computer.read_state", json!({"target":target}))
                .await;
            assert_eq!(
                serde_json::to_vec(&reply).unwrap(),
                expected,
                "{target}: {reply}"
            );
        }
    }
}

#[tokio::test]
async fn a_release_requirement_read_error_stays_closed_and_names_the_error() {
    struct Code;
    impl AppCode for Code {
        fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
            Ok(ad_hoc())
        }
        fn satisfies(&self, _: &str) -> Result<bool, AppIdentityUnreadable> {
            Err(AppIdentityUnreadable::Failed {
                detail: "TimedOut".into(),
            })
        }
    }
    struct Resolver(Desktop);
    impl TargetResolver for Resolver {
        fn resolve(&self, bundle_identity: &str) -> TargetResolution {
            self.0.resolve(bundle_identity)
        }
        fn app_code(&self, _: &ProcessGrant) -> Arc<dyn AppCode> {
            Arc::new(Code)
        }
    }
    let mut rig = rig();
    rig.management = Arc::new(ManagementPlane::new(Arc::new(Resolver(Desktop(apps())))));
    let reply = rig
        .serve_as(&head(CKDESK), "computer.read_state", json!({"target": DEV}))
        .await;
    assert_refused(&reply, DEV);
    assert_eq!(
        reply["detail"]["development_build_check"],
        json!({
            "condition":"signature_unreadable","error_kind":"Failed","error":"TimedOut",
        })
    );
}

/// A head the daemon attested, as the route's accepted bind names it.
fn head(agent: &str) -> GrantCaller {
    GrantCaller::new(
        support::identity().conversation_key,
        agent.to_string(),
        true,
    )
}

/// A consent context that asks through `carrier`.
fn asking(caller: GrantCaller, carrier: &ScriptedCarrier) -> ConsentContext {
    let (sender, drain) = tokio::sync::watch::channel(false);
    // Kept alive: a dropped sender would read as a drain.
    std::mem::forget(sender);
    ConsentContext::new(
        caller,
        Some(Arc::new(carrier.clone()) as Arc<dyn QuestionCarrier>),
        Arc::new(AlwaysOpenRoute),
        drain,
        None,
    )
}

impl Rig {
    async fn serve(&self, name: &str, arguments: Value, consent: ConsentContext) -> Value {
        let clock = cerebellum_core::clock::FakeClock::new();
        self.plane
            .serve(
                servable(name).expect("the row is served"),
                &arguments,
                ServeContext {
                    cancel: crate::CancelHandle::pending(),
                    grantee: support::GRANTEE,
                    identity: support::identity(),
                    management: &self.management,
                    consent,
                    clock: &clock,
                    now_ms: 10,
                },
                |_| InMemoryCaptureBackend::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"))
    }

    /// Serve as `caller` with nobody to answer, and check nobody was asked.
    async fn serve_as(&self, caller: &GrantCaller, name: &str, arguments: Value) -> Value {
        let carrier = ScriptedCarrier::answering(&[]);
        let reply = self
            .serve(name, arguments, asking(caller.clone(), &carrier))
            .await;
        assert!(
            carrier.questions().is_empty(),
            "{name}: the person was asked: {reply}"
        );
        reply
    }

    /// An element id read from the process of `bundle_identity`.
    fn element_of(&self, bundle_identity: &str) -> String {
        let app = apps()
            .into_iter()
            .find(|app| app.bundle_identity == bundle_identity)
            .expect("a fixture app");
        let process = process(&app);
        let raw = self
            .desk
            .read_app_state(&process, ReadBounds::default())
            .expect("the desk reads");
        let read = self.management.app_state_sessions().observe(
            &support::identity().conversation_key,
            &process,
            &raw,
        );
        read.roots[0].children[0]
            .element_id
            .clone()
            .expect("the text field is numbered")
    }

    fn listed(&self, reply: &Value) -> Vec<String> {
        assert_eq!(reply["outcome"], "completed", "{reply}");
        reply["apps"]
            .as_array()
            .expect("apps")
            .iter()
            .map(|app| app["bundle_identity"].as_str().unwrap().to_string())
            .collect()
    }
}

fn assert_refused(reply: &Value, what: &str) {
    assert_eq!(reply["outcome"], "authorization_denied", "{what}: {reply}");
    assert_eq!(reply["reason"], "operator_app_blocked", "{what}: {reply}");
}

/// Refused on `target` by name and, for a fixture app, on an element read
/// from it.
async fn assert_target_refused(rig: &Rig, caller: &GrantCaller, target: &str) {
    let reply = rig
        .serve_as(caller, "computer.read_state", json!({"target": target}))
        .await;
    assert_refused(&reply, target);
    let reply = rig
        .serve_as(
            caller,
            "computer.keys",
            json!({"target": target, "keys": ["s"]}),
        )
        .await;
    assert_refused(&reply, target);
    if apps().iter().any(|app| app.bundle_identity == target) {
        let element = rig.element_of(target);
        let reply = rig
            .serve_as(
                caller,
                "computer.write_text",
                json!({"element_id": element, "text": "hi", "write_mode": "replace_value"}),
            )
            .await;
        assert_refused(&reply, target);
    }
    assert!(rig.desk.state().writes.is_empty(), "{target}: wrote");
}

#[test]
fn ckdesk_is_the_one_development_build_driver() {
    assert_eq!(DEV_BUILD_DRIVERS, [CKDESK]);
    for driver in DEV_BUILD_DRIVERS {
        let lower = driver.to_ascii_lowercase();
        assert!(
            !driver.trim().is_empty() && !lower.contains("placeholder") && !lower.contains("todo"),
            "{driver} is not a real agent id"
        );
    }
}

#[tokio::test]
async fn ckdesk_drives_a_development_build_with_no_card_and_no_stored_grant() {
    let rig = rig();
    let ckdesk = head(CKDESK);
    let reply = rig
        .serve_as(&ckdesk, "computer.read_state", json!({"target": DEV}))
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    // The fixture's text field belongs to the development build's process,
    // and its value can be written.
    {
        let mut desk = rig.desk.state();
        let field = desk.elements.get_mut(&2).expect("the text field");
        field.facts.pid = Some(DEV_PID);
        field.facts.value_settable = true;
    }
    let element = rig.element_of(DEV);
    let reply = rig
        .serve_as(
            &ckdesk,
            "computer.write_text",
            json!({"element_id": element, "text": "hi", "write_mode": "replace_value"}),
        )
        .await;
    assert_ne!(reply["outcome"], "authorization_denied", "{reply}");
    assert_eq!(rig.desk.state().writes.len(), 1, "{reply}");
    // Admitted without a grant: none was recorded for the conversation.
    let need = rig.management.app_need(
        DEV,
        &process(&apps().into_iter().find(|app| app.pid == DEV_PID).unwrap()),
        String::new(),
    );
    assert!(!rig.management.computer_grants().holds(&ckdesk, &need));
}

#[tokio::test]
async fn any_other_agent_is_refused_a_development_build() {
    let rig = rig();
    assert_target_refused(&rig, &head(OTHER_AGENT), DEV).await;
}

#[tokio::test]
async fn a_worker_acting_for_ckdesk_is_refused_a_development_build() {
    let rig = rig();
    let worker = GrantCaller {
        holder: Some(GrantHolder::Worker {
            agent_id: CKDESK.into(),
            scope_ref: "worker-scope".into(),
        }),
        conversation_key: support::identity().conversation_key,
        agent_project_id: CKDESK.into(),
        durable_identity_attested: false,
    };
    assert_target_refused(&rig, &worker, DEV).await;
}

/// The caller a route's bind leads to, through the same derivation a live
/// computer call takes.
fn caller_from_scope(attributes: subc_protocol::scope::ScopeAttributes) -> ConsentContext {
    let core = crate::session_caller_principal_for_test().expect("the session caller");
    let stamp = subc_protocol::scope::ScopeStamp::new(
        core.clone(),
        "scope-1",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(attributes)
    .with_owner_authorized(true);
    let facts = cerebellum_core::identity::AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", "test-session".to_string()),
        Some(core),
        Some(&json!({
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
        })),
        Some(&["elicitation".to_string()]),
        &subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".to_string(),
        },
    )
    .with_scope(Some(stamp));
    let planes = crate::Planes::with_browser_config_journaling(
        Arc::new(crate::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    let (writer, _frames) = tokio::sync::mpsc::channel(1);
    crate::consent_context(&planes, &facts, &writer, 7, 1)
}

#[tokio::test]
async fn a_scope_naming_ckdesk_only_on_behalf_of_it_is_refused() {
    // The control: a scope whose agent is CKDESK, delegating, is CKDESK's head.
    let delegated = caller_from_scope(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some(CKDESK.into()))
            .with_delegates(true),
    );
    assert!(
        drives_development_builds(&delegated.caller),
        "{:?}",
        delegated.caller
    );
    let rig = rig();
    let reply = rig
        .serve_as(
            &delegated.caller,
            "computer.read_state",
            json!({"target": DEV}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");

    // A scope that names CKDESK only as the agent it works on behalf of has
    // no agent of its own, and gets none of CKDESK's authority.
    let attributed = caller_from_scope(
        subc_protocol::scope::ScopeAttributes::new().with_on_behalf_of_agent(Some(CKDESK.into())),
    );
    assert!(
        !drives_development_builds(&attributed.caller),
        "{:?}",
        attributed.caller
    );
    let reply = rig
        .serve("computer.read_state", json!({"target": DEV}), attributed)
        .await;
    assert_refused(&reply, "on_behalf_of_agent");
}

#[tokio::test]
async fn ckdesk_is_refused_the_released_app_by_id_by_signature_and_by_executable() {
    let rig = rig();
    let ckdesk = head(CKDESK);
    for target in [
        RELEASED_BY_ID,
        RELEASED_BY_SIGNATURE,
        RELEASED_BY_EXECUTABLE,
        // Named while not running, under a child of the released identifier.
        "io.cortexkit.alfonso.desktop.helper",
    ] {
        assert_target_refused(&rig, &ckdesk, target).await;
    }
}

#[tokio::test]
async fn ckdesk_is_refused_iphone_mirroring() {
    let rig = rig();
    assert_target_refused(&rig, &head(CKDESK), MIRRORING).await;
    assert_target_refused(&rig, &head(CKDESK), "iPhone Mirroring").await;
}

#[tokio::test]
async fn ckdesk_is_refused_a_development_id_signed_by_the_release_team_or_unsigned() {
    let rig = rig();
    assert_target_refused(&rig, &head(CKDESK), DEV_RELEASE_SIGNED).await;
    assert_target_refused(&rig, &head(CKDESK), DEV_UNSIGNED).await;
}

#[tokio::test]
async fn ckdesk_is_refused_an_unidentified_app_titled_alfonso() {
    let rig = rig();
    // Its executable cannot be read, so it might be the released app.
    assert_target_refused(&rig, &head(CKDESK), UNIDENTIFIED).await;
    // Its process cannot be identified at all.
    let reply = rig
        .serve_as(
            &head(CKDESK),
            "computer.read_state",
            json!({"target": "Alfonso Beta"}),
        )
        .await;
    assert_refused(&reply, "Alfonso Beta");
}

#[tokio::test]
async fn list_apps_shows_development_builds_to_ckdesk_alone() {
    let rig = rig();
    // The application whose process cannot be identified is left out for
    // every caller, since its name says Alfonso.
    let ordinary = [support::TARGET_BUNDLE_ID];
    for (caller, expected) in [
        (head(CKDESK), vec![DEV]),
        (head(OTHER_AGENT), vec![]),
        (
            GrantCaller {
                holder: None,
                conversation_key: support::identity().conversation_key,
                agent_project_id: String::new(),
                durable_identity_attested: false,
            },
            vec![],
        ),
    ] {
        let reply = rig.serve_as(&caller, "computer.list_apps", json!({})).await;
        let mut listed = rig.listed(&reply);
        listed.sort();
        let mut expected: Vec<String> = expected
            .into_iter()
            .chain(ordinary)
            .map(str::to_string)
            .collect();
        expected.sort();
        assert_eq!(listed, expected, "{caller:?}: {reply}");
    }
}
