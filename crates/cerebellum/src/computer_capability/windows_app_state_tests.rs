//! Windows application-state rows are not yet advertised in release builds.
//! Exercise the shared wire handler with fixture review keys and integrity evidence.

use super::*;
use cerebellum_computer::platform::{
    validate_vocabulary_digests,
    windows::{app_state::WindowsAppStateSource, WindowsPlatformDriver},
    CapabilityAdvertisementContext, ImmutableReleaseInputs, PermissionLiveness,
    PermissionLivenessReport, PermissionProbeResult, PermissionService, ProcessGrant,
    StartupCapabilityProbe, TargetResolution, VocabularyDigestInputs, WindowsElevation,
    COMPUTER_ACTION_VOCABULARY_SHA256,
};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use subc_protocol::{Flags, Frame, FrameType, Priority};

mod actions;
mod launch;
mod picture;

fn app_state_block(context: &CapabilityAdvertisementContext) -> Option<&'static str> {
    if context
        .inputs
        .windows_app_identity_review_revision
        .is_none()
    {
        Some("windows app identity review unbound")
    } else if context.inputs.windows_app_state_review_revision.is_none() {
        Some("windows app state review unbound")
    } else if !vocabulary_ready(context) {
        Some("computer action vocabulary input unresolved")
    } else if context.inputs.release_signing_topology_revision.is_none() {
        Some("release signing topology unbound")
    } else {
        match context.startup.windows_elevation {
            WindowsElevation::Medium => None,
            WindowsElevation::ElevatedOrAboveMedium => Some("cerebellum is running elevated"),
            WindowsElevation::UnreadableOrBelowMedium => Some("integrity unreadable"),
        }
    }
}

fn vocabulary_ready(context: &CapabilityAdvertisementContext) -> bool {
    validate_vocabulary_digests(&context.inputs.vocabulary_digests).is_ok()
}

fn rows(context: &CapabilityAdvertisementContext) -> BTreeSet<String> {
    let mut rows: BTreeSet<_> = WindowsPlatformDriver::default()
        .declarations(context)
        .into_iter()
        .filter(|row| row.advertised)
        .map(|row| row.capability_id)
        .collect();
    if app_state_block(context).is_none() {
        rows.extend(["computer.read_state".into(), "computer.list_apps".into()]);
    }
    if launch::launch_block(context).is_none() {
        rows.insert("computer.open_app".into());
    }
    if actions::block(context).is_none() {
        rows.extend(actions::ROWS.map(str::to_owned));
    }
    rows
}

fn exact_inputs() -> CapabilityAdvertisementContext {
    let digest = || Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_owned());
    CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs {
            windows_actuation_review_revision: Some("legacy-wait-fixture".into()),
            windows_app_identity_review_revision: Some("identity-fixture".into()),
            windows_app_state_review_revision: Some("app-state-fixture".into()),
            release_signing_topology_revision: Some("signing-fixture".into()),
            vocabulary_digests: VocabularyDigestInputs {
                manifest_digest: digest(),
                source_lock_digest: digest(),
                computed_artifact_digest: digest(),
            },
            ..Default::default()
        },
        startup: StartupCapabilityProbe {
            windows_elevation: WindowsElevation::Medium,
            ..Default::default()
        },
        permissions: Default::default(),
    }
}

#[test]
fn only_the_test_route_admits_app_state_rows_with_the_exact_keys() {
    let inputs = exact_inputs();
    let legacy = BTreeSet::from(["computer.wait".to_owned()]);
    assert_eq!(
        rows(&inputs),
        BTreeSet::from([
            "computer.wait".to_owned(),
            "computer.read_state".into(),
            "computer.list_apps".into()
        ])
    );
    let mut no_wait = inputs.clone();
    no_wait.inputs.windows_actuation_review_revision = None;
    assert_eq!(
        rows(&no_wait),
        BTreeSet::from([
            "computer.read_state".to_owned(),
            "computer.list_apps".into()
        ])
    );
    let advertised = WindowsPlatformDriver::default()
        .declarations(&inputs)
        .into_iter()
        .filter(|row| row.advertised)
        .map(|row| row.capability_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(advertised, legacy);
    assert!(crate::dispatchable_tool(crate::flat_tools::COMPUTER_USE).is_none());

    let mut no_identity = inputs.clone();
    no_identity.inputs.windows_app_identity_review_revision = None;
    let mut no_state = inputs.clone();
    no_state.inputs.windows_app_state_review_revision = None;
    let mut no_signing = inputs.clone();
    no_signing.inputs.release_signing_topology_revision = None;
    let mut no_vocabulary = inputs.clone();
    no_vocabulary.inputs.vocabulary_digests.manifest_digest = None;
    let mut elevated = inputs.clone();
    elevated.startup.windows_elevation = WindowsElevation::ElevatedOrAboveMedium;
    let mut unreadable = inputs;
    unreadable.startup.windows_elevation = WindowsElevation::UnreadableOrBelowMedium;
    for (context, reason) in [
        (no_identity, "windows app identity review unbound"),
        (no_state, "windows app state review unbound"),
        (no_signing, "release signing topology unbound"),
        (no_vocabulary, "computer action vocabulary input unresolved"),
        (elevated, "cerebellum is running elevated"),
        (unreadable, "integrity unreadable"),
    ] {
        assert_eq!(app_state_block(&context), Some(reason));
        assert!(!rows(&context).contains("computer.read_state"));
        assert!(!rows(&context).contains("computer.list_apps"));
        assert_eq!(
            rows(&context).contains("computer.wait"),
            vocabulary_ready(&context)
        );
    }
}

#[derive(Default)]
struct CountLookups(AtomicUsize);
impl crate::management::TargetResolver for CountLookups {
    fn resolve(&self, _: &str) -> TargetResolution {
        self.0.fetch_add(1, Ordering::SeqCst);
        TargetResolution::NotRunning
    }
}

fn rig(
    context: &CapabilityAdvertisementContext,
    resolver: Arc<dyn crate::management::TargetResolver>,
    override_source: Option<Arc<dyn AppStateSource>>,
) -> crate::Planes {
    let mut planes = crate::Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    planes.management = Arc::new(crate::management::ManagementPlane::new(resolver));
    let audit = computer_audit(crate::JournalPersistence::Isolated).expect("isolated audit");
    let mut plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit,
        ResultSchemaEnforcement::Withhold,
        NativeComputerPlatformDriver::default,
    )
    .with_wire_dispatch_for_test()
    .with_session_lock_for_test(Some(false));
    let app_state_admitted = app_state_block(context).is_none();
    let launch_admitted = launch::launch_block(context).is_none();
    if app_state_admitted || launch_admitted {
        let mut source = WindowsAppStateSource::new(windows_identity::blocked);
        if launch_admitted {
            source = source
                .with_launch_inventory(launch::operator_name)
                .expect("start fixture inventory workers");
        }
        let permissions = PermissionLivenessReport::from_results([PermissionProbeResult {
            service: PermissionService::Accessibility,
            liveness: if WindowsAppStateSource::client_available() {
                PermissionLiveness::Live
            } else {
                PermissionLiveness::Unavailable
            },
            responsible_process: "ck-cerebellum".into(),
            off_main: true,
        }]);
        let permissions = if context.inputs.windows_capture_review_revision.is_some() {
            cerebellum_computer::platform::windows::picture::startup_permissions(
                &context.inputs,
                context.startup.windows_elevation,
            )
        } else {
            permissions
        };
        plane.windows_app_state_for_test = app_state_admitted.then(|| source.clone());
        plane = plane
            .with_app_state_source(Arc::new(source))
            .with_permission_liveness(permissions);
    }
    if let Some(source) = override_source {
        plane = plane.with_app_state_source(source);
    }
    planes.computer = Ok(Arc::new(plane));
    planes.computer_admitted = Arc::new(rows(context));
    planes.routes.insert(9, 3, crate::AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", "test-session"), crate::session_caller_principal_for_test(),
        Some(&json!({"agentProjectId":"test-project","sessionKind":"primary","effectiveCapabilityScope":["*"]})),
        Some(&["elicitation".into()]), &subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() },
    ));
    crate::computer_grants::tests::CardService::install(planes, 9, 3)
}

async fn wire(planes: &crate::Planes, action: &str, arguments: Value) -> Value {
    wire_with_questions(planes, action, arguments).await.0
}

async fn wire_with_questions(
    planes: &crate::Planes,
    action: &str,
    arguments: Value,
) -> (Value, usize) {
    wire_with_consent_hook(planes, action, arguments, || {}).await
}

async fn wire_with_consent_hook(
    planes: &crate::Planes,
    action: &str,
    arguments: Value,
    on_question: impl FnMut(),
) -> (Value, usize) {
    wire_with_decision(planes, action, arguments, "allow_30m", on_question).await
}

async fn wire_with_decision(
    planes: &crate::Planes,
    action: &str,
    mut arguments: Value,
    decision: &str,
    mut on_question: impl FnMut(),
) -> (Value, usize) {
    arguments["action"] = json!(action);
    let request = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        71,
        serde_json::to_vec(&json!({"name":"computer_use", "arguments":arguments})).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame_for_test(request, &tx, planes)
        .await
        .unwrap();
    tokio::time::timeout(crate::test_support::HANG_GUARD, async {
        let mut questions = 0;
        loop {
            let service = planes.consent_test.as_ref().unwrap();
            tokio::select! {
                question = service.card(9, 3) => {
                    questions += 1;
                    on_question();
                    assert!(service.answer(question.header.corr, crate::cingulate_client::ScriptedAnswer::Answered(json!({"decision":decision}))));
                }
                frame = rx.recv() => {
                    let frame = frame.unwrap();
                    assert_eq!(frame.header.ty, FrameType::Response);
                    return (serde_json::from_slice(&frame.body).unwrap(), questions);
                }
            }
        }
    }).await.expect("served Windows fixture call timed out")
}

#[tokio::test]
async fn unadmitted_value_wait_refuses_before_target_lookup_on_the_wire() {
    let resolver = Arc::new(CountLookups::default());
    let mut context = exact_inputs();
    for remove in 0..4 {
        let mut current = context.clone();
        match remove {
            0 => current.inputs.windows_app_identity_review_revision = None,
            1 => current.inputs.windows_app_state_review_revision = None,
            2 => current.inputs.release_signing_topology_revision = None,
            _ => current.startup.windows_elevation = WindowsElevation::ElevatedOrAboveMedium,
        }
        let planes = rig(&current, resolver.clone(), None);
        let reply = wire(&planes, "wait", json!({
            "app":"fixture.exe", "predicate":"element_value_equals Identifier=entry => ready", "timeout_ms":100,
        })).await;
        assert_eq!(reply["outcome"], "indeterminate", "{reply}");
        assert_eq!(reply["attempts"], 0, "{reply}");
        assert!(reply["evidence"]
            .as_str()
            .unwrap()
            .contains("scoped_read_unsupported"));
        assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
    }
    // Legacy wait still looks up the target without the application-state review key.
    context.inputs.windows_app_state_review_revision = None;
    let planes = rig(&context, resolver.clone(), None);
    let reply = wire(
        &planes,
        "wait",
        json!({
            "app":"fixture.exe", "predicate":"element_present Identifier=entry", "timeout_ms":100,
        }),
    )
    .await;
    assert_eq!(reply["outcome"], "not_running", "{reply}");
    assert_ne!(resolver.0.load(Ordering::SeqCst), 0);
}

struct BrokenInventory;
impl AppStateSource for BrokenInventory {
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        unreachable!("list_apps reads no application content")
    }
    fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
        Err(AppStateReadError::Unreadable)
    }
    fn installed_apps(&self, _: Duration) -> cerebellum_computer::app_state::source::InstalledApps {
        panic!("a failed running list must not read installed entries")
    }
}

#[tokio::test]
async fn failed_running_inventory_has_the_windows_remedy_on_the_wire() {
    let planes = rig(
        &exact_inputs(),
        Arc::new(CountLookups::default()),
        Some(Arc::new(BrokenInventory)),
    );
    let reply = wire(&planes, "list_apps", json!({})).await;
    assert_eq!(reply["outcome"], "targets_unreadable", "{reply}");
    assert_eq!(reply["unreadable"]["reason"], "window_list_unavailable");
    assert_eq!(
        reply["remedy"],
        "the running applications could not be read; retry, or name an application by app identity"
    );
}

struct NativeFixture(ProcessGrant);
impl crate::management::TargetResolver for NativeFixture {
    fn resolve(&self, target: &str) -> TargetResolution {
        if target == self.0.bundle_identity {
            TargetResolution::Resolved(self.0.clone())
        } else {
            TargetResolution::NotRunning
        }
    }
    fn resolves_windows_names(&self) -> bool {
        true
    }
    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        (pid == self.0.pid).then(|| self.0.clone())
    }
    fn app_code(&self, grant: &ProcessGrant) -> Arc<dyn crate::computer_grants::AppCode> {
        Arc::new(windows_identity::RunningCode(grant.clone()))
    }
}

/// The dedicated runner provides an owned, signed fixture with two normal
/// windows, a button in the second window and an ordinary value-bearing edit.
#[tokio::test]
#[ignore = "requires the medium-integrity interactive Windows fixture"]
async fn native_served_background_tree_value_wait_and_running_list() {
    assert_eq!(
        WindowsElevation::read_current_process(),
        WindowsElevation::Medium
    );
    assert_eq!(cerebellum_windows::input_desktop_name().unwrap(), "Default");
    let required =
        |name| std::env::var(name).unwrap_or_else(|_| panic!("fixture input {name} is missing"));
    let pid = required("CK_WINDOWS_APP_STATE_FIXTURE_PID")
        .parse()
        .unwrap();
    let button = required("CK_WINDOWS_APP_STATE_FIXTURE_BUTTON_TITLE");
    let entry = required("CK_WINDOWS_APP_STATE_FIXTURE_EDIT_AUTOMATION_ID");
    let value = required("CK_WINDOWS_APP_STATE_FIXTURE_EDIT_VALUE");
    let target =
        windows_identity::grant_for_pid(pid).expect("fixture has a verifiable app identity");
    assert!(target.bundle_identity.starts_with("win-signed:"));
    let principal = target.bundle_identity.clone();
    let planes = rig(&exact_inputs(), Arc::new(NativeFixture(target)), None);
    let before =
        cerebellum_windows::foreground_window_number().expect("person's foreground window");
    assert_ne!(cerebellum_windows::window_owner(before).unwrap().0, pid);

    let full = wire(&planes, "read_state", json!({"target":principal})).await;
    assert_eq!(full["outcome"], "completed", "{full}");
    let text = full["state_text"].as_str().unwrap();
    assert!(text.matches("AXWindow").count() >= 2, "{text}");
    assert!(!text.contains("no open window"), "{text}");
    assert_eq!(cerebellum_windows::foreground_window_number(), Some(before));

    let filtered = wire(
        &planes,
        "read_state",
        json!({"target":principal,"role_filter":"Button"}),
    )
    .await;
    assert_eq!(filtered["outcome"], "completed", "{filtered}");
    let text = filtered["state_text"].as_str().unwrap();
    assert!(
        text.lines()
            .any(|line| line.contains("AXButton") && line.contains(&button)),
        "{text}"
    );
    assert_eq!(cerebellum_windows::foreground_window_number(), Some(before));

    let waited = wire(
        &planes,
        "wait",
        json!({
            "app":principal, "predicate": {
                "kind":"element_value_equals", "element":{"Identifier":entry}, "expected":value,
            }, "timeout_ms":4000,
        }),
    )
    .await;
    assert_eq!(waited["outcome"], "predicate_satisfied", "{waited}");
    assert_eq!(cerebellum_windows::foreground_window_number(), Some(before));

    let listed = wire(&planes, "list_apps", json!({"text_filter":principal})).await;
    assert_eq!(listed["outcome"], "completed", "{listed}");
    assert_eq!(listed["installed_list"], "partial", "{listed}");
    assert!(
        listed["apps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|app| app["pid"] == pid
                && app["bundle_identity"] == principal
                && app["running"] == true),
        "{listed}"
    );
    assert_eq!(cerebellum_windows::foreground_window_number(), Some(before));
}
