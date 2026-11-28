use super::*;

pub(super) fn launch_block(context: &CapabilityAdvertisementContext) -> Option<&'static str> {
    let inputs = &context.inputs;
    if inputs.windows_app_identity_review_revision.is_none() {
        return Some("windows app identity review unbound");
    }
    if inputs.windows_app_launch_review_revision.is_none() {
        return Some("windows app launch review unbound");
    }
    if !vocabulary_ready(context) {
        return Some("computer action vocabulary input unresolved");
    }
    if inputs.release_signing_topology_revision.is_none() {
        return Some("release signing topology unbound");
    }
    match context.startup.windows_elevation {
        WindowsElevation::Medium => None,
        WindowsElevation::ElevatedOrAboveMedium => Some("cerebellum is running elevated"),
        WindowsElevation::UnreadableOrBelowMedium => Some("integrity unreadable"),
    }
}

pub(super) fn operator_name(name: &str) -> bool {
    operator_apps::identity_blocked(name) || operator_apps::title_names_operator_app(name)
}

fn reviewed() -> CapabilityAdvertisementContext {
    let mut context = exact_inputs();
    context.inputs.windows_app_launch_review_revision = Some("launch-fixture".into());
    context
}

#[test]
fn only_the_test_route_admits_open_app_with_the_exact_keys() {
    let mut context = reviewed();
    context.inputs.windows_app_state_review_revision = None;
    context.inputs.windows_actuation_review_revision = None;
    assert_eq!(
        rows(&context),
        BTreeSet::from(["computer.open_app".to_owned()])
    );
    for (remove, expected) in [
        (0, "windows app identity review unbound"),
        (1, "windows app launch review unbound"),
        (2, "computer action vocabulary input unresolved"),
        (3, "release signing topology unbound"),
        (4, "cerebellum is running elevated"),
        (5, "integrity unreadable"),
    ] {
        let mut less = context.clone();
        match remove {
            0 => less.inputs.windows_app_identity_review_revision = None,
            1 => less.inputs.windows_app_launch_review_revision = None,
            2 => less.inputs.vocabulary_digests.manifest_digest = None,
            3 => less.inputs.release_signing_topology_revision = None,
            4 => less.startup.windows_elevation = WindowsElevation::ElevatedOrAboveMedium,
            _ => less.startup.windows_elevation = WindowsElevation::UnreadableOrBelowMedium,
        }
        assert_eq!(launch_block(&less), Some(expected));
        assert!(rows(&less).is_empty());
    }
    assert!(WindowsPlatformDriver::default()
        .declarations(&context)
        .iter()
        .all(|row| !row.advertised));
    assert!(crate::dispatchable_tool(crate::flat_tools::COMPUTER_USE).is_none());
}

struct FixtureResolver;

impl crate::management::TargetResolver for FixtureResolver {
    fn resolve(&self, target: &str) -> TargetResolution {
        self.resolve_with_policy(target)
            .unwrap_or(TargetResolution::Unreadable(
                cerebellum_computer::platform::UnreadableReason::RunningAppListUnavailable,
            ))
    }

    fn resolve_with_policy(&self, target: &str) -> Result<TargetResolution, Value> {
        windows_identity::resolve_target(target)
    }

    fn resolves_windows_names(&self) -> bool {
        true
    }

    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        windows_identity::grant_for_pid(pid)
    }

    fn app_code(&self, grant: &ProcessGrant) -> Arc<dyn crate::computer_grants::AppCode> {
        Arc::new(windows_identity::RunningCode(grant.clone()))
    }
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("fixture input {name} is missing"))
}

fn desktop() -> u32 {
    assert_eq!(
        WindowsElevation::read_current_process(),
        WindowsElevation::Medium
    );
    assert!(matches!(
        cerebellum_windows::current_session_provenance(),
        cerebellum_windows::SessionProvenance::Console { .. }
    ));
    assert_eq!(cerebellum_windows::input_desktop_name().unwrap(), "Default");
    cerebellum_windows::foreground_window_number().expect("fixture runner foreground window")
}

fn fixture_rig() -> crate::Planes {
    rig(&reviewed(), Arc::new(FixtureResolver), None)
}

fn entry<'a>(reply: &'a Value, principal: &str) -> Option<&'a Value> {
    assert_eq!(reply["outcome"], "completed", "{reply}");
    reply["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|app| app["bundle_identity"] == principal)
}

async fn list(planes: &crate::Planes, target: &str) -> Value {
    wire(planes, "list_apps", json!({"text_filter":target})).await
}

async fn cached(planes: &crate::Planes, target: &str) {
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let reply = list(planes, target).await;
        if let Some(app) = entry(&reply, target) {
            assert_eq!(app["running"], false, "fixture must start stopped: {reply}");
            return;
        }
        assert_eq!(reply["installed_list"], "partial", "{reply}");
        assert!(
            std::time::Instant::now() < until,
            "inventory never verified {target}: {reply}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn open(planes: &crate::Planes, target: &str) -> Value {
    let before = desktop();
    let reply = wire(planes, "open_app", json!({"target":target})).await;
    if cerebellum_windows::foreground_window_number() != Some(before) {
        assert_eq!(reply["fronting"]["mode"], "background", "{reply}");
        assert_eq!(reply["fronting"]["fronted"], false, "{reply}");
        assert_eq!(reply["fronting"]["purpose"], "none", "{reply}");
    }
    reply
}

async fn scoped_read(planes: &crate::Planes, principal: &str, asks: usize) {
    let (state, questions) =
        wire_with_questions(planes, "read_state", json!({"target":principal})).await;
    assert_eq!(state["outcome"], "completed", "{state}");
    assert!(
        state["state_text"].as_str().unwrap().contains("AXWindow"),
        "{state}"
    );
    assert_eq!(questions, asks, "{state}");
}

async fn owned_launch(target: &str, handoff: bool) {
    desktop();
    let planes = fixture_rig();
    cached(&planes, target).await;
    let reply = open(&planes, target).await;
    assert_eq!(reply["outcome"], "launched", "{reply}");
    assert_eq!(reply["has_window"], true, "{reply}");
    let pid = reply["pid"].as_u64().unwrap() as u32;
    assert_eq!(
        windows_identity::grant_for_pid(pid)
            .unwrap()
            .bundle_identity,
        target
    );
    if !target.starts_with("win-package:") {
        assert!(!cerebellum_windows::retain_image_process(pid)
            .unwrap()
            .in_job()
            .unwrap());
    }
    if handoff {
        let path = cerebellum_windows::retain_image_process(pid)
            .unwrap()
            .image_path()
            .unwrap();
        assert!(
            path.file_name()
                .unwrap()
                .eq_ignore_ascii_case(required("CK_WINDOWS_LAUNCH_HANDOFF_OWNER_EXE")),
            "returned the stub, not the window owner: {reply}"
        );
    }
    scoped_read(&planes, target, 0).await;
}

#[tokio::test]
#[ignore = "requires a stopped signed Win32 fixture with a per-user Start-menu shortcut and a job that permits breakaway"]
async fn native_win32_launch_binds_a_process_and_scoped_read() {
    owned_launch(&required("CK_WINDOWS_LAUNCH_WIN32"), false).await;
}

#[tokio::test]
#[ignore = "requires a stopped signed package with an ApplicationFrameHost-hosted fixture app"]
async fn native_package_launch_binds_the_hosted_owner_and_scoped_read() {
    owned_launch(&required("CK_WINDOWS_LAUNCH_PACKAGE"), false).await;
}

#[tokio::test]
#[ignore = "requires a stopped signed launcher that exits after creating a same-principal child with a different image path"]
async fn native_same_principal_handoff_returns_the_window_owners_pid() {
    owned_launch(&required("CK_WINDOWS_LAUNCH_HANDOFF"), true).await;
}

#[tokio::test]
#[ignore = "requires a stopped signed launcher stub that starts a same-publisher child with a different OriginalFilename"]
async fn native_different_principal_child_remains_ungranted() {
    desktop();
    let target = required("CK_WINDOWS_LAUNCH_WRONG_CHILD_STUB");
    let child = required("CK_WINDOWS_LAUNCH_WRONG_CHILD");
    let planes = fixture_rig();
    cached(&planes, &target).await;
    let reply = open(&planes, &target).await;
    assert_eq!(reply["outcome"], "launched_no_window", "{reply}");
    assert_eq!(reply["has_window"], false, "{reply}");
    let listed = list(&planes, &child).await;
    let running = entry(&listed, &child).expect("child is listed under its own principal");
    assert_eq!(running["running"], true, "{listed}");
    assert_ne!(running["pid"], reply["pid"], "{reply}");
    scoped_read(&planes, &child, 1).await;
}

#[tokio::test]
#[ignore = "requires a stopped signed shortcut fixture whose manifest requests elevation; UAC enabled"]
async fn native_elevation_required_creates_no_process() {
    desktop();
    let target = required("CK_WINDOWS_LAUNCH_ELEVATED");
    let planes = fixture_rig();
    cached(&planes, &target).await;
    let reply = open(&planes, &target).await;
    assert_eq!(reply["outcome"], "launch_failed", "{reply}");
    assert_eq!(reply["detail"]["reason"], "target_elevated", "{reply}");
    assert!(reply.get("pid").is_none(), "{reply}");
    let listed = list(&planes, &target).await;
    assert_eq!(
        entry(&listed, &target).unwrap()["running"],
        false,
        "{listed}"
    );
}

#[tokio::test]
#[ignore = "requires a stopped installed signed fixture in the interactive session"]
async fn native_installed_list_is_partial_until_review_and_cache_are_ready() {
    desktop();
    let target = required("CK_WINDOWS_LAUNCH_INVENTORY");
    let unbound = rig(&exact_inputs(), Arc::new(FixtureResolver), None);
    let listed = list(&unbound, &target).await;
    assert_eq!(listed["installed_list"], "partial", "{listed}");
    assert!(entry(&listed, &target).is_none(), "{listed}");
    let planes = fixture_rig();
    let (uncached, asks) = wire_with_questions(&planes, "open_app", json!({"target":target})).await;
    assert_eq!(uncached["outcome"], "no_installed_app_named", "{uncached}");
    assert_eq!(uncached["installed_list"], "partial", "{uncached}");
    assert_eq!(asks, 0);
    cached(&planes, &target).await;
    let (url, asks) = wire_with_questions(
        &planes,
        "open_app",
        json!({"target":target,"url":"launch-fixture:unsupported"}),
    )
    .await;
    assert_eq!(url["outcome"], "url_scheme_refused", "{url}");
    assert_eq!(asks, 0);
}

#[tokio::test]
#[ignore = "requires a signed package with two apps, one operator-named by its manifest executable"]
async fn native_package_inventory_excludes_just_the_operator_application() {
    desktop();
    let target = required("CK_WINDOWS_LAUNCH_PACKAGE_ALLOWED");
    let blocked = required("CK_WINDOWS_LAUNCH_PACKAGE_BLOCKED");
    let planes = fixture_rig();
    cached(&planes, &target).await;
    let listed = list(&planes, &blocked).await;
    assert!(entry(&listed, &blocked).is_none(), "{listed}");
    assert_ne!(target, blocked);
}

#[tokio::test]
#[ignore = "requires per-user launch fixtures with a nonempty shortcut argument list and a neutral shortcut to an operator-named executable"]
async fn native_inventory_omits_shortcut_arguments_and_neutral_operator_title() {
    desktop();
    let sentinel = required("CK_WINDOWS_LAUNCH_INVENTORY");
    let planes = fixture_rig();
    cached(&planes, &sentinel).await;
    for name in [
        "CK_WINDOWS_LAUNCH_ARGUMENTS_LINK",
        "CK_WINDOWS_LAUNCH_OPERATOR_LINK",
    ] {
        let path = std::path::PathBuf::from(required(name));
        let title = path.file_stem().unwrap().to_str().unwrap();
        assert!(path.is_file(), "fixture shortcut is not installed");
        let found = list(&planes, title).await;
        assert!(
            !found["apps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|app| app["name"] == title),
            "{found}"
        );
        let (reply, asks) = wire_with_questions(&planes, "open_app", json!({"target":title})).await;
        assert_eq!(reply["outcome"], "no_installed_app_named", "{reply}");
        assert_eq!(asks, 0);
    }
}

#[tokio::test]
#[ignore = "requires an unsigned Win32 fixture installed via a per-user shortcut"]
async fn native_unsigned_inventory_entry_cannot_be_launched() {
    desktop();
    let target = required("CK_WINDOWS_LAUNCH_UNSIGNED");
    let planes = fixture_rig();
    cached(&planes, &target).await;
    let (reply, asks) = wire_with_questions(&planes, "open_app", json!({"target":target})).await;
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert_eq!(
        reply["detail"]["reason"], "app_identity_unreadable",
        "{reply}"
    );
    assert_eq!(asks, 0);
    let listed = list(&planes, &target).await;
    assert_eq!(
        entry(&listed, &target).unwrap()["running"],
        false,
        "{listed}"
    );
}

struct OwnedChild(std::process::Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires a signed windowless launch fixture and a separate signed GUI fixture executable"]
async fn native_unrelated_window_during_wait_does_not_receive_the_grant() {
    desktop();
    let target = required("CK_WINDOWS_LAUNCH_WINDOWLESS");
    let other = required("CK_WINDOWS_LAUNCH_UNRELATED");
    let executable = required("CK_WINDOWS_LAUNCH_UNRELATED_EXE");
    let started = std::path::PathBuf::from(required("CK_WINDOWS_LAUNCH_WINDOWLESS_STARTED_FILE"));
    assert!(
        !started.exists(),
        "the fixture marker must be absent before launch"
    );
    let planes = fixture_rig();
    cached(&planes, &target).await;
    let introduce_other = async {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !started.is_file() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("windowless fixture startup marker");
        // The unrelated executable is a signed GUI test fixture, never a browser.
        #[allow(
            clippy::disallowed_methods,
            reason = "spawns the signed GUI fixture executable as an owned test child, never a browser"
        )]
        OwnedChild(
            std::process::Command::new(executable)
                .spawn()
                .expect("start owned unrelated fixture"),
        )
    };
    let (reply, child) = tokio::join!(open(&planes, &target), introduce_other);
    assert_eq!(reply["outcome"], "launched_no_window", "{reply}");
    assert_ne!(reply["pid"], child.0.id(), "{reply}");
    scoped_read(&planes, &other, 1).await;
}

#[tokio::test]
#[ignore = "requires a stopped signed fixture, a test-owned Start-menu shortcut, and a startup marker written only if the fixture executes"]
async fn native_changed_shortcut_after_consent_prompt_starts_no_fixture() {
    desktop();
    let target = required("CK_WINDOWS_LAUNCH_CHANGED");
    let link = std::path::PathBuf::from(required("CK_WINDOWS_LAUNCH_CHANGED_LINK"));
    let moved = link.with_extension("lnk.cereb-fixture-hold");
    let started = std::path::PathBuf::from(required("CK_WINDOWS_LAUNCH_CHANGED_STARTED_FILE"));
    assert!(link.is_file() && !moved.exists() && !started.exists());
    struct RestoreLink<'a>(&'a std::path::Path, &'a std::path::Path);
    impl Drop for RestoreLink<'_> {
        fn drop(&mut self) {
            if self.1.exists() {
                let _ = std::fs::rename(self.1, self.0);
            }
        }
    }
    let _restore = RestoreLink(&link, &moved);
    let planes = fixture_rig();
    cached(&planes, &target).await;
    let (reply, asks) =
        wire_with_consent_hook(&planes, "open_app", json!({"target":target}), || {
            std::fs::rename(&link, &moved).expect("remove the test shortcut during consent");
        })
        .await;
    assert_eq!(asks, 1);
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert!(reply.get("pid").is_none() && !started.exists(), "{reply}");
}

#[tokio::test]
#[ignore = "requires a running signed fixture with its Start-menu shortcut on the interactive Windows runner"]
async fn windows_foreground_open_is_unavailable_with_all_windows_review_keys() {
    let before = desktop();
    let target = required("CK_WINDOWS_FRONTING_OPEN_RUNNING");
    let mut context = reviewed();
    all_fronting_inputs(&mut context);
    let mut planes = rig(&context, Arc::new(FixtureResolver), None);
    foreground_without_driver(&mut planes);
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let listed = list(&planes, &target).await;
        if let Some(app) = entry(&listed, &target) {
            assert_eq!(
                app["running"], true,
                "the fixture must already be running: {listed}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "installed fixture missing: {listed}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let reply = wire(&planes, "open_app", json!({"target":target})).await;
    assert_eq!(reply["outcome"], "already_running", "{reply}");
    assert_eq!(
        reply["fronting"],
        json!({
            "mode":"foreground", "fronted":false, "purpose":"foreground_mode", "restore":"not_needed", "not_fronted_reason":"fronting_unavailable"
        }),
        "{reply}"
    );
    assert_eq!(cerebellum_windows::foreground_window_number(), Some(before));
}
