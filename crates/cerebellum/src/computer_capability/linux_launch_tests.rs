use super::tests::request;
use super::*;
use cerebellum_computer::platform::vocabulary::validate_capability_result;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::{fs, process::Command};
use subc_protocol::{Flags, Frame, FrameType, Priority};

const ACTION: &str = "computer.open_app";
const TARGET: &str = "org.example.Fixture";
const PROGRAM: &str = "/mnt/ck-launch-fixture/program";
const ENTRY: &str = "/mnt/ck-launch-fixture/system/applications/org.example.Fixture.desktop";
const ENTRY_PACKAGE: &str = "ck-launch-entry";
const PROGRAM_PACKAGE: &str = "ck-launch-program";
const MARKER: &str = "/mnt/ck-launch-fixture/ran";

fn admitted() -> Arc<BTreeSet<String>> {
    Arc::new([ACTION.to_owned()].into_iter().collect())
}

#[tokio::test]
async fn open_app_admission_needs_a_readable_lock_but_no_accessibility_bus() {
    let reading = Arc::new(Mutex::new(None));
    let session = launch_session(reading.clone());
    assert_eq!(
        session.refusal(ComputerCapability::OpenApp).await.unwrap()["reason"],
        "no_supported_session"
    );
    let mut desktop = desktop();
    desktop.locked = true;
    *reading.lock().await = Some(desktop.clone());
    assert_eq!(
        session.refusal(ComputerCapability::OpenApp).await.unwrap()["outcome"],
        "screen_locked"
    );
    desktop.locked = false;
    for kind in [SessionKind::X11, SessionKind::Wayland] {
        desktop.kind = kind;
        *reading.lock().await = Some(desktop.clone());
        assert!(session.refusal(ComputerCapability::OpenApp).await.is_none());
    }
}

#[test]
fn open_app_launch_replies_match_the_published_schema() {
    use semantic::launch::Settle;
    for (settled, outcome, reason, detail) in [
        (
            Settle::Exited(DesktopExit::Code(0)),
            "launch_failed",
            json!("launch_child_exited"),
            json!({"exit_status":0}),
        ),
        (
            Settle::Exited(DesktopExit::Signal(11)),
            "launch_failed",
            json!("launch_child_exited"),
            json!({"signal":11}),
        ),
        (
            Settle::Unknown,
            "launch_failed",
            json!("launch_status_unknown"),
            Value::Null,
        ),
        (
            Settle::Running(16),
            "launched_no_window",
            Value::Null,
            Value::Null,
        ),
    ] {
        let reply = launch_settle_reply(settled);
        assert_eq!(reply["outcome"], outcome);
        assert_eq!(reply["reason"], reason);
        assert_eq!(reply["detail"], detail);
        if reason == "launch_child_exited" {
            assert!(reply["remedy"]
                .as_str()
                .unwrap()
                .contains("activation effect is unknown"));
        }
        validate_capability_result(ACTION, &reply).unwrap();
    }
    for reason in [
        "stale_reference",
        "image_replaced_since_launch",
        "launch_entry_unsupported",
        "app_identity_unproven",
        "package_checksum_unavailable",
        "launch_scope_unavailable",
        "cancelled",
        "screen_locked",
        "no_supported_session",
    ] {
        let reply = launch_failure(reason);
        validate_capability_result(ACTION, &reply)
            .unwrap_or_else(|error| panic!("{reply}: {error:?}"));
    }
}

fn desktop() -> DesktopSession {
    DesktopSession {
        id: "fixture-session".into(),
        kind: SessionKind::X11,
        locked: false,
        accessibility: None,
        environment: Environment::from([
            (
                "XDG_DATA_DIRS".into(),
                "/mnt/ck-launch-fixture/user:/mnt/ck-launch-fixture/system".into(),
            ),
            ("XDG_CURRENT_DESKTOP".into(), "LaunchFixture".into()),
            ("XMODIFIERS".into(), "@im=launch-fixture".into()),
            ("LD_PRELOAD".into(), "/not-allowed.so".into()),
            (
                "PATH".into(),
                "/mnt/ck-launch-fixture/home/.local/bin:/usr/bin".into(),
            ),
        ]),
    }
}

fn launch_session(reading: Arc<Mutex<Option<DesktopSession>>>) -> LinuxSession {
    let mut session = LinuxSession::new(false, admitted());
    session.identity = Some(Arc::default());
    session.read = Box::new(move || {
        let reading = reading.clone();
        Box::pin(async move {
            Ok(SessionReading {
                desktop: reading
                    .lock()
                    .await
                    .clone()
                    .ok_or(session::NoSupportedSession)?,
                x11_connection: None,
                permissions: PermissionLivenessReport::default(),
            })
        })
    });
    session
}

fn entry_text(exec: &str) -> String {
    format!("[Desktop Entry]\nType=Application\nName=Launch Fixture\nExec={exec}\n")
}

fn update_package(package: &str, paths: &[&str]) {
    let mut sums = String::new();
    for path in paths {
        let output = Command::new("/usr/bin/md5sum").arg(path).output().unwrap();
        assert!(output.status.success(), "md5sum failed for {path}");
        let text = String::from_utf8(output.stdout).unwrap();
        let sum = text.split_ascii_whitespace().next().unwrap();
        sums.push_str(&format!("{sum}  {}\n", path.trim_start_matches('/')));
    }
    // Install each record by rename so the package reader sees the same
    // directory change that invalidates its index on a dpkg update.
    for (suffix, bytes) in [
        ("list", format!("{}\n", paths.join("\n"))),
        ("md5sums", sums),
    ] {
        let record = format!("/var/lib/dpkg/info/{package}.{suffix}");
        let incoming = format!("{record}.new");
        fs::write(&incoming, bytes).unwrap();
        fs::rename(incoming, record).unwrap();
    }
}

fn set_exec(exec: &str) {
    fs::write(ENTRY, entry_text(exec)).unwrap();
    update_package(ENTRY_PACKAGE, &[ENTRY]);
}

fn checked(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Mount(&'static str);
impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/umount").arg(self.0).status();
    }
}

struct Fixture {
    _db: Mount,
    _workspace: Mount,
    _scratch: Scratch,
}

fn fixture() -> Fixture {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    assert_ne!(
        fs::metadata("/proc/self/ns/mnt").unwrap().ino(),
        fs::metadata("/proc/1/ns/mnt").unwrap().ino()
    );
    let scratch = Scratch(PathBuf::from(format!(
        "/tmp/ck-linux-launch-{}",
        std::process::id()
    )));
    fs::create_dir(&scratch.0).unwrap();
    assert_eq!(fs::metadata(&scratch.0).unwrap().uid(), 0);
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    checked(
        Command::new("/usr/bin/mount")
            .arg("--bind")
            .arg(&scratch.0)
            .arg("/mnt"),
    );
    let workspace = Mount("/mnt");
    for dir in [
        "system/applications",
        "user/applications",
        "dpkg/info",
        "home/.local/bin",
    ] {
        fs::create_dir_all(format!("/mnt/ck-launch-fixture/{dir}")).unwrap();
    }
    fs::set_permissions(
        "/mnt/ck-launch-fixture/user",
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    fs::write("/mnt/ck-launch-fixture/dpkg/status", "").unwrap();
    checked(Command::new("/usr/bin/mount").args([
        "--bind",
        "/mnt/ck-launch-fixture/dpkg",
        "/var/lib/dpkg",
    ]));
    let db = Mount("/var/lib/dpkg");
    let source = "/mnt/ck-launch-fixture/program.c";
    fs::write(
        source,
        include_str!("../../../cerebellum-computer/src/platform/linux/fixtures/launch.c"),
    )
    .unwrap();
    checked(Command::new("/usr/bin/cc").args(["-static", "-o", PROGRAM, source]));
    fs::copy(PROGRAM, "/mnt/ck-launch-fixture/home/.local/bin/true").unwrap();
    fs::write(
        "/mnt/ck-launch-fixture/user/applications/org.example.Fixture.desktop",
        entry_text("/bin/sh -c ignored"),
    )
    .unwrap();
    update_package(
        PROGRAM_PACKAGE,
        &[PROGRAM, "/usr/bin/true", "/usr/bin/env", "/bin/dash"],
    );
    Fixture {
        _db: db,
        _workspace: workspace,
        _scratch: scratch,
    }
}

const NORMAL: usize = 0;
const LOCK: usize = 1;
const SWITCH: usize = 2;
const LOST: usize = 3;
const SCOPE_ERROR: usize = 4;
const UPDATE_ENTRY: usize = 5;
const CANCEL_IN_SCOPE: usize = 6;
const REPLACE_PROGRAM: usize = 7;

enum Consent {
    Approve,
    Cancel,
}

struct Rig {
    planes: crate::Planes,
    desktop: Arc<Mutex<Option<DesktopSession>>>,
    scope: Arc<AtomicUsize>,
    stopped_pid: Arc<AtomicU32>,
    next: u64,
}

impl Rig {
    fn new() -> Self {
        let desktop = Arc::new(Mutex::new(Some(desktop())));
        let scope = Arc::new(AtomicUsize::new(NORMAL));
        let stopped_pid = Arc::new(AtomicU32::new(0));
        let mut session = launch_session(desktop.clone());
        let scoped = (desktop.clone(), scope.clone(), stopped_pid.clone());
        session.scope_for_test = Some(Arc::new(move |generation| {
            let (desktop, scope, stopped_pid) = scoped.clone();
            Box::pin(async move {
                let pid = generation.pid;
                assert!(
                    !Path::new(MARKER).exists(),
                    "the app ran before scope placement"
                );
                assert_eq!(
                    cerebellum_linux::process_descriptors(pid).unwrap(),
                    [0, 1, 2]
                );
                stopped_pid.store(pid, Ordering::Release);
                match scope.load(Ordering::Acquire) {
                    LOCK => desktop.lock().await.as_mut().unwrap().locked = true,
                    SWITCH => desktop.lock().await.as_mut().unwrap().id = "replacement".into(),
                    LOST => *desktop.lock().await = None,
                    SCOPE_ERROR => return Err("launch_scope_unavailable"),
                    UPDATE_ENTRY => {
                        fs::write(ENTRY, entry_text(&format!("{PROGRAM} exit"))).unwrap()
                    }
                    REPLACE_PROGRAM => {
                        let saved = format!("{PROGRAM}.saved");
                        fs::rename(PROGRAM, &saved).unwrap();
                        fs::copy(saved, PROGRAM).unwrap();
                    }
                    CANCEL_IN_SCOPE => std::future::pending::<()>().await,
                    _ => (),
                }
                Ok(())
            })
        }));
        let session = Arc::new(session);
        let driver = session.clone();
        let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
            computer_audit(JournalPersistence::Isolated).unwrap(),
            ResultSchemaEnforcement::Withhold,
            move || driver.driver(),
        );
        let mut planes = crate::Planes::with_browser_config_journaling(
            Arc::default(),
            None,
            JournalPersistence::Isolated,
        );
        planes.computer_admitted = session.admitted.clone();
        planes.computer = Ok(Arc::new(ComputerPlane {
            linux_session: Some(session),
            ..plane
        }));
        super::tests::bind_fixture(&planes);
        let planes = crate::computer_grants::tests::CardService::install(planes, 7, 1);
        Self {
            planes,
            desktop,
            scope,
            stopped_pid,
            next: 100,
        }
    }

    async fn cancel(&self, tx: &tokio::sync::mpsc::Sender<Frame>) {
        let cancel = Frame::build(
            FrameType::Cancel,
            Flags::new(false, Priority::Interactive, true),
            7,
            1,
            self.next,
            b"{}".to_vec(),
        )
        .unwrap();
        crate::handle_frame_for_test(cancel, tx, &self.planes)
            .await
            .unwrap();
    }

    async fn call(&mut self, target: &str, mut on_question: impl FnMut() -> Consent) -> Value {
        self.stopped_pid.store(0, Ordering::Release);
        self.next += 1;
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        crate::handle_frame_for_test(
            request(self.next, ACTION, json!({"target":target})),
            &tx,
            &self.planes,
        )
        .await
        .unwrap();
        let mut cancel_pending = self.scope.load(Ordering::Acquire) == CANCEL_IN_SCOPE;
        tokio::time::timeout(crate::test_support::HANG_GUARD, async {
            loop {
                let service = self.planes.consent_test.as_ref().unwrap();
                tokio::select! {
                    question = service.card(7, 1) => {
                        assert_eq!(self.stopped_pid.load(Ordering::Acquire), 0, "spawn before consent");
                        assert!(!Path::new(MARKER).exists());
                        match on_question() {
                            Consent::Approve => assert!(service.answer(question.header.corr, crate::cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"})))),
                            Consent::Cancel => self.cancel(&tx).await,
                        }
                    }
                    () = wait_for(|| self.stopped_pid.load(Ordering::Acquire) != 0), if cancel_pending => {
                        cancel_pending = false;
                        self.cancel(&tx).await;
                    }
                    frame = rx.recv() => {
                        let frame = frame.unwrap();
                        let reply: Value = serde_json::from_slice(&frame.body).unwrap();
                        assert_eq!(frame.header.ty, FrameType::Response, "{reply}");
                        validate_capability_result(ACTION, &reply).unwrap_or_else(|error| panic!("{reply}: {error:?}"));
                        return reply;
                    }
                }
            }
        }).await.expect("Linux launch did not settle")
    }

    async fn reaped(&self) {
        let pid = self.stopped_pid.load(Ordering::Acquire);
        assert_ne!(pid, 0, "scope was never reached");
        tokio::time::timeout(
            Duration::from_secs(6),
            wait_for(|| !Path::new(&format!("/proc/{pid}")).exists()),
        )
        .await
        .expect("launch child was not reaped");
    }

    async fn no_question(&mut self, target: &str) -> Value {
        self.call(target, || panic!("unexpected consent for {target}"))
            .await
    }
}

async fn wait_for(condition: impl Fn() -> bool) {
    while !condition() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires GitHub-hosted Ubuntu and the workflow's private mount namespace"]
async fn native_open_app_checks_package_grant_scope_lock_and_release() {
    let _fixture = fixture();
    let command = format!("{PROGRAM} check %U %%");
    set_exec(&command);
    {
        let mut awaiting_consent = Rig::new();
        let reply = awaiting_consent.call(TARGET, || Consent::Cancel).await;
        assert_eq!(reply["outcome"], "cancelled", "{reply}");
        assert_eq!(awaiting_consent.stopped_pid.load(Ordering::Acquire), 0);
        assert!(!Path::new(MARKER).exists());
    }
    let mut rig = Rig::new();

    // Select the system desktop file by ID, ignoring the shadow file in the
    // writable data directory. Grant the program's package, not the entry's.
    let mut asked = false;
    let reply = rig
        .call(TARGET, || {
            asked = true;
            fs::write(ENTRY, entry_text(&format!("{PROGRAM} exit"))).unwrap();
            Consent::Approve
        })
        .await;
    assert!(asked);
    assert_eq!(reply["reason"], "stale_reference", "{reply}");
    assert_eq!(rig.stopped_pid.load(Ordering::Acquire), 0);
    let grants = rig.planes.management.computer_grants().agent_grants();
    let rows = grants.live_rows(None, grants.now_ms()).unwrap();
    assert!(rows.iter().any(|row| row.subject
        == crate::agent_grants::GrantSubject::App(format!("dpkg:{PROGRAM_PACKAGE}"))));
    assert!(!rows.iter().any(|row| row.subject
        == crate::agent_grants::GrantSubject::App(format!("dpkg:{ENTRY_PACKAGE}"))));
    set_exec(&command);
    let reply = rig.no_question(TARGET).await;
    assert_eq!(reply["outcome"], "launched_no_window", "{reply}");
    assert_eq!(reply["pid"], rig.stopped_pid.load(Ordering::Acquire));
    assert!(Path::new(MARKER).exists());
    rig.reaped().await;
    fs::remove_file(MARKER).unwrap();

    for (mode, reason) in [
        (LOCK, "screen_locked"),
        (SWITCH, "stale_reference"),
        (LOST, "no_supported_session"),
        (SCOPE_ERROR, "launch_scope_unavailable"),
        (UPDATE_ENTRY, "stale_reference"),
        (REPLACE_PROGRAM, "image_replaced_since_launch"),
    ] {
        rig.scope.store(mode, Ordering::Release);
        let reply = rig.no_question(TARGET).await;
        let failure = reply["reason"].as_str().or(reply["outcome"].as_str());
        assert_eq!(failure, Some(reason), "{reply}");
        rig.reaped().await;
        assert!(!Path::new(MARKER).exists(), "child ran after {reason}");
        *rig.desktop.lock().await = Some(desktop());
        if mode == REPLACE_PROGRAM {
            fs::rename(format!("{PROGRAM}.saved"), PROGRAM).unwrap();
        }
        set_exec(&command);
    }
    // The scope request comes after dispatch was committed. The terminal
    // reply cannot promise the worker has already stopped the barred child.
    rig.scope.store(CANCEL_IN_SCOPE, Ordering::Release);
    let cancelled = rig.no_question(TARGET).await;
    assert_eq!(
        cancelled["outcome"], "dispatch_outcome_unknown",
        "{cancelled}"
    );
    assert_eq!(cancelled["detail"]["reason"], "cancelled", "{cancelled}");
    assert_eq!(cancelled["detail"]["dispatched"], true, "{cancelled}");
    assert_eq!(cancelled["detail"]["step"], "dispatch", "{cancelled}");
    rig.reaped().await;
    assert!(
        !Path::new(MARKER).exists(),
        "cancelled scope released its child"
    );
    rig.scope.store(NORMAL, Ordering::Release);

    for (exec, detail) in [
        ("true".into(), json!({"exit_status":0})),
        (format!("{PROGRAM} crash"), json!({"signal":11})),
    ] {
        set_exec(&exec);
        let reply = rig.no_question(TARGET).await;
        assert_eq!(reply["reason"], "launch_child_exited", "{reply}");
        assert_eq!(reply["detail"], detail, "{reply}");
        assert!(reply.get("pid").is_none());
        rig.reaped().await;
    }
    entry_refusals(&mut rig, &command).await;
    edit_between_pre_spawn_check_and_exec_stop(&command);

    let running = rig.no_question(TARGET).await;
    assert_eq!(running["outcome"], "launched_no_window", "{running}");
    let pid = rig.stopped_pid.load(Ordering::Acquire);
    let proc = PathBuf::from(format!("/proc/{pid}"));
    drop(rig);
    assert!(
        proc.is_dir(),
        "module teardown stopped the released process"
    );
    tokio::time::timeout(Duration::from_secs(6), wait_for(|| !proc.exists()))
        .await
        .unwrap();
}

async fn entry_refusals(rig: &mut Rig, working: &str) {
    set_exec(working);
    let not_installed = rig.no_question("No Such App").await;
    assert_eq!(
        not_installed["outcome"], "no_installed_app_named",
        "{not_installed}"
    );
    const HELPER: &str = "/mnt/ck-launch-fixture/system/applications/helper.desktop";
    fs::write(HELPER, format!("{}NoDisplay=true\n", entry_text(working))).unwrap();
    update_package(ENTRY_PACKAGE, &[ENTRY, HELPER]);
    let snapshot = desktop_entry::resolve(
        &IdentityReader::default(),
        &desktop().environment,
        &format!("dpkg:{PROGRAM_PACKAGE}"),
    );
    assert!(
        snapshot.is_ok(),
        "NoDisplay helper must not count in a subject match"
    );
    fs::write(HELPER, entry_text(working)).unwrap();
    update_package(ENTRY_PACKAGE, &[ENTRY, HELPER]);
    let ambiguous = rig.no_question("Launch Fixture").await;
    assert_eq!(ambiguous["outcome"], "ambiguous_app", "{ambiguous}");
    fs::remove_file(HELPER).unwrap();

    let wrapper = "/mnt/ck-launch-fixture/wrapper";
    let unowned = "/mnt/ck-launch-fixture/unowned";
    fs::write(wrapper, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    // Leave this ELF outside the private dpkg inventory. The hosted runner
    // also installs rpm for another fixture; the tool alone is not a database.
    fs::copy(PROGRAM, unowned).unwrap();
    for exec in [
        "sh -c ignored",
        "env true",
        "/bin/dash",
        "/snap/bin/example",
        wrapper,
        unowned,
        "/mnt/ck-launch-fixture/program %Z",
    ] {
        set_exec(exec);
        let reply = rig.no_question(TARGET).await;
        assert_eq!(
            reply["reason"], "launch_entry_unsupported",
            "{exec}: {reply}"
        );
        assert_eq!(rig.stopped_pid.load(Ordering::Acquire), 0);
    }
    fs::write(ENTRY, format!("{}Terminal=true\n", entry_text(working))).unwrap();
    update_package(ENTRY_PACKAGE, &[ENTRY]);
    let terminal = rig.no_question(TARGET).await;
    assert_eq!(terminal["reason"], "launch_entry_unsupported", "{terminal}");
    set_exec(working);
    fs::write(ENTRY, entry_text(&format!("{PROGRAM} exit"))).unwrap();
    let wrong_sum = rig.no_question(TARGET).await;
    assert_eq!(
        wrong_sum["reason"], "launch_entry_unsupported",
        "{wrong_sum}"
    );
    set_exec(working);
    fs::remove_file(format!("/var/lib/dpkg/info/{ENTRY_PACKAGE}.md5sums")).unwrap();
    let missing_sum = rig.no_question(TARGET).await;
    assert_eq!(
        missing_sum["reason"], "package_checksum_unavailable",
        "{missing_sum}"
    );
    fs::remove_file(format!("/var/lib/dpkg/info/{ENTRY_PACKAGE}.list")).unwrap();
    let unlisted = rig.no_question(TARGET).await;
    assert_eq!(unlisted["reason"], "launch_entry_unsupported", "{unlisted}");
    set_exec(working);
}

fn edit_between_pre_spawn_check_and_exec_stop(working: &str) {
    let environment = desktop().environment;
    let identity = IdentityReader::default();
    let saved = format!("{PROGRAM}.saved");
    for scenario in 0..3 {
        let snapshot = desktop_entry::resolve(&identity, &environment, TARGET).unwrap();
        let result = semantic::launch::release(
            &snapshot,
            &identity,
            &environment,
            || {
                match scenario {
                    0 => fs::write(ENTRY, entry_text(&format!("{PROGRAM} exit"))).unwrap(),
                    1 => {
                        fs::rename(ENTRY, format!("{ENTRY}.saved")).unwrap();
                        fs::copy(format!("{ENTRY}.saved"), ENTRY).unwrap();
                    }
                    _ => {
                        fs::rename(PROGRAM, &saved).unwrap();
                        fs::copy(&saved, PROGRAM).unwrap();
                    }
                }
                Ok(())
            },
            || Ok(()),
            |_| panic!("changed launch reached the scope placer"),
        );
        assert_eq!(
            result.err(),
            Some(if scenario == 2 {
                "image_replaced_since_launch"
            } else {
                "stale_reference"
            })
        );
        assert!(!Path::new(MARKER).exists());
        if scenario == 2 {
            fs::rename(&saved, PROGRAM).unwrap();
        }
        set_exec(working);
    }
}
