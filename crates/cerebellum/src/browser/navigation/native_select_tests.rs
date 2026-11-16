//! Real Chrome behind the same session connection owner and BrowserPlane checks
//! as an agent call. The launcher alone is a test adapter: it uses a fresh profile
//! and forces headless mode without changing production launch arguments.
use super::*;
use crate::browser_launch_readiness::UnixCdpPipe;
use crate::browser_session::*;
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

struct TracePipe(UnixCdpPipe);
impl CdpPipeIo for TracePipe {
    fn readiness(&self) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
        self.0.readiness()
    }
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        eprintln!("SELECT CDP SEND {}", String::from_utf8_lossy(bytes));
        self.0.write_frame(bytes)
    }
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<PipeRead> {
        let result = self.0.read(bytes)?;
        if let PipeRead::Bytes(count) = result {
            eprintln!(
                "SELECT CDP READ {}",
                String::from_utf8_lossy(&bytes[..count.min(1000)])
            );
        }
        Ok(result)
    }
}

const HTML: &str = r#"<!doctype html><title>Native select fixture</title>
<select id="platform"><option value="ios">iOS</option><option value="mac">macOS</option></select>
<select id="multi" multiple><option selected>First</option><option>Second</option></select>
<select><option disabled>Disabled option</option><optgroup disabled><option>Disabled group</option></optgroup></select>
<select disabled><option>Disabled select</option></select>
<form><input autocomplete="cc-number"><select id="payment"><option>Card default</option><option>Card choice</option></select></form>
<form><input type="password"><select id="login"><option>Login default</option><option>Login choice</option></select></form>
<p id="status">No change</p><script>const statusEl=document.getElementById('status');window.events=[];platform.addEventListener('input',()=>events.push('input'));platform.addEventListener('change',()=>{events.push('change');statusEl.textContent='Selected '+platform.value+'; events '+events.join(',')});multi.addEventListener('change',()=>statusEl.textContent='Multiple '+Array.from(multi.options).map(o=>o.selected).join(','));</script>"#;

struct Page {
    address: std::net::SocketAddr,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Page {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = stopped.clone();
        let worker = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let _ = stream.read(&mut [0; 4096]);
                let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", HTML.len(), HTML);
            }
        });
        Self {
            address,
            stopped,
            worker: Some(worker),
        }
    }
    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

struct Process {
    driver: CdpNavigationDriver<TracePipe>,
    child: Option<cerebellum_macos::ReleasedChild>,
    profile: std::path::PathBuf,
}
impl Process {
    fn new() -> Self {
        let profile = std::path::PathBuf::from(format!(
            "/tmp/cerebellum-native-select-{}",
            std::process::id()
        ));
        std::fs::create_dir(&profile).unwrap();
        let (child_commands, writer) = UnixStream::pair().unwrap();
        let (reader, child_responses) = UnixStream::pair().unwrap();
        let child = crate::test_browser::spawn_barred(
            std::path::Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            &[
                "--headless=new".into(),
                "--disable-gpu".into(),
                "--no-startup-window".into(),
                "--disable-blink-features=AutomationControlled".into(),
                "--remote-debugging-pipe".into(),
                "--no-first-run".into(),
                "--no-default-browser-check".into(),
                format!("--user-data-dir={}", profile.display()).into(),
            ],
            &[],
            child_commands.as_raw_fd(),
            child_responses.as_raw_fd(),
        )
        .unwrap()
        .release()
        .unwrap();
        drop(child_commands);
        drop(child_responses);
        Self {
            driver: CdpNavigationDriver::new(
                TracePipe(UnixCdpPipe::new(writer, reader).unwrap()),
                CdpTransport::new(),
                CdpFrameDecoder::default(),
            ),
            child: Some(child),
            profile,
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            let _ = child.terminate_and_reap();
        }
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}
impl OwnedBrowserProcess for Process {
    fn enable_connection_service(&mut self) {
        self.driver.enable_connection_service();
    }
    fn connection_quiet_epoch(&self) -> u64 {
        self.driver.connection_quiet_epoch()
    }
    fn connection_readiness(&self) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
        self.driver.connection_readiness()
    }
    fn service_connection(&mut self) -> Result<bool, NavigationDriveError> {
        self.driver.service_connection()
    }
    fn connection_metadata(&mut self) -> ConnectionMetadata {
        self.driver.connection_metadata()
    }
    fn main_frame_url(
        &mut self,
        context: &str,
        deadline: u64,
    ) -> Result<String, NavigationDriveError> {
        self.driver.main_frame_url(context, deadline)
    }
    fn committed_document(
        &mut self,
        context: &str,
        deadline: u64,
    ) -> Result<crate::snapshot_store::CommittedDocument, NavigationDriveError> {
        self.driver.committed_document(context, deadline)
    }
    fn navigate(
        &mut self,
        context: &str,
        url: &str,
        wait: NavigationWait,
        deadline: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.driver.navigate(context, url, wait, deadline, tracker)
    }
    fn snapshot_classified(
        &mut self,
        context: &str,
        kind: SnapshotKind,
        epoch: u64,
        origin: &str,
        deadline: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.driver
            .snapshot_classified(context, kind, epoch, origin, deadline)
    }
    fn frame_documents(
        &mut self,
        context: &str,
        deadline: u64,
    ) -> Result<Vec<crate::snapshot_store::FrameDocument>, NavigationDriveError> {
        self.driver.frame_documents(context, deadline)
    }
    fn set_read_frames(
        &mut self,
        frames: Vec<crate::snapshot_store::FrameDocument>,
    ) -> Result<(), NavigationDriveError> {
        self.driver.set_read_frames(frames);
        Ok(())
    }
    fn prepare_frame(
        &mut self,
        context: &str,
        frame: &crate::snapshot_store::FrameDocument,
        deadline: u64,
    ) -> Result<bool, NavigationDriveError> {
        self.driver.prepare_frame(context, frame, deadline)
    }
    fn click_classified(
        &mut self,
        context: &str,
        identity: &BackendNodeIdentity,
        epoch: u64,
        origin: &str,
        expected: Option<&NonTypeClassificationRecord>,
        deadline: u64,
        dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.driver.click_classified(
            context, identity, epoch, origin, expected, deadline, dispatched,
        )
    }
    fn generation_matches(&self) -> bool {
        self.child.is_some()
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        if let Some(child) = self.child.take() {
            child.terminate_and_reap().map_err(|_| {
                ProcessControlFailure::new(ProcessControlStep::GracefulCloseRequest)
            })?;
        }
        Ok(())
    }
    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(self.child.is_none())
    }
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        self.request_graceful_termination()
    }
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        self.request_graceful_termination()
    }
}
struct Cleanup;
impl SessionCleanup for Cleanup {
    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        Ok(SessionCleanupOutcome::Complete)
    }
}
struct Launcher(Mutex<Option<Process>>);
impl BrowserSessionLauncher for Launcher {
    fn launch(&self, _: &crate::AcceptedBindFacts, _: &str) -> Result<LaunchedBrowser, Value> {
        Ok(LaunchedBrowser {
            process: Box::new(self.0.lock().unwrap().take().unwrap()),
            cleanup: Box::new(Cleanup),
            executable_identity_checkpoints:
                crate::browser_launch::ExecutableIdentityCheckpoints::AfterExecOnly,
        })
    }
}

async fn call(planes: &crate::Planes, corr: &mut u64, name: &str, arguments: Value) -> Value {
    *corr += 1;
    let frame = subc_protocol::Frame::build(
        subc_protocol::FrameType::Request,
        crate::control_flags(),
        9,
        3,
        *corr,
        serde_json::to_vec(&json!({"name":name,"arguments":arguments})).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = tokio::sync::mpsc::channel(4);
    crate::handle_tool_request_for_test_with_planes(frame, &writer, planes)
        .await
        .unwrap();
    let reply = replies.recv().await.unwrap();
    serde_json::from_slice(&reply.body).unwrap()
}

async fn choose(planes: &crate::Planes, corr: &mut u64, label: &str) -> Value {
    let snapshot = call(
        planes,
        corr,
        "browser.snapshot",
        json!({"role_filter":["option"]}),
    )
    .await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let text = snapshot["state_text"].as_str().unwrap();
    let reference = text
        .lines()
        .find(|line| line.contains(&format!("option {label}")))
        .unwrap_or_else(|| panic!("missing {label}: {snapshot}"))
        .split_whitespace()
        .next()
        .unwrap();
    call(planes, corr, "browser.click", json!({"ref":reference,"snapshot_id":snapshot["snapshot_id"],"intent":"choose a loopback native option","severity":{"tier":2,"credential":false,"financial":false}})).await
}

#[tokio::test]
// Chrome 157 on macOS crashes its headless renderer (Inspector.targetCrashed)
// after Target.setAutoAttach, before Page.enable replies. Keep this opt-in until
// that installed-browser blocker is resolved; browser-wide handshake still works.
#[ignore = "installed headless Chrome renderer crashes before Page.enable"]
async fn real_chrome_closed_native_option_click_selects_and_refuses_sensitive_forms() {
    let page = Page::new();
    let mut planes = crate::Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::new()),
        Some(crate::BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 10_000,
            termination_grace_period_ms: 1_000,
            browser_idle_timeout_ms: 60_000,
            browser_exit_observation_deadline_ms: 1_000,
            navigation_settle_deadline_ms: 10_000,
        }),
        crate::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(Launcher(Mutex::new(Some(Process::new())))));
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .ok()
            .unwrap()
            .with_grants_installed(crate::authorization::GrantStore::new([
                crate::authorization::ActionGrant::new(
                    "native-select",
                    1,
                    "test-session",
                    crate::authorization::Severity::new(4, false, false),
                    [page.origin()],
                ),
            ])),
    );
    let mut corr = 0;
    let launched = call(&planes, &mut corr, "browser.launch", json!({})).await;
    assert_eq!(launched["outcome"], "launched", "{launched}");
    let navigated = call(&planes, &mut corr, "browser.navigate", json!({"url":page.origin(),"intent":"open loopback fixture","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}})).await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    let reply = choose(&planes, &mut corr, "macOS").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["value"], "mac");
    assert_eq!(reply["selectedIndex"], 1);
    let after = call(&planes, &mut corr, "browser.snapshot", json!({})).await;
    assert!(
        after["state_text"]
            .as_str()
            .unwrap()
            .contains("Selected mac; events input,change"),
        "{after}"
    );
    for expected in ["Multiple true,true", "Multiple true,false"] {
        assert_eq!(choose(&planes, &mut corr, "Second").await["outcome"], "ok");
        let after = call(&planes, &mut corr, "browser.snapshot", json!({})).await;
        assert!(
            after["state_text"].as_str().unwrap().contains(expected),
            "{after}"
        );
    }
    for label in [
        "Disabled option",
        "Disabled group",
        "Disabled select",
        "Card choice",
        "Login choice",
    ] {
        let reply = choose(&planes, &mut corr, label).await;
        assert_ne!(reply["outcome"], "ok", "{label}: {reply}");
    }
    let closed = call(
        &planes,
        &mut corr,
        "browser.close",
        json!({"browser_session_id":launched["browser_session_id"]}),
    )
    .await;
    assert_eq!(closed["outcome"], "closed", "{closed}");
}
