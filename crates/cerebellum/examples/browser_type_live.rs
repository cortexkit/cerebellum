//! Headless, loopback-only typing probe using BrowserPlane and the production
//! CDP driver. The example supplies its own process adapter and launch arguments;
//! it does not exercise ProductionProcess or ProductionLaunchService.
//!
//! `cargo run --locked -p cerebellum --example browser_type_live -- --click-fixture`
//! checks styled checkbox clicks, scrolled point classification, replaced refs,
//! and compact AX snapshots on a separate loopback form in headless Chrome.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("browser_type_live requires macOS and Google Chrome");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runs = args
        .windows(2)
        .find(|pair| pair[0] == "--runs")
        .map(|pair| pair[1].parse::<usize>())
        .transpose()
        .expect("--runs requires a positive integer")
        .unwrap_or(1);
    if runs == 0 {
        eprintln!("--runs must be positive");
        std::process::exit(1);
    }
    let navigate_only = args.iter().any(|arg| arg == "--navigate-only");
    let headed = args.iter().any(|arg| arg == "--headed");
    let click_fixture = args.iter().any(|arg| arg == "--click-fixture");
    let mut outcomes = std::collections::BTreeMap::new();
    let mut failures = 0;
    for index in 1..=runs {
        let no_settle = args.iter().any(|arg| arg == "--no-settle")
            || (args.iter().any(|arg| arg == "--alternate-no-settle") && index % 2 == 0);
        println!(
            "Cold run {index}/{runs}; navigate wait={}",
            if no_settle { "none" } else { "settle" }
        );
        if let Err(error) = probe::run(
            no_settle,
            navigate_only,
            headed,
            click_fixture,
            &mut outcomes,
        )
        .await
        {
            eprintln!("FAIL: {error}");
            failures += 1;
        }
    }
    println!("NAVIGATE OUTCOMES: {outcomes:?}");
    println!("COLD RUN SUMMARY: {runs} runs, {failures} failed");
    if failures != 0 {
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
mod probe {
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use cerebellum::authorization::{ActionGrant, GrantStore, Severity};
    use cerebellum::browser::navigation::{BrowserSnapshotObservation, CdpNavigationDriver};
    use cerebellum::browser::{BrowserPlane, Tracker};
    use cerebellum::browser_launch::ExecutableIdentityCheckpoints;
    use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
    use cerebellum::browser_session::{
        BrowserClickOutcome, BrowserInputEvent, BrowserSessionLauncher, CleanupStage,
        ClickDriveError, LaunchedBrowser, NavigationDriveError, NavigationWait,
        OwnedBrowserProcess, ProcessControlFailure, SessionCleanup, SessionCleanupOutcome,
    };
    use cerebellum::browser_type::{BrowserTypeResult, TypeDispatch};
    use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
    use cerebellum::classification::NonTypeClassificationRecord;
    use cerebellum::snapshot_store::{
        BackendNodeIdentity, CommittedDocument, FrameDocument, SnapshotKind,
    };
    use cerebellum::{BrowserConfig, JournalPersistence, Planes};
    use cerebellum_core::health::HealthState;
    use cerebellum_core::identity::AcceptedBindFacts;
    use cerebellum_macos::ReleasedChild;
    use serde_json::{json, Value};
    use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
    use tokio::sync::mpsc;

    mod click_fixture {
        include!("support/browser_click_fixture.rs");
    }

    const TOP: &str = r#"<!doctype html><meta charset="utf-8"><title>Typing probe</title>
<label>Plain<input id="plain" aria-label="Probe plain" value="existing"></label>
<label>Textarea<textarea id="area" aria-label="Probe textarea">existing</textarea></label>
<div id="editable" role="textbox" aria-label="Probe editable" contenteditable="true" style="border:1px solid;width:250px;min-height:30px">existing</div>
<label>Password<input id="password" aria-label="Probe password" type="password"></label>
<label>Card<input id="card" aria-label="Probe card" autocomplete="cc-number"></label>
<iframe id="frame" title="Probe iframe" src="/frame"></iframe>
<script>window.focusLog=[]; for (const id of ['plain','area','editable']) document.getElementById(id).addEventListener('focus', function() { if (typeof this.setSelectionRange === 'function') this.setSelectionRange(0,0); else { const range=document.createRange(); range.selectNodeContents(this); range.collapse(true); const selection=getSelection(); selection.removeAllRanges(); selection.addRange(range); } focusLog.push({id,hasFocus:document.hasFocus(),start:this.selectionStart}); });</script>"#;
    const CHILD: &str =
        r#"<!doctype html><meta charset="utf-8"><input id="child" aria-label="Probe frame">"#;
    const NON_ASCII: &str = "café 🦀";

    struct Page {
        address: std::net::SocketAddr,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl Page {
        fn start() -> Result<Self, String> {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            let address = listener.local_addr().map_err(|e| e.to_string())?;
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            let worker = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(mut stream) = stream else {
                        break;
                    };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut request = [0u8; 4096];
                    let count = stream.read(&mut request).unwrap_or(0);
                    let request = String::from_utf8_lossy(&request[..count]);
                    let body = if request.starts_with("GET /frame ") {
                        CHILD
                    } else if request.starts_with("GET /click ") {
                        click_fixture::HTML
                    } else if request.starts_with("GET /away ") {
                        "<!doctype html><title>Away</title><p>Another document</p>"
                    } else {
                        TOP
                    };
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Ok(Self {
                address,
                stop,
                worker: Some(worker),
            })
        }
        fn origin(&self) -> String {
            format!("http://{}", self.address)
        }
    }
    impl Drop for Page {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Result<Self, String> {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos();
            let path = PathBuf::from(format!(
                "/tmp/ck-browser-type-live-{}-{nonce}",
                std::process::id()
            ));
            cerebellum_core::private_fs::create_dir(&path).map_err(|e| e.to_string())?;
            Ok(Self(path))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct PipeState {
        writer: UnixStream,
        reader: UnixStream,
        observed: Vec<u8>,
        main_session: Option<String>,
        next_probe_id: u64,
        queued: std::collections::VecDeque<u8>,
        trace: std::collections::HashMap<u64, Value>,
        history: Vec<(Value, Value)>,
    }
    #[derive(Clone)]
    struct Pipe(Arc<Mutex<PipeState>>);
    impl CdpPipeIo for Pipe {
        fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            let mut state = self.0.lock().unwrap();
            let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
            let mut command = command;
            if command["method"] == "Input.insertText" {
                command["params"]["text"] = json!("<redacted>");
            }
            state.trace.insert(command["id"].as_u64().unwrap(), command);
            state.writer.write_all(bytes)
        }
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<PipeRead> {
            let mut state = self.0.lock().unwrap();
            let read = if state.queued.is_empty() {
                state.reader.read(bytes)
            } else {
                let count = bytes.len().min(state.queued.len());
                for byte in &mut bytes[..count] {
                    *byte = state.queued.pop_front().unwrap();
                }
                Ok(count)
            };
            match read {
                Ok(0) => Ok(PipeRead::Closed),
                Ok(count) => {
                    state.observed.extend_from_slice(&bytes[..count]);
                    while let Some(end) = state.observed.iter().position(|byte| *byte == 0) {
                        let frame: Vec<u8> = state.observed.drain(..=end).collect();
                        if let Ok(response) = serde_json::from_slice::<Value>(&frame[..end]) {
                            if let Some(command) = response["id"]
                                .as_u64()
                                .and_then(|id| state.trace.remove(&id))
                            {
                                state.history.push((command, response.clone()));
                            }
                            if state.main_session.is_none() {
                                state.main_session = response
                                    .pointer("/result/sessionId")
                                    .and_then(Value::as_str)
                                    .map(str::to_string);
                            }
                        }
                    }
                    Ok(PipeRead::Bytes(count))
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    Ok(PipeRead::WouldBlock)
                }
                Err(error) => Err(error),
            }
        }
    }
    impl Pipe {
        // Called only after a plane request completes. This client and the driver
        // never read the pipe concurrently; probe command ids use a separate range.
        fn evaluate(&self, expression: &str) -> Result<Value, String> {
            self.command(
                "Runtime.evaluate",
                json!({"expression":expression,"returnByValue":true}),
            )?
            .pointer("/result/result/value")
            .cloned()
            .ok_or_else(|| "Runtime.evaluate returned no value".into())
        }
        fn command(&self, method: &str, params: Value) -> Result<Value, String> {
            let mut state = self.0.lock().map_err(|_| "pipe poisoned")?;
            let session = state
                .main_session
                .clone()
                .ok_or("no attached main-frame session")?;
            let id = state.next_probe_id;
            state.next_probe_id += 1;
            let mut command = serde_json::to_vec(
                &json!({"id":id,"sessionId":session,"method":method,"params":params}),
            )
            .map_err(|e| e.to_string())?;
            command.push(0);
            state
                .writer
                .write_all(&command)
                .map_err(|e| e.to_string())?;
            state
                .reader
                .set_nonblocking(false)
                .map_err(|e| e.to_string())?;
            let result = (|| {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut buffer = state.observed.clone();
                let mut prefix_already_delivered = buffer.len();
                loop {
                    while let Some(end) = buffer.iter().position(|byte| *byte == 0) {
                        let frame: Vec<u8> = buffer.drain(..=end).collect();
                        let message: Value =
                            serde_json::from_slice(&frame[..end]).map_err(|e| e.to_string())?;
                        if message["id"].as_u64() == Some(id) {
                            state.queued.extend(buffer.drain(..));
                            return Ok(message);
                        }
                        // Keep late driver responses and events for its transport,
                        // including the suffix of a frame it already partially read.
                        state.queued.extend(&frame[prefix_already_delivered..]);
                        prefix_already_delivered = 0;
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err("readback timed out".into());
                    }
                    state
                        .reader
                        .set_read_timeout(Some(remaining))
                        .map_err(|e| e.to_string())?;
                    let mut chunk = [0u8; 65536];
                    let count = state.reader.read(&mut chunk).map_err(|e| e.to_string())?;
                    if count == 0 {
                        return Err("Chrome closed the readback pipe".into());
                    }
                    buffer.extend_from_slice(&chunk[..count]);
                }
            })();
            state
                .reader
                .set_nonblocking(true)
                .map_err(|e| e.to_string())?;
            result
        }
    }

    struct LiveProcess {
        driver: CdpNavigationDriver<Pipe>,
        child: Option<ReleasedChild>,
    }
    impl OwnedBrowserProcess for LiveProcess {
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
        ) -> Result<CommittedDocument, NavigationDriveError> {
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
        fn snapshot(
            &mut self,
            context: &str,
            mode: SnapshotKind,
            deadline: u64,
        ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
            self.driver.snapshot(context, mode, deadline)
        }
        fn snapshot_classified(
            &mut self,
            context: &str,
            mode: SnapshotKind,
            epoch: u64,
            origin: &str,
            deadline: u64,
        ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
            self.driver
                .snapshot_classified(context, mode, epoch, origin, deadline)
        }
        fn frame_documents(
            &mut self,
            context: &str,
            deadline: u64,
        ) -> Result<Vec<FrameDocument>, NavigationDriveError> {
            self.driver.frame_documents(context, deadline)
        }
        fn set_read_frames(
            &mut self,
            frames: Vec<FrameDocument>,
        ) -> Result<(), NavigationDriveError> {
            self.driver.set_read_frames(frames);
            Ok(())
        }
        fn prepare_frame(
            &mut self,
            context: &str,
            frame: &FrameDocument,
            deadline: u64,
        ) -> Result<bool, NavigationDriveError> {
            self.driver.prepare_frame(context, frame, deadline)
        }
        #[allow(clippy::too_many_arguments)]
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
        fn screenshot(
            &mut self,
            context: &str,
            epoch: u64,
            deadline: u64,
            full: bool,
        ) -> Result<
            cerebellum::browser::navigation::BrowserScreenshotObservation,
            NavigationDriveError,
        > {
            self.driver.screenshot(context, epoch, deadline, full)
        }
        fn point_frame_document(&mut self) -> Option<FrameDocument> {
            self.driver.point_frame_document()
        }
        fn classify_point(
            &mut self,
            context: &str,
            position: cerebellum::browser_session::BrowserClickPosition,
            epoch: u64,
            origin: &str,
            deadline: u64,
        ) -> Result<
            Result<
                NonTypeClassificationRecord,
                cerebellum::classification::ClassificationUnavailable,
            >,
            NavigationDriveError,
        > {
            self.driver
                .classify_point(context, position, epoch, origin, deadline)
        }
        #[allow(clippy::too_many_arguments)]
        fn click_point_classified(
            &mut self,
            context: &str,
            position: cerebellum::browser_session::BrowserClickPosition,
            epoch: u64,
            origin: &str,
            expected: &NonTypeClassificationRecord,
            deadline: u64,
            dispatched: &mut dyn FnMut(BrowserInputEvent),
        ) -> Result<BrowserClickOutcome, ClickDriveError> {
            self.driver.click_point_classified(
                context, position, epoch, origin, expected, deadline, dispatched,
            )
        }
        fn type_classified(
            &mut self,
            context: &str,
            target: &TypeDispatch,
            text: &str,
            clear_first: bool,
            deadline: u64,
        ) -> Result<BrowserTypeResult, NavigationDriveError> {
            self.driver
                .type_classified(context, target, text, clear_first, deadline)
        }
        fn generation_matches(&self) -> bool {
            self.child.is_some()
        }
        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            if let Some(child) = self.child.take() {
                child
                    .terminate_and_reap()
                    .map_err(|_| ProcessControlFailure)?;
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
    struct Launcher {
        ready: Mutex<Option<LiveProcess>>,
    }
    impl BrowserSessionLauncher for Launcher {
        fn launch(&self, _: &AcceptedBindFacts, _: &str) -> Result<LaunchedBrowser, Value> {
            let process = self
                .ready
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| json!({"outcome":"internal_error"}))?;
            Ok(LaunchedBrowser {
                process: Box::new(process),
                cleanup: Box::new(Cleanup),
                executable_identity_checkpoints: ExecutableIdentityCheckpoints::AfterExecOnly,
            })
        }
    }

    async fn invoke(
        planes: &Planes,
        corr: &mut u64,
        name: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        *corr += 1;
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            9,
            3,
            *corr,
            serde_json::to_vec(&json!({"name":name,"arguments":arguments}))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let (tx, mut rx) = mpsc::channel(4);
        cerebellum::handle_tool_request_for_test_with_planes(frame, &tx, planes)
            .await
            .map_err(|e| e.to_string())?;
        let reply = rx.recv().await.ok_or("no wire reply")?;
        serde_json::from_slice(&reply.body).map_err(|e| e.to_string())
    }
    fn check_ok(reply: &Value) -> Result<(), String> {
        check_outcome(reply, "ok")
    }
    fn check_outcome(reply: &Value, expected: &str) -> Result<(), String> {
        if reply["outcome"] == expected {
            Ok(())
        } else {
            Err(format!("plane refused: {reply}"))
        }
    }
    fn reference(snapshot: &Value, label: &str) -> Result<String, String> {
        let text = snapshot["state_text"]
            .as_str()
            .ok_or("snapshot missing state_text")?;
        text.lines()
            .filter(|line| line.contains(label))
            .find_map(|line| {
                if let Ok(row) = serde_json::from_str::<Value>(line) {
                    return row["ref"].as_str().map(str::to_string);
                }
                line.split_whitespace()
                    .next()
                    .filter(|word| {
                        word.starts_with('e') && word[1..].chars().all(|c| c.is_ascii_digit())
                    })
                    .map(str::to_string)
            })
            .ok_or_else(|| format!("no ref for {label}: {text}"))
    }
    fn table_row(name: &str, passed: bool, actual: &Value) -> bool {
        println!(
            "{:<28} | {:<4} | {}",
            name,
            if passed { "PASS" } else { "FAIL" },
            actual
        );
        passed
    }

    async fn exercise(
        planes: &Planes,
        pipe: &Pipe,
        origin: &str,
        no_settle: bool,
        navigate_only: bool,
        outcomes: &mut std::collections::BTreeMap<String, usize>,
    ) -> Result<(), String> {
        let mut corr = 0;
        let launched = invoke(planes, &mut corr, "browser.launch", json!({})).await?;
        check_outcome(&launched, "launched")?;
        let result = async {
            let navigated = invoke(planes, &mut corr, "browser.navigate", json!({"url":format!("{origin}/"),"intent":"open isolated typing fixture","wait":if no_settle { "none" } else { "settle" },"severity":{"tier":1,"credential":false,"financial":false}})).await?;
            *outcomes.entry(navigated["outcome"].as_str().unwrap_or("missing").to_string()).or_default() += 1;
            println!("NAVIGATE REPLY: {navigated}");
            check_ok(&navigated)?;
            if navigate_only { return Ok(()); }
            let version = pipe.evaluate("navigator.userAgent")?;
            println!("Chrome: {version}");
            let snapshot = invoke(planes, &mut corr, "browser.snapshot", json!({"mode":"ax"})).await?;
            check_ok(&snapshot)?;
            let mut passed = true;
            println!("Page focus before type: {}", pipe.evaluate("document.hasFocus()")?);
            println!("CHECK                        | RESULT | ACTUAL");
            for (name, label, expression, text, clear_first, expected) in [
                ("plain non-ASCII", "Probe plain", "document.getElementById('plain').value", NON_ASCII, false, "existingcafé 🦀"),
                ("textarea initial append", "Probe textarea", "document.getElementById('area').value", " + initial", false, "existing + initial"),
                ("textarea clear_first", "Probe textarea", "document.getElementById('area').value", "replacement", true, "replacement"),
                ("textarea append", "Probe textarea", "document.getElementById('area').value", " + appended", false, "replacement + appended"),
                ("contenteditable", "Probe editable", "document.getElementById('editable').textContent", NON_ASCII, false, "existingcafé 🦀"),
                ("same-origin iframe", "Probe frame", "document.getElementById('frame').contentDocument.getElementById('child').value", "frame text", false, "frame text"),
            ] {
                let reference = reference(&snapshot, label)?;
                let typed = invoke(planes, &mut corr, "browser.type", json!({"ref":reference,"text":text,"clear_first":clear_first})).await?;
                let value = pipe.evaluate(expression)?;
                if name == "plain non-ASCII" { println!("Focus event evidence: {}", pipe.evaluate("focusLog")?); }
                passed &= table_row(name, typed["outcome"] == "ok" && value == expected, &json!({"value":value,"reply":typed}));
            }
            for (name, label, id) in [("password refusal", "Probe password", "password"), ("cc-number refusal", "Probe card", "card")] {
                let reference = reference(&snapshot, label)?;
                let typed = invoke(planes, &mut corr, "browser.type", json!({"ref":reference,"text":"must-not-enter"})).await?;
                let value = pipe.evaluate(&format!("document.getElementById('{id}').value"))?;
                passed &= table_row(name, typed.pointer("/detail/reason_code") == Some(&json!("credential_input_unsupported")) && value == "", &json!({"value":value,"reply":typed}));
            }
            let away = invoke(planes, &mut corr, "browser.navigate", json!({"url":format!("{origin}/away"),"intent":"invalidate fixture refs","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}})).await?;
            check_ok(&away)?;
            let stale = invoke(planes, &mut corr, "browser.type", json!({"ref":reference(&snapshot,"Probe plain")?,"text":"stale"})).await?;
            passed &= table_row("stale after navigation", stale["outcome"] == "stale_snapshot", &stale);
            if passed { Ok(()) } else { Err("one or more live typing checks failed".into()) }
        }.await;
        let closed = invoke(
            planes,
            &mut corr,
            "browser.close",
            json!({"browser_session_id":launched["browser_session_id"]}),
        )
        .await?;
        check_outcome(&closed, "closed")?;
        result
    }

    pub async fn run(
        no_settle: bool,
        navigate_only: bool,
        headed: bool,
        click_fixture: bool,
        outcomes: &mut std::collections::BTreeMap<String, usize>,
    ) -> Result<(), String> {
        let page = Page::start()?;
        let scratch = Scratch::new()?;
        let chrome = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        if !chrome.is_file() {
            return Err("Google Chrome is not installed".into());
        }
        // Headed mode launches the way production does: no startup window, so
        // the only window is the background page the driver creates. It shows
        // whether typing ever brings Chrome in front of the person's work.
        let first_arg = if headed {
            "--no-startup-window"
        } else {
            "--headless=new"
        };
        let args: Vec<OsString> = [
            first_arg.to_string(),
            "--remote-debugging-pipe".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-background-networking".into(),
            format!("--user-data-dir={}", scratch.0.display()),
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let (child_commands, writer) = UnixStream::pair().map_err(|e| e.to_string())?;
        let (reader, child_responses) = UnixStream::pair().map_err(|e| e.to_string())?;
        let child = cerebellum_macos::spawn_barred(
            &chrome,
            &args,
            &[],
            child_commands.as_raw_fd(),
            child_responses.as_raw_fd(),
        )
        .map_err(|e| format!("headless spawn failed: {e:?}"))?
        .release()
        .map_err(|e| format!("release failed: {e:?}"))?;
        drop(child_commands);
        drop(child_responses);
        reader.set_nonblocking(true).map_err(|e| e.to_string())?;
        let pipe = Pipe(Arc::new(Mutex::new(PipeState {
            writer,
            reader,
            observed: Vec::new(),
            main_session: None,
            next_probe_id: 1_000_000_000,
            queued: Default::default(),
            trace: Default::default(),
            history: Vec::new(),
        })));
        let config = BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 10_000,
            termination_grace_period_ms: 1_000,
            browser_idle_timeout_ms: 60_000,
            browser_exit_observation_deadline_ms: 1_000,
            navigation_settle_deadline_ms: 10_000,
        };
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config),
            JournalPersistence::Isolated,
        );
        planes.launch_service = Some(Arc::new(Launcher {
            ready: Mutex::new(Some(LiveProcess {
                driver: CdpNavigationDriver::new(
                    pipe.clone(),
                    CdpTransport::new(),
                    CdpFrameDecoder::default(),
                ),
                child: Some(child),
            })),
        }));
        planes.browser = Arc::new(
            BrowserPlane::with_session_gate(
                planes.sessions.clone(),
                planes.lease_clock.clone(),
                10_000,
            )
            .with_result_schema_enforcement(
                cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
            )
            .with_in_memory_journal(cerebellum::journal::JournalConfig {
                journal_retention_bytes: 1_048_576,
                journal_max_entry_bytes: 65_536,
            })
            .with_grants_installed(GrantStore::new([ActionGrant::new(
                "live-probe",
                1,
                "test-session",
                Severity::new(4, false, false),
                [page.origin()],
            )])),
        );
        let focus = headed.then(|| FocusWatch::start(scratch.0.clone()));
        let result = if click_fixture {
            click_fixture::exercise(&planes, &pipe, &page.origin()).await
        } else {
            exercise(
                &planes,
                &pipe,
                &page.origin(),
                no_settle,
                navigate_only,
                outcomes,
            )
            .await
        };
        let result = match (result, focus.map(FocusWatch::finish)) {
            (Ok(()), Some(Err(focus))) => Err(focus),
            (result, Some(Ok(report))) => {
                println!("{report}");
                result
            }
            (result, _) => result,
        };
        if result.is_err() {
            for command in pipe.0.lock().unwrap().trace.values() {
                eprintln!("CDP TRACE NO RESPONSE {command}");
            }
            for (command, response) in &pipe.0.lock().unwrap().history {
                if response.get("error").is_some()
                    || matches!(
                        command["method"].as_str(),
                        Some(
                            "DOM.enable"
                                | "Accessibility.getChildAXNodes"
                                | "DOM.getFlattenedDocument"
                                | "DOM.getNodeForLocation"
                                | "DOM.getContentQuads"
                                | "DOM.scrollIntoViewIfNeeded"
                                | "Runtime.enable"
                                | "Network.enable"
                                | "Page.getFrameTree"
                                | "DOM.focus"
                                | "DOM.resolveNode"
                                | "Runtime.callFunctionOn"
                                | "Input.dispatchKeyEvent"
                                | "Input.insertText"
                        )
                    )
                {
                    eprintln!("CDP TRACE COMMAND {command}\nCDP TRACE RESPONSE {response}");
                }
            }
        }
        drop(planes);
        drop(pipe);
        let profile = scratch.0.clone();
        drop(scratch);
        if profile.exists() {
            return Err("throwaway profile cleanup failed".into());
        }
        println!("Profile cleanup              | PASS | throwaway /tmp profile deleted");
        result
    }

    /// Watches, while a headed run types, whether Chrome ever comes in front
    /// of the person's work: the owner of the topmost normal window every
    /// 100 ms, and the active application every 500 ms. It only reads; it never
    /// activates, clicks or types anything.
    struct FocusWatch {
        stop: Arc<AtomicBool>,
        thread: std::thread::JoinHandle<FocusSamples>,
    }

    #[derive(Default)]
    struct FocusSamples {
        samples: usize,
        chrome_pids: std::collections::BTreeSet<i32>,
        topmost: std::collections::BTreeMap<i32, usize>,
        active: std::collections::BTreeMap<i32, usize>,
    }

    impl FocusWatch {
        fn start(profile: PathBuf) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let thread = std::thread::spawn(move || {
                let mut seen = FocusSamples::default();
                let mut tick = 0usize;
                while !flag.load(Ordering::SeqCst) {
                    if let Some(pid) = cerebellum_macos::frontmost_process_id() {
                        *seen.topmost.entry(pid).or_default() += 1;
                    }
                    if tick.is_multiple_of(5) {
                        if let Some(pid) = active_application_pid() {
                            *seen.active.entry(pid).or_default() += 1;
                        }
                        seen.chrome_pids.extend(pids_naming(&profile));
                    }
                    seen.samples += 1;
                    tick += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                seen
            });
            Self { stop, thread }
        }

        fn finish(self) -> Result<String, String> {
            self.stop.store(true, Ordering::SeqCst);
            let seen = self.thread.join().map_err(|_| "focus watch panicked")?;
            let report = format!(
                "FOCUS: {} samples; Chrome pids {:?}; topmost normal-window owners {:?}; active apps {:?}",
                seen.samples, seen.chrome_pids, seen.topmost, seen.active
            );
            if seen.chrome_pids.is_empty() {
                return Err(format!(
                    "{report}; no Chrome process was seen, so the watch proves nothing"
                ));
            }
            let fronted = seen
                .chrome_pids
                .iter()
                .any(|pid| seen.topmost.contains_key(pid) || seen.active.contains_key(pid));
            if fronted {
                Err(format!("{report}; CHROME CAME TO THE FRONT"))
            } else {
                Ok(format!("{report}; Chrome stayed behind"))
            }
        }
    }

    fn active_application_pid() -> Option<i32> {
        let asn = std::process::Command::new("/usr/bin/lsappinfo")
            .arg("front")
            .output()
            .ok()?;
        let asn = String::from_utf8_lossy(&asn.stdout).trim().to_string();
        let info = std::process::Command::new("/usr/bin/lsappinfo")
            .args(["info", "-only", "pid", &asn])
            .output()
            .ok()?;
        // `lsappinfo info` prints a block whose pid appears as `pid = N`;
        // take the number after the first `pid` key rather than the last `=`.
        let text = String::from_utf8_lossy(&info.stdout).to_string();
        let after = text.split("pid").nth(1)?;
        after
            .trim_start_matches([' ', '=', '"'])
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    }

    fn pids_naming(profile: &std::path::Path) -> Vec<i32> {
        std::process::Command::new("/usr/bin/pgrep")
            .args(["-f", &profile.display().to_string()])
            .output()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|line| line.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}
