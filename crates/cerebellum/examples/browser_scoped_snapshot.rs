//! Headless, isolated, loopback-only snapshot probe with a disposable profile.
//! Run on macOS: `CK_PROBE_REQUIRE=1 cargo run --locked -p cerebellum --example browser_scoped_snapshot`.
//! `CK_CHROME` selects Chrome; `CK_PROBE_LABEL` labels archived comparison runs.
//! `CK_PROBE_SCOPED_ONLY=1` injects only the native-read refusal; scoped CDP
//! commands still execute in Chrome. `CK_PROBE_BASELINE` names an old probe log
//! for side-by-side timings (native path limit: 1.3x old time plus 20ms).

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = probe::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("This manual probe uses the macOS CDP process barrier.");
}

#[cfg(target_os = "macos")]
mod probe {
    use cerebellum::browser::navigation::{BrowserSnapshotObservation, CdpNavigationDriver};
    use cerebellum::browser::state_text::{self, Filters, RenderInput, Zoom};
    use cerebellum::browser::Tracker;
    use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
    use cerebellum::browser_session::NavigationWait;
    use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
    use cerebellum::snapshot_store::{RefRecord, SnapshotKind};
    use serde_json::Value;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::ffi::OsString;
    use std::io::{self, Read, Write};
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Instant;

    const DEADLINE: u64 = 8_000;
    const CONTEXT: &str = "scoped-probe";

    struct Pipe {
        commands: UnixStream,
        responses: UnixStream,
        pending: HashMap<u64, (String, Instant)>,
        buffer: Vec<u8>,
        errors: BTreeMap<String, usize>,
        reject_flatten: Arc<AtomicBool>,
        injected: VecDeque<u8>,
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            for (method, started) in self.pending.values() {
                println!(
                    "CDP_UNANSWERED {method} elapsed_ms={}",
                    started.elapsed().as_millis()
                );
            }
        }
    }

    impl CdpPipeIo for Pipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            if let Ok(v) =
                serde_json::from_slice::<Value>(bytes.strip_suffix(&[0]).unwrap_or(bytes))
            {
                if let (Some(id), Some(method)) = (v["id"].as_u64(), v["method"].as_str()) {
                    if method == "DOM.getFlattenedDocument"
                        && self.reject_flatten.load(Ordering::SeqCst)
                    {
                        let mut reply = serde_json::to_vec(&serde_json::json!({"id":id,"sessionId":v["sessionId"],"error":{"code":-32000,"message":"probe: force scoped fallback"}})).unwrap();
                        reply.push(0);
                        self.injected.extend(reply);
                        return Ok(());
                    }
                    self.pending.insert(id, (method.into(), Instant::now()));
                }
            }
            self.commands.write_all(bytes)
        }
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<PipeRead> {
            if !self.injected.is_empty() {
                let n = bytes.len().min(self.injected.len());
                for byte in &mut bytes[..n] {
                    *byte = self.injected.pop_front().unwrap();
                }
                return Ok(PipeRead::Bytes(n));
            }
            match self.responses.read(bytes) {
                Ok(0) => Ok(PipeRead::Closed),
                Ok(n) => {
                    self.buffer.extend_from_slice(&bytes[..n]);
                    while let Some(end) = self.buffer.iter().position(|b| *b == 0) {
                        let frame: Vec<_> = self.buffer.drain(..=end).collect();
                        if let Ok(v) = serde_json::from_slice::<Value>(&frame[..end]) {
                            if let Some((method, started)) =
                                v["id"].as_u64().and_then(|id| self.pending.remove(&id))
                            {
                                if std::env::var_os("CK_PROBE_TRACE").is_some()
                                    && [
                                        "Accessibility.queryAXTree",
                                        "Accessibility.getPartialAXTree",
                                        "Page.createIsolatedWorld",
                                    ]
                                    .contains(&method.as_str())
                                {
                                    println!(
                                        "CDP_REPLY {method} {}",
                                        v.to_string().chars().take(3000).collect::<String>()
                                    );
                                }
                                if std::env::var_os("CK_PROBE_TRACE").is_some()
                                    && method == "DOM.describeNode"
                                    && v["result"]["node"].get("shadowRoots").is_some()
                                {
                                    println!("CDP_SHADOW {}", v["result"]["node"]);
                                }
                                if let Ok(path) = std::env::var("CK_PROBE_FLAT_WIRE") {
                                    if method == "DOM.getFlattenedDocument" {
                                        let _ = std::fs::write(
                                            path,
                                            serde_json::to_vec_pretty(&v).unwrap(),
                                        );
                                    }
                                }
                                let error = v
                                    .get("error")
                                    .or_else(|| v["result"].get("exceptionDetails"));
                                if let Some(error) = error {
                                    let key = format!(
                                        "{method}: {}",
                                        error["exception"]["description"].as_str().unwrap_or_else(
                                            || error["message"].as_str().unwrap_or("unknown")
                                        )
                                    );
                                    let count = self.errors.entry(key.clone()).or_default();
                                    *count += 1;
                                    if *count == 1 {
                                        println!(
                                            "CDP_ERROR {key} elapsed_ms={}",
                                            started.elapsed().as_millis()
                                        );
                                    }
                                }
                                if std::env::var_os("CK_PROBE_TRACE").is_some()
                                    && started.elapsed().as_millis() > 50
                                {
                                    println!(
                                        "CDP_SLOW {method} elapsed_ms={} reply_bytes={end}",
                                        started.elapsed().as_millis()
                                    );
                                }
                            }
                        }
                    }
                    Ok(PipeRead::Bytes(n))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PipeRead::WouldBlock),
                Err(error) => Err(error),
            }
        }
    }

    fn fixtures(other: u16) -> BTreeMap<String, String> {
        let wrap = |body: String| {
            format!("<!doctype html><html><head><title>Snapshot fixture</title></head><body>{body}</body></html>")
        };
        let results = (0..30).map(|n| format!("<article><a href='https://example.org/{n}'>Result {n}</a><p>comment {n} result payload</p></article>")).collect::<String>();
        let comments = (0..50).map(|n| format!("<article><h2><a href='/thread/{n}'>Thread {n}</a></h2><p>comment {n} discussion payload</p><form><button name='vote' value='up'>Upvote {n}</button><button name='vote' value='down'>Downvote {n}</button></form></article>")).collect::<String>();
        let rows = (0..300).map(|n| format!("<tr><td>Country {n}</td><td>comment population {n}</td><td><button>Details {n}</button></td></tr>")).collect::<String>();
        let fields = (0..80).map(|n| format!("<div><label for='field{n}'>Ordinary field {n}</label><input id='field{n}' name='field{n}'></div>")).collect::<String>();
        BTreeMap::from([
            ("reddit".into(), wrap(format!("<nav><a href='/'>Home</a></nav><main aria-label='Probe main'>{comments}<p>END reddit</p></main>"))),
            ("results".into(), wrap(format!("<main aria-label='Probe main'>{results}<p>END results</p></main>"))),
            ("table".into(), wrap(format!("<main aria-label='Probe main'><table>{rows}</table><p>END table</p></main>"))),
            ("form".into(), wrap(format!("<form id='big' action='https://example.org/save'><main aria-label='Probe main'>{fields}<p>comment END form</p><button>Save</button></main></form>"))),
            ("shadow".into(), wrap("<main aria-label='Probe main'><div id='host'></div><p>END shadow</p></main><script>host.attachShadow({mode:'open'}).innerHTML='<section><button>Shadow button</button><p>comment shadow payload</p></section>'</script>".into())),
            ("same-frame".into(), wrap("<main aria-label='Probe main'><p>comment parent</p><iframe title='Same origin' src='/child'></iframe><p>END same-frame</p></main>".into())),
            ("cross-frame".into(), wrap(format!("<main aria-label='Probe main'><p>comment parent</p><iframe title='Other origin' src='http://localhost:{other}/child'></iframe><p>END cross-frame</p></main>"))),
            ("child".into(), wrap("<main aria-label='Child main'><button>Child button</button><p>comment child payload</p></main>".into())),
        ])
    }

    fn serve(listener: TcpListener, pages: BTreeMap<String, String>) {
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]);
                let path = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .trim_start_matches('/');
                let page = pages.get(path).map(String::as_str).unwrap_or("not found");
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}", page.len());
                let _ = stream.write_all(response.as_bytes());
            }
        });
    }

    pub fn run() -> Result<(), String> {
        let main = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let child = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = main.local_addr().unwrap().port();
        let pages = fixtures(child.local_addr().unwrap().port());
        serve(main, pages.clone());
        serve(child, pages);
        let profile =
            PathBuf::from("target/scratch").join(format!("scoped-chrome-{}", std::process::id()));
        std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
        let profile = std::fs::canonicalize(profile).map_err(|e| e.to_string())?;
        let chrome = std::env::var_os("CK_CHROME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            });
        let version = std::process::Command::new(&chrome)
            .args(["--headless=new", "--no-sandbox", "--version"])
            .arg(format!("--user-data-dir={}", profile.display()))
            .output()
            .map_err(|e| e.to_string())?;
        println!(
            "browser: {} label={}",
            String::from_utf8_lossy(&version.stdout).trim(),
            std::env::var("CK_PROBE_LABEL").unwrap_or_else(|_| "scoped".into())
        );
        let args: Vec<OsString> = [
            "--headless=new".into(),
            "--no-sandbox".into(),
            "--remote-debugging-pipe".into(),
            "--disable-background-networking".into(),
            "--disable-component-update".into(),
            "--disable-sync".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            format!("--user-data-dir={}", profile.display()),
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let (child_commands, commands) = UnixStream::pair().map_err(|e| e.to_string())?;
        let (responses, child_responses) = UnixStream::pair().map_err(|e| e.to_string())?;
        let browser = cerebellum_macos::spawn_barred(
            &chrome,
            &args,
            &[],
            child_commands.as_raw_fd(),
            child_responses.as_raw_fd(),
        )
        .map_err(|e| format!("spawn: {e:?}"))?
        .release()
        .map_err(|e| format!("release: {e:?}"))?;
        drop(child_commands);
        drop(child_responses);
        responses.set_nonblocking(true).map_err(|e| e.to_string())?;
        let result = std::panic::catch_unwind(|| {
            exercise(
                Pipe {
                    commands,
                    responses,
                    pending: HashMap::new(),
                    buffer: Vec::new(),
                    errors: BTreeMap::new(),
                    reject_flatten: Arc::new(AtomicBool::new(false)),
                    injected: VecDeque::new(),
                },
                port,
            )
        })
        .unwrap_or_else(|_| Err("probe panicked".into()));
        let _ = browser.terminate_and_reap();
        let _ = std::fs::remove_dir_all(profile);
        result
    }

    fn render(
        observation: &BrowserSnapshotObservation,
        filter: bool,
        reference: Option<&RefRecord>,
        url: &str,
    ) -> String {
        let filters = Filters {
            text: filter.then(|| "comment".into()),
            ..Filters::default()
        };
        let target = reference
            .and_then(|reference| {
                observation
                    .refs
                    .iter()
                    .find(|r| r.backend_identity == reference.backend_identity)
            })
            .map(|r| r.captured.reference.as_str());
        state_text::render(&RenderInput {
            records: &observation.records,
            facts: &observation.facts,
            filters: &filters,
            page_url: url,
            snapshot_id: "0123456789abcdef0123456789abcdef",
            zoom: reference.map(|r| Zoom {
                requested: &r.captured.reference,
                target,
            }),
            max_bytes: 262144,
        })
        .text
    }

    fn exercise(pipe: Pipe, port: u16) -> Result<(), String> {
        let mut baseline = HashMap::new();
        if let Ok(path) = std::env::var("CK_PROBE_BASELINE") {
            for line in std::fs::read_to_string(path)
                .map_err(|e| e.to_string())?
                .lines()
            {
                let words = line.split_whitespace().collect::<Vec<_>>();
                if words.first() == Some(&"RESULT") {
                    if let (Some(name), Some(ms)) = (
                        words.get(1),
                        words
                            .get(2)
                            .and_then(|w| w.strip_prefix("elapsed_ms="))
                            .and_then(|ms| ms.parse::<u128>().ok()),
                    ) {
                        baseline.insert((*name).to_owned(), ms);
                    }
                }
            }
        }
        let reject_flatten = pipe.reject_flatten.clone();
        let mut driver =
            CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());
        for fixture in [
            "results",
            "reddit",
            "table",
            "form",
            "shadow",
            "same-frame",
            "cross-frame",
        ] {
            if std::env::var("CK_PROBE_FIXTURE").is_ok_and(|name| name != fixture) {
                continue;
            }
            let url = format!("http://127.0.0.1:{port}/{fixture}");
            driver
                .navigate(
                    CONTEXT,
                    &url,
                    NavigationWait::Settle,
                    30_000,
                    &mut Tracker::default(),
                )
                .map_err(|e| format!("{fixture} navigate: {e:?}"))?;
            let frames = driver
                .frame_documents(CONTEXT, DEADLINE)
                .map_err(|e| format!("frames: {e:?}"))?;
            if fixture.ends_with("frame") {
                assert_eq!(
                    frames.len(),
                    2,
                    "the iframe must finish loading before capture"
                );
                let main = frames.iter().find(|f| f.parent_id.is_none()).unwrap();
                let child = frames.iter().find(|f| f.parent_id.is_some()).unwrap();
                assert_eq!(
                    main.session_id == child.session_id,
                    fixture == "same-frame",
                    "cross-origin fixture must use an OOPIF session"
                );
            }
            driver.set_read_frames(frames);
            let mut main = None;
            for phase in ["full", "text_filter", "zoom"] {
                reject_flatten.store(
                    std::env::var_os("CK_PROBE_SCOPED_ONLY").is_some(),
                    Ordering::SeqCst,
                );
                let started = Instant::now();
                let observation = if phase == "zoom" {
                    driver.snapshot_subtree_classified(
                        CONTEXT,
                        SnapshotKind::Actionable,
                        main.as_ref().ok_or("main ref missing")?,
                        1,
                        &url,
                        DEADLINE,
                    )
                } else {
                    driver.snapshot_classified(CONTEXT, SnapshotKind::Actionable, 1, &url, DEADLINE)
                }
                .map_err(|e| format!("{fixture}/{phase}: {e:?}"))?;
                let elapsed = started.elapsed().as_millis();
                reject_flatten.store(false, Ordering::SeqCst);
                let parity = if std::env::var_os("CK_PROBE_REQUIRE").is_some() {
                    Some(driver.check_snapshot_classification_parity(&observation, 1, &url, 30_000))
                } else {
                    None
                };
                if phase == "full" {
                    main = observation
                        .refs
                        .iter()
                        .find(|r| r.captured.role == "main")
                        .cloned();
                }
                let text = render(
                    &observation,
                    phase == "text_filter",
                    (phase == "zoom").then_some(main.as_ref()).flatten(),
                    &url,
                );
                if std::env::var_os("CK_PROBE_REQUIRE").is_some() && phase == "zoom" {
                    assert!(
                        text.contains(&format!("END {fixture}")),
                        "{fixture} zoom content incomplete: {text}"
                    );
                    let expected = match fixture {
                        "results" => (0..30).map(|n| format!("Result {n}")).collect::<Vec<_>>(),
                        "reddit" => (0..50)
                            .flat_map(|n| {
                                [
                                    format!("Upvote {n}"),
                                    format!("Downvote {n}"),
                                    format!("Thread {n}"),
                                ]
                            })
                            .collect(),
                        "table" => (0..300)
                            .flat_map(|n| [format!("Country {n}"), format!("Details {n}")])
                            .collect(),
                        "form" => (0..80).map(|n| format!("Ordinary field {n}")).collect(),
                        "shadow" => vec!["Shadow button".into()],
                        _ => vec!["Child button".into()],
                    };
                    for name in expected {
                        assert!(
                            observation.records.iter().any(|r| r.name == name),
                            "missing captured element {name}"
                        );
                        assert!(text.contains(&name), "missing zoom content {name}");
                    }
                }
                let mut reasons = BTreeMap::new();
                let mut classified = 0;
                let mut fields_refused = 0;
                for r in &observation.refs {
                    match &r.classification {
                        Ok(_) => classified += 1,
                        Err(reason) => {
                            *reasons.entry(reason.reason_code()).or_insert(0usize) += 1;
                            if r.captured.role == "textbox" {
                                fields_refused += 1;
                            }
                        }
                    }
                }
                println!("RESULT {fixture}/{phase} elapsed_ms={elapsed} timings={:?} records={} refs={} classified={classified} refused={} fields_refused={fields_refused} reasons={reasons:?} bytes={} end_present={}", driver.last_snapshot_timings(), observation.records.len(), observation.refs.len(), observation.refs.len()-classified, text.len(), text.contains(&format!("END {fixture}")));
                if let Some(old) = baseline.get(&format!("{fixture}/{phase}")) {
                    let limit = old * 13 / 10 + 20;
                    println!("COMPARE {fixture}/{phase} old_ms={old} new_ms={elapsed} native_limit_ms={limit}");
                    if std::env::var_os("CK_PROBE_SCOPED_ONLY").is_none() {
                        assert!(
                            elapsed <= limit,
                            "normal snapshot exceeded 1.3x old time plus 20ms"
                        );
                    }
                }
                if let Some(parity) = parity {
                    println!("PARITY {fixture}/{phase} identical={}", parity?);
                }
                if std::env::var_os("CK_PROBE_REQUIRE").is_some()
                    && fixture == "form"
                    && phase == "full"
                {
                    let field = observation
                        .refs
                        .iter()
                        .find(|r| {
                            r.captured.role == "textbox" && r.captured.name == "Ordinary field 0"
                        })
                        .ok_or("ordinary field missing")?;
                    let frame = field.frame_document.as_ref().ok_or("field frame missing")?;
                    assert!(driver
                        .prepare_frame(CONTEXT, frame, DEADLINE)
                        .map_err(|e| format!("prepare field: {e:?}"))?);
                    driver
                        .click_classified(
                            CONTEXT,
                            field.backend_identity.as_ref().unwrap(),
                            1,
                            &frame.origin,
                            field.classification.as_deref().ok(),
                            DEADLINE,
                            &mut |_| {},
                        )
                        .map_err(|e| format!("ordinary field click: {e:?}"))?;
                    println!("FORM_CLICK Ordinary field 0 succeeded");
                }
                // Records are exported for archived old/new element-wise comparison.
                if let Ok(dir) = std::env::var("CK_PROBE_RECORDS") {
                    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                    let records: Vec<_> = observation.refs.iter().map(|r| serde_json::json!({"role":r.captured.role,"name":r.captured.name,"identity":format!("{:?}",r.backend_identity),"classification":r.classification.as_ref().map(|c| serde_json::to_value(c).unwrap()).unwrap_or_else(|e| serde_json::json!({"refused":e.reason_code()}))})).collect();
                    std::fs::write(
                        PathBuf::from(dir).join(format!("{fixture}-{phase}.json")),
                        serde_json::to_vec_pretty(&records).unwrap(),
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        Ok(())
    }
}
