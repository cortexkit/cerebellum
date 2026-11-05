//! Headless, loopback-only measurement of an unread own-browser CDP connection.
//! Run with CK_CHROME=/path/to/chrome cargo run --locked -p cerebellum
//! --example cdp_idle_drain. CK_IDLE_SECONDS defaults to 10,60,300; a short
//! override is useful for checking the fixture, not as measurement evidence.
//! CK_IDLE_PAGE and CK_IDLE_ARM can select a single failed measurement to retry.
//! Each arm has its own temporary profile and the production pipe and driver.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn main() {
    eprintln!("This live probe requires the Unix Chrome launcher (macOS or Linux).");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn main() -> Result<(), String> {
    probe::run()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod probe {
    use cerebellum::browser::navigation::CdpNavigationDriver;
    use cerebellum::browser::Tracker;
    use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead, UnixCdpPipe};
    use cerebellum::browser_session::NavigationWait;
    use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
    use cerebellum::snapshot_store::SnapshotKind;
    #[cfg(target_os = "linux")]
    use cerebellum_linux as platform;
    #[cfg(target_os = "macos")]
    use cerebellum_macos as platform;
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const DEADLINE: u64 = 20_000;
    const PAGE: &str = r#"<!doctype html><title>idle fixture</title>
<h1 id="marker">idle fixture</h1><button>Snapshot marker</button><div id="images"></div>
<script>
const busy = location.pathname === '/busy';
const key = new URLSearchParams(location.search).get('key');
const t0 = performance.now(); let last=t0, ticks=0, maxGap=0, fetches=0, images=0;
let running=true; const gaps=[];
const timer=setInterval(()=>{const now=performance.now(); gaps.push(now-last);
 maxGap=Math.max(maxGap,now-last); last=now; ticks++; if(!busy)window.name=JSON.stringify(stats());},50);
function stats(){return {elapsed:performance.now()-t0,ticks,maxGap,fetches,images,
 last:performance.now(),gaps:gaps.slice(-10),href:location.href};}
const beat=busy?setInterval(()=>fetch('/beat?key='+key,{method:'POST',body:JSON.stringify(stats())})
 .then(r=>r.text()).then(s=>{if(s==='stop'){running=false;clearInterval(timer);
 clearInterval(beat);clearInterval(work);fetch('/final?key='+key,{method:'POST',body:JSON.stringify(stats())});}
 else if(s==='navigate'&&!new URLSearchParams(location.search).has('old'))
 location.href=location.pathname+'?key='+key+'&old=1';}),1000):0;
function image(){const i=new Image(); i.onload=()=>images++; i.src='/image?key='+key+'&n='+Math.random();
 document.querySelector('#images').replaceChildren(i);}
let work=setInterval(()=>{if(busy&&running){for(let i=0;i<4;i++){
 fetch('/poll?key='+key+'&n='+Math.random()).then(r=>r.text()).then(()=>fetches++);image();}
 console.log('idle fixture',performance.now(),'x'.repeat(1024));}},100);
if(busy){for(let i=0;i<32;i++)image(); for(let i=0;i<3;i++){
 const f=document.createElement('iframe');f.src='/frame';document.body.append(f);}}
</script>"#;

    #[derive(Default)]
    struct Fixture {
        stopped: AtomicBool,
        navigate: AtomicBool,
        beats: Mutex<Vec<Value>>,
        requests: Mutex<BTreeMap<String, usize>>,
    }

    struct Server {
        address: String,
        fixtures: Arc<Mutex<BTreeMap<String, Arc<Fixture>>>>,
        shutdown: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Server {
        fn start() -> Result<Self, String> {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            listener.set_nonblocking(true).map_err(|e| e.to_string())?;
            let address = listener
                .local_addr()
                .map_err(|e| e.to_string())?
                .to_string();
            let fixtures = Arc::new(Mutex::new(BTreeMap::new()));
            let shutdown = Arc::new(AtomicBool::new(false));
            let state = fixtures.clone();
            let stop = shutdown.clone();
            let thread = std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let state = state.clone();
                            std::thread::spawn(move || serve(stream, &state));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Ok(Self {
                address,
                fixtures,
                shutdown,
                thread: Some(thread),
            })
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn serve(mut stream: TcpStream, fixtures: &Mutex<BTreeMap<String, Arc<Fixture>>>) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        let header_end = loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            }
            if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                break end + 4;
            }
            if bytes.len() > 65536 {
                return;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
        let path = headers.split_whitespace().nth(1).unwrap_or("/");
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
            .min(65536);
        while bytes.len() < header_end + length {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            }
        }
        let key = path
            .split_once('?')
            .into_iter()
            .flat_map(|(_, q)| q.split('&'))
            .find_map(|part| part.strip_prefix("key="))
            .unwrap_or("");
        let fixture = fixtures.lock().unwrap().get(key).cloned();
        let route = path.split('?').next().unwrap_or("/");
        if let Some(fixture) = &fixture {
            *fixture
                .requests
                .lock()
                .unwrap()
                .entry(route.to_string())
                .or_default() += 1;
            if matches!(route, "/beat" | "/final") {
                if let Ok(value) = serde_json::from_slice(&bytes[header_end..header_end + length]) {
                    fixture.beats.lock().unwrap().push(value);
                }
            }
        }
        let (kind, body) = match route {
            "/busy" | "/quiet" => ("text/html", PAGE.to_string()),
            "/frame" => ("text/html", "<p>local iframe</p>".to_string()),
            "/image" => ("image/svg+xml", "<svg xmlns='http://www.w3.org/2000/svg' width='8' height='8'><rect width='8' height='8'/></svg>".to_string()),
            "/next" => {
                // A delayed load distinguishes real completion from old load events.
                std::thread::sleep(Duration::from_secs(2));
                ("text/html", format!("<h1>NEW DOCUMENT {key}</h1><button>New marker</button>"))
            }
            "/beat" if fixture.as_ref().is_some_and(|f| f.stopped.load(Ordering::Relaxed)) => ("text/plain", "stop".to_string()),
            "/beat" if fixture.as_ref().is_some_and(|f| f.navigate.load(Ordering::Relaxed)) => {
                ("text/plain", "navigate".to_string())
            }
            _ => ("text/plain", "ok".to_string()),
        };
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len());
    }

    #[derive(Default)]
    struct Counts {
        bytes: usize,
        events: BTreeMap<String, usize>,
        responses: usize,
        unknown_responses: usize,
        first_response: Option<Value>,
    }

    #[derive(Default)]
    struct Meter {
        decoder: CdpFrameDecoder,
        issued: BTreeSet<u64>,
        measuring: bool,
        counts: Counts,
        session: Option<String>,
        control_response: Option<Value>,
        measurement_start: Option<Instant>,
    }

    struct Pipe {
        inner: UnixCdpPipe,
        meter: Arc<Mutex<Meter>>,
    }

    impl CdpPipeIo for Pipe {
        fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes[..bytes.len() - 1]) {
                let mut meter = self.meter.lock().unwrap();
                if let Some(id) = value["id"].as_u64() {
                    meter.issued.insert(id);
                }
                if value["method"] == "Network.enable" {
                    meter.session = value["sessionId"].as_str().map(str::to_owned);
                }
            }
            self.inner.write_frame(bytes)
        }
        fn write_frame_until(&mut self, bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
            self.inner.write_frame_until(bytes, deadline)
        }
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<PipeRead> {
            let result = self.inner.read(bytes)?;
            if let PipeRead::Bytes(n) = result {
                let mut meter = self.meter.lock().unwrap();
                if meter.measuring {
                    meter.counts.bytes += n;
                }
                for frame in meter.decoder.push(&bytes[..n]) {
                    if let Ok(value) = serde_json::from_slice::<Value>(&frame) {
                        if let Some(id) = value["id"].as_u64() {
                            if id >= 1_000_000_000 {
                                meter.control_response = Some(value.clone());
                            }
                            let known = meter.issued.remove(&id);
                            if meter.measuring {
                                meter.counts.responses += 1;
                                if !known {
                                    meter.counts.unknown_responses += 1;
                                }
                                if meter.counts.first_response.is_none() {
                                    meter.counts.first_response = Some(
                                        json!({"id":id,"events_before":meter.counts.events.values().sum::<usize>(),"read_bytes_through_reply_chunk":meter.counts.bytes,"ms":meter.measurement_start.map(|s|s.elapsed().as_millis())}),
                                    );
                                }
                            }
                        } else if meter.measuring {
                            *meter
                                .counts
                                .events
                                .entry(value["method"].as_str().unwrap_or("invalid").to_string())
                                .or_default() += 1;
                        }
                    }
                }
            }
            Ok(result)
        }
    }

    // These probe-only commands run after the last driver call. Their disjoint
    // ids and mirror decoder never participate in production reply correlation.
    fn query(
        pipe: &mut Pipe,
        id: u64,
        method: &str,
        session: Option<&str>,
        params: Value,
    ) -> Value {
        let mut value = json!({"id":id,"method":method,"params":params});
        if let Some(session) = session {
            value["sessionId"] = json!(session);
        }
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(0);
        pipe.meter.lock().unwrap().control_response = None;
        if let Err(error) = pipe.write_frame(&bytes) {
            return json!({"error":error.to_string()});
        }
        let start = Instant::now();
        let mut buffer = [0; 65536];
        while start.elapsed() < Duration::from_secs(5) {
            match pipe.read(&mut buffer) {
                Ok(PipeRead::Bytes(_)) => {
                    if let Some(value) = pipe.meter.lock().unwrap().control_response.take() {
                        if value["id"] == id {
                            return value;
                        }
                    }
                }
                Ok(PipeRead::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
                other => return json!({"read":format!("{other:?}")}),
            }
        }
        json!({"error":"memory query deadline"})
    }

    fn memory(pipe: &mut Pipe) -> Value {
        let session = pipe.meter.lock().unwrap().session.clone();
        let enable = query(
            pipe,
            1_000_000_000,
            "Performance.enable",
            session.as_deref(),
            json!({}),
        );
        let performance = query(
            pipe,
            1_000_000_001,
            "Performance.getMetrics",
            session.as_deref(),
            json!({}),
        );
        let dom = query(
            pipe,
            1_000_000_002,
            "Memory.getDOMCounters",
            session.as_deref(),
            json!({}),
        );
        let processes = query(
            pipe,
            1_000_000_003,
            "SystemInfo.getProcessInfo",
            None,
            json!({}),
        );
        let profile = query(
            pipe,
            1_000_000_004,
            "Memory.getBrowserSamplingProfile",
            None,
            json!({}),
        );
        let timers = query(
            pipe,
            1_000_000_005,
            "Runtime.evaluate",
            session.as_deref(),
            json!({"expression":"window.name","returnByValue":true}),
        );
        let page_timers = timers
            .pointer("/result/result/value")
            .and_then(Value::as_str)
            .and_then(|s| serde_json::from_str::<Value>(s).ok());
        let samples = profile
            .pointer("/result/profile/samples")
            .and_then(Value::as_array);
        json!({"performance_enable":enable,"performance":performance,"dom":dom,"processes":processes,"page_timers":page_timers,
            "browser_sampling": {"sample_count":samples.map(Vec::len),
                "sampled_size":samples.map(|s|s.iter().filter_map(|s|s["size"].as_f64()).sum::<f64>()),
                "estimated_total":samples.map(|s|s.iter().filter_map(|s|s["total"].as_f64()).sum::<f64>()),
                "error":profile.get("error")}})
    }

    fn snapshot(driver: &mut CdpNavigationDriver<Pipe>, marker: &str) -> Value {
        let start = Instant::now();
        match driver.snapshot("probe", SnapshotKind::DomFull, DEADLINE) {
            Ok(observation) => json!({"ms":start.elapsed().as_millis(),"ok":true,
                "marker_present":observation.dom_text.as_ref().is_some_and(|s|s.contains(marker)),
                "dom_bytes":observation.dom_text.as_ref().map(String::len)}),
            Err(error) => json!({"ms":start.elapsed().as_millis(),"error":format!("{error:?}")}),
        }
    }

    fn navigate(driver: &mut CdpNavigationDriver<Pipe>, url: &str) -> Value {
        let start = Instant::now();
        let mut tracker = Tracker::default();
        let result = driver.navigate("probe", url, NavigationWait::Settle, DEADLINE, &mut tracker);
        json!({"ms":start.elapsed().as_millis(),"result":format!("{result:?}"),
            "tracker":format!("{tracker:?}"),"waited_for_delayed_document":start.elapsed()>=Duration::from_secs(2),
            "http_status":tracker.http_status(),"main_frame_failure":tracker.main_frame_failure()})
    }

    fn trial(
        chrome: &Path,
        server: &Server,
        page: &str,
        arm: &str,
        seconds: u64,
    ) -> Result<(), String> {
        let key = format!("{page}-{arm}-{seconds}");
        let fixture = Arc::new(Fixture::default());
        server
            .fixtures
            .lock()
            .unwrap()
            .insert(key.clone(), fixture.clone());
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        // Launch a separate Chrome process with a new temporary profile; never
        // reuse the person's Chrome profile or the running cerebellum service.
        let profile = std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join("target/scratch")
            .join(format!("cdp-idle-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
        let args: Vec<OsString> = [
            "--headless=new".to_string(),
            "--no-sandbox".into(),
            "--remote-debugging-pipe".into(),
            "--no-startup-window".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-background-networking".into(),
            format!("--user-data-dir={}", profile.display()),
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let (child_commands, commands) = UnixStream::pair().map_err(|e| e.to_string())?;
        let (responses, child_responses) = UnixStream::pair().map_err(|e| e.to_string())?;
        let socket = socket2::SockRef::from(&responses);
        let buffers = json!({"receive_buffer":socket.recv_buffer_size().ok(),"send_buffer":socket.send_buffer_size().ok()});
        let browser = platform::spawn_barred(
            chrome,
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
        let pid = browser.generation().pid;
        let meter = Arc::new(Mutex::new(Meter::default()));
        let mut drain = Pipe {
            inner: UnixCdpPipe::new(
                commands.try_clone().map_err(|e| e.to_string())?,
                responses.try_clone().map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?,
            meter: meter.clone(),
        };
        let pipe = Pipe {
            inner: UnixCdpPipe::new(commands, responses).map_err(|e| e.to_string())?,
            meter: meter.clone(),
        };
        let result = (|| {
            let mut driver =
                CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());
            let url = format!("http://{}/{page}?key={key}", server.address);
            driver
                .navigate(
                    "probe",
                    &url,
                    NavigationWait::None,
                    DEADLINE,
                    &mut Tracker::default(),
                )
                .map_err(|e| format!("setup navigate: {e:?}"))?;
            let warm = snapshot(&mut driver, "idle fixture");
            if warm["ok"] != true {
                return Err(format!("setup snapshot: {warm}"));
            }
            let beats_before = fixture.beats.lock().unwrap().len();
            fixture.navigate.store(true, Ordering::Relaxed);
            let start = Instant::now();
            // No CDP read, including a liveness or timer query, occurs here.
            std::thread::sleep(Duration::from_secs(seconds));
            let idle_ms = start.elapsed().as_millis();
            let beats = fixture.beats.lock().unwrap().clone();
            let requests = fixture.requests.lock().unwrap().clone();
            fixture.stopped.store(true, Ordering::Relaxed);
            // Stop the producers out of band. This does not read CDP and allows
            // the drain-only arm to distinguish backlog from new live traffic.
            std::thread::sleep(Duration::from_millis(1200));
            {
                let mut m = meter.lock().unwrap();
                m.measuring = true;
                m.measurement_start = Some(Instant::now());
                m.counts = Counts::default();
            }
            let next = format!("http://{}/next?key={key}", server.address);
            let first = match arm {
                "snapshot" => snapshot(&mut driver, "idle fixture"),
                "navigate" => navigate(&mut driver, &next),
                "drain" => {
                    // The duplicate is used only after the driver has stopped,
                    // and the driver is never called again in this trial.
                    let start = Instant::now();
                    let mut last = Instant::now();
                    let mut buffer = [0; 65536];
                    while start.elapsed() < Duration::from_secs(10)
                        && last.elapsed() < Duration::from_millis(200)
                    {
                        match drain.read(&mut buffer).map_err(|e| e.to_string())? {
                            PipeRead::Bytes(_) => last = Instant::now(),
                            PipeRead::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
                            PipeRead::Closed => {
                                return Err("Chrome closed pipe during drain".into())
                            }
                        }
                    }
                    json!({"ms":start.elapsed().as_millis(),"quiet_ms":last.elapsed().as_millis()})
                }
                _ => unreachable!(),
            };
            let counts = {
                let mut m = meter.lock().unwrap();
                m.measuring = false;
                json!({"bytes":m.counts.bytes,"events":m.counts.events,"event_count":m.counts.events.values().sum::<usize>(),
                    "responses":m.counts.responses,"unknown_responses":m.counts.unknown_responses,"first_response":m.counts.first_response})
            };
            let second = match arm {
                "snapshot" => navigate(&mut driver, &next),
                "navigate" => snapshot(&mut driver, &key),
                _ => Value::Null,
            };
            let verified = if arm == "snapshot" {
                snapshot(&mut driver, &key)
            } else {
                Value::Null
            };
            println!(
                "{}",
                json!({"page":page,"arm":arm,"idle_seconds":seconds,"actual_idle_ms":idle_ms,
                "buffers":buffers,"warm_snapshot":warm,"producers_stopped":fixture.requests.lock().unwrap().contains_key("/final"),
                "cdp_memory_after_calls":memory(&mut drain),"rss_limitation":"ps denied by worker sandbox","pid":pid,"beats_before":beats_before,"beats_at_idle_end":beats.len(),
                "first_beat":beats.first(),"last_beat":beats.last(),"requests_at_idle_end":requests,
                "counts":counts,"first":first,"second":second,"verified_snapshot":verified})
            );
            Ok(())
        })();
        let cleanup = browser
            .terminate_and_reap()
            .map_err(|e| format!("cleanup: {e:?}"));
        let _ = std::fs::remove_dir_all(&profile);
        result.and(cleanup)
    }

    pub fn run() -> Result<(), String> {
        let chrome = std::env::var_os("CK_CHROME")
            .map(PathBuf::from)
            .ok_or("set CK_CHROME to an explicit Chrome executable")?;
        let version = Command::new(&chrome)
            .args(["--headless=new", "--no-sandbox", "--version"])
            .output()
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            json!({"browser":String::from_utf8_lossy(&version.stdout).trim(),"os":std::env::consts::OS,
            "probe":"cdp_idle_drain","timer_ms":50,"busy_tick_ms":100,"heartbeat_ms":1000,"next_load_delay_ms":2000})
        );
        let seconds: Vec<u64> = std::env::var("CK_IDLE_SECONDS")
            .unwrap_or_else(|_| "10,60,300".into())
            .split(',')
            .map(|s| s.parse().map_err(|e| format!("idle seconds: {e}")))
            .collect::<Result<_, _>>()?;
        let server = Server::start()?;
        let only_page = std::env::var("CK_IDLE_PAGE").ok();
        let only_arm = std::env::var("CK_IDLE_ARM").ok();
        if only_page
            .as_ref()
            .is_some_and(|p| !["busy", "quiet"].contains(&p.as_str()))
            || only_arm
                .as_ref()
                .is_some_and(|a| !["drain", "snapshot", "navigate"].contains(&a.as_str()))
        {
            return Err("invalid CK_IDLE_PAGE or CK_IDLE_ARM filter".into());
        }
        // Six isolated arms share the host, not a pipe or a Chrome process.
        // Concurrent idle periods keep the five-minute measurement practical.
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for page in ["busy", "quiet"] {
                for arm in ["drain", "snapshot", "navigate"] {
                    if only_page.as_ref().is_some_and(|p| p != page)
                        || only_arm.as_ref().is_some_and(|a| a != arm)
                    {
                        continue;
                    }
                    let chrome = &chrome;
                    let server = &server;
                    let seconds = &seconds;
                    workers.push(scope.spawn(move || {
                        for &seconds in seconds {
                            trial(chrome, server, page, arm, seconds)?;
                        }
                        Ok::<_, String>(())
                    }));
                }
            }
            for worker in workers {
                worker.join().map_err(|_| "probe worker panicked")??;
            }
            Ok(())
        })
    }
}
