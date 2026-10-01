//! What does Chrome send on the route page's CDP session while a person signs
//! in, and can the page still be read afterwards?
//!
//! `browser.present` fronts the route's page, a person signs in, and
//! `browser.resume` hands the page back. The handoff polls the page while it
//! is open (`cookie_names_for_origin`, `main_frame_url`,
//! `has_credential_field`), and the first `browser.snapshot` after the resume
//! reads it again. This probe drives the same driver calls on a page that
//! signs in by itself, so no person and no real site is needed:
//!
//! - origin A (`http://127.0.0.1:<port>`) shows a password field, then sends
//!   the page to origin B (`http://localhost:<port>`), another site, so Chrome
//!   moves the page to a new renderer process the way a single sign-on
//!   provider does;
//! - B sends it back to A's callback, which sets a cookie and replaces the
//!   page with A's home page;
//! - A's home page carries a cross-site frame and a same-origin frame, pushes
//!   a history entry and keeps changing its DOM;
//! - after the handoff it reads the page twice the way `browser.snapshot`
//!   does (committed document, classified snapshot, committed document),
//!   then reads a page whose text holds a lone UTF-16 surrogate, then a fresh
//!   load of the home page.
//!
//! Every frame on the pipe, in both directions, is written to a log under the
//! temp directory; the probe prints the log's path, every event method it saw
//! on the route's session, and each read's result.
//!
//! It launches Chrome as a session does on a throwaway profile under the temp
//! directory and signs in nowhere. Pass `--headless` to run Chrome with no
//! window at all; without it Chrome opens a visible window, so run it that
//! way only with the operator's permission:
//!
//! ```text
//! cargo run -p cerebellum --example handoff_attachment_probe -- --headless
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe launches macOS Chrome and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    probe::run();
}

#[cfg(target_os = "macos")]
mod probe {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use cerebellum::browser::navigation::CdpNavigationDriver;
    use cerebellum::browser::Tracker;
    use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead, UnixCdpPipe};
    use cerebellum::browser_session::NavigationWait;
    use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
    use cerebellum::snapshot_store::SnapshotKind;
    use serde_json::Value;

    const CONTEXT: &str = "handoff-attachment-probe";
    const DEADLINE_MS: u64 = 10_000;

    /// One line per frame, plus the probe's own step markers, in order.
    type Log = Arc<Mutex<Vec<String>>>;

    /// Records every frame crossing the pipe before the driver sees it.
    struct LoggingPipe<P> {
        inner: P,
        log: Log,
        started: Instant,
        inbound: Vec<u8>,
    }

    impl<P: CdpPipeIo> CdpPipeIo for LoggingPipe<P> {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            let frame = bytes.strip_suffix(&[0]).unwrap_or(bytes);
            self.push(format!(">> {}", String::from_utf8_lossy(frame)));
            self.inner.write_frame(bytes)
        }

        fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
            let read = self.inner.read(destination)?;
            if let PipeRead::Bytes(count) = read {
                for &byte in &destination[..count] {
                    if byte == 0 {
                        let frame = std::mem::take(&mut self.inbound);
                        // Whether the driver's JSON parser accepts the frame is
                        // recorded beside it: a frame it rejects fails the read
                        // that was waiting when it arrived.
                        let verdict = match serde_json::from_slice::<Value>(&frame) {
                            Ok(_) => "",
                            Err(_) => "UNPARSEABLE ",
                        };
                        self.push(format!("<< {verdict}{}", String::from_utf8_lossy(&frame)));
                    } else {
                        self.inbound.push(byte);
                    }
                }
            }
            Ok(read)
        }
    }

    impl<P> LoggingPipe<P> {
        fn push(&self, line: String) {
            let elapsed = self.started.elapsed().as_millis();
            self.log
                .lock()
                .unwrap()
                .push(format!("{elapsed:>7} {line}"));
        }
    }

    fn mark(log: &Log, started: Instant, line: impl AsRef<str>) {
        let elapsed = started.elapsed().as_millis();
        let line = format!("{elapsed:>7} == {}", line.as_ref());
        println!("{line}");
        log.lock().unwrap().push(line);
    }

    /// Serves both origins' pages. Which origin a request reached does not
    /// matter: the paths are distinct.
    struct Server {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn serve(mut stream: TcpStream, pages: &BTreeMap<&'static str, (String, String)>) {
        let _ = stream.set_nonblocking(false);
        // Chrome opens connections ahead of the requests it will send on
        // them. Answering one before its request arrives would hand the next
        // request this answer, so an idle connection is closed unanswered.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => request.extend_from_slice(&chunk[..count]),
            }
        }
        if request.is_empty() {
            return;
        }
        let request = String::from_utf8_lossy(&request);
        let target = request.split_whitespace().nth(1).unwrap_or("/");
        let path = target.split('?').next().unwrap_or("/");
        let (status, headers, body) = match pages.get(path) {
            Some((headers, body)) => ("200 OK", headers.as_str(), body.as_str()),
            None => ("404 Not Found", "", "not found"),
        };
        if status != "200 OK" {
            eprintln!("probe server: {status} for {target:?}");
        }
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    fn pages(origin_a: &str, origin_b: &str) -> BTreeMap<&'static str, (String, String)> {
        let page = |title: &str, body: &str| {
            format!("<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>")
        };
        let mut pages = BTreeMap::new();
        pages.insert(
            "/start",
            (
                String::new(),
                page(
                    "Sign in",
                    &format!(
                        "<form><label>Email <input name=u autocomplete=username></label>\
                         <label>Password <input type=password autocomplete=current-password></label>\
                         <button>Sign in</button></form>\
                         <script>setTimeout(() => {{ location.href = '{origin_b}/sso?back={origin_a}/callback'; }}, 2500);</script>"
                    ),
                ),
            ),
        );
        pages.insert(
            "/sso",
            (
                String::new(),
                page(
                    "Provider",
                    "<p>Signing you in</p>\
                     <script>setTimeout(() => { location.href = new URLSearchParams(location.search).get('back'); }, 1500);</script>",
                ),
            ),
        );
        pages.insert(
            "/callback",
            (
                "Set-Cookie: auth_token=probe; Path=/\r\n".to_string(),
                page(
                    "Callback",
                    "<p>Done</p><script>setTimeout(() => { location.replace('/home'); }, 500);</script>",
                ),
            ),
        );
        let home = page(
            "Home",
            &format!(
                "<main><h1>Home</h1><a href=/start>Settings</a><button>Post</button><ul id=feed></ul>\
                 <iframe src='{origin_b}/frame' title=provider></iframe>\
                 <iframe srcdoc='<button>Inner</button>' title=inner></iframe></main>\
                 <script>\
                 setTimeout(() => history.pushState({{}}, '', '/home?tab=1'), 300);\
                 let n = 0; setInterval(() => {{ const li = document.createElement('li');\
                 li.textContent = 'item ' + (n++); document.getElementById('feed').prepend(li); }}, 150);\
                 </script>"
            ),
        );
        pages.insert("/home", (String::new(), home));
        pages.insert(
            "/frame",
            (String::new(), page("Frame", "<button>Provider button</button>")),
        );
        pages.insert(
            "/surrogate",
            (
                String::new(),
                page(
                    "Surrogate",
                    "<button id=b>x</button>\
                     <script>document.getElementById('b').textContent = 'cut \\ud83d';</script>",
                ),
            ),
        );
        pages
    }

    /// Read the page the way `browser.snapshot` does.
    fn read_like_snapshot(
        driver: &mut CdpNavigationDriver<LoggingPipe<UnixCdpPipe>>,
        log: &Log,
        started: Instant,
        label: &str,
    ) -> bool {
        let before = driver.committed_document(CONTEXT, DEADLINE_MS);
        mark(log, started, format!("{label}: committed_document before = {before:?}"));
        let Ok(before) = before else { return false };
        let snapshot = driver.snapshot_classified(
            CONTEXT,
            SnapshotKind::Actionable,
            1,
            &before.url,
            DEADLINE_MS,
        );
        let ok = match &snapshot {
            Ok(observation) => {
                mark(
                    log,
                    started,
                    format!(
                        "{label}: snapshot ok records={} refs={}",
                        observation.records.len(),
                        observation.refs.len()
                    ),
                );
                true
            }
            Err(error) => {
                mark(log, started, format!("{label}: snapshot FAILED {error:?}"));
                false
            }
        };
        let after = driver.committed_document(CONTEXT, DEADLINE_MS);
        mark(log, started, format!("{label}: committed_document after = {after:?}"));
        ok && after.is_ok()
    }

    pub fn run() {
        let headless = std::env::args().any(|argument| argument == "--headless");
        let chrome =
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        if !chrome.is_file() {
            println!("skipped: no Chrome at {}", chrome.display());
            return;
        }
        // Each origin's port is picked first so both origins' URLs can be
        // written into the pages before either server starts.
        let free_port = || {
            TcpListener::bind("127.0.0.1:0")
                .and_then(|listener| listener.local_addr())
                .expect("free port")
                .port()
        };
        let port_a = free_port();
        let port_b = free_port();
        let origin_a = format!("http://127.0.0.1:{port_a}");
        let origin_b = format!("http://localhost:{port_b}");
        let table = Arc::new(pages(&origin_a, &origin_b));
        let _server_a = start_on(port_a, Arc::clone(&table));
        let _server_b = start_on(port_b, Arc::clone(&table));

        let profile =
            std::env::temp_dir().join(format!("ck-handoff-probe-{}", std::process::id()));
        std::fs::create_dir_all(&profile).expect("profile dir");
        let mut arguments = cerebellum::browser_launch_service::browser_launch_arguments(
            &profile,
            &profile.join("crash-dumps"),
        );
        if headless {
            arguments.push(OsString::from("--headless=new"));
        }
        let (command_child, command_parent) = UnixStream::pair().expect("command pair");
        let (response_parent, response_child) = UnixStream::pair().expect("response pair");
        let barred = cerebellum_macos::spawn_barred(
            &chrome,
            &arguments,
            &[],
            command_child.as_raw_fd(),
            response_child.as_raw_fd(),
        )
        .expect("spawn barred");
        let released = barred.release().expect("release");
        drop(command_child);
        drop(response_child);

        let started = Instant::now();
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let pipe = LoggingPipe {
            inner: UnixCdpPipe::new(command_parent, response_parent).expect("pipe"),
            log: Arc::clone(&log),
            started,
            inbound: Vec::new(),
        };
        let mut driver =
            CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());

        mark(&log, started, format!("A={origin_a} B={origin_b} headless={headless}"));
        let mut tracker = Tracker::default();
        let navigated = driver.navigate(
            CONTEXT,
            &format!("{origin_a}/start"),
            NavigationWait::Settle,
            DEADLINE_MS,
            &mut tracker,
        );
        mark(&log, started, format!("navigate /start = {navigated:?}"));
        let baseline = read_like_snapshot(&mut driver, &log, started, "baseline");
        let presented = driver.present(CONTEXT, DEADLINE_MS);
        mark(&log, started, format!("present = {presented:?}"));

        // The handoff's poll, at a quarter of its real interval so the
        // transitions above are crossed by several polls.
        let poll_until = Instant::now() + Duration::from_secs(15);
        let mut home_seen_at = None;
        while Instant::now() < poll_until {
            let cookies = driver.cookie_names_for_origin(CONTEXT, &origin_a, DEADLINE_MS);
            let url = driver.main_frame_url(CONTEXT, DEADLINE_MS);
            let credential = driver.has_credential_field(CONTEXT, DEADLINE_MS);
            mark(
                &log,
                started,
                format!("poll cookies={cookies:?} url={url:?} credential_field={credential:?}"),
            );
            if url.as_deref().is_ok_and(|url| url.contains("/home")) {
                let seen = *home_seen_at.get_or_insert_with(Instant::now);
                if seen.elapsed() > Duration::from_secs(1) {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        mark(&log, started, "resume (no CDP traffic of its own)");
        let first = read_like_snapshot(&mut driver, &log, started, "after-resume #1");
        let second = read_like_snapshot(&mut driver, &log, started, "after-resume #2");

        let navigated = driver.navigate(
            CONTEXT,
            &format!("{origin_a}/surrogate"),
            NavigationWait::Settle,
            DEADLINE_MS,
            &mut tracker,
        );
        mark(&log, started, format!("navigate /surrogate = {navigated:?}"));
        let surrogate = read_like_snapshot(&mut driver, &log, started, "lone surrogate");

        let navigated = driver.navigate(
            CONTEXT,
            &format!("{origin_a}/home"),
            NavigationWait::Settle,
            DEADLINE_MS,
            &mut tracker,
        );
        mark(&log, started, format!("navigate /home = {navigated:?}"));
        let fresh = read_like_snapshot(&mut driver, &log, started, "fresh home");

        let lines = log.lock().unwrap().clone();
        let path = std::env::temp_dir().join(format!(
            "ck-handoff-probe-{}.log",
            std::process::id()
        ));
        std::fs::write(&path, lines.join("\n")).expect("write log");
        let mut methods = BTreeMap::<String, usize>::new();
        for line in &lines {
            let Some(frame) = line.split_once("<< ").map(|(_, frame)| frame) else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<Value>(frame) else {
                *methods.entry("UNPARSEABLE".into()).or_default() += 1;
                continue;
            };
            if let Some(method) = value.get("method").and_then(Value::as_str) {
                *methods.entry(method.to_string()).or_default() += 1;
            }
        }
        println!("events seen: {methods:?}");
        println!("log: {}", path.display());
        println!(
            "VERDICT: baseline={baseline} after_resume_1={first} after_resume_2={second} lone_surrogate={surrogate} fresh_home={fresh}"
        );

        let _ = released.terminate_and_reap();
        let _ = std::fs::remove_dir_all(&profile);
    }

    fn start_on(port: u16, pages: Arc<BTreeMap<&'static str, (String, String)>>) -> Server {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind origin");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let pages = Arc::clone(&pages);
                        std::thread::spawn(move || serve(stream, &pages));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Server {
            address,
            stop,
            worker: Some(worker),
        }
    }
}
