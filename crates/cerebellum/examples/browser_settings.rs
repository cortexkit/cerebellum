//! Live, isolated Chrome regression probe for settings forms behind long navigation.
//! Run on macOS with `cargo run -p cerebellum --example browser_settings`.
//! `CK_CHROME` can select a different Chrome binary; no personal profile is used.

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = probe::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("This live probe uses the macOS process barrier.");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
mod probe {
    use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::{self, Read, Write};
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const DEADLINE: u64 = 30_000;
    mod plane {
        include!("support/browser_settings_plane.rs");
    }

    struct Pipe {
        commands: UnixStream,
        responses: UnixStream,
        counts: Arc<Mutex<BTreeMap<String, usize>>>,
        session: Arc<Mutex<Option<String>>>,
        timings: Arc<Mutex<Timings>>,
    }

    #[derive(Default)]
    struct Timings {
        decoder: cerebellum::cdp::CdpFrameDecoder,
        issued: BTreeMap<u64, (String, Instant)>,
        completed: Vec<(String, u128)>,
    }

    impl CdpPipeIo for Pipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1])?;
            *self
                .counts
                .lock()
                .unwrap()
                .entry(command["method"].as_str().unwrap().to_string())
                .or_default() += 1;
            self.timings.lock().unwrap().issued.insert(
                command["id"].as_u64().unwrap(),
                (
                    command["method"].as_str().unwrap().to_string(),
                    Instant::now(),
                ),
            );
            self.commands.write_all(bytes)
        }
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<PipeRead> {
            match self.responses.read(bytes) {
                Ok(0) => Ok(PipeRead::Closed),
                Ok(n) => {
                    let mut timings = self.timings.lock().unwrap();
                    for frame in timings.decoder.push(&bytes[..n]) {
                        if let Ok(reply) = serde_json::from_slice::<Value>(&frame) {
                            if let Some((method, start)) = reply["id"]
                                .as_u64()
                                .and_then(|id| timings.issued.remove(&id))
                            {
                                timings
                                    .completed
                                    .push((method, start.elapsed().as_millis()));
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

    impl Pipe {
        fn duplicate(&self) -> Self {
            Self {
                commands: self.commands.try_clone().unwrap(),
                responses: self.responses.try_clone().unwrap(),
                counts: self.counts.clone(),
                session: self.session.clone(),
                timings: self.timings.clone(),
            }
        }

        // Probe reads run only between driver calls, with disjoint command ids.
        // They measure the fixture's geometry without exposing script to tools.
        fn evaluate(&mut self, session: &str, id: u64, expression: &str) -> Result<Value, String> {
            let mut command = serde_json::to_vec(&json!({"id":id,"sessionId":session,"method":"Runtime.evaluate","params":{"expression":expression,"returnByValue":true,"awaitPromise":true}})).unwrap();
            command.push(0);
            self.commands
                .write_all(&command)
                .map_err(|e| e.to_string())?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut buffer = Vec::new();
            let mut chunk = [0; 65536];
            while Instant::now() < deadline {
                match self.responses.read(&mut chunk) {
                    Ok(0) => return Err("Chrome closed the probe pipe".into()),
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                    Err(e) => return Err(e.to_string()),
                }
                while let Some(end) = buffer.iter().position(|b| *b == 0) {
                    let response: Value =
                        serde_json::from_slice(&buffer[..end]).map_err(|e| e.to_string())?;
                    buffer.drain(..=end);
                    if response["id"] == id {
                        println!("geometry readback {id}: {response}");
                        return response
                            .pointer("/result/result/value")
                            .cloned()
                            .ok_or_else(|| format!("probe evaluate: {response}"));
                    }
                }
            }
            Err("probe evaluate deadline".into())
        }
    }

    fn page() -> String {
        let links = (0..600)
            .map(|n| format!("<li><a href='#setting-{n}'>Repository setting {n}</a></li>"))
            .collect::<String>();
        format!(
            r#"<!doctype html><html><head><title>Branch protection fixture</title>
<style>nav{{position:absolute;width:220px}} main{{margin-left:240px}} .spacer{{height:1800px}}</style>
<script type='application/json'>{}</script></head><body><header><nav aria-label='Global'><a href='/'>Dashboard</a></nav></header>
<nav aria-label='Settings'><ul>{links}</ul></nav>
<main aria-label='Branch protection'><h1>Settings: fixture/repository</h1><div><div><form><fieldset><legend>Protect matching branches</legend>
<label>Branch name pattern <input value='main'></label>
<details><summary>Additional restrictions</summary><label><input type='checkbox'>Hidden restriction</label></details>
<div class='spacer'></div><div role='presentation'><fieldset><legend>Protect branches</legend>
<label><input type='checkbox'>Require a pull request before merging</label><p>Reviews help protect important branches.</p>
<div id='shadow'></div><label><input id='target' type='checkbox'>Require status checks to pass before merging</label>
<p>Choose which checks must pass before branches can be merged.</p>
<label><input type='checkbox'>Require merge queue</label></fieldset></div></fieldset></form></div></div></main>
<script>shadow.attachShadow({{mode:'open'}}).innerHTML='<label><input type="checkbox">Shadow check</label>';</script></body></html>"#,
            "x".repeat(320_000)
        )
    }

    fn serve(listener: TcpListener, page: String) {
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0; 4096];
                let _ = stream.read(&mut request);
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}", page.len());
                let _ = stream.write_all(response.as_bytes());
            }
        });
    }

    pub fn run() -> Result<(), String> {
        let main = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let url = format!("http://127.0.0.1:{}/", main.local_addr().unwrap().port());
        serve(main, page());
        let profile = PathBuf::from(format!("/tmp/ck-browser-settings-{}", std::process::id()));
        std::fs::create_dir(&profile).map_err(|e| e.to_string())?;
        let chrome = std::env::var_os("CK_CHROME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            });
        let version = std::process::Command::new(&chrome)
            .args(["--headless=new", "--version"])
            .arg(format!("--user-data-dir={}", profile.display()))
            .output()
            .map_err(|e| e.to_string())?;
        println!(
            "browser: {}",
            String::from_utf8_lossy(&version.stdout).trim()
        );
        let args: Vec<OsString> = [
            "--headless=new".to_string(),
            "--remote-debugging-pipe".into(),
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
        let browser = Arc::new(Mutex::new(Some(browser)));
        let result = std::panic::catch_unwind(|| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(plane::exercise(
                Pipe {
                    commands,
                    responses,
                    counts: Arc::default(),
                    session: Arc::default(),
                    timings: Arc::default(),
                },
                &url,
                browser.clone(),
            ))
        })
        .unwrap_or_else(|_| Err("probe assertion failed".into()));
        if let Some(browser) = browser.lock().unwrap().take() {
            let _ = browser.terminate_and_reap();
        }
        let _ = std::fs::remove_dir_all(profile);
        result
    }
}
