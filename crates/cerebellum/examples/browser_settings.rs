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
    use cerebellum::browser::navigation::{BrowserSnapshotObservation, CdpNavigationDriver};
    use cerebellum::browser::state_text::{self, Filters, RenderInput, Zoom};
    use cerebellum::browser::Tracker;
    use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
    use cerebellum::browser_session::NavigationWait;
    use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
    use cerebellum::snapshot_store::{RefRecord, SnapshotKind};
    use std::ffi::OsString;
    use std::io::{self, Read, Write};
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::Instant;

    const DEADLINE: u64 = 30_000;

    struct Pipe {
        commands: UnixStream,
        responses: UnixStream,
    }

    impl CdpPipeIo for Pipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.commands.write_all(bytes)
        }
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<PipeRead> {
            match self.responses.read(bytes) {
                Ok(0) => Ok(PipeRead::Closed),
                Ok(n) => Ok(PipeRead::Bytes(n)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PipeRead::WouldBlock),
                Err(error) => Err(error),
            }
        }
    }

    fn page(_label: &str, _iframe: &str) -> String {
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
        let child = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let url = format!("http://127.0.0.1:{}/", main.local_addr().unwrap().port());
        let iframe = format!(
            "<iframe src='http://localhost:{}/' title='Embedded events'></iframe>",
            child.local_addr().unwrap().port()
        );
        serve(main, page("Event", &iframe));
        serve(child, page("Embedded event", ""));
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
        let result = std::panic::catch_unwind(|| {
            exercise(
                Pipe {
                    commands,
                    responses,
                },
                &url,
            )
        })
        .unwrap_or_else(|_| Err("probe assertion failed".into()));
        let _ = browser.terminate_and_reap();
        let _ = std::fs::remove_dir_all(profile);
        result
    }

    fn named(observation: &BrowserSnapshotObservation, name: &str) -> RefRecord {
        observation
            .refs
            .iter()
            .find(|r| r.captured.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .clone()
    }

    fn render(
        observation: &BrowserSnapshotObservation,
        reference: &RefRecord,
        cap: usize,
    ) -> state_text::RenderedState {
        let target = observation
            .refs
            .iter()
            .find(|r| r.backend_identity == reference.backend_identity)
            .map(|r| r.captured.reference.as_str());
        state_text::render(&RenderInput {
            records: &observation.records,
            facts: &observation.facts,
            filters: &Filters::default(),
            page_url: "http://fixture.invalid/",
            snapshot_id: "0123456789abcdef0123456789abcdef",
            zoom: Some(Zoom {
                requested: &reference.captured.reference,
                target,
            }),
            max_bytes: cap,
        })
    }

    fn exercise(pipe: Pipe, url: &str) -> Result<(), String> {
        let mut driver =
            CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());
        driver
            .navigate(
                "settings-probe",
                url,
                NavigationWait::Settle,
                DEADLINE,
                &mut Tracker::default(),
            )
            .map_err(|e| format!("navigate: {e:?}"))?;
        let start = Instant::now();
        let observation = driver
            .snapshot_classified("settings-probe", SnapshotKind::Actionable, 1, url, DEADLINE)
            .map_err(|e| format!("capture: {e:?}"))?;
        println!(
            "capture: {} ms, {} records, {} refs, truncated={}",
            start.elapsed().as_millis(),
            observation.records.len(),
            observation.refs.len(),
            observation.ax_truncated
        );
        println!(
            "last records: {:?}",
            &observation.records[observation.records.len().saturating_sub(5)..]
        );
        println!(
            "settings form records: {:?}",
            observation
                .records
                .iter()
                .filter(|r| r.role == "main" || r.role == "checkbox")
                .collect::<Vec<_>>()
        );
        let render_filtered = |filters: &Filters| {
            state_text::render(&RenderInput {
                records: &observation.records,
                facts: &observation.facts,
                filters,
                page_url: url,
                snapshot_id: "0123456789abcdef0123456789abcdef",
                zoom: None,
                max_bytes: 8000,
            })
        };
        println!("OUTLINE:\n{}", render_filtered(&Filters::default()).text);
        for (name, filters) in [
            (
                "settings_role_filter_finds_below_fold",
                Filters {
                    text: None,
                    roles: vec!["checkbox".into()],
                },
            ),
            (
                "settings_text_filter_finds_below_fold",
                Filters {
                    text: Some("Require status checks".into()),
                    roles: vec![],
                },
            ),
        ] {
            let text = render_filtered(&filters).text;
            println!("{name}:\n{text}");
            println!(
                "{name}: found={}",
                text.contains("Require status checks to pass before merging")
            );
        }
        let main = named(&observation, "Branch protection");
        let zoom = driver
            .snapshot_subtree_classified(
                "settings-probe",
                SnapshotKind::Actionable,
                &main,
                1,
                url,
                DEADLINE,
            )
            .map_err(|e| format!("zoom: {e:?}"))?;
        println!(
            "settings_zoom_main_lists_checkbox: found={}",
            render(&zoom, &main, 8000)
                .text
                .contains("Require status checks to pass before merging")
        );
        let dom = driver
            .snapshot("settings-probe", SnapshotKind::DomFull, DEADLINE)
            .map_err(|e| format!("dom: {e:?}"))?
            .dom_text
            .unwrap();
        println!(
            "dom_full: {} bytes, starts {:?}",
            dom.len(),
            &dom[..dom.len().min(100)]
        );
        println!(
            "settings_dom_full_starts_at_body: {}",
            !dom.contains("<head>")
        );
        Ok(())
    }
}
