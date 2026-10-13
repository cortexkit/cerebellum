//! Live, isolated Chrome probe for identity-directed zoom on a 20,000-row page.
//! Run on macOS with `cargo run -p cerebellum --example browser_zoom_subtree`.
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

    fn page(label: &str, iframe: &str) -> String {
        format!(
            r#"<!doctype html><button id="grow" onclick="grow()">Populate {label}</button>
<main><div role="table" id="rows"><div role="row" id="tail" aria-label="{label} 19999">
<span>{label} tail payload</span><label>Card number<input autocomplete="cc-number" value="4111111111111111"></label>
</div></div></main>{iframe}<script>
function grow() {{
 if (document.querySelector('[role=rowgroup]')) return;
 const fragment = document.createDocumentFragment();
 for(let group=0;group<200;group++) {{
  const section=document.createElement('div'); section.setAttribute('role','rowgroup');
  for(let n=group*100;n<Math.min((group+1)*100,19999);n++) {{
   const row=document.createElement('div'); row.setAttribute('role','row');
   row.textContent='{label} '+n; section.appendChild(row);
  }}
  fragment.appendChild(section);
 }}
 rows.insertBefore(fragment,tail);
 document.getElementById('grow').textContent='Populated {label}';
}}
</script>"#
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
        let profile = std::env::temp_dir().join(format!("ck-browser-zoom-{}", std::process::id()));
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
                "zoom-probe",
                url,
                NavigationWait::Settle,
                DEADLINE,
                &mut Tracker::default(),
            )
            .map_err(|e| format!("navigate: {e:?}"))?;
        let frames = driver
            .frame_documents("zoom-probe", DEADLINE)
            .map_err(|e| format!("frames: {e:?}"))?;
        let main = frames.iter().find(|f| f.parent_id.is_none()).unwrap();
        let embedded = frames.iter().find(|f| f.parent_id.is_some()).unwrap();
        assert_ne!(
            main.session_id, embedded.session_id,
            "fixture must exercise an OOPIF session"
        );
        // The fixture intentionally grants both loopback documents. Permission
        // filtering is exercised separately by withholding the embedded document.
        driver.set_read_frames(frames.clone());
        let initial = driver
            .snapshot_classified("zoom-probe", SnapshotKind::Actionable, 1, url, DEADLINE)
            .map_err(|e| format!("initial capture: {e:?}"))?;
        let tail = named(&initial, "Event 19999");
        let embedded_tail = named(&initial, "Embedded event 19999");
        for name in ["Populate Event", "Populate Embedded event"] {
            let button = named(&initial, name);
            let frame = button.frame_document.as_ref().unwrap();
            assert!(driver
                .prepare_frame("zoom-probe", frame, DEADLINE)
                .map_err(|e| format!("prepare: {e:?}"))?);
            driver
                .click_classified(
                    "zoom-probe",
                    button.backend_identity.as_ref().unwrap(),
                    1,
                    &frame.origin,
                    button.classification.as_deref().ok(),
                    DEADLINE,
                    &mut |_| {},
                )
                .map_err(|e| format!("populate: {e:?}"))?;
        }
        let frames = driver
            .frame_documents("zoom-probe", DEADLINE)
            .map_err(|e| format!("grown frames: {e:?}"))?;
        driver.set_read_frames(frames.clone());
        let started = Instant::now();
        let full = driver
            .snapshot_classified("zoom-probe", SnapshotKind::Actionable, 1, url, DEADLINE)
            .map_err(|e| format!("bounded full walk: {e:?}"))?;
        let full_ms = started.elapsed().as_millis();
        assert!(full.ax_truncated);
        assert!(!render(&full, &tail, 65536)
            .text
            .contains("Event tail payload"));
        println!("20,000 rows in each of two documents; bounded full walk: {full_ms} ms, {} AX records, late row absent", full.records.len());
        for (reference, payload) in [
            (&tail, "Event tail payload"),
            (&embedded_tail, "Embedded event tail payload"),
        ] {
            let started = Instant::now();
            let zoom = driver
                .snapshot_subtree_classified(
                    "zoom-probe",
                    SnapshotKind::Actionable,
                    reference,
                    1,
                    url,
                    DEADLINE,
                )
                .map_err(|e| format!("subtree zoom: {e:?}"))?;
            let zoom_ms = started.elapsed().as_millis();
            let text = render(&zoom, reference, 65536).text;
            assert!(text.contains(payload), "{text}");
            assert!(
                !text.contains("4111111111111111"),
                "card value escaped masking"
            );
            assert!(
                !zoom.ax_truncated,
                "a small subtree must not inherit whole-page truncation"
            );
            assert!(
                zoom_ms < u128::from(DEADLINE),
                "subtree exceeded the capture budget"
            );
            let small = render(&zoom, reference, 150);
            assert!(
                small.cut_lines > 0,
                "subtree output must still obey its byte cap"
            );
            println!(
                "{}: {zoom_ms} ms, {} AX records, tail present, card masked, output cap respected",
                reference.captured.name,
                zoom.records.len()
            );
        }
        driver.set_read_frames(
            frames
                .iter()
                .filter(|f| f.parent_id.is_none())
                .cloned()
                .collect(),
        );
        let withheld = driver
            .snapshot_subtree_classified(
                "zoom-probe",
                SnapshotKind::Actionable,
                &embedded_tail,
                1,
                url,
                DEADLINE,
            )
            .map_err(|e| format!("withheld embedded zoom: {e:?}"))?;
        assert!(!withheld
            .records
            .iter()
            .any(|r| r.name.starts_with("Embedded event ")));
        println!("withheld embedded frame: no child document content");
        println!("live subtree probe: 4 assertion groups passed");
        Ok(())
    }
}
