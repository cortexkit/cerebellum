//! Headless production-driver probe for same-process and out-of-process frames.
//! Run: cargo run -p cerebellum --example browser_iframes
//! Only loopback servers and a disposable /tmp Chrome profile are used; no
//! journals are opened. The public browser tool does not expose browser.type.
//! The probe feeds the live card-field ref into the existing typing executor
//! and asserts refusal before authorization or text insertion.
#[cfg(not(target_os = "macos"))]
fn main() {
    println!("skipped: the barred Chrome launcher requires macOS");
}
#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = probe::run() {
        eprintln!("PROBE FAILED: {error}");
        std::process::exit(1);
    }
}
#[cfg(target_os = "macos")]
mod probe {
    use cerebellum::browser::navigation::CdpNavigationDriver;
    use cerebellum::browser::Tracker;
    use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
    use cerebellum::browser_session::{BrowserClickPosition, NavigationWait};
    use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
    use cerebellum::snapshot_store::SnapshotKind;
    use std::ffi::OsString;
    use std::io::{self, Read, Write};
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    const DEADLINE: u64 = 10_000;
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
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(PipeRead::WouldBlock),
                Err(e) => Err(e),
            }
        }
    }
    fn serve(listener: TcpListener, top: String) {
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0u8; 4096];
                let n = stream.read(&mut request).unwrap_or(0);
                let path = String::from_utf8_lossy(&request[..n]);
                let body = if path.starts_with("GET /same ") {
                    "<button type='button' onclick=\"this.textContent='Same button '+(this.dataset.n=+(this.dataset.n||0)+1)\">Same button</button><a href='/same'>Same link</a>".to_string()
                } else if path.starts_with("GET /cross ") {
                    "<button type='button' onclick=\"this.textContent='Cross button '+(this.dataset.n=+(this.dataset.n||0)+1)\">Cross button</button><a href='/cross#link'>Cross link</a>".to_string()
                } else if path.starts_with("GET /payment ") {
                    "<form><input aria-label='Card number' autocomplete='cc-number'><button type='submit'>Pay</button></form>".to_string()
                } else {
                    top.clone()
                };
                let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = stream.write_all(reply.as_bytes());
            }
        });
    }
    pub fn run() -> Result<(), String> {
        let first = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let second = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let first_port = first.local_addr().unwrap().port();
        let second_port = second.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{first_port}/");
        let page = format!("<iframe style='position:absolute;left:0;top:0;width:300px;height:100px' src='/same'></iframe><iframe style='position:absolute;left:320px;top:0;width:300px;height:100px' src='http://localhost:{second_port}/cross'></iframe><iframe style='position:absolute;left:0;top:130px;width:300px;height:100px' src='http://localhost:{second_port}/payment'></iframe><div id='shadow' role='button' style='position:absolute;left:320px;top:130px;padding:12px'></div><script>window.getComputedStyle=()=>({{width:'1px',height:'1px',boxSizing:'content-box'}});shadow.attachShadow({{mode:'open'}}).innerHTML='<span>Shadow button</span>';shadow.onclick=()=>shadow.shadowRoot.querySelector('span').textContent='Shadow button '+(shadow.dataset.n=+(shadow.dataset.n||0)+1);</script>");
        serve(first, page);
        serve(second, String::new());
        let profile = PathBuf::from(format!("/tmp/ck-browser-iframes-{}", std::process::id()));
        std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
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
    fn readable_frames(
        grants: &cerebellum::authorization::GrantStore,
        frames: &[cerebellum::snapshot_store::FrameDocument],
    ) -> Vec<cerebellum::snapshot_store::FrameDocument> {
        frames
            .iter()
            .filter(|frame| {
                grants
                    .authorize(
                        cerebellum::authorization::AuthorizationRequest::snapshot(
                            "probe", &frame.url, "probe",
                        ),
                        &frame.origin,
                    )
                    .ok()
                    .is_some_and(|decision| grants.commit(&decision).is_ok())
            })
            .cloned()
            .collect()
    }

    fn exercise(pipe: Pipe, url: &str) -> Result<(), String> {
        let mut driver =
            CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());
        driver
            .navigate(
                "probe",
                url,
                NavigationWait::Settle,
                DEADLINE,
                &mut Tracker::default(),
            )
            .map_err(|e| format!("navigate: {e:?}"))?;
        let frames = driver
            .frame_documents("probe", DEADLINE)
            .map_err(|e| format!("frames: {e:?}"))?;
        println!("frame documents: {:?}", frames);
        let main = frames
            .iter()
            .find(|f| f.parent_id.is_none())
            .ok_or("missing main frame")?;
        assert!(
            frames
                .iter()
                .any(|f| f.origin.contains("localhost") && f.session_id != main.session_id),
            "cross-site frame must be an attached OOPIF"
        );
        println!("cross-site frame has independent CDP session: PASS");
        use cerebellum::authorization::{
            ActionGrant, AuthorizationRequest, GrantStore, Severity, COMPOSE,
        };
        let top_grant = ActionGrant::new(
            "top",
            1,
            "probe",
            Severity::new(COMPOSE, false, false),
            [&main.origin],
        );
        let top_grants = GrantStore::new([top_grant.clone()]);
        driver.set_read_frames(readable_frames(&top_grants, &frames));
        let redacted = driver
            .snapshot_classified("probe", SnapshotKind::Actionable, 1, url, DEADLINE)
            .map_err(|e| format!("redacted snapshot: {e:?}"))?;
        assert!(redacted.records.iter().any(|n| n.name == "Same button"));
        assert!(!redacted
            .records
            .iter()
            .any(|n| n.name == "Cross button" || n.name == "Card number"));
        assert!(redacted
            .records
            .iter()
            .any(|n| n.name.contains("localhost") && n.name.contains("read grant")));
        println!("ungranted cross-site content withheld, exact origin grant named: PASS");
        let denied_full = driver
            .snapshot_classified("probe", SnapshotKind::DomFull, 1, url, DEADLINE)
            .map_err(|e| format!("denied dom_full: {e:?}"))?
            .dom_text
            .ok_or("missing denied dom_full")?;
        assert!(!denied_full.contains("Cross button") && !denied_full.contains("cc-number"));
        println!("dom_full withholds ungranted cross-origin document bodies: PASS");
        let cross_origin = frames
            .iter()
            .find(|frame| frame.origin.contains("localhost"))
            .unwrap()
            .origin
            .clone();
        let grants = GrantStore::new([
            top_grant,
            ActionGrant::new(
                "cross",
                1,
                "probe",
                Severity::new(COMPOSE, false, false),
                [&cross_origin],
            ),
        ]);
        driver.set_read_frames(readable_frames(&grants, &frames));
        let snapshot = driver
            .snapshot_classified("probe", SnapshotKind::Actionable, 1, url, DEADLINE)
            .map_err(|e| format!("snapshot: {e:?}"))?;
        for name in [
            "Same button",
            "Cross button",
            "Card number",
            "Shadow button",
        ] {
            assert!(
                snapshot.records.iter().any(|n| n.name == name),
                "missing {name}"
            );
        }
        println!("granted snapshot walks same-process, OOPIF and payment frames: PASS");
        for name in ["Same link", "Cross link"] {
            let reference = snapshot
                .refs
                .iter()
                .find(|reference| reference.captured.name == name)
                .ok_or("missing frame link")?;
            let record = reference
                .classification
                .as_deref()
                .map_err(|e| e.to_string())?;
            assert_eq!(record.required_tier, 1);
            assert_eq!(
                record.activation_destination_origin.as_deref(),
                Some(reference.frame_document.as_ref().unwrap().origin.as_str())
            );
        }
        println!("relative links classify navigation against their own frame origin: PASS");
        let owner = snapshot
            .refs
            .iter()
            .find(|reference| {
                reference
                    .backend_identity
                    .as_ref()
                    .is_some_and(|identity| identity.frame_id == main.frame_id)
                    && reference.captured.role == "Iframe"
                    && snapshot.records.iter().any(|record| {
                        record.reference.as_ref() == Some(&reference.captured.reference)
                    })
            })
            .ok_or("missing iframe owner ref")?;
        let zoom = cerebellum::browser::state_text::render(
            &cerebellum::browser::state_text::RenderInput {
                records: &snapshot.records,
                facts: &snapshot.facts,
                page_url: url,
                snapshot_id: "0123456789abcdef0123456789abcdef",
                zoom: Some(cerebellum::browser::state_text::Zoom {
                    requested: &owner.captured.reference,
                    target: Some(&owner.captured.reference),
                }),
                max_bytes: 65536,
            },
        );
        assert!(
            zoom.text.contains("button") || zoom.text.contains("Card number"),
            "iframe zoom lost its children: {}",
            zoom.text
        );
        println!("iframe outline zoom includes nested frame controls: PASS");
        let full = driver
            .snapshot_classified("probe", SnapshotKind::DomFull, 1, url, DEADLINE)
            .map_err(|e| format!("dom_full: {e:?}"))?;
        let full = full.dom_text.ok_or("missing dom_full")?;
        assert!(
            full.contains("Same button")
                && full.contains("Cross button")
                && full.contains("cc-number")
        );
        println!("dom_full includes granted same-process and OOPIF documents: PASS");
        for name in ["Same button", "Cross button", "Shadow button"] {
            let reference = snapshot
                .refs
                .iter()
                .find(|r| r.captured.name == name && r.captured.role.to_lowercase() == "button")
                .ok_or(format!("missing button ref {name}"))?;
            let frame = reference
                .frame_document
                .as_ref()
                .ok_or("ref missing frame metadata")?;
            let record = reference
                .classification
                .as_deref()
                .map_err(|e| e.to_string())?;
            let decision = grants
                .authorize(
                    AuthorizationRequest::click(
                        "probe",
                        Severity::new(COMPOSE, false, false),
                        "ref-click",
                        "probe",
                        record,
                    ),
                    &frame.origin,
                )
                .map_err(|e| format!("ref authorization: {e:?}"))?;
            grants
                .commit(&decision)
                .map_err(|e| format!("ref commitment: {e:?}"))?;
            assert!(driver
                .prepare_frame("probe", frame, DEADLINE)
                .map_err(|e| format!("prepare: {e:?}"))?);
            driver
                .click_classified(
                    "probe",
                    reference.backend_identity.as_ref().unwrap(),
                    1,
                    &frame.origin,
                    reference.classification.as_deref().ok(),
                    DEADLINE,
                    &mut |_| {},
                )
                .map_err(|e| format!("ref click {name}: {e:?}"))?;
            let after = driver
                .snapshot_classified("probe", SnapshotKind::Actionable, 1, url, DEADLINE)
                .map_err(|e| format!("after click: {e:?}"))?;
            assert!(
                after
                    .records
                    .iter()
                    .any(|node| node.name == format!("{name} 1")),
                "{name} did not receive the ref click"
            );
            println!("ref click {name}, observed click counter 1: PASS");
        }
        for (name, x, y) in [("Same button", 40., 25.), ("Cross button", 360., 25.)] {
            let position = BrowserClickPosition { x_css: x, y_css: y };
            let record = driver
                .classify_point("probe", position, 1, url, DEADLINE)
                .map_err(|e| format!("point: {e:?}"))?
                .map_err(|e| e.to_string())?;
            let frame = driver.point_frame_document().ok_or("point missing frame")?;
            let expected_ref = snapshot
                .refs
                .iter()
                .find(|r| r.captured.name == name && r.captured.role.to_lowercase() == "button")
                .ok_or("missing addressed ref")?;
            assert_eq!(
                record.node_identity,
                expected_ref.backend_identity.as_ref().unwrap().digest(),
                "point hit a different element than {name}"
            );
            let decision = grants
                .authorize(
                    AuthorizationRequest::click_point(
                        "probe",
                        Severity::new(COMPOSE, false, false),
                        "point-click",
                        "probe",
                        &record,
                    ),
                    &frame.origin,
                )
                .map_err(|e| format!("point authorization: {e:?}"))?;
            grants
                .commit(&decision)
                .map_err(|e| format!("point commitment: {e:?}"))?;
            assert!(driver
                .prepare_frame("probe", &frame, DEADLINE)
                .map_err(|e| format!("prepare: {e:?}"))?);
            driver
                .click_point_classified(
                    "probe",
                    position,
                    1,
                    &frame.origin,
                    &record,
                    DEADLINE,
                    &mut |_| {},
                )
                .map_err(|e| format!("point click {name}: {e:?}"))?;
            let after = driver
                .snapshot_classified("probe", SnapshotKind::Actionable, 1, url, DEADLINE)
                .map_err(|e| format!("after point click: {e:?}"))?;
            println!(
                "after point {name}: {:?}",
                after
                    .records
                    .iter()
                    .filter(|node| node.role.to_lowercase() == "button")
                    .map(|node| &node.name)
                    .collect::<Vec<_>>()
            );
            assert!(
                after
                    .records
                    .iter()
                    .any(|node| node.name == format!("{name} 2")),
                "{name} did not receive the point click"
            );
            println!("point click {name}, observed click counter 2: PASS");
        }
        println!("isolated-world frame geometry ignores tampered page getters: PASS");
        let payment = snapshot
            .refs
            .iter()
            .find(|r| r.captured.name == "Card number")
            .ok_or("missing payment ref")?;
        let record = payment.classification.as_ref().map_err(|e| e.to_string())?;
        assert!(record
            .target_autocomplete_tokens
            .iter()
            .any(|t| t == "cc-number"));
        let pay = snapshot
            .refs
            .iter()
            .find(|r| r.captured.name == "Pay")
            .ok_or("missing submit ref")?
            .classification
            .as_ref()
            .map_err(|e| e.to_string())?;
        assert!(pay.financial && pay.required_tier == 4);
        assert!(grants
            .authorize(
                AuthorizationRequest::click(
                    "probe",
                    Severity::new(4, false, true),
                    "payment",
                    "probe",
                    pay
                ),
                &cross_origin
            )
            .is_err());
        println!("cross-site card field and submit retain financial classification: PASS");
        use cerebellum::browser_type::{
            BrowserTypeExecutor, BrowserTypeRequest, BrowserTypeResult, DeterministicTypeFixture,
            RecordingAuthorizer, RecordingJournal, TypeGeometry, TypeTarget,
        };
        let mut target = TypeTarget {
            node_identity: String::new(),
            document_epoch: 1,
            form_owner: None,
            autocomplete_tokens: vec![],
            password: false,
            writable_text_control: true,
            editable_region: false,
            disabled: false,
            readonly: false,
            inert: false,
            form_descendants: vec![],
            geometry: TypeGeometry::default(),
        };
        target
            .apply_snapshot_ref(payment)
            .map_err(|e| e.to_string())?;
        let mut typing = DeterministicTypeFixture::new(target.clone());
        let mut journal = RecordingJournal::default();
        let mut authorizer = RecordingAuthorizer::allowing();
        let result = BrowserTypeExecutor::execute(
            &mut typing,
            &mut journal,
            &mut authorizer,
            &target,
            &BrowserTypeRequest::new("e1", "0123456789abcdef0123456789abcdef", "4111111111111111"),
        );
        assert_eq!(
            result,
            BrowserTypeResult::InvalidRequest {
                field: "text".into(),
                reason_code: "credential_input_unsupported".into()
            }
        );
        assert!(!typing.inserted() && authorizer.calls == 0);
        println!(
            "type executor refuses live cross-site card field before authorization/input: PASS"
        );
        println!(
            "production-driver assertions: 15 groups passed; production browser.type route absent"
        );
        Ok(())
    }
}
