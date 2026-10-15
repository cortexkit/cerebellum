use super::*;
use cerebellum::authorization::{ActionGrant, GrantStore, Severity};
use cerebellum::browser::navigation::{BrowserSnapshotObservation, CdpNavigationDriver};
use cerebellum::browser::{BrowserPlane, Tracker};
use cerebellum::browser_launch::ExecutableIdentityCheckpoints;
use cerebellum::browser_session::{
    BrowserScrollTarget, BrowserSessionLauncher, CleanupStage, LaunchedBrowser,
    NavigationDriveError, NavigationWait, OwnedBrowserProcess, ProcessControlFailure,
    SessionCleanup, SessionCleanupOutcome,
};
use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
use cerebellum::snapshot_store::{CommittedDocument, FrameDocument, RefRecord, SnapshotKind};
use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::{health::HealthState, identity::AcceptedBindFacts};
use cerebellum_macos::ReleasedChild;
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};

type Child = Arc<Mutex<Option<ReleasedChild>>>;
struct Process {
    driver: CdpNavigationDriver<Pipe>,
    child: Child,
    session: Arc<Mutex<Option<String>>>,
}

fn observed(
    label: &str,
    result: Result<BrowserSnapshotObservation, NavigationDriveError>,
) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
    if let Ok(observation) = &result {
        println!(
            "{label}: {} records, {} refs, truncated={}; last records: {:?}",
            observation.records.len(),
            observation.refs.len(),
            observation.ax_truncated,
            &observation.records[observation.records.len().saturating_sub(5)..]
        );
    }
    result
}

impl OwnedBrowserProcess for Process {
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
    fn committed_document(
        &mut self,
        context: &str,
        deadline: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        self.driver.committed_document(context, deadline)
    }
    fn frame_documents(
        &mut self,
        context: &str,
        deadline: u64,
    ) -> Result<Vec<FrameDocument>, NavigationDriveError> {
        let frames = self.driver.frame_documents(context, deadline)?;
        *self.session.lock().unwrap() = frames
            .iter()
            .find(|f| f.parent_id.is_none())
            .map(|f| f.session_id.clone());
        Ok(frames)
    }
    fn set_read_frames(&mut self, frames: Vec<FrameDocument>) -> Result<(), NavigationDriveError> {
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
    fn snapshot_classified(
        &mut self,
        context: &str,
        kind: SnapshotKind,
        epoch: u64,
        url: &str,
        deadline: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        observed(
            "capture",
            self.driver
                .snapshot_classified(context, kind, epoch, url, deadline),
        )
    }
    fn snapshot_subtree_classified(
        &mut self,
        context: &str,
        kind: SnapshotKind,
        reference: &RefRecord,
        epoch: u64,
        url: &str,
        deadline: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        observed(
            "zoom capture",
            self.driver
                .snapshot_subtree_classified(context, kind, reference, epoch, url, deadline),
        )
    }
    fn scroll(
        &mut self,
        context: &str,
        target: &BrowserScrollTarget,
        deadline: u64,
    ) -> Result<(), NavigationDriveError> {
        self.driver.scroll(context, target, deadline)
    }
    fn generation_matches(&self) -> bool {
        self.child.lock().unwrap().is_some()
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        if let Some(child) = self.child.lock().unwrap().take() {
            child
                .terminate_and_reap()
                .map_err(|_| ProcessControlFailure)?;
        }
        Ok(())
    }
    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(self.child.lock().unwrap().is_none())
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
    fn launch(&self, _: &AcceptedBindFacts, _: &str) -> Result<LaunchedBrowser, Value> {
        Ok(LaunchedBrowser {
            process: Box::new(
                self.0
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| json!({"outcome":"internal_error"}))?,
            ),
            cleanup: Box::new(Cleanup),
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::AfterExecOnly,
        })
    }
}

async fn invoke(
    planes: &Planes,
    corr: &mut u64,
    action: &str,
    arguments: Value,
) -> Result<Value, String> {
    *corr += 1;
    let mut arguments = arguments.as_object().unwrap().clone();
    arguments.insert("action".into(), json!(action));
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        *corr,
        serde_json::to_vec(&json!({"name":"browser_use","arguments":arguments})).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    cerebellum::handle_tool_request_for_test_with_planes(frame, &tx, planes)
        .await
        .map_err(|e| e.to_string())?;
    let frame = rx.recv().await.ok_or("missing wire reply")?;
    let reply: Value = serde_json::from_slice(&frame.body).map_err(|e| e.to_string())?;
    if !matches!(
        reply["outcome"].as_str(),
        Some("ok" | "launched" | "closed")
    ) {
        return Err(format!("{action}: {reply}"));
    }
    Ok(reply)
}
fn reference(reply: &Value, label: &str) -> Result<String, String> {
    reply["state_text"]
        .as_str()
        .ok_or("missing state_text")?
        .lines()
        .filter(|line| line.contains(label))
        .find_map(|line| {
            line.split_whitespace()
                .next()
                .filter(|word| {
                    word.starts_with('e') && word[1..].chars().all(|c| c.is_ascii_digit())
                })
                .map(str::to_string)
        })
        .ok_or_else(|| format!("missing ref for {label}: {reply}"))
}

pub(super) async fn exercise(pipe: Pipe, url: &str, child: Child) -> Result<(), String> {
    let mut observer = pipe.duplicate();
    let config = BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 10_000,
        termination_grace_period_ms: 1_000,
        browser_idle_timeout_ms: 60_000,
        browser_exit_observation_deadline_ms: 1_000,
        navigation_settle_deadline_ms: DEADLINE,
    };
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config),
        JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(Launcher(Mutex::new(Some(Process {
        driver: CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default()),
        child,
        session: observer.session.clone(),
    })))));
    let origin = url.trim_end_matches('/');
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            planes.lease_clock.clone(),
            DEADLINE,
        )
        .with_result_schema_enforcement(
            cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
        )
        .with_grants_installed(GrantStore::new([ActionGrant::new(
            "fixture",
            1,
            "test-session",
            Severity::new(4, false, false),
            [origin],
        )])),
    );
    let mut corr = 0;
    let launched = invoke(&planes, &mut corr, "launch", json!({})).await?;
    let result = async {
        invoke(&planes, &mut corr, "navigate", json!({"url":url,"intent":"open local fixture","wait":"settle","severity":{"tier":3,"credential":false,"financial":false}})).await?;
        let counts_before = observer.counts.lock().unwrap().clone();
        let timing_start = observer.timings.lock().unwrap().completed.len();
        let start = Instant::now();
        let outline = invoke(&planes, &mut corr, "snapshot", json!({"max_bytes":8000})).await?;
        let counts = observer.counts.lock().unwrap().iter().map(|(method, count)| (method.clone(), count-counts_before.get(method).unwrap_or(&0))).collect::<BTreeMap<_,_>>();
        println!("capture elapsed: {} ms; CDP commands: {counts:?}", start.elapsed().as_millis());
        let timings = observer.timings.lock().unwrap().completed[timing_start..].to_vec();
        let wire_ms = timings.iter().map(|(_, ms)| ms).sum::<u128>();
        for (method, ms) in timings { println!("capture command {method}: {ms} ms"); }
        println!("capture CDP total: {wire_ms} ms; non-CDP work: {} ms", start.elapsed().as_millis().saturating_sub(wire_ms));
        let text = outline["state_text"].as_str().ok_or("missing outline")?;
        println!("OUTLINE:\n{text}");
        let main = reference(&outline,"main Branch protection")?;
        let mut checks = vec![("settings_outline_main_before_nav", text.find("main Branch protection").zip(text.find("navigation Settings")).is_some_and(|(a,b)| a<b))];
        let role = invoke(&planes,&mut corr,"snapshot",json!({"role_filter":["checkbox"],"max_bytes":8000})).await?;
        println!("ROLE FILTER: {role}");
        let target = reference(&role,"Require status checks to pass before merging")?;
        checks.push(("settings_role_filter_finds_below_fold", role["state_text"].as_str().unwrap().contains("Require status checks to pass before merging")));
        let filtered = invoke(&planes,&mut corr,"snapshot",json!({"text_filter":"Require status checks","max_bytes":8000})).await?;
        println!("TEXT FILTER: {filtered}");
        checks.push(("settings_text_filter_finds_below_fold", reference(&filtered,"Require status checks to pass before merging")? == target));
        let zoom = invoke(&planes,&mut corr,"snapshot",json!({"zoom":main,"max_bytes":8000})).await?;
        println!("MAIN ZOOM: {zoom}");
        checks.push(("settings_zoom_main_lists_checkbox", reference(&zoom,"Require status checks to pass before merging").is_ok_and(|found| found==target) && zoom["state_text"].as_str().unwrap().contains(&format!("zoom {main}"))));
        let session = observer.session.lock().unwrap().clone().ok_or("missing main session")?;
        // A background page may suspend requestAnimationFrame indefinitely.
        // Synchronous geometry forces layout without requiring an active window.
        let rect = "({rect:document.getElementById('target').getBoundingClientRect().toJSON(),width:innerWidth,height:innerHeight,scrollY,scrollHeight:document.scrollingElement.scrollHeight,clientHeight:document.scrollingElement.clientHeight})";
        let before = observer.evaluate(&session,1_000_001,rect)?;
        println!("checkbox rect before scroll: {before}");
        checks.push(("settings_target_starts_below_fold", before["rect"]["top"].as_f64().unwrap() > before["height"].as_f64().unwrap()));
        invoke(&planes,&mut corr,"scroll",json!({"direction":"down","amount":400})).await?;
        let down = observer.evaluate(&session,1_000_002,rect)?;
        println!("page scroll down 400 from top: {down}");
        invoke(&planes,&mut corr,"scroll",json!({"direction":"up","amount":400})).await?;
        let up = observer.evaluate(&session,1_000_003,rect)?;
        println!("page scroll up 400 to top: {up}");
        checks.push(("settings_scroll_page_moves_viewport", before["scrollY"].as_f64()==Some(0.0) && down["scrollY"].as_f64()==Some(400.0) && up["scrollY"].as_f64()==Some(0.0)));
        invoke(&planes,&mut corr,"scroll",json!({"ref":target})).await?;
        let after = observer.evaluate(&session,1_000_004,rect)?;
        println!("checkbox rect after scroll: {after}");
        let inside = after["rect"]["top"].as_f64().unwrap()>=0.0 && after["rect"]["bottom"].as_f64().unwrap()<=after["height"].as_f64().unwrap()
            && after["rect"]["left"].as_f64().unwrap()>=0.0 && after["rect"]["right"].as_f64().unwrap()<=after["width"].as_f64().unwrap();
        checks.push(("settings_scroll_ref_brings_checkbox_into_viewport",inside));
        let dom = invoke(&planes,&mut corr,"snapshot",json!({"mode":"dom_full","max_bytes":8000})).await?;
        let text = dom["state_text"].as_str().ok_or("missing DOM body")?;
        println!("dom_full: {} bytes, starts {:?}",text.len(),&text[..text.len().min(100)]);
        checks.push(("settings_dom_full_starts_at_body",text.contains("<body") && !text.contains("<head>")));
        for (name,passed) in &checks { println!("{name}: {}", if *passed {"PASS"} else {"FAIL"}); }
        println!("{} checks, {} failed",checks.len(),checks.iter().filter(|(_,passed)| !passed).count());
        if checks.iter().all(|(_,passed)| *passed) { Ok(()) } else { Err("settings fixture regressions failed".into()) }
    }.await;
    let closed = invoke(
        &planes,
        &mut corr,
        "close",
        json!({"browser_session_id":launched["browser_session_id"]}),
    )
    .await;
    result.and(closed.map(|_| ()))
}
