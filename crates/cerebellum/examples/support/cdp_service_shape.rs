use super::*;
use cerebellum::browser::BrowserPlane;
use cerebellum::browser_config::BrowserConfig;
use cerebellum::browser_session::{BrowserSessionLauncher, CleanupStage, LaunchedBrowser, SessionCleanup, SessionCleanupOutcome};
use cerebellum::authorization::{ActionGrant, GrantStore, Severity};
use cerebellum::{JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use cerebellum_core::identity::AcceptedBindFacts;
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};

struct Cleanup;
impl SessionCleanup for Cleanup {
    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> { Ok(SessionCleanupOutcome::Complete) }
}
struct Launcher(Mutex<Option<Box<dyn OwnedBrowserProcess>>>, Arc<Mutex<Option<String>>>);
impl BrowserSessionLauncher for Launcher {
    fn launch(&self, accepted: &AcceptedBindFacts, _: &str) -> Result<LaunchedBrowser, Value> {
        *self.1.lock().unwrap() = Some(accepted.identity.conversation_key.clone());
        Ok(LaunchedBrowser { process: self.0.lock().unwrap().take().ok_or_else(|| json!({"outcome":"internal_error"}))?, cleanup: Box::new(Cleanup), executable_identity_checkpoints: cerebellum::browser_launch::ExecutableIdentityCheckpoints::AfterExecOnly })
    }
}
fn request(corr: u64, action: &str, arguments: Value) -> Frame {
    let mut arguments = arguments.as_object().unwrap().clone();
    arguments.insert("action".into(), json!(action));
    Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false), 9, 3, corr, serde_json::to_vec(&json!({"name":"browser_use","arguments":arguments})).unwrap()).unwrap()
}
async fn invoke(planes: &Planes, corr: &mut u64, action: &str, args: Value) -> Result<Value, String> {
    *corr += 1;
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    cerebellum::handle_tool_request_for_test_with_planes(request(*corr, action, args), &tx, planes).await.map_err(|e| e.to_string())?;
    let reply = rx.recv().await.ok_or("missing reply")?;
    serde_json::from_slice(&reply.body).map_err(|e| e.to_string())
}
fn summary(reply: &Value) -> Value {
    json!({"outcome":reply["outcome"],"reason_code":reply["detail"]["reason_code"],"step":reply["detail"]["step"],
        "state_bytes":reply["state_text"].as_str().map(str::len),"snapshot_id_present":reply["snapshot_id"].is_string()})
}
fn main_ref(reply: &Value) -> Option<String> {
    reply["state_text"].as_str()?.lines().filter(|line| line.split_whitespace().any(|word| word == "main"))
        .find_map(|line| line.split_whitespace().find(|word| word.starts_with('e') && word[1..].chars().all(|c| c.is_ascii_digit()) && word.len() > 1).map(str::to_owned))
}
fn reset_meter(meter: &Mutex<Meter>) {
    let mut meter = meter.lock().unwrap();
    meter.measuring = true;
    meter.measurement_start = Some(Instant::now());
    meter.counts = Counts::default();
}
fn counts(meter: &Mutex<Meter>) -> Value {
    let meter = meter.lock().unwrap();
    json!({"bytes":meter.counts.bytes,"events":meter.counts.events.values().sum::<usize>(),"unknown_replies":meter.counts.unknown_responses,"first_response":meter.counts.first_response})
}

pub(super) fn run(process: Box<dyn OwnedBrowserProcess>, server: &Server, fixture: Arc<Fixture>, key: String, meter: Arc<Mutex<Meter>>) -> Result<(), String> {
    let enabled = std::env::var("CK_CDP_SERVICE").as_deref() == Ok("1");
    let config = BrowserConfig { executable_path: None, expected_identity: None, launch_handshake_deadline_ms: 10_000,
        termination_grace_period_ms: 1_000, browser_idle_timeout_ms: 600_000, browser_exit_observation_deadline_ms: 1_000,
        navigation_settle_deadline_ms: DEADLINE };
    let mut planes = Planes::with_browser_config_journaling(Arc::new(HealthState::new()), Some(config), JournalPersistence::Isolated);
    planes.sessions = planes.sessions.clone().with_continuous_servicing(enabled);
    let probe_route = Arc::new(Mutex::new(None));
    planes.launch_service = Some(Arc::new(Launcher(Mutex::new(Some(process)), probe_route.clone())));
    let local = format!("http://{}", server.address);
    planes.browser = Arc::new(BrowserPlane::with_session_gate(planes.sessions.clone(), planes.lease_clock.clone(), DEADLINE)
        .with_result_schema_enforcement(cerebellum::computer_capability::ResultSchemaEnforcement::Withhold)
        .with_grants_installed(GrantStore::new([ActionGrant::new("isolated-live-probe", 1, "test-session", Severity::new(4, false, false), ["https://github.com", "https://en.wikipedia.org", local.as_str()])])));
    tokio::runtime::Runtime::new().map_err(|e| e.to_string())?.block_on(async {
        let mut corr = 0;
        let start = Instant::now();
        let launched = invoke(&planes, &mut corr, "launch", json!({})).await?;
        println!("{}", json!({"live_shape":true,"continuously_serviced":enabled,"action":"launch","ms":start.elapsed().as_millis(),"reply":summary(&launched)}));
        if launched["outcome"] != "launched" { return Err(format!("launch: {launched}")); }
        let route = probe_route.lock().unwrap().clone().ok_or("missing probe route")?;
        let result = async {
            let mut checks_ok = true;
            for (url, filter) in [("https://github.com/rust-lang/rust/issues/25860", "soundness"), ("https://en.wikipedia.org/wiki/Rust_(programming_language)", "Rust")] {
                let start = Instant::now();
                let navigation = invoke(&planes, &mut corr, "navigate", json!({"url":url,"intent":"measure public page reads","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}})).await?;
                println!("{}", json!({"live_shape":true,"continuously_serviced":enabled,"url":url,"action":"navigate","ms":start.elapsed().as_millis(),"reply":summary(&navigation)}));
                checks_ok &= navigation["outcome"] == "ok";
                for idle in [0, 60] {
                    let before = planes.sessions.connection_observation_for_test(&route, thread_cpu_ns);
                    tokio::time::sleep(Duration::from_secs(idle)).await;
                    let after = planes.sessions.connection_observation_for_test(&route, thread_cpu_ns);
                    let cpu_ns = before.as_ref().zip(after.as_ref()).and_then(|(a, b)| Some(b["thread_cpu_ns"].as_u64()?.saturating_sub(a["thread_cpu_ns"].as_u64()?)));
                    reset_meter(&meter);
                    let start = Instant::now();
                    let outline = invoke(&planes, &mut corr, "snapshot", json!({"max_bytes":8000})).await?;
                    let elapsed = start.elapsed().as_millis();
                    let main = main_ref(&outline);
                    checks_ok &= outline["outcome"] == "ok" && main.is_some();
                    println!("{}", json!({"live_shape":true,"continuously_serviced":enabled,"url":url,"idle_seconds":idle,"action":"snapshot","ms":elapsed,"reply":summary(&outline),"main_ref_found":main.is_some(),"wire":counts(&meter),"worker_before":before,"worker_after":after,"idle_cpu_ns":cpu_ns}));
                    if let Some(main) = main {
                        reset_meter(&meter);
                        let start = Instant::now();
                        let zoom = invoke(&planes, &mut corr, "snapshot", json!({"zoom":main,"max_bytes":8000})).await?;
                        checks_ok &= zoom["outcome"] == "ok";
                        println!("{}", json!({"live_shape":true,"continuously_serviced":enabled,"url":url,"idle_seconds":idle,"action":"zoom_main","ms":start.elapsed().as_millis(),"reply":summary(&zoom),"wire":counts(&meter)}));
                    } else {
                        println!("{}", json!({"live_shape":true,"continuously_serviced":enabled,"url":url,"idle_seconds":idle,"action":"zoom_main","skipped":"outline did not expose a main ref"}));
                    }
                    reset_meter(&meter);
                    let start = Instant::now();
                    let filtered = invoke(&planes, &mut corr, "snapshot", json!({"text_filter":filter,"max_bytes":8000})).await?;
                    let found = filtered["state_text"].as_str().is_some_and(|text| text.contains(filter));
                    checks_ok &= filtered["outcome"] == "ok" && found;
                    println!("{}", json!({"live_shape":true,"continuously_serviced":enabled,"url":url,"idle_seconds":idle,"action":"text_filter","ms":start.elapsed().as_millis(),"reply":summary(&filtered),"filter_found":found,"wire":counts(&meter)}));
                }
            }
            if enabled { cancel_firehose(&planes, &mut corr, &route, &local, fixture, key, meter).await?; }
            if enabled && !checks_ok { Err("one or more continuously serviced live-shape checks failed; see JSON rows".into()) } else { Ok(()) }
        }.await;
        let closed = invoke(&planes, &mut corr, "close", json!({"browser_session_id":launched["browser_session_id"]})).await?;
        println!("{}", json!({"live_shape":true,"continuously_serviced":enabled,"action":"close","reply":summary(&closed)}));
        result
    })
}

async fn cancel_firehose(planes: &Planes, corr: &mut u64, route: &str, local: &str, fixture: Arc<Fixture>, key: String, meter: Arc<Mutex<Meter>>) -> Result<(), String> {
    let url = format!("{local}/busy?key={key}&firehose=1");
    let navigation = invoke(planes, corr, "navigate", json!({"url":url,"intent":"measure cancellation against local CDP traffic","wait":"none","severity":{"tier":1,"credential":false,"financial":false}})).await?;
    if navigation["outcome"] != "ok" { return Err(format!("firehose navigation: {}", summary(&navigation))); }
    reset_meter(&meter);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let traffic_before = counts(&meter);
    let commands = meter.lock().unwrap().commands_sent;
    *corr += 1;
    let call = request(*corr, "snapshot", json!({"max_bytes":8000}));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    cerebellum::handle_frame_for_test(call.clone(), &tx, planes).await.map_err(|e| e.to_string())?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while meter.lock().unwrap().commands_sent == commands {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.map_err(|_| "snapshot never reached the real CDP pipe during firehose")?;
    let cancel = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Cancel, call.header.flags, call.header.channel, call.header.epoch, call.header.corr, vec![]).unwrap();
    let started = Instant::now();
    cerebellum::handle_frame_for_test(cancel, &tx, planes).await.map_err(|e| e.to_string())?;
    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.map_err(|_| "cancellation reply timed out")?.ok_or("missing cancellation reply")?;
    let terminal_ms = started.elapsed().as_millis();
    let reply: Value = serde_json::from_slice(&reply.body).map_err(|e| e.to_string())?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while planes.sessions.execution_quarantine(route).is_some() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.map_err(|_| "cancelled worker did not acknowledge cleanup")?;
    let acknowledged_ms = started.elapsed().as_millis();
    let traffic_at_ack = counts(&meter);
    fixture.stopped.store(true, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let next = invoke(planes, corr, "snapshot", json!({"max_bytes":8000})).await?;
    println!("{}", json!({"live_shape":true,"continuously_serviced":true,"action":"cancel_firehose","terminal_ms":terminal_ms,"worker_ack_ms":acknowledged_ms,"reply":summary(&reply),"cancel_code":reply["code"],"traffic_before_cancel":traffic_before,"traffic_at_ack":traffic_at_ack,"next_snapshot":summary(&next)}));
    if reply["outcome"] != "cancelled" && reply["code"] != "cancelled" { return Err("snapshot completed before the cancel or returned another terminal outcome".into()); }
    if next["outcome"] != "ok" { return Err("session was not healthy after firehose cancellation".into()); }
    Ok(())
}
