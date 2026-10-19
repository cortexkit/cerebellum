// Separate binary: changes HOME, XDG homes and launch-nonce environment variables.
//! A session scope ending, against the real daemon.
//!
//! The frame-level tests in `browser_session_wire.rs` play the daemon
//! themselves. This one proves the same path end to end with the in-process
//! daemon the other live tests boot: cerebellum's `scope.describe` goes out on
//! its own module connection and the daemon's real answer comes back.
//!
//! The daemon admits a scope sync only from the connection that presented the
//! owner's launch nonce, which only a process the daemon spawned is given. So
//! the owner (`prefrontal-core`, which the daemon authorizes by default) is
//! configured as a module whose test helper writes its nonce to a file
//! and stays alive, and this test registers and syncs as that module with
//! the nonce. The same nonce, presented on a client connection, opens routes
//! as the owner.
//!
//! Cerebellum runs in this process through `run_entry_prepared_for_test`,
//! with one fake browser seeded for the scope's conversation, so the test can
//! read its sessions and grants directly. Its homes are pointed at a scratch
//! directory before anything runs, so it writes nothing into the real ones;
//! that is also why this file holds a single test.
//!
//! What it cannot show is the daemon answering `not_live` for an owner that
//! has not synced since a restart: that needs the daemon to restart, which
//! also ends cerebellum's connection. The frame-level test
//! `a_non_definitive_answer_leaves_the_browser_the_grants_and_the_question`
//! covers that answer.
#![cfg(unix)]

mod support;

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::browser_session::{
    BrowserSessionLauncher, BrowserSessionTerminalOutcome, CleanupStage, LaunchedBrowser,
    OwnedBrowserProcess, ProcessControlFailure, SessionCleanup, SessionCleanupOutcome,
};
use cerebellum::management::ManagementPlane;
use cerebellum::scope_watch::{ScopeKey, ScopeRevocation};
use cerebellum::BrowserConfig;
use cerebellum_core::identity::{AcceptedBindFacts, ProfileDisposition};
use serde_json::{json, Value};
use subc_control::{ClientControlRequest, ClientControlResponse, ConsumerIdentity};
use subc_protocol::scope::{ScopeKind, ScopeRecord, ScopeSelector};
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};
use subc_protocol::{
    BindIdentity, Frame, FrameType, ModuleHelloBody, Principal, RouteTarget, PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const OWNER: &str = "prefrontal-core";
const CONVERSATION: &str = "live-scope-conversation";
const SCOPE_REF: &str = "live-s-1";

/// Generous: it only decides how long a broken boot takes to fail.
const STARTUP: Duration = Duration::from_secs(60);

fn browser_config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 1_000,
        termination_grace_period_ms: 200,
        // Long enough that idle expiry never closes the browser first.
        browser_idle_timeout_ms: 600_000,
        browser_exit_observation_deadline_ms: 1_000,
        navigation_settle_deadline_ms: 1_000,
    }
}

struct RefusingLauncher;

impl BrowserSessionLauncher for RefusingLauncher {
    fn launch(&self, _: &AcceptedBindFacts, _: &str) -> Result<LaunchedBrowser, Value> {
        Err(json!({"outcome": "launch_refused_in_test"}))
    }
}

struct QuietProcess;

impl OwnedBrowserProcess for QuietProcess {
    fn generation_matches(&self) -> bool {
        true
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(true)
    }
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
}

/// Records how the session ended, which is what the launch journal would.
struct OutcomeCleanup {
    ended: Arc<Mutex<Option<BrowserSessionTerminalOutcome>>>,
    outcome: Option<BrowserSessionTerminalOutcome>,
}

impl SessionCleanup for OutcomeCleanup {
    fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
        self.outcome = Some(outcome);
    }
    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        *self.ended.lock().unwrap() = self.outcome;
        Ok(SessionCleanupOutcome::Complete)
    }
}

/// What the test reads from the module running in this process.
struct ModuleView {
    sessions: cerebellum::browser_session::BrowserSessions,
    management: Arc<ManagementPlane>,
    scopes: Arc<ScopeRevocation>,
}

async fn connect(connection: &subc_transport::ConnectionInfo) -> TcpStream {
    let endpoint = connection.endpoints.first().expect("an endpoint");
    let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
        .await
        .expect("connect to the daemon");
    authenticate_client(&mut stream, connection, Duration::from_secs(5))
        .await
        .expect("authenticate");
    stream
}

async fn next_frame(stream: &mut TcpStream) -> Frame {
    timeout(Duration::from_secs(10), read_frame(stream))
        .await
        .expect("the daemon answers")
        .expect("readable frame")
        .expect("connection open")
}

async fn client_request(stream: &mut TcpStream, corr: u64, request: ClientControlRequest) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        cerebellum::control_flags(),
        0,
        0,
        corr,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.expect("write request");
    loop {
        let reply = next_frame(stream).await;
        if reply.header.channel == 0 && reply.header.corr == corr {
            return reply;
        }
    }
}

/// Open a route to cerebellum as the owner, under the live scope.
async fn open_scoped_route(
    connection: &subc_transport::ConnectionInfo,
    nonce: &str,
) -> (TcpStream, u16, u32) {
    let mut client = connect(connection).await;
    let reply = client_request(
        &mut client,
        7,
        ClientControlRequest::RouteOpen {
            role_versions: None,
            target: RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            identity: BindIdentity::new("/tmp", "scope-live", CONVERSATION),
            consumer_identity: Some(ConsumerIdentity {
                module_id: OWNER.into(),
                launch_nonce: nonce.into(),
            }),
            consumer_capabilities: Some(vec!["elicitation".into()]),
            admission_facts: None,
            scope: Some(ScopeSelector::new(
                Principal::Reserved {
                    module_id: OWNER.into(),
                },
                SCOPE_REF,
                Some(1),
            )),
        },
    )
    .await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "route.open under the scope failed: {}",
        String::from_utf8_lossy(&reply.body)
    );
    match serde_json::from_slice::<ClientControlResponse>(&reply.body).unwrap() {
        ClientControlResponse::RouteOpen {
            route_channel,
            route_epoch,
        } => (client, route_channel, route_epoch),
        other => panic!("expected route.open, got {other:?}"),
    }
}

/// The owner's registered module connection: sends syncs and answers the
/// daemon's own channel-0 requests so the daemon keeps it registered.
struct Owner {
    writer: mpsc::Sender<Frame>,
    answers: mpsc::Receiver<Frame>,
    next_corr: u64,
}

impl Owner {
    async fn register(connection: &subc_transport::ConnectionInfo, nonce: &str) -> Self {
        let mut stream = connect(connection).await;
        let hello = ModuleHelloBody {
            manifest: cerebellum::manifest::build(OWNER),
            protocol_ver: PROTOCOL_VERSION,
            control_ops: Some(vec!["route.bind".into(), "health.check".into()]),
            launch_nonce: Some(nonce.into()),
        };
        let frame = Frame::build(
            FrameType::Hello,
            cerebellum::control_flags(),
            0,
            0,
            1,
            serde_json::to_vec(&hello).unwrap(),
        )
        .unwrap();
        write_frame(&mut stream, &frame).await.expect("HELLO");
        let ack = next_frame(&mut stream).await;
        assert_eq!(
            ack.header.ty,
            FrameType::HelloAck,
            "the owner's HELLO was refused: {}",
            String::from_utf8_lossy(&ack.body)
        );
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (writer, mut outgoing) = mpsc::channel::<Frame>(16);
        let (answered, answers) = mpsc::channel::<Frame>(16);
        tokio::spawn(async move {
            while let Some(frame) = outgoing.recv().await {
                if write_frame(&mut write_half, &frame).await.is_err() {
                    return;
                }
            }
        });
        let replies = writer.clone();
        tokio::spawn(async move {
            while let Ok(Some(frame)) = read_frame(&mut read_half).await {
                match (frame.header.ty, frame.header.channel) {
                    (FrameType::Request, 0) => {
                        let body: Value = serde_json::from_slice(&frame.body).unwrap_or_default();
                        let reply = match body["op"].as_str() {
                            Some("health.check") => {
                                json!({"op": "health.check", "status": "healthy"})
                            }
                            _ => json!({"op": "route.bind"}),
                        };
                        let reply = Frame::build(
                            FrameType::Response,
                            cerebellum::control_flags(),
                            0,
                            0,
                            frame.header.corr,
                            serde_json::to_vec(&reply).unwrap(),
                        )
                        .unwrap();
                        let _ = replies.send(reply).await;
                    }
                    (FrameType::Response | FrameType::Error, 0) => {
                        let _ = answered.send(frame).await;
                    }
                    _ => {}
                }
            }
        });
        Self {
            writer,
            answers,
            next_corr: 100,
        }
    }

    async fn sync(&mut self, generation: u64, scopes: Vec<ScopeRecord>) -> Value {
        self.next_corr += 1;
        let corr = self.next_corr;
        let frame = Frame::build(
            FrameType::Request,
            cerebellum::control_flags(),
            0,
            0,
            corr,
            serde_json::to_vec(&ModuleControlRequestFromModule::ScopeSync { generation, scopes })
                .unwrap(),
        )
        .unwrap();
        self.writer.send(frame).await.unwrap();
        let answer = timeout(Duration::from_secs(10), self.answers.recv())
            .await
            .expect("the sync is answered")
            .expect("owner connection open");
        assert_eq!(answer.header.corr, corr);
        assert_eq!(
            answer.header.ty,
            FrameType::Response,
            "scope.sync refused: {}",
            String::from_utf8_lossy(&answer.body)
        );
        let reply: ModuleControlResponseToModule = serde_json::from_slice(&answer.body).unwrap();
        serde_json::to_value(reply).unwrap()
    }
}

fn scope_record() -> ScopeRecord {
    ScopeRecord::new(SCOPE_REF, 1, ScopeKind::Head)
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    timeout(Duration::from_secs(10), async {
        while !done() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scope_end_closes_its_browser_and_questions_without_minting_unattested_grants() {
    let directory = cortexkit_test_support::ScratchDir::new("cerebellum-scope-live");
    let data = cortexkit_test_support::fenced_subc_env_dir(directory.path(), "XDG_DATA_HOME");
    // Before anything reads them: the module in this process resolves its
    // data and config homes from these, and must not present a nonce of its
    // own.
    for (name, path) in cortexkit_test_support::fenced_subc_daemon_env(directory.path()) {
        std::env::set_var(name, path);
    }
    std::env::remove_var("SUBC_LAUNCH_NONCE");
    std::env::remove_var("SUBC_LAUNCH_NONCE_FD");

    // The daemon, with the owner configured as a helper that hands the test
    // its launch nonce. The daemon passes the nonce only on a pipe at
    // descriptor 3 (named by SUBC_LAUNCH_NONCE_FD); there is no environment
    // copy, so the helper reads the pipe.
    let nonce_file = directory.join("owner-nonce");
    let mut module_env = support::fenced_module_env(directory.path());
    module_env.insert("NONCE_OUT".into(), nonce_file.clone());
    let connection_file_path = directory.join("subc-connection.json");
    let daemon_config_path = directory.join("subc.jsonc");
    fs::write(
        &daemon_config_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "modules": {
                OWNER: {
                    "program": support::nonce_holder(),
                    "env": module_env,
                    "reserved": true,
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let run = data.join("cortexkit/run");
    let daemon_config = subc_daemon::bootstrap::BootstrapConfig::new(&connection_file_path, 0)
        .with_privacy_trampoline(support::privacy_trampoline())
        .with_daemon_config_path(&daemon_config_path)
        .expect("load the daemon configuration")
        .with_live_children_record(run.join("live-children.json"))
        .with_machine_id_path(data.join("cortexkit/machine-id"))
        .with_capture_logs_dir(run.join("logs"))
        .with_terminal_journal_path(run.join("terminals.jsonl"))
        .with_scope_authority_owners(vec![OWNER.to_string()]);
    let daemon = tokio::spawn(subc_daemon::bootstrap::run_with_config(daemon_config));
    let connection = timeout(STARTUP, async {
        loop {
            if let Ok(connection) = connection_file::read(&connection_file_path) {
                break connection;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the daemon publishes its connection file");
    let nonce = timeout(STARTUP, async {
        loop {
            if let Ok(nonce) = fs::read_to_string(&nonce_file) {
                if !nonce.is_empty() {
                    break nonce;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the daemon spawns the owner, which hands over its nonce");

    // The owner registers and syncs its session.
    let mut owner = Owner::register(&connection, &nonce).await;
    let synced = owner.sync(1, vec![scope_record()]).await;
    assert_eq!(synced["results"][0]["outcome"], "created", "{synced}");

    // Cerebellum, in this process, with one fake browser open for the
    // session's conversation.
    let config = browser_config();
    let ended = Arc::new(Mutex::new(None));
    let view: Arc<Mutex<Option<ModuleView>>> = Arc::new(Mutex::new(None));
    let module = {
        let (config, ended, view) = (config.clone(), Arc::clone(&ended), Arc::clone(&view));
        let connection_file_path: PathBuf = connection_file_path.clone();
        tokio::spawn(cerebellum::run_entry_prepared_for_test(
            connection_file_path,
            config.clone(),
            move |planes| {
                planes.launch_service = Some(Arc::new(RefusingLauncher));
                // Long enough that no interval re-ask happens during the test,
                // so the end below is found by the route close alone.
                planes.scopes = Arc::new(ScopeRevocation::with_intervals(
                    Duration::from_secs(600),
                    Duration::from_secs(5),
                ));
                let _ = planes.sessions.acquire_launch_slot(CONVERSATION);
                planes
                    .sessions
                    .establish_ready(
                        CONVERSATION,
                        ProfileDisposition::Disposable,
                        &config,
                        planes.lease_clock.as_ref(),
                        Box::new(QuietProcess),
                        Box::new(OutcomeCleanup {
                            ended,
                            outcome: None,
                        }),
                    )
                    .expect("seed the session's browser");
                *view.lock().unwrap() = Some(ModuleView {
                    sessions: planes.sessions.clone(),
                    management: Arc::clone(&planes.management),
                    scopes: Arc::clone(&planes.scopes),
                });
            },
        ))
    };
    eventually("cerebellum to start", || view.lock().unwrap().is_some()).await;
    let ModuleView {
        sessions,
        management,
        scopes,
    } = view.lock().unwrap().take().unwrap();

    // The route opens only once cerebellum is registered.
    let (first_client, _, _) = timeout(STARTUP, async {
        loop {
            let mut probe = connect(&connection).await;
            let catalog = client_request(
                &mut probe,
                3,
                ClientControlRequest::CatalogList {
                    module_id: Some("cerebellum".into()),
                },
            )
            .await;
            if String::from_utf8_lossy(&catalog.body).contains("\"cerebellum\"") {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        open_scoped_route(&connection, &nonce).await
    })
    .await
    .expect("a route under the scope opens");

    // This fixture's scope names no admitted agent. Answering its helper
    // question cannot mint a row, but scope teardown must still close its
    // browser and any pending questions.
    let granted = management
        .browser_grant_question_for_test(
            CONVERSATION,
            vec!["https://granted.example".into()],
            Vec::new(),
        )
        .await;
    assert_eq!(
        management
            .settle_browser_grant_outcome(
                &granted.ask_id,
                Some(&cerebellum::cingulate_client::desk::Ending::Granted {
                    choice_id: "allow_30m".into()
                })
            )
            .await,
        cerebellum::management::BrowserGrantSettlement::UnrecognizedAnswer,
        "an unattested scope was never offered the granting option"
    );
    assert!(management
        .agent_grants()
        .live_rows(None, management.agent_grants().now_ms())
        .unwrap()
        .is_empty());
    let open = management
        .browser_grant_question_for_test(
            CONVERSATION,
            vec!["https://asked.example".into()],
            Vec::new(),
        )
        .await;
    let key = ScopeKey {
        owner: Principal::Reserved {
            module_id: OWNER.into(),
        },
        scope_ref: SCOPE_REF.into(),
        scope_epoch: 1,
    };

    // An ordinary close: the client goes away while the scope stays live. The
    // daemon answers `live` at the same epoch, which ends nothing.
    drop(first_client);
    eventually("the close to be noted", || scopes.is_watching(&key)).await;
    eventually("the describe to be answered", || {
        scopes.control.outstanding() == 0
    })
    .await;
    sleep(Duration::from_millis(300)).await;
    assert!(
        sessions.has_open_session(CONVERSATION),
        "an ordinary close closed the browser"
    );
    assert!(management
        .agent_grants()
        .live_rows(None, management.agent_grants().now_ms())
        .unwrap()
        .is_empty());
    assert!(management.browser_grant_question_open(&open.ask_id).await);
    assert!(
        scopes.is_watching(&key),
        "a live scope with an open browser stopped being watched"
    );
    assert_eq!(*ended.lock().unwrap(), None);

    // The session reconnects, then its owner ends it. The daemon drains the
    // route, cerebellum asks, and the daemon says the scope ended.
    let (_second_client, _, _) = open_scoped_route(&connection, &nonce).await;
    let synced = owner.sync(2, Vec::new()).await;
    assert_eq!(
        synced["ended"],
        json!([{"ref": SCOPE_REF, "scope_epoch": 1}]),
        "{synced}"
    );
    eventually("the scope's browser to close", || {
        ended.lock().unwrap().is_some()
    })
    .await;
    assert_eq!(
        *ended.lock().unwrap(),
        Some(BrowserSessionTerminalOutcome::ScopeRevoked)
    );
    assert!(!sessions.has_open_session(CONVERSATION));
    assert!(management
        .agent_grants()
        .live_rows(None, management.agent_grants().now_ms())
        .unwrap()
        .is_empty());
    assert!(!management.browser_grant_question_open(&open.ask_id).await);
    assert!(
        !management
            .settle_browser_grant(&open.ask_id, Some(&json!({"decision": "allow_30m"})))
            .await,
        "a late answer to the ended session's question was applied"
    );
    assert!(!scopes.is_watching(&key));

    module.abort();
    daemon.abort();
}
