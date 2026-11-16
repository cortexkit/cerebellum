//! Both registration paths of the supervised binary, against the real daemon.
//!
//! The daemon starts cerebellum either with a launch nonce (the module dials
//! the daemon and presents the nonce in HELLO) or with a private registration
//! channel it hands over at spawn (`registration_channel: true`). On the channel
//! path every outbound connection cerebellum opens must first present a self
//! claim, which it mints on its own module connection. The claim's answer
//! arrives on the same connection the daemon uses to send `route.bind` and
//! `health.check`, so these tests drive exactly that traffic: head routes opened
//! together under an attested scope, a health probe while their binds are in
//! flight, and a tool call whose display record opens a route of cerebellum's
//! own. Each answer must arrive well inside the daemon's own budget; a module
//! that only answers near the budget is one burst of reconnecting agents away
//! from timing every bind out.
//!
//! Each test boots its own daemon with data, runtime and config homes fenced
//! into a scratch directory, so nothing touches the operator's daemon or homes.
#![cfg(unix)]

#[path = "it/support/hang_guard.rs"]
mod hang_guard;
mod support;
use hang_guard::HANG_GUARD;

use cortexkit_test_support::{fenced_subc_env_dir, ScratchDir};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use std::{fs, path::PathBuf};
use subc_control::{ClientControlRequest, ClientControlResponse, ConsumerIdentity};
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeRecord, ScopeSelector};
use subc_protocol::{BindIdentity, Frame, FrameType, Principal, RouteTarget, PROTOCOL_VERSION};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};

const OWNER: &str = "prefrontal-core";
const DISPLAY: &str = "display-fake";
const SCOPE_REF: &str = "registration-live";
/// The agent the head scope attests, which is also its agent project id.
const AGENT: &str = "registration-live-agent";
/// How many head routes open at once, as agents reconnecting after a restart do.
const HEADS: usize = 4;
/// The daemon allows a module 12 s to acknowledge `route.bind` and 5 s to
/// answer `health.check`. A module serving binds from a free frame loop answers
/// in milliseconds; this bound leaves ample room for a loaded build machine
/// while staying far below the point where queued binds start timing out.
const ANSWER_BUDGET: Duration = Duration::from_secs(2);

async fn connect(connection: &subc_transport::ConnectionInfo) -> TcpStream {
    let endpoint = connection.endpoints.first().expect("an endpoint");
    let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
        .await
        .expect("connect to the daemon");
    authenticate_client(&mut stream, connection, HANG_GUARD)
        .await
        .expect("authenticate");
    stream
}

async fn next_frame(stream: &mut TcpStream) -> Frame {
    timeout(HANG_GUARD, read_frame(stream))
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

/// Send one request on a route and wait for its answer.
async fn route_call(
    client: &mut TcpStream,
    channel: u16,
    epoch: u32,
    corr: u64,
    body: Value,
) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        cerebellum::control_flags(),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    write_frame(client, &frame)
        .await
        .expect("write route request");
    loop {
        let reply = next_frame(client).await;
        if (reply.header.channel, reply.header.corr) == (channel, corr) {
            return reply;
        }
    }
}

fn reserved(module_id: &str) -> Principal {
    Principal::Reserved {
        module_id: module_id.into(),
    }
}

/// A module registered by this test with a nonce the daemon handed a helper.
/// It acknowledges every bind and records each one it receives.
struct Registered {
    writer: mpsc::Sender<Frame>,
    answers: mpsc::Receiver<Frame>,
    binds: tokio::sync::Mutex<mpsc::UnboundedReceiver<Value>>,
}

impl Registered {
    async fn register(
        connection: &subc_transport::ConnectionInfo,
        nonce: &str,
        module_id: &str,
        extra_capability: Option<&str>,
    ) -> Self {
        let mut stream = connect(connection).await;
        let mut manifest = serde_json::to_value(cerebellum::manifest::build(module_id)).unwrap();
        if let Some(capability) = extra_capability {
            manifest["capabilities"]["provides"]
                .as_array_mut()
                .expect("the manifest lists provided capabilities")
                .push(json!(capability));
        }
        if module_id == "ckbus" {
            for role in manifest["provides"].as_array_mut().unwrap() {
                if let Some(operations) = role.get_mut("operations").and_then(Value::as_array_mut) {
                    operations.push(json!({"name":"ckbus.credential","kind":"query"}));
                }
            }
        }
        let hello = json!({
            "manifest": manifest,
            "protocol_ver": PROTOCOL_VERSION,
            "control_ops": ["route.bind", "health.check"],
            "launch_nonce": nonce,
        });
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
            "{module_id}'s HELLO was refused: {}",
            String::from_utf8_lossy(&ack.body)
        );
        let (mut reader, mut writer_half) = tokio::io::split(stream);
        let (writer, mut outgoing) = mpsc::channel::<Frame>(16);
        let (answered, answers) = mpsc::channel::<Frame>(16);
        let (bound, binds) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(frame) = outgoing.recv().await {
                if write_frame(&mut writer_half, &frame).await.is_err() {
                    break;
                }
            }
        });
        let replies = writer.clone();
        tokio::spawn(async move {
            while let Ok(Some(frame)) = read_frame(&mut reader).await {
                match (frame.header.ty, frame.header.channel) {
                    (FrameType::Request, 0) => {
                        let body: Value = serde_json::from_slice(&frame.body).unwrap_or_default();
                        let reply = if body["op"] == "health.check" {
                            json!({"op":"health.check", "status":"ok"})
                        } else {
                            let _ = bound.send(body);
                            json!({"op":"route.bind"})
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
                    (FrameType::Request, _) => {
                        let reply = Frame::build(FrameType::Error, cerebellum::control_flags(),
                            frame.header.channel, frame.header.epoch, frame.header.corr,
                            serde_json::to_vec(&json!({"code":"test_bus_unavailable","message":"no NATS server in the registration fixture"})).unwrap()).unwrap();
                        let _ = replies.send(reply).await;
                    }
                    _ => {}
                }
            }
        });
        Self {
            writer,
            answers,
            binds: tokio::sync::Mutex::new(binds),
        }
    }

    /// Sync the one head scope the routes below open under.
    async fn sync_head_scope(&mut self) {
        let record = ScopeRecord::new(SCOPE_REF, 1, ScopeKind::Head)
            .with_attributes(ScopeAttributes::new().with_agent_id(Some(AGENT.into())));
        let frame = Frame::build(
            FrameType::Request,
            cerebellum::control_flags(),
            0,
            0,
            100,
            serde_json::to_vec(
                &subc_protocol::session::ModuleControlRequestFromModule::ScopeSync {
                    generation: 1,
                    scopes: vec![record],
                },
            )
            .unwrap(),
        )
        .unwrap();
        self.writer.send(frame).await.unwrap();
        let answer = timeout(HANG_GUARD, self.answers.recv())
            .await
            .expect("the sync is answered")
            .expect("owner connection open");
        assert_eq!(
            answer.header.ty,
            FrameType::Response,
            "scope.sync refused: {}",
            String::from_utf8_lossy(&answer.body)
        );
        let body: Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(body["results"][0]["outcome"], "created", "{body}");
    }
}

fn module_binary() -> PathBuf {
    let binary = cortexkit_test_support::ckdev_binary(env!("CARGO_BIN_EXE_ck-cerebellum"));
    support::daemon_binary("ckdev-cerebellum-registration", binary)
}

struct Fixture {
    _directory: ScratchDir,
    daemon: tokio::task::JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>,
    connection: subc_transport::ConnectionInfo,
    owner_nonce: String,
    _owner: Registered,
    display: Registered,
    ckbus: Registered,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.daemon.abort();
    }
}

async fn read_nonce(directory: &std::path::Path, id: &str) -> String {
    timeout(HANG_GUARD, async {
        loop {
            if let Ok(nonce) = fs::read_to_string(directory.join(format!("{id}-nonce"))) {
                if !nonce.is_empty() {
                    break nonce;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the daemon spawns {id}, which hands over its nonce"))
}

impl Fixture {
    async fn start(registration_channel: bool) -> Self {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let directory = ScratchDir::new("cerebellum-registration-live");
        let module_env = support::fenced_module_env(directory.path());
        let data = fenced_subc_env_dir(directory.path(), "XDG_DATA_HOME");
        let config = fenced_subc_env_dir(directory.path(), "XDG_CONFIG_HOME");
        let run = data.join("cortexkit/run");
        // A browser is configured so browser_use is advertised, but its
        // executable does not exist: nothing here may start a real browser.
        fs::create_dir_all(config.join("cortexkit")).unwrap();
        fs::write(
            config.join("cortexkit/cerebellum.jsonc"),
            serde_json::to_vec(&json!({"browser": {
                "executable_path": directory.join("no-browser"), "expected_identity":"test.browser",
                "launch_handshake_deadline_ms":1000, "termination_grace_period_ms":200,
                "browser_idle_timeout_ms":60000, "browser_exit_observation_deadline_ms":1000,
                "navigation_settle_deadline_ms":1000
            }}))
            .unwrap(),
        )
        .unwrap();
        let connection_path = directory.join("subc-connection.json");
        let daemon_path = directory.join("subc.jsonc");
        let mut modules = serde_json::Map::new();
        for id in [OWNER, DISPLAY, "ckbus"] {
            let mut helper_env = module_env.clone();
            helper_env.insert("NONCE_OUT".into(), directory.join(format!("{id}-nonce")));
            modules.insert(
                id.into(),
                json!({"program":support::nonce_holder(), "env":helper_env, "reserved":true}),
            );
        }
        if registration_channel {
            let mut probe_env = module_env.clone();
            probe_env.insert("CEREBELLUM_CLAIM_PROBE".into(), connection_path.clone());
            probe_env.insert(
                "CEREBELLUM_CLAIM_PROBE_DONE".into(),
                directory.join("probe-done"),
            );
            modules.insert("claim-probe".into(), json!({
                "program": support::daemon_binary("ckdev-cerebellum-claim-probe", std::env::current_exe().unwrap()),
                "args":["--exact","claim_consumer_probe","--nocapture","--"],
                "env":probe_env,"reserved":true,"registration_channel":true
            }));
        }
        // This daemon hands every module it starts a registration channel. The
        // channel launch runs cerebellum directly, so it adopts that channel.
        // The nonce launch runs it under a launcher that withholds the channel,
        // as a daemon that offers none would, so it dials the daemon and
        // presents its launch nonce.
        let cerebellum = if registration_channel {
            json!({"program":module_binary(), "env":module_env, "reserved":true,
                "registration_channel":true})
        } else {
            let mut launcher_env = module_env.clone();
            launcher_env.insert("NONCE_LAUNCH_PROGRAM".into(), module_binary());
            json!({"program":support::nonce_launcher(), "env":launcher_env, "reserved":true})
        };
        modules.insert("cerebellum".into(), cerebellum);
        // Head routes carry the agent's project as admission facts, which the
        // daemon accepts only from the configured carrier.
        fs::write(
            &daemon_path,
            serde_json::to_vec(&json!({
                "version":1,
                "admission_facts_carrier_module_id":OWNER,
                "admission_facts_targets":["cerebellum"],
                "modules":modules,
            }))
            .unwrap(),
        )
        .unwrap();
        let daemon_config = subc_daemon::bootstrap::BootstrapConfig::new(&connection_path, 0)
            .with_privacy_trampoline(support::privacy_trampoline())
            .with_daemon_config_path(&daemon_path)
            .unwrap()
            .with_capture_logs_dir(run.join("logs"))
            .with_terminal_journal_path(run.join("terminals.jsonl"))
            .with_live_children_record(run.join("live-children.json"))
            .with_machine_id_path(data.join("cortexkit/machine-id"))
            .with_scope_authority_owners(vec![OWNER.into()]);
        let daemon = tokio::spawn(subc_daemon::bootstrap::run_with_config(daemon_config));
        let connection = timeout(HANG_GUARD, async {
            loop {
                if let Ok(connection) = connection_file::read(&connection_path) {
                    break connection;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the daemon publishes its connection file");
        let owner_nonce = read_nonce(directory.path(), OWNER).await;
        let display_nonce = read_nonce(directory.path(), DISPLAY).await;
        let ckbus_nonce = read_nonce(directory.path(), "ckbus").await;
        let mut owner = Registered::register(&connection, &owner_nonce, OWNER, None).await;
        let display = Registered::register(
            &connection,
            &display_nonce,
            DISPLAY,
            Some(cortexkit_role_tool_display::TOOL_DISPLAY_CAPABILITY),
        )
        .await;
        let ckbus = Registered::register(
            &connection,
            &ckbus_nonce,
            "ckbus",
            Some("caller-attestation/v1"),
        )
        .await;
        if registration_channel {
            // Cerebellum's startup views reconcile may reach the fake ckbus
            // before the probe does. Its route must be claimed too; skip past it.
            let bind = timeout(HANG_GUARD, async {
                loop {
                    let bind = ckbus.binds.lock().await.recv().await.unwrap();
                    if bind["principal"] != serde_json::to_value(reserved("cerebellum")).unwrap() {
                        return bind;
                    }
                    assert_eq!(
                        bind["caller"]["claim"], "own",
                        "cerebellum's startup bus route must present a self claim: {bind}"
                    );
                }
            })
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "probe did not open its claimed route: {error}; {}",
                    fs::read_to_string(run.join("logs/claim-probe.stderr.log")).unwrap_or_default()
                )
            });
            assert_eq!(
                bind["principal"],
                serde_json::to_value(reserved("claim-probe")).unwrap()
            );
            assert_eq!(
                bind["caller"]["claim"], "own",
                "SDK probe must present a self claim: {bind}"
            );
            timeout(HANG_GUARD, async {
                while !directory.join("probe-done").exists() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("probe passed its pre-install refusal and post-install connection checks");
        }
        owner.sync_head_scope().await;
        let fixture = Self {
            _directory: directory,
            daemon,
            connection,
            owner_nonce,
            _owner: owner,
            display,
            ckbus,
        };
        fixture.await_registration(registration_channel).await;
        fixture
    }

    /// Wait until the daemon lists cerebellum, then check which path it used.
    async fn await_registration(&self, registration_channel: bool) {
        timeout(HANG_GUARD, async {
            loop {
                let mut probe = connect(&self.connection).await;
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
        })
        .await
        .expect("supervised cerebellum registers");
        let mut probe = connect(&self.connection).await;
        let provenance = client_request(
            &mut probe,
            4,
            ClientControlRequest::SupervisorProvenance {
                module_id: Some("cerebellum".into()),
            },
        )
        .await;
        let body: Value = serde_json::from_slice(&provenance.body).unwrap();
        let entry = body["modules"]
            .as_array()
            .and_then(|modules| {
                modules
                    .iter()
                    .find(|module| module["module_id"] == "cerebellum")
            })
            .unwrap_or_else(|| panic!("provenance lists cerebellum: {body}"));
        let expected = if registration_channel {
            "channel"
        } else {
            "nonce"
        };
        assert_eq!(
            entry["registration"], expected,
            "the daemon registered cerebellum on the path this test configured: {entry}"
        );
    }

    /// Open a head route to cerebellum as the scope's owner, the way an agent's
    /// session does, and return how long the daemon took to answer.
    async fn open_head(&self, session: usize) -> (Duration, Result<(TcpStream, u16, u32), String>) {
        let mut client = connect(&self.connection).await;
        let started = Instant::now();
        let reply = client_request(
            &mut client,
            7,
            ClientControlRequest::RouteOpen {
                busy_refusals: None,
                role_versions: None,
                target: RouteTarget::ToolProvider {
                    module_id: "cerebellum".into(),
                },
                identity: BindIdentity::new("registration-live", format!("session-{session}")),
                consumer_identity: Some(ConsumerIdentity {
                    module_id: OWNER.into(),
                    launch_nonce: self.owner_nonce.clone(),
                }),
                consumer_capabilities: Some(vec!["elicitation".into()]),
                admission_facts: Some(json!({
                    "agentProjectId": AGENT,
                    "sessionKind": "primary",
                })),
                scope: Some(ScopeSelector::new(reserved(OWNER), SCOPE_REF, Some(1))),
            },
        )
        .await;
        let elapsed = started.elapsed();
        if reply.header.ty != FrameType::Response {
            return (
                elapsed,
                Err(String::from_utf8_lossy(&reply.body).into_owned()),
            );
        }
        match serde_json::from_slice::<ClientControlResponse>(&reply.body).unwrap() {
            ClientControlResponse::RouteOpen {
                route_channel,
                route_epoch,
                ..
            } => (elapsed, Ok((client, route_channel, route_epoch))),
            other => (
                elapsed,
                Err(format!("unexpected route.open reply {other:?}")),
            ),
        }
    }

    /// Ask the daemon to send cerebellum `health.check` now.
    async fn health(&self) -> (Duration, Value) {
        let mut client = connect(&self.connection).await;
        let started = Instant::now();
        let reply = client_request(
            &mut client,
            9,
            ClientControlRequest::SupervisorHealthProbe {
                module_id: "cerebellum".into(),
            },
        )
        .await;
        let elapsed = started.elapsed();
        let mut body: Value = serde_json::from_slice(&reply.body).unwrap_or_default();
        body["frame"] = json!(format!("{:?}", reply.header.ty));
        (elapsed, body)
    }
}

/// Binds, health and an outbound route, all answered promptly.
async fn serves_binds_health_and_outbound_routes(registration_channel: bool) {
    let fixture = std::sync::Arc::new(Fixture::start(registration_channel).await);
    let path = if registration_channel {
        "channel"
    } else {
        "nonce"
    };

    // Head routes open together while the daemon probes health.
    let mut opens = tokio::task::JoinSet::new();
    for session in 0..HEADS {
        let fixture = std::sync::Arc::clone(&fixture);
        opens.spawn(async move { fixture.open_head(session).await });
    }
    let probe = {
        let fixture = std::sync::Arc::clone(&fixture);
        tokio::spawn(async move {
            // Let the binds reach the module first, so the probe queues behind them.
            sleep(Duration::from_millis(100)).await;
            fixture.health().await
        })
    };
    let mut routes = Vec::new();
    while let Some(opened) = opens.join_next().await {
        let (elapsed, result) = opened.unwrap();
        let route = result
            .unwrap_or_else(|error| panic!("a head route.open failed after {elapsed:?}: {error}"));
        eprintln!("{path} launch: head route.bind acknowledged in {elapsed:?}");
        assert!(
            elapsed < ANSWER_BUDGET,
            "cerebellum acknowledged a head route.bind only after {elapsed:?}"
        );
        routes.push(route);
    }
    let (elapsed, health) = probe.await.unwrap();
    eprintln!("{path} launch: health.check during the binds answered in {elapsed:?}");
    assert_eq!(health["frame"], "Response", "{health}");
    assert!(
        elapsed < ANSWER_BUDGET,
        "health.check answered only after {elapsed:?}: {health}"
    );

    // Health once more after the binds, as the daemon's periodic probe does.
    let (elapsed, health) = fixture.health().await;
    assert_eq!(health["frame"], "Response", "{health}");
    assert!(
        elapsed < ANSWER_BUDGET,
        "health.check answered only after {elapsed:?}: {health}"
    );

    // A tool call on one head route. After its reply, cerebellum opens a route
    // of its own to the display module to record the call. The display module
    // sees the bind only if cerebellum's outbound connection was admitted as
    // cerebellum: with a self claim on the channel path, with its launch nonce
    // on the nonce path.
    let (client, channel, epoch) = routes.first_mut().expect("a head route");
    let catalog = route_call(
        client,
        *channel,
        *epoch,
        100,
        json!({"name":"tool.catalog", "arguments":{}}),
    )
    .await;
    let catalog: cortexkit_role_tool_provider::catalog::CatalogAnswer =
        serde_json::from_slice(&catalog.body).expect("tool.catalog answers a catalog");
    let browser = catalog
        .tools
        .iter()
        .find(|tool| tool.name == "browser_use")
        .expect("browser_use is advertised");
    let pin = cortexkit_role_tool_provider::call::SchemaPin::new(
        &browser.name,
        &browser.schema_digest,
        browser.semantics,
    )
    .encode()
    .unwrap();
    let started = Instant::now();
    let reply = route_call(
        client,
        *channel,
        *epoch,
        101,
        json!({
            "name": "browser_use",
            "arguments": {"action": "status"},
            "call_key": "registration-live-status",
            "schema_pin": pin,
        }),
    )
    .await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "browser_use status: {}",
        String::from_utf8_lossy(&reply.body)
    );
    assert!(
        started.elapsed() < ANSWER_BUDGET,
        "browser_use status answered only after {:?}",
        started.elapsed()
    );
    let bind = timeout(HANG_GUARD, async {
        fixture.display.binds.lock().await.recv().await
    })
    .await
    .expect("cerebellum opens a display route after the tool call")
    .expect("display module connection open");
    assert_eq!(
        bind["principal"],
        serde_json::to_value(reserved("cerebellum")).unwrap(),
        "the daemon stamped cerebellum's own outbound route as cerebellum: {bind}"
    );
    let bus_bind = timeout(HANG_GUARD, fixture.ckbus.binds.lock().await.recv())
        .await
        .expect("publisher opens the SDK credential route")
        .expect("fake ckbus remains registered");
    assert_eq!(
        bus_bind["principal"],
        serde_json::to_value(reserved("cerebellum")).unwrap()
    );
    if registration_channel {
        assert_eq!(
            bus_bind["caller"]["claim"], "own",
            "production bus consumer must present a self claim: {bus_bind}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_launch_answers_binds_health_and_opens_claimed_routes() {
    serves_binds_health_and_outbound_routes(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nonce_launch_answers_binds_health_and_opens_attested_routes() {
    serves_binds_health_and_outbound_routes(false).await;
}

/// This exact test is also the daemon-launched, process-isolated SDK probe.
#[test]
fn claim_consumer_probe() {
    let Some(connection_path) = std::env::var_os("CEREBELLUM_CLAIM_PROBE") else {
        return;
    };
    let done =
        std::env::var_os("CEREBELLUM_CLAIM_PROBE_DONE").expect("parent supplies completion path");
    let failure = PathBuf::from(&done).with_extension("failed");
    std::panic::set_hook(Box::new(move |info| {
        let _ = fs::write(&failure, info.to_string());
    }));
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        use std::sync::Arc;
        use subc_client_rs::registration::{self, ClaimError, ClaimMinter};
        use subc_protocol::claim::{ClaimMintReply, ClaimMintRequest};
        struct Minter(tokio::sync::Mutex<Box<dyn subc_client_rs::ModuleStream>>);
        #[subc_client_rs::async_trait]
        impl ClaimMinter for Minter {
            async fn mint(&self, request: ClaimMintRequest) -> Result<ClaimMintReply, ClaimError> {
                let mut stream = self.0.lock().await;
                let frame = Frame::build(FrameType::Request, cerebellum::control_flags(), 0, 0, 900,
                    serde_json::to_vec(&request).unwrap()).unwrap();
                write_frame(&mut *stream, &frame).await.map_err(|_| ClaimError::Unavailable)?;
                let reply = read_frame(&mut *stream).await.map_err(|_| ClaimError::Unavailable)?.ok_or(ClaimError::Unavailable)?;
                assert_eq!((reply.header.channel, reply.header.corr), (0, 900), "unexpected frame while minting");
                assert_eq!(reply.header.ty, FrameType::Response, "claim refused: {}", String::from_utf8_lossy(&reply.body));
                serde_json::from_slice(&reply.body).map_err(|_| ClaimError::Protocol)
            }
        }
        let mut stream = registration::adopt_channel().unwrap().expect("probe must be channel launched");
        let connection_path = PathBuf::from(connection_path);
        let connection = connection_file::read(&connection_path).unwrap();
        authenticate_client(&mut stream, &connection, HANG_GUARD).await.unwrap();
        assert!(registration::adopt_channel().is_err(), "second take must refuse");
        let before = subc_client_rs::SubcConsumer::connect(&connection_path, Default::default()).await;
        assert!(matches!(before, Err(subc_client_rs::consumer::ConsumerError::Connect { ref endpoint, ref source, .. })
            if endpoint == "claim binding" && matches!(source.get_ref().and_then(|error| error.downcast_ref::<ClaimError>()), Some(ClaimError::Unavailable))),
            "a pre-minter consumer must refuse specifically for the missing claim owner");
        let hello = Frame::build(FrameType::Hello, cerebellum::control_flags(), 0, 0, 1,
            serde_json::to_vec(&json!({"manifest":cerebellum::manifest::build("claim-probe"),"protocol_ver":PROTOCOL_VERSION,"control_ops":["health.check"]})).unwrap()).unwrap();
        write_frame(&mut stream, &hello).await.unwrap();
        let ack = read_frame(&mut stream).await.unwrap().unwrap();
        assert_eq!(ack.header.ty, FrameType::HelloAck);
        registration::install_claim_minter(Arc::new(Minter(tokio::sync::Mutex::new(stream)))).unwrap();
        let consumer = subc_client_rs::SubcConsumer::connect(&connection_path, Default::default()).await.expect("post-install SDK consumer presents claim");
        let result = consumer.call(RouteTarget::ManagementSurface { module_id:"ckbus".into() }, BindIdentity::new("probe", "claim-probe"),
            serde_json::to_vec(&json!({"method":"ckbus.credential","params":{}})).unwrap(), Default::default()).await;
        assert!(matches!(result, Err(subc_client_rs::consumer::CallError::Module(ref body)) if body.code == "test_bus_unavailable"), "fixture must receive the claimed SDK call: {result:?}");
        fs::write(done, b"passed").unwrap();
    });
}
