//! Flow admission and consent over real daemon routes to the supervised binary.
#![cfg(unix)]

use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subc_control::{ClientControlRequest, ClientControlResponse, ConsumerIdentity};
use subc_protocol::scope::{ScopeAttributes, ScopeCarrier, ScopeKind, ScopeRecord, ScopeSelector};
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};
use subc_protocol::{
    BindIdentity, Frame, FrameType, ModuleHelloBody, Principal, RouteTarget, PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};

const OWNER: &str = "prefrontal-core";
const AGENT: &str = "flow-live-agent";
const STARTUP: Duration = Duration::from_secs(60);
static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn connect(connection: &subc_transport::ConnectionInfo) -> TcpStream {
    let endpoint = connection.endpoints.first().unwrap();
    let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
        .await
        .unwrap();
    authenticate_client(&mut stream, connection, Duration::from_secs(5))
        .await
        .unwrap();
    stream
}

async fn next_frame(stream: &mut TcpStream) -> Frame {
    timeout(Duration::from_secs(10), read_frame(stream))
        .await
        .expect("daemon answers")
        .unwrap()
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
    write_frame(stream, &frame).await.unwrap();
    loop {
        let reply = next_frame(stream).await;
        assert_ne!(
            reply.header.ty,
            FrameType::Request,
            "unexpected reverse request: {}",
            String::from_utf8_lossy(&reply.body)
        );
        if reply.header.channel == 0 && reply.header.corr == corr {
            return reply;
        }
    }
}

/// A connection attested with the nonce from the daemon's supervised shell.
struct Owner {
    writer: mpsc::Sender<Frame>,
    answers: mpsc::Receiver<Frame>,
}

impl Owner {
    async fn register(
        connection: &subc_transport::ConnectionInfo,
        nonce: &str,
        module_id: &str,
    ) -> Self {
        let mut stream = connect(connection).await;
        let hello = ModuleHelloBody {
            manifest: cerebellum::manifest::build(module_id),
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
        write_frame(&mut stream, &frame).await.unwrap();
        let ack = next_frame(&mut stream).await;
        assert_eq!(
            ack.header.ty,
            FrameType::HelloAck,
            "{}",
            String::from_utf8_lossy(&ack.body)
        );
        let (mut reader, mut writer_half) = tokio::io::split(stream);
        let (writer, mut outgoing) = mpsc::channel::<Frame>(16);
        let (answered, answers) = mpsc::channel::<Frame>(16);
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
                        let body: Value = serde_json::from_slice(&frame.body).unwrap();
                        let reply = if body["op"] == "health.check" {
                            json!({"op":"health.check", "status":"healthy"})
                        } else {
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
                    _ => {}
                }
            }
        });
        Self { writer, answers }
    }

    async fn sync(&mut self, carrier: &str) {
        let record = ScopeRecord {
            scope_ref: "flow-live".into(),
            scope_epoch: 1,
            kind: ScopeKind::Head,
            parent: None,
            child_owners: vec![],
            carriers: vec![ScopeCarrier {
                principal: reserved(carrier),
                targets: Some(vec!["cerebellum".into()]),
            }],
            attributes: ScopeAttributes {
                agent_id: Some(AGENT.into()),
                delegates: true,
                flow_id: Some("flow-live-1".into()),
            },
        };
        let frame = Frame::build(
            FrameType::Request,
            cerebellum::control_flags(),
            0,
            0,
            100,
            serde_json::to_vec(&ModuleControlRequestFromModule::ScopeSync {
                generation: 1,
                scopes: vec![record],
            })
            .unwrap(),
        )
        .unwrap();
        self.writer.send(frame).await.unwrap();
        let answer = timeout(Duration::from_secs(10), self.answers.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            answer.header.ty,
            FrameType::Response,
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
        let reply: ModuleControlResponseToModule = serde_json::from_slice(&answer.body).unwrap();
        let body = serde_json::to_value(reply).unwrap();
        assert_eq!(body["results"][0]["outcome"], "created", "{body}");
        eprintln!("scope.sync: {body}");
    }
}

fn reserved(module_id: &str) -> Principal {
    Principal::Reserved {
        module_id: module_id.into(),
    }
}

fn module_binary() -> PathBuf {
    let binary = std::env::var_os("CEREBELLUM_FLOW_E2E_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ck-cerebellum")));
    let binary = fs::canonicalize(binary).expect("flow test module binary exists");
    eprintln!("flow e2e binary: {}", binary.display());
    binary
}

struct Fixture {
    directory: PathBuf,
    computer_tools: Vec<String>,
    daemon: tokio::task::JoinHandle<Result<(), subc_daemon::bootstrap::BootstrapError>>,
    connection: subc_transport::ConnectionInfo,
    nonce: String,
    _owner: Owner,
    _carrier: Owner,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.daemon.abort();
        // Keep failed fixtures for diagnosis; the supervisor owns child cleanup.
        if !std::thread::panicking() {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

impl Fixture {
    async fn start(carrier: &str, standing: bool) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "cerebellum-flow-live-{}-{stamp}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let home = directory.join("home");
        let data = home.join(".local/share");
        let config = home.join(".config");
        let runtime = home.join("run");
        let run = data.join("cortexkit/run");
        for path in [&home, &data, &config, &runtime, &run] {
            fs::create_dir_all(path).unwrap();
        }
        let browser_marker = directory.join("browser-launched");
        // An invalid executable is intentional: even the standing-grant control
        // must never start the operator's Chrome or open a real browser profile.
        fs::create_dir_all(config.join("cortexkit")).unwrap();
        fs::write(
            config.join("cortexkit/cerebellum.jsonc"),
            serde_json::to_vec(&json!({"browser": {
                "executable_path": browser_marker, "expected_identity":"test.browser",
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
        for id in [OWNER, carrier] {
            modules.insert(id.into(), json!({"program":"/bin/sh", "args":["-c", "cat <&3 > \"$NONCE_OUT.tmp\" && mv \"$NONCE_OUT.tmp\" \"$NONCE_OUT\" && exec sleep 600"],
                "env":{"HOME":home,"XDG_DATA_HOME":data,"XDG_CONFIG_HOME":config,"XDG_RUNTIME_DIR":runtime,"NONCE_OUT":directory.join(format!("{id}-nonce"))}, "reserved":true}));
        }
        // Start the production module only after seeding the isolated grant store.
        // The shell preserves the daemon's nonce descriptor across exec.
        modules.insert("cerebellum".into(), json!({"program":"/bin/sh", "args":["-c", "while [ ! -f \"$READY\" ]; do sleep 0.05; done; exec \"$BINARY\" \"$@\"", "flow-module"],
            "env":{"HOME":home,"XDG_DATA_HOME":data,"XDG_CONFIG_HOME":config,"XDG_RUNTIME_DIR":runtime,"READY":directory.join("ready"),"BINARY":module_binary()}, "reserved":true}));
        fs::write(
            &daemon_path,
            serde_json::to_vec(&json!({"version":1,"modules":modules})).unwrap(),
        )
        .unwrap();
        let daemon_config = subc_daemon::bootstrap::BootstrapConfig::new(&connection_path, 0)
            .with_daemon_config_path(&daemon_path)
            .unwrap()
            .with_capture_logs_dir(run.join("logs"))
            .with_terminal_journal_path(run.join("terminals.jsonl"))
            .with_live_children_record(run.join("live-children.json"))
            .with_machine_id_path(data.join("cortexkit/machine-id"))
            .with_scope_authority_owners(vec![OWNER.into()]);
        let daemon = tokio::spawn(subc_daemon::bootstrap::run_with_config(daemon_config));
        let connection = timeout(STARTUP, async {
            loop {
                if let Ok(c) = connection_file::read(&connection_path) {
                    break c;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        if standing {
            use cerebellum::browser_standing_grants::{
                FilesystemStandingGrantStorage, StandingBrowserGrants, StandingSubject,
                STANDING_GRANT_STORE_FILE,
            };
            let machine = cerebellum::computer_grants::this_machine_uuid()
                .expect("standing grants require the production machine identity source");
            let store = StandingBrowserGrants::open(
                Arc::new(FilesystemStandingGrantStorage::new(
                    data.join("cortexkit/cerebellum/journal")
                        .join(STANDING_GRANT_STORE_FILE),
                )),
                Some(machine),
            );
            store
                .record(
                    AGENT,
                    StandingSubject::Origin("https://page.example".into()),
                    2,
                    vec![],
                    None,
                    "flow-live-consent",
                )
                .unwrap();
        }
        fs::write(directory.join("ready"), b"ready").unwrap();
        let owner_nonce = read_nonce(&directory, OWNER).await;
        let nonce = read_nonce(&directory, carrier).await;
        let mut owner = Owner::register(&connection, &owner_nonce, OWNER).await;
        let registered_carrier = Owner::register(&connection, &nonce, carrier).await;
        owner.sync(carrier).await;
        let computer_tools = timeout(STARTUP, async {
            loop {
                let mut probe = connect(&connection).await;
                let frame = client_request(
                    &mut probe,
                    3,
                    ClientControlRequest::CatalogList {
                        module_id: Some("cerebellum".into()),
                    },
                )
                .await;
                if let ClientControlResponse::CatalogList { modules, .. } =
                    serde_json::from_slice(&frame.body).unwrap()
                {
                    if let Some(entry) =
                        modules.iter().find(|entry| entry.module_id == "cerebellum")
                    {
                        let tools = entry
                            .roles
                            .iter()
                            .flat_map(|role| match role {
                                subc_protocol::manifest::ProviderRole::ToolProvider {
                                    tools,
                                    ..
                                } => tools
                                    .iter()
                                    .map(|tool| tool.name.clone())
                                    .collect::<Vec<_>>(),
                                _ => vec![],
                            })
                            .filter(|name| name.starts_with("computer."))
                            .collect::<Vec<_>>();
                        eprintln!("daemon catalog computer tools: {tools:?}");
                        break tools;
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("supervised cerebellum registers");
        Self {
            directory,
            computer_tools,
            daemon,
            connection,
            nonce,
            _owner: owner,
            _carrier: registered_carrier,
        }
    }

    async fn open(&self, carrier: &str, scoped: bool) -> (TcpStream, Frame) {
        let mut client = connect(&self.connection).await;
        let reply = client_request(
            &mut client,
            7,
            ClientControlRequest::RouteOpen {
                role_versions: None,
                target: RouteTarget::ToolProvider {
                    module_id: "cerebellum".into(),
                },
                identity: BindIdentity::new("/tmp", "flow-live", "flow-live-conversation"),
                consumer_identity: Some(ConsumerIdentity {
                    module_id: carrier.into(),
                    launch_nonce: self.nonce.clone(),
                }),
                consumer_capabilities: Some(vec!["elicitation".into()]),
                admission_facts: None,
                scope: scoped.then(|| ScopeSelector {
                    owner: reserved(OWNER),
                    scope_ref: "flow-live".into(),
                    scope_epoch: Some(1),
                }),
            },
        )
        .await;
        eprintln!(
            "route.open ({carrier}, scoped={scoped}): {}",
            String::from_utf8_lossy(&reply.body)
        );
        (client, reply)
    }

    fn journal(&self) -> PathBuf {
        self.directory
            .join("home/.local/share/cortexkit/cerebellum/journal/call_records.jsonl")
    }
}

async fn read_nonce(directory: &std::path::Path, id: &str) -> String {
    timeout(STARTUP, async {
        loop {
            if let Ok(n) = fs::read_to_string(directory.join(format!("{id}-nonce"))) {
                if !n.is_empty() {
                    break n;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

async fn route(fixture: &Fixture, carrier: &str) -> (TcpStream, u16, u32) {
    let (client, reply) = fixture.open(carrier, true).await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    match serde_json::from_slice::<ClientControlResponse>(&reply.body).unwrap() {
        ClientControlResponse::RouteOpen {
            route_channel,
            route_epoch,
        } => (client, route_channel, route_epoch),
        other => panic!("unexpected {other:?}"),
    }
}

async fn call(client: &mut TcpStream, channel: u16, epoch: u32, name: &str, args: Value) -> Value {
    let frame = Frame::build(
        FrameType::Request,
        cerebellum::control_flags(),
        channel,
        epoch,
        101,
        serde_json::to_vec(
            &json!({"name":name, "arguments":args, "call_key":format!("flow-live-{name}")}),
        )
        .unwrap(),
    )
    .unwrap();
    write_frame(client, &frame).await.unwrap();
    let reply = next_frame(client).await;
    assert!(
        !String::from_utf8_lossy(&reply.body).contains("screen_locked"),
        "the screen must be unlocked for the computer never-ask assertion: {}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "unexpected elicitation or error: {}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!((reply.header.channel, reply.header.corr), (channel, 101));
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    eprintln!("{name}: {body}");
    assert!(
        timeout(Duration::from_millis(200), read_frame(client))
            .await
            .is_err(),
        "no unsolicited frame after reply"
    );
    body
}

fn navigation() -> Value {
    json!({"action":"navigate", "url":"https://page.example/page", "intent":"read the page", "severity":{"tier":2,"credential":false,"financial":false}})
}

#[tokio::test]
async fn basal_flow_admission_binds() {
    let fixture = Fixture::start("basal", false).await;
    let _ = route(&fixture, "basal").await;
}

#[tokio::test]
async fn browser_flow_missing_grant_never_asks_or_launches() {
    let fixture = Fixture::start("basal", false).await;
    let (mut client, channel, epoch) = route(&fixture, "basal").await;
    let body = call(&mut client, channel, epoch, "browser_use", navigation()).await;
    assert_eq!(body["outcome"], "consent_unavailable", "{body}");
    assert_eq!(body["detail"]["reason"], "unattended_flow", "{body}");
    let records =
        fs::read_to_string(fixture.journal()).expect("call journal confined to fixture data home");
    let record: Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
    assert_eq!(record["state"], "refused", "{record}");
    assert!(!fixture.directory.join("browser-launched").exists());
}

#[tokio::test]
async fn computer_flow_missing_grant_never_asks() {
    let fixture = Fixture::start("basal", false).await;
    if fixture.computer_tools.is_empty() {
        eprintln!("computer never-ask not exercised: the binary has no admitted computer capabilities; set CEREBELLUM_FLOW_E2E_BINARY to a release-attested build");
        return;
    }
    assert!(
        fixture
            .computer_tools
            .iter()
            .any(|name| name == "computer.wait"),
        "computer.wait must be advertised for the app-grant assertion: {:?}",
        fixture.computer_tools
    );
    let (mut client, channel, epoch) = route(&fixture, "basal").await;
    let body = call(
        &mut client,
        channel,
        epoch,
        "computer_use",
        json!({"action":"wait", "app":"com.apple.finder", "predicate":{"kind":"element_present", "element":{"Identifier":"ready"}}, "timeout_ms":250}),
    )
    .await;
    assert_eq!(body["outcome"], "consent_unavailable", "{body}");
    assert!(
        fixture.journal().is_file(),
        "journal confined to fixture data home"
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "production hardware identity for standing grants is only available on macOS"
)]
async fn standing_owner_grant_gets_past_consent_without_asking() {
    let fixture = Fixture::start("basal", true).await;
    let (mut client, channel, epoch) = route(&fixture, "basal").await;
    let body = call(&mut client, channel, epoch, "browser_use", navigation()).await;
    assert_ne!(body["outcome"], "consent_unavailable", "{body}");
    assert_eq!(
        body["outcome"], "no_session",
        "standing grant must reach browser session dispatch: {body}"
    );
    assert!(
        fixture.journal().is_file(),
        "journal confined to fixture data home"
    );
}

#[tokio::test]
async fn wrong_carrier_broca_is_refused_by_cerebellum() {
    let fixture = Fixture::start("broca", false).await;
    let (mut client, channel, epoch) = route(&fixture, "broca").await;
    for (name, args) in [
        ("browser_use", navigation()),
        (
            "computer_use",
            json!({"action":"wait", "app":"com.apple.finder", "predicate":{"kind":"element_present", "element":{"Identifier":"ready"}}, "timeout_ms":250}),
        ),
    ] {
        let body = call(&mut client, channel, epoch, name, args).await;
        assert_eq!(body["outcome"], "consent_unavailable", "{body}");
        assert_eq!(
            body["detail"]["reason"], "flow_carrier_not_admitted",
            "{body}"
        );
    }
}

#[tokio::test]
async fn plain_basal_route_is_principal_denied_at_bind() {
    let fixture = Fixture::start("basal", false).await;
    let (_, reply) = fixture.open("basal", false).await;
    assert_eq!(reply.header.ty, FrameType::Error);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["code"], "principal_denied", "{body}");
}

#[test]
#[ignore = "production manifest always declares flow-scopes/v1; no existing test-only switch"]
fn daemon_gate_without_flow_declaration() {}
