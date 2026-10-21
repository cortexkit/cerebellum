// Separate binary: changes HOME and XDG homes and boots an in-process daemon.
//! The capture's vault deposit, against the real daemon.
//!
//! The capture tests drive the deposit through a fake vault behind the
//! `CookieVault` seam. This one runs the production opener,
//! `login_capture::vault::ClaustrumVault`, against the in-process daemon the
//! other live tests boot, to show what only the daemon can: that the route it
//! opens is stamped `Reserved { module_id: "cerebellum" }` when it presents the
//! launch nonce, and `Direct` when it does not.
//!
//! The daemon admits a `Reserved` principal only for a nonce it handed to a
//! process it spawned. So `cerebellum` is configured as a module whose program
//! is a test helper that writes its nonce to a file and stays alive; this test registers
//! as `cerebellum` with that nonce and cerebellum's real manifest, which also
//! shows that manifest no longer forbids routes to a credentials provider.
//!
//! Claustrum is a stub registered by this test: a management surface that
//! provides `credentials-provider/v1`, records the principal each route was
//! bound with and the keys of each request, and answers as the vault does. A
//! route stamped anything but `reserved:cerebellum` gets the vault's own
//! answer to a caller without the deposit grant, `not_found`.
#![cfg(unix)]

#[path = "it/support/hang_guard.rs"]
mod hang_guard;
mod support;
use hang_guard::HANG_GUARD;

use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::login_capture::vault::{self, ClaustrumVault, DepositEnd};
use cerebellum::login_capture::{vault_wire, CookieHeader};
use serde_json::{json, Value};
use subc_control::{ClientControlRequest, ClientControlResponse};
use subc_protocol::manifest::CapabilityDeclarations;
use subc_protocol::{
    Flags, Frame, FrameType, ModuleHelloBody, Principal, Priority, PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const CEREBELLUM: &str = "cerebellum";
const CLAUSTRUM: &str = "claustrum";
const CREDENTIAL_ID: &str = "cookie:ollama.com:work";

/// Generous: it only decides how long a broken boot takes to fail.
const STARTUP: Duration = HANG_GUARD;

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

/// What the stub vault saw on one deposit.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    principal: Option<Principal>,
    keys: Vec<String>,
}

/// Register `module_id` with `manifest` and serve its channel-0 control
/// requests (and, for the stub vault, its deposits) until the test ends.
async fn register(
    connection: &subc_transport::ConnectionInfo,
    manifest: subc_protocol::manifest::ModuleManifest,
    nonce: Option<String>,
    seen: Arc<Mutex<Vec<Seen>>>,
) {
    let module_id = manifest.module_id.clone();
    let mut stream = connect(connection).await;
    let hello = ModuleHelloBody {
        manifest,
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec!["route.bind".into(), "health.check".into()]),
        launch_nonce: nonce,
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
        "{module_id}'s HELLO was refused: {}",
        String::from_utf8_lossy(&ack.body)
    );
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let (writer, mut outgoing) = mpsc::channel::<Frame>(16);
    tokio::spawn(async move {
        while let Some(frame) = outgoing.recv().await {
            if write_frame(&mut write_half, &frame).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        // The principal each route was bound with, by its channel here.
        let mut bound: BTreeMap<u16, Option<Principal>> = BTreeMap::new();
        while let Ok(Some(frame)) = read_frame(&mut read_half).await {
            if frame.header.ty != FrameType::Request {
                continue;
            }
            let body: Value = serde_json::from_slice(&frame.body).unwrap_or_default();
            let (flags, reply) = if frame.header.channel == 0 {
                let reply = match body["op"].as_str() {
                    Some("health.check") => json!({"op": "health.check", "status": "healthy"}),
                    Some("route.bind") => {
                        let channel = body["route_channel"].as_u64().unwrap() as u16;
                        let principal = serde_json::from_value(body["principal"].clone()).ok();
                        bound.insert(channel, principal);
                        json!({"op": "route.bind"})
                    }
                    _ => json!({}),
                };
                (cerebellum::control_flags(), reply)
            } else {
                // A deposit. Only its keys are kept: the cookie is not this
                // test's to print.
                let principal = bound.get(&frame.header.channel).cloned().flatten();
                let mut keys = body["params"]
                    .as_object()
                    .map(|params| params.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                keys.sort();
                let granted = principal
                    == Some(Principal::Reserved {
                        module_id: CEREBELLUM.into(),
                    })
                    && body["method"] == vault_wire::DEPOSIT_METHOD;
                seen.lock().unwrap().push(Seen { principal, keys });
                let reply = if granted {
                    json!({"result": {"id": body["params"]["id"], "outcome": "created", "record_version": 1}})
                } else {
                    json!({"result": {"error": {"class": "permanent", "code": "not_found"}}})
                };
                (Flags::new(false, Priority::Interactive, false), reply)
            };
            let reply = Frame::build(
                FrameType::Response,
                flags,
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
                serde_json::to_vec(&reply).unwrap(),
            )
            .unwrap();
            if writer.send(reply).await.is_err() {
                return;
            }
        }
    });
}

/// The stub vault's manifest: cerebellum's own shape (a tool provider and a
/// management surface), renamed, claiming the capability the vault provides.
fn claustrum_manifest() -> subc_protocol::manifest::ModuleManifest {
    let mut manifest = cerebellum::manifest::build(CLAUSTRUM);
    manifest.capabilities = Some(CapabilityDeclarations {
        provides: vec!["credentials-provider/v1".to_string()],
        requires: Vec::new(),
        must_never_reach: Vec::new(),
    });
    manifest
}

async fn deposit(vault: &ClaustrumVault) -> DepositEnd {
    let header = CookieHeader::from_pairs([("session", "live-test-value")]).unwrap();
    let request =
        vault_wire::deposit_request(CREDENTIAL_ID, header, "capture-login-live", None).unwrap();
    vault::deposit(
        vault,
        request,
        CREDENTIAL_ID,
        vault::DEPOSIT_DEADLINE,
        &vault::RETRY_BACKOFF,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_deposit_route_is_stamped_reserved_cerebellum_only_with_the_launch_nonce() {
    let directory = cortexkit_test_support::ScratchDir::new("cerebellum-vault-live");
    let data = cortexkit_test_support::fenced_subc_env_dir(directory.path(), "XDG_DATA_HOME");
    // Before the daemon starts: it resolves its homes from these.
    for (name, path) in cortexkit_test_support::fenced_subc_daemon_env(directory.path()) {
        std::env::set_var(name, path);
    }

    // The daemon, with cerebellum configured as a helper that hands the test
    // its launch nonce.
    let nonce_file = directory.join("cerebellum-nonce");
    let mut module_env = support::fenced_module_env(directory.path());
    module_env.insert("NONCE_OUT".into(), nonce_file.clone());
    let connection_file_path = directory.join("subc-connection.json");
    let daemon_config_path = directory.join("subc.jsonc");
    fs::write(
        &daemon_config_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "modules": {
                CEREBELLUM: {
                    "program": support::nonce_holder(),
                    // The daemon passes the nonce only on a pipe at descriptor 3
                    // (named by SUBC_LAUNCH_NONCE_FD), never in the environment.

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
        .with_terminal_journal_path(run.join("terminals.jsonl"));
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
    .expect("the daemon spawns cerebellum, which hands over its nonce");

    // Cerebellum, registered with its real manifest: a deny edge on the
    // vault's capability there would refuse every route below.
    let seen = Arc::new(Mutex::new(Vec::new()));
    register(
        &connection,
        cerebellum::manifest::build(CEREBELLUM),
        Some(nonce.clone()),
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;
    register(&connection, claustrum_manifest(), None, Arc::clone(&seen)).await;
    timeout(STARTUP, async {
        loop {
            let mut probe = connect(&connection).await;
            let request = ClientControlRequest::CatalogList {
                module_id: Some(CLAUSTRUM.into()),
            };
            let frame = Frame::build(
                FrameType::Request,
                cerebellum::control_flags(),
                0,
                0,
                3,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
            write_frame(&mut probe, &frame).await.unwrap();
            let reply = next_frame(&mut probe).await;
            if let Ok(ClientControlResponse::CatalogList { modules, .. }) =
                serde_json::from_slice(&reply.body)
            {
                if !modules.is_empty() {
                    break;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the stub vault registers");

    // With the launch nonce: the route is cerebellum's, and the vault stores.
    let supervised = ClaustrumVault::new(
        connection_file_path.clone(),
        CEREBELLUM.to_string(),
        Some(nonce.clone()),
    );
    let end = deposit(&supervised).await;
    let seen_now = seen.lock().unwrap().clone();
    assert_eq!(
        seen_now,
        vec![Seen {
            principal: Some(Principal::Reserved {
                module_id: CEREBELLUM.into()
            }),
            keys: vec!["consent_ref".into(), "cookie".into(), "id".into()],
        }],
        "the route did not reach the vault as reserved:cerebellum: {end:?}"
    );
    let DepositEnd::Stored(stored) = end else {
        panic!("the deposit was not stored: {end:?}");
    };
    assert_eq!(stored.id, CREDENTIAL_ID);

    // Without it: the daemon stamps the route Direct, and the vault refuses.
    let direct = ClaustrumVault::new(connection_file_path.clone(), CEREBELLUM.to_string(), None);
    let end = deposit(&direct).await;
    assert_eq!(
        seen.lock().unwrap().last().unwrap().principal,
        Some(Principal::Direct)
    );
    let DepositEnd::Refused(refusal) = end else {
        panic!("a direct route was not refused by the vault: {end:?}");
    };
    assert_eq!(refusal.code, "not_found");

    // With a nonce the daemon did not hand out: the route never opens.
    let forged = ClaustrumVault::new(
        connection_file_path.clone(),
        CEREBELLUM.to_string(),
        Some("0".repeat(64)),
    );
    let calls_before = seen.lock().unwrap().len();
    let end = deposit(&forged).await;
    assert!(
        matches!(&end, DepositEnd::RouteRefused { code: Some(code) } if code == "bad_consumer_identity"),
        "{end:?}"
    );
    assert_eq!(seen.lock().unwrap().len(), calls_before);

    daemon.abort();
}
