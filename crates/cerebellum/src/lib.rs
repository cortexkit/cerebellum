//! ck-cerebellum library core — the subc wire seam, health-v2, identity,
//! principal default-deny, and the `browser.status` capability.
//!
//! The binary (`main.rs`) is a thin entry point that reads config from env and
//! calls [`run`]. The library exposes the module's internal handlers for
//! conformance tests.

#![forbid(unsafe_code)]

pub mod capability;
pub mod clock;
pub mod config;
pub mod dispatch;
pub mod health;
pub mod identity;
pub mod manifest;
pub mod principal;
pub mod wire;

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde_json::json;
use subc_protocol::session::{
    ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
};
use subc_protocol::{
    ErrorBody, Flags, Frame, FrameType, ModuleHelloAckBody, ModuleHelloBody, Priority,
    PROTOCOL_VERSION, SUBC_MODULE_ID_ENV,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub use capability::{handle_browser_status, handle_browser_status_for_identity};
pub use config::{parse_config, Config, ConfigError, HealthConfig};
pub use health::HealthState;
#[cfg(any(test, feature = "test-observer"))]
pub use identity::{take_test_observations, IdentityResolutionObservation};
pub use identity::{
    AcceptedBindFacts, LogicalProfileKey, ProfileDisposition, ProfileResolution, RouteIdentity,
    SessionKind,
};
pub use principal::{trust_for_principal, PrincipalTrust};
pub use wire::{build_error_frame, control_flags};

const DEFAULT_MODULE_ID: &str = "cerebellum";
const HELLO_CORR: u64 = 1;
const EGRESS_BUFFER: usize = 64;
const BROWSER_STATUS_TOOL: &str = "browser.status";

/// Accepted bind facts retained for the lifetime of a route.
///
/// This is an in-memory route table, not a profile registry or storage layer.
/// It lets data-plane frames inherit the identity and effective scope that the
/// daemon accepted on `route.bind`.
#[derive(Clone, Default)]
pub struct RouteBindings {
    inner: Arc<RwLock<HashMap<(u16, u32), AcceptedBindFacts>>>,
}

impl RouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, channel: u16, epoch: u32, facts: AcceptedBindFacts) {
        if let Ok(mut routes) = self.inner.write() {
            routes.insert((channel, epoch), facts);
        }
    }

    fn get(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        self.inner
            .read()
            .ok()
            .and_then(|routes| routes.get(&(channel, epoch)).cloned())
    }
}

/// The binary entry point: read config from env, load the health config
/// file, and run the module loop. Exposed publicly so the thin `main.rs`
/// binary can delegate here.
pub async fn run_entry() -> Result<(), ModuleError> {
    let config = ModuleConfig::from_env()?;
    run(config).await
}

struct ModuleConfig {
    connection_file_path: PathBuf,
    module_id: String,
    health: HealthConfig,
}

impl ModuleConfig {
    fn from_env() -> Result<Self, ModuleError> {
        let connection_file_path = parse_subc_arg(std::env::args_os().skip(1))?;
        let module_id = std::env::var(SUBC_MODULE_ID_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
        // Load the health config file at boot. A missing file uses defaults;
        // a present-but-malformed file fails registration deterministically
        // rather than silently falling back (Spec A: zero, negative,
        // fractional, non-numeric, and unknown-member values are
        // configuration errors).
        let health = config::load_config_file()
            .map_err(ModuleError::Config)?
            .health;
        Ok(Self {
            connection_file_path,
            module_id,
            health,
        })
    }
}

async fn run(config: ModuleConfig) -> Result<(), ModuleError> {
    let stream = connect_to_subc(&config.connection_file_path).await?;
    let (mut read_half, write_half) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let writer = tokio::spawn(drain_writer(write_half, rx));

    let health_state = Arc::new(HealthState::with_config(config.health));
    let route_bindings = Arc::new(RouteBindings::new());
    let loop_result = module_loop(
        &mut read_half,
        tx.clone(),
        &config,
        Arc::clone(&health_state),
        Arc::clone(&route_bindings),
    )
    .await;
    drop(tx);

    let writer_result = writer
        .await
        .map_err(|e| ModuleError::Message(e.to_string()));
    match (loop_result, writer_result) {
        (Err(loop_err), _) => Err(loop_err),
        (Ok(()), Ok(Ok(()))) => Ok(()),
        (Ok(()), Ok(Err(writer_err))) => Err(ModuleError::Message(writer_err.to_string())),
        (Ok(()), Err(join_err)) => Err(join_err),
    }
}

async fn connect_to_subc(connection_file_path: &PathBuf) -> Result<TcpStream, ModuleError> {
    let conn = connection_file::read(connection_file_path)
        .map_err(|e| ModuleError::Message(format!("reading connection file: {e}")))?;
    let endpoint = conn
        .endpoints
        .first()
        .ok_or_else(|| ModuleError::Message("connection file has no endpoints".into()))?;
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| ModuleError::Message(format!("connect {addr}: {e}")))?;
    authenticate_client(&mut stream, &conn, std::time::Duration::from_secs(5))
        .await
        .map_err(|e| ModuleError::Message(format!("authenticate: {e}")))?;
    Ok(stream)
}

async fn module_loop<R>(
    read_half: &mut R,
    writer: mpsc::Sender<Frame>,
    config: &ModuleConfig,
    health_state: Arc<HealthState>,
    route_bindings: Arc<RouteBindings>,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    send_hello(&writer, config).await?;
    expect_hello_ack(read_half).await?;

    // Stamp the initial heartbeat so a freshly-started module reports healthy.
    health_state.stamp_heartbeat();

    loop {
        health_state.stamp_heartbeat();
        let Some(frame) = read_frame(read_half)
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?
        else {
            return Ok(()); // clean EOF: subc closed the connection.
        };
        if !handle_frame(frame, &writer, &health_state, &route_bindings).await? {
            return Ok(());
        }
    }
}

async fn drain_writer<W>(write_half: W, mut rx: mpsc::Receiver<Frame>) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(write_half);
    while let Some(frame) = rx.recv().await {
        write_frame(&mut writer, &frame)
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
        while let Ok(frame) = rx.try_recv() {
            write_frame(&mut writer, &frame)
                .await
                .map_err(|e| ModuleError::Message(e.to_string()))?;
        }
        writer
            .flush()
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
    }
    writer
        .flush()
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    Ok(())
}

async fn send_hello(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfig,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&ModuleHelloBody {
        manifest: manifest::build(&config.module_id),
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            "route.status".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
        ]),
        launch_nonce: std::env::var(subc_protocol::SUBC_LAUNCH_NONCE_ENV)
            .ok()
            .filter(|value| !value.is_empty()),
    })
    .map_err(ModuleError::Json)?;
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, 0, HELLO_CORR, body)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn expect_hello_ack<R>(reader: &mut R) -> Result<ModuleHelloAckBody, ModuleError>
where
    R: AsyncRead + Unpin,
{
    let frame = read_frame(reader)
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?
        .ok_or_else(|| ModuleError::Message("connection closed before HELLO_ACK".into()))?;
    match frame.header.ty {
        FrameType::HelloAck => serde_json::from_slice(&frame.body).map_err(ModuleError::Json),
        FrameType::Error => {
            let body =
                serde_json::from_slice::<ErrorBody>(&frame.body).map_err(ModuleError::Json)?;
            Err(ModuleError::Message(format!(
                "subc rejected HELLO: {} — {}",
                body.code, body.message
            )))
        }
        ty => Err(ModuleError::Message(format!(
            "unexpected frame {ty:?} awaiting HELLO_ACK"
        ))),
    }
}

/// Returns `Ok(false)` to stop the loop (graceful goodbye / EOF).
async fn handle_frame(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<bool, ModuleError> {
    match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => {
            let pong = Frame::build_with_version(
                frame.header.ver,
                FrameType::Pong,
                frame.header.flags,
                0,
                0,
                frame.header.corr,
                Vec::new(),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            send(writer, pong).await?;
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => Ok(true),
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, writer, health_state, route_bindings).await?;
            Ok(true)
        }
        FrameType::Request => {
            let writer = writer.clone();
            let health_state = Arc::clone(health_state);
            let route_bindings = Arc::clone(route_bindings);
            tokio::spawn(async move {
                let _ = handle_tool_request(frame, &writer, &health_state, &route_bindings).await;
            });
            Ok(true)
        }
        _ => Ok(true),
    }
}

async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let request =
        serde_json::from_slice::<ModuleControlRequest>(&frame.body).map_err(ModuleError::Json)?;
    let response_body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            identity,
            admission_facts,
            ..
        } => {
            // In-module principal default-deny backstop: the gateway policy
            // (subc-mcp) is the primary exclusion of cerebellum capabilities
            // from `mcp:*` surfaces. This check is the defense-in-depth backstop
            // that rejects a forged direct dispatch under a non-first-party
            // principal before any capability executes.
            let trust = principal::trust_for_principal(&principal);
            if !trust.is_first_party() {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }

            // Retain only facts from the accepted bind. Data-plane frames inherit
            // these facts by (channel, epoch); request bodies cannot replace them.
            let accepted_facts = AcceptedBindFacts::from_bind(
                &identity,
                principal.clone(),
                admission_facts.as_ref(),
            );
            route_bindings.insert(route_channel, epoch, accepted_facts);
            // Accept the bind — capability scope is checked at dispatch time.
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // Insulated health-v2 lane: the report is a mechanical mapper over
            // atomics stamped by the dispatch path. It never blocks on a lock
            // and never forms its own opinion (Health-Path-Rule-v2).
            health_state.report()
        }
    };
    let body = serde_json::to_vec(&response_body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        frame.header.ver,
        FrameType::Response,
        control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

/// Send the pinned transport rejection for an ineligible principal.
async fn send_principal_denied(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    corr: u64,
    principal: &Option<subc_protocol::Principal>,
) -> Result<(), ModuleError> {
    let label = principal
        .as_ref()
        .map(|p| match p {
            subc_protocol::Principal::Reserved { module_id } => {
                format!("reserved:{module_id}")
            }
            subc_protocol::Principal::Direct => "direct".to_string(),
            subc_protocol::Principal::Unverified => "unverified".to_string(),
        })
        .unwrap_or_else(|| "absent".to_string());
    let frame = build_error_frame(
        ver,
        0,
        0,
        corr,
        "principal_denied",
        &format!(
            "cerebellum capabilities are first-party only; principal '{label}' is not eligible"
        ),
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn handle_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    _health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;

    let request: serde_json::Value = match serde_json::from_slice(&frame.body) {
        Ok(v) => v,
        Err(e) => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "invalid_request",
                &format!("request body not decodable: {e}"),
            )
            .await;
        }
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if method != BROWSER_STATUS_TOOL {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "unknown_method",
            &format!("unknown method '{method}', expected '{BROWSER_STATUS_TOOL}'"),
        )
        .await;
    }

    let Some(accepted_facts) = route_bindings.get(channel, epoch) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "route_not_bound",
            "browser.status requires an accepted route.bind",
        )
        .await;
    };
    if !accepted_facts.allows_capability(BROWSER_STATUS_TOOL) {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "capability_denied",
            "browser.status is outside the effective capability scope",
        )
        .await;
    }

    let params = request.get("params").cloned().unwrap_or(json!({}));
    let result = handle_browser_status_for_identity(&params, &accepted_facts.identity);

    let body = serde_json::to_vec(&result).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        ver,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

async fn send_route_error(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    code: &str,
    message: &str,
) -> Result<(), ModuleError> {
    let frame = build_error_frame(ver, channel, epoch, corr, code, message)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), ModuleError> {
    writer
        .send(frame)
        .await
        .map_err(|_| ModuleError::Message("egress channel closed".into()))
}

fn parse_subc_arg(args: impl IntoIterator<Item = OsString>) -> Result<PathBuf, ModuleError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--subc" {
            let value = args
                .next()
                .ok_or_else(|| ModuleError::Message("--subc requires a value".into()))?;
            return Ok(PathBuf::from(value));
        }
        if let Some(raw) = arg.to_str().and_then(|a| a.strip_prefix("--subc=")) {
            if raw.is_empty() {
                return Err(ModuleError::Message("--subc= requires a value".into()));
            }
            return Ok(PathBuf::from(raw));
        }
    }
    Err(ModuleError::Message(
        "--subc <connection-file> is required".into(),
    ))
}

#[derive(Debug)]
pub enum ModuleError {
    Message(String),
    Json(serde_json::Error),
    Config(ConfigError),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(m) => write!(f, "{m}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::Config(e) => write!(f, "config: {e}"),
        }
    }
}

impl std::error::Error for ModuleError {}

// ---------------------------------------------------------------------------
// Test-only public API: thin wrappers that the conformance test suite drives
// to exercise the real handlers without a live subc daemon.
// ---------------------------------------------------------------------------

pub struct ModuleConfigForTest {
    pub module_id: String,
}

pub async fn send_hello_for_test(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfigForTest,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&ModuleHelloBody {
        manifest: manifest::build(&config.module_id),
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            "route.status".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
        ]),
        launch_nonce: None,
    })
    .map_err(ModuleError::Json)?;
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, 0, HELLO_CORR, body)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

pub async fn handle_control_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    handle_control_request(frame, writer, health_state, &route_bindings).await
}

pub async fn handle_control_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_control_request(frame, writer, health_state, route_bindings).await
}

pub async fn handle_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    // Older unit fixtures invoke only the data-plane helper. Install a
    // synthetic accepted first-party bind so they still exercise the real
    // bound-route path without weakening the production handler.
    let identity = subc_protocol::BindIdentity {
        project_root: PathBuf::from("/test/project"),
        harness: "test".to_string(),
        session: "test-session".to_string(),
    };
    route_bindings.insert(
        frame.header.channel,
        frame.header.epoch,
        AcceptedBindFacts::from_bind(&identity, Some(subc_protocol::Principal::Direct), None),
    );
    handle_tool_request(frame, writer, health_state, &route_bindings).await
}

pub async fn handle_tool_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_tool_request(frame, writer, health_state, route_bindings).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use subc_protocol::Principal;

    #[test]
    fn parse_subc_arg_accepts_space_separated() {
        let args = vec!["--subc".to_string().into(), "/tmp/conn.json".into()];
        assert_eq!(
            parse_subc_arg(args).unwrap(),
            PathBuf::from("/tmp/conn.json")
        );
    }

    #[test]
    fn parse_subc_arg_accepts_equals_form() {
        let args: Vec<OsString> = vec!["--subc=/tmp/conn.json".into()];
        assert_eq!(
            parse_subc_arg(args).unwrap(),
            PathBuf::from("/tmp/conn.json")
        );
    }

    #[test]
    fn parse_subc_arg_rejects_missing_value() {
        let args: Vec<OsString> = vec!["--subc".into()];
        assert!(parse_subc_arg(args).is_err());
    }

    #[test]
    fn parse_subc_arg_rejects_missing_flag() {
        let args: Vec<OsString> = vec!["--other".into()];
        assert!(parse_subc_arg(args).is_err());
    }

    #[test]
    fn default_module_id_is_cerebellum() {
        assert_eq!(DEFAULT_MODULE_ID, "cerebellum");
    }

    #[test]
    fn browser_status_is_the_single_capability() {
        assert_eq!(BROWSER_STATUS_TOOL, "browser.status");
    }

    #[test]
    fn principal_backstop_rejects_unverified() {
        let trust = trust_for_principal(&Some(Principal::Unverified));
        assert!(!trust.is_first_party());
    }

    #[test]
    fn principal_backstop_rejects_absent() {
        let trust = trust_for_principal(&None);
        assert!(!trust.is_first_party());
    }

    #[test]
    fn principal_backstop_accepts_direct() {
        let trust = trust_for_principal(&Some(Principal::Direct));
        assert!(trust.is_first_party());
    }

    #[test]
    fn principal_backstop_accepts_alfonso_core() {
        let trust = trust_for_principal(&Some(Principal::Reserved {
            module_id: "alfonso-core".to_string(),
        }));
        assert!(trust.is_first_party());
    }

    #[test]
    fn principal_backstop_rejects_subc_mcp() {
        let trust = trust_for_principal(&Some(Principal::Reserved {
            module_id: "subc-mcp".to_string(),
        }));
        assert!(!trust.is_first_party());
    }
}
