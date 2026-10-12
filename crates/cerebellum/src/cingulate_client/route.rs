//! The route to Cingulate: opened by cerebellum itself, under the calling
//! agent's session scope, for the life of one held call.
//!
//! Cingulate takes the requester's identity from the daemon's stamp on this
//! route and nothing else: the principal (`reserved:cerebellum`, from the
//! launch nonce presented as `consumer_identity`) and the session scope the
//! route was admitted under (whose agent becomes the card's subject). The
//! daemon admits cerebellum under an agent's scope only because core lists
//! `reserved:cerebellum` as a carrier of that scope with `cingulate` as its one
//! target, so the scope selector here must be the inbound call's own.
//!
//! The opener is hand-rolled on `subc-transport`, as the vault deposit's is
//! (`login_capture::vault`): one connection, one route, a handful of
//! request/reply pairs, then dropped. A general client's reconnects, route
//! caches and background reader serve long-lived consumers, and this route
//! must not outlive the call it was opened for.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use serde::Serialize;
use subc_protocol::scope::ScopeSelector;
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;

use super::live_call::LiveCall;
use super::wire::{self, Refusal};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a call to Cingulate produced no result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// Cingulate answered with an Error frame.
    Refused(Refusal),
    /// The daemon or the route failed: no connection, a refused route.open,
    /// a closed connection, or a reply outside the contract. Nothing about the
    /// card can be concluded from it.
    Transport { code: Option<String> },
    /// No live inbound call was held when the route was to be opened, so it
    /// was not opened.
    NotLive,
    /// The registry of raised cards could not be read at startup (a newer
    /// version or a damaged file), so no route is opened and no card raised:
    /// raising one would mean saving the registry over that file.
    RegistryUnreadable,
}

/// One open route to Cingulate. Dropping it closes the route.
pub trait CingulateRoute: Send {
    /// Send one request and return its `result` member.
    fn call<'a>(
        &'a mut self,
        method: &'a str,
        params: serde_json::Value,
    ) -> BoxFuture<'a, Result<serde_json::Value, CallError>>;
}

/// Opens routes to Cingulate. Production is [`DaemonCingulate`]; the wire
/// tests use a scripted double.
pub trait CingulateOpener: Send + Sync {
    /// Open one route under `live`'s session scope. Callers reach this only
    /// through `ConsentDesk::session`, which checks the call is still held.
    fn open<'a>(
        &'a self,
        live: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>>;
}

/// The handshake's own bound: the same five seconds the module connection
/// gives it.
const AUTH_DEADLINE: Duration = Duration::from_secs(5);

/// How long one request may wait for its reply. A `consent.await` waits up
/// to [`wire::AWAIT_CAP_MS`] on Cingulate's side, so this is that plus room
/// for the reply to travel; anything longer is a wedged route.
const REPLY_DEADLINE: Duration = Duration::from_millis(wire::AWAIT_CAP_MS + 15_000);

/// Correlation id of the route.open request; nothing else rides channel 0.
const OPEN_CORRELATION: u64 = 1;

/// Attribution only: the daemon and Cingulate authorize on the stamped
/// principal and scope, never on these.
const BIND_HARNESS: &str = "cerebellum";
const BIND_SESSION: &str = "consent";

/// Cingulate reached through the daemon this module is registered with.
pub struct DaemonCingulate {
    connection_file: PathBuf,
    module_id: String,
    launch_nonce: Option<String>,
}

impl std::fmt::Debug for DaemonCingulate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DaemonCingulate")
            .field("connection_file", &self.connection_file)
            .field("module_id", &self.module_id)
            .field("presents_launch_nonce", &self.launch_nonce.is_some())
            .finish()
    }
}

#[derive(Serialize)]
struct ConsumerIdentity<'a> {
    module_id: &'a str,
    launch_nonce: &'a str,
}

/// `route.open` as the daemon decodes it, with the scope the route asks to be
/// admitted under.
#[derive(Serialize)]
struct RouteOpenRequest<'a> {
    op: &'static str,
    target: RouteTarget,
    identity: &'a BindIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_identity: Option<ConsumerIdentity<'a>>,
    scope: &'a ScopeSelector,
}

impl DaemonCingulate {
    pub fn new(connection_file: PathBuf, module_id: String, launch_nonce: Option<String>) -> Self {
        Self {
            connection_file,
            module_id,
            launch_nonce,
        }
    }

    /// Cingulate as this running module reaches it: its own connection file
    /// and module id, and the launch nonce the daemon spawned it with, which
    /// is what makes the daemon stamp the route `reserved:cerebellum`.
    pub fn supervised(connection_file: PathBuf, module_id: String) -> Self {
        let nonce = crate::launch_nonce::for_consumer_identity();
        Self::new(connection_file, module_id, nonce)
    }

    fn open_body(&self, scope: &ScopeSelector) -> Vec<u8> {
        let project_root = self
            .connection_file
            .parent()
            .map(PathBuf::from)
            .unwrap_or_default();
        let identity = BindIdentity::new(project_root, BIND_HARNESS, BIND_SESSION);
        let request = RouteOpenRequest {
            op: "route.open",
            target: RouteTarget::ManagementSurface {
                module_id: wire::CINGULATE_MODULE_ID.to_string(),
            },
            identity: &identity,
            consumer_identity: self
                .launch_nonce
                .as_deref()
                .map(|launch_nonce| ConsumerIdentity {
                    module_id: &self.module_id,
                    launch_nonce,
                }),
            scope,
        };
        serde_json::to_vec(&request).expect("the route.open body always serializes")
    }

    async fn open_route(&self, scope: &ScopeSelector) -> Result<DaemonRoute, CallError> {
        let unreachable = || CallError::Transport { code: None };
        let connection = connection_file::read(&self.connection_file).map_err(|_| unreachable())?;
        let endpoint = connection.endpoints.first().ok_or_else(unreachable)?;
        let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
            .await
            .map_err(|_| unreachable())?;
        let _ = stream.set_nodelay(true);
        authenticate_client(&mut stream, &connection, AUTH_DEADLINE)
            .await
            .map_err(|_| unreachable())?;
        let open = Frame::build(
            FrameType::Request,
            crate::control_flags(),
            0,
            0,
            OPEN_CORRELATION,
            self.open_body(scope),
        )
        .map_err(|_| unreachable())?;
        write_frame(&mut stream, &open)
            .await
            .map_err(|_| unreachable())?;
        let reply = tokio::time::timeout(REPLY_DEADLINE, async {
            loop {
                match read_frame(&mut stream).await {
                    Ok(Some(frame))
                        if frame.header.channel == 0 && frame.header.corr == OPEN_CORRELATION =>
                    {
                        return Some(frame)
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => return None,
                }
            }
        })
        .await
        .ok()
        .flatten()
        .ok_or_else(unreachable)?;
        match reply.header.ty {
            FrameType::Response => {
                #[derive(serde::Deserialize)]
                struct Opened {
                    route_channel: u16,
                    route_epoch: u32,
                }
                let opened: Opened =
                    serde_json::from_slice(&reply.body).map_err(|_| unreachable())?;
                Ok(DaemonRoute {
                    stream,
                    channel: opened.route_channel,
                    epoch: opened.route_epoch,
                    next_correlation: 1,
                })
            }
            // The daemon's own code (`scope_not_carrier`, `scope_ended` and
            // the like) says why the route was refused; it is kept verbatim.
            _ => Err(CallError::Transport {
                code: serde_json::from_slice::<serde_json::Value>(&reply.body)
                    .ok()
                    .and_then(|body| body.get("code")?.as_str().map(str::to_string)),
            }),
        }
    }
}

impl CingulateOpener for DaemonCingulate {
    fn open<'a>(
        &'a self,
        live: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
        Box::pin(async move {
            self.open_route(live.scope())
                .await
                .map(|route| Box::new(route) as Box<dyn CingulateRoute>)
        })
    }
}

/// One open route to Cingulate on its own connection.
struct DaemonRoute {
    stream: TcpStream,
    channel: u16,
    epoch: u32,
    next_correlation: u64,
}

impl CingulateRoute for DaemonRoute {
    fn call<'a>(
        &'a mut self,
        method: &'a str,
        params: serde_json::Value,
    ) -> BoxFuture<'a, Result<serde_json::Value, CallError>> {
        Box::pin(async move {
            let broken = || CallError::Transport { code: None };
            let correlation = self.next_correlation;
            self.next_correlation += 1;
            let frame = Frame::build(
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                self.channel,
                self.epoch,
                correlation,
                wire::envelope(method, params),
            )
            .map_err(|_| broken())?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|_| broken())?;
            let reply = tokio::time::timeout(REPLY_DEADLINE, async {
                loop {
                    match read_frame(&mut self.stream).await {
                        Ok(Some(frame))
                            if frame.header.channel == self.channel
                                && frame.header.corr == correlation =>
                        {
                            return Some(frame)
                        }
                        Ok(Some(_)) => continue,
                        Ok(None) | Err(_) => return None,
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .ok_or_else(broken)?;
            match reply.header.ty {
                FrameType::Response => wire::result_of(&reply.body).ok_or_else(broken),
                FrameType::Error => {
                    Err(Refusal::from_error_body(&reply.body)
                        .map_or_else(broken, CallError::Refused))
                }
                _ => Err(broken()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subc_protocol::Principal;

    /// The route asks to be admitted under the inbound call's own scope, at
    /// Cingulate's management surface, and presents the launch nonce so the
    /// daemon stamps `reserved:cerebellum`.
    #[test]
    fn the_route_open_presents_cingulate_the_scope_and_the_nonce() {
        let cingulate = DaemonCingulate::new(
            PathBuf::from("/run/subc/connection.json"),
            "cerebellum".into(),
            Some("n0nce".into()),
        );
        let scope = ScopeSelector {
            owner: Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            scope_ref: "sc_head_alf".into(),
            scope_epoch: Some(3),
        };
        let body: serde_json::Value = serde_json::from_slice(&cingulate.open_body(&scope)).unwrap();
        assert_eq!(body["op"], "route.open");
        assert_eq!(
            body["target"],
            serde_json::json!({"kind": "management_surface", "module_id": "cingulate"})
        );
        assert_eq!(
            body["consumer_identity"],
            serde_json::json!({"module_id": "cerebellum", "launch_nonce": "n0nce"})
        );
        assert_eq!(
            body["scope"],
            serde_json::json!({
                "owner": {"kind": "reserved", "module_id": "prefrontal-core"},
                "ref": "sc_head_alf",
                "scope_epoch": 3,
            })
        );
    }

    #[test]
    fn the_debug_form_never_prints_the_nonce() {
        let cingulate = DaemonCingulate::new(
            PathBuf::from("/tmp/c.json"),
            "cerebellum".into(),
            Some("planted-nonce-77".into()),
        );
        let debug = format!("{cingulate:?}");
        assert!(!debug.contains("planted-nonce-77"), "{debug}");
    }
}
