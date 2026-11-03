//! The capture's one vault call: deposit the captured cookie in claustrum.
//!
//! The vault opens a route of its own, because the vault is not the caller: a second,
//! consumer connection to the daemon, authenticated with the same connection
//! file and HMAC handshake as the module connection, opens a route to
//! claustrum presenting this module's launch nonce as `consumer_identity`. The
//! daemon checks the nonce against the process it spawned and stamps the route
//! `Reserved { module_id }`; claustrum's deposit grant is keyed on that stamp.
//!
//! One connection per deposit: opened when a capture has a cookie to store and
//! dropped (closing the route with it) when the deposit ends, all inside
//! [`DEPOSIT_DEADLINE`]. Nothing is kept open between captures, so an idle
//! module holds no route into the vault.
//!
//! The opener is hand-rolled on `subc-transport` rather than taken from
//! `subc-client-rs`. That client is not a dependency today, and its
//! connection machinery (reconnects, a background reader, route caches) serves
//! long-lived consumers; a single request on a connection dropped right after
//! needs none of it. Writing the frames here also keeps every copy of the
//! request in buffers this module wipes, which a general client's internal
//! frame buffers would not.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use subc_protocol::{BindIdentity, EnvelopeHeader, Flags, FrameType, Priority, PROTOCOL_VERSION};
use subc_transport::{authenticate_client, connection_file, read_frame};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::vault_wire::{
    self, ConsumerIdentity, DepositReply, Deposited, RouteOpened, SecretBytes,
};

/// The whole deposit, from connecting to the daemon to the vault's answer,
/// including every retry.
///
/// The person has just finished signing in and the agent's call is still
/// open, so this bounds how long both wait after the browser has closed. A
/// healthy deposit is a loopback connect, an HMAC handshake, one route open
/// and one store write: tens of milliseconds. The slack covers a daemon that
/// has to start or warm claustrum on the route open (seconds) and the retry
/// backoff below (under two seconds). Fifteen seconds is well past all of
/// that, and short enough that a wedged daemon is reported while the person is
/// still at the screen.
pub const DEPOSIT_DEADLINE: Duration = Duration::from_secs(15);

/// The pause before each retry of a transient refusal: three retries, about
/// 1.75 s in all. A transient refusal is the store being busy or failing a
/// write, which clears in a fraction of a second when it clears at all;
/// waiting longer only delays the reply that says to try again.
pub const RETRY_BACKOFF: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
];

/// The handshake's own bound, inside [`DEPOSIT_DEADLINE`]: the same five
/// seconds the module connection gives it.
const AUTH_DEADLINE: Duration = Duration::from_secs(5);

/// Correlation id of the route.open request. The connection carries nothing
/// else on channel 0, so any fixed id is unique on it.
const OPEN_CORRELATION: u64 = 1;

/// The `harness` and `session` named in the route's bind identity. They are
/// attribution only (the daemon and the vault authorize on the stamped
/// principal), and say which part of this module opened the route.
const BIND_HARNESS: &str = "cerebellum";
const BIND_SESSION: &str = "browser.capture_login";

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why the vault could not be reached or asked. Carries daemon codes only,
/// never anything from a request or reply body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultReachError {
    /// No connection to the daemon: the connection file, the connect or the
    /// handshake failed, or the daemon closed the connection before the route
    /// opened.
    Unreachable,
    /// The daemon refused the route.open, with its code when it gave one.
    RouteRefused { code: Option<String> },
    /// The request was sent on an open route and no reply came back: the
    /// connection closed, or the daemon answered with an error frame.
    CallFailed { code: Option<String> },
}

/// Where a deposit can be made. The seam the capture flow is tested through;
/// production is [`ClaustrumVault`].
pub trait CookieVault: Send + Sync {
    /// Open one route to the vault.
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn VaultRoute>, VaultReachError>>;
}

/// One open route to the vault. Dropping it closes the route.
pub trait VaultRoute: Send {
    /// Send one request body and return the reply body.
    fn call<'a>(&'a mut self, request: &'a [u8])
        -> BoxFuture<'a, Result<Vec<u8>, VaultReachError>>;
}

/// How a deposit ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositEnd {
    Stored(Deposited),
    /// The vault refused. For a transient refusal, after the retries ran out.
    Refused(vault_wire::VaultRefusal),
    Unreachable,
    RouteRefused {
        code: Option<String>,
    },
    CallFailed {
        code: Option<String>,
    },
    /// The vault could not decode the request (an unknown, missing or
    /// mistyped field) and said so with a transport Error frame carrying
    /// [`vault_wire::INVALID_PARAMS`]. Nothing was written, and only a bug in
    /// this module's request causes it.
    RequestRejected,
    /// The deadline passed. `sent` says whether any request had been written,
    /// so whether the vault may have stored the login after all.
    DeadlineExceeded {
        sent: bool,
    },
    /// The vault answered outside the contract, or for another id.
    Malformed,
}

/// Deposit one request, retrying the transient class, all within `deadline`.
///
/// Takes the request by value so it is dropped, and so wiped, when the deposit
/// ends, whatever the ending: retries reuse the one buffer rather than
/// rebuilding it, because the cookie it was built from is already gone.
pub async fn deposit(
    vault: &dyn CookieVault,
    request: SecretBytes,
    credential_id: &str,
    deadline: Duration,
    backoff: &[Duration],
) -> DepositEnd {
    let sent = AtomicBool::new(false);
    let started = Instant::now();
    let attempt = async {
        let mut route = match vault.open().await {
            Ok(route) => route,
            Err(VaultReachError::Unreachable) => return DepositEnd::Unreachable,
            Err(VaultReachError::RouteRefused { code }) => {
                return DepositEnd::RouteRefused { code }
            }
            Err(VaultReachError::CallFailed { code }) => return DepositEnd::CallFailed { code },
        };
        let mut retries = backoff.iter();
        loop {
            sent.store(true, Ordering::Release);
            let reply = match route.call(request.as_bytes()).await {
                Ok(reply) => reply,
                Err(VaultReachError::CallFailed { code: Some(code) })
                    if code == vault_wire::INVALID_PARAMS =>
                {
                    return DepositEnd::RequestRejected
                }
                Err(VaultReachError::CallFailed { code })
                | Err(VaultReachError::RouteRefused { code }) => {
                    return DepositEnd::CallFailed { code }
                }
                Err(VaultReachError::Unreachable) => return DepositEnd::CallFailed { code: None },
            };
            match vault_wire::parse_deposit_reply(&reply) {
                Ok(DepositReply::Deposited(deposited)) if deposited.id == credential_id => {
                    return DepositEnd::Stored(deposited)
                }
                // A reply naming another id answers some other request.
                Ok(DepositReply::Deposited(_)) | Err(_) => return DepositEnd::Malformed,
                Ok(DepositReply::Refused(refusal)) if refusal.is_transient() => {
                    match retries.next() {
                        // Only a retry that can still finish inside the
                        // deadline is worth its wait.
                        Some(wait) if started.elapsed() + *wait < deadline => {
                            tokio::time::sleep(*wait).await;
                        }
                        _ => return DepositEnd::Refused(refusal),
                    }
                }
                Ok(DepositReply::Refused(refusal)) => return DepositEnd::Refused(refusal),
            }
        }
    };
    let end = tokio::time::timeout(deadline, attempt)
        .await
        .unwrap_or_else(|_| DepositEnd::DeadlineExceeded {
            sent: sent.load(Ordering::Acquire),
        });
    drop(request);
    end
}

/// The production vault: claustrum, reached through the daemon this module
/// is registered with.
pub struct ClaustrumVault {
    connection_file: PathBuf,
    module_id: String,
    launch_nonce: Option<String>,
    target_module: String,
    bind_session: &'static str,
}

impl std::fmt::Debug for ClaustrumVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaustrumVault")
            .field("connection_file", &self.connection_file)
            .field("module_id", &self.module_id)
            .field("presents_launch_nonce", &self.launch_nonce.is_some())
            .finish()
    }
}

impl ClaustrumVault {
    /// A vault reached through `connection_file`, presenting `launch_nonce`
    /// as `module_id`'s consumer identity. `None` opens the route without
    /// one, which the daemon stamps `Direct`.
    pub fn new(connection_file: PathBuf, module_id: String, launch_nonce: Option<String>) -> Self {
        Self {
            connection_file,
            module_id,
            launch_nonce,
            target_module: vault_wire::VAULT_MODULE_ID.to_owned(),
            bind_session: BIND_SESSION,
        }
    }

    /// The vault as this running module reaches it: its own connection file
    /// and module id, and the launch nonce the daemon spawned it with.
    pub(crate) fn supervised(connection_file: PathBuf, module_id: String) -> Self {
        let nonce = crate::launch_nonce::for_consumer_identity();
        Self::new(connection_file, module_id, nonce)
    }

    /// Reuse the authenticated, one-call transport for another management read.
    /// The caller owns the deadline and dropping the route closes its connection.
    pub(crate) fn management(connection_file: PathBuf, module_id: String, target: &str) -> Self {
        Self {
            target_module: target.to_owned(),
            bind_session: "computer.agent_cursor",
            ..Self::supervised(connection_file, module_id)
        }
    }

    async fn open_route(&self) -> Result<ClaustrumRoute, VaultReachError> {
        let connection = connection_file::read(&self.connection_file)
            .map_err(|_| VaultReachError::Unreachable)?;
        let endpoint = connection
            .endpoints
            .first()
            .ok_or(VaultReachError::Unreachable)?;
        let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
            .await
            .map_err(|_| VaultReachError::Unreachable)?;
        // One request and then a wait for its reply: there is no following
        // write for Nagle to coalesce with, only an ACK to wait for.
        let _ = stream.set_nodelay(true);
        authenticate_client(&mut stream, &connection, AUTH_DEADLINE)
            .await
            .map_err(|_| VaultReachError::Unreachable)?;

        let identity = BindIdentity::new(BIND_HARNESS, self.bind_session);
        let consumer = self
            .launch_nonce
            .as_deref()
            .map(|launch_nonce| ConsumerIdentity {
                module_id: &self.module_id,
                launch_nonce,
            });
        let open =
            vault_wire::management_route_open_request(&identity, consumer, &self.target_module)
                .map_err(|_| VaultReachError::Unreachable)?;
        send_request(
            &mut stream,
            crate::control_flags(),
            0,
            0,
            OPEN_CORRELATION,
            open.as_bytes(),
        )
        .await
        .map_err(|_| VaultReachError::Unreachable)?;
        drop(open);
        loop {
            let frame = match read_frame(&mut stream).await {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(_) => return Err(VaultReachError::Unreachable),
            };
            if frame.header.channel != 0 || frame.header.corr != OPEN_CORRELATION {
                continue;
            }
            match frame.header.ty {
                FrameType::Response => {
                    let Some(RouteOpened {
                        route_channel,
                        route_epoch,
                    }) = vault_wire::parse_route_opened(&frame.body)
                    else {
                        return Err(VaultReachError::RouteRefused { code: None });
                    };
                    return Ok(ClaustrumRoute {
                        stream,
                        channel: route_channel,
                        epoch: route_epoch,
                        next_correlation: 1,
                    });
                }
                FrameType::Error => {
                    return Err(VaultReachError::RouteRefused {
                        code: vault_wire::error_frame_code(&frame.body),
                    })
                }
                _ => continue,
            }
        }
    }
}

impl CookieVault for ClaustrumVault {
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn VaultRoute>, VaultReachError>> {
        Box::pin(async move {
            self.open_route()
                .await
                .map(|route| Box::new(route) as Box<dyn VaultRoute>)
        })
    }
}

/// One open route to claustrum on its own connection.
struct ClaustrumRoute {
    stream: TcpStream,
    channel: u16,
    epoch: u32,
    next_correlation: u64,
}

impl VaultRoute for ClaustrumRoute {
    fn call<'a>(
        &'a mut self,
        request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, VaultReachError>> {
        Box::pin(async move {
            let correlation = self.next_correlation;
            self.next_correlation += 1;
            let flags = Flags::new(false, Priority::Interactive, false);
            send_request(
                &mut self.stream,
                flags,
                self.channel,
                self.epoch,
                correlation,
                request,
            )
            .await
            .map_err(|_| VaultReachError::CallFailed { code: None })?;
            loop {
                let frame = match read_frame(&mut self.stream).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => return Err(VaultReachError::CallFailed { code: None }),
                };
                if frame.header.channel != self.channel || frame.header.corr != correlation {
                    continue;
                }
                match frame.header.ty {
                    FrameType::Response => return Ok(frame.body),
                    FrameType::Error => {
                        return Err(VaultReachError::CallFailed {
                            code: vault_wire::error_frame_code(&frame.body),
                        })
                    }
                    _ => continue,
                }
            }
        })
    }
}

/// Write one request frame as its header and then its body, straight to the
/// socket.
///
/// Not `subc_transport::write_frame`: that joins header and body into a fresh
/// buffer it frees unwiped, which for the deposit is one more copy of the
/// cookie. Writing the two parts in turn leaves the caller's buffer the only
/// copy in this process.
async fn send_request(
    stream: &mut TcpStream,
    flags: Flags,
    channel: u16,
    epoch: u32,
    correlation: u64,
    body: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let header = EnvelopeHeader {
        len,
        ver: PROTOCOL_VERSION,
        ty: FrameType::Request,
        flags,
        channel,
        epoch,
        corr: correlation,
    };
    stream.write_all(&header.encode()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A daemon that is not there is reported as unreachable, promptly.
    #[tokio::test]
    async fn a_missing_connection_file_is_unreachable() {
        let vault = ClaustrumVault::new(
            PathBuf::from("/nonexistent/ck-cerebellum-test/subc-connection.json"),
            "cerebellum".to_string(),
            Some("nonce".to_string()),
        );
        let error = vault.open().await.err().expect("no daemon to reach");
        assert_eq!(error, VaultReachError::Unreachable);
    }

    #[test]
    fn the_debug_form_never_prints_the_nonce() {
        let vault = ClaustrumVault::new(
            PathBuf::from("/tmp/c.json"),
            "cerebellum".to_string(),
            Some("planted-nonce-77".to_string()),
        );
        let debug = format!("{vault:?}");
        assert!(!debug.contains("planted-nonce-77"), "{debug}");
        assert!(debug.contains("presents_launch_nonce: true"), "{debug}");
    }
}
