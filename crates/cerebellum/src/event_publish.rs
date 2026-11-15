//! Best-effort, post-commit notices. Call records and direct display writes remain
//! authoritative; losing a notice must never change either path.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering::Relaxed},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use cortexkit_bus_naming::{validate_token, TokenKind};
use cortexkit_role_tool_display::DisplayWrite;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::{sync::mpsc, time::Instant};

#[cfg(test)]
pub(crate) mod tests;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
const CAPACITY: usize = 128;
const OPEN_WINDOW: Duration = Duration::from_secs(5);
const PUBLISH_WINDOW: Duration = Duration::from_secs(3);
const QUEUE_WINDOW: Duration = Duration::from_secs(10);
const LINGER: Duration = Duration::from_secs(30);

/// The transport builds subjects with `cortexkit-bus-naming` and the credential's
/// account. No account, session, or agent name is inferred at the commit hooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    LateResultReady { custodian_module: Option<String> },
    ToolDisplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Failure {
    Unavailable = 1,
    Timeout,
    Overflow,
    Expired,
}

pub(crate) trait Transport: Send + Sync {
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn Connection>, Failure>>;
}

/// Dropping a connection must release all client owners and background work.
/// Success means the JetStream acknowledgement arrived, not just a socket write.
pub(crate) trait Connection: Send {
    fn publish<'a>(
        &'a mut self,
        kind: &'a Kind,
        message_id: &'a str,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Failure>>;
}

#[derive(Default)]
pub(crate) struct Gauges {
    published: AtomicU64,
    failed: AtomicU64,
    last_failure: AtomicU8,
}

static GAUGES: OnceLock<Arc<Gauges>> = OnceLock::new();

pub(crate) fn gauges() -> &'static Arc<Gauges> {
    GAUGES.get_or_init(|| Arc::new(Gauges::default()))
}

impl Gauges {
    fn failed(&self, reason: Failure) {
        self.last_failure.store(reason as u8, Relaxed);
        self.failed.fetch_add(1, Relaxed);
    }

    pub(crate) fn insert_into(&self, metrics: &mut Map<String, Value>) {
        metrics.insert(
            "busEventsPublished".into(),
            json!(self.published.load(Relaxed)),
        );
        metrics.insert("busEventsFailed".into(), json!(self.failed.load(Relaxed)));
        let reason = match self.last_failure.load(Relaxed) {
            1 => Some("unavailable"),
            2 => Some("timeout"),
            3 => Some("overflow"),
            4 => Some("expired"),
            _ => None,
        };
        metrics.insert("busEventsLastFailureReason".into(), json!(reason));
    }
}

pub(crate) struct Publisher {
    sender: mpsc::Sender<Event>,
    receiver: Mutex<Option<mpsc::Receiver<Event>>>,
    gauges: Arc<Gauges>,
}

impl Default for Publisher {
    fn default() -> Self {
        Self::new(gauges().clone())
    }
}

struct Event {
    kind: Kind,
    message_id: String,
    bytes: Vec<u8>,
    queued_at: Instant,
}

fn identity(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn custodian_module(principal: &str) -> Option<String> {
    let module = principal.strip_prefix("reserved:")?;
    validate_token(TokenKind::ModuleId, module).ok()?;
    Some(module.to_owned())
}

impl Publisher {
    fn new(gauges: Arc<Gauges>) -> Self {
        let (sender, receiver) = mpsc::channel(CAPACITY);
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            gauges,
        }
    }

    // The shared bus client's adapter will install the production transport.
    // Recovery can queue notices before installation, without a task or timer.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "The shared bus client adapter has not landed yet")
    )]
    pub(crate) fn connect(&self, transport: Arc<dyn Transport>) {
        if let Some(receiver) = self.receiver.lock().unwrap().take() {
            tokio::spawn(run(transport, receiver, self.gauges.clone()));
        }
    }

    pub(crate) fn late_result(&self, principal: &str, call_key: &str, outcome: &str) {
        self.enqueue(
            Kind::LateResultReady {
                custodian_module: custodian_module(principal),
            },
            identity(
                &serde_json::to_vec(&("late_result_ready", principal, call_key, outcome))
                    .expect("identity serializes"),
            ),
            serde_json::to_vec(&json!({"call_key":call_key, "outcome":outcome}))
                .expect("notice serializes"),
        );
    }

    pub(crate) fn tool_display(&self, write: &DisplayWrite) {
        let writer = subc_protocol::Principal::Reserved {
            module_id: "cerebellum".into(),
        };
        let key = cortexkit_role_tool_display::idempotency_key(&writer, write)
            .expect("display identity serializes");
        self.enqueue(
            Kind::ToolDisplay,
            identity(&key),
            serde_json::to_vec(write).expect("display write serializes"),
        );
    }

    fn enqueue(&self, kind: Kind, message_id: String, bytes: Vec<u8>) {
        let event = Event {
            kind,
            message_id,
            bytes,
            queued_at: Instant::now(),
        };
        if let Err(error) = self.sender.try_send(event) {
            self.gauges.failed(match error {
                mpsc::error::TrySendError::Full(_) => Failure::Overflow,
                mpsc::error::TrySendError::Closed(_) => Failure::Unavailable,
            });
        }
    }
}

async fn run(
    transport: Arc<dyn Transport>,
    mut events: mpsc::Receiver<Event>,
    gauges: Arc<Gauges>,
) {
    let mut connection: Option<Box<dyn Connection>> = None;
    let mut idle_close = None;
    // Startup recovery may predate transport installation. Its queue budget
    // starts when delivery becomes possible, not while no client exists.
    let installed_at = Instant::now();
    loop {
        let event = tokio::select! {
            event = events.recv() => match event { Some(event) => event, None => break },
            _ = async {
                match idle_close {
                    Some(until) => tokio::time::sleep_until(until).await,
                    None => std::future::pending().await,
                }
            } => {
                connection = None;
                idle_close = None;
                continue;
            }
        };
        if idle_close.is_some_and(|until| until <= Instant::now()) {
            connection = None;
            idle_close = None;
        }
        let expires = event.queued_at.max(installed_at) + QUEUE_WINDOW;
        if expires <= Instant::now() {
            gauges.failed(Failure::Expired);
            continue;
        }
        if connection.is_none() {
            match tokio::time::timeout_at(
                expires.min(Instant::now() + OPEN_WINDOW),
                transport.open(),
            )
            .await
            {
                Ok(Ok(opened)) => connection = Some(opened),
                failure => {
                    gauges.failed(match failure {
                        Ok(Err(reason)) => reason,
                        _ => Failure::Timeout,
                    });
                    continue;
                }
            }
        }
        let bus = connection.as_mut().expect("opened connection");
        let result = tokio::time::timeout_at(
            expires.min(Instant::now() + PUBLISH_WINDOW),
            bus.publish(&event.kind, &event.message_id, &event.bytes),
        )
        .await;
        idle_close = Some(Instant::now() + LINGER);
        match result {
            Ok(Ok(())) => {
                gauges.published.fetch_add(1, Relaxed);
            }
            failure => {
                gauges.failed(match failure {
                    Ok(Err(reason)) => reason,
                    _ => Failure::Timeout,
                });
                connection = None;
                idle_close = None;
            }
        }
    }
}
