//! Optional live turn hints. Core's direct notification and the helper's idle
//! fade remain the fallback when a live subscription misses a notice.

#[cfg(target_os = "macos")]
mod live;
#[cfg(all(target_os = "macos", test))]
mod live_tests;
mod notice;
#[cfg(test)]
mod tests;

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::{sync::mpsc, task::JoinHandle, time::Instant};

#[cfg(target_os = "macos")]
pub(crate) use live::LiveTransport;
pub(crate) use notice::{Kind, Notice};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

const LINGER: Duration = Duration::from_secs(30);
const RETRY: Duration = Duration::from_secs(1);
const OPEN_WINDOW: Duration = Duration::from_secs(4);

/// Process-lifetime counts for the live hint subscription, reported in health
/// so a live check can tell whether hints arrived and whether the connection
/// closed when the last badge went idle. Identifier-free by design.
#[derive(Default)]
pub(crate) struct HintGauges {
    opened: std::sync::atomic::AtomicU64,
    open_failures: std::sync::atomic::AtomicU64,
    last_open_failure: std::sync::atomic::AtomicU8,
    closed: std::sync::atomic::AtomicU64,
    received: std::sync::atomic::AtomicU64,
    matched: std::sync::atomic::AtomicU64,
    open_now: std::sync::atomic::AtomicBool,
    active_badges: std::sync::atomic::AtomicU64,
}

pub(crate) static HINT_GAUGES: HintGauges = HintGauges {
    opened: std::sync::atomic::AtomicU64::new(0),
    open_failures: std::sync::atomic::AtomicU64::new(0),
    last_open_failure: std::sync::atomic::AtomicU8::new(0),
    closed: std::sync::atomic::AtomicU64::new(0),
    received: std::sync::atomic::AtomicU64::new(0),
    matched: std::sync::atomic::AtomicU64::new(0),
    open_now: std::sync::atomic::AtomicBool::new(false),
    active_badges: std::sync::atomic::AtomicU64::new(0),
};

impl HintGauges {
    pub(crate) fn matched(&self) {
        self.matched
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn insert_into(&self, metrics: &mut serde_json::Map<String, serde_json::Value>) {
        use std::sync::atomic::Ordering::{Acquire, Relaxed};
        for (name, value) in [
            ("turnHintSubscriptionsOpened", self.opened.load(Relaxed)),
            ("turnHintOpenFailures", self.open_failures.load(Acquire)),
            ("turnHintSubscriptionsClosed", self.closed.load(Relaxed)),
            ("turnHintNoticesReceived", self.received.load(Relaxed)),
            ("turnHintBadgesEnded", self.matched.load(Relaxed)),
            ("turnHintActiveBadges", self.active_badges.load(Relaxed)),
        ] {
            metrics.insert(name.into(), serde_json::json!(value));
        }
        metrics.insert(
            "turnHintSubscriptionOpen".into(),
            serde_json::json!(self.open_now.load(Relaxed)),
        );
        let reason = match self.last_open_failure.load(Relaxed) {
            1 => Some("unavailable"),
            2 => Some("timeout"),
            _ => None,
        };
        metrics.insert(
            "turnHintLastOpenFailureReason".into(),
            serde_json::json!(reason),
        );
    }

    fn open_failed(&self, reason: OpenFailure) {
        use std::sync::atomic::Ordering::{Relaxed, Release};
        self.last_open_failure.store(reason as u8, Relaxed);
        self.open_failures.fetch_add(1, Release);
    }

    fn set_connection(&self, connection: &Option<Connection>, was_open: &mut bool) {
        let open = connection.is_some();
        if *was_open && !open {
            self.closed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        *was_open = open;
        self.open_now
            .store(open, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum OpenFailure {
    Unavailable = 1,
    Timeout,
}

pub(crate) trait Transport: Send + Sync {
    fn open(&self) -> BoxFuture<'_, Result<Connection, OpenFailure>>;
}

pub(crate) struct Connection {
    notices: mpsc::Receiver<Notice>,
    refresh_at: Option<Instant>,
    // Owns the reader and every NATS client clone; dropping a subscription alone
    // would leave the connection's authentication/reconnect work alive.
    _guard: Box<dyn Send>,
}

#[derive(Clone)]
pub(crate) struct Listener {
    commands: mpsc::UnboundedSender<Activity>,
    idle: Duration,
}

enum Activity {
    Drawn(String, Instant),
    Ended(String),
    Shutdown,
}

impl Listener {
    pub(crate) fn new(
        transport: Arc<dyn Transport>,
        idle: Duration,
        receive: impl Fn(Notice) + Send + Sync + 'static,
    ) -> Self {
        let (commands, receiver) = mpsc::unbounded_channel();
        tokio::spawn(run(transport, receiver, receive, &HINT_GAUGES));
        Self { commands, idle }
    }

    pub(crate) fn drawn(&self, agent: &str) {
        let _ = self.commands.send(Activity::Drawn(
            agent.to_owned(),
            Instant::now() + self.idle,
        ));
    }

    pub(crate) fn ended(&self, agent: &str) {
        let _ = self.commands.send(Activity::Ended(agent.to_owned()));
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.commands.send(Activity::Shutdown);
    }
}

struct Opening(JoinHandle<Result<Connection, OpenFailure>>);

impl Drop for Opening {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run(
    transport: Arc<dyn Transport>,
    mut commands: mpsc::UnboundedReceiver<Activity>,
    receive: impl Fn(Notice),
    gauges: &HintGauges,
) {
    let mut active = HashMap::<String, Instant>::new();
    let mut connection: Option<Connection> = None;
    let mut opening: Option<Opening> = None;
    let mut linger = None;
    let mut retry = None;
    let mut was_open = false;
    loop {
        let now = Instant::now();
        let was_active = !active.is_empty();
        let last_idle = active.values().copied().max();
        active.retain(|_, until| *until > now);
        if was_active && active.is_empty() {
            linger = last_idle.map(|until| until + LINGER);
        }
        if linger.is_some_and(|until| until <= now) {
            connection = None;
            opening = None;
            linger = None;
            retry = None;
        }
        if connection
            .as_ref()
            .and_then(|bus| bus.refresh_at)
            .is_some_and(|until| until <= now)
        {
            connection = None;
        }
        if !active.is_empty()
            && connection.is_none()
            && opening.is_none()
            && retry.is_none_or(|until| until <= now)
        {
            let transport = transport.clone();
            opening = Some(Opening(tokio::spawn(async move {
                tokio::time::timeout(OPEN_WINDOW, transport.open())
                    .await
                    .unwrap_or(Err(OpenFailure::Timeout))
            })));
            retry = None;
        }
        gauges.set_connection(&connection, &mut was_open);
        gauges
            .active_badges
            .store(active.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let deadline = active
            .values()
            .copied()
            .chain(linger)
            .chain(connection.as_ref().and_then(|bus| bus.refresh_at))
            .chain(retry.filter(|_| !active.is_empty()))
            .min();
        tokio::select! {
            command = commands.recv() => match command {
                Some(Activity::Drawn(agent, until)) => {
                    active.insert(agent, until);
                    linger = None;
                }
                Some(Activity::Ended(agent)) => {
                    if active.remove(&agent).is_some() && active.is_empty() {
                        linger = Some(Instant::now() + LINGER);
                    }
                }
                Some(Activity::Shutdown) | None => break,
            },
            result = async {
                match opening.as_mut() {
                    Some(task) => (&mut task.0).await.unwrap_or(Err(OpenFailure::Unavailable)),
                    None => std::future::pending().await,
                }
            } => {
                opening = None;
                match result {
                    Ok(bus) => {
                        gauges
                            .opened
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        connection = Some(bus);
                    }
                    Err(reason) => {
                        gauges.open_failed(reason);
                        retry = Some(Instant::now() + RETRY);
                    }
                }
            },
            notice = async {
                match connection.as_mut() {
                    Some(bus) => bus.notices.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(notice) = notice {
                    gauges
                        .received
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    receive(notice);
                } else {
                    connection = None;
                    retry = Some(Instant::now() + RETRY);
                }
            },
            _ = async {
                match deadline {
                    Some(until) => tokio::time::sleep_until(until).await,
                    None => std::future::pending().await,
                }
            } => {},
        }
    }
}
