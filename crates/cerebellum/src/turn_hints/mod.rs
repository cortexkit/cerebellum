//! Optional live turn hints. Core's direct notification and the helper's idle
//! fade remain the fallback when a live subscription misses a notice.

mod live;
mod notice;
#[cfg(test)]
mod tests;

use std::{collections::HashMap, sync::Arc, time::Duration};

use futures_util::future::BoxFuture;
use tokio::{sync::mpsc, task::JoinHandle, time::Instant};

pub(crate) use live::LiveTransport;
pub(crate) use notice::{Kind, Notice};

const LINGER: Duration = Duration::from_secs(30);
const RETRY: Duration = Duration::from_secs(1);

pub(crate) trait Transport: Send + Sync {
    fn open(&self) -> BoxFuture<'_, Result<Connection, String>>;
}

pub(crate) struct Connection {
    notices: mpsc::Receiver<Notice>,
    refresh_at: Instant,
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
        tokio::spawn(run(transport, receiver, receive));
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

struct Opening(JoinHandle<Result<Connection, String>>);

impl Drop for Opening {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run(
    transport: Arc<dyn Transport>,
    mut commands: mpsc::UnboundedReceiver<Activity>,
    receive: impl Fn(Notice),
) {
    let mut active = HashMap::<String, Instant>::new();
    let mut connection: Option<Connection> = None;
    let mut opening: Option<Opening> = None;
    let mut linger = None;
    let mut retry = None;
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
        if connection.as_ref().is_some_and(|bus| bus.refresh_at <= now) {
            connection = None;
        }
        if !active.is_empty()
            && connection.is_none()
            && opening.is_none()
            && retry.is_none_or(|until| until <= now)
        {
            let transport = transport.clone();
            opening = Some(Opening(tokio::spawn(async move { transport.open().await })));
            retry = None;
        }
        let deadline = active
            .values()
            .copied()
            .chain(linger)
            .chain(connection.as_ref().map(|bus| bus.refresh_at))
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
                    Some(task) => Some((&mut task.0).await),
                    None => std::future::pending().await,
                }
            } => {
                opening = None;
                match result {
                    Some(Ok(Ok(bus))) => connection = Some(bus),
                    _ => retry = Some(Instant::now() + RETRY),
                }
            },
            notice = async {
                match connection.as_mut() {
                    Some(bus) => bus.notices.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(notice) = notice {
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
