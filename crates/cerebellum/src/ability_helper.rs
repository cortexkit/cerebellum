//! Host-neutral helper transport. Platform launchers own suspended spawn,
//! running-image verification and release; the manager owns the framed session.

use std::{future::Future, io, path::Path, pin::Pin, sync::Arc, time::Duration};

use cerebellum_ability::Token;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
    time::Instant,
};

use crate::{ability_source::UnitKind, terminal_arbiter::TerminalArbiter};

pub const REQUEST_MAX: usize = 256 * 1024;
pub const REPLY_MAX: usize = 4 * 1024 * 1024;
pub const IDLE_LIMIT: Duration = Duration::from_secs(30);
const STOP_POLL: Duration = Duration::from_millis(250);

pub type HelperFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Channel: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Channel for T {}

/// `start` must use the supplied absolute sibling path, never PATH or an
/// inherited environment. It returns only after verifying the suspended child's
/// running image and releasing it. Failure (including cancellation of the start
/// future) must kill and reap any child, without releasing an unverified image.
pub trait Launcher: Send + Sync + 'static {
    fn start<'a>(
        &'a self,
        kind: UnitKind,
        path: &'a Path,
    ) -> HelperFuture<'a, io::Result<Box<dyn Process>>>;
}

/// Dropping a process must close its channel and arrange child cleanup even if
/// its async owner is dropped. `reap` observes exit, and must not block a thread.
pub trait Process: Send {
    fn channel(&mut self) -> &mut dyn Channel;
    fn has_exited(&mut self) -> io::Result<bool>;
    fn kill(&mut self) -> io::Result<()>;
    fn close_channel(&mut self);
    fn reap(&mut self) -> HelperFuture<'_, io::Result<()>>;
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionStatus {
    Granted,
    Undecided,
    Denied,
    Restricted,
    WriteOnly,
    PermissionMissing,
    SourceMissing,
    FormatUnrecognized,
}

impl PermissionStatus {
    pub(crate) fn unavailable_reason(self) -> Option<&'static str> {
        match self {
            Self::Granted => None,
            Self::Undecided
            | Self::Denied
            | Self::Restricted
            | Self::WriteOnly
            | Self::PermissionMissing => Some("permission_missing"),
            Self::SourceMissing => Some("source_missing"),
            Self::FormatUnrecognized => Some("format_unrecognized"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenStatus {
    pub token: Token,
    pub status: PermissionStatus,
}

#[derive(Debug, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {
        tokens: Vec<Token>,
    },
    Setup {
        token: Token,
    },
    Choices {
        token: Token,
        key: String,
        limit: Option<usize>,
        cursor: Option<String>,
    },
    Call {
        token: Token,
        op: String,
        args: Value,
        scope: Value,
    },
    Proceed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Hello { build_commit: String },
    Status { tokens: Vec<TokenStatus> },
    Prompting,
    Setup { status: PermissionStatus },
    Result { value: Value },
    Error { code: ErrorCode },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AbilityScopeStale,
    AbilityItemNotFound,
    AbilitySourceTimeout,
    AbilitySourceFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Unverified,
    RevisionMismatch,
    TimedOut,
    Failed,
    Stopped,
}

pub(crate) enum Completion {
    Reply(Reply),
    Unanswered,
}

struct Session {
    process: Option<Box<dyn Process>>,
    last_reply: Option<Instant>,
}

pub(crate) struct Manager {
    kind: UnitKind,
    commit: String,
    launcher: Arc<dyn Launcher>,
    session: Arc<Mutex<Session>>,
}

impl Manager {
    pub(crate) fn new(kind: UnitKind, commit: String, launcher: Arc<dyn Launcher>) -> Self {
        assert!(matches!(kind, UnitKind::Pim | UnitKind::Fda));
        Self {
            kind,
            commit,
            launcher,
            session: Arc::new(Mutex::new(Session {
                process: None,
                last_reply: None,
            })),
        }
    }

    pub(crate) fn executable_path(&self) -> io::Result<std::path::PathBuf> {
        let executable = std::env::current_exe()?;
        let directory = executable
            .parent()
            .ok_or_else(|| io::Error::other("no executable directory"))?;
        Ok(directory.join(match self.kind {
            UnitKind::Pim => "ck-cerebellum-pim",
            UnitKind::Fda => "ck-cerebellum-fda",
            _ => unreachable!(),
        }))
    }

    pub(crate) async fn request(
        &self,
        request: Request,
        deadline: Instant,
        gate: &TerminalArbiter,
    ) -> Result<Completion, Failure> {
        let mut session = self.session.lock().await;
        let result = self.exchange(&mut session, request, deadline, gate).await;
        if result.is_err()
            || matches!(
                result,
                Ok(Completion::Unanswered
                    | Completion::Reply(Reply::Error {
                        code: ErrorCode::AbilitySourceTimeout | ErrorCode::AbilitySourceFailed,
                    }))
            )
        {
            terminate(&mut session, true).await;
        } else {
            session.last_reply = Some(Instant::now());
            self.expire_idle();
        }
        result
    }

    pub(crate) async fn invalidate(&self) {
        let mut session = self.session.lock().await;
        terminate(&mut session, true).await;
    }

    async fn exchange(
        &self,
        session: &mut Session,
        request: Request,
        deadline: Instant,
        gate: &TerminalArbiter,
    ) -> Result<Completion, Failure> {
        if gate.gate.stopped() {
            return Err(Failure::Stopped);
        }
        if let Some(process) = session.process.as_mut() {
            if process.has_exited().map_err(|_| Failure::Failed)? {
                // A privacy change can end an idle helper. Reap it before
                // launching a replacement, without refusing the new request.
                terminate(session, false).await;
            }
        }
        if session.process.is_none() {
            let path = self.executable_path().map_err(|_| Failure::Unverified)?;
            let process = until(self.launcher.start(self.kind, &path), deadline, gate, true)
                .await?
                .map_err(|_| Failure::Unverified)?;
            session.process = Some(process);
            let hello = receive(session, deadline, gate, true).await?;
            match hello {
                Reply::Hello { build_commit } if build_commit == self.commit => {}
                Reply::Hello { .. } => return Err(Failure::RevisionMismatch),
                _ => return Err(Failure::Failed),
            }
        }
        send(session, &request, deadline, gate).await?;
        let setup = matches!(request, Request::Setup { .. });
        let reply = receive(session, deadline, gate, setup).await?;
        if matches!(reply, Reply::Prompting) {
            if !setup || self.kind != UnitKind::Pim {
                return Err(Failure::Failed);
            }
            // Recheck after prompting, immediately before the sole frame that
            // authorizes the helper to enter a system permission request API.
            send(session, &Request::Proceed, deadline, gate).await?;
            let park_deadline =
                Instant::now() + Duration::from_millis(crate::budgets::CONSENT_PARK_LIMIT_MS);
            return match receive(session, park_deadline, gate, true).await {
                Err(Failure::TimedOut) => Ok(Completion::Unanswered),
                Ok(
                    reply @ (Reply::Setup { .. }
                    | Reply::Error {
                        code: ErrorCode::AbilitySourceTimeout | ErrorCode::AbilitySourceFailed,
                    }),
                ) => Ok(Completion::Reply(reply)),
                Ok(_) => Err(Failure::Failed),
                Err(error) => Err(error),
            };
        }
        if matches!(
            (&request, &reply),
            (
                _,
                Reply::Error {
                    code: ErrorCode::AbilitySourceTimeout | ErrorCode::AbilitySourceFailed,
                }
            ) | (Request::Call { .. }, Reply::Error { .. })
                | (Request::Status { .. }, Reply::Status { .. })
                | (Request::Setup { .. }, Reply::Setup { .. })
                | (
                    Request::Choices { .. } | Request::Call { .. },
                    Reply::Result { .. }
                )
        ) {
            Ok(Completion::Reply(reply))
        } else {
            Err(Failure::Failed)
        }
    }

    fn expire_idle(&self) {
        let weak = Arc::downgrade(&self.session);
        let deadline = Instant::now() + IDLE_LIMIT;
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            let Some(session) = weak.upgrade() else {
                return;
            };
            let mut session = session.lock().await;
            if session
                .last_reply
                .is_some_and(|last| Instant::now() >= last + IDLE_LIMIT)
            {
                terminate(&mut session, false).await;
            }
        });
    }
}

async fn terminate(session: &mut Session, kill: bool) {
    if let Some(mut process) = session.process.take() {
        if kill {
            let _ = process.kill();
        }
        process.close_channel();
        if tokio::time::timeout(
            Duration::from_millis(crate::budgets::EXIT_OBSERVATION_MS),
            process.reap(),
        )
        .await
        .is_err()
        {
            let _ = process.kill();
        }
    }
    session.last_reply = None;
}

async fn until<T>(
    future: impl Future<Output = T>,
    deadline: Instant,
    gate: &TerminalArbiter,
    stop: bool,
) -> Result<T, Failure> {
    tokio::pin!(future);
    loop {
        if stop && gate.gate.stopped() {
            return Err(Failure::Stopped);
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => return Err(Failure::TimedOut),
            result = &mut future => return Ok(result),
            _ = tokio::time::sleep(STOP_POLL), if stop => {},
        }
    }
}

async fn send(
    session: &mut Session,
    request: &Request,
    deadline: Instant,
    gate: &TerminalArbiter,
) -> Result<(), Failure> {
    if gate.gate.stopped() {
        return Err(Failure::Stopped);
    }
    until(
        write_frame(
            session.process.as_mut().expect("started helper").channel(),
            request,
            REQUEST_MAX,
        ),
        deadline,
        gate,
        true,
    )
    .await?
    .map_err(|_| Failure::Failed)
}

async fn receive(
    session: &mut Session,
    deadline: Instant,
    gate: &TerminalArbiter,
    stop: bool,
) -> Result<Reply, Failure> {
    until(
        read_frame(
            session.process.as_mut().expect("started helper").channel(),
            REPLY_MAX,
        ),
        deadline,
        gate,
        stop,
    )
    .await?
    .map_err(|_| Failure::Failed)
}

/// Check the announced size before allocating or reading a body.
pub async fn read_frame<T: serde::de::DeserializeOwned>(
    channel: &mut dyn Channel,
    max: usize,
) -> io::Result<T> {
    let len = channel.read_u32().await? as usize;
    if len == 0 || len > max {
        return Err(io::Error::other("invalid helper frame size"));
    }
    let mut body = vec![0; len];
    channel.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(io::Error::other)
}

pub async fn write_frame<T: Serialize>(
    channel: &mut dyn Channel,
    value: &T,
    max: usize,
) -> io::Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() > max || body.len() > u32::MAX as usize {
        return Err(io::Error::other("helper frame too large"));
    }
    channel.write_u32(body.len() as u32).await?;
    channel.write_all(&body).await?;
    channel.flush().await
}
