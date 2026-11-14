//! Host-neutral source units. Queue admission precedes journal reservation;
//! a lease keeps the unit until the handler's commit, or until stuck work ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_ability::{Platform, Token};
use tokio::time::Instant;

use crate::call_queue::{LaneGuard, QueuePosition, Registry};
use crate::terminal_arbiter::TerminalArbiter;

pub const QUEUE_LIMIT: Duration = Duration::from_secs(10);
pub const SOURCE_LIMIT: Duration = Duration::from_secs(10);
const STOP_POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitKind {
    Pim,
    Fda,
    Outlook,
    Eds,
}

impl UnitKind {
    pub fn for_platform(platform: Platform) -> &'static [Self] {
        match platform {
            Platform::MacOs => &[Self::Pim, Self::Fda],
            Platform::Windows => &[Self::Outlook],
            Platform::Linux => &[Self::Eds],
        }
    }

    pub fn tokens(self) -> &'static [Token] {
        match self {
            Self::Pim | Self::Eds => &[Token::Calendar, Token::Reminders, Token::Contacts],
            Self::Fda => &[Token::Messages, Token::Mail],
            Self::Outlook => Platform::Windows.tokens(),
        }
    }
}

/// An in-process adapter opens, uses and drops its entire session inside each
/// method. No COM interface, connection or other thread-affine handle may escape
/// into a reply. Status checks all of the unit's tokens in one request.
pub trait Source: Send + Sync + 'static {
    type Request: Send + 'static;
    type Reply: Send + 'static;
    type Status: Send + 'static;
    type Error: Send + 'static;

    fn request(&self, request: Self::Request) -> Result<Self::Reply, Self::Error>;
    fn status(&self, tokens: &'static [Token]) -> Result<Self::Status, Self::Error>;
}

#[derive(Clone)]
pub struct SourceUnit(Arc<Unit>);

/// One set belongs to a service plane. All tokens of an in-process platform
/// resolve to the same runner, not separate per-token queues.
pub struct SourceUnits(Vec<SourceUnit>);

impl SourceUnits {
    pub fn new(platform: Platform) -> Self {
        Self(
            UnitKind::for_platform(platform)
                .iter()
                .map(|&kind| SourceUnit::new(kind))
                .collect(),
        )
    }

    pub fn for_token(&self, token: Token) -> Option<&SourceUnit> {
        self.0
            .iter()
            .find(|unit| unit.kind().tokens().contains(&token))
    }

    pub fn iter(&self) -> impl Iterator<Item = &SourceUnit> {
        self.0.iter()
    }
}

struct Unit {
    kind: UnitKind,
    queue: Arc<Registry>,
    work: Mutex<Option<Work>>,
}

struct Work {
    deadline: Instant,
    done: Arc<AtomicBool>,
}

/// Queue refusals occur before reservation. Queue expiry and quarantine map to
/// `ability_source_timeout` without a journal entry, unlike a source deadline
/// after dispatch, which must be committed before replying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    SourceTimeout,
    Stopped,
}

pub struct SourceTicket {
    unit: SourceUnit,
    position: QueuePosition,
    gate: Arc<TerminalArbiter>,
    deadline: Instant,
}

/// Keep the lease through reservation, dispatch and journal commit. A timed-out
/// blocking call retains its own hold, even after this lease is dropped.
pub struct SourceLease {
    unit: SourceUnit,
    lane: Arc<LaneGuard>,
    gate: Arc<TerminalArbiter>,
    deadline: Instant,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SourceOutcome<T, E> {
    Completed(Result<T, E>),
    /// The work finished after the call stopped. Retain only its outcome for
    /// the journal; never forward its data to the caller.
    Discarded(Result<(), E>),
    TimedOut,
    Stopped,
    WorkerFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum UnitStatus<T> {
    Responsive(T),
    /// Local describe state only; never an Error-frame refusal code.
    SourceUnresponsive,
}

impl SourceUnit {
    pub fn new(kind: UnitKind) -> Self {
        Self(Arc::new(Unit {
            kind,
            queue: Arc::default(),
            work: Mutex::new(None),
        }))
    }

    pub fn kind(&self) -> UnitKind {
        self.0.kind
    }

    pub fn quarantined(&self) -> bool {
        self.0.work.lock().unwrap().as_ref().is_some_and(|work| {
            !work.done.load(Ordering::Acquire) && Instant::now() >= work.deadline
        })
    }

    /// Fix FIFO order synchronously, before the handler task is polled. Dropping
    /// a ticket, including on stop or expiry, removes its position.
    pub fn arrive(&self, gate: Arc<TerminalArbiter>) -> Result<SourceTicket, QueueError> {
        if gate.gate.stopped() {
            return Err(QueueError::Stopped);
        }
        if self.quarantined() {
            return Err(QueueError::SourceTimeout);
        }
        Ok(SourceTicket {
            unit: self.clone(),
            position: self.0.queue.reserve((String::new(), String::new())),
            gate,
            deadline: Instant::now() + QUEUE_LIMIT,
        })
    }

    /// Exactly one status request per unit, in the ordinary FIFO. Callers can
    /// poll units concurrently so one unresponsive unit cannot hide the others.
    pub async fn status<S: Source>(
        &self,
        source: Arc<S>,
        gate: Arc<TerminalArbiter>,
    ) -> UnitStatus<S::Status> {
        let ticket = match self.arrive(gate) {
            Ok(ticket) => ticket,
            Err(_) => return UnitStatus::SourceUnresponsive,
        };
        let mut lease = match ticket.wait().await {
            Ok(lease) => lease,
            Err(_) => return UnitStatus::SourceUnresponsive,
        };
        let tokens = self.kind().tokens();
        match lease.blocking(move || source.status(tokens)).await {
            SourceOutcome::Completed(Ok(status)) => UnitStatus::Responsive(status),
            _ => UnitStatus::SourceUnresponsive,
        }
    }
}

impl SourceTicket {
    pub async fn wait(self) -> Result<SourceLease, QueueError> {
        let Self {
            unit,
            position,
            gate,
            deadline,
        } = self;
        let acquire = position.acquire();
        tokio::pin!(acquire);
        loop {
            if gate.gate.stopped() {
                return Err(QueueError::Stopped);
            }
            if unit.quarantined() || Instant::now() >= deadline {
                return Err(QueueError::SourceTimeout);
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => return Err(QueueError::SourceTimeout),
                lane = &mut acquire => {
                    if gate.gate.stopped() {
                        return Err(QueueError::Stopped);
                    }
                    return Ok(SourceLease {
                        unit,
                        lane: Arc::new(lane),
                        gate,
                        deadline: Instant::now() + SOURCE_LIMIT,
                    });
                }
                _ = tokio::time::sleep(STOP_POLL) => {}
            }
        }
    }
}

impl SourceLease {
    pub fn source_deadline(&self) -> Instant {
        self.deadline
    }

    pub async fn request<S: Source>(
        &mut self,
        source: Arc<S>,
        request: S::Request,
    ) -> SourceOutcome<S::Reply, S::Error> {
        self.blocking(move || source.request(request)).await
    }

    async fn blocking<T, E>(
        &mut self,
        work: impl FnOnce() -> Result<T, E> + Send + 'static,
    ) -> SourceOutcome<T, E>
    where
        T: Send + 'static,
        E: Send + 'static,
    {
        if self.gate.gate.stopped() {
            return SourceOutcome::Stopped;
        }
        if self.unit.quarantined() || Instant::now() >= self.deadline {
            return SourceOutcome::TimedOut;
        }
        let done = Arc::new(AtomicBool::new(false));
        {
            let mut active = self.unit.0.work.lock().unwrap();
            // A dropped request future cannot cancel blocking work. Even its
            // original lease must not dispatch again while that work runs.
            if active
                .as_ref()
                .is_some_and(|work| !work.done.load(Ordering::Acquire))
            {
                return SourceOutcome::TimedOut;
            }
            *active = Some(Work {
                deadline: self.deadline,
                done: done.clone(),
            });
        }
        let lane = self.lane.clone();
        let gate = self.gate.clone();
        let deadline = self.deadline;
        let mut worker = tokio::task::spawn_blocking(move || {
            let _lane = lane;
            let _done = WorkDone(done);
            // Pool saturation can delay the closure. Recheck before opening a
            // session so a stopped or expired call starts no source access.
            if gate.gate.stopped() {
                return SourceOutcome::Stopped;
            }
            if Instant::now() >= deadline {
                return SourceOutcome::TimedOut;
            }
            let result = work();
            if gate.gate.stopped() {
                SourceOutcome::Discarded(result.map(|_| ()))
            } else {
                SourceOutcome::Completed(result)
            }
        });
        let outcome = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => SourceOutcome::TimedOut,
            result = &mut worker => result.unwrap_or(SourceOutcome::WorkerFailed),
        };
        match outcome {
            SourceOutcome::Completed(result) if self.gate.gate.stopped() => {
                SourceOutcome::Discarded(result.map(|_| ()))
            }
            outcome => outcome,
        }
    }
}

struct WorkDone(Arc<AtomicBool>);

impl Drop for WorkDone {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
