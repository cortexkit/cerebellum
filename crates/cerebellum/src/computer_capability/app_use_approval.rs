//! Process-memory authority for widening app use, independent of release admission.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_core::config::AppUse;
use tokio::sync::watch;
use tokio::time::Instant;

use super::operator_confirm::{self, Failure};

pub(super) const CONFIRM_LIMIT: Duration = Duration::from_secs(290);
const DECLINE_HOLD: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct Approval {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    observed: Option<AppUse>,
    approved: Option<AppUse>,
    generation: u64,
    attempt: Option<Arc<Attempt>>,
    backoff: Option<Instant>,
}

struct Attempt {
    generation: u64,
    result: watch::Sender<Option<Result<(), Failure>>>,
    stop: watch::Sender<bool>,
}

impl Approval {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn observe(&self, value: Option<AppUse>) {
        let mut state = self.lock();
        if state.observed != value {
            state.observed = value;
            state.approved = None;
            state.generation += 1;
            if let Some(attempt) = &state.attempt {
                attempt.stop.send_replace(true);
            }
        }
    }

    /// Explicit desk fixtures have no operator route and never read live config.
    pub(super) fn foreground_fixture() -> Self {
        Self {
            state: Mutex::new(State {
                observed: Some(AppUse::Foreground),
                approved: Some(AppUse::Foreground),
                ..State::default()
            }),
        }
    }

    pub(super) async fn resolve(&self, mode: AppUse, cancel: &crate::CancelHandle) -> AppUse {
        if mode == AppUse::Background {
            return mode;
        }
        match self.confirm(cancel).await {
            Ok(()) => AppUse::Foreground,
            Err(reason) => {
                crate::tool_result::app_use_note(format!(
                    "Using background mode: {}.",
                    reason.line()
                ));
                AppUse::Background
            }
        }
    }

    async fn confirm(&self, cancel: &crate::CancelHandle) -> Result<(), Failure> {
        let deadline = crate::call_context::CALL_DEADLINE.try_with(|end| *end).ok();
        let (attempt, leader) = {
            let mut state = self.lock();
            if state.observed != Some(AppUse::Foreground) {
                return Err(Failure::SettingChanged);
            }
            if state.approved == Some(AppUse::Foreground) {
                return Ok(());
            }
            if let Some(until) = state.backoff.filter(|until| *until > Instant::now()) {
                return Err(Failure::Backoff {
                    retry_after_ms: remaining_ms(until),
                });
            }
            // A prompt may take 290 seconds. Do not start one the caller cannot
            // wait for, or spend the action's much shorter platform-work budget.
            if let Some(end) =
                deadline.filter(|end| end.saturating_duration_since(Instant::now()) < CONFIRM_LIMIT)
            {
                return Err(Failure::TimeLimit {
                    remaining_ms: remaining_ms(end),
                });
            }
            match &state.attempt {
                Some(attempt) => (Arc::clone(attempt), false),
                None => {
                    let attempt = Arc::new(Attempt {
                        generation: state.generation,
                        result: watch::channel(None).0,
                        stop: watch::channel(false).0,
                    });
                    state.attempt = Some(Arc::clone(&attempt));
                    (attempt, true)
                }
            }
        };
        let end = deadline.unwrap_or_else(|| Instant::now() + CONFIRM_LIMIT);
        let mut stopped = attempt.stop.subscribe();
        let result = if leader {
            let guard = Leader {
                approval: self,
                attempt: Arc::clone(&attempt),
                finished: false,
            };
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(Failure::Cancelled),
                _ = async { if !*stopped.borrow_and_update() { let _ = stopped.changed().await; } } => Err(Failure::SettingChanged),
                _ = tokio::time::sleep_until(end) => Err(Failure::TimeLimit { remaining_ms: 0 }),
                result = operator_confirm::confirm() => result,
            };
            guard.finish(result)
        } else {
            let mut receiver = attempt.result.subscribe();
            loop {
                if let Some(result) = receiver.borrow_and_update().clone() {
                    break result;
                }
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break Err(Failure::Cancelled),
                    _ = tokio::time::sleep_until(end) => break Err(Failure::TimeLimit { remaining_ms: 0 }),
                    _ = receiver.changed() => {},
                }
            }
        };
        let state = self.lock();
        if state.generation != attempt.generation || state.observed != Some(AppUse::Foreground) {
            return Err(Failure::SettingChanged);
        }
        result
    }
}

fn remaining_ms(end: Instant) -> u64 {
    end.saturating_duration_since(Instant::now())
        .as_millis()
        .min(u64::MAX as u128) as u64
}

// The initiating call owns the confirm future. Dropping it publishes a result
// to waiters and drops the wire guard, which withdraws the person's prompt.
struct Leader<'a> {
    approval: &'a Approval,
    attempt: Arc<Attempt>,
    finished: bool,
}

impl Leader<'_> {
    fn finish(mut self, mut result: Result<(), Failure>) -> Result<(), Failure> {
        let mut state = self.approval.lock();
        if state.generation != self.attempt.generation {
            result = Err(Failure::SettingChanged);
        }
        if result.is_ok() {
            state.approved = Some(AppUse::Foreground);
        }
        match &result {
            Err(Failure::Declined) => state.backoff = Some(Instant::now() + DECLINE_HOLD),
            Err(Failure::Backoff { retry_after_ms }) => {
                state.backoff = Some(Instant::now() + Duration::from_millis(*retry_after_ms))
            }
            _ => {}
        }
        state.attempt = None;
        self.attempt.result.send_replace(Some(result.clone()));
        self.finished = true;
        result
    }
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.approval.lock().attempt = None;
            self.attempt
                .result
                .send_replace(Some(Err(Failure::Cancelled)));
        }
    }
}
