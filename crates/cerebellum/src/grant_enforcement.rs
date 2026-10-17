//! Revocation must still allow a pressed key or mouse button to be released
//! and the action's journal record to be closed. Cancellation therefore signals
//! the running action instead of dropping it. Before each new external effect,
//! the dispatch gate also rechecks the exact grant rows the action selected.

use std::sync::{Arc, Mutex};

use crate::agent_grants::GrantUse;
use crate::CancelHandle;

#[derive(Default)]
pub(crate) struct CallGrants {
    active: std::sync::atomic::AtomicBool,
    rows: Mutex<Vec<GrantUse>>,
    changed: tokio::sync::Notify,
}

tokio::task_local! {
    static CALL_GRANTS: Arc<CallGrants>;
}

impl CallGrants {
    pub(crate) fn uses_row(&self, id: &str) -> bool {
        self.active.load(std::sync::atomic::Ordering::Acquire)
            && self
                .rows
                .lock()
                .unwrap()
                .iter()
                .any(|row| row.row().id == id)
    }
    pub(crate) fn is_live(&self) -> bool {
        let rows = self.rows.lock().unwrap().clone();
        rows.iter().all(GrantUse::is_live)
    }

    async fn invalidated(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let rows = self.rows.lock().unwrap().clone();
            let checks = async {
                let mut waiting = tokio::task::JoinSet::new();
                for row in rows {
                    waiting.spawn(async move { row.invalidated().await });
                }
                if waiting.is_empty() {
                    std::future::pending::<()>().await;
                } else {
                    let _ = waiting.join_next().await;
                }
            };
            tokio::select! {
                _ = notified => {},
                _ = checks => return,
            }
        }
    }
}

pub(crate) fn track(row: &GrantUse) {
    if let (Some(terminal), Some(id)) = (
        crate::TerminalArbiter::current(),
        row.row().card_ref.as_deref(),
    ) {
        terminal.track_grant_consent(id);
    }
    let _ = CALL_GRANTS.try_with(|grants| {
        grants.rows.lock().unwrap().push(row.clone());
        row.register(grants);
        grants.changed.notify_waiters();
        if let Some(terminal) = crate::TerminalArbiter::current() {
            terminal.gate.bind_grants(Arc::clone(grants));
        }
    });
}

pub(crate) fn commit_current() -> bool {
    CALL_GRANTS
        .try_with(|grants| grants.is_live())
        .unwrap_or(true)
}

pub(crate) async fn scope<F: std::future::Future>(cancel: CancelHandle, future: F) -> F::Output {
    let grants = Arc::new(CallGrants::default());
    grants
        .active
        .store(true, std::sync::atomic::Ordering::Release);
    struct Active(Arc<CallGrants>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0
                .active
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }
    let _active = Active(Arc::clone(&grants));
    CALL_GRANTS
        .scope(Arc::clone(&grants), async {
            tokio::pin!(future);
            tokio::select! {
                result = &mut future => result,
                _ = grants.invalidated() => {
                    cancel.cancel();
                    future.await
                },
            }
        })
        .await
}
