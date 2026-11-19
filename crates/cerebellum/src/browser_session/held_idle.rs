//! Idle protection for a held consent call, without owning a driver operation.

use super::*;
use cerebellum_core::clock::SystemClock;
use std::sync::Weak;

#[derive(Default)]
pub(super) struct IdleHolds {
    next: u64,
    deadlines: HashMap<u64, MonoInstant>,
}

/// A candidate names the exact browser that was live when the call started.
/// Only a recorded consent hold activates it; dropping an ordinary call does
/// not renew its lease. A weak reference cannot keep a closed session alive.
#[derive(Debug)]
pub(crate) struct IdleHold {
    cell: Weak<SessionCell>,
    clock: Arc<SystemClock>,
    id: Option<u64>,
}

impl IdleHold {
    pub(crate) fn start(&mut self, max_age: Duration) {
        let Some(cell) = self.cell.upgrade() else {
            return;
        };
        let Ok(mut meta) = cell.meta() else {
            return;
        };
        let now = self.clock.now();
        if self.id.is_some() || !meta.admits_calls() || idle_expired(&mut meta, &*self.clock, now) {
            return;
        }
        let id = meta.idle_holds.next;
        meta.idle_holds.next += 1;
        meta.idle_holds
            .deadlines
            .insert(id, now.saturating_add(max_age));
        self.id = Some(id);
    }
}

impl Drop for IdleHold {
    fn drop(&mut self) {
        let (Some(id), Some(cell)) = (self.id, self.cell.upgrade()) else {
            return;
        };
        let mut meta = recovered(cell.meta());
        if meta.admits_calls() {
            idle_expired(&mut meta, &*self.clock, self.clock.now());
            if meta.idle_holds.deadlines.remove(&id).is_some()
                && meta.idle_holds.deadlines.is_empty()
            {
                meta.lease.renew(&*self.clock);
            }
        }
    }
}

pub(super) fn idle_expired<C: MonotonicClock>(
    meta: &mut SessionMeta,
    clock: &C,
    now: MonoInstant,
) -> bool {
    // If no terminal event reaches us, the pin still ends at the maximum age
    // of a continuation. Count idle time from that deadline, not from the
    // first sweep that happens to notice it.
    let mut last_expiry = None;
    meta.idle_holds.deadlines.retain(|_, deadline| {
        if *deadline > now {
            return true;
        }
        last_expiry = last_expiry.max(Some(*deadline));
        false
    });
    if !meta.idle_holds.deadlines.is_empty() {
        return false;
    }
    if let Some(expired_at) = last_expiry {
        meta.lease.monotonic_deadline =
            expired_at.saturating_add(Duration::from_millis(meta.lease.idle_timeout_ms));
        meta.lease.sync_custody_deadline(clock);
    }
    now >= meta.lease.deadline()
}

impl BrowserSessions {
    pub(crate) fn idle_hold(&self, route_key: &str, clock: Arc<SystemClock>) -> Option<IdleHold> {
        let cell = self.active_cell(route_key).ok()??;
        Some(IdleHold {
            cell: Arc::downgrade(&cell),
            clock,
            id: None,
        })
    }

    pub fn accept_dispatch<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
    ) -> DispatchAdmission {
        let cell = match self.active_cell(route_key) {
            Ok(Some(cell)) => cell,
            Ok(None) => return DispatchAdmission::NoSession,
            Err(()) => return DispatchAdmission::StateUnavailable,
        };
        let Ok(mut meta) = cell.meta() else {
            return DispatchAdmission::StateUnavailable;
        };
        // A launching or tearing-down session does not have a driver to admit.
        if matches!(
            meta.lifecycle,
            Lifecycle::Launching | Lifecycle::TeardownOwned
        ) {
            return DispatchAdmission::LaunchPending;
        }
        if !meta.admits_calls() || idle_expired(&mut meta, clock, clock.now()) {
            return DispatchAdmission::NoSession;
        }
        meta.lease.renew(clock);
        DispatchAdmission::Accepted(self.admit(&cell, &mut meta, false))
    }

    pub(super) fn expire_cell<C: MonotonicClock>(
        &self,
        cell: &Arc<SessionCell>,
        clock: &C,
        config: &BrowserConfig,
    ) -> bool {
        {
            let mut meta = recovered(cell.meta());
            let now = clock.now();
            if meta.lifecycle != Lifecycle::Ready
                || meta.terminal.is_some()
                || meta.pending_operations != 0
                || meta.handoff.as_ref().is_some_and(
                    |handoff| matches!(handoff, HandoffState::Open(open) if now < open.expires_at),
                )
                || !idle_expired(&mut meta, clock, now)
            {
                return false;
            }
            meta.terminal = Some(BrowserSessionTerminalOutcome::IdleExpired);
        }
        cell.notify();
        self.finish_teardown(
            cell,
            BrowserSessionTerminalOutcome::IdleExpired,
            configured_grace(config),
        );
        true
    }
}
