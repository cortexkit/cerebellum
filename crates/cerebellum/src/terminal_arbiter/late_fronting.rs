//! Bounded cleanup of one OS activation that outlived its action's reply.
//! The original reply stays failed: this task can restore focus, never finish
//! or retry the refused action. The fronting lock moves here with the host.

use super::*;
use crate::computer::dispatch::FrontingBracketHost;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex};

struct PendingWatch {
    request: crate::egress::RequestId,
    route_namespace: usize,
    stop: std::sync::Weak<AtomicU8>,
}

static PENDING: LazyLock<Mutex<BTreeMap<(usize, u32), PendingWatch>>> =
    LazyLock::new(Mutex::default);

/// Covers the gap between obligation registration and late-task startup.
/// Weak registry entries cannot extend the lifetime of a completed call.
pub(super) struct PendingRegistration {
    key: (usize, u32),
    stop: Arc<AtomicU8>,
}

pub(super) fn register_pending(
    domain: usize,
    target: u32,
    namespace: usize,
    request: crate::egress::RequestId,
) -> PendingRegistration {
    let stop = Arc::new(AtomicU8::new(0));
    let key = (domain, target);
    PENDING.lock().unwrap().insert(
        key,
        PendingWatch {
            request,
            route_namespace: namespace,
            stop: Arc::downgrade(&stop),
        },
    );
    PendingRegistration { key, stop }
}

impl Drop for PendingRegistration {
    fn drop(&mut self) {
        let mut pending = PENDING.lock().unwrap();
        if pending
            .get(&self.key)
            .is_some_and(|watch| watch.stop.ptr_eq(&Arc::downgrade(&self.stop)))
        {
            pending.remove(&self.key);
        }
    }
}

fn request_stop(stop: &AtomicU8, reason: u8) {
    // A new call or Cancel must never be upgraded into a route-close restore.
    let _ = stop.try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        Some(if old == 1 { 1 } else { reason })
    });
}

struct Watch {
    request: crate::egress::RequestId,
    route_namespace: usize,
    stop: Arc<AtomicU8>,
    done: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

static WATCHES: LazyLock<Mutex<BTreeMap<(usize, u32), Watch>>> = LazyLock::new(Mutex::default);

struct RegisteredWatch {
    key: (usize, u32),
    stop: Arc<AtomicU8>,
    done: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

impl Drop for RegisteredWatch {
    fn drop(&mut self) {
        let mut watches = WATCHES.lock().unwrap();
        if watches
            .get(&self.key)
            .is_some_and(|watch| Arc::ptr_eq(&watch.stop, &self.stop))
        {
            watches.remove(&self.key);
        }
        *self.done.0.lock().unwrap() = true;
        self.done.1.notify_all();
    }
}

pub(crate) fn cancel_late_fronting_target(domain: usize, pid: u32) -> bool {
    if let Some(stop) = PENDING
        .lock()
        .unwrap()
        .get(&(domain, pid))
        .and_then(|watch| watch.stop.upgrade())
    {
        request_stop(&stop, 1);
    }
    let done = {
        let watches = WATCHES.lock().unwrap();
        let Some(watch) = watches.get(&(domain, pid)) else {
            return true;
        };
        request_stop(&watch.stop, 1);
        Arc::clone(&watch.done)
    };
    // A new app call must not race a restore already in flight. If native
    // cleanup cannot finish, its caller closes the new dispatch gate.
    let (lock, changed) = &*done;
    let (finished, _) = changed
        .wait_timeout_while(
            lock.lock().unwrap(),
            Duration::from_millis(budgets::LATE_ACTIVATION_WATCH_MS),
            |done| !*done,
        )
        .unwrap();
    *finished
}

pub(crate) fn cancel_late_fronting_request(namespace: usize, request: crate::egress::RequestId) {
    for watch in PENDING.lock().unwrap().values() {
        if watch.route_namespace == namespace && watch.request == request {
            if let Some(stop) = watch.stop.upgrade() {
                request_stop(&stop, 1);
            }
        }
    }
    for watch in WATCHES.lock().unwrap().values() {
        if watch.route_namespace == namespace && watch.request == request {
            request_stop(&watch.stop, 1);
        }
    }
}

pub(crate) fn cancel_late_fronting_route(namespace: usize, channel: u16, epoch: u32) {
    for watch in PENDING.lock().unwrap().values() {
        if watch.route_namespace == namespace
            && (watch.request.0, watch.request.1) == (channel, epoch)
        {
            if let Some(stop) = watch.stop.upgrade() {
                request_stop(&stop, 2);
            }
        }
    }
    for watch in WATCHES.lock().unwrap().values() {
        if watch.route_namespace == namespace
            && (watch.request.0, watch.request.1) == (channel, epoch)
        {
            request_stop(&watch.stop, 2);
        }
    }
}

pub(crate) fn cancel_late_fronting_all(namespace: usize) {
    for watch in PENDING.lock().unwrap().values() {
        if watch.route_namespace == namespace {
            if let Some(stop) = watch.stop.upgrade() {
                request_stop(&stop, 2);
            }
        }
    }
    for watch in WATCHES.lock().unwrap().values() {
        if watch.route_namespace == namespace {
            request_stop(&watch.stop, 2);
        }
    }
}

#[cfg(all(feature = "desk-probe", target_os = "macos"))]
static LANDINGS: Mutex<Vec<(u32, u64)>> = Mutex::new(Vec::new());

#[cfg(all(feature = "desk-probe", target_os = "macos"))]
pub(crate) fn take_landings() -> Vec<(u32, u64)> {
    std::mem::take(&mut *LANDINGS.lock().unwrap())
}

#[cfg(all(feature = "desk-probe", target_os = "macos"))]
pub(super) fn note_landing(target: u32, latency: u64) {
    LANDINGS.lock().unwrap().push((target, latency));
}

pub(super) fn start(
    cell: &Arc<RestoreCell>,
    request: crate::egress::RequestId,
    domain: usize,
    route_namespace: usize,
    cause: Option<TerminalCause>,
    recorder: Option<LateFrontingRecorder>,
) {
    let (mut host, lock, since, already_restored) = {
        let mut inner = cell.inner();
        let Some(since) = inner.pending_since.take() else {
            return;
        };
        let Some(host) = inner.host.take() else {
            return;
        };
        let already_restored = std::mem::take(&mut inner.pending_restored);
        (host, inner.lock.take(), since, already_restored)
    };
    let stop = Arc::clone(&cell.pending_watch.stop);
    match cause {
        Some(TerminalCause::RouteClosed) => request_stop(&stop, 2),
        Some(TerminalCause::Cancelled) => request_stop(&stop, 1),
        _ => {}
    }
    let done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    {
        let mut watches = WATCHES.lock().unwrap();
        // The process-wide fronting lock is still held. A previous task for
        // this target cannot be running under a different obligation.
        if watches.contains_key(&(domain, cell.target_pid)) {
            return;
        }
        watches.insert(
            (domain, cell.target_pid),
            Watch {
                request,
                route_namespace,
                stop: Arc::clone(&stop),
                done: Arc::clone(&done),
            },
        );
    }
    let target = cell.target_pid;
    let previous = cell.previous_pid;
    #[cfg(all(feature = "desk-probe", target_os = "macos"))]
    let probe_timing = cell.probe_timing.clone();
    let registered = RegisteredWatch {
        key: (domain, target),
        stop: Arc::clone(&stop),
        done,
    };
    std::thread::spawn(move || {
        let _lock = lock;
        #[cfg(target_os = "macos")]
        let _ax = cerebellum_macos::ax_budget::bound_messages_until(
            std::time::Instant::now()
                + Duration::from_millis(
                    budgets::LATE_ACTIVATION_WATCH_MS
                        .saturating_sub(host.now_ms().saturating_sub(since)),
                ),
        );
        let mut adapter = RestoreDecisionHost {
            host: host.as_mut(),
            _target: target,
            write_deadline: None,
            owner: super::DecisionOwner::Unowned,
            cell: None,
            #[cfg(all(feature = "desk-probe", target_os = "macos"))]
            probe_timing: &probe_timing,
        };
        let ended = crate::computer::dispatch::watch_late_activation_ending(
            &mut adapter,
            previous,
            target,
            since,
            budgets::LATE_ACTIVATION_WATCH_MS,
            crate::computer::dispatch::LateWatch::WholeWindow { already_restored },
            &|| stop.load(Ordering::Acquire) != 0,
        );
        let (mut restore, latency, input) =
            (ended.restore, ended.first_landing_ms, ended.person_input);
        let mut coverage_lost = ended.coverage_lost;
        // Route close ends the task too, but first puts back a target that
        // has already landed if observation still proves no person input.
        if stop.load(Ordering::Acquire) == 2
            && adapter.frontmost_pid() == Some(target)
            && !crate::computer::dispatch::hardware_input_since(
                adapter.hardware_input_snapshot(),
                since,
            )
        {
            let last = crate::computer::dispatch::watch_late_activation_ending(
                &mut adapter,
                previous,
                target,
                since,
                budgets::LATE_ACTIVATION_WATCH_MS,
                crate::computer::dispatch::LateWatch::FirstAttempt,
                &|| false,
            );
            restore = last.restore;
            coverage_lost = last.coverage_lost;
        }
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        probe_timing.watch_finished(restore);
        // No focus operation follows these drops. Slow audit persistence must
        // not extend the fronting lock or hold up a new call on this app.
        drop(_lock);
        drop(registered);
        if let Some(record) = recorder {
            let status = recorded_restore(restore, coverage_lost);
            record(json!({"cleanup": "restore", "target_pid": target,
                "previous_pid": previous, "restore": status,
                "person_input_during_fronting": input,
                "activation_latency_ms": latency}));
        }
    });
}

/// The late watch record's `restore` word. A watch that left focus alone
/// because the input observer lost coverage records `skipped_coverage`,
/// distinct from `skipped_person` (person input, or a third application in
/// front). The record is open completion JSON in the journal, read as
/// opaque bytes, so a new word needs no journal format change and an older
/// reader reads it like any other.
fn recorded_restore(
    restore: crate::computer::dispatch::RestoreStatus,
    coverage_lost: bool,
) -> &'static str {
    match restore {
        crate::computer::dispatch::RestoreStatus::Restored => "restored",
        crate::computer::dispatch::RestoreStatus::SkippedPerson { .. } if coverage_lost => {
            "skipped_coverage"
        }
        crate::computer::dispatch::RestoreStatus::SkippedPerson { .. } => "skipped_person",
        _ => "failed",
    }
}

#[cfg(test)]
pub(crate) struct HeldWatchForTest(RegisteredWatch);

#[cfg(test)]
impl HeldWatchForTest {
    pub(crate) fn stopped(&self) -> bool {
        self.0.stop.load(Ordering::Acquire) != 0
    }
}

#[cfg(test)]
pub(crate) fn hold_watch_for_test(domain: usize, pid: u32) -> HeldWatchForTest {
    let stop = Arc::new(AtomicU8::new(0));
    let done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let key = (domain, pid);
    WATCHES.lock().unwrap().insert(
        key,
        Watch {
            request: (0, 0, 0),
            route_namespace: domain,
            stop: Arc::clone(&stop),
            done: Arc::clone(&done),
        },
    );
    HeldWatchForTest(RegisteredWatch { key, stop, done })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_watch_cancellation_is_scoped_to_request_route_and_fronting_domain() {
        let key = (usize::MAX, u32::MAX);
        let stop = Arc::new(AtomicU8::new(0));
        let done = Arc::new((Mutex::new(true), std::sync::Condvar::new()));
        let registration = RegisteredWatch {
            key,
            stop: Arc::clone(&stop),
            done: Arc::clone(&done),
        };
        WATCHES.lock().unwrap().insert(
            key,
            Watch {
                request: (91, 92, 93),
                route_namespace: usize::MAX,
                stop: Arc::clone(&stop),
                done,
            },
        );
        cancel_late_fronting_request(0, (91, 92, 93));
        cancel_late_fronting_route(usize::MAX, 91, 0);
        assert_eq!(stop.load(Ordering::Acquire), 0);
        cancel_late_fronting_request(usize::MAX, (91, 92, 93));
        assert_eq!(stop.swap(0, Ordering::AcqRel), 1);
        cancel_late_fronting_route(usize::MAX, 91, 92);
        assert_eq!(stop.swap(0, Ordering::AcqRel), 2);
        assert!(cancel_late_fronting_target(0, u32::MAX));
        assert_eq!(stop.load(Ordering::Acquire), 0);
        assert!(cancel_late_fronting_target(usize::MAX, u32::MAX));
        assert_eq!(stop.load(Ordering::Acquire), 1);
        drop(registration);
        assert!(!WATCHES.lock().unwrap().contains_key(&key));
    }

    #[test]
    fn cancellation_before_task_start_is_retained_and_outranks_route_close() {
        let namespace = usize::MAX - 1;
        let key = (usize::MAX - 1, u32::MAX - 1);
        let pending = register_pending(key.0, key.1, namespace, (41, 42, 43));
        cancel_late_fronting_request(0, (41, 42, 43));
        assert_eq!(pending.stop.load(Ordering::Acquire), 0);
        cancel_late_fronting_route(namespace, 41, 42);
        assert_eq!(pending.stop.load(Ordering::Acquire), 2);
        cancel_late_fronting_request(namespace, (41, 42, 43));
        cancel_late_fronting_route(namespace, 41, 42);
        assert_eq!(pending.stop.load(Ordering::Acquire), 1);
        drop(pending);
        assert!(!PENDING.lock().unwrap().contains_key(&key));
    }
}

#[cfg(test)]
mod record_tests {
    use super::*;
    use crate::computer::dispatch::RestoreStatus;

    #[test]
    fn a_watch_stopped_by_lost_coverage_is_recorded_apart_from_a_person() {
        let skipped = RestoreStatus::SkippedPerson { now_front: None };
        assert_eq!(recorded_restore(skipped, true), "skipped_coverage");
        assert_eq!(recorded_restore(skipped, false), "skipped_person");
        assert_eq!(recorded_restore(RestoreStatus::Restored, true), "restored");
        assert_eq!(
            recorded_restore(
                RestoreStatus::Failed {
                    left_in_front: None
                },
                false
            ),
            "failed"
        );
    }
}
