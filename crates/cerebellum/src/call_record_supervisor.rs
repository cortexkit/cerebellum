//! Bounded admission and settlement for keyed tool calls.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use subc_protocol::{session::ModuleControlResponse, Frame};

use crate::{budgets, build_error_frame, journal, wall_clock_ms, Planes};

pub(crate) struct CallRecordWorkers {
    permits: Arc<tokio::sync::Semaphore>,
    detached: std::sync::atomic::AtomicUsize,
    settlements: Mutex<HashMap<(String, String), PendingRecordSettlement>>,
    #[cfg(test)]
    pub(crate) lookup_observations: Mutex<Vec<LookupObservation>>,
    // A per-Planes barrier seam keeps concurrent fixture commits deterministic.
    #[cfg(test)]
    pub(crate) before_settlement: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[cfg(test)]
pub(crate) struct LookupObservation {
    pub(crate) pending_found: bool,
    pub(crate) settlement_confirmed: bool,
    pub(crate) elapsed: Duration,
    pub(crate) timed_out: bool,
    pub(crate) state: Option<journal::call_records::CallState>,
}

#[cfg(test)]
impl std::fmt::Debug for LookupObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupObservation")
            .field("pending_found", &self.pending_found)
            .field("settlement_confirmed", &self.settlement_confirmed)
            .field("elapsed", &self.elapsed)
            .field("timed_out", &self.timed_out)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone)]
struct PendingRecordSettlement {
    ready: tokio::sync::watch::Receiver<bool>,
    started: Arc<journal::call_records::CallSnapshot>,
}

impl Default for CallRecordWorkers {
    fn default() -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(
                budgets::MAX_CALL_RECORD_WORKERS,
            )),
            detached: std::sync::atomic::AtomicUsize::new(0),
            settlements: Mutex::new(HashMap::new()),
            #[cfg(test)]
            lookup_observations: Mutex::new(Vec::new()),
            #[cfg(test)]
            before_settlement: Mutex::new(None),
        }
    }
}

impl CallRecordWorkers {
    pub(crate) fn track_settlement(
        self: &Arc<Self>,
        ticket: &journal::call_records::CallTicket,
    ) -> CallRecordSettlement {
        let key = ticket.identity().clone();
        let (ready, receiver) = tokio::sync::watch::channel(false);
        self.settlements
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                key.clone(),
                PendingRecordSettlement {
                    ready: receiver,
                    started: ticket.started().clone(),
                },
            );
        CallRecordSettlement {
            workers: self.clone(),
            key,
            ready,
        }
    }

    pub(crate) fn health_report(&self, mut report: ModuleControlResponse) -> ModuleControlResponse {
        let detached = self.detached.load(std::sync::atomic::Ordering::SeqCst);
        if let ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } = &mut report
        {
            if detached > 0 {
                *status = subc_protocol::session::HealthStatus::Degraded;
            }
            if let Some(Value::Object(metrics)) = metrics {
                metrics.insert("detachedCallRecordWorkers".to_string(), json!(detached));
            }
        }
        report
    }
}

/// Published before a terminal frame can escape, including while its write is queued.
pub(crate) struct CallRecordSettlement {
    workers: Arc<CallRecordWorkers>,
    key: (String, String),
    ready: tokio::sync::watch::Sender<bool>,
}

impl CallRecordSettlement {
    pub(crate) fn finish(self) {
        let _ = self.ready.send(true);
    }
}

impl Drop for CallRecordSettlement {
    fn drop(&mut self) {
        self.workers
            .settlements
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.key);
    }
}

/// A forwarded reply may precede its record write. Wait for that exact write,
/// then read the record off the async executor, within one admission deadline.
pub(crate) async fn lookup_call_record(
    planes: &Planes,
    carrier: String,
    call_key: String,
) -> journal::call_records::Lookup {
    use journal::call_records::{CallRecordError, Lookup};
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS);
    let pending = planes
        .call_record_workers
        .settlements
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&(carrier.clone(), call_key.clone()))
        .cloned();
    // A timed-out write may hold the record mutex. Keep the initial durable
    // Started record snapshot so timeout can report uncertainty without waiting
    // on that mutex or treating an unpersisted consent settlement as proof of no action.
    let fallback = pending.as_ref().map(|pending| pending.started.clone());
    #[cfg(test)]
    let observation_start = std::time::Instant::now();
    #[cfg(test)]
    let pending_found = pending.is_some();
    #[cfg(test)]
    let settlement_confirmed = std::sync::atomic::AtomicBool::new(false);
    let lookup = async {
        if let Some(mut pending) = pending {
            pending
                .ready
                .wait_for(|finished| *finished)
                .await
                .map_err(|_| {
                    CallRecordError::WriteFailed("call-record settlement did not finish".into())
                })?;
            #[cfg(test)]
            settlement_confirmed.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let permit = planes
            .call_record_workers
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("call-record pool stays open");
        let task = CallRecordTask::new(&planes.call_record_workers);
        let _wait = CallRecordWait(Arc::clone(&task));
        let calls = planes.calls.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _completion = CallRecordCompletion(task);
            calls.lookup_exact(&carrier, &call_key)
        })
        .await
        .map_err(|error| {
            CallRecordError::WriteFailed(format!("call-record lookup failed: {error}"))
        })
    };
    let result = tokio::time::timeout_at(deadline, lookup).await;
    #[cfg(test)]
    planes
        .call_record_workers
        .lookup_observations
        .lock()
        .unwrap()
        .push(LookupObservation {
            pending_found,
            settlement_confirmed: settlement_confirmed.load(std::sync::atomic::Ordering::Relaxed),
            elapsed: observation_start.elapsed(),
            timed_out: result.is_err(),
            state: match &result {
                Ok(Ok(Lookup::Own(record))) => Some(record.state),
                _ => None,
            },
        });
    match result {
        Ok(Ok(lookup)) => lookup,
        Ok(Err(error)) => Lookup::Unavailable(error),
        Err(_) => match fallback {
            Some(started) => Lookup::Own((*started).clone()),
            None => Lookup::Unavailable(CallRecordError::WriteFailed(
                "call-record lookup timed out".into(),
            )),
        },
    }
}

#[derive(Default)]
struct CallRecordTaskState {
    finished: bool,
    detached: bool,
}

struct CallRecordTask {
    workers: Arc<CallRecordWorkers>,
    state: std::sync::Mutex<CallRecordTaskState>,
}

impl CallRecordTask {
    fn new(workers: &Arc<CallRecordWorkers>) -> Arc<Self> {
        Arc::new(Self {
            workers: Arc::clone(workers),
            state: std::sync::Mutex::new(CallRecordTaskState::default()),
        })
    }

    fn detach(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.finished && !state.detached {
            state.detached = true;
            self.workers
                .detached
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn finish(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.finished = true;
        if state.detached {
            state.detached = false;
            self.workers
                .detached
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct CallRecordCompletion(Arc<CallRecordTask>);

impl Drop for CallRecordCompletion {
    fn drop(&mut self) {
        self.0.finish();
    }
}

struct CallRecordWait(Arc<CallRecordTask>);

impl Drop for CallRecordWait {
    fn drop(&mut self) {
        self.0.detach();
    }
}

#[derive(Default)]
struct CallRecordAdmissionState {
    begun: Option<journal::call_records::Begin>,
    abandoned: bool,
}

struct CallRecordAdmissionWait {
    delivery: Arc<(
        std::sync::Mutex<CallRecordAdmissionState>,
        std::sync::Condvar,
    )>,
    task: Arc<CallRecordTask>,
}

impl Drop for CallRecordAdmissionWait {
    fn drop(&mut self) {
        let mut state = self
            .delivery
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.abandoned = true;
        self.delivery.1.notify_one();
        self.task.detach();
    }
}

pub(crate) fn call_record_unavailable(
    address: (u8, u16, u32, u64),
    error: &journal::call_records::CallRecordError,
) -> Frame {
    build_error_frame(
        address.0,
        address.1,
        address.2,
        address.3,
        "call_record_unavailable",
        &format!(
            "this call carries a call_key, and no record of it can be kept ({error}), so \
                 it was not run: a resend could not be told apart from a new call. Send it \
                 without a call_key to run it unprotected"
        ),
    )
    .expect("the bounded call-record refusal serializes")
}

pub(crate) async fn begin_call_record(
    planes: &Planes,
    address: (u8, u16, u32, u64),
    begin: impl FnOnce() -> journal::call_records::Begin + Send + 'static,
) -> journal::call_records::Begin {
    use journal::call_records::{Begin, CallRecordError, Settlement};
    // Queueing for a worker and writing the begin share one admission budget.
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS);
    let Ok(permit) = tokio::time::timeout_at(
        deadline,
        Arc::clone(&planes.call_record_workers.permits).acquire_owned(),
    )
    .await
    else {
        return Begin::Unavailable(CallRecordError::WriteFailed(
            "call-record admission timed out while all record workers were busy".into(),
        ));
    };
    let permit = permit.expect("call-record pool stays open");
    let timeout_error = CallRecordError::WriteFailed("call-record admission timed out".into());
    let refusal = Settlement::admission_timeout(&call_record_unavailable(address, &timeout_error));
    let task = CallRecordTask::new(&planes.call_record_workers);
    let delivery = Arc::new((
        std::sync::Mutex::new(CallRecordAdmissionState::default()),
        std::sync::Condvar::new(),
    ));
    let wait = CallRecordAdmissionWait {
        delivery: Arc::clone(&delivery),
        task: Arc::clone(&task),
    };
    let calls = Arc::clone(&planes.calls);
    let (ready, receiver) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _completion = CallRecordCompletion(task);
        let begun = begin();
        let mut state = delivery.0.lock().unwrap_or_else(|error| error.into_inner());
        state.begun = Some(begun);
        if !state.abandoned {
            let _ = ready.send(());
            // Keep ownership until the async caller claims the result. A timeout
            // or cancellation must not drop a buffered Execute ticket unrefused.
            state = delivery
                .1
                .wait_while(state, |state| !state.abandoned && state.begun.is_some())
                .unwrap_or_else(|error| error.into_inner());
        }
        let abandoned = state.begun.take();
        drop(state);
        if let Some(Begin::Execute(ticket)) = abandoned {
            calls.settle(ticket, refusal, wall_clock_ms());
        }
    });
    match tokio::time::timeout_at(deadline, receiver).await {
        Ok(Ok(())) => {
            let mut state = wait
                .delivery
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let begun = state
                .begun
                .take()
                .expect("the admission worker published its result");
            wait.delivery.1.notify_one();
            begun
        }
        Ok(Err(error)) => Begin::Unavailable(CallRecordError::WriteFailed(format!(
            "the record task did not finish: {error}"
        ))),
        Err(_) => Begin::Unavailable(timeout_error),
    }
}

pub(crate) async fn settle_call_record(planes: &Planes, settle: impl FnOnce() + Send + 'static) {
    let task = CallRecordTask::new(&planes.call_record_workers);
    let _wait = CallRecordWait(Arc::clone(&task));
    let permits = Arc::clone(&planes.call_record_workers.permits);
    // A full pool delays only this write, never replaces the chosen frame. The
    // supervisor waits asynchronously and owns the settlement after timeout.
    let mut job = tokio::spawn(async move {
        let completion = CallRecordCompletion(task);
        let permit = permits
            .acquire_owned()
            .await
            .expect("call-record pool stays open");
        let _ = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _completion = completion;
            settle();
        })
        .await;
    });
    let _ = tokio::time::timeout(
        Duration::from_millis(budgets::CALL_RECORD_SETTLE_MS),
        &mut job,
    )
    .await;
}

#[cfg(test)]
mod call_record_deadline_tests {
    use super::*;
    use crate::{
        forward_recording_reply, handle_keyed_tool_request, install_browser_test_bind,
        refused_before_dispatch, CallObservation, HealthState, JournalPersistence,
        PendingSettlement,
    };
    use journal::call_records::{
        Begin, CallRecordError, CallRecordStorage, CallRecords, CallState,
        InMemoryCallRecordStorage, Lookup,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use subc_protocol::{Flags, FrameType, Priority, PROTOCOL_VERSION};
    use tokio::sync::mpsc;

    #[derive(Default)]
    struct WriteBarrier {
        released: std::sync::Mutex<bool>,
        wake: std::sync::Condvar,
        entered: tokio::sync::Notify,
    }

    impl WriteBarrier {
        fn block(&self) {
            self.entered.notify_one();
            let released = self.released.lock().unwrap();
            drop(
                self.wake
                    .wait_while(released, |released| !*released)
                    .unwrap(),
            );
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.wake.notify_all();
        }
    }

    struct ReleaseOnDrop(Arc<WriteBarrier>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    struct BlockingStorage {
        memory: Arc<InMemoryCallRecordStorage>,
        writes: Arc<AtomicUsize>,
        block_write: usize,
        barrier: Arc<WriteBarrier>,
    }

    impl BlockingStorage {
        fn before_write(&self) {
            if self.writes.fetch_add(1, Ordering::SeqCst) + 1 == self.block_write {
                self.barrier.block();
            }
        }
    }

    impl CallRecordStorage for BlockingStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError> {
            self.memory.load()
        }
        fn append(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
            self.before_write();
            self.memory.append(bytes, version)
        }
        fn replace(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
            self.before_write();
            self.memory.replace(bytes, version)
        }
    }

    fn fixture(
        block_write: usize,
    ) -> (
        Planes,
        Arc<InMemoryCallRecordStorage>,
        Arc<AtomicUsize>,
        ReleaseOnDrop,
    ) {
        let memory = Arc::new(InMemoryCallRecordStorage::new());
        let writes = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(WriteBarrier::default());
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            None,
            JournalPersistence::Isolated,
        );
        planes.calls = Arc::new(CallRecords::open(
            Box::new(BlockingStorage {
                memory: memory.clone(),
                writes: writes.clone(),
                block_write,
                barrier: barrier.clone(),
            }),
            0,
        ));
        install_browser_test_bind(&planes.routes, 1, 1, &[]);
        (planes, memory, writes, ReleaseOnDrop(barrier))
    }

    fn request(corr: u64) -> Frame {
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            1,
            1,
            corr,
            serde_json::to_vec(
                &json!({"name": "no_such_tool", "arguments": {}, "call_key": "bounded:call"}),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn body(frame: &Frame) -> Value {
        serde_json::from_slice(&frame.body).unwrap()
    }

    fn principal(planes: &Planes) -> String {
        journal::call_records::principal_label(planes.routes.get(1, 1).unwrap().principal.as_ref())
    }

    fn pending(planes: &Planes) -> PendingSettlement {
        let Begin::Execute(ticket) =
            planes
                .calls
                .begin(&principal(planes), "bounded:call", "records", 0)
        else {
            panic!("first admission must execute")
        };
        let observation = CallObservation::new();
        observation.commit_point_follows();
        observation.gate_dispatched.store(true, Ordering::SeqCst);
        PendingSettlement {
            ticket: Some(ticket),
            observation,
            unattributed_at_start: cerebellum_core::dispatch_witness::unattributed_commit_count(),
            request: (1, 1, 1),
        }
    }

    fn chosen_reply() -> Frame {
        Frame::build(FrameType::Response, Flags::new(false, Priority::Interactive, false), 1, 1, 1,
            serde_json::to_vec(&json!({"outcome": "dispatch_outcome_unknown", "effect_status": "effect_indeterminate",
                "detail": {"dispatched": true, "reason": "action_deadline_exceeded", "step": "dispatch", "held_state": "none_held"}})).unwrap()).unwrap()
    }

    async fn idle(planes: &Planes) {
        let permits = planes
            .call_record_workers
            .permits
            .clone()
            .acquire_many_owned(budgets::MAX_CALL_RECORD_WORKERS as u32)
            .await
            .unwrap();
        drop(permits);
        assert_eq!(
            planes.call_record_workers.detached.load(Ordering::SeqCst),
            0
        );
    }

    fn snapshot(planes: &Planes) -> journal::call_records::CallSnapshot {
        let Lookup::Own(record) = planes.calls.lookup(&principal(planes), "bounded:call") else {
            panic!("record must exist")
        };
        record
    }

    fn poll_once<F: std::future::Future>(
        future: std::pin::Pin<&mut F>,
    ) -> std::task::Poll<F::Output> {
        future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    }

    async fn without_time_advancing<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        loop {
            if let std::task::Poll::Ready(output) = poll_once(future.as_mut()) {
                return output;
            }
            // Blocking workers need CPU time, not advancement of the paused clock.
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn burst_keyed_admissions_wait_for_workers_and_all_execute() {
        let (planes, _, writes, _) = fixture(usize::MAX);
        let gates: Vec<_> = (0..4)
            .map(|_| ReleaseOnDrop(Arc::new(WriteBarrier::default())))
            .collect();
        let mut admissions = Vec::new();
        let started = tokio::time::Instant::now();
        for (index, gate) in gates.iter().enumerate() {
            let planes = planes.clone();
            let barrier = gate.0.clone();
            admissions.push(tokio::spawn(async move {
                let calls = planes.calls.clone();
                let principal = principal(&planes);
                begin_call_record(&planes, (PROTOCOL_VERSION, 1, 1, index as u64), move || {
                    barrier.block();
                    calls.begin(&principal, &format!("burst:{index}"), "records", 0)
                })
                .await
            }));
            tokio::task::yield_now().await;
            if index < budgets::MAX_CALL_RECORD_WORKERS {
                without_time_advancing(gate.0.entered.notified()).await;
            }
        }
        assert_eq!(planes.call_record_workers.permits.available_permits(), 0);
        assert!(
            admissions.iter().all(|admission| !admission.is_finished()),
            "a burst queues rather than refusing calls when the workers are busy"
        );
        for index in 0..4 {
            gates[index].0.release();
            assert!(matches!(
                without_time_advancing(&mut admissions[index])
                    .await
                    .unwrap(),
                Begin::Execute(_)
            ));
            if index + budgets::MAX_CALL_RECORD_WORKERS < gates.len() {
                without_time_advancing(
                    gates[index + budgets::MAX_CALL_RECORD_WORKERS]
                        .0
                        .entered
                        .notified(),
                )
                .await;
            }
        }
        assert_eq!(writes.load(Ordering::SeqCst), 4);
        assert_eq!(tokio::time::Instant::now(), started);
        idle(&planes).await;
    }

    #[tokio::test(start_paused = true)]
    async fn held_workers_refuse_admission_only_at_the_deadline() {
        let (planes, memory, writes, _) = fixture(usize::MAX);
        let held = planes
            .call_record_workers
            .permits
            .clone()
            .acquire_many_owned(budgets::MAX_CALL_RECORD_WORKERS as u32)
            .await
            .unwrap();
        let (writer, mut frames) = mpsc::channel(8);
        let started = tokio::time::Instant::now();
        let mut admission = Box::pin(handle_keyed_tool_request(request(1), &writer, &planes));
        assert!(poll_once(admission.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS - 1)).await;
        assert!(poll_once(admission.as_mut()).is_pending());
        assert!(frames.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(
            matches!(
                poll_once(admission.as_mut()),
                std::task::Poll::Ready(Ok(()))
            ),
            "a full pool must refuse at the admission deadline, not wait forever"
        );
        let refusal = frames.try_recv().unwrap();
        assert_eq!(body(&refusal)["code"], "call_record_unavailable");
        assert!(body(&refusal)["message"]
            .as_str()
            .unwrap()
            .contains("call-record admission timed out while all record workers were busy"));
        assert!(refused_before_dispatch(&refusal));
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS)
        );
        assert_eq!(planes.call_record_workers.permits.available_permits(), 0);
        assert_eq!(
            planes.call_record_workers.detached.load(Ordering::SeqCst),
            0
        );
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert!(memory.load().unwrap().is_none());
        drop(admission);
        drop(held);
        idle(&planes).await;
        assert_eq!(
            writes.load(Ordering::SeqCst),
            0,
            "no late record worker was spawned"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_and_dropped_admissions_leave_no_permit_waiter_or_record() {
        let (planes, memory, writes, _) = fixture(usize::MAX);
        let held = planes
            .call_record_workers
            .permits
            .clone()
            .acquire_many_owned(budgets::MAX_CALL_RECORD_WORKERS as u32)
            .await
            .unwrap();
        let (writer, mut frames) = mpsc::channel(8);
        let cancelled = tokio::spawn({
            let planes = planes.clone();
            let writer = writer.clone();
            async move { handle_keyed_tool_request(request(1), &writer, &planes).await }
        });
        tokio::task::yield_now().await;
        assert!(!cancelled.is_finished());
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        {
            let mut dropped = Box::pin(handle_keyed_tool_request(request(2), &writer, &planes));
            assert!(poll_once(dropped.as_mut()).is_pending());
        }
        assert_eq!(planes.call_record_workers.permits.available_permits(), 0);
        assert_eq!(
            planes.call_record_workers.detached.load(Ordering::SeqCst),
            0
        );
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        drop(held);
        idle(&planes).await;
        assert_eq!(
            planes.call_record_workers.permits.available_permits(),
            budgets::MAX_CALL_RECORD_WORKERS
        );
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert!(memory.load().unwrap().is_none());
        assert!(frames.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn permit_wait_and_begin_share_one_admission_deadline() {
        let (planes, _, writes, release) = fixture(1);
        let held = planes
            .call_record_workers
            .permits
            .clone()
            .acquire_many_owned(budgets::MAX_CALL_RECORD_WORKERS as u32)
            .await
            .unwrap();
        let (writer, mut frames) = mpsc::channel(8);
        let mut admission = Box::pin(handle_keyed_tool_request(request(1), &writer, &planes));
        assert!(poll_once(admission.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS - 1)).await;
        drop(held);
        assert!(poll_once(admission.as_mut()).is_pending());
        without_time_advancing(release.0.entered.notified()).await;
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            poll_once(admission.as_mut()),
            std::task::Poll::Ready(Ok(()))
        ));
        let refusal = frames.try_recv().unwrap();
        assert_eq!(body(&refusal)["code"], "call_record_unavailable");
        let message = body(&refusal)["message"].as_str().unwrap().to_owned();
        assert!(message.contains("call-record admission timed out"));
        assert!(!message.contains("all record workers were busy"));
        drop(admission);
        release.0.release();
        idle(&planes).await;
        assert_eq!(snapshot(&planes).state, CallState::Refused);
    }

    #[tokio::test(start_paused = true)]
    async fn admission_timeout_refuses_late_execute_and_bounds_worker_capacity() {
        let (planes, _, writes, release) = fixture(1);
        let (writer, mut frames) = mpsc::channel(8);
        let first = tokio::spawn({
            let planes = planes.clone();
            let writer = writer.clone();
            async move {
                handle_keyed_tool_request(request(1), &writer, &planes)
                    .await
                    .unwrap();
            }
        });
        release.0.entered.notified().await;
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS - 1)).await;
        tokio::task::yield_now().await;
        assert!(
            frames.try_recv().is_err(),
            "admission waits up to its budget"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        first.await.unwrap();
        let refusal = frames.recv().await.unwrap();
        assert_eq!(body(&refusal)["code"], "call_record_unavailable");
        assert!(refused_before_dispatch(&refusal));
        assert_eq!(
            planes.call_record_workers.permits.available_permits(),
            budgets::MAX_CALL_RECORD_WORKERS - 1
        );
        let retry = tokio::spawn({
            let planes = planes.clone();
            let writer = writer.clone();
            async move {
                handle_keyed_tool_request(request(2), &writer, &planes)
                    .await
                    .unwrap();
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS)).await;
        retry.await.unwrap();
        assert_eq!(
            body(&frames.recv().await.unwrap())["code"],
            "call_record_unavailable"
        );
        assert_eq!(planes.call_record_workers.permits.available_permits(), 0);
        let started = tokio::time::Instant::now();
        let queued = tokio::spawn({
            let planes = planes.clone();
            let writer = writer.clone();
            async move {
                handle_keyed_tool_request(request(3), &writer, &planes)
                    .await
                    .unwrap();
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS - 1)).await;
        tokio::task::yield_now().await;
        assert!(
            frames.try_recv().is_err(),
            "a busy pool waits up to the deadline"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        queued.await.unwrap();
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS)
        );
        assert_eq!(
            body(&frames.recv().await.unwrap())["code"],
            "call_record_unavailable"
        );
        assert_eq!(
            writes.load(Ordering::SeqCst),
            1,
            "no excess blocking write is spawned"
        );
        assert_eq!(
            planes.call_record_workers.detached.load(Ordering::SeqCst),
            2
        );
        let report = planes
            .call_record_workers
            .health_report(planes.health.report());
        let ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } = report
        else {
            panic!()
        };
        assert_eq!(status, subc_protocol::session::HealthStatus::Degraded);
        assert_eq!(metrics.unwrap()["detachedCallRecordWorkers"], 2);
        release.0.release();
        idle(&planes).await;
        let record = snapshot(&planes);
        assert_eq!(record.state, CallState::Refused);
        assert_eq!(
            record.refusal_reason.as_deref(),
            Some("call_record_admission_timeout")
        );
        handle_keyed_tool_request(request(4), &writer, &planes)
            .await
            .unwrap();
        assert_eq!(body(&frames.recv().await.unwrap()), body(&refusal));
        idle(&planes).await;
    }

    #[tokio::test(start_paused = true)]
    async fn settlement_timeout_forwards_chosen_frame_and_late_write_keeps_it() {
        let (planes, memory, _, release) = fixture(2);
        let mut pending = pending(&planes);
        let observation = pending.observation.clone();
        let (writer, mut frames) = mpsc::channel(8);
        let out = chosen_reply();
        let forward = tokio::spawn({
            let planes = planes.clone();
            let writer = writer.clone();
            let out = out.clone();
            async move {
                forward_recording_reply(out, &mut pending, &writer, &planes)
                    .await
                    .unwrap();
            }
        });
        release.0.entered.notified().await;
        let recovered = CallRecords::open(
            Box::new(BlockingStorage {
                memory: memory.clone(),
                writes: Arc::new(AtomicUsize::new(0)),
                block_write: usize::MAX,
                barrier: Arc::new(WriteBarrier::default()),
            }),
            0,
        );
        assert!(matches!(
            recovered.begin(&principal(&planes), "bounded:call", "records", 0),
            Begin::OutcomeUnknown
        ));
        let retry = tokio::spawn({
            let planes = planes.clone();
            let writer = writer.clone();
            async move {
                handle_keyed_tool_request(request(2), &writer, &planes)
                    .await
                    .unwrap();
            }
        });
        tokio::task::yield_now().await;
        let bound = budgets::CALL_RECORD_SETTLE_MS.max(budgets::CALL_RECORD_BEGIN_MS);
        tokio::time::advance(Duration::from_millis(bound - 1)).await;
        tokio::task::yield_now().await;
        assert!(
            frames.try_recv().is_err(),
            "settlement waits up to its budget"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        forward.await.unwrap();
        retry.await.unwrap();
        let a = frames.recv().await.unwrap();
        let b = frames.recv().await.unwrap();
        let (terminal, refusal) = if a.header.corr == 1 { (a, b) } else { (b, a) };
        assert_eq!(terminal.body, out.body);
        assert_eq!(body(&refusal)["code"], "call_record_unavailable");
        observation.dispatch.mark_committed();
        release.0.release();
        idle(&planes).await;
        assert_eq!(snapshot(&planes).state, CallState::Unknown);
        let Begin::Replay(reply) =
            planes
                .calls
                .begin(&principal(&planes), "bounded:call", "records", 0)
        else {
            panic!("late settle must be replayable")
        };
        assert_eq!(reply.readdressed(PROTOCOL_VERSION, 1, 1, 3).body, out.body);
        assert!(
            frames.try_recv().is_err(),
            "late settlement sends no second frame"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn settlement_deferral_forwards_frame_then_replays_after_permit_frees() {
        let (planes, _, writes, _) = fixture(usize::MAX);
        let mut pending = pending(&planes);
        let held = planes
            .call_record_workers
            .permits
            .clone()
            .acquire_many_owned(budgets::MAX_CALL_RECORD_WORKERS as u32)
            .await
            .unwrap();
        let (writer, mut frames) = mpsc::channel(8);
        let out = chosen_reply();
        let forward = tokio::spawn({
            let planes = planes.clone();
            let out = out.clone();
            async move {
                forward_recording_reply(out, &mut pending, &writer, &planes)
                    .await
                    .unwrap();
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_SETTLE_MS)).await;
        forward.await.unwrap();
        assert_eq!(frames.recv().await.unwrap().body, out.body);
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(snapshot(&planes).state, CallState::Started);
        assert_eq!(
            planes.call_record_workers.detached.load(Ordering::SeqCst),
            1
        );
        let (writer, mut admission_frames) = mpsc::channel(8);
        let started = tokio::time::Instant::now();
        handle_keyed_tool_request(request(2), &writer, &planes)
            .await
            .unwrap();
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS)
        );
        let refusal = admission_frames.recv().await.unwrap();
        assert_eq!(body(&refusal)["code"], "call_record_unavailable");
        assert!(body(&refusal)["message"]
            .as_str()
            .unwrap()
            .contains("call-record admission timed out while all record workers were busy"));
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        drop(held);
        idle(&planes).await;
        let Begin::Replay(reply) =
            planes
                .calls
                .begin(&principal(&planes), "bounded:call", "records", 0)
        else {
            panic!("deferred settle must run")
        };
        assert_eq!(reply.readdressed(PROTOCOL_VERSION, 1, 1, 2).body, out.body);
        assert!(frames.try_recv().is_err());
    }

    fn asked_reply() -> Frame {
        let mut frame = chosen_reply();
        frame.body = serde_json::to_vec(&json!({
            "outcome": "consent_pending", "ask_id": "bounded:card"
        }))
        .unwrap();
        frame
    }

    fn withdraw_request() -> Frame {
        let mut frame = request(2);
        frame.body = serde_json::to_vec(&json!({
            "name": "tool.withdraw", "arguments": {"call_key": "bounded:call"}
        }))
        .unwrap();
        frame
    }

    async fn deferred_asked_reply(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
    ) -> tokio::sync::OwnedSemaphorePermit {
        let mut pending = pending(planes);
        pending
            .observation
            .gate_dispatched
            .store(false, Ordering::SeqCst);
        let held = planes
            .call_record_workers
            .permits
            .clone()
            .acquire_many_owned(budgets::MAX_CALL_RECORD_WORKERS as u32)
            .await
            .unwrap();
        // Exhaust the settlement budget while its write is still queued, before
        // it can take the record mutex. The consent reply must still be sent.
        forward_recording_reply(asked_reply(), &mut pending, writer, planes)
            .await
            .unwrap();
        assert_eq!(snapshot(planes).state, CallState::Started);
        held
    }

    #[tokio::test(start_paused = true)]
    async fn withdrawing_a_forwarded_consent_reply_waits_for_its_record_write() {
        let (planes, _, _, release) = fixture(2);
        let (writer, mut frames) = mpsc::channel(8);
        let held = deferred_asked_reply(&planes, &writer).await;
        assert_eq!(body(&frames.recv().await.unwrap()), body(&asked_reply()));
        let withdraw = handle_keyed_tool_request(withdraw_request(), &writer, &planes);
        tokio::pin!(withdraw);
        assert!(
            poll_once(withdraw.as_mut()).is_pending(),
            "withdraw must not answer already_started while the consent record is queued"
        );
        drop(held);
        without_time_advancing(release.0.entered.notified()).await;
        assert!(
            poll_once(withdraw.as_mut()).is_pending(),
            "withdraw must also wait for the blocked storage write"
        );
        release.0.release();
        without_time_advancing(withdraw).await.unwrap();
        assert_eq!(
            body(&frames.recv().await.unwrap()),
            json!({"answer": "withdrawn"})
        );
        assert_eq!(snapshot(&planes).state, CallState::Asked);
        assert!(planes
            .call_record_workers
            .settlements
            .lock()
            .unwrap()
            .is_empty());
        idle(&planes).await;
    }

    #[tokio::test(start_paused = true)]
    async fn withdrawing_a_deferred_consent_record_is_bounded_by_one_admission_deadline() {
        let (planes, memory, _, release) = fixture(2);
        let (writer, mut frames) = mpsc::channel(8);
        let held = deferred_asked_reply(&planes, &writer).await;
        assert_eq!(body(&frames.recv().await.unwrap()), body(&asked_reply()));
        drop(held);
        without_time_advancing(release.0.entered.notified()).await;
        let started = tokio::time::Instant::now();
        let withdraw = handle_keyed_tool_request(withdraw_request(), &writer, &planes);
        tokio::pin!(withdraw);
        assert!(poll_once(withdraw.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS - 1)).await;
        assert!(poll_once(withdraw.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(1)).await;
        without_time_advancing(withdraw).await.unwrap();
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_millis(budgets::CALL_RECORD_BEGIN_MS)
        );
        assert_eq!(
            body(&frames.recv().await.unwrap()),
            json!({
                "answer": "already_started", "outcome": "unknown"
            })
        );
        // The storage write still holds the live record mutex. Only Started is
        // durable, so timeout cannot use the worker's unpersisted Asked state.
        let recovered = CallRecords::open(
            Box::new(BlockingStorage {
                memory,
                writes: Arc::new(AtomicUsize::new(0)),
                block_write: usize::MAX,
                barrier: Arc::new(WriteBarrier::default()),
            }),
            0,
        );
        assert!(
            matches!(recovered.lookup_exact(&principal(&planes), "bounded:call"),
            Lookup::Own(record) if record.state == CallState::Unknown)
        );
        release.0.release();
        without_time_advancing(idle(&planes)).await;
        without_time_advancing(handle_keyed_tool_request(
            withdraw_request(),
            &writer,
            &planes,
        ))
        .await
        .unwrap();
        assert_eq!(
            body(&frames.recv().await.unwrap()),
            json!({"answer": "withdrawn"})
        );
    }

    #[tokio::test]
    async fn settlement_within_budget_is_written_before_frame_is_forwarded() {
        let (planes, _, _, _) = fixture(usize::MAX);
        let mut pending = pending(&planes);
        let (writer, mut frames) = mpsc::channel(8);
        let out = chosen_reply();
        forward_recording_reply(out.clone(), &mut pending, &writer, &planes)
            .await
            .unwrap();
        assert_eq!(frames.recv().await.unwrap().body, out.body);
        assert_eq!(snapshot(&planes).state, CallState::Unknown);
        assert!(matches!(
            planes
                .calls
                .begin(&principal(&planes), "bounded:call", "records", 0),
            Begin::Replay(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_before_settlement_takes_mutex_gets_in_flight() {
        let (planes, _, _, _) = fixture(usize::MAX);
        let mut pending = pending(&planes);
        let ticket = pending.ticket.take().unwrap();
        let barrier = Arc::new(WriteBarrier::default());
        let release = ReleaseOnDrop(barrier.clone());
        let settle = tokio::spawn({
            let planes = planes.clone();
            let calls = planes.calls.clone();
            async move {
                settle_call_record(&planes, move || {
                    barrier.block();
                    calls.settle(
                        ticket,
                        journal::call_records::Settlement::from_reply(
                            &chosen_reply(),
                            journal::call_records::DispatchEvidence {
                                gate_dispatched: true,
                                ..Default::default()
                            },
                        ),
                        0,
                    );
                })
                .await;
            }
        });
        release.0.entered.notified().await;
        let (writer, mut frames) = mpsc::channel(8);
        handle_keyed_tool_request(request(2), &writer, &planes)
            .await
            .unwrap();
        assert_eq!(
            body(&frames.recv().await.unwrap())["code"],
            "call_in_flight"
        );
        release.0.release();
        settle.await.unwrap();
        idle(&planes).await;
    }

    #[test]
    fn new_safe_refusals_match_outcome_not_reason() {
        for outcome in [
            "action_deadline_exceeded",
            "target_busy",
            "blocking_capacity_exhausted",
        ] {
            let frame = |value| {
                Frame::build(
                    FrameType::Response,
                    Flags::new(false, Priority::Interactive, false),
                    1,
                    1,
                    1,
                    serde_json::to_vec(&value).unwrap(),
                )
                .unwrap()
            };
            assert!(refused_before_dispatch(&frame(json!({"outcome": outcome}))));
            assert!(!refused_before_dispatch(&frame(
                json!({"outcome": "retry_unsafe", "detail": {"reason": outcome}})
            )));
            assert!(!refused_before_dispatch(&frame(json!({"reason": outcome}))));
        }
    }
}
