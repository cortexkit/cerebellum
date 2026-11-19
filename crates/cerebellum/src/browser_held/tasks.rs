//! Owned, bounded continuations; none waits inside another browser queue ticket.

use super::*;
use journal::call_records::{
    BrowserResume, CallRecords, ScopeIdentity, CACHE_MAX_BYTES, CACHE_MAX_REPLIES,
};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

type Key = (String, String);

struct Job {
    cancel: CancelHandle,
    idle_hold: Option<browser_session::IdleHold>,
    bytes: usize,
    route: (u16, u32, u64),
    head_route: Option<(u16, u32)>,
    scopes: Vec<ScopeIdentity>,
    conversation: String,
    active: bool,
}

#[derive(Default)]
struct State {
    stopped: bool,
    bytes: usize,
    jobs: HashMap<Key, Job>,
    tasks: JoinSet<()>,
    heads: HashMap<ScopeIdentity, std::sync::Weak<Semaphore>>,
}

pub(crate) struct Tasks {
    state: Mutex<State>,
    global: Arc<Semaphore>,
    per_head: usize,
}

impl Default for Tasks {
    fn default() -> Self {
        Self::new(8, 32)
    }
}

pub(crate) struct Reservation {
    registry: Arc<Tasks>,
    key: Key,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock().unwrap();
        if let Some(job) = state.jobs.remove(&self.key) {
            job.cancel.cancel();
            state.bytes -= job.bytes;
        }
    }
}

struct SettlementGuard {
    calls: Arc<CallRecords>,
    key: Key,
    fallback: Option<Frame>,
}

impl Drop for SettlementGuard {
    fn drop(&mut self) {
        if let Some(reply) = self.fallback.take() {
            let _ = self.calls.finish_browser_request(
                &self.key.0,
                &self.key.1,
                reply,
                false,
                wall_clock_ms(),
            );
        }
    }
}

impl Tasks {
    pub(crate) fn usage(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (state.jobs.len(), state.bytes)
    }
    pub(crate) fn new(per_head: usize, global: usize) -> Self {
        Self {
            state: Mutex::new(State::default()),
            global: Arc::new(Semaphore::new(global)),
            per_head,
        }
    }

    pub(crate) fn reserve(self: &Arc<Self>, key: Key, bytes: usize) -> Option<Reservation> {
        let mut state = self.state.lock().unwrap();
        while state.tasks.try_join_next().is_some() {}
        if state.stopped
            || state.jobs.contains_key(&key)
            || state.jobs.len() >= CACHE_MAX_REPLIES
            || state.bytes.saturating_add(bytes) > CACHE_MAX_BYTES
        {
            return None;
        }
        state.bytes += bytes;
        state.jobs.insert(
            key.clone(),
            Job {
                cancel: CancelHandle::pending(),
                idle_hold: None,
                bytes,
                route: (0, 0, 0),
                head_route: None,
                scopes: Vec::new(),
                conversation: String::new(),
                active: false,
            },
        );
        Some(Reservation {
            registry: Arc::clone(self),
            key,
        })
    }

    pub(crate) fn spawn(
        self: &Arc<Self>,
        reservation: Reservation,
        mut resume: BrowserResume,
        planes: Planes,
    ) {
        let key = reservation.key.clone();
        let mut state = self.state.lock().unwrap();
        if state.stopped {
            drop(state);
            let mut reply = resume.frame;
            reply.header.ty = FrameType::Response;
            reply.body =
                serde_json::to_vec(&json!({"outcome":"not_started","reason":"cancelled"})).unwrap();
            let _ =
                planes
                    .calls
                    .finish_browser_request(&key.0, &key.1, reply, false, wall_clock_ms());
            return;
        }
        let Some(job) = state.jobs.get_mut(&key) else {
            return;
        };
        job.idle_hold = resume.idle_hold.take();
        job.route = (
            resume.frame.header.channel,
            resume.frame.header.epoch,
            resume.frame.header.corr,
        );
        job.head_route = resume.head.map(|(route, _)| route);
        job.conversation = resume.facts.identity.conversation_key.clone();
        job.scopes = resume
            .facts
            .scope
            .iter()
            .chain(
                resume
                    .facts
                    .codemode_head
                    .iter()
                    .filter_map(|head| head.scope.as_ref()),
            )
            .map(ScopeIdentity::from_stamp)
            .collect();
        let head_key = job
            .scopes
            .last()
            .cloned()
            .expect("a held browser call has an admitted scope");
        let cancel = job.cancel.clone();
        if state.stopped {
            cancel.cancel();
        }
        state.heads.retain(|_, head| head.strong_count() > 0);
        let head = state
            .heads
            .get(&head_key)
            .and_then(std::sync::Weak::upgrade)
            .unwrap_or_else(|| {
                let head = Arc::new(Semaphore::new(self.per_head));
                state.heads.insert(head_key, Arc::downgrade(&head));
                head
            });
        let registry = Arc::clone(self);
        let global = Arc::clone(&self.global);
        let run = planes
            .run_calls
            .register(&resume.facts, &key.1, Some(cancel.clone()));
        let mut fallback = resume.frame.clone();
        fallback.header.ty = FrameType::Response;
        fallback.body =
            serde_json::to_vec(&json!({"outcome":"not_started","reason":"cancelled"})).unwrap();
        let settlement = SettlementGuard {
            calls: Arc::clone(&planes.calls),
            key: key.clone(),
            fallback: Some(fallback),
        };
        // Count the owned continuation while queued or executing. The normal
        // request guard also covers its fresh dispatcher once it starts.
        let health = Arc::new(planes.health.enter_request());
        state.tasks.spawn(async move {
            let mut settlement = settlement;
            let _health = health;
            let _run = run;
            let permits = async {
                Some((
                    head.acquire_owned().await.ok()?,
                    global.acquire_owned().await.ok()?,
                ))
            };
            let permits = tokio::select! {
                biased;
                _ = cancel.cancelled() => None,
                permits = permits => permits,
            };
            if let Some(permits) = permits {
                if let Some(job) = registry.state.lock().unwrap().jobs.get_mut(&key) {
                    job.active = true;
                }
                settlement.fallback.as_mut().unwrap().body =
                    serde_json::to_vec(&json!({"outcome":"outcome_unknown"})).unwrap();
                let reply = execute(&planes, &key.1, resume, &cancel).await;
                let _ = planes.calls.finish_browser_request(
                    &key.0,
                    &key.1,
                    reply.0,
                    reply.1,
                    wall_clock_ms(),
                );
                settlement.fallback = None;
                drop(permits);
            }
            drop(settlement);
            drop(reservation);
            // A full task queue leaves approved requests pending. When
            // capacity frees, run_ready schedules those requests.
            run_ready(&planes).await;
        });
    }

    fn cancel_matching(&self, matches: impl Fn(&Job) -> bool) {
        for job in self
            .state
            .lock()
            .unwrap()
            .jobs
            .values_mut()
            .filter(|job| matches(job))
        {
            job.idle_hold = None;
            job.cancel.cancel();
        }
    }
    pub(crate) fn cancel_handle(&self, cancel: &CancelHandle) {
        self.cancel_matching(|job| Arc::ptr_eq(&job.cancel.0, &cancel.0));
    }
    pub(crate) fn cancel_route(&self, channel: u16, epoch: u32) {
        self.cancel_matching(|job| {
            (job.route.0, job.route.1) == (channel, epoch)
                || job.head_route == Some((channel, epoch))
        });
    }
    pub(crate) fn cancel_correlation(&self, address: (u16, u32, u64)) {
        self.cancel_matching(|job| job.route == address);
    }
    pub(crate) fn cancel_scope(&self, scope: &ScopeIdentity) {
        self.cancel_matching(|job| job.scopes.contains(scope));
    }
    pub(crate) fn cancel_conversation(&self, conversation: &str) {
        self.cancel_matching(|job| job.conversation == conversation);
    }
    pub(crate) fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.stopped = true;
        for job in state.jobs.values_mut() {
            job.idle_hold = None;
            job.cancel.cancel();
        }
        state.tasks.abort_all();
    }
    pub(crate) async fn stop_and_join(&self, deadline: tokio::time::Instant) {
        self.stop();
        let mut tasks = std::mem::take(&mut self.state.lock().unwrap().tasks);
        let _ = tokio::time::timeout_at(deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
    }
    #[cfg(test)]
    pub(crate) fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (
            state.jobs.len(),
            state.jobs.values().filter(|job| job.active).count(),
        )
    }
    #[cfg(test)]
    pub(crate) fn active_keys(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .jobs
            .iter()
            .filter(|(_, job)| job.active)
            .map(|(key, _)| key.1.clone())
            .collect()
    }
}

struct CancelRequest {
    planes: Planes,
    address: (u16, u32, u64),
}
impl Drop for CancelRequest {
    fn drop(&mut self) {
        if let Some(cancel) = self.planes.cancellations.get(self.address) {
            cancel.cancel();
        }
    }
}

async fn execute(
    planes: &Planes,
    call_key: &str,
    resume: BrowserResume,
    cancel: &CancelHandle,
) -> (Frame, bool) {
    if !still_live(planes, &resume) {
        let mut reply = resume.frame;
        reply.header.ty = FrameType::Response;
        reply.body=serde_json::to_vec(&json!({"outcome":"not_started","detail":{"consent":"approved","ask_id":resume.ask_id},"remedy":"Approved; call again to run it."})).unwrap();
        return (reply, false);
    }
    if cancel.is_cancelled() {
        let mut reply = resume.frame;
        reply.header.ty = FrameType::Response;
        reply.body =
            serde_json::to_vec(&json!({"outcome":"not_started","reason":"cancelled"})).unwrap();
        return (reply, false);
    }
    let (writer, mut replies) = mpsc::channel(16);
    let address = (
        resume.frame.header.channel,
        resume.frame.header.epoch,
        resume.frame.header.corr,
    );
    let _cancellation = CancelRequest {
        planes: planes.clone(),
        address,
    };
    let context = ResumeContext {
        ask_id: resume.ask_id.clone(),
        call_key: call_key.into(),
        dispatch: Arc::new(Mutex::new(None)),
    };
    let _ = with_context(
        Some(context.clone()),
        Box::pin(handle_frame(resume.frame.clone(), &writer, planes)),
    )
    .await;
    drop(writer);
    let mut terminal = None;
    {
        let receive = async {
            while let Some(reply) = replies.recv().await {
                if matches!(reply.header.ty, FrameType::Response | FrameType::Error) {
                    terminal = Some(reply);
                }
            }
        };
        tokio::pin!(receive);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                if let Some(inner)=planes.cancellations.get(address) { inner.cancel(); }
                receive.await;
            }
            _ = &mut receive => {}
        }
    }
    let dispatched = context
        .dispatch
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|(witness, gate)| {
            witness.committed() || gate.load(std::sync::atomic::Ordering::Acquire)
        });
    let reply = terminal.unwrap_or_else(|| {
        let mut reply = resume.frame;
        reply.header.ty = FrameType::Response;
        reply.body = serde_json::to_vec(&json!({"outcome":"outcome_unknown"})).unwrap();
        reply
    });
    (reply, dispatched)
}
