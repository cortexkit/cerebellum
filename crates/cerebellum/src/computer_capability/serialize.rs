//! FIFO execution for one conversation's reads and actions on one application.
//!
//! A reservation is polled once when it is issued, not first polled by the
//! spawned request. Tokio's mutex queues on that first poll. The frame loop
//! only reserves a conversation position. The spawned task resolves the app,
//! reserves its app position, then releases the conversation lane before
//! waiting for the app. Platform work can never hold the frame reader.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use cerebellum_computer::app_state::session::ElementResolution;
use cerebellum_computer::app_state::source::HitScope;
use cerebellum_computer::capture::CaptureBackend;
use cerebellum_computer::platform::{PlatformDriver, SyntheticPoint};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::journal::{JournalStorage, Redactor, SeverityTaxonomy};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::{ComputerPlane, Servable, ServeContext, Served};
use crate::computer_grants::ConsentRefusal;

const RESOLUTION_LIMIT: Duration = Duration::from_secs(2);

type LockFuture = Pin<Box<dyn Future<Output = OwnedMutexGuard<()>> + Send>>;

/// A live queue position, including when the caller has not been spawned yet.
/// Dropping it releases either the acquired lock or its unfulfilled position.
struct Reservation {
    future: LockFuture,
}

impl Reservation {
    fn new(mutex: Arc<AsyncMutex<()>>) -> Self {
        let mut future: LockFuture = Box::pin(mutex.lock_owned());
        if let Poll::Ready(guard) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            future = Box::pin(std::future::ready(guard));
        }
        Self { future }
    }
}

type Key = (String, String);

struct Entry {
    mutex: Arc<AsyncMutex<()>>,
    users: usize,
}

#[derive(Default)]
struct Registry(Mutex<HashMap<Key, Entry>>);

/// Counts queued as well as executing calls. A final drop removes the entry
/// under the same map lock as insertion, so there can never be two live locks
/// for one key. Field order releases the lock before removing its map entry.
pub(super) struct LaneGuard {
    _lock: OwnedMutexGuard<()>,
    _lease: Lease,
}

struct Lease {
    registry: Arc<Registry>,
    key: Key,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut entries = self.registry.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get_mut(&self.key).expect("live queue entry");
        entry.users -= 1;
        if entry.users == 0 {
            entries.remove(&self.key);
        }
    }
}

pub(crate) struct QueuePosition {
    reservation: Reservation,
    lease: Lease,
}

impl QueuePosition {
    async fn acquire(mut self) -> LaneGuard {
        // Borrow the future while awaiting so cancellation drops the queued
        // position before its lease, just like a completed guard's fields.
        let lock = self.reservation.future.as_mut().await;
        LaneGuard {
            _lock: lock,
            _lease: self.lease,
        }
    }
}

#[derive(Default)]
pub(super) struct Serializer {
    conversations: Arc<Registry>,
    registry: Arc<Registry>,
}

impl Registry {
    fn reserve(self: &Arc<Self>, key: Key) -> QueuePosition {
        let mut entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.entry(key.clone()).or_insert_with(|| Entry {
            mutex: Arc::new(AsyncMutex::new(())),
            users: 0,
        });
        entry.users += 1;
        QueuePosition {
            reservation: Reservation::new(entry.mutex.clone()),
            lease: Lease {
                registry: self.clone(),
                key,
            },
        }
    }
}

tokio::task_local! {
    static ARRIVAL: RefCell<Option<QueuePosition>>;
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) async fn scope<T>(arrival: Option<QueuePosition>, future: impl Future<Output = T>) -> T {
    ARRIVAL.scope(RefCell::new(arrival), future).await
}

/// Reserve a conversation's FIFO position without resolving a target or
/// querying the platform. Refused calls still use the normal reply handler.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn arrive(
    frame: &subc_protocol::Frame,
    planes: &crate::Planes,
) -> Option<QueuePosition> {
    let body: Value = serde_json::from_slice(&frame.body).ok()?;
    let name = body.get("name")?.as_str()?;
    let arguments = body.get("arguments")?;
    let translated;
    let (capability, arguments) = if name == crate::flat_tools::COMPUTER_USE {
        translated = crate::flat_tools::translate_computer(arguments).ok()?;
        match &translated {
            crate::flat_tools::FlatDispatch::Computer {
                capability,
                arguments,
            } => (super::servable(capability)?, arguments),
            _ => return None,
        }
    } else {
        (super::servable(name)?, arguments)
    };
    if matches!(capability.0, Served::ListApps)
        || valid_request(capability, arguments).is_err()
        || !planes
            .computer_admitted
            .contains(capability.capability().capability_id())
    {
        return None;
    }
    let facts = planes
        .routes
        .get(frame.header.channel, frame.header.epoch)?;
    let declared = crate::dispatchable_tool(name)?;
    if !facts.admits_session_calls()
        || crate::session_flow_refusal(&facts).is_some()
        || !facts.allows_capability(declared)
        || (facts.flow_id.is_some()
            && (!facts.acts_as_agent
                || matches!(
                    capability.0,
                    Served::TakeoverMove | Served::TakeoverDrag | Served::TakeoverScroll
                )))
    {
        return None;
    }
    let plane = planes.computer.as_ref().ok()?;
    if super::permissions::refusal(capability.capability(), &plane.permissions).is_some() {
        return None;
    }
    Some(
        plane
            .serializer
            .conversations
            .reserve((facts.identity.conversation_key, String::new())),
    )
}

impl<B, R, T, S, D> ComputerPlane<B, R, T, S, D>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    pub(super) async fn serialize<C: MonotonicClock>(
        &self,
        capability: Servable,
        arguments: &Value,
        context: &ServeContext<'_, C>,
    ) -> Result<Option<LaneGuard>, ConsentRefusal> {
        if matches!(capability.0, Served::ListApps) || valid_request(capability, arguments).is_err()
        {
            return Ok(None);
        }
        let ticket = ARRIVAL
            .try_with(|arrival| arrival.borrow_mut().take())
            .ok()
            .flatten();
        let enter = async {
            let ticket = ticket.unwrap_or_else(|| {
                self.serializer
                    .conversations
                    .reserve((context.identity.conversation_key.clone(), String::new()))
            });
            let conversation = ticket.acquire().await;
            // Ordering is best-effort when resolution exceeds two seconds:
            // run this call unserialized rather than letting a wedged platform
            // query stall every other app in the conversation. Dropping the
            // await cannot stop a running blocking query, but that query owns
            // neither lane and cannot reserve an app lock after the timeout.
            let app = tokio::time::timeout(
                RESOLUTION_LIMIT,
                self.reserve_app(
                    capability,
                    arguments,
                    &context.identity.conversation_key,
                    context.management,
                ),
            )
            .await
            .ok()
            .flatten();
            drop(conversation);
            let ticket = app?;
            Some(ticket.acquire().await)
        };
        let mut drain = context.consent.drain.clone();
        tokio::select! {
            biased;
            _ = context.cancel.cancelled() => Err(ConsentRefusal::Cancelled),
            _ = async {
                if drain.wait_for(|draining| *draining).await.is_err() {
                    std::future::pending::<()>().await;
                }
            } => Err(ConsentRefusal::Draining),
            guard = enter => Ok(guard),
        }
    }

    async fn reserve_app(
        &self,
        capability: Servable,
        arguments: &Value,
        conversation: &str,
        management: &Arc<crate::management::ManagementPlane>,
    ) -> Option<QueuePosition> {
        let app = self
            .serialization_app(capability, arguments, conversation, management)
            .await?;
        Some(
            self.serializer
                .registry
                .reserve((conversation.to_string(), app.to_lowercase())),
        )
    }

    async fn serialization_app(
        &self,
        capability: Servable,
        arguments: &Value,
        conversation: &str,
        management: &Arc<crate::management::ManagementPlane>,
    ) -> Option<String> {
        let sessions = management.app_state_sessions();
        match capability.0 {
            Served::ListApps => None,
            Served::PressElement | Served::WriteText => {
                match sessions.resolve(conversation, arguments.get("element_id")?.as_str()?) {
                    ElementResolution::Live {
                        bundle_identity, ..
                    } => Some(bundle_identity),
                    _ => None,
                }
            }
            Served::PressPoint => sessions
                .resolve_image(conversation, arguments.get("image_id")?.as_str()?)
                .map(|image| image.bundle_identity),
            Served::TakeoverMove | Served::TakeoverDrag => {
                let request =
                    super::takeover::parse_request(capability.capability(), arguments).ok()?;
                let (image_id, points) = match request {
                    super::takeover::TakeoverRequest::Move { image_id, to } => (image_id, vec![to]),
                    super::takeover::TakeoverRequest::Drag { image_id, from, to } => {
                        (image_id, vec![from, to])
                    }
                    _ => return None,
                };
                let image = sessions.resolve_image(conversation, &image_id)?;
                // Reject every out-of-bounds point and an obsolete process
                // before hit-testing, just as the dispatch's placement does.
                if points.iter().any(|(x, y)| {
                    *x >= u64::from(image.width_px) || *y >= u64::from(image.height_px)
                }) {
                    return None;
                }
                let (x, y) = points[0];
                let (x, y) = image.mapping.pixel_to_desktop(x as f64, y as f64);
                let point = SyntheticPoint { x, y };
                let source = self.app_state_source.clone();
                let management = management.clone();
                tokio::task::spawn_blocking(move || {
                    let current = management.resolve_process(&image.bundle_identity).ok()?;
                    if current.pid != image.pid
                        || current.process_generation_evidence != image.process_generation
                    {
                        return None;
                    }
                    let at = (point.x, point.y);
                    if let Ok(Some((_, owner))) =
                        source.element_at(HitScope::Application { pid: image.pid }, at)
                    {
                        if owner.is_none_or(|pid| pid == image.pid) {
                            return Some(image.bundle_identity);
                        }
                    }
                    let (_, owner) = source.element_at(HitScope::SystemWide, at).ok()??;
                    let owner = owner?;
                    if owner == image.pid {
                        Some(image.bundle_identity)
                    } else {
                        management
                            .process_for_pid(owner)
                            .map(|grant| grant.bundle_identity)
                    }
                })
                .await
                .ok()
                .flatten()
            }
            Served::Wait => self
                .resolve_target_name(arguments.get("app")?.as_str()?)
                .await
                .ok(),
            Served::ReadState | Served::Type | Served::Keys | Served::TakeoverScroll => self
                .resolve_target_name(arguments.get("target")?.as_str()?)
                .await
                .ok(),
        }
    }
}

pub(super) fn queued_refusal(
    capability: Servable,
    arguments: &Value,
    refusal: ConsentRefusal,
) -> Value {
    let reply = if refusal == ConsentRefusal::Cancelled {
        match capability.0 {
            Served::Wait => super::cancelled_before_polling_reply(
                super::parse_wait_request(arguments)
                    .expect("validated wait request")
                    .predicate,
            ),
            Served::Type
            | Served::Keys
            | Served::TakeoverMove
            | Served::TakeoverDrag
            | Served::TakeoverScroll => super::synthetic_dispatch_refusal(
                &cerebellum_computer::dispatch::DispatchError::Cancelled {
                    posts_returned: 0,
                    held_state: cerebellum_computer::platform::HeldStateDisposition::NoneHeld,
                },
            ),
            _ => {
                serde_json::json!({"outcome": "cancelled", "remedy": "the call was cancelled before it ran; nothing was done"})
            }
        }
    } else {
        refusal.reply(None)
    };
    if matches!(capability.0, Served::Type | Served::Keys) {
        super::synthetic_wire_envelope(super::keystrokes::refused_before_posting(reply))
    } else {
        reply
    }
}

fn valid_request(capability: Servable, arguments: &Value) -> Result<(), Value> {
    match capability.0 {
        Served::ReadState => super::parse_read_state_request(arguments).map(|_| ()),
        Served::ListApps => super::parse_list_apps_request(arguments),
        Served::Wait => super::parse_wait_request(arguments).map(|_| ()),
        Served::PressElement => super::element_actions::parse_press_element(arguments).map(|_| ()),
        Served::PressPoint => super::element_actions::parse_press_point(arguments).map(|_| ()),
        Served::WriteText => super::element_actions::parse_write_text(arguments).map(|_| ()),
        Served::TakeoverMove | Served::TakeoverDrag | Served::TakeoverScroll => {
            super::takeover::parse_request(capability.capability(), arguments).map(|_| ())
        }
        _ => super::parse_synthetic_request(capability.capability(), arguments).map(|_| ()),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::*;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, AppStateSource, ElementActionError, ElementHandle, RawAppState,
        ReadBounds, RunningApp,
    };
    use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Condvar;
    use std::time::Duration;
    use subc_protocol::{Frame, FrameType};
    use tokio::io::DuplexStream;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    const APP: &str = "com.example.Editor";
    const OTHER: &str = "com.example.Viewer";

    struct Running;
    impl management::TargetResolver for Running {
        fn resolve(&self, bundle_identity: &str) -> TargetResolution {
            TargetResolution::Resolved(ProcessGrant {
                pid: if bundle_identity == APP { 42 } else { 43 },
                bundle_identity: bundle_identity.to_string(),
                process_generation_evidence: "fixture-generation".into(),
            })
        }
        fn app_code(&self, _: &ProcessGrant) -> Arc<dyn computer_grants::AppCode> {
            Arc::new(computer_grants::SignedByFixtureTeam)
        }
    }

    #[derive(Debug, PartialEq)]
    enum Event {
        Start(usize),
        End(usize),
    }

    /// Each read reports its invocation number through a different real reply:
    /// the first reads an unreadable subtree, the second sees a vanished app.
    /// This makes wire correlation, not just task start order, observable.
    struct Desk {
        reads: AtomicUsize,
        events: mpsc::UnboundedSender<Event>,
        released: (Mutex<bool>, Condvar),
        hits: AtomicUsize,
        hits_returned: AtomicUsize,
        hit_started: mpsc::UnboundedSender<usize>,
        hit_released: (Mutex<bool>, Condvar),
    }
    impl Desk {
        fn release_hit(&self) {
            *self.hit_released.0.lock().unwrap() = true;
            self.hit_released.1.notify_all();
        }

        fn release(&self) {
            *self.released.0.lock().unwrap() = true;
            self.released.1.notify_all();
        }
    }
    struct ReleaseHit(Arc<Desk>);
    impl Drop for ReleaseHit {
        fn drop(&mut self) {
            self.0.release_hit();
        }
    }

    impl AppStateSource for Desk {
        fn element_at(
            &self,
            _: HitScope,
            _: (f64, f64),
        ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
            let number = self.hits.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = self.hit_started.send(number);
            if number == 1 {
                let (released, timeout) = self
                    .hit_released
                    .1
                    .wait_timeout_while(
                        self.hit_released.0.lock().unwrap(),
                        Duration::from_secs(10),
                        |released| !*released,
                    )
                    .unwrap();
                drop(released);
                assert!(!timeout.timed_out(), "scripted hit test was never released");
            }
            self.hits_returned.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
        fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
            Ok(vec![RunningApp {
                name: "Editor".into(),
                bundle_identity: APP.into(),
                pid: 42,
                frontmost: true,
            }])
        }
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            let number = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            self.events.send(Event::Start(number)).unwrap();
            let (released, timeout) = self
                .released
                .1
                .wait_timeout_while(
                    self.released.0.lock().unwrap(),
                    Duration::from_secs(5),
                    |released| !*released,
                )
                .unwrap();
            assert!(!timeout.timed_out(), "scripted desk was never released");
            drop(released);
            self.events.send(Event::End(number)).unwrap();
            Err(if number == 1 {
                AppStateReadError::Unreadable
            } else {
                AppStateReadError::TargetGone
            })
        }
    }

    struct Rig {
        planes: Planes,
        desk: Arc<Desk>,
        events: mpsc::UnboundedReceiver<Event>,
        hit_events: mpsc::UnboundedReceiver<usize>,
        wire: DuplexStream,
        replies: mpsc::Receiver<Frame>,
        dispatch: JoinHandle<Result<(), ModuleError>>,
    }
    fn frame(ty: FrameType, channel: u16, corr: u64, body: Value) -> Frame {
        Frame::build(
            ty,
            wire::control_flags(),
            channel,
            if channel == 0 { 0 } else { 1 },
            corr,
            if matches!(ty, FrameType::Cancel | FrameType::Goodbye) {
                Vec::new()
            } else {
                serde_json::to_vec(&body).unwrap()
            },
        )
        .unwrap()
    }
    fn request(channel: u16, corr: u64, app: &str) -> Frame {
        frame(
            FrameType::Request,
            channel,
            corr,
            serde_json::json!({
                "name": "computer_use", "arguments": {"action": "read_state", "target": app},
            }),
        )
    }
    fn bind(planes: &Planes, channel: u16, session: &str) {
        planes.routes.insert(channel, 1, AcceptedBindFacts::from_bind(
            &subc_protocol::BindIdentity::new("/serialization", "fixture", session.to_string()),
            session_caller_principal_for_test(),
            Some(&serde_json::json!({"agentProjectId": "fixture-project", "sessionKind": "primary", "effectiveCapabilityScope": ["*"]})),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() },
        ));
    }
    struct SlowDispatch {
        armed: Arc<AtomicBool>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    fn rig(second_conversation: bool, slowed: Option<SlowDispatch>) -> Rig {
        let (events_tx, events) = mpsc::unbounded_channel();
        let (hit_started, hit_events) = mpsc::unbounded_channel();
        let desk = Arc::new(Desk {
            reads: AtomicUsize::new(0),
            events: events_tx,
            released: (Mutex::new(false), Condvar::new()),
            hits: AtomicUsize::new(0),
            hits_returned: AtomicUsize::new(0),
            hit_started,
            hit_released: (Mutex::new(true), Condvar::new()),
        });
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.management = Arc::new(management::ManagementPlane::new(Arc::new(Running)));
        planes.computer = Ok(Arc::new(
            ComputerPlane::with_synthetic_driver(
                super::super::computer_audit(JournalPersistence::Isolated).unwrap(),
                || {
                    super::super::NativeComputerPlatformDriver::default()
                        .without_expected_post_condition()
                },
            )
            .with_permission_liveness(super::super::live_for_test())
            .with_session_lock_for_test(Some(false))
            .with_app_state_source(desk.clone()),
        ));
        planes.computer_admitted = Arc::new(
            [
                "computer.read_state",
                "computer.takeover_move",
                "computer.takeover_scroll",
                "computer.keys",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        );
        bind(&planes, 7, "one");
        bind(&planes, 8, if second_conversation { "two" } else { "one" });
        if let Some(SlowDispatch {
            armed,
            entered,
            release,
        }) = slowed
        {
            planes.route_test_handler = Some(Arc::new(move || {
                let first = armed.swap(false, Ordering::SeqCst);
                let entered = entered.clone();
                let release = release.clone();
                Box::pin(async move {
                    if first {
                        entered.notify_one();
                        release.notified().await;
                    }
                })
            }));
        }
        let (wire, mut input) = tokio::io::duplex(8192);
        let (tx, replies) = mpsc::channel(32);
        let served = planes.clone();
        let dispatch = tokio::spawn(async move {
            let health = served.health.clone();
            let clock = health.clock().clone();
            let mut idle = PeriodicIdleWake {
                period: Duration::from_secs(1),
            };
            run_dispatch_loop(&mut input, &health, &clock, &mut idle, move |frame| {
                let planes = served.clone();
                let tx = tx.clone();
                async move { handle_frame(frame, &tx, &planes).await }
            })
            .await
        });
        Rig {
            planes,
            desk,
            events,
            hit_events,
            wire,
            replies,
            dispatch,
        }
    }
    impl Rig {
        fn block_hit(&self) -> ReleaseHit {
            *self.desk.hit_released.0.lock().unwrap() = false;
            ReleaseHit(self.desk.clone())
        }

        fn move_request(&self, channel: u16, corr: u64) -> Frame {
            use cerebellum_computer::app_state::{image::ImageMapping, session::RegisteredImage};
            let conversation = self
                .planes
                .routes
                .get(channel, 1)
                .unwrap()
                .identity
                .conversation_key;
            let image = self.planes.management.app_state_sessions().register_image(
                &conversation,
                RegisteredImage {
                    bundle_identity: APP.to_string(),
                    pid: 42,
                    process_generation: "fixture-generation".into(),
                    width_px: 100,
                    height_px: 100,
                    mapping: ImageMapping::for_window(
                        (0.0, 0.0),
                        (100.0, 100.0),
                        (100, 100),
                        (100, 100),
                    )
                    .unwrap(),
                },
            );
            frame(
                FrameType::Request,
                channel,
                corr,
                serde_json::json!({
                    "name": "computer_use", "arguments": {"action": "takeover_move", "image_id": image, "to": {"x": 10, "y": 20}},
                }),
            )
        }

        async fn hit_started(&mut self) {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), self.hit_events.recv())
                    .await
                    .expect("resolution reached the scripted hit test"),
                Some(1)
            );
        }

        async fn fast_reply(&mut self) -> Frame {
            tokio::time::timeout(Duration::from_secs(1), self.replies.recv())
                .await
                .expect("frame reader and cancellation remain responsive during resolution")
                .unwrap()
        }

        async fn send(&mut self, frame: Frame) {
            subc_transport::write_frame(&mut self.wire, &frame)
                .await
                .unwrap();
        }
        async fn reply(&mut self) -> Frame {
            tokio::time::timeout(Duration::from_secs(2), self.replies.recv())
                .await
                .expect("wire reply arrived promptly")
                .unwrap()
        }
        async fn event(&mut self) -> Event {
            tokio::time::timeout(Duration::from_secs(2), self.events.recv())
                .await
                .expect("desk event arrived promptly")
                .unwrap()
        }
        async fn allow(&mut self, question: &Frame) {
            self.send(frame(
                FrameType::Response,
                question.header.channel,
                question.header.corr,
                serde_json::json!({"decision": "allow_conversation"}),
            ))
            .await;
        }
        async fn grant(&mut self, channel: u16, app: &str) {
            // Prime only the grant: invalid zoom prevents any desk read.
            let prime = request(channel, 100 + u64::from(channel), app);
            let mut body: Value = serde_json::from_slice(&prime.body).unwrap();
            body["arguments"]["zoom"] = serde_json::json!("zz999999");
            let prime = frame(FrameType::Request, channel, 100 + u64::from(channel), body);
            self.send(prime).await;
            let question = self.reply().await;
            assert_eq!(question.header.ty, FrameType::Request);
            self.allow(&question).await;
            let response = self.reply().await;
            assert_eq!(response.header.ty, FrameType::Response);
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap()["outcome"],
                "stale_element"
            );
            self.idle().await;
        }
        async fn idle(&self) {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let serializer = &self.planes.computer.as_ref().unwrap().serializer;
                    if serializer.registry.0.lock().unwrap().is_empty()
                        && serializer.conversations.0.lock().unwrap().is_empty()
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("idle app lock map is empty");
        }
        async fn finish(mut self) {
            self.idle().await;
            self.send(frame(FrameType::Goodbye, 0, 0, serde_json::json!({})))
                .await;
            tokio::time::timeout(Duration::from_secs(2), self.dispatch)
                .await
                .expect("shutdown does not deadlock")
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn same_app_calls_do_not_overlap() {
        let mut rig = rig(false, None);
        rig.grant(7, APP).await;
        rig.send(request(7, 1, "Editor")).await;
        rig.send(request(7, 2, APP)).await;
        assert_eq!(rig.event().await, Event::Start(1));
        let early = tokio::time::timeout(Duration::from_millis(100), rig.events.recv()).await;
        rig.desk.release();
        assert!(
            early.is_err(),
            "the second read overlapped the first: {early:?}"
        );
        assert_eq!(rig.event().await, Event::End(1));
        assert_eq!(rig.event().await, Event::Start(2));
        assert_eq!(rig.event().await, Event::End(2));
        for _ in 0..2 {
            assert_eq!(rig.reply().await.header.ty, FrameType::Response);
        }
        rig.finish().await;
    }

    #[tokio::test]
    async fn wire_order_survives_delayed_first_dispatch() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let armed = Arc::new(AtomicBool::new(false));
        let mut rig = rig(
            false,
            Some(SlowDispatch {
                armed: armed.clone(),
                entered: entered.clone(),
                release: release.clone(),
            }),
        );
        rig.grant(7, APP).await;
        armed.store(true, Ordering::SeqCst);
        rig.desk.release();
        rig.send(request(7, 1, APP)).await;
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        rig.send(request(7, 2, APP)).await;
        // The second frame is ready to run while the first is still before serve.
        let early = tokio::time::timeout(Duration::from_millis(100), rig.events.recv()).await;
        release.notify_one();
        assert!(
            early.is_err(),
            "a later wire frame executed before the delayed first frame: {early:?}"
        );
        let first = rig.reply().await;
        assert_eq!(first.header.corr, 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&first.body).unwrap()["outcome"],
            "completed"
        );
        let second = rig.reply().await;
        assert_eq!(second.header.corr, 2);
        assert_eq!(
            serde_json::from_slice::<Value>(&second.body).unwrap()["outcome"],
            "not_running"
        );
        assert_eq!(rig.event().await, Event::Start(1));
        assert_eq!(rig.event().await, Event::End(1));
        assert_eq!(rig.event().await, Event::Start(2));
        assert_eq!(rig.event().await, Event::End(2));
        rig.finish().await;
    }

    async fn overlap(second_conversation: bool) {
        let mut rig = rig(second_conversation, None);
        let app = if second_conversation { APP } else { OTHER };
        rig.grant(7, APP).await;
        rig.grant(8, app).await;
        rig.send(request(7, 1, APP)).await;
        assert_eq!(rig.event().await, Event::Start(1));
        rig.send(request(8, 2, app)).await;
        let second = tokio::time::timeout(Duration::from_secs(1), rig.events.recv()).await;
        rig.desk.release();
        assert_eq!(
            second.expect("independent app/conversation must overlap"),
            Some(Event::Start(2))
        );
        for _ in 0..2 {
            assert!(matches!(rig.event().await, Event::End(_)));
        }
        for _ in 0..2 {
            assert_eq!(rig.reply().await.header.ty, FrameType::Response);
        }
        rig.finish().await;
    }
    #[tokio::test]
    async fn different_apps_overlap() {
        overlap(false).await;
    }
    #[tokio::test]
    async fn different_conversations_on_one_app_overlap() {
        overlap(true).await;
    }

    async fn parked(ending: FrameType) {
        let mut rig = rig(false, None);
        rig.desk.release();
        rig.send(request(7, 1, APP)).await;
        let question = rig.reply().await;
        assert_eq!(question.header.ty, FrameType::Request);
        rig.send(request(8, 2, APP)).await;
        // One lock owner and one waiter, and no app read before consent.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let ready = rig
                    .planes
                    .computer
                    .as_ref()
                    .unwrap()
                    .serializer
                    .registry
                    .0
                    .lock()
                    .unwrap()
                    .values()
                    .any(|entry| entry.users == 2);
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second call queued behind parked first call");
        assert_eq!(rig.desk.reads.load(Ordering::SeqCst), 0);
        if ending == FrameType::Push {
            rig.send(frame(ending, 0, 0, serde_json::json!({"op": "module.draining", "reason": "restart", "deadline_ms": 123}))).await;
            let mut responses = 0;
            while responses < 2 {
                let response = rig.reply().await;
                if response.header.ty == FrameType::Response {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&response.body).unwrap()["outcome"],
                        "module_draining"
                    );
                    responses += 1;
                }
            }
        } else {
            rig.send(frame(ending, 7, 1, serde_json::json!({}))).await;
            if ending == FrameType::Cancel {
                let response = rig.reply().await;
                assert_eq!(response.header.corr, 1);
                assert_eq!(
                    serde_json::from_slice::<Value>(&response.body).unwrap()["outcome"],
                    "cancelled"
                );
                rig.allow(&question).await;
            } else {
                // Closing the original route withdraws its carrier; the next
                // live route must put its own question rather than wait on it.
                let next_question = rig.reply().await;
                assert_eq!(next_question.header.ty, FrameType::Request);
                rig.allow(&next_question).await;
            }
            let response = rig.reply().await;
            assert_eq!(
                (response.header.ty, response.header.corr),
                (FrameType::Response, 2)
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap()["outcome"],
                "completed"
            );
            assert_eq!(rig.event().await, Event::Start(1));
            assert_eq!(rig.event().await, Event::End(1));
        }
        rig.finish().await;
    }
    #[tokio::test]
    async fn cancel_parked_first_releases_second() {
        parked(FrameType::Cancel).await;
    }
    #[tokio::test]
    async fn goodbye_parked_first_releases_second() {
        parked(FrameType::Goodbye).await;
    }
    #[tokio::test]
    async fn drain_releases_owner_and_waiter() {
        parked(FrameType::Push).await;
    }

    #[tokio::test]
    async fn blocked_hit_test_does_not_block_other_routes_or_cancel_frames() {
        let mut rig = rig(true, None);
        rig.grant(8, OTHER).await;
        rig.desk.release();
        let release = rig.block_hit();
        rig.send(rig.move_request(7, 1)).await;
        rig.hit_started().await;
        rig.send(request(8, 2, OTHER)).await;
        let independent = rig.fast_reply().await;
        assert_eq!(
            (independent.header.ty, independent.header.corr),
            (FrameType::Response, 2)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&independent.body).unwrap()["outcome"],
            "completed"
        );
        assert_eq!(
            rig.desk.hits_returned.load(Ordering::SeqCst),
            0,
            "the hit-test latch is still held"
        );
        rig.send(frame(FrameType::Cancel, 7, 1, serde_json::json!({})))
            .await;
        let cancelled = rig.fast_reply().await;
        assert_eq!(
            (cancelled.header.ty, cancelled.header.corr),
            (FrameType::Response, 1)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&cancelled.body).unwrap()["outcome"],
            "cancelled"
        );
        assert_eq!(
            rig.desk.hits_returned.load(Ordering::SeqCst),
            0,
            "Cancel did not wait for the platform query"
        );
        rig.idle().await;
        drop(release);
        rig.finish().await;
    }

    #[tokio::test]
    async fn resolution_timeout_runs_unserialized_and_releases_conversation() {
        let mut rig = rig(false, None);
        rig.grant(8, OTHER).await;
        rig.desk.release();
        let release = rig.block_hit();
        rig.send(rig.move_request(7, 1)).await;
        rig.hit_started().await;
        rig.send(request(8, 2, OTHER)).await;
        let responses = tokio::time::timeout(Duration::from_secs(4), async {
            let mut responses = std::collections::BTreeMap::new();
            for _ in 0..2 {
                let frame = rig.replies.recv().await.unwrap();
                assert_eq!(frame.header.ty, FrameType::Response);
                responses.insert(
                    frame.header.corr,
                    serde_json::from_slice::<Value>(&frame.body).unwrap(),
                );
            }
            responses
        })
        .await
        .expect("resolution timeout must run the call and release the conversation lane");
        assert_eq!(
            responses[&1]["outcome"], "target_not_frontmost",
            "the move's ordinary handler ran without ordering"
        );
        assert_eq!(
            responses[&2]["outcome"], "completed",
            "the conversation's other app was released"
        );
        assert_eq!(
            rig.desk.hits.load(Ordering::SeqCst),
            3,
            "one unresolved ordering hit and two ordinary placement hits"
        );
        assert_eq!(
            rig.desk.hits_returned.load(Ordering::SeqCst),
            2,
            "the original ordering query is still blocked"
        );
        rig.idle().await;
        drop(release);
        rig.finish().await;
    }

    #[tokio::test]
    async fn drain_interrupts_resolution_and_conversation_wait() {
        let mut rig = rig(false, None);
        rig.grant(8, OTHER).await;
        rig.desk.release();
        let release = rig.block_hit();
        rig.send(rig.move_request(7, 1)).await;
        rig.hit_started().await;
        rig.send(request(8, 2, OTHER)).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let queued = rig
                    .planes
                    .computer
                    .as_ref()
                    .unwrap()
                    .serializer
                    .conversations
                    .0
                    .lock()
                    .unwrap()
                    .values()
                    .any(|entry| entry.users == 2);
                if queued {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second call occupies a conversation queue position");
        rig.send(frame(
            FrameType::Push,
            0,
            0,
            serde_json::json!({"op":"module.draining", "reason":"restart", "deadline_ms":123}),
        ))
        .await;
        let mut correlations = Vec::new();
        for _ in 0..2 {
            let response = rig.fast_reply().await;
            assert_eq!(response.header.ty, FrameType::Response);
            correlations.push(response.header.corr);
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap()["outcome"],
                "module_draining"
            );
        }
        correlations.sort();
        assert_eq!(correlations, [1, 2]);
        assert_eq!(rig.desk.hits_returned.load(Ordering::SeqCst), 0);
        assert_eq!(rig.desk.reads.load(Ordering::SeqCst), 0);
        rig.idle().await;
        drop(release);
        rig.finish().await;
    }

    #[tokio::test]
    async fn scroll_waits_for_keys_on_its_resolved_target() {
        let mut rig = rig(false, None);
        rig.send(frame(FrameType::Request, 7, 1, serde_json::json!({
            "name":"computer_use", "arguments":{"action":"keys", "target":"Editor", "keys":["d"]},
        }))).await;
        let keys_question = rig.reply().await;
        assert_eq!(keys_question.header.ty, FrameType::Request);
        assert_eq!(
            serde_json::from_slice::<Value>(&keys_question.body).unwrap()["params"]["target"]
                ["kind"],
            "app"
        );
        rig.send(frame(FrameType::Request, 7, 2, serde_json::json!({
            "name":"computer_use", "arguments":{"action":"takeover_scroll", "target":APP, "axis":"vertical", "amount_lines":2},
        }))).await;
        let early = tokio::time::timeout(Duration::from_millis(100), rig.replies.recv()).await;
        assert!(
            early.is_err(),
            "scroll overtook the keys call on the same app: {early:?}"
        );
        // Cancelling rather than approving avoids posting any real input. The
        // second call's takeover question proves it entered its handler only
        // after the first app-lane owner finished.
        rig.send(frame(FrameType::Cancel, 7, 1, serde_json::json!({})))
            .await;
        let mut keys_finished = false;
        let mut scroll_question = None;
        for _ in 0..2 {
            let frame = rig.reply().await;
            match frame.header.ty {
                FrameType::Response => {
                    assert_eq!(frame.header.corr, 1);
                    assert_eq!(
                        serde_json::from_slice::<Value>(&frame.body).unwrap()["outcome"],
                        "cancelled"
                    );
                    keys_finished = true;
                }
                FrameType::Request => scroll_question = Some(frame),
                _ => panic!("unexpected frame: {frame:?}"),
            }
        }
        assert!(keys_finished);
        let question = scroll_question.expect("scroll ran after keys released the lane");
        assert_eq!(
            serde_json::from_slice::<Value>(&question.body).unwrap()["params"]["target"]["kind"],
            "machine"
        );
        rig.send(frame(FrameType::Cancel, 7, 2, serde_json::json!({})))
            .await;
        let response = rig.reply().await;
        assert_eq!(
            (response.header.ty, response.header.corr),
            (FrameType::Response, 2)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap()["outcome"],
            "cancelled"
        );
        rig.finish().await;
    }
}
