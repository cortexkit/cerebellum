//! FIFO execution for one conversation's reads and actions on one application.
//!
//! A reservation is polled once when it is issued, not first polled by the
//! spawned request. Tokio's mutex queues on that first poll. The frame loop
//! resolves the app and issues this ticket before spawning, without awaiting
//! the app lock. A slow spawn therefore cannot let a later frame overtake it,
//! and neither consent nor dispatch blocks the frame reader.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

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

    async fn acquire(self) -> OwnedMutexGuard<()> {
        self.future.await
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
pub(super) struct AppGuard {
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

pub(crate) struct AppReservation {
    reservation: Reservation,
    lease: Lease,
}

#[derive(Default)]
pub(super) struct Serializer {
    registry: Arc<Registry>,
}

impl Serializer {
    fn reserve(&self, key: Key) -> AppReservation {
        let mut entries = self.registry.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.entry(key.clone()).or_insert_with(|| Entry {
            mutex: Arc::new(AsyncMutex::new(())),
            users: 0,
        });
        entry.users += 1;
        AppReservation {
            reservation: Reservation::new(entry.mutex.clone()),
            lease: Lease {
                registry: self.registry.clone(),
                key,
            },
        }
    }
}

tokio::task_local! {
    static ARRIVAL: RefCell<Option<AppReservation>>;
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) async fn scope<T>(
    arrival: Option<AppReservation>,
    future: impl Future<Output = T>,
) -> T {
    ARRIVAL.scope(RefCell::new(arrival), future).await
}

/// Resolve and reserve in frame order, but never wait for the app lock here.
/// Admission is checked before any platform lookup; refused calls still go
/// through the ordinary handler to receive its existing refusal.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) async fn arrive(
    frame: &subc_protocol::Frame,
    planes: &crate::Planes,
) -> Option<AppReservation> {
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
    plane
        .reserve_app(
            capability,
            arguments,
            &facts.identity.conversation_key,
            &planes.management,
        )
        .await
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
    ) -> Result<Option<AppGuard>, ConsentRefusal> {
        if matches!(capability.0, Served::ListApps) || valid_request(capability, arguments).is_err()
        {
            return Ok(None);
        }
        let ticket = ARRIVAL
            .try_with(|arrival| arrival.borrow_mut().take())
            .ok()
            .flatten();
        let enter = async {
            let ticket = match ticket {
                Some(ticket) => ticket,
                None => {
                    self.reserve_app(
                        capability,
                        arguments,
                        &context.identity.conversation_key,
                        context.management,
                    )
                    .await?
                }
            };
            let lock = ticket.reservation.acquire().await;
            Some(AppGuard {
                _lock: lock,
                _lease: ticket.lease,
            })
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
    ) -> Option<AppReservation> {
        let app = self
            .serialization_app(capability, arguments, conversation, management)
            .await?;
        Some(
            self.serializer
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
            // Scroll has no point that can be resolved before dispatch. It uses
            // a conversation-local takeover lane rather than guessing the app
            // currently under the shared pointer.
            Served::TakeoverScroll => Some("takeover".to_string()),
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
                let current = management.resolve_process(&image.bundle_identity).ok()?;
                if current.pid != image.pid
                    || current.process_generation_evidence != image.process_generation
                {
                    return None;
                }
                let (x, y) = points[0];
                let (x, y) = image.mapping.pixel_to_desktop(x as f64, y as f64);
                let point = SyntheticPoint { x, y };
                let source = self.app_state_source.clone();
                let management = management.clone();
                tokio::task::spawn_blocking(move || {
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
            Served::ReadState | Served::Type | Served::Keys => self
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
        AppStateReadError, AppStateSource, RawAppState, ReadBounds, RunningApp,
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
    }
    impl Desk {
        fn release(&self) {
            *self.released.0.lock().unwrap() = true;
            self.released.1.notify_all();
        }
    }
    impl AppStateSource for Desk {
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
        let desk = Arc::new(Desk {
            reads: AtomicUsize::new(0),
            events: events_tx,
            released: (Mutex::new(false), Condvar::new()),
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
        planes.computer_admitted = Arc::new(["computer.read_state".to_string()].into());
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
            wire,
            replies,
            dispatch,
        }
    }
    impl Rig {
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
                    let registry = &self.planes.computer.as_ref().unwrap().serializer.registry;
                    if registry.0.lock().unwrap().is_empty() {
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
}
