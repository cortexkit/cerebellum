//! Message-ordered entry, then FIFO execution on one application.
//!
//! A reservation is polled once when it is issued, not first polled by the
//! spawned request. Tokio's mutex queues on that first poll. The frame loop
//! registers a message index and reserves a conversation position if ready.
//! The spawned task waits for its predecessor, resolves the app, reserves its
//! app position, then releases the conversation lane before waiting for the
//! app. Platform work can never hold the frame reader.

use std::cell::RefCell;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use cerebellum_computer::app_state::session::ElementResolution;
use cerebellum_computer::app_state::source::HitScope;
use cerebellum_computer::capture::CaptureBackend;
use cerebellum_computer::platform::{PlatformDriver, SyntheticPoint};
use cerebellum_core::clock::MonotonicClock;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_core::journal::message_position_from_request_member;
use cerebellum_core::journal::{JournalStorage, Redactor, SeverityTaxonomy};
use serde_json::Value;

use super::{ComputerPlane, Servable, ServeContext, Served};
use crate::call_queue::{ConversationPosition, ConversationQueue, LaneGuard, Registry};
use crate::computer_grants::ConsentRefusal;

const RESOLUTION_LIMIT: Duration = Duration::from_secs(2);

// A predecessor may park for consent for 120s, then spend the signer's learned
// launch budget (at most 120s) opening an app. Include the 2s target-resolution
// window. One arrival-based deadline covers both queues so moving from the
// conversation lane to the app FIFO cannot restart the wait budget.
const QUEUE_WAIT_LIMIT: Duration = crate::computer_grants::CONSENT_PARK_LIMIT
    .saturating_add(Duration::from_millis(crate::open_app_history::CEILING_MS))
    .saturating_add(RESOLUTION_LIMIT);

#[derive(Default)]
pub(super) struct Serializer {
    conversations: ConversationQueue,
    registry: Arc<Registry>,
    /// The plane's blocking-worker capacity.
    pub(super) permits: super::quarantine::PermitPool,
    /// Workers still running after their call was answered, by application.
    pub(super) quarantine: Arc<super::quarantine::ExecutionQuarantine>,
    #[cfg(test)]
    entered: std::sync::Mutex<Vec<cerebellum_core::journal::ComputerOrderRecord>>,
}

impl Serializer {
    fn arrive(
        &self,
        conversation: String,
        position: Option<subc_protocol::tool_call::MessagePosition>,
    ) -> ConversationPosition {
        self.conversations.arrive(conversation, position)
    }
}

tokio::task_local! {
    static ARRIVAL: RefCell<Option<ConversationPosition>>;
}

/// How often a call waiting for its application's lane checks whether a
/// stuck worker now holds that application, so it is refused promptly rather
/// than queued behind a worker that may never return.
const QUARANTINE_POLL: Duration = Duration::from_millis(50);

/// A call that has reached its execution lane: the lane, when the call is
/// serialized, and the application it resolved to, when resolution finished.
pub(super) struct Admitted {
    pub(super) lane: Option<LaneGuard>,
    pub(super) app: Option<String>,
}

impl Admitted {
    fn unserialized() -> Self {
        Self {
            lane: None,
            app: None,
        }
    }
}

/// Why a call was refused before reaching its execution lane.
pub(super) enum QueueRefusal {
    Consent(ConsentRefusal),
    /// A worker still running past its call's answer holds the application.
    Busy(&'static str),
    /// No blocking-worker permit was free for the target-resolution query.
    CapacityExhausted,
}

impl From<ConsentRefusal> for QueueRefusal {
    fn from(refusal: ConsentRefusal) -> Self {
        Self::Consent(refusal)
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) async fn scope<T>(
    arrival: Option<ConversationPosition>,
    future: impl Future<Output = T>,
) -> T {
    ARRIVAL.scope(RefCell::new(arrival), future).await
}

/// Register an arrival without resolving a target, waiting for a predecessor,
/// or querying the platform. Refused calls still use the normal reply handler.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn arrive(
    frame: &subc_protocol::Frame,
    planes: &crate::Planes,
) -> Option<ConversationPosition> {
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
    let position = message_position_from_request_member(body.get("origin"));
    if (matches!(capability.0, Served::ListApps) && position.is_none())
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
            .arrive(facts.identity.conversation_key, position),
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
        context: &mut ServeContext<'_, C>,
    ) -> Result<Admitted, QueueRefusal> {
        if valid_request(capability, arguments).is_err() {
            return Ok(Admitted::unserialized());
        }
        let ticket = ARRIVAL
            .try_with(|arrival| arrival.borrow_mut().take())
            .ok()
            .flatten();
        // An indexed inventory call still enters its message window, otherwise
        // its successor would wait for an index we intentionally discarded.
        // Legacy inventory calls retain their existing unserialized behavior.
        if matches!(capability.0, Served::ListApps) && ticket.is_none() {
            return Ok(Admitted::unserialized());
        }
        let cancel = context.cancel.clone();
        let drain = context.consent.drain.clone();
        let ticket = ticket.unwrap_or_else(|| {
            self.serializer
                .arrive(context.identity.conversation_key.clone(), None)
        });
        let deadline = ticket.wait_deadline(QUEUE_WAIT_LIMIT);
        let enter = async {
            let (conversation, order) = ticket.acquire().await;
            context.identity.computer_order = order.positioned();
            #[cfg(test)]
            self.serializer.entered.lock().unwrap().push(order);
            // A resolution that may query the platform takes a work permit of
            // its own, held by the query until it really ends. With none free
            // nothing is spawned and the call is refused before dispatch.
            let hold = if resolution_may_block(capability) {
                match self.serializer.permits.try_resolution() {
                    Some(permit) => Some(permit),
                    None => return Err(QueueRefusal::CapacityExhausted),
                }
            } else {
                None
            };
            // Ordering is best-effort when resolution exceeds two seconds:
            // run this call unserialized rather than letting a wedged platform
            // query stall every other app in the conversation. Dropping the
            // await cannot stop a running blocking query, but that query holds
            // neither the conversation lane nor an app lane, keeps its own permit, and cannot reserve an app
            // lock after the timeout.
            let app = tokio::time::timeout(
                RESOLUTION_LIMIT,
                self.serialization_app(
                    capability,
                    arguments,
                    &context.identity.conversation_key,
                    context.management,
                    hold,
                ),
            )
            .await
            .ok()
            .flatten();
            drop(conversation);
            let Some(app) = app else {
                return Ok(Admitted::unserialized());
            };
            let busy = || self.serializer.quarantine.busy(None, None, Some(&app));
            if let Some(stuck) = busy() {
                return Err(QueueRefusal::Busy(stuck));
            }
            let ticket = self.serializer.registry.reserve((
                context.identity.conversation_key.clone(),
                app.to_lowercase(),
            ));
            let acquire = ticket.acquire();
            tokio::pin!(acquire);
            let lane = loop {
                tokio::select! {
                    lane = &mut acquire => break lane,
                    _ = tokio::time::sleep(QUARANTINE_POLL) => {
                        if let Some(stuck) = busy() {
                            return Err(QueueRefusal::Busy(stuck));
                        }
                    }
                }
            };
            Ok(Admitted {
                lane: Some(lane),
                app: Some(app),
            })
        };
        wait_for_lane(deadline, enter, cancel, drain).await?
    }

    async fn serialization_app(
        &self,
        capability: Servable,
        arguments: &Value,
        conversation: &str,
        management: &Arc<crate::management::ManagementPlane>,
        hold: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    ) -> Option<String> {
        let sessions = management.app_state_sessions();
        match capability.0 {
            Served::ListApps => None,
            Served::PressElement | Served::WriteText => {
                let id = arguments
                    .get("element_id")
                    .or_else(|| arguments.get("element_ids")?.as_array()?.first())?
                    .as_str()?;
                match sessions.resolve(conversation, id) {
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
                    let _permit = hold;
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
            Served::Wait => {
                self.resolve_target_name_or_installed(arguments.get("app")?.as_str()?, hold)
                    .await
            }
            Served::ReadState | Served::Type | Served::Keys | Served::TakeoverScroll => {
                self.resolve_target_name_or_installed(arguments.get("target")?.as_str()?, hold)
                    .await
            }
            // The app has no process yet, so resolve it from the installed
            // inventory. Its lane is the bundle identity that later calls on
            // the running app resolve to, so they queue behind the launch.
            Served::OpenApp => {
                let target = super::open_app::parse_request(arguments).ok()?;
                let source = self.app_state_source.clone();
                tokio::task::spawn_blocking(move || {
                    let _permit = hold;
                    let listed = source.installed_apps(std::time::Duration::from_secs(1));
                    super::open_app::resolve_installed(&target.target, &listed.apps)
                        .ok()
                        .map(|app| app.bundle_identity)
                })
                .await
                .ok()
                .flatten()
            }
        }
    }

    async fn resolve_target_name_or_installed(
        &self,
        target: &str,
        hold: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    ) -> Option<String> {
        if let Ok(bundle_identity) = self.resolve_target_name_holding(target, hold.clone()).await {
            return Some(bundle_identity);
        }

        let source = self.app_state_source.clone();
        let target = target.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = hold;
            let listed = source.installed_apps(std::time::Duration::from_secs(1));
            super::open_app::resolve_installed(&target, &listed.apps)
                .ok()
                .map(|app| app.bundle_identity)
        })
        .await
        .ok()
        .flatten()
    }
}

async fn wait_for_lane<T>(
    deadline: tokio::time::Instant,
    enter: impl Future<Output = T>,
    cancel: crate::CancelHandle,
    mut drain: tokio::sync::watch::Receiver<bool>,
) -> Result<T, ConsentRefusal> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(ConsentRefusal::Cancelled),
        _ = async {
            if drain.wait_for(|draining| *draining).await.is_err() {
                std::future::pending::<()>().await;
            }
        } => Err(ConsentRefusal::Draining),
        _ = tokio::time::sleep_until(deadline) => Err(ConsentRefusal::QueueWaitExpired),
        guard = enter => Ok(guard),
    }
}

/// Whether resolving this capability's target may query the platform, and so
/// needs a blocking-worker permit of its own.
fn resolution_may_block(capability: Servable) -> bool {
    !matches!(
        capability.0,
        Served::ListApps | Served::PressElement | Served::WriteText | Served::PressPoint
    )
}

/// A refusal decided before the call's action could start, in the reply
/// envelope its capability's vocabulary row requires (the keystroke rows
/// require effect and containment fields).
pub(super) fn refused_in_queue(capability: Servable, reply: Value) -> Value {
    if matches!(capability.0, Served::Type | Served::Keys) {
        super::synthetic_wire_envelope(super::keystrokes::refused_before_posting(reply))
    } else {
        reply
    }
}

pub(super) fn queued_refusal(
    capability: Servable,
    arguments: &Value,
    refusal: impl Into<QueueRefusal>,
) -> Value {
    let refusal = match refusal.into() {
        QueueRefusal::Consent(refusal) => refusal,
        QueueRefusal::Busy(stuck) => {
            return refused_in_queue(
                capability,
                super::quarantine::target_busy_reply(stuck, "queue"),
            )
        }
        QueueRefusal::CapacityExhausted => {
            return refused_in_queue(
                capability,
                super::quarantine::capacity_exhausted_reply("queue", "target resolution"),
            )
        }
    };
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
    refused_in_queue(capability, reply)
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
        Served::OpenApp => super::open_app::parse_request(arguments).map(|_| ()),
        _ => super::parse_synthetic_request(capability.capability(), arguments).map(|_| ()),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::call_queue::GAP_LIMIT;
    use crate::*;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, AppStateSource, BundleSignature, ElementActionError, ElementHandle,
        InstalledApp, InstalledApps, OpenAppBounds, OpenedApp, RawAppState, ReadBounds, RunningApp,
    };
    use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
    use cerebellum_core::journal::{ComputerOrderRecord, ComputerOrdering};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;
    use subc_protocol::{Frame, FrameType};
    use tokio::io::DuplexStream;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio::time::Instant;

    const APP: &str = "com.example.Editor";
    const OTHER: &str = "com.example.Viewer";

    struct Running {
        desk: Arc<Desk>,
    }
    impl management::TargetResolver for Running {
        fn resolve(&self, bundle_identity: &str) -> TargetResolution {
            if !self.desk.is_running(bundle_identity) {
                return TargetResolution::NotRunning;
            }
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
        LaunchStarted(String),
        PressStarted(usize),
    }

    /// Each read reports its invocation number through a different real reply:
    /// the first reads an unreadable subtree, the second sees a vanished app.
    /// This makes wire correlation, not just task start order, observable.
    struct Desk {
        reads: AtomicUsize,
        unreadable_reads: AtomicBool,
        events: mpsc::UnboundedSender<Event>,
        released: (Mutex<bool>, Condvar),
        hits: AtomicUsize,
        hits_returned: AtomicUsize,
        hit_started: mpsc::UnboundedSender<usize>,
        hit_released: (Mutex<bool>, Condvar),
        scripted_installed: Mutex<Option<Vec<InstalledApp>>>,
        scripted_running: Mutex<Option<HashSet<String>>>,
        launch_blocked: AtomicBool,
        launch_released: (Mutex<bool>, Condvar),
        running_queries: AtomicUsize,
        read_targets: Mutex<Vec<String>>,
        presses: AtomicUsize,
        press_released: (Mutex<bool>, Condvar),
    }
    impl Desk {
        fn release_press(&self) {
            *self.press_released.0.lock().unwrap() = true;
            self.press_released.1.notify_all();
        }

        fn script_apps(&self, installed: Vec<InstalledApp>, running: &[&str]) {
            *self.scripted_installed.lock().unwrap() = Some(installed);
            *self.scripted_running.lock().unwrap() =
                Some(running.iter().map(|bundle| (*bundle).to_string()).collect());
            *self.launch_released.0.lock().unwrap() = false;
            self.launch_blocked.store(true, Ordering::SeqCst);
        }

        fn is_running(&self, bundle_identity: &str) -> bool {
            self.scripted_running
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(|running| running.contains(bundle_identity))
        }

        fn release_hit(&self) {
            *self.hit_released.0.lock().unwrap() = true;
            self.hit_released.1.notify_all();
        }

        fn release(&self) {
            *self.released.0.lock().unwrap() = true;
            self.released.1.notify_all();
        }

        fn release_launch(&self) {
            *self.launch_released.0.lock().unwrap() = true;
            self.launch_released.1.notify_all();
        }
    }
    struct ReleaseHit(Arc<Desk>);
    impl Drop for ReleaseHit {
        fn drop(&mut self) {
            self.0.release_hit();
        }
    }

    impl AppStateSource for Desk {
        fn element_facts(
            &self,
            _: &ElementHandle,
        ) -> Result<cerebellum_computer::app_state::source::ElementFacts, ElementActionError>
        {
            Ok(cerebellum_computer::app_state::source::ElementFacts {
                pid: Some(42),
                role: Some("AXButton".into()),
                subrole: None,
                title: Some("Go".into()),
                actions: vec!["AXPress".into()],
                value_settable: false,
                selected_text_settable: false,
            })
        }
        /// Every press is counted; each waits until the test releases it.
        fn press(&self, _: &ElementHandle) -> Result<(), ElementActionError> {
            let number = self.presses.fetch_add(1, Ordering::SeqCst) + 1;
            self.events.send(Event::PressStarted(number)).unwrap();
            let (released, _) = self
                .press_released
                .1
                .wait_timeout_while(
                    self.press_released.0.lock().unwrap(),
                    Duration::from_secs(30),
                    |released| !*released,
                )
                .unwrap();
            drop(released);
            Ok(())
        }
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
            self.running_queries.fetch_add(1, Ordering::SeqCst);
            let scripted = self.scripted_installed.lock().unwrap().clone();
            let Some(installed) = scripted else {
                return Ok(vec![RunningApp {
                    name: "Editor".into(),
                    bundle_identity: APP.into(),
                    pid: 42,
                    frontmost: true,
                }]);
            };
            let running = self.scripted_running.lock().unwrap();
            let running = running.as_ref().expect("scripted running inventory");
            Ok(installed
                .into_iter()
                .filter(|app| running.contains(&app.bundle_identity))
                .map(|app| RunningApp {
                    name: app.name,
                    pid: if app.bundle_identity == APP { 42 } else { 43 },
                    bundle_identity: app.bundle_identity,
                    frontmost: false,
                })
                .collect())
        }

        fn installed_apps(&self, _: Duration) -> InstalledApps {
            InstalledApps {
                apps: self
                    .scripted_installed
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_default(),
                complete: true,
            }
        }

        fn bundle_signature(&self, _: &InstalledApp) -> Result<BundleSignature, AppStateReadError> {
            Ok(BundleSignature {
                signed: true,
                ad_hoc: false,
                team_id: Some("fixture-team".into()),
                designated_requirement: Some("fixture-requirement".into()),
                apple_anchored: false,
            })
        }

        fn bundle_satisfies(&self, _: &InstalledApp, _: &str) -> bool {
            true
        }

        fn open_app(
            &self,
            app: &InstalledApp,
            _: OpenAppBounds,
        ) -> Result<OpenedApp, cerebellum_computer::app_state::source::OpenAppError> {
            if self.launch_blocked.load(Ordering::SeqCst) {
                self.events
                    .send(Event::LaunchStarted(app.bundle_identity.clone()))
                    .unwrap();
                let (released, timeout) = self
                    .launch_released
                    .1
                    .wait_timeout_while(
                        self.launch_released.0.lock().unwrap(),
                        Duration::from_secs(5),
                        |released| !*released,
                    )
                    .unwrap();
                assert!(
                    !timeout.timed_out(),
                    "scripted app launch was never released"
                );
                drop(released);
                self.scripted_running
                    .lock()
                    .unwrap()
                    .as_mut()
                    .expect("scripted running inventory")
                    .insert(app.bundle_identity.clone());
            }
            Ok(OpenedApp {
                pid: if app.bundle_identity == APP { 42 } else { 43 },
                already_running: false,
                has_window: true,
                frontmost: false,
                process_started_ms: 50,
                first_window_ms: Some(100),
            })
        }
        fn read_app_state(
            &self,
            target: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            self.read_targets
                .lock()
                .unwrap()
                .push(target.bundle_identity.clone());
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
            Err(
                if number == 1 || self.unreadable_reads.load(Ordering::SeqCst) {
                    AppStateReadError::Unreadable
                } else {
                    AppStateReadError::TargetGone
                },
            )
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
    fn positioned(corr: u64, message: &str, index: Value) -> Frame {
        let mut body: Value = serde_json::from_slice(&request(7, corr, APP).body).unwrap();
        body["origin"] = serde_json::json!({
            "carrier": {"kind": "direct"}, "call_key": format!("call-{corr}"),
            "message_position": {"message_id": message, "index": index},
        });
        frame(FrameType::Request, 7, corr, body)
    }
    fn press_request(channel: u16, corr: u64, ids: &[String]) -> Frame {
        frame(
            FrameType::Request,
            channel,
            corr,
            serde_json::json!({
                "name": "computer_use",
                "arguments": {"action": "press_element", "element_ids": ids},
            }),
        )
    }
    /// A read_state whose zoom names nothing: it is admitted and checked like
    /// any read, then answers `stale_element` without reading the desk.
    fn unread_request(channel: u16, corr: u64, app: &str) -> Frame {
        let mut body: Value = serde_json::from_slice(&request(channel, corr, app).body).unwrap();
        body["arguments"]["zoom"] = serde_json::json!("zz999999");
        frame(FrameType::Request, channel, corr, body)
    }
    fn outcome(frame: &Frame) -> Value {
        assert_eq!(frame.header.ty, FrameType::Response, "{frame:?}");
        serde_json::from_slice(&frame.body).unwrap()
    }
    fn open_request(channel: u16, corr: u64, app: &str) -> Frame {
        frame(
            FrameType::Request,
            channel,
            corr,
            serde_json::json!({
                "name": "computer_use", "arguments": {"action": "open_app", "target": app},
            }),
        )
    }
    fn installed_app(name: &str, bundle_identity: &str) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            bundle_identity: bundle_identity.into(),
            path: std::path::PathBuf::from(format!("/fixture/{name}.app")),
        }
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
            unreadable_reads: AtomicBool::new(false),
            events: events_tx,
            released: (Mutex::new(false), Condvar::new()),
            hits: AtomicUsize::new(0),
            hits_returned: AtomicUsize::new(0),
            hit_started,
            hit_released: (Mutex::new(true), Condvar::new()),
            scripted_installed: Mutex::new(None),
            scripted_running: Mutex::new(None),
            launch_blocked: AtomicBool::new(false),
            launch_released: (Mutex::new(true), Condvar::new()),
            running_queries: AtomicUsize::new(0),
            read_targets: Mutex::new(Vec::new()),
            presses: AtomicUsize::new(0),
            press_released: (Mutex::new(false), Condvar::new()),
        });
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.management = Arc::new(management::ManagementPlane::new(Arc::new(Running {
            desk: desk.clone(),
        })));
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
                "computer.list_apps",
                "computer.open_app",
                "computer.takeover_move",
                "computer.takeover_scroll",
                "computer.keys",
                "computer.press_element",
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
        async fn ordering_ready(&mut self) {
            self.grant(7, APP).await;
            self.desk.unreadable_reads.store(true, Ordering::SeqCst);
            self.desk.release();
            self.planes
                .computer
                .as_ref()
                .unwrap()
                .serializer
                .entered
                .lock()
                .unwrap()
                .clear();
        }

        fn entries(&self) -> Vec<ComputerOrderRecord> {
            self.planes
                .computer
                .as_ref()
                .unwrap()
                .serializer
                .entered
                .lock()
                .unwrap()
                .clone()
        }

        async fn wait_entries(&self, count: usize) {
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.entries().len() < count {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("ready calls enter without paying another message's gap");
        }

        async fn responses(&mut self, count: usize) -> Vec<u64> {
            let mut correlations = Vec::new();
            for _ in 0..count {
                let reply = self.reply().await;
                assert_eq!(reply.header.ty, FrameType::Response);
                correlations.push(reply.header.corr);
            }
            correlations
        }

        async fn audit_rows(&self) -> Vec<Value> {
            let plane = self.planes.computer.as_ref().unwrap();
            let audit = cerebellum_computer::audit::lock_audit(&plane.audit);
            serde_json::Deserializer::from_slice(&audit.journal().export_bytes())
                .into_iter::<Value>()
                .map(Result::unwrap)
                .collect()
        }
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
        async fn start_held_launch(&mut self, channel: u16, corr: u64, app: &str) {
            self.send(open_request(channel, corr, app)).await;
            let question = self.reply().await;
            assert_eq!(question.header.ty, FrameType::Request);
            self.allow(&question).await;
            assert_eq!(
                self.event().await,
                Event::LaunchStarted(if app == "Calculator" {
                    APP.into()
                } else {
                    app.into()
                })
            );
        }

        async fn read_response_after_launch(&mut self, corr: u64) -> (Value, Value) {
            let mut launch_reply = None;
            let mut read_reply = None;
            while launch_reply.is_none() || read_reply.is_none() {
                let frame = self.reply().await;
                if frame.header.ty == FrameType::Request {
                    assert_eq!(frame.header.corr, corr);
                    self.allow(&frame).await;
                    continue;
                }
                assert_eq!(frame.header.ty, FrameType::Response);
                let body: Value = serde_json::from_slice(&frame.body).unwrap();
                if frame.header.corr == 1 {
                    launch_reply = Some(body);
                } else if frame.header.corr == corr {
                    read_reply = Some(body);
                } else {
                    panic!(
                        "unexpected response correlation {}: {body}",
                        frame.header.corr
                    );
                }
            }
            (launch_reply.unwrap(), read_reply.unwrap())
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
                    if serializer.registry.is_empty() && serializer.conversations.is_empty() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("idle app lock map is empty");
        }
        /// Number two buttons of the editor for `channel`'s conversation, as a
        /// read would, and return their element ids.
        fn register_buttons(&self, channel: u16) -> Vec<String> {
            use cerebellum_computer::app_state::source::{
                ElementValue, FixtureElementToken, RawElement,
            };
            let conversation = self
                .planes
                .routes
                .get(channel, 1)
                .unwrap()
                .identity
                .conversation_key;
            let button = |token: u64| RawElement {
                handle: Arc::new(FixtureElementToken(token)),
                role: Some("AXButton".into()),
                subrole: None,
                title: Some(format!("Go {token}")),
                description: None,
                value_description: None,
                value: ElementValue::Absent,
                value_settable: false,
                selected: false,
                enabled: true,
                focused: false,
                expanded: None,
                menu_visible: false,
                closed_menu_children: 0,
                url: None,
                children: Vec::new(),
                unreadable_children: 0,
            };
            let raw = RawAppState {
                roots: vec![button(1), button(2)],
                focused: None,
                unreadable_subtrees: 0,
                read_bound_reached: false,
            };
            let grant = ProcessGrant {
                pid: 42,
                bundle_identity: APP.into(),
                process_generation_evidence: "fixture-generation".into(),
            };
            let read =
                self.planes
                    .management
                    .app_state_sessions()
                    .observe(&conversation, &grant, &raw);
            let ids: Vec<String> = read
                .roots
                .iter()
                .filter_map(|node| node.element_id.clone())
                .collect();
            assert_eq!(ids.len(), 2, "both buttons were numbered");
            ids
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
    async fn message_indices_enter_in_model_order() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        for index in [2, 0, 3, 1] {
            rig.send(positioned(
                index + 1,
                "one-message",
                serde_json::json!(index),
            ))
            .await;
        }
        let mut replies = rig.responses(4).await;
        replies.sort_unstable();
        assert_eq!(replies, [1, 2, 3, 4]);
        assert_eq!(
            rig.entries()
                .iter()
                .map(|entry| entry.message_index)
                .collect::<Vec<_>>(),
            [Some(0), Some(1), Some(2), Some(3)]
        );
        assert!(rig
            .entries()
            .iter()
            .all(|entry| entry.ordering == ComputerOrdering::Position));
        let rows = rig.audit_rows().await;
        assert_eq!(
            rows.iter()
                .map(|row| row["identity"]["message_index"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert!(rows
            .iter()
            .all(|row| row["identity"]["ordering"] == "position"));
        assert!(!serde_json::to_string(&rows)
            .unwrap()
            .contains("one-message"));
        rig.finish().await;
    }

    #[tokio::test]
    async fn missing_predecessor_skips_after_bound_and_is_journaled() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        rig.send(positioned(1, "gap-message", serde_json::json!(0)))
            .await;
        rig.responses(1).await;
        let start = Instant::now();
        rig.send(positioned(2, "gap-message", serde_json::json!(2)))
            .await;
        rig.responses(1).await;
        assert!(
            start.elapsed() >= GAP_LIMIT,
            "a missing predecessor must get its arrival window"
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(rig.entries()[1].ordering, ComputerOrdering::SkippedGap);
        let rows = rig.audit_rows().await;
        assert_eq!(rows[1]["identity"]["message_index"], 2);
        assert_eq!(rows[1]["identity"]["ordering"], "skipped_gap");
        rig.finish().await;
    }

    #[tokio::test]
    async fn unpositioned_calls_interleave_in_arrival_order() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        rig.send(positioned(1, "a", serde_json::json!(2))).await;
        rig.send(request(7, 2, APP)).await;
        rig.wait_entries(1).await;
        rig.send(request(7, 3, APP)).await;
        rig.wait_entries(2).await;
        rig.send(positioned(4, "a", serde_json::json!(0))).await;
        rig.wait_entries(3).await;
        rig.send(positioned(5, "a", serde_json::json!(1))).await;
        rig.responses(5).await;
        assert_eq!(
            rig.entries()
                .iter()
                .map(|entry| entry.message_index)
                .collect::<Vec<_>>(),
            [None, None, Some(0), Some(1), Some(2)]
        );
        let rows = rig.audit_rows().await;
        assert!(rows[0]["identity"].get("ordering").is_none());
        assert!(rows[0]["identity"].get("message_index").is_none());
        rig.finish().await;
    }

    #[tokio::test]
    async fn two_messages_bypass_each_others_gap_waiters() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        // A:2, U, A:0, B:0, A:1: only A's own indices wait for A.
        rig.send(positioned(1, "a", serde_json::json!(2))).await;
        rig.send(request(7, 2, APP)).await;
        rig.wait_entries(1).await;
        rig.send(positioned(3, "a", serde_json::json!(0))).await;
        rig.wait_entries(2).await;
        rig.send(positioned(4, "b", serde_json::json!(0))).await;
        rig.wait_entries(3).await;
        assert_eq!(
            rig.entries()
                .iter()
                .map(|entry| entry.message_index)
                .collect::<Vec<_>>(),
            [None, Some(0), Some(0)]
        );
        rig.send(positioned(5, "a", serde_json::json!(1))).await;
        rig.responses(5).await;
        assert_eq!(
            rig.entries()
                .iter()
                .map(|entry| entry.message_index)
                .collect::<Vec<_>>(),
            [None, Some(0), Some(0), Some(1), Some(2)]
        );
        rig.finish().await;
    }

    #[tokio::test]
    async fn cancel_predecessor_wait_is_prompt_and_successor_is_bounded() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        rig.send(positioned(1, "a", serde_json::json!(0))).await;
        rig.responses(1).await;
        rig.send(positioned(2, "a", serde_json::json!(2))).await;
        let start = Instant::now();
        rig.send(positioned(3, "a", serde_json::json!(3))).await;
        rig.send(frame(FrameType::Cancel, 7, 2, serde_json::json!({})))
            .await;
        let cancelled = rig.fast_reply().await;
        assert_eq!(cancelled.header.corr, 2);
        assert_eq!(
            serde_json::from_slice::<Value>(&cancelled.body).unwrap()["outcome"],
            "cancelled"
        );
        assert_eq!(rig.responses(1).await, [3]);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            rig.entries()
                .iter()
                .map(|entry| entry.message_index)
                .collect::<Vec<_>>(),
            [Some(0), Some(3)]
        );
        assert_eq!(rig.entries()[1].ordering, ComputerOrdering::SkippedGap);
        rig.finish().await;
    }

    #[tokio::test]
    async fn invalid_position_is_ignored_without_losing_attribution() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        let before = cerebellum_core::journal::message_position_invalid_count();
        let cases = [
            ("has space".to_string(), serde_json::json!(2)),
            (String::new(), serde_json::json!(2)),
            ("x".repeat(257), serde_json::json!(2)),
            ("hidden\n".to_string(), serde_json::json!(2)),
            ("non-ascii-é".to_string(), serde_json::json!(2)),
            ("valid".to_string(), serde_json::json!(-1)),
            ("valid".to_string(), serde_json::json!(0.5)),
            ("valid".to_string(), serde_json::json!("2")),
            ("valid".to_string(), serde_json::json!(u64::MAX)),
            ("valid".to_string(), serde_json::json!(65536)),
        ];
        for (number, (message, index)) in cases.into_iter().enumerate() {
            let corr = number as u64 + 1;
            rig.send(positioned(corr, &message, index)).await;
            assert_eq!(rig.fast_reply().await.header.corr, corr);
        }
        assert!(rig.entries().iter().all(|entry| *entry
            == ComputerOrderRecord {
                message_index: None,
                ordering: ComputerOrdering::Arrival,
            }));
        assert!(cerebellum_core::journal::message_position_invalid_count() > before);
        let rows = rig.audit_rows().await;
        assert_eq!(rows.len(), 10);
        assert!(rows
            .iter()
            .all(|row| row["identity"]["origin"]["status"] == "relayed"
                && row["identity"].get("ordering").is_none()));
        rig.finish().await;
    }

    #[tokio::test]
    async fn index_window_starts_at_lowest_arrival_not_zero() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        rig.send(positioned(1, "nonzero", serde_json::json!(7)))
            .await;
        rig.send(positioned(2, "nonzero", serde_json::json!(8)))
            .await;
        rig.responses(2).await;
        assert_eq!(
            rig.entries(),
            [
                ComputerOrderRecord {
                    message_index: Some(7),
                    ordering: ComputerOrdering::SkippedGap
                },
                ComputerOrderRecord {
                    message_index: Some(8),
                    ordering: ComputerOrdering::Position
                },
            ]
        );
        let mut inventory: Value =
            serde_json::from_slice(&positioned(3, "nonzero", serde_json::json!(9)).body).unwrap();
        inventory["arguments"] = serde_json::json!({"action": "list_apps"});
        rig.send(frame(FrameType::Request, 7, 3, inventory)).await;
        rig.send(positioned(4, "nonzero", serde_json::json!(10)))
            .await;
        // Inventory has no app lane, but must grant its index so the following
        // read does not pay a spurious gap or lose its ordering attribution.
        assert_eq!(rig.fast_reply().await.header.ty, FrameType::Response);
        assert_eq!(rig.fast_reply().await.header.ty, FrameType::Response);
        assert_eq!(rig.entries()[2].message_index, Some(9));
        assert_eq!(rig.entries()[3].message_index, Some(10));
        assert_eq!(rig.entries()[3].ordering, ComputerOrdering::Position);
        rig.finish().await;
    }

    #[tokio::test]
    async fn drain_interrupts_message_predecessor_wait() {
        let mut rig = rig(false, None);
        rig.ordering_ready().await;
        rig.send(positioned(1, "drain", serde_json::json!(2))).await;
        rig.send(frame(
            FrameType::Push,
            0,
            0,
            serde_json::json!({"op":"module.draining", "reason":"restart", "deadline_ms":123}),
        ))
        .await;
        let reply = rig.fast_reply().await;
        assert_eq!(reply.header.corr, 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.body).unwrap()["outcome"],
            "module_draining"
        );
        assert!(rig.entries().is_empty());
        rig.finish().await;
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
    async fn read_state_by_name_waits_for_held_open_app() {
        let mut rig = rig(false, None);
        rig.desk.script_apps(
            vec![
                installed_app("Calculator", APP),
                installed_app("Viewer", OTHER),
            ],
            &[OTHER],
        );
        rig.desk.release();
        rig.start_held_launch(7, 1, "Calculator").await;

        let queries_before_read = rig.desk.running_queries.load(Ordering::SeqCst);
        rig.send(request(7, 2, "Calculator")).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while rig.desk.running_queries.load(Ordering::SeqCst) == queries_before_read {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("read resolves the target while Calculator is not running");
        assert!(!rig.desk.is_running(APP));
        assert_eq!(rig.desk.reads.load(Ordering::SeqCst), 0);
        let early = tokio::time::timeout(Duration::from_millis(100), rig.replies.recv()).await;
        rig.desk.release_launch();
        assert!(
            early.is_err(),
            "read ran before the launch completed: {early:?}"
        );

        let (opened, read) = rig.read_response_after_launch(2).await;
        assert_eq!(opened["outcome"], "launched", "{opened}");
        assert_ne!(read["outcome"], "not_running", "{read}");
        assert_eq!(rig.event().await, Event::Start(1));
        assert_eq!(rig.event().await, Event::End(1));
        assert_eq!(*rig.desk.read_targets.lock().unwrap(), [APP]);
        rig.finish().await;
    }

    #[tokio::test]
    async fn different_app_read_runs_while_open_app_is_held() {
        let mut rig = rig(false, None);
        rig.desk.script_apps(
            vec![
                installed_app("Calculator", APP),
                installed_app("Viewer", OTHER),
            ],
            &[OTHER],
        );
        rig.grant(8, OTHER).await;
        rig.desk.release();
        rig.start_held_launch(7, 1, "Calculator").await;

        rig.send(request(8, 2, OTHER)).await;
        assert_eq!(rig.event().await, Event::Start(1));
        assert_eq!(*rig.desk.read_targets.lock().unwrap(), [OTHER]);
        assert_eq!(rig.event().await, Event::End(1));
        let independent = rig.reply().await;
        assert_eq!(
            (independent.header.ty, independent.header.corr),
            (FrameType::Response, 2)
        );
        assert_ne!(
            serde_json::from_slice::<Value>(&independent.body).unwrap()["outcome"],
            "not_running"
        );
        assert!(!rig.desk.is_running(APP), "launch remains held");

        rig.desk.release_launch();
        let opened = rig.reply().await;
        assert_eq!(
            (opened.header.ty, opened.header.corr),
            (FrameType::Response, 1)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&opened.body).unwrap()["outcome"],
            "launched"
        );
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
                    .has_users(2);
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
                    .has_users(2);
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

    #[tokio::test]
    async fn a_stop_after_a_press_began_answers_unknown_and_no_later_press_runs() {
        let mut rig = rig(false, None);
        rig.grant(7, APP).await;
        rig.desk.release();
        let ids = rig.register_buttons(7);
        rig.send(press_request(7, 1, &ids)).await;
        assert_eq!(rig.event().await, Event::PressStarted(1));
        rig.send(frame(FrameType::Cancel, 7, 1, serde_json::json!({})))
            .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        // The first press returns inside the cleanup window; the batch's
        // second press must not follow it.
        rig.desk.release_press();
        let reply = outcome(&rig.reply().await);
        assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
        assert_eq!(reply["detail"]["reason"], "cancelled", "{reply}");
        assert_eq!(reply["detail"]["dispatched"], true, "{reply}");
        assert_eq!(
            rig.desk.presses.load(Ordering::SeqCst),
            1,
            "no external call after the stop"
        );
        rig.finish().await;
    }

    #[tokio::test]
    async fn a_stuck_press_quarantines_its_app_for_every_conversation_until_it_ends() {
        let mut rig = rig(true, None);
        rig.grant(7, APP).await;
        rig.grant(8, APP).await;
        rig.grant(8, OTHER).await;
        rig.desk.release();
        let ids = rig.register_buttons(7);
        rig.send(press_request(7, 1, &ids[..1])).await;
        assert_eq!(rig.event().await, Event::PressStarted(1));
        rig.send(frame(FrameType::Cancel, 7, 1, serde_json::json!({})))
            .await;
        let stuck = tokio::time::timeout(Duration::from_secs(10), rig.replies.recv())
            .await
            .expect("the stuck call is answered after its bounded cleanup window")
            .unwrap();
        assert_eq!(outcome(&stuck)["outcome"], "dispatch_outcome_unknown");

        let plane = rig.planes.computer.as_ref().unwrap().clone();
        for (channel, corr) in [(8, 2), (7, 3)] {
            rig.send(unread_request(channel, corr, APP)).await;
            let busy = rig.reply().await;
            assert_eq!(busy.header.corr, corr);
            let busy = outcome(&busy);
            assert_eq!(busy["outcome"], "target_busy", "channel {channel}: {busy}");
            assert_eq!(busy["detail"]["call"], "computer.press_element", "{busy}");
            assert_eq!(busy["detail"]["dispatched"], false, "{busy}");
        }
        rig.send(unread_request(8, 4, OTHER)).await;
        assert_eq!(
            outcome(&rig.reply().await)["outcome"],
            "stale_element",
            "a call on another application proceeds"
        );
        assert_eq!(rig.desk.presses.load(Ordering::SeqCst), 1);

        rig.desk.release_press();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !plane.serializer.quarantine.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("execution quarantine clears when the worker ends");
        rig.send(unread_request(8, 5, APP)).await;
        assert_eq!(outcome(&rig.reply().await)["outcome"], "stale_element");
        rig.finish().await;
    }

    #[tokio::test]
    async fn no_free_permit_refuses_before_any_blocking_work_is_spawned() {
        let mut rig = rig(false, None);
        rig.grant(7, APP).await;
        let plane = rig.planes.computer.as_ref().unwrap().clone();
        let mut held: Vec<_> = (0..crate::budgets::MAX_BLOCKING_WORKERS_COMPUTER / 2)
            .map(|_| plane.serializer.permits.try_call().unwrap())
            .collect();
        let queries = rig.desk.running_queries.load(Ordering::SeqCst);
        rig.send(request(7, 1, "Editor")).await;
        let refused = outcome(&rig.reply().await);
        assert_eq!(
            refused["outcome"], "blocking_capacity_exhausted",
            "{refused}"
        );
        assert_eq!(refused["detail"]["call"], "target resolution", "{refused}");
        assert_eq!(
            rig.desk.running_queries.load(Ordering::SeqCst),
            queries,
            "no resolution query was spawned"
        );

        // One permit free: the resolution query runs on it and returns it,
        // but the call's lane needs two, so it is refused there instead.
        let last = held.pop().unwrap();
        drop(last.take_release());
        rig.send(request(7, 2, "Editor")).await;
        let refused = outcome(&rig.reply().await);
        assert_eq!(
            refused["outcome"], "blocking_capacity_exhausted",
            "{refused}"
        );
        assert_eq!(
            refused["detail"]["call"], "computer.read_state",
            "{refused}"
        );
        assert_eq!(rig.desk.running_queries.load(Ordering::SeqCst), queries + 1);
        assert_eq!(rig.desk.reads.load(Ordering::SeqCst), 0, "nothing was read");
        drop((held, last));
        rig.finish().await;
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stuck_computer_holder_expires_both_queue_waits_without_dispatch() {
        assert_eq!(QUEUE_WAIT_LIMIT, Duration::from_secs(242));
        for stuck_app in [false, true] {
            let queue = ConversationQueue::default();
            let registry = Arc::new(Registry::default());
            let (conversation, _) = queue.arrive("conversation".into(), None).acquire().await;
            let mut conversation = Some(conversation);
            let mut app_holder = Some(
                registry
                    .reserve(("conversation".into(), "app".into()))
                    .acquire()
                    .await,
            );
            let ticket = queue.arrive("conversation".into(), None);
            let deadline = ticket.wait_deadline(QUEUE_WAIT_LIMIT);
            let app = registry.reserve(("conversation".into(), "app".into()));
            let (drain_tx, drain) = tokio::sync::watch::channel(false);
            let enter = async move {
                let (guard, _) = ticket.acquire().await;
                drop(guard);
                Some(app.acquire().await)
            };
            let queued = tokio::spawn(wait_for_lane(
                deadline,
                enter,
                crate::CancelHandle::pending(),
                drain,
            ));
            tokio::task::yield_now().await;
            tokio::time::advance(RESOLUTION_LIMIT).await;
            if stuck_app {
                drop(conversation.take());
            } else {
                drop(app_holder.take());
            }
            tokio::task::yield_now().await;
            tokio::time::advance(QUEUE_WAIT_LIMIT - RESOLUTION_LIMIT - Duration::from_millis(1))
                .await;
            assert!(!queued.is_finished());
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert!(
                queued.is_finished(),
                "queue deadline did not end the call (app={stuck_app})"
            );
            assert_eq!(
                queued.await.unwrap().err(),
                Some(ConsentRefusal::QueueWaitExpired)
            );
            drop(conversation);
            drop(app_holder);
            assert!(queue.is_empty());
            assert!(registry.is_empty());
            drop(drain_tx);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn computer_queue_preserves_a_normal_consent_park() {
        let registry = Arc::new(Registry::default());
        let holder = registry
            .reserve(("conversation".into(), "app".into()))
            .acquire()
            .await;
        let ticket = registry.reserve(("conversation".into(), "app".into()));
        let (drain_tx, drain) = tokio::sync::watch::channel(false);
        let queued = tokio::spawn(wait_for_lane(
            tokio::time::Instant::now() + QUEUE_WAIT_LIMIT,
            async move { Some(ticket.acquire().await) },
            crate::CancelHandle::pending(),
            drain,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(crate::computer_grants::CONSENT_PARK_LIMIT).await;
        assert!(
            !queued.is_finished(),
            "normal consent must not expire the successor"
        );
        drop(holder);
        drop(queued.await.unwrap().unwrap());
        assert!(registry.is_empty());
        drop(drain_tx);
    }

    #[test]
    fn queue_expiry_replies_validate_for_every_computer_row() {
        for id in cerebellum_computer::platform::COMPUTER_CAPABILITY_ROW_IDS {
            let capability = super::super::servable(id).unwrap();
            let reply = queued_refusal(
                capability,
                &serde_json::json!({}),
                ConsentRefusal::QueueWaitExpired,
            );
            assert_eq!(reply["outcome"], "queue_wait_expired", "{id}: {reply}");
            assert!(reply["remedy"]
                .as_str()
                .unwrap()
                .contains("nothing was dispatched"));
            cerebellum_computer::platform::vocabulary::validate_capability_result(id, &reply)
                .unwrap();
        }
    }
}
