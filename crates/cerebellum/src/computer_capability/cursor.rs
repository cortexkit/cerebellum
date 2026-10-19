//! A lossy, memory-only picture alongside an admitted action. Nothing here
//! returns an action outcome or receives a request body.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
#[cfg(any(target_os = "macos", test))]
use std::time::Instant;

use cerebellum_computer::app_state::source::{AppStateSource, CursorWindowWatch, ElementHandle};
use cerebellum_computer::cursor::{
    follow_offset, label, CursorEvent, CursorFollow, CursorHide, CursorKind, CursorLine,
    WindowChange,
};
use cerebellum_computer::platform::ProcessGrant;
use tokio::sync::mpsc;

use crate::terminal_arbiter::TerminalArbiter;

const READ_BUDGET: Duration = Duration::from_millis(50);
const CAPACITY: usize = 32;
/// Bounds each memory-only record of who drew a badge. Far more than the agents
/// one person runs at once; past it the oldest record goes, and that agent's
/// badge still idles out on its own.
const RECORD_CAP: usize = 256;
/// At most this many windows are watched at once, one per badge on screen:
/// the helper draws no more badges than this either.
const FOLLOW_CAP: usize = 64;

#[cfg(target_os = "macos")]
pub(crate) mod avatar;

tokio::task_local! {
    pub(crate) static ACTING_AGENT: Option<String>;
    /// The daemon-stamped scope of the head session this call belongs to,
    /// so that session's turn ending can hide the badge the call drew.
    pub(crate) static ACTING_SESSION: Option<SessionScope>;
}

/// A head session's scope as the daemon stamped it on the route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionScope {
    pub(crate) scope_ref: String,
    /// Kept with the record but never compared: a revived session keeps its
    /// ref and takes a new epoch, and its turn ending must still find the
    /// badge drawn before the revival.
    #[allow(dead_code)]
    pub(crate) epoch: u64,
}

pub(crate) struct Identity {
    badge: String,
    avatar_agent: Option<String>,
    /// The route call drawing the badge. Captured here because the drawing may
    /// be scheduled from a blocking thread, where task-locals are not visible.
    call: Option<Arc<TerminalArbiter>>,
    session: Option<SessionScope>,
}

impl Identity {
    pub(crate) fn current(fallback: String) -> Self {
        let avatar_agent = ACTING_AGENT.try_with(Clone::clone).ok().flatten();
        Self {
            badge: avatar_agent.clone().unwrap_or(fallback),
            avatar_agent,
            call: TerminalArbiter::current(),
            session: ACTING_SESSION.try_with(Clone::clone).ok().flatten(),
        }
    }
}

/// How a head session's turn ended, as its owner reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TurnOutcome {
    Completed,
    Stopped,
    Failed,
}

/// Who drew which badge, so that a route closing, a call being cancelled, or a
/// session's turn ending can hide exactly those badges.
#[derive(Default)]
struct Drawn {
    /// For each agent, the serial counter's value when its badge was last
    /// ended. A picture scheduled before that end is still reading geometry
    /// and must not bring the badge back once its read finishes.
    ended_at: HashMap<String, u64>,
    /// Agents whose badges each `(channel, epoch)` route has drawn.
    routes: HashMap<(u16, u32), BTreeSet<String>>,
    /// Which head session drew which agent's badge, least recently drawn
    /// first.
    sessions: VecDeque<(SessionScope, String)>,
}

#[derive(Default)]
struct State {
    stopped: std::sync::atomic::AtomicBool,
    sender: OnceLock<mpsc::Sender<CursorLine>>,
    serial: std::sync::atomic::AtomicU64,
    drawn: std::sync::Mutex<Drawn>,
    /// For each agent whose badge is on screen, the window it rests on.
    follows: std::sync::Mutex<HashMap<String, Follow>>,
    follow_ids: std::sync::atomic::AtomicU64,
    #[cfg(target_os = "macos")]
    avatars: OnceLock<Arc<avatar::Avatars>>,
    #[cfg(target_os = "macos")]
    generation: std::sync::Mutex<Option<cerebellum_macos::ProcessGeneration>>,
}

/// One badge following its window: when the person moves or resizes the
/// window, the badge moves with the element it points at.
///
/// The watch is event-driven (an accessibility observer on the window, run
/// by the platform), so a resting badge costs nothing until the window
/// actually changes. It lives in this process, which already holds the
/// Accessibility permission the observer needs; the helper that draws the
/// badge has no such permission and only ever hears how far to move.
struct Follow {
    /// Tells this follow's watch from an older one for the same agent whose
    /// report is still on its way.
    id: u64,
    /// The picture event the badge was last drawn for; offsets count from it.
    serial: u64,
    source: Arc<dyn AppStateSource>,
    window: ElementHandle,
    element: Option<ElementHandle>,
    /// The window's and the element's frames when that event was drawn.
    base_window: [f64; 4],
    base_element: Option<[f64; 4]>,
    /// Dropping it removes the observer: on a hide, a new target, or the
    /// window closing.
    _watch: Box<dyn CursorWindowWatch>,
}

#[derive(Clone, Default)]
pub struct Coordinator(Arc<State>);

/// An initial launch and at most one restart, no sooner than a minute later.
/// A second crash leaves the cosmetic helper off until the module restarts.
#[derive(Default)]
#[cfg(any(target_os = "macos", test))]
struct RestartLimit {
    first: Option<Instant>,
    restarted: bool,
}

#[cfg(any(target_os = "macos", test))]
impl RestartLimit {
    fn admit(&mut self, now: Instant) -> bool {
        match self.first {
            None => {
                self.first = Some(now);
                true
            }
            Some(first)
                if !self.restarted && now.duration_since(first) >= Duration::from_secs(60) =>
            {
                self.restarted = true;
                true
            }
            _ => false,
        }
    }
}

impl Coordinator {
    #[cfg(target_os = "macos")]
    pub(crate) fn set_avatars(&self, avatars: Arc<avatar::Avatars>) {
        let _ = self.0.avatars.set(avatars);
    }
    /// Tests may supply a blocked or closed receiver without drawing a window.
    /// All production planes start disabled; only the module's config loader
    /// enables the native transport.
    #[doc(hidden)]
    pub fn channel() -> (Self, mpsc::Receiver<CursorLine>) {
        let result = Self::default();
        let (tx, rx) = mpsc::channel(CAPACITY);
        let _ = result.0.sender.set(tx);
        (result, rx)
    }

    pub fn enable(&self, enabled: bool) {
        if !enabled {
            self.shutdown();
        }
        #[cfg(target_os = "macos")]
        if enabled && self.0.sender.get().is_none() {
            let (tx, rx) = mpsc::channel(CAPACITY);
            if self.0.sender.set(tx).is_ok() {
                let state = self.0.clone();
                let _ = std::thread::Builder::new()
                    .name("agent-cursor-pipe".into())
                    .spawn(move || transport(state, rx));
            }
        }
    }

    /// No lock, await, backpressure, journal, or call-record writer on this path.
    pub fn send(&self, event: CursorEvent) {
        self.send_line(CursorLine::Picture(event));
    }

    fn send_line(&self, line: CursorLine) {
        if self.0.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        if let Some(sender) = self.0.sender.get() {
            let _ = sender.try_send(line);
        }
    }

    fn drawn(&self) -> std::sync::MutexGuard<'_, Drawn> {
        self.0
            .drawn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The one way to say an agent is done with the computer: its badge comes
    /// off the screen now instead of idling out. Every end signal (route
    /// closed, computer call cancelled, the session's turn ended) comes here.
    /// A later action by the same agent draws a fresh badge.
    pub fn end(&self, agent: &str) {
        if self.0.sender.get().is_none() {
            return;
        }
        let mut drawn = self.drawn();
        if drawn.ended_at.len() >= RECORD_CAP && !drawn.ended_at.contains_key(agent) {
            // Each entry only matters for the few milliseconds a geometry read
            // can still be running, so forgetting old ones loses nothing real.
            drawn.ended_at.clear();
        }
        drawn.ended_at.insert(
            agent.to_owned(),
            self.0.serial.load(std::sync::atomic::Ordering::SeqCst),
        );
        // Sent while holding the record, so a picture whose read finishes now
        // either goes out before this hide or sees the end and is dropped.
        self.send_line(CursorLine::Hide(CursorHide::new(agent)));
        drop(drawn);
        // The badge is gone, so its window needs no watching.
        self.follows().remove(agent);
    }

    fn follows(&self) -> std::sync::MutexGuard<'_, HashMap<String, Follow>> {
        self.0
            .follows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// After a picture was sent: watch the window it points into, so the
    /// badge can follow the element when that window moves.
    ///
    /// A picture with a target replaces the agent's watch, since the badge
    /// now rests somewhere else. A resting read leaves the badge where it
    /// was, in the window already watched, so that watch stays and only
    /// counts from this event from now on; with no watch yet, the badge has
    /// just appeared over the application's focused window, which is watched.
    ///
    /// Runs on a blocking thread: it reads the window and its frame through
    /// the accessibility API, after the picture has gone out, so it never
    /// delays the picture or the action.
    fn follow(
        &self,
        event: &CursorEvent,
        grant: &ProcessGrant,
        source: &Arc<dyn AppStateSource>,
        element: Option<ElementHandle>,
    ) {
        let agent = &event.agent;
        if event.resting {
            let current = self
                .follows()
                .get(agent)
                .map(|follow| (follow.id, follow.source.clone(), follow.window.clone()));
            if let Some((id, source, window)) = current {
                // Count from now: the helper restarts its follow offset at
                // every picture event.
                let base_window = source.cursor_frame(&window);
                let mut follows = self.follows();
                if let Some(follow) = follows.get_mut(agent).filter(|follow| follow.id == id) {
                    match base_window {
                        Some(base_window) if follow.serial < event.serial => {
                            follow.serial = event.serial;
                            follow.base_window = base_window;
                            follow.base_element =
                                follow.element.as_ref().and_then(|e| source.cursor_frame(e));
                        }
                        Some(_) => {}
                        // The window can no longer be read: stop following.
                        None => {
                            follows.remove(agent);
                        }
                    }
                }
                return;
            }
        }
        let Some(window) = source.cursor_window(grant, element.as_ref()) else {
            // Nothing to follow, so an older watch must not move the badge
            // away from its new target either.
            self.drop_older_follow(agent, event.serial);
            return;
        };
        let Some(base_window) = source.cursor_frame(&window) else {
            self.drop_older_follow(agent, event.serial);
            return;
        };
        let id = self
            .0
            .follow_ids
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let state = Arc::downgrade(&self.0);
        let followed = agent.clone();
        let Some(watch) = source.watch_cursor_window(
            &window,
            Box::new(move |change| {
                if let Some(state) = state.upgrade() {
                    Coordinator(state).window_changed(&followed, id, change);
                }
            }),
        ) else {
            self.drop_older_follow(agent, event.serial);
            return;
        };
        let follow = Follow {
            id,
            serial: event.serial,
            source: source.clone(),
            window,
            element,
            base_window,
            // The frame the picture itself was drawn from, read with it.
            base_element: event.target,
            _watch: watch,
        };
        // Checked and inserted under the record's lock, the same lock `end`
        // records an end under before it removes the watch: an end either
        // comes first and is seen here, or comes after and removes this.
        let drawn = self.drawn();
        if drawn
            .ended_at
            .get(agent)
            .is_some_and(|ended| event.serial < *ended)
        {
            return;
        }
        let mut follows = self.follows();
        if follows
            .get(agent)
            .is_some_and(|newer| newer.serial > event.serial)
        {
            // A later picture's watch is already in place.
            return;
        }
        if follows.len() >= FOLLOW_CAP && !follows.contains_key(agent) {
            // Bounded: the badge whose watch goes keeps its place and simply
            // stops following its window.
            if let Some(oldest) = follows
                .iter()
                .min_by_key(|(_, follow)| follow.serial)
                .map(|(agent, _)| agent.clone())
            {
                follows.remove(&oldest);
            }
        }
        follows.insert(agent.clone(), follow);
    }

    fn drop_older_follow(&self, agent: &str, serial: u64) {
        let mut follows = self.follows();
        if follows.get(agent).is_some_and(|old| old.serial < serial) {
            follows.remove(agent);
        }
    }

    /// A watched window moved, was resized or went away. Called on the
    /// platform's watching thread.
    fn window_changed(&self, agent: &str, id: u64, change: WindowChange) {
        let current = {
            let mut follows = self.follows();
            let Some(follow) = follows.get(agent).filter(|follow| follow.id == id) else {
                // A watch already replaced or removed; its report is stale.
                return;
            };
            if change == WindowChange::Gone {
                // Nothing left to follow; the badge stays where it last was.
                follows.remove(agent);
                return;
            }
            (
                follow.serial,
                follow.source.clone(),
                follow.window.clone(),
                follow.element.clone(),
                follow.base_window,
                follow.base_element,
            )
        };
        let (serial, source, window, element, base_window, base_element) = current;
        // Read without holding the record: these are messages to another
        // application, which may be slow to answer.
        let Some(now_window) = source.cursor_frame(&window) else {
            return;
        };
        let now_element = match (change, &element) {
            (WindowChange::Resized, Some(element)) => source.cursor_frame(element),
            _ => None,
        };
        let Some(offset) =
            follow_offset(change, base_window, now_window, base_element, now_element)
        else {
            return;
        };
        let follows = self.follows();
        // Sent only if the badge still rests on the same event, so a report
        // computed against an older event never moves a newer picture.
        if follows
            .get(agent)
            .is_some_and(|follow| follow.id == id && follow.serial == serial)
        {
            self.send_line(CursorLine::Follow(CursorFollow {
                agent: agent.to_owned(),
                serial,
                offset,
            }));
        }
    }

    /// A route closed: end every badge it drew.
    pub(crate) fn end_route(&self, channel: u16, epoch: u32) {
        let agents = self.drawn().routes.remove(&(channel, epoch));
        for agent in agents.into_iter().flatten() {
            self.end(&agent);
        }
    }

    /// A head session's turn ended: end every badge that session's calls drew.
    /// This is the single internal entry for that signal, whatever delivers it
    /// (today a management call from Prefrontal core; later the harness's
    /// turn-ended event), so changing the source never touches the mapping.
    ///
    /// Badges are matched on the daemon-stamped `scope_ref`, the only session
    /// name a computer call carries. `session_ref` is the harness runner's own
    /// ref; nothing records it against badges yet, so a source that knows only
    /// that ref ends nothing until such a record exists. It is in the signature
    /// so that source can be wired without changing every caller.
    ///
    /// An unknown session is not an error; it simply drew nothing that is
    /// still recorded. Every outcome ends the badge the same way: a turn that
    /// stopped or failed is just as finished with the computer as one that
    /// completed, so `outcome` is carried for the record only.
    pub(crate) fn turn_ended(
        &self,
        session_ref: &str,
        scope_ref: Option<&str>,
        outcome: TurnOutcome,
    ) -> bool {
        let _ = (session_ref, outcome);
        let Some(scope_ref) = scope_ref else {
            return false;
        };
        let agents: BTreeSet<String> = self
            .drawn()
            .sessions
            .iter()
            .filter(|(session, _)| session.scope_ref == scope_ref)
            .map(|(_, agent)| agent.clone())
            .collect();
        let matched = !agents.is_empty();
        for agent in agents {
            self.end(&agent);
        }
        matched
    }

    /// Remember who is drawing this badge, before any read starts, so an end
    /// that arrives while the read is still running still finds it.
    fn record(&self, identity: &Identity) {
        let agent = &identity.badge;
        if let Some(call) = &identity.call {
            call.note_cursor_agent(agent);
        }
        let mut drawn = self.drawn();
        if let Some(call) = &identity.call {
            drawn
                .routes
                .entry(call.route())
                .or_default()
                .insert(agent.clone());
        }
        if let Some(session) = &identity.session {
            // One record per (ref, agent): a revival's new epoch replaces the
            // old one rather than adding a second record for the same badge.
            drawn.sessions.retain(|(recorded, recorded_agent)| {
                recorded.scope_ref != session.scope_ref || recorded_agent != agent
            });
            if drawn.sessions.len() >= RECORD_CAP {
                drawn.sessions.pop_front();
            }
            drawn.sessions.push_back((session.clone(), agent.clone()));
        }
    }

    /// Send a scheduled picture unless its agent was ended after it was
    /// scheduled.
    fn send_unless_ended(&self, event: CursorEvent) {
        let drawn = self.drawn();
        if drawn
            .ended_at
            .get(&event.agent)
            .is_some_and(|ended| event.serial < *ended)
        {
            return;
        }
        self.send(event);
    }

    /// The whole optional read has a deadline. A slow AX reply may still finish
    /// on its blocking thread, but it can never emit a late picture or hold an
    /// action. Do not change a retained AX element's timeout: dispatch shares it.
    pub(crate) fn schedule(
        &self,
        identity: Identity,
        kind: CursorKind,
        grant: ProcessGrant,
        source: Arc<dyn AppStateSource>,
        handle: Option<ElementHandle>,
        point: Option<[f64; 2]>,
    ) {
        if self.0.sender.get().is_none()
            || self.0.stopped.load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        let cursor = self.clone();
        // Numbered before it is recorded: an end that lands in between then
        // counts this picture as scheduled before it, and drops it.
        let serial = self
            .0
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        cursor.record(&identity);
        let follow_with = (grant.clone(), source.clone(), handle.clone());
        tokio::spawn(async move {
            let agent = identity.badge;
            #[cfg(not(target_os = "macos"))]
            let _ = identity.avatar_agent;
            let read = tokio::task::spawn_blocking(move || {
                let (title, secure, frame) = match handle {
                    Some(handle) => {
                        // A read's picture has no label, so it reads no title.
                        let (title, secure) = if kind == CursorKind::Reading {
                            (None, false)
                        } else {
                            source.cursor_label(&handle).unwrap_or((None, true))
                        };
                        let frame = source.cursor_frame(&handle);
                        (title, secure, frame)
                    }
                    None => (None, false, None),
                };
                // Element actions without an exact point aim at the frame's
                // visible centre, never its origin. Only reads may appear with
                // nothing to aim at; a press or a write with no geometry shows
                // no picture rather than a misleading one.
                if point.is_none()
                    && frame.is_none()
                    && matches!(kind, CursorKind::Press | CursorKind::Write)
                {
                    return None;
                }
                let to = source.visible_cursor_point(&grant, point, frame)?;
                Some(CursorEvent {
                    initial: agent.chars().next().unwrap_or('A').to_ascii_uppercase(),
                    agent,
                    to,
                    target: frame,
                    resting: point.is_none() && frame.is_none(),
                    label: label(kind, title.as_deref(), secure),
                    kind,
                    serial,
                    avatar_rgba: None,
                    avatar_update: false,
                })
            });
            if let Ok(Ok(Some(event))) = tokio::time::timeout(READ_BUDGET, read).await {
                cursor.send_unless_ended(event.clone());
                // Off the read's deadline: following the window is a nicety
                // that must never hold up or drop the picture itself.
                let follower = cursor.clone();
                let followed = event.clone();
                let (grant, source, handle) = follow_with;
                let _ = tokio::task::spawn_blocking(move || {
                    follower.follow(&followed, &grant, &source, handle)
                })
                .await;
                #[cfg(target_os = "macos")]
                if let (Some(agent), Some(avatars)) =
                    (identity.avatar_agent, cursor.0.avatars.get())
                {
                    if let Some(pixels) = avatars.fetch_and_render(&agent).await {
                        let mut update = event;
                        update.avatar_rgba = Some(pixels);
                        update.avatar_update = true;
                        cursor.send(update);
                    }
                }
            }
        });
    }

    /// Signal before browser teardown starts. Reaping and any blocked pipe write
    /// belong to the transport thread, never to the twenty-second drain budget.
    pub fn shutdown(&self) {
        self.0
            .stopped
            .store(true, std::sync::atomic::Ordering::Release);
        self.follows().clear();
        #[cfg(target_os = "macos")]
        if let Some(generation) = *self
            .0
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            let _ = cerebellum_macos::terminate_exact_generation(generation);
        }
        if let Some(sender) = self.0.sender.get() {
            // Wake an idle transport so it can reap its child. A full channel
            // already guarantees a wake; the stopped flag prevents any drawing.
            let _ = sender.try_send(CursorLine::Picture(CursorEvent {
                agent: String::new(),
                initial: 'A',
                to: [0.0, 0.0],
                target: None,
                resting: true,
                label: None,
                kind: CursorKind::Reading,
                serial: 0,
                avatar_rgba: None,
                avatar_update: false,
            }));
        }
    }
}

impl Identity {
    /// An identity as a computer call would capture it, for tests of the end
    /// signals that do not drive a whole computer call.
    #[cfg(test)]
    pub(crate) fn for_test(
        badge: &str,
        call: Option<Arc<TerminalArbiter>>,
        session: Option<SessionScope>,
    ) -> Self {
        Self {
            badge: badge.to_owned(),
            avatar_agent: None,
            call,
            session,
        }
    }
}

impl Coordinator {
    /// Record a badge as `schedule` does, without reading any geometry.
    #[cfg(test)]
    pub(crate) fn draw_for_test(&self, identity: &Identity) {
        self.record(identity);
    }
}

#[cfg(target_os = "macos")]
fn transport(state: Arc<State>, mut rx: mpsc::Receiver<CursorLine>) {
    use std::io::Write;
    let mut helper: Option<(cerebellum_macos::ReleasedChild, std::fs::File)> = None;
    let mut restarts = RestartLimit::default();
    while let Some(event) = rx.blocking_recv() {
        if state.stopped.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        // A locked or unreadable screen never launches or displays the helper.
        if cerebellum_macos::screen_is_locked() != Some(false) {
            continue;
        }
        if helper.is_none() {
            // No helper means no badge on screen, so there is nothing to hide
            // or move; never launch a helper just for that.
            if matches!(event, CursorLine::Hide(_) | CursorLine::Follow(_)) {
                continue;
            }
            if !restarts.admit(Instant::now()) {
                continue;
            }
            let launched = (|| {
                let executable = std::env::current_exe().ok()?;
                let (barred, pipe) =
                    cerebellum_macos::spawn_barred_stdin(&executable, &["--agent-cursor".into()])
                        .ok()?;
                let mut generation = state
                    .generation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.stopped.load(std::sync::atomic::Ordering::Acquire) {
                    return None;
                }
                *generation = Some(barred.generation());
                cerebellum_macos::register_cursor_generation(*generation);
                drop(generation);
                let child = barred.release().ok()?;
                Some((child, std::fs::File::from(pipe)))
            })();
            helper = launched;
        }
        let Some(line) = event.encode_line() else {
            continue;
        };
        if helper
            .as_mut()
            .is_some_and(|(_, pipe)| pipe.write_all(&line).is_err())
        {
            helper.take();
            cerebellum_macos::register_cursor_generation(None);
            *state
                .generation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }
    drop(helper);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Geometry that takes the given time to read.
    struct SlowGeometry(Duration);
    impl AppStateSource for SlowGeometry {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: cerebellum_computer::app_state::source::ReadBounds,
        ) -> Result<
            cerebellum_computer::app_state::source::RawAppState,
            cerebellum_computer::app_state::source::AppStateReadError,
        > {
            Err(cerebellum_computer::app_state::source::AppStateReadError::Unreadable)
        }
        fn cursor_label(&self, _: &ElementHandle) -> Option<(Option<String>, bool)> {
            Some((Some("Send".into()), false))
        }
        fn cursor_frame(&self, _: &ElementHandle) -> Option<[f64; 4]> {
            std::thread::sleep(self.0);
            Some([0.0, 0.0, 10.0, 10.0])
        }
        fn visible_cursor_point(
            &self,
            _: &ProcessGrant,
            p: Option<[f64; 2]>,
            _: Option<[f64; 4]>,
        ) -> Option<[f64; 2]> {
            p
        }
    }

    #[tokio::test]
    async fn cursor_geometry_deadline_discards_late_reads_without_blocking_actions() {
        let (cursor, mut receiver) = Coordinator::channel();
        let grant = ProcessGrant {
            bundle_identity: "test.app".into(),
            pid: 7,
            process_generation_evidence: "generation".into(),
        };
        let start = Instant::now();
        cursor.schedule(
            Identity::current("agent".into()),
            CursorKind::Press,
            grant,
            Arc::new(SlowGeometry(Duration::from_millis(150))),
            Some(cerebellum_computer::app_state::source::RawElement::fixture(1, "AXButton").handle),
            None,
        );
        assert!(
            start.elapsed() < READ_BUDGET,
            "scheduling must not read geometry inline"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(250), receiver.recv())
                .await
                .is_err(),
            "late geometry must not reach the helper"
        );
    }

    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    fn grant() -> ProcessGrant {
        ProcessGrant {
            bundle_identity: "test.app".into(),
            pid: 7,
            process_generation_evidence: "generation".into(),
        }
    }

    fn hidden(line: CursorLine) -> String {
        match line {
            CursorLine::Hide(hide) => hide.agent,
            CursorLine::Picture(event) => {
                panic!("expected a hide, got a picture for {}", event.agent)
            }
            CursorLine::Follow(follow) => {
                panic!("expected a hide, got a follow for {}", follow.agent)
            }
        }
    }

    fn head(scope_ref: &str, epoch: u64) -> Option<SessionScope> {
        Some(SessionScope {
            scope_ref: scope_ref.into(),
            epoch,
        })
    }

    #[test]
    fn end_hides_only_the_named_agent_and_needs_a_transport() {
        // A disabled cursor has nowhere to send a hide, and must not panic.
        Coordinator::default().end("agent-a");
        let (cursor, mut receiver) = Coordinator::channel();
        cursor.end("agent-a");
        assert_eq!(hidden(receiver.try_recv().unwrap()), "agent-a");
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn turn_ended_matches_the_scope_ref_whatever_its_epoch() {
        let (cursor, mut receiver) = Coordinator::channel();
        cursor.draw_for_test(&Identity::for_test("agent-a", None, head("head-a", 1)));
        cursor.draw_for_test(&Identity::for_test("agent-b", None, head("head-b", 1)));
        // The same session revived: same ref, new epoch, same badge.
        cursor.draw_for_test(&Identity::for_test("agent-a", None, head("head-a", 2)));
        cursor.turn_ended(SESSION, Some("unknown"), TurnOutcome::Completed);
        assert!(
            receiver.try_recv().is_err(),
            "an unknown session ends nothing"
        );
        cursor.turn_ended(SESSION, None, TurnOutcome::Completed);
        assert!(
            receiver.try_recv().is_err(),
            "no scope, nothing to match yet"
        );
        cursor.turn_ended(SESSION, Some("head-a"), TurnOutcome::Stopped);
        assert_eq!(hidden(receiver.try_recv().unwrap()), "agent-a");
        assert!(
            receiver.try_recv().is_err(),
            "agent-b's session did not end"
        );
    }

    #[tokio::test]
    async fn a_picture_scheduled_before_an_end_does_not_bring_the_badge_back() {
        let (cursor, mut receiver) = Coordinator::channel();
        let schedule = || {
            cursor.schedule(
                Identity::for_test("agent-a", None, None),
                CursorKind::Press,
                grant(),
                // Well inside the read budget, so the picture would be sent.
                Arc::new(SlowGeometry(Duration::from_millis(20))),
                Some(
                    cerebellum_computer::app_state::source::RawElement::fixture(1, "AXButton")
                        .handle,
                ),
                // The fixture shows a picture only where it is told to aim.
                Some([1.0, 1.0]),
            )
        };
        schedule();
        cursor.end("agent-a");
        let hide = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("end sends a hide at once")
            .unwrap();
        assert_eq!(hidden(hide), "agent-a");
        assert!(
            tokio::time::timeout(Duration::from_millis(150), receiver.recv())
                .await
                .is_err(),
            "the read that finished after the end must not redraw the badge"
        );
        schedule();
        let picture = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .picture()
            .expect("an action after the end draws the badge again");
        assert_eq!(picture.agent, "agent-a");
    }

    const AGENT: &str = "agent-a";

    /// A watch's report callback, as the fake platform keeps it.
    type Report = Arc<dyn Fn(WindowChange) + Send + Sync>;

    /// A fake platform: one window holding one element, whose frames each
    /// test sets directly. Every window watch it hands out keeps its report
    /// callback, and a test calls that callback itself to stand in for the
    /// platform's observer reporting a move, a resize or a closed window.
    struct FollowGeometry {
        window: ElementHandle,
        window_frame: std::sync::Mutex<[f64; 4]>,
        element_frame: std::sync::Mutex<[f64; 4]>,
        /// Every watch's report callback, in the order they were created.
        watches: std::sync::Mutex<Vec<Report>>,
        live: Arc<std::sync::atomic::AtomicUsize>,
    }

    struct FakeWatch(Arc<std::sync::atomic::AtomicUsize>);
    impl CursorWindowWatch for FakeWatch {}
    impl Drop for FakeWatch {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl FollowGeometry {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                window: cerebellum_computer::app_state::source::RawElement::fixture(
                    100, "AXWindow",
                )
                .handle,
                window_frame: std::sync::Mutex::new([100.0, 80.0, 800.0, 600.0]),
                element_frame: std::sync::Mutex::new([400.0, 120.0, 90.0, 22.0]),
                watches: std::sync::Mutex::new(Vec::new()),
                live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            })
        }

        fn live(&self) -> usize {
            self.live.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn created(&self) -> usize {
            self.watches.lock().unwrap().len()
        }

        /// What the platform's observer does when the window changes.
        fn fire(&self, watch: usize, change: WindowChange) {
            let report = self.watches.lock().unwrap()[watch].clone();
            report(change);
        }

        fn shift(frame: &std::sync::Mutex<[f64; 4]>, by: [f64; 4]) {
            let mut frame = frame.lock().unwrap();
            for (value, by) in frame.iter_mut().zip(by) {
                *value += by;
            }
        }
    }

    impl AppStateSource for FollowGeometry {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: cerebellum_computer::app_state::source::ReadBounds,
        ) -> Result<
            cerebellum_computer::app_state::source::RawAppState,
            cerebellum_computer::app_state::source::AppStateReadError,
        > {
            Err(cerebellum_computer::app_state::source::AppStateReadError::Unreadable)
        }
        fn cursor_label(&self, _: &ElementHandle) -> Option<(Option<String>, bool)> {
            Some((Some("Date Added".into()), false))
        }
        fn cursor_frame(&self, element: &ElementHandle) -> Option<[f64; 4]> {
            Some(if element.same_element(self.window.as_ref()) {
                *self.window_frame.lock().unwrap()
            } else {
                *self.element_frame.lock().unwrap()
            })
        }
        fn visible_cursor_point(
            &self,
            _: &ProcessGrant,
            point: Option<[f64; 2]>,
            frame: Option<[f64; 4]>,
        ) -> Option<[f64; 2]> {
            // No point and no frame: the window's middle.
            Some(point.unwrap_or(match frame {
                Some([x, y, w, h]) => [x + w / 2.0, y + h / 2.0],
                None => [500.0, 380.0],
            }))
        }
        fn cursor_window(
            &self,
            _: &ProcessGrant,
            _: Option<&ElementHandle>,
        ) -> Option<ElementHandle> {
            Some(self.window.clone())
        }
        fn watch_cursor_window(
            &self,
            _: &ElementHandle,
            changed: Box<dyn Fn(WindowChange) + Send + Sync>,
        ) -> Option<Box<dyn CursorWindowWatch>> {
            self.watches.lock().unwrap().push(Arc::from(changed));
            self.live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(Box::new(FakeWatch(self.live.clone())))
        }
    }

    fn schedule_on(cursor: &Coordinator, geometry: &Arc<FollowGeometry>, kind: CursorKind) {
        let element = (kind != CursorKind::Reading).then(|| {
            cerebellum_computer::app_state::source::RawElement::fixture(2, "AXButton").handle
        });
        cursor.schedule(
            Identity::for_test(AGENT, None, None),
            kind,
            grant(),
            geometry.clone(),
            element,
            None,
        );
    }

    async fn next_line(receiver: &mut mpsc::Receiver<CursorLine>) -> CursorLine {
        tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("a line within a second")
            .unwrap()
    }

    async fn no_line(receiver: &mut mpsc::Receiver<CursorLine>, why: &str) {
        if let Ok(Some(line)) =
            tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await
        {
            panic!("{why}: got {line:?}");
        }
    }

    /// Wait for the follow-up a picture schedules after it has gone out, such
    /// as installing its window watch.
    async fn until(what: &str, done: impl Fn() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(start.elapsed() < Duration::from_secs(1), "never {what}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn a_window_move_moves_the_badge_with_its_element() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = FollowGeometry::new();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        let picture = next_line(&mut receiver).await.picture().unwrap();
        assert_eq!(picture.to, [445.0, 131.0], "the element's centre");
        until("watched the window", || geometry.live() == 1).await;

        // The person drags the window 120 right and 40 up.
        FollowGeometry::shift(&geometry.window_frame, [120.0, -40.0, 0.0, 0.0]);
        geometry.fire(0, WindowChange::Moved);
        assert_eq!(
            next_line(&mut receiver).await,
            CursorLine::Follow(CursorFollow {
                agent: AGENT.into(),
                serial: picture.serial,
                offset: [120.0, -40.0],
            })
        );

        // Then widens it from the left edge: the element is laid out again
        // and is now 90 right and 40 up of where the picture was drawn.
        FollowGeometry::shift(&geometry.window_frame, [-60.0, 0.0, 60.0, 0.0]);
        FollowGeometry::shift(&geometry.element_frame, [90.0, -40.0, 0.0, 0.0]);
        geometry.fire(0, WindowChange::Resized);
        assert_eq!(
            next_line(&mut receiver).await,
            CursorLine::Follow(CursorFollow {
                agent: AGENT.into(),
                serial: picture.serial,
                offset: [90.0, -40.0],
            })
        );

        // The window closes: nothing is sent, so the badge stays where it
        // last was, and the watch is released.
        geometry.fire(0, WindowChange::Gone);
        no_line(&mut receiver, "a closed window moved the badge").await;
        assert_eq!(geometry.live(), 0, "the closed window's watch was kept");
        geometry.fire(0, WindowChange::Moved);
        no_line(&mut receiver, "a released watch still reported").await;
    }

    #[tokio::test]
    async fn the_window_watch_is_removed_on_hide_and_replaced_on_a_new_target() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = FollowGeometry::new();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        let first = next_line(&mut receiver).await.picture().unwrap();
        until("watched the window", || geometry.live() == 1).await;

        // The window was moved before the read; a resting read leaves the
        // badge where it is, so the same watch stays and from now on counts
        // from the read's event and the window's place at that read.
        FollowGeometry::shift(&geometry.window_frame, [10.0, 0.0, 0.0, 0.0]);
        schedule_on(&cursor, &geometry, CursorKind::Reading);
        let read = next_line(&mut receiver).await.picture().unwrap();
        assert!(read.resting && read.serial > first.serial);
        until("re-keyed the watch", || {
            cursor.follows().get(AGENT).is_some_and(|follow| {
                follow.serial == read.serial && follow.base_window == [110.0, 80.0, 800.0, 600.0]
            })
        })
        .await;
        assert_eq!((geometry.created(), geometry.live()), (1, 1));

        // A new target: one watch, the new one; the old one's late report
        // goes nowhere.
        schedule_on(&cursor, &geometry, CursorKind::Press);
        next_line(&mut receiver).await.picture().unwrap();
        until("replaced the watch", || {
            geometry.created() == 2 && geometry.live() == 1
        })
        .await;
        FollowGeometry::shift(&geometry.window_frame, [5.0, 5.0, 0.0, 0.0]);
        geometry.fire(0, WindowChange::Moved);
        no_line(&mut receiver, "the replaced watch moved the badge").await;

        // The turn ends: the badge hides and its window is no longer watched.
        cursor.end(AGENT);
        assert_eq!(hidden(next_line(&mut receiver).await), AGENT);
        assert_eq!(geometry.live(), 0, "the hidden badge's watch was kept");
        geometry.fire(1, WindowChange::Moved);
        no_line(&mut receiver, "a hidden badge was moved").await;
    }

    #[test]
    fn cursor_restart_limit_is_one_after_a_minute() {
        let start = Instant::now();
        let mut limit = RestartLimit::default();
        assert!(limit.admit(start));
        assert!(!limit.admit(start + Duration::from_secs(59)));
        assert!(limit.admit(start + Duration::from_secs(60)));
        assert!(!limit.admit(start + Duration::from_secs(120)));
    }

    #[test]
    fn cursor_send_never_waits_on_a_full_pipe() {
        let (cursor, _receiver) = Coordinator::channel();
        let event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 1.0],
            target: None,
            resting: false,
            label: None,
            kind: CursorKind::Press,
            serial: 0,
            avatar_rgba: None,
            avatar_update: false,
        };
        for _ in 0..CAPACITY {
            cursor.send(event.clone());
        }
        // On a separate thread so an accidentally blocking send fails by timeout
        // rather than wedging the test executor.
        let (done, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            cursor.send(event);
            let _ = done.send(());
        });
        assert!(
            received.recv_timeout(Duration::from_millis(100)).is_ok(),
            "cursor send awaited a full channel"
        );
    }
}
