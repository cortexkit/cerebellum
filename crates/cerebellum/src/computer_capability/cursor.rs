//! A lossy, memory-only picture alongside an admitted action. Nothing here
//! returns an action outcome or receives a request body.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
#[cfg(any(target_os = "macos", test))]
use std::time::Instant;

use cerebellum_computer::app_state::source::{AppStateSource, CursorWindowWatch, ElementHandle};
use cerebellum_computer::cursor::{
    follow_offset, label, CursorEvent, CursorFollow, CursorHide, CursorKind, CursorLine,
    PictureMotion, WindowChange, IDLE_FADE_AFTER_MS, IDLE_FADE_MS, LONGEST_ARRIVAL_MS,
};
use cerebellum_computer::platform::ProcessGrant;
use tokio::sync::{mpsc, oneshot};

use crate::terminal_arbiter::TerminalArbiter;

const READ_BUDGET: Duration = Duration::from_millis(50);
/// The longest an action waits for its badge before it is sent: the badge's
/// geometry read, then the longest animation the helper plays before the
/// badge is on its target (a first appearance's entry; a glide is shorter).
/// The action waits so that the real click and the badge's tap happen
/// together. The call's work budget counts this as
/// `budgets::CURSOR_ARRIVAL_MS`.
pub(crate) const ARRIVAL_CAP: Duration =
    Duration::from_millis(READ_BUDGET.as_millis() as u64 + LONGEST_ARRIVAL_MS as u64);
/// How often a waiting action looks again at what can only be read, not
/// awaited: the call's dispatch gate and whether the badge was ended.
const ARRIVAL_POLL: Duration = Duration::from_millis(10);
/// Reduce Motion is read again at most this often, and only when a picture
/// is scheduled: a change the person makes shows within about this long.
const REDUCE_MOTION_REFRESH: Duration = Duration::from_secs(30);
/// The thread that reads Reduce Motion, named so a test can tell its reads
/// from any made on the picture path.
pub(crate) const REDUCE_MOTION_THREAD: &str = "agent-cursor-reduce-motion";

/// Reads the system's Reduce Motion setting. May be slow: the first read in
/// this process loads AppKit, which has taken hundreds of milliseconds.
type ReduceMotionReader = Arc<dyn Fn() -> bool + Send + Sync>;

/// The Reduce Motion setting as last read, off the picture path. A picture
/// only ever takes the value already here; it never waits for a read.
#[derive(Default)]
struct ReduceMotionCache {
    /// 0 until the first read finishes (the full animation is assumed), then
    /// 1 for off and 2 for on.
    value: std::sync::atomic::AtomicU8,
    /// When the latest read was started.
    started: std::sync::Mutex<Option<tokio::time::Instant>>,
    /// The platform's reader unless a test supplied one.
    reader: OnceLock<ReduceMotionReader>,
}
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
    /// Where each agent's badge was last sent, so the next picture's glide
    /// length, and so the moment it arrives, can be worked out here.
    tips: HashMap<String, Tip>,
}

/// One agent's badge as the module last sent it to the helper.
struct Tip {
    /// The picture event it was sent for.
    serial: u64,
    /// Where its tip was sent.
    to: [f64; 2],
    /// How far the window under it has moved since, as last reported to the
    /// helper, which moves the badge by as much.
    offset: [f64; 2],
    /// When that event was sent: the helper's idle fade counts from it.
    sent: tokio::time::Instant,
}

impl Tip {
    fn place(&self) -> [f64; 2] {
        [self.to[0] + self.offset[0], self.to[1] + self.offset[1]]
    }
}

impl Drawn {
    /// Choose the motion for a picture about to be sent to the helper, and
    /// the record of where its badge will then be. Nothing is recorded yet:
    /// `keep` does that once the picture is really on its way.
    ///
    /// A badge the module has not seen drawn (never drawn, ended, or faded
    /// out after the idle timeout) appears with its entry animation; one
    /// already on screen glides from where it was last sent. A read with
    /// nothing to aim at leaves a shown badge where it is. The helper follows
    /// the chosen motion from wherever its badge really is, so even where
    /// this record is out of date the badge arrives when the motion says.
    fn aim(
        &self,
        event: &CursorEvent,
        now: tokio::time::Instant,
        reduce_motion: bool,
    ) -> (PictureMotion, Tip) {
        let gone_after = Duration::from_millis(IDLE_FADE_AFTER_MS + IDLE_FADE_MS);
        let shown = self
            .tips
            .get(&event.agent)
            .filter(|tip| now.saturating_duration_since(tip.sent) < gone_after)
            .map(Tip::place);
        let to = match (event.resting, shown) {
            (true, Some(resting)) => resting,
            _ => event.to,
        };
        let distance = shown.map_or(0.0, |from| (to[0] - from[0]).hypot(to[1] - from[1]));
        (
            PictureMotion::chosen(distance, shown.is_none(), reduce_motion),
            Tip {
                serial: event.serial,
                to,
                offset: [0.0, 0.0],
                sent: now,
            },
        )
    }

    /// Record where an agent's badge was just sent.
    fn keep(&mut self, agent: &str, tip: Tip) {
        if self.tips.len() >= RECORD_CAP && !self.tips.contains_key(agent) {
            // Bounded like the other records: the oldest goes, and its agent's
            // next picture is simply taken for a first appearance.
            if let Some(oldest) = self
                .tips
                .iter()
                .min_by_key(|(_, tip)| tip.sent)
                .map(|(agent, _)| agent.clone())
            {
                self.tips.remove(&oldest);
            }
        }
        self.tips.insert(agent.to_owned(), tip);
    }
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
    /// The helper could not be started and will not be retried, so nothing
    /// sent to it is drawn and no action waits for a badge.
    helper_down: std::sync::atomic::AtomicBool,
    reduce_motion: ReduceMotionCache,
    /// Stands in for the system's Reduce Motion setting in tests.
    #[cfg(test)]
    reduce_motion_for_test: std::sync::Mutex<Option<bool>>,
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

/// Preferred element for a read picture and the focused element to use when
/// the preferred element has no readable frame.
pub(crate) struct ReadAim {
    pub(crate) preferred: Option<ElementHandle>,
    pub(crate) focused: Option<ElementHandle>,
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
                // Read now, in the background, so the first picture already
                // has the person's setting.
                self.refresh_reduce_motion();
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

    /// Whether the line was put on the pipe to the helper.
    fn send_line(&self, line: CursorLine) -> bool {
        if self.0.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        self.0
            .sender
            .get()
            .is_some_and(|sender| sender.try_send(line).is_ok())
    }

    /// The system's Reduce Motion setting as last read, without reading it.
    /// Until a first read has finished, the full animation. The picture line
    /// carries whichever value is used, so the helper always agrees.
    fn reduce_motion(&self) -> bool {
        #[cfg(test)]
        if let Some(reduce) = *self
            .0
            .reduce_motion_for_test
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return reduce;
        }
        self.0
            .reduce_motion
            .value
            .load(std::sync::atomic::Ordering::Acquire)
            == 2
    }

    /// Start a read of Reduce Motion on a thread of its own, unless one was
    /// started less than `REDUCE_MOTION_REFRESH` ago. Never waits for it.
    fn refresh_reduce_motion(&self) {
        let cache = &self.0.reduce_motion;
        let now = tokio::time::Instant::now();
        {
            let mut started = cache
                .started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if started.is_some_and(|at| now.saturating_duration_since(at) < REDUCE_MOTION_REFRESH) {
                return;
            }
            *started = Some(now);
        }
        let reader = cache.reader.get_or_init(platform_reduce_motion).clone();
        let state = Arc::downgrade(&self.0);
        let _ = std::thread::Builder::new()
            .name(REDUCE_MOTION_THREAD.into())
            .spawn(move || {
                let on = reader();
                if let Some(state) = state.upgrade() {
                    state
                        .reduce_motion
                        .value
                        .store(if on { 2 } else { 1 }, std::sync::atomic::Ordering::Release);
                }
            });
    }

    /// Read Reduce Motion with this reader instead of the platform's.
    #[cfg(test)]
    fn with_reduce_motion_reader(&self, reader: impl Fn() -> bool + Send + Sync + 'static) {
        let _ = self.0.reduce_motion.reader.set(Arc::new(reader));
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
        // The helper takes the badge off the screen, so the agent's next
        // picture is a new appearance.
        drawn.tips.remove(agent);
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
        let moved = follows
            .get(agent)
            .is_some_and(|follow| follow.id == id && follow.serial == serial)
            && self.send_line(CursorLine::Follow(CursorFollow {
                agent: agent.to_owned(),
                serial,
                offset,
            }));
        // Released first: the record's lock is always taken before this one.
        drop(follows);
        if moved {
            // The helper moves the badge with the window, so the next glide
            // starts from there.
            if let Some(tip) = self
                .drawn()
                .tips
                .get_mut(agent)
                .filter(|tip| tip.serial == serial)
            {
                tip.offset = offset;
            }
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
    /// scheduled. Answers when the badge will be on its target, or `None`
    /// when nothing will be drawn.
    fn send_unless_ended(&self, mut event: CursorEvent) -> Option<tokio::time::Instant> {
        let mut drawn = self.drawn();
        if drawn
            .ended_at
            .get(&event.agent)
            .is_some_and(|ended| event.serial < *ended)
        {
            return None;
        }
        let now = tokio::time::Instant::now();
        let (motion, tip) = drawn.aim(&event, now, self.reduce_motion());
        // The line carries the motion, so the helper animates exactly what
        // this wait is timed by.
        event.motion = motion;
        let (agent, resting) = (event.agent.clone(), event.resting);
        if !self.send_line(CursorLine::Picture(event)) {
            return None;
        }
        drawn.keep(&agent, tip);
        // A badge that only rests somewhere aims at nothing an action waits
        // for.
        let waits = !resting
            && !self
                .0
                .helper_down
                .load(std::sync::atomic::Ordering::Acquire);
        waits.then(|| now + Duration::from_secs_f64(motion.duration_ms / 1000.0))
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
    ) -> Arrival {
        self.schedule_with_fallback(
            identity,
            kind,
            grant,
            source,
            ReadAim {
                preferred: handle,
                focused: None,
            },
            point,
        )
    }

    /// Schedule a read with a focused fallback if its preferred element has
    /// no readable frame. The emitted picture and its follow watch use the
    /// same element, so later window moves stay tied to what was shown.
    pub(crate) fn schedule_with_fallback(
        &self,
        identity: Identity,
        kind: CursorKind,
        grant: ProcessGrant,
        source: Arc<dyn AppStateSource>,
        aim: ReadAim,
        point: Option<[f64; 2]>,
    ) -> Arrival {
        if self.0.sender.get().is_none()
            || self.0.stopped.load(std::sync::atomic::Ordering::Acquire)
        {
            return Arrival::none();
        }
        let cursor = self.clone();
        // Numbered before it is recorded: an end that lands in between then
        // counts this picture as scheduled before it, and drops it.
        let serial = self
            .0
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        cursor.record(&identity);
        // Off the picture path: this picture uses the value already read.
        self.refresh_reduce_motion();
        let (decided, decision) = oneshot::channel();
        let arrival = Arrival {
            decision: Some(decision),
            scheduled: tokio::time::Instant::now(),
            watch: Some(BadgeWatch {
                cursor: self.clone(),
                agent: identity.badge.clone(),
                serial,
            }),
        };
        let source_for_follow = source.clone();
        let read_grant = grant.clone();
        tokio::spawn(async move {
            let agent = identity.badge;
            #[cfg(not(target_os = "macos"))]
            let _ = identity.avatar_agent;
            let read = tokio::task::spawn_blocking(move || {
                let mut aimed_handle = aim.preferred;
                let (title, secure, mut frame) = match aimed_handle.as_ref() {
                    Some(handle) => {
                        // A read's picture has no label, so it reads no title.
                        let (title, secure) = if kind == CursorKind::Reading {
                            (None, false)
                        } else {
                            source.cursor_label(handle).unwrap_or((None, true))
                        };
                        (title, secure, source.cursor_frame(handle))
                    }
                    None => (None, false, None),
                };
                if kind == CursorKind::Reading && frame.is_none() {
                    if let Some(fallback) = aim.focused {
                        let already_focused = aimed_handle
                            .as_ref()
                            .is_some_and(|current| current.same_element(fallback.as_ref()));
                        if !already_focused {
                            aimed_handle = Some(fallback);
                            frame = aimed_handle
                                .as_ref()
                                .and_then(|element| source.cursor_frame(element));
                        }
                    }
                }
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
                let to = source.visible_cursor_point(&read_grant, point, frame)?;
                Some((
                    CursorEvent {
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
                        avatar_tint: None,
                        // Chosen when the picture is sent, from where the badge is then.
                        motion: PictureMotion::still(),
                    },
                    aimed_handle,
                ))
            });
            // A read that fails or runs out of time drops `decided`, which
            // tells a waiting action that no badge will be drawn.
            if let Ok(Ok(Some((event, followed_element)))) =
                tokio::time::timeout(READ_BUDGET, read).await
            {
                // A badge for an agent whose avatar colour is already known
                // starts in that colour rather than the neutral one.
                #[cfg(target_os = "macos")]
                let event = {
                    let mut event = event;
                    if let (Some(agent), Some(avatars)) =
                        (identity.avatar_agent.as_deref(), cursor.0.avatars.get())
                    {
                        event.avatar_tint = avatars.known_tint(agent).flatten();
                    }
                    event
                };
                let _ = decided.send(cursor.send_unless_ended(event.clone()));
                // Off the read's deadline: following the window is a nicety
                // that must never hold up or drop the picture itself.
                let follower = cursor.clone();
                let followed = event.clone();
                let (grant, source, handle) = (grant, source_for_follow, followed_element);
                let _ = tokio::task::spawn_blocking(move || {
                    follower.follow(&followed, &grant, &source, handle)
                })
                .await;
                #[cfg(target_os = "macos")]
                if let (Some(agent), Some(avatars)) =
                    (identity.avatar_agent, cursor.0.avatars.get())
                {
                    if let Some(rendered) = avatars.fetch_and_render(&agent).await {
                        let mut update = event;
                        update.avatar_rgba = Some(rendered.pixels);
                        update.avatar_tint = rendered.tint;
                        update.avatar_update = true;
                        cursor.send(update);
                    }
                }
            }
        });
        arrival
    }

    /// Signal before browser teardown starts. Reaping and any blocked pipe write
    /// belong to the transport thread, never to the twenty-second drain budget.
    pub fn shutdown(&self) {
        self.0
            .stopped
            .store(true, std::sync::atomic::Ordering::Release);
        self.follows().clear();
        self.drawn().tips.clear();
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
                avatar_tint: None,
                motion: PictureMotion::still(),
            }));
        }
    }
}

/// When the badge an action scheduled will be on its target.
///
/// An action that shows a badge waits for this before it is sent, so the real
/// press or write happens as the badge arrives and taps, not before it sets
/// off. The wait first hears whether a picture went out at all (the geometry
/// read decides that, within `READ_BUDGET`), then lasts until the arrival
/// the helper's timeline gives. Nothing to see means no wait.
pub(crate) struct Arrival {
    /// Answers once the picture is sent, with the moment its badge arrives,
    /// or with nothing (or is dropped) when no picture will be drawn.
    decision: Option<oneshot::Receiver<Option<tokio::time::Instant>>>,
    /// When the picture was scheduled; no wait runs past this plus
    /// `ARRIVAL_CAP`.
    scheduled: tokio::time::Instant,
    watch: Option<BadgeWatch>,
}

/// How a wait for a badge ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Landing {
    /// Send the action now: the badge is on its target, or no picture will
    /// be drawn. `drawn` says whether a picture was drawn for it.
    Arrived { drawn: bool },
    /// The call was cancelled while it waited.
    Cancelled,
    /// The agent's badge was ended (its turn ended, its route closed) while
    /// it travelled to this action's target: the agent is done with the
    /// computer, so the action is not sent.
    Ended,
    /// The call's work deadline passed, or its dispatch gate closed.
    Stopped,
}

/// One scheduled picture, as an action that waits for it watches it.
#[derive(Clone)]
pub(crate) struct BadgeWatch {
    cursor: Coordinator,
    agent: String,
    serial: u64,
}

impl BadgeWatch {
    /// Whether the agent's badge was ended after this picture was scheduled.
    /// An end before it (the previous turn's) does not count: this picture
    /// draws a new badge.
    pub(crate) fn ended(&self) -> bool {
        self.cursor
            .drawn()
            .ended_at
            .get(&self.agent)
            .is_some_and(|ended| self.serial < *ended)
    }

    fn helper_stopped(&self) -> bool {
        self.cursor
            .0
            .stopped
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

impl Arrival {
    /// No picture: the action goes ahead at once.
    pub(crate) fn none() -> Self {
        Self {
            decision: None,
            scheduled: tokio::time::Instant::now(),
            watch: None,
        }
    }

    /// The picture this waits for, to check right before the action is sent
    /// whether its badge was ended meanwhile.
    pub(crate) fn watch(&self) -> Option<BadgeWatch> {
        self.watch.clone()
    }

    /// Wait until the badge is on its target, or until the call must not be
    /// sent: `cancelled` resolves, `stopped` answers true (the call's
    /// dispatch gate closed), or `deadline` passes first. Never longer than
    /// `ARRIVAL_CAP` after the picture was scheduled.
    pub(crate) async fn wait(
        self,
        deadline: tokio::time::Instant,
        cancelled: impl Future<Output = ()>,
        stopped: impl Fn() -> bool,
    ) -> Landing {
        tokio::pin!(cancelled);
        let cap = self.scheduled + ARRIVAL_CAP;
        let (mut decision, mut deciding) = match self.decision {
            Some(decision) => (decision, true),
            None => (oneshot::channel().1, false),
        };
        let mut landing = None;
        loop {
            if stopped() {
                return Landing::Stopped;
            }
            let drawn = landing.is_some();
            let until = if deciding {
                cap
            } else {
                match landing {
                    // A stopped helper draws nothing more: nothing to wait for.
                    Some(at) if !self.watch.as_ref().is_some_and(BadgeWatch::helper_stopped) => {
                        // The badge is on its way. Ended meanwhile, it is gone
                        // from the screen and the agent is done: stop now
                        // rather than wait out a glide nobody sees.
                        if self.watch.as_ref().is_some_and(BadgeWatch::ended) {
                            return Landing::Ended;
                        }
                        std::cmp::min(at, cap)
                    }
                    // No picture was drawn, so there is nothing to wait for.
                    // An end that landed while the geometry read ran is what
                    // dropped the picture; the dispatch gate refuses that
                    // action when it would be sent (see `BadgeWatch::ended`).
                    _ => return Landing::Arrived { drawn },
                }
            };
            let now = tokio::time::Instant::now();
            if now >= until {
                return Landing::Arrived { drawn };
            }
            if now >= deadline {
                return Landing::Stopped;
            }
            let wake = until.min(deadline).min(now + ARRIVAL_POLL);
            tokio::select! {
                biased;
                () = &mut cancelled => return Landing::Cancelled,
                decided = &mut decision, if deciding => {
                    deciding = false;
                    landing = decided.ok().flatten();
                }
                () = tokio::time::sleep_until(wake) => {}
            }
        }
    }
}

impl Arrival {
    /// A picture already decided on, whose badge lands at `at`.
    #[cfg(test)]
    pub(crate) fn landing_at(at: tokio::time::Instant) -> Self {
        let (decided, decision) = oneshot::channel();
        let _ = decided.send(Some(at));
        Self {
            decision: Some(decision),
            scheduled: tokio::time::Instant::now(),
            watch: None,
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

/// The platform's Reduce Motion reader; the full animation where there is
/// no setting to read.
fn platform_reduce_motion() -> ReduceMotionReader {
    #[cfg(target_os = "macos")]
    {
        Arc::new(cerebellum_macos::reduce_motion)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(|| false)
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
                state
                    .helper_down
                    .store(true, std::sync::atomic::Ordering::Release);
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
            // A helper that did not start draws nothing; until another one
            // starts, no action waits for its badge.
            state
                .helper_down
                .store(helper.is_none(), std::sync::atomic::Ordering::Release);
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

    /// No action waits past the cap after its picture was scheduled: not
    /// for a landing named far in the future, and not for a decision that
    /// never comes.
    #[tokio::test(start_paused = true)]
    async fn a_badge_wait_never_runs_past_its_cap() {
        let far = tokio::time::Instant::now() + Duration::from_secs(10);
        let start = tokio::time::Instant::now();
        let landing = Arrival::landing_at(far)
            .wait(
                far + Duration::from_secs(10),
                std::future::pending(),
                || false,
            )
            .await;
        assert_eq!(landing, Landing::Arrived { drawn: true });
        assert_eq!(tokio::time::Instant::now() - start, ARRIVAL_CAP);

        let (_undecided, decision) = oneshot::channel();
        let start = tokio::time::Instant::now();
        let landing = Arrival {
            decision: Some(decision),
            scheduled: start,
            watch: None,
        }
        .wait(
            start + Duration::from_secs(10),
            std::future::pending(),
            || false,
        )
        .await;
        assert_eq!(landing, Landing::Arrived { drawn: false });
        assert_eq!(tokio::time::Instant::now() - start, ARRIVAL_CAP);
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

    struct AimedWindowGeometry {
        target: ElementHandle,
        focused: ElementHandle,
        target_window: ElementHandle,
        focused_window: ElementHandle,
        target_frame: Option<[f64; 4]>,
        focused_frame: Option<[f64; 4]>,
        watched: std::sync::Mutex<Vec<ElementHandle>>,
    }

    struct NoopWindowWatch;
    impl CursorWindowWatch for NoopWindowWatch {}

    impl AimedWindowGeometry {
        fn new(target_frame: Option<[f64; 4]>) -> Arc<Self> {
            Arc::new(Self {
                target: cerebellum_computer::app_state::source::RawElement::fixture(
                    201, "AXButton",
                )
                .handle,
                focused: cerebellum_computer::app_state::source::RawElement::fixture(
                    202,
                    "AXTextField",
                )
                .handle,
                target_window: cerebellum_computer::app_state::source::RawElement::fixture(
                    203, "AXWindow",
                )
                .handle,
                focused_window: cerebellum_computer::app_state::source::RawElement::fixture(
                    204, "AXWindow",
                )
                .handle,
                target_frame,
                focused_frame: Some([210.0, 310.0, 40.0, 20.0]),
                watched: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn watched_window(&self) -> Option<ElementHandle> {
            self.watched.lock().unwrap().last().cloned()
        }
    }

    impl AppStateSource for AimedWindowGeometry {
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

        fn cursor_frame(&self, element: &ElementHandle) -> Option<[f64; 4]> {
            if element.same_element(self.target.as_ref()) {
                self.target_frame
            } else if element.same_element(self.focused.as_ref()) {
                self.focused_frame
            } else if element.same_element(self.target_window.as_ref()) {
                Some([100.0, 80.0, 800.0, 600.0])
            } else if element.same_element(self.focused_window.as_ref()) {
                Some([50.0, 60.0, 800.0, 600.0])
            } else {
                None
            }
        }

        fn visible_cursor_point(
            &self,
            _: &ProcessGrant,
            point: Option<[f64; 2]>,
            frame: Option<[f64; 4]>,
        ) -> Option<[f64; 2]> {
            Some(point.unwrap_or_else(|| match frame {
                Some([x, y, width, height]) => [x + width / 2.0, y + height / 2.0],
                None => [500.0, 380.0],
            }))
        }

        fn cursor_window(
            &self,
            _: &ProcessGrant,
            element: Option<&ElementHandle>,
        ) -> Option<ElementHandle> {
            Some(
                if element.is_some_and(|element| element.same_element(self.target.as_ref())) {
                    self.target_window.clone()
                } else {
                    self.focused_window.clone()
                },
            )
        }

        fn watch_cursor_window(
            &self,
            window: &ElementHandle,
            _: Box<dyn Fn(WindowChange) + Send + Sync>,
        ) -> Option<Box<dyn CursorWindowWatch>> {
            self.watched.lock().unwrap().push(window.clone());
            Some(Box::new(NoopWindowWatch))
        }
    }

    #[tokio::test]
    async fn an_unframed_filtered_target_falls_back_to_focus_without_origin_aiming() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = AimedWindowGeometry::new(None);
        cursor.schedule_with_fallback(
            Identity::for_test(AGENT, None, None),
            CursorKind::Reading,
            grant(),
            geometry.clone(),
            ReadAim {
                preferred: Some(geometry.target.clone()),
                focused: Some(geometry.focused.clone()),
            },
            None,
        );
        let picture = next_line(&mut receiver).await.picture().unwrap();
        assert_eq!(picture.target, geometry.focused_frame);
        assert_eq!(picture.to, [230.0, 320.0]);
        assert_ne!(picture.to, [0.0, 0.0]);
        until("watched the focused element's window", || {
            geometry.watched_window().is_some()
        })
        .await;
        assert!(geometry
            .watched_window()
            .unwrap()
            .same_element(geometry.focused_window.as_ref()));
    }

    #[tokio::test]
    async fn follow_watches_the_window_of_the_element_that_was_aimed_at() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = AimedWindowGeometry::new(Some([400.0, 120.0, 90.0, 22.0]));
        cursor.schedule_with_fallback(
            Identity::for_test(AGENT, None, None),
            CursorKind::Reading,
            grant(),
            geometry.clone(),
            ReadAim {
                preferred: Some(geometry.target.clone()),
                focused: Some(geometry.focused.clone()),
            },
            None,
        );
        let picture = next_line(&mut receiver).await.picture().unwrap();
        assert_eq!(picture.target, geometry.target_frame);
        until("watched the aimed element's window", || {
            geometry.watched_window().is_some()
        })
        .await;
        assert!(geometry
            .watched_window()
            .unwrap()
            .same_element(geometry.target_window.as_ref()));
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
            avatar_tint: None,
            motion: PictureMotion::still(),
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

    /// Wait, in real time, until `done` holds: a read runs on a plain thread
    /// that tokio's clock knows nothing of.
    fn until_read(done: impl Fn() -> bool) {
        let give_up = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < give_up, "the read never finished");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The first Reduce Motion read in a process can take hundreds of
    /// milliseconds (it loads AppKit), far past the geometry read's budget.
    /// A picture never waits for it: it goes out at once, with the full
    /// animation until a read has finished, and says so on its line.
    #[tokio::test]
    async fn a_slow_reduce_motion_read_never_holds_back_a_picture() {
        let (cursor, mut receiver) = Coordinator::channel();
        cursor.with_reduce_motion_reader(|| {
            std::thread::sleep(Duration::from_millis(400));
            true
        });
        let geometry = FollowGeometry::new();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        let picture = next_line(&mut receiver).await.picture().expect("a picture");
        assert!(
            !picture.motion.reduce_motion,
            "no read had finished, so the full animation"
        );
    }

    /// Once the setting has been read, pictures take it from what was read
    /// and never read it themselves: every read happens on the reading
    /// thread, none on the path that sends a picture.
    #[tokio::test]
    async fn pictures_never_read_reduce_motion_themselves() {
        let (cursor, mut receiver) = Coordinator::channel();
        let reads = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorded = reads.clone();
        cursor.with_reduce_motion_reader(move || {
            let thread = std::thread::current();
            recorded
                .lock()
                .unwrap()
                .push(thread.name().unwrap_or_default().to_owned());
            true
        });
        cursor.refresh_reduce_motion();
        until_read(|| cursor.reduce_motion());
        let geometry = FollowGeometry::new();
        for kind in [CursorKind::Press, CursorKind::Write, CursorKind::Reading] {
            schedule_on(&cursor, &geometry, kind);
            let picture = next_line(&mut receiver).await.picture().expect("a picture");
            assert!(picture.motion.reduce_motion, "{kind:?}: the value read");
        }
        let elsewhere: Vec<String> = reads
            .lock()
            .unwrap()
            .iter()
            .filter(|thread| *thread != REDUCE_MOTION_THREAD)
            .cloned()
            .collect();
        assert!(
            elsewhere.is_empty(),
            "read on the picture path, on {elsewhere:?}"
        );
    }

    /// Scheduling pictures reads the setting again at most every 30 seconds,
    /// on tokio's paused clock.
    #[tokio::test(start_paused = true)]
    async fn reduce_motion_is_read_again_at_most_every_30_seconds() {
        let (cursor, _receiver) = Coordinator::channel();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = count.clone();
        cursor.with_reduce_motion_reader(move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            false
        });
        let reads = || count.load(std::sync::atomic::Ordering::SeqCst);
        let geometry = FollowGeometry::new();
        // At 0 s, 10 s, 29.9 s, 30 s and 31 s.
        for (advance_ms, expected) in [(0, 1), (10_000, 1), (19_900, 1), (100, 2), (1_000, 2)] {
            tokio::time::advance(Duration::from_millis(advance_ms)).await;
            schedule_on(&cursor, &geometry, CursorKind::Reading);
            // A read that was started has had ample time to count.
            std::thread::sleep(Duration::from_millis(30));
            until_read(|| reads() >= expected);
            assert_eq!(reads(), expected, "after {advance_ms} ms more");
        }
    }
}
