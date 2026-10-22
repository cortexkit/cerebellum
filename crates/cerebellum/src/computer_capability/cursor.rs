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
    follow_offset, label, CursorEvent, CursorFollow, CursorFrame, CursorHide, CursorKind,
    CursorLine, CursorPreview, CursorPreviewMotion, PictureMotion, WindowChange,
    IDLE_FADE_AFTER_MS, IDLE_FADE_MS, LONGEST_ARRIVAL_MS,
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

/// At most this many agents' frames wait for the pipe at once, one each.
/// The helper shows at most three previews; past this bound a new agent's
/// frame is dropped, which only leaves its preview on the previous frame.
const PENDING_FRAME_CAP: usize = 8;

/// Told when a line's write to the helper completed, or `None` when it was
/// not written.
type WriteNote = oneshot::Sender<Option<tokio::time::Instant>>;
/// The lines actions wait for, by agent and serial.
type AwaitedWrites = HashMap<(String, u64), WriteNote>;

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

/// Where a badge is drawn: on the screen, or inside its agent's preview of
/// one window. A badge that moves to another space appears there anew, with
/// its entry, rather than gliding across from somewhere it cannot be seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Space {
    Screen,
    Preview { window: u32 },
}

/// One agent's badge as the module last sent it to the helper.
struct Tip {
    /// The picture event it was sent for.
    serial: u64,
    /// The space it was drawn in; `to` and `offset` are in that space.
    space: Space,
    /// Where its tip was sent: global screen points on the screen, or the
    /// window-relative 0..1 point inside a preview.
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

/// Where a badge is about to be sent, for choosing its motion.
struct Aim<'a> {
    agent: &'a str,
    serial: u64,
    space: Space,
    to: [f64; 2],
    /// `to` is only a place to appear: a badge already showing in the same
    /// space stays where it is.
    resting: bool,
    /// Points per unit of `to` on each axis: 1 on the screen, the
    /// thumbnail's size in points inside a preview, so a glide's length (and
    /// so its duration) is measured in the points the person sees it travel.
    scale: [f64; 2],
}

impl Drawn {
    /// Choose the motion for a picture about to be sent to the helper, and
    /// the record of where its badge will then be. Nothing is recorded yet:
    /// `keep` does that once the picture is really on its way.
    ///
    /// A badge the module has not seen drawn in this space (never drawn,
    /// ended, faded out after the idle timeout, or last drawn in another
    /// space) appears with its entry animation; one already showing there
    /// glides from where it was last sent. A read with nothing to aim at
    /// leaves a shown badge where it is. The helper follows the chosen motion
    /// from wherever its badge really is, so even where this record is out of
    /// date the badge arrives when the motion says.
    fn aim(
        &self,
        aim: &Aim<'_>,
        now: tokio::time::Instant,
        reduce_motion: bool,
    ) -> (PictureMotion, Tip) {
        let gone_after = Duration::from_millis(IDLE_FADE_AFTER_MS + IDLE_FADE_MS);
        let shown = self
            .tips
            .get(aim.agent)
            .filter(|tip| tip.space == aim.space)
            .filter(|tip| now.saturating_duration_since(tip.sent) < gone_after)
            .map(Tip::place);
        let to = match (aim.resting, shown) {
            (true, Some(resting)) => resting,
            _ => aim.to,
        };
        let distance = shown.map_or(0.0, |from| {
            ((to[0] - from[0]) * aim.scale[0]).hypot((to[1] - from[1]) * aim.scale[1])
        });
        (
            PictureMotion::chosen(distance, shown.is_none(), reduce_motion),
            Tip {
                serial: aim.serial,
                space: aim.space,
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
    /// Preview frames waiting for the pipe: at most one per agent, the
    /// latest. The writer takes one only when no other line is waiting.
    frames: std::sync::Mutex<VecDeque<CursorFrame>>,
    /// For each picture or preview motion an action waits for, by agent and
    /// serial: told when the writer has written it to the helper, or that it
    /// was not written.
    awaiting: std::sync::Mutex<AwaitedWrites>,
    /// A writer takes lines off the channel and says when each was written.
    /// Without one (a test reading the channel itself), a line counts as
    /// written the moment it is queued.
    writes_confirmed: std::sync::atomic::AtomicBool,
    /// How many awaited lines the writer has settled, written or not.
    #[cfg(test)]
    settled: std::sync::atomic::AtomicUsize,
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
                self.0
                    .writes_confirmed
                    .store(true, std::sync::atomic::Ordering::Release);
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
        // A frame still waiting would be drawn into nothing: the helper drops
        // a frame after a hide, so it is not sent at all.
        self.frames().retain(|frame| frame.frame_agent != agent);
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
    /// scheduled. Answers how an action waits for its badge, or `None` when
    /// nothing will be drawn or there is nothing to wait for.
    fn send_unless_ended(&self, mut event: CursorEvent) -> Option<Sent> {
        let mut drawn = self.drawn();
        if drawn
            .ended_at
            .get(&event.agent)
            .is_some_and(|ended| event.serial < *ended)
        {
            return None;
        }
        let now = tokio::time::Instant::now();
        let (motion, tip) = drawn.aim(
            &Aim {
                agent: &event.agent,
                serial: event.serial,
                space: Space::Screen,
                to: event.to,
                resting: event.resting,
                scale: [1.0, 1.0],
            },
            now,
            self.reduce_motion(),
        );
        // The line carries the motion, so the helper animates exactly what
        // this wait is timed by.
        event.motion = motion;
        // A badge that only rests somewhere aims at nothing an action waits
        // for.
        let waits = !event.resting
            && !self
                .0
                .helper_down
                .load(std::sync::atomic::Ordering::Acquire);
        let agent = event.agent.clone();
        let sent = self.send_awaited(CursorLine::Picture(event), &agent, tip.serial, waits)?;
        drawn.keep(&agent, tip);
        sent.map(|written| Sent {
            duration: Duration::from_secs_f64(motion.duration_ms / 1000.0),
            written,
        })
    }

    /// Put a picture or a preview motion on the pipe. `None` when it could
    /// not be queued; otherwise, when `waits`, how to learn when it was
    /// written. With a writer that is a note the writer settles once the line
    /// is through; without one, the moment it was queued.
    fn send_awaited(
        &self,
        line: CursorLine,
        agent: &str,
        serial: u64,
        waits: bool,
    ) -> Option<Option<Written>> {
        let confirmed = self
            .0
            .writes_confirmed
            .load(std::sync::atomic::Ordering::Acquire);
        if !waits || !confirmed {
            let queued_at = tokio::time::Instant::now();
            return self
                .send_line(line)
                .then(|| waits.then_some(Written::At(queued_at)));
        }
        let key = (agent.to_owned(), serial);
        let (settle, settled) = oneshot::channel();
        {
            // Noted before the line is queued, so the writer always finds it.
            let mut awaiting = self.awaiting();
            if awaiting.len() >= RECORD_CAP {
                // Each note lives at most until its action's cap, so a full
                // record means notes nobody waits for any more.
                awaiting.clear();
            }
            awaiting.insert(key.clone(), settle);
        }
        if !self.send_line(line) {
            self.awaiting().remove(&key);
            return None;
        }
        Some(Some(Written::Pending(key, settled)))
    }

    fn awaiting(&self) -> std::sync::MutexGuard<'_, AwaitedWrites> {
        self.0
            .awaiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn frames(&self) -> std::sync::MutexGuard<'_, VecDeque<CursorFrame>> {
        self.0
            .frames
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Answer an action's wait once its line is written: the badge is on its
    /// target the line's motion duration after the write completed. A line
    /// that was not written draws nothing, so nothing is waited for. A write
    /// still not done by the cap is given up on; the action has already gone
    /// ahead, unsynchronized.
    async fn decide(
        self,
        decided: oneshot::Sender<Option<tokio::time::Instant>>,
        sent: Option<Sent>,
        queued: Arc<std::sync::atomic::AtomicBool>,
        cap: tokio::time::Instant,
    ) {
        let Some(sent) = sent else {
            let _ = decided.send(None);
            return;
        };
        let written = match sent.written {
            Written::At(at) => Some(at),
            Written::Pending(key, settled) => {
                queued.store(true, std::sync::atomic::Ordering::Release);
                match tokio::time::timeout_at(cap, settled).await {
                    Ok(written) => written.ok().flatten(),
                    Err(_) => {
                        self.awaiting().remove(&key);
                        return;
                    }
                }
            }
        };
        let _ = decided.send(written.map(|at| at + sent.duration));
    }

    /// Show an agent's preview, or point it at another window. It may start
    /// the helper.
    // Only this module's tests call it so far; the background-mode preview
    // calls it as it shows and retargets.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn send_preview(&self, preview: CursorPreview) -> bool {
        self.send_line(CursorLine::Preview(preview))
    }

    /// Queue a frame for an agent's preview. It never waits and never starts
    /// the helper, and it is not an action: the badge's idle clock is not
    /// restarted by it. At most one frame per agent waits for the pipe; a
    /// newer one replaces it. A frame over `MAX_FRAME_BYTES` is dropped.
    // Only this module's tests call it so far; the background-mode preview's
    // capture worker calls it with each frame.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn send_frame(&self, frame: CursorFrame) -> bool {
        if self.0.stopped.load(std::sync::atomic::Ordering::Acquire) || !frame.valid() {
            return false;
        }
        let Some(sender) = self.0.sender.get() else {
            return false;
        };
        if !self
            .0
            .writes_confirmed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            // No writer: whoever reads the channel stands for the pipe.
            return sender.try_send(CursorLine::Frame(frame)).is_ok();
        }
        let mut frames = self.frames();
        if let Some(waiting) = frames
            .iter_mut()
            .find(|waiting| waiting.frame_agent == frame.frame_agent)
        {
            // Latest wins; the writer was already woken for the older one.
            *waiting = frame;
            return true;
        }
        if frames.len() >= PENDING_FRAME_CAP {
            return false;
        }
        // Only a wake: the writer takes frames from the record, never from
        // the channel. If the channel is full the writer is busy and finds
        // the frame once it has written the lines ahead of it.
        let wake = CursorFrame {
            frame_agent: frame.frame_agent.clone(),
            frame_generation: frame.frame_generation,
            frame_window: frame.frame_window,
            frame_w: frame.frame_w,
            frame_h: frame.frame_h,
            frame_jpeg: String::new(),
        };
        frames.push_back(frame);
        let _ = sender.try_send(CursorLine::Frame(wake));
        true
    }

    /// Move an agent's badge inside its preview of `motion.pmotion_window`,
    /// and answer when its tip lands. The serial and the motion on the line
    /// are chosen here: the motion from where the badge last was in that
    /// preview, measured in the thumbnail's points (`thumbnail` is its width
    /// and height). A badge last drawn on the screen or in another window's
    /// preview appears with its entry.
    // Only this module's tests call it so far; the background-mode preview
    // calls it before each action.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn schedule_preview_motion(
        &self,
        mut motion: CursorPreviewMotion,
        thumbnail: [f64; 2],
    ) -> Arrival {
        if self.0.sender.get().is_none()
            || self.0.stopped.load(std::sync::atomic::Ordering::Acquire)
            || !thumbnail.iter().all(|v| v.is_finite() && *v > 0.0)
        {
            return Arrival::none();
        }
        let serial = self
            .0
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.refresh_reduce_motion();
        let scheduled = tokio::time::Instant::now();
        let agent = motion.pmotion_agent.clone();
        let queued = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sent = {
            let mut drawn = self.drawn();
            let (chosen, tip) = drawn.aim(
                &Aim {
                    agent: &agent,
                    serial,
                    space: Space::Preview {
                        window: motion.pmotion_window,
                    },
                    to: motion.pmotion_to,
                    resting: false,
                    scale: thumbnail,
                },
                scheduled,
                self.reduce_motion(),
            );
            motion.pmotion_serial = serial;
            motion.pmotion_motion = chosen;
            let waits = !self
                .0
                .helper_down
                .load(std::sync::atomic::Ordering::Acquire);
            let sent = self.send_awaited(CursorLine::PreviewMotion(motion), &agent, serial, waits);
            if sent.is_some() {
                drawn.keep(&agent, tip);
            }
            sent.flatten().map(|written| Sent {
                duration: Duration::from_secs_f64(chosen.duration_ms / 1000.0),
                written,
            })
        };
        let (decided, decision) = oneshot::channel();
        tokio::spawn(
            self.clone()
                .decide(decided, sent, queued.clone(), scheduled + ARRIVAL_CAP),
        );
        Arrival {
            decision: Some(decision),
            scheduled,
            queued,
            watch: Some(BadgeWatch {
                cursor: self.clone(),
                agent,
                serial,
            }),
        }
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
            queued: Arc::default(),
            watch: Some(BadgeWatch {
                cursor: self.clone(),
                agent: identity.badge.clone(),
                serial,
            }),
        };
        let (queued, cap) = (arrival.queued.clone(), arrival.scheduled + ARRIVAL_CAP);
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
                // Its own task: the wait for the write must not hold up the
                // window watch or the avatar below.
                let sent = cursor.send_unless_ended(event.clone());
                tokio::spawn(cursor.clone().decide(decided, sent, queued, cap));
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
        self.frames().clear();
        // Every action still waiting for a write hears now that nothing more
        // will be written.
        self.awaiting().clear();
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
/// read decides that, within `READ_BUDGET`) and when the writer finished
/// writing it to the helper, then lasts until that write plus the motion the
/// line carries. Nothing to see means no wait.
pub(crate) struct Arrival {
    /// Answers once the picture is written, with the moment its badge
    /// arrives, or with nothing (or is dropped) when no picture will be
    /// drawn.
    decision: Option<oneshot::Receiver<Option<tokio::time::Instant>>>,
    /// When the picture was scheduled; no wait runs past this plus
    /// `ARRIVAL_CAP`.
    scheduled: tokio::time::Instant,
    /// Set once the line is queued for a writer that has not yet said it
    /// wrote it: a wait that reaches the cap then knows a badge is still on
    /// its way, so the action goes ahead unsynchronized.
    queued: Arc<std::sync::atomic::AtomicBool>,
    watch: Option<BadgeWatch>,
}

/// Whether an action went ahead together with its badge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArrivalSync {
    /// The badge landed before the action went, or there was no badge to
    /// wait for.
    OnTime,
    /// The cap came first: the line was not yet written, or its badge lands
    /// after the cap. The action went ahead at the cap, and its reply says
    /// `preview: "not_synchronized"` rather than claiming the badge arrived.
    NotSynchronized,
}

/// A picture or preview motion on its way, as an action waits for it.
struct Sent {
    /// The line's serialized motion duration: the badge lands this long
    /// after the line was written.
    duration: Duration,
    written: Written,
}

/// When a line an action waits for was written to the helper.
enum Written {
    /// At this moment (a line with no writer to confirm it counts as
    /// written when it is queued).
    At(tokio::time::Instant),
    /// The writer settles the note for this agent and serial once the line
    /// is through, with the moment its write completed, or with nothing
    /// when it was not written.
    Pending(
        (String, u64),
        oneshot::Receiver<Option<tokio::time::Instant>>,
    ),
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
            queued: Arc::default(),
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
        self.wait_reporting(deadline, cancelled, stopped).await.0
    }

    /// `wait`, also saying whether the action goes with its badge or ahead
    /// of it at the cap.
    pub(crate) async fn wait_reporting(
        self,
        deadline: tokio::time::Instant,
        cancelled: impl Future<Output = ()>,
        stopped: impl Fn() -> bool,
    ) -> (Landing, ArrivalSync) {
        tokio::pin!(cancelled);
        let cap = self.scheduled + ARRIVAL_CAP;
        let (mut decision, mut deciding) = match self.decision {
            Some(decision) => (decision, true),
            None => (oneshot::channel().1, false),
        };
        let mut landing = None;
        let on_time = |landing: Landing| (landing, ArrivalSync::OnTime);
        loop {
            if stopped() {
                return on_time(Landing::Stopped);
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
                            return on_time(Landing::Ended);
                        }
                        std::cmp::min(at, cap)
                    }
                    // No picture was drawn, so there is nothing to wait for.
                    // An end that landed while the geometry read ran is what
                    // dropped the picture; the dispatch gate refuses that
                    // action when it would be sent (see `BadgeWatch::ended`).
                    _ => return on_time(Landing::Arrived { drawn }),
                }
            };
            let now = tokio::time::Instant::now();
            if now >= until {
                // At the cap with the line still unwritten, or with a badge
                // that lands after it: the action goes now, ahead of it.
                let late = if deciding {
                    self.queued.load(std::sync::atomic::Ordering::Acquire)
                } else {
                    landing.is_some_and(|at| at > cap)
                };
                return if late {
                    (
                        Landing::Arrived { drawn: true },
                        ArrivalSync::NotSynchronized,
                    )
                } else {
                    on_time(Landing::Arrived { drawn })
                };
            }
            if now >= deadline {
                return on_time(Landing::Stopped);
            }
            let wake = until.min(deadline).min(now + ARRIVAL_POLL);
            tokio::select! {
                biased;
                () = &mut cancelled => return on_time(Landing::Cancelled),
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
            queued: Arc::default(),
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

/// The writer's loop: take each line to send, hand it to `deliver`, which
/// answers whether it reached the helper, and settle any action waiting for
/// it with the moment its write completed. Returns when the channel closes
/// or the cursor is shut down.
///
/// Every line on the channel (a picture, preview, preview motion, hide or
/// follow) is written before any waiting frame, in the order it was queued.
/// Frames are taken from the per-agent record, one at a time, only when no
/// other line is waiting. A frame already being written still delays the
/// lines queued behind it: `deliver` writes a whole line at once.
// Outside macOS only this module's tests run a writer.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn write_lines(
    state: &State,
    rx: &mut mpsc::Receiver<CursorLine>,
    mut deliver: impl FnMut(&CursorLine) -> bool,
) {
    let mut waiting: VecDeque<CursorLine> = VecDeque::new();
    // A frame on the channel is only a wake for one in the record.
    let keep = |waiting: &mut VecDeque<CursorLine>, line: CursorLine| {
        if !matches!(line, CursorLine::Frame(_)) {
            waiting.push_back(line);
        }
    };
    loop {
        if state.stopped.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        // Taken from the channel only once the last batch is written, so
        // what waits here stays within the channel's own bound.
        if waiting.is_empty() {
            while let Ok(line) = rx.try_recv() {
                keep(&mut waiting, line);
            }
        }
        let next = waiting.pop_front().or_else(|| {
            state
                .frames
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .map(CursorLine::Frame)
        });
        let Some(line) = next else {
            match rx.blocking_recv() {
                Some(line) => {
                    keep(&mut waiting, line);
                    continue;
                }
                None => break,
            }
        };
        let written = deliver(&line);
        let at = tokio::time::Instant::now();
        state.settle(&line, written.then_some(at));
    }
}

impl State {
    /// Tell the action waiting for `line`, if any, when its write completed,
    /// or that it was not written.
    fn settle(&self, line: &CursorLine, written: Option<tokio::time::Instant>) {
        let key = match line {
            CursorLine::Picture(event) => (event.agent.clone(), event.serial),
            CursorLine::PreviewMotion(motion) => {
                (motion.pmotion_agent.clone(), motion.pmotion_serial)
            }
            _ => return,
        };
        let waiter = self
            .awaiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
        if let Some(waiter) = waiter {
            let _ = waiter.send(written);
            #[cfg(test)]
            self.settled
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(target_os = "macos")]
fn transport(state: Arc<State>, mut rx: mpsc::Receiver<CursorLine>) {
    use std::io::Write;
    let mut helper: Option<(cerebellum_macos::ReleasedChild, std::fs::File)> = None;
    let mut restarts = RestartLimit::default();
    write_lines(&state, &mut rx, |event| {
        // A locked or unreadable screen never launches or displays the helper.
        if cerebellum_macos::screen_is_locked() != Some(false) {
            return false;
        }
        if helper.is_none() {
            // No helper means no badge and no preview on screen, so there is
            // nothing to hide, move or fill in; never launch a helper just
            // for that.
            if !event.launches_helper() {
                return false;
            }
            if !restarts.admit(Instant::now()) {
                state
                    .helper_down
                    .store(true, std::sync::atomic::Ordering::Release);
                return false;
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
            return false;
        };
        let Some((_, pipe)) = helper.as_mut() else {
            return false;
        };
        if pipe.write_all(&line).is_ok() {
            return true;
        }
        helper.take();
        cerebellum_macos::register_cursor_generation(None);
        *state
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        false
    });
    drop(helper);
}

impl Coordinator {
    /// A cursor whose lines go through the real writer to `deliver`, which
    /// stands for the helper's pipe, on a thread of its own. It runs on the
    /// calling runtime's clock, so a test on a paused clock sees each write
    /// complete at the paused time.
    #[cfg(test)]
    pub(crate) fn piped_for_test(
        deliver: impl FnMut(&CursorLine) -> bool + Send + 'static,
    ) -> Self {
        let result = Self::default();
        let (tx, mut rx) = mpsc::channel(CAPACITY);
        let _ = result.0.sender.set(tx);
        result
            .0
            .writes_confirmed
            .store(true, std::sync::atomic::Ordering::Release);
        let state = result.0.clone();
        let runtime = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            let _entered = runtime.enter();
            write_lines(&state, &mut rx, deliver);
        });
        result
    }

    /// How many awaited lines the writer has settled so far.
    #[cfg(test)]
    fn settled(&self) -> usize {
        self.0.settled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::HANG_GUARD;
    use cerebellum_computer::cursor::MAX_FRAME_BYTES;

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

    /// Keeps an AX read blocked until the test releases it, without sleeping on
    /// the runtime thread that schedules the cursor update.
    struct HeldGeometry {
        started: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        finished: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }

    impl AppStateSource for HeldGeometry {
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
            if let Some(started) = self.started.lock().unwrap().take() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.lock().unwrap().take() {
                let _ = release.blocking_recv();
            }
            if let Some(finished) = self.finished.lock().unwrap().take() {
                let _ = finished.send(());
            }
            Some([0.0, 0.0, 10.0, 10.0])
        }

        fn visible_cursor_point(
            &self,
            _: &ProcessGrant,
            point: Option<[f64; 2]>,
            _: Option<[f64; 4]>,
        ) -> Option<[f64; 2]> {
            point
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
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let geometry = Arc::new(HeldGeometry {
            started: std::sync::Mutex::new(Some(started_tx)),
            release: std::sync::Mutex::new(Some(release_rx)),
            finished: std::sync::Mutex::new(Some(finished_tx)),
        });
        // A wall-clock speed assertion would fail under load. The read stays
        // blocked here, so event ordering proves scheduling and runtime work
        // continue without comparing real elapsed time with READ_BUDGET.
        let scheduling_cursor = cursor.clone();
        let runtime = tokio::runtime::Handle::current();
        let scheduling = tokio::task::spawn_blocking(move || {
            let _entered = runtime.enter();
            scheduling_cursor.schedule(
                Identity::current("agent".into()),
                CursorKind::Press,
                grant,
                geometry,
                Some(
                    cerebellum_computer::app_state::source::RawElement::fixture(1, "AXButton")
                        .handle,
                ),
                None,
            );
        });
        let scheduled = tokio::time::timeout(HANG_GUARD, scheduling).await;
        if scheduled.is_err() {
            let _ = release_tx.send(());
            panic!("scheduling waited for the blocked geometry read");
        }
        scheduled.unwrap().unwrap();
        tokio::time::timeout(HANG_GUARD, started_rx)
            .await
            .expect("the geometry worker never started")
            .unwrap();
        let runtime_work = tokio::time::timeout(HANG_GUARD, tokio::spawn(async { "completed" }))
            .await
            .expect("the runtime stopped dispatching while geometry was blocked")
            .unwrap();
        assert_eq!(runtime_work, "completed");
        assert!(
            tokio::time::timeout(Duration::from_millis(250), receiver.recv())
                .await
                .is_err(),
            "late geometry must not reach the helper"
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(HANG_GUARD, finished_rx)
            .await
            .expect("the released geometry worker did not finish")
            .unwrap();
        assert!(receiver.try_recv().is_err(), "a late picture was sent");
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
            queued: Arc::default(),
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
            other => panic!("expected a hide, got {other:?}"),
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
        let hide = tokio::time::timeout(HANG_GUARD, receiver.recv())
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
        let picture = tokio::time::timeout(HANG_GUARD, receiver.recv())
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
        tokio::time::timeout(HANG_GUARD, receiver.recv())
            .await
            .expect("a cursor line before HANG_GUARD")
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
            assert!(start.elapsed() < HANG_GUARD, "never {what}");
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
            received.recv_timeout(HANG_GUARD).is_ok(),
            "cursor send awaited a full channel"
        );
    }

    /// Wait, in real time, until `done` holds: a read runs on a plain thread
    /// that tokio's clock knows nothing of. The deadline only detects a stuck read.
    fn until_read(done: impl Fn() -> bool) {
        let give_up = Instant::now() + HANG_GUARD;
        while !done() {
            assert!(Instant::now() < give_up, "the read never finished");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The first Reduce Motion read in a process can take hundreds of
    /// milliseconds (it loads AppKit), far past the geometry read's budget.
    /// A picture never waits for it: it still goes out at once.
    #[tokio::test]
    async fn a_slow_reduce_motion_read_never_holds_back_a_picture() {
        let (cursor, mut receiver) = Coordinator::channel();
        cursor.with_reduce_motion_reader(|| {
            std::thread::sleep(Duration::from_millis(400));
            true
        });
        let geometry = FollowGeometry::new();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        next_line(&mut receiver).await.picture().expect("a picture");
    }

    /// Pictures take Reduce Motion from what was last read and never read it
    /// themselves. Before the first read has finished they use the full
    /// animation, and say so on their line; once it has, the value read.
    /// Every read happens on the reading thread, none on the path that sends
    /// a picture.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pictures_never_read_reduce_motion_themselves() {
        let (cursor, mut receiver) = Coordinator::channel();
        let reads = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        // The read remains parked until the test releases it; the shared guard
        // only prevents a broken test from leaving the reader thread stuck.
        let (release, released) = std::sync::mpsc::channel::<()>();
        let released = std::sync::Mutex::new(released);
        let recorded = reads.clone();
        cursor.with_reduce_motion_reader(move || {
            let thread = std::thread::current();
            recorded
                .lock()
                .unwrap()
                .push(thread.name().unwrap_or_default().to_owned());
            let _ = released.lock().unwrap().recv_timeout(HANG_GUARD);
            true
        });
        let geometry = FollowGeometry::new();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        let before = next_line(&mut receiver).await.picture().expect("a picture");
        assert!(
            !before.motion.reduce_motion,
            "no read had finished, so the full animation"
        );
        release.send(()).unwrap();
        until_read(|| cursor.reduce_motion());
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

    /// Scheduling pictures starts a background read of the setting at most
    /// every 30 seconds, on tokio's paused clock.
    #[tokio::test(start_paused = true)]
    async fn reduce_motion_is_read_again_at_most_every_30_seconds() {
        let (cursor, _receiver) = Coordinator::channel();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = count.clone();
        cursor.with_reduce_motion_reader(move || {
            // Only the background reads; this test is about how often they
            // start, not about where else a read might happen.
            if std::thread::current().name() == Some(REDUCE_MOTION_THREAD) {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
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

    /// Stands for the helper's pipe: keeps each line written in full, and can
    /// be made to stop partway through one line until the test releases it.
    #[derive(Clone, Default)]
    struct FakePipe(Arc<FakePipeState>);

    #[derive(Default)]
    struct FakePipeState {
        written: std::sync::Mutex<Vec<CursorLine>>,
        hold: std::sync::Mutex<Option<Hold>>,
    }

    /// Stop writing the next line `matches` accepts after `after_bytes`
    /// bytes, say so on `stalled`, and go on once `release` hears.
    struct Hold {
        matches: fn(&CursorLine) -> bool,
        after_bytes: usize,
        stalled: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    /// One line's bytes as the pipe takes them, a write call at a time.
    struct Sink {
        line: Vec<u8>,
        hold: Option<Hold>,
    }

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(hold) = &self.hold {
                if self.line.len() < hold.after_bytes {
                    let taken = buf.len().min(hold.after_bytes - self.line.len());
                    self.line.extend_from_slice(&buf[..taken]);
                    return Ok(taken);
                }
                // Partway through the line: the reader stops reading.
                let hold = self.hold.take().unwrap();
                let _ = hold.stalled.send(());
                let _ = hold.release.recv_timeout(HANG_GUARD);
            }
            self.line.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl FakePipe {
        fn deliver(&self) -> impl FnMut(&CursorLine) -> bool + Send + 'static {
            let pipe = self.clone();
            move |line| {
                let Some(bytes) = line.encode_line() else {
                    return false;
                };
                let hold = {
                    let mut hold = pipe.0.hold.lock().unwrap();
                    if hold.as_ref().is_some_and(|hold| (hold.matches)(line)) {
                        hold.take()
                    } else {
                        None
                    }
                };
                let mut sink = Sink {
                    line: Vec::new(),
                    hold,
                };
                std::io::Write::write_all(&mut sink, &bytes).unwrap();
                pipe.0
                    .written
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&sink.line).unwrap());
                true
            }
        }

        /// Hold the next matching line; answers the stall notice and the
        /// release.
        fn hold(
            &self,
            matches: fn(&CursorLine) -> bool,
            after_bytes: usize,
        ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
            let (stalled, stall) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            *self.0.hold.lock().unwrap() = Some(Hold {
                matches,
                after_bytes,
                stalled,
                release: released,
            });
            (stall, release)
        }

        fn written(&self) -> Vec<CursorLine> {
            self.0.written.lock().unwrap().clone()
        }

        /// Each written line, named by its shape and agent (and a frame by
        /// its generation).
        fn names(&self) -> Vec<String> {
            self.written()
                .iter()
                .map(|line| match line {
                    CursorLine::Frame(frame) => {
                        format!("frame:{}:{}", frame.frame_agent, frame.frame_generation)
                    }
                    CursorLine::Picture(_) => format!("picture:{}", line.agent()),
                    CursorLine::Hide(_) => format!("hide:{}", line.agent()),
                    CursorLine::Follow(_) => format!("follow:{}", line.agent()),
                    CursorLine::Preview(_) => format!("preview:{}", line.agent()),
                    CursorLine::PreviewMotion(_) => format!("pmotion:{}", line.agent()),
                })
                .collect()
        }

        /// Wait, in real time, until `count` lines were written: the writer
        /// runs on a plain thread.
        fn until_written(&self, count: usize) {
            until_read(|| self.0.written.lock().unwrap().len() >= count);
        }
    }

    fn stalled(stall: &std::sync::mpsc::Receiver<()>) {
        stall
            .recv_timeout(HANG_GUARD)
            .expect("the writer never reached the held line");
    }

    fn frame(agent: &str, generation: u64, bytes: usize) -> CursorFrame {
        let jpeg: Vec<u8> = (0..bytes).map(|at| at as u8).collect();
        CursorFrame::new(agent, generation, 77, [280, 187], &jpeg)
    }

    fn picture(agent: &str) -> CursorEvent {
        CursorEvent {
            agent: agent.into(),
            initial: 'A',
            to: [10.0, 10.0],
            target: None,
            resting: false,
            label: None,
            kind: CursorKind::Press,
            serial: 0,
            avatar_rgba: None,
            avatar_update: false,
            avatar_tint: None,
            motion: PictureMotion::still(),
        }
    }

    /// A badge motion inside `agent`'s preview of `window`. The serial and
    /// motion are placeholders: scheduling chooses both.
    fn preview_motion(agent: &str, window: u32, to: [f64; 2]) -> CursorPreviewMotion {
        CursorPreviewMotion {
            pmotion_agent: agent.into(),
            pmotion_serial: 0,
            pmotion_generation: 1,
            pmotion_window: window,
            pmotion_kind: CursorKind::Press,
            pmotion_to: to,
            pmotion_target: to,
            pmotion_motion: PictureMotion::still(),
        }
    }

    const THUMBNAIL: [f64; 2] = [280.0, 187.0];

    fn is_hide(line: &CursorLine) -> bool {
        matches!(line, CursorLine::Hide(_))
    }

    fn is_frame(line: &CursorLine) -> bool {
        matches!(line, CursorLine::Frame(_))
    }

    fn is_preview_motion(line: &CursorLine) -> bool {
        matches!(line, CursorLine::PreviewMotion(_))
    }

    #[tokio::test]
    async fn a_picture_queued_behind_a_pending_frame_is_written_first() {
        let pipe = FakePipe::default();
        let cursor = Coordinator::piped_for_test(pipe.deliver());
        // The writer is busy with a hide while the rest is queued.
        let (stall, release) = pipe.hold(is_hide, 5);
        cursor.end("agent-x");
        stalled(&stall);
        assert!(cursor.send_frame(frame("agent-a", 1, 100)));
        assert!(cursor.send_frame(frame("agent-b", 1, 100)));
        // Latest wins, in the older frame's place.
        assert!(cursor.send_frame(frame("agent-a", 2, 100)));
        cursor.send(picture("agent-a"));
        assert!(cursor.send_preview(CursorPreview {
            preview_agent: "agent-a".into(),
            preview_generation: 2,
            preview_slot: 0,
            preview_window: 77,
            preview_app: "Mail".into(),
            preview_aspect: [1200.0, 800.0],
            preview_label: None,
            preview_fallback: None,
            preview_icon_path: None,
        }));
        release.send(()).unwrap();
        pipe.until_written(5);
        assert_eq!(
            pipe.names(),
            [
                "hide:agent-x",
                "picture:agent-a",
                "preview:agent-a",
                "frame:agent-a:2",
                "frame:agent-b:1"
            ]
        );
    }

    #[tokio::test]
    async fn an_end_drops_the_agents_waiting_frame() {
        let pipe = FakePipe::default();
        let cursor = Coordinator::piped_for_test(pipe.deliver());
        let (stall, release) = pipe.hold(is_hide, 5);
        cursor.end("agent-x");
        stalled(&stall);
        assert!(cursor.send_frame(frame("agent-a", 1, 100)));
        cursor.end("agent-a");
        release.send(()).unwrap();
        pipe.until_written(2);
        // Give a frame that was wrongly kept the time to be written.
        cursor.end("agent-y");
        pipe.until_written(3);
        assert_eq!(
            pipe.names(),
            ["hide:agent-x", "hide:agent-a", "hide:agent-y"]
        );
    }

    #[tokio::test]
    async fn an_oversized_frame_is_dropped_before_the_pipe() {
        let oversized = frame("agent-a", 1, MAX_FRAME_BYTES + 1);
        let (cursor, mut receiver) = Coordinator::channel();
        assert!(!cursor.send_frame(oversized.clone()));
        assert!(receiver.try_recv().is_err());
        assert!(cursor.send_frame(frame("agent-a", 1, MAX_FRAME_BYTES)));
        assert!(matches!(receiver.try_recv(), Ok(CursorLine::Frame(_))));

        let pipe = FakePipe::default();
        let cursor = Coordinator::piped_for_test(pipe.deliver());
        assert!(!cursor.send_frame(oversized));
        assert!(cursor.frames().is_empty());
        assert!(cursor.send_frame(frame("agent-a", 1, MAX_FRAME_BYTES)));
        pipe.until_written(1);
        assert_eq!(pipe.names(), ["frame:agent-a:1"]);
    }

    /// A consumer that stops reading partway through a frame holds back the
    /// preview motion, picture and hide queued after it. The action waiting
    /// for that motion goes ahead at the cap, not synchronized, rather than
    /// claiming the badge arrived; once the consumer reads again, every
    /// queued line is written before the agent's latest frame.
    #[tokio::test(start_paused = true)]
    async fn a_consumer_stalled_mid_frame_gives_a_motion_that_is_not_synchronized() {
        let pipe = FakePipe::default();
        let cursor = Coordinator::piped_for_test(pipe.deliver());
        let (stall, release) = pipe.hold(is_frame, 1000);
        assert!(cursor.send_frame(frame("agent-a", 1, 4000)));
        stalled(&stall);
        assert!(cursor.send_frame(frame("agent-a", 2, 4000)));
        assert!(cursor.send_frame(frame("agent-a", 3, 4000)));
        let start = tokio::time::Instant::now();
        let arrival =
            cursor.schedule_preview_motion(preview_motion("agent-a", 77, [0.5, 0.5]), THUMBNAIL);
        cursor.send(picture("agent-b"));
        cursor.end("agent-c");
        let (landing, sync) = arrival
            .wait_reporting(
                start + Duration::from_secs(10),
                std::future::pending(),
                || false,
            )
            .await;
        assert_eq!(landing, Landing::Arrived { drawn: true });
        assert_eq!(sync, ArrivalSync::NotSynchronized);
        assert_eq!(tokio::time::Instant::now() - start, ARRIVAL_CAP);
        release.send(()).unwrap();
        pipe.until_written(5);
        assert_eq!(
            pipe.names(),
            [
                "frame:agent-a:1",
                "pmotion:agent-a",
                "picture:agent-b",
                "hide:agent-c",
                "frame:agent-a:3"
            ]
        );
    }

    /// The badge lands its serialized motion after the write completes, not
    /// after the line was queued: a first appearance (a 1040 ms entry) whose
    /// write completes 30 ms after scheduling lands at 1070 ms, on time.
    #[tokio::test(start_paused = true)]
    async fn arrival_counts_from_the_write_not_the_queue() {
        let pipe = FakePipe::default();
        let cursor = Coordinator::piped_for_test(pipe.deliver());
        let (stall, release) = pipe.hold(is_preview_motion, 10);
        let start = tokio::time::Instant::now();
        let arrival =
            cursor.schedule_preview_motion(preview_motion("agent-a", 77, [0.5, 0.5]), THUMBNAIL);
        stalled(&stall);
        tokio::time::advance(Duration::from_millis(30)).await;
        release.send(()).unwrap();
        // Blocks this thread, so the paused clock cannot move on while the
        // writer finishes: its write completes at exactly 30 ms.
        until_read(|| cursor.settled() == 1);
        let (landing, sync) = arrival
            .wait_reporting(
                start + Duration::from_secs(10),
                std::future::pending(),
                || false,
            )
            .await;
        assert_eq!(landing, Landing::Arrived { drawn: true });
        assert_eq!(sync, ArrivalSync::OnTime);
        assert_eq!(
            tokio::time::Instant::now() - start,
            Duration::from_millis(30 + 1040)
        );
    }

    /// A write that completes at 1000 ms puts the badge's landing past the
    /// cap, though queuing plus the entry (1040 ms) would be within it: the
    /// action goes at 1090 ms, not synchronized.
    #[tokio::test(start_paused = true)]
    async fn a_write_completing_at_1000_ms_is_not_synchronized_at_the_cap() {
        let pipe = FakePipe::default();
        let cursor = Coordinator::piped_for_test(pipe.deliver());
        let (stall, release) = pipe.hold(is_preview_motion, 10);
        let start = tokio::time::Instant::now();
        let arrival =
            cursor.schedule_preview_motion(preview_motion("agent-a", 77, [0.5, 0.5]), THUMBNAIL);
        stalled(&stall);
        tokio::time::advance(Duration::from_millis(1000)).await;
        release.send(()).unwrap();
        until_read(|| cursor.settled() == 1);
        let (landing, sync) = arrival
            .wait_reporting(
                start + Duration::from_secs(10),
                std::future::pending(),
                || false,
            )
            .await;
        assert_eq!(landing, Landing::Arrived { drawn: true });
        assert_eq!(sync, ArrivalSync::NotSynchronized);
        assert_eq!(tokio::time::Instant::now() - start, ARRIVAL_CAP);
        assert_eq!(ARRIVAL_CAP, Duration::from_millis(1090));
    }

    async fn next_motion(receiver: &mut mpsc::Receiver<CursorLine>) -> PictureMotion {
        match next_line(receiver).await {
            CursorLine::Picture(event) => event.motion,
            CursorLine::PreviewMotion(motion) => motion.pmotion_motion,
            other => panic!("expected a motion, got {other:?}"),
        }
    }

    /// The last tip is kept with its space: a badge moving between the
    /// screen and a preview, or to another window's preview, appears anew.
    /// Inside one preview it glides, timed by the distance in thumbnail
    /// points.
    #[tokio::test]
    async fn the_last_tip_is_keyed_by_space() {
        let (cursor, mut receiver) = Coordinator::channel();
        let entry = PictureMotion::chosen(0.0, true, false);
        let mut screen = picture(AGENT);
        screen.serial = 1;
        assert!(cursor.send_unless_ended(screen.clone()).is_some());
        assert_eq!(next_motion(&mut receiver).await, entry, "first on screen");

        cursor.schedule_preview_motion(preview_motion(AGENT, 77, [0.5, 0.5]), THUMBNAIL);
        assert_eq!(next_motion(&mut receiver).await, entry, "screen to preview");
        cursor.schedule_preview_motion(preview_motion(AGENT, 77, [0.0, 0.5]), THUMBNAIL);
        assert_eq!(
            next_motion(&mut receiver).await,
            // Half the thumbnail's 280-point width.
            PictureMotion::chosen(140.0, false, false),
            "within one preview"
        );
        cursor.schedule_preview_motion(preview_motion(AGENT, 78, [0.0, 0.5]), THUMBNAIL);
        assert_eq!(
            next_motion(&mut receiver).await,
            entry,
            "another window's preview"
        );
        screen.serial = 9;
        assert!(cursor.send_unless_ended(screen).is_some());
        assert_eq!(next_motion(&mut receiver).await, entry, "preview to screen");
    }

    /// Frames are not actions: an agent's frames arriving all through the
    /// idle timeout leave its badge to idle out, so its next motion is a
    /// first appearance again.
    #[tokio::test(start_paused = true)]
    async fn frames_never_restart_the_idle_clock() {
        let pipe = FakePipe::default();
        let cursor = Coordinator::piped_for_test(pipe.deliver());
        let idle = Duration::from_millis(IDLE_FADE_AFTER_MS + IDLE_FADE_MS);
        cursor.schedule_preview_motion(preview_motion(AGENT, 77, [0.5, 0.5]), THUMBNAIL);
        let mut elapsed = Duration::ZERO;
        let step = Duration::from_secs(30);
        while elapsed + step < idle {
            tokio::time::advance(step).await;
            elapsed += step;
            assert!(cursor.send_frame(frame(AGENT, 1, 100)));
        }
        tokio::time::advance(idle - elapsed).await;
        cursor.schedule_preview_motion(preview_motion(AGENT, 77, [0.0, 0.5]), THUMBNAIL);
        // Frames may replace one another before they are written, so count
        // the motions, which are never replaced.
        let motions = || -> Vec<PictureMotion> {
            pipe.written()
                .into_iter()
                .filter_map(|line| match line {
                    CursorLine::PreviewMotion(motion) => Some(motion.pmotion_motion),
                    _ => None,
                })
                .collect()
        };
        until_read(|| motions().len() == 2);
        let entry = PictureMotion::chosen(0.0, true, false);
        assert_eq!(motions(), [entry, entry]);
    }
}
