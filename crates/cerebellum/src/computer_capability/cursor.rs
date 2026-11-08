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

use super::preview::{
    preview_window, PreviewGauges, PreviewRequest, PreviewWindow, PreviewWindowSource,
    PreviewWorker, ShowOutcome, PREVIEW_GAUGES,
};
use super::preview_call::PreviewCall;
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

#[cfg(target_os = "macos")]
static HELPER_EXECUTABLE: std::sync::Mutex<Option<cerebellum_macos::PinnedExecutable>> =
    std::sync::Mutex::new(None);
#[cfg(target_os = "macos")]
static HELPER_BINARY_UNAVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "macos")]
#[doc(hidden)]
pub struct HelperExecutableGuard(());

#[cfg(target_os = "macos")]
impl Drop for HelperExecutableGuard {
    fn drop(&mut self) {
        helper_transport::shutdown();
        HELPER_EXECUTABLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

/// Pin before configuration or serving can start the lazy helper. The guard
/// removes the link after module teardown, before a SIGTERM is re-raised.
#[cfg(target_os = "macos")]
pub(crate) fn pin_helper_at_startup() -> HelperExecutableGuard {
    let executable = cerebellum_macos::PinnedExecutable::at_startup().ok();
    HELPER_BINARY_UNAVAILABLE.store(executable.is_none(), std::sync::atomic::Ordering::Relaxed);
    *HELPER_EXECUTABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = executable;
    helper_transport::install_queries();
    HelperExecutableGuard(())
}

/// The helper could not be launched with the executable captured at startup.
#[cfg(target_os = "macos")]
pub(crate) fn helper_binary_unavailable() -> bool {
    HELPER_BINARY_UNAVAILABLE.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "macos")]
fn helper_launch_path(
    pin: Option<&cerebellum_macos::PinnedExecutable>,
) -> Option<std::path::PathBuf> {
    let path = pin.and_then(|pin| pin.launch_path().ok());
    if path.is_none() {
        HELPER_BINARY_UNAVAILABLE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    path
}

/// The standalone desk probe launches the sibling module binary rather than
/// another copy of the probe. Keep that helper pinned for the whole probe run.
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
#[doc(hidden)]
pub fn pin_helper_for_probe(
    executable: &std::path::Path,
) -> std::io::Result<HelperExecutableGuard> {
    let executable = cerebellum_macos::PinnedExecutable::for_probe(executable)?;
    *HELPER_EXECUTABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(executable);
    helper_transport::install_queries();
    Ok(HelperExecutableGuard(()))
}
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
/// How a scheduled picture answers the action waiting for it: the channel
/// its arrival is told on, the flag set once its line is queued for a
/// writer, and the cap past which nothing is waited for.
type Decision = (
    oneshot::Sender<Option<tokio::time::Instant>>,
    Arc<std::sync::atomic::AtomicBool>,
    tokio::time::Instant,
);
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
    /// The agent the badge is drawn for.
    pub(crate) fn badge(&self) -> &str {
        &self.badge
    }

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
    /// Current, not historical, badge ownership. An end consumes this entry so
    /// the other notification source cannot hide the same appearance twice.
    active: HashMap<String, Option<SessionScope>>,
    #[cfg(any(target_os = "macos", test))]
    hint_sequences: HashMap<(&'static str, String, String), u64>,
    hint_sessions: HashMap<String, (&'static str, String)>,
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
    #[cfg(any(target_os = "macos", test))]
    turn_hints: OnceLock<crate::turn_hints::Listener>,
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
    /// The preview workers drawing through this cursor, told of every end
    /// so an ended agent's preview stops being captured or timed.
    preview_ends: std::sync::Mutex<Vec<std::sync::Weak<PreviewWorker>>>,
    /// Where written frame lines are counted; the process's gauges unless a
    /// test counts its own.
    gauges: OnceLock<&'static PreviewGauges>,
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
    /// window closing. Absent only while the observer is being installed.
    _watch: Option<Box<dyn CursorWindowWatch>>,
}

/// Preferred element for a read picture and the focused element to use when
/// the preferred element has no readable frame.
#[derive(Clone)]
pub(crate) struct ReadAim {
    pub(crate) preferred: Option<ElementHandle>,
    pub(crate) focused: Option<ElementHandle>,
}

/// Pixels per point the preview's frames are captured at. The module does
/// not read the display's scale; a Retina display's 2 is assumed, which on a
/// standard display only captures a sharper frame than it can show.
const PREVIEW_BACKING_SCALE: f64 = 2.0;

/// Which window a background-mode action's preview shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WindowChoice {
    /// The window of the element the badge aims at (the addressed element of
    /// a press or a write, the focused element of `keys` and `type`), or,
    /// with no element, the application's focused window.
    Element,
    /// `read_state` without an element: the application's frontmost window
    /// in the window server's front-to-back list.
    Frontmost,
}

/// Reads the window server's frontmost window of a process, by id.
pub(crate) type FrontmostWindow = Arc<dyn Fn(&ProcessGrant) -> Option<u32> + Send + Sync>;
/// Finds the application bundle a process runs from, for the icon a preview
/// shows in place of a frame. Display only: never an authority.
pub(crate) type BundlePath = Arc<dyn Fn(&ProcessGrant) -> Option<String> + Send + Sync>;

/// What a background-mode badge needs beyond an on-screen one.
pub(crate) struct PreviewAim {
    pub(crate) worker: Arc<PreviewWorker>,
    pub(crate) window: WindowChoice,
    /// The application's name, shown on the preview.
    pub(crate) app: String,
    pub(crate) frontmost: FrontmostWindow,
    pub(crate) bundle: BundlePath,
    /// The call the badge belongs to, whose reply says when the preview did
    /// not track the action.
    pub(crate) call: Option<Arc<PreviewCall>>,
}

/// The window a preview shows and where its badge goes, read in one step.
struct PreviewAimed {
    window: PreviewWindow,
    /// The badge's tip and the element's visible centre, both as positions
    /// in the window from 0 to 1; `None` for no motion.
    to: Option<([f64; 2], [f64; 2])>,
    label: Option<String>,
    /// The application bundle's path, for the icon shown in place of a
    /// frame; `None` when it cannot be found.
    icon_path: Option<String>,
}

/// Whose preview `draw_in_preview` draws, and for which action.
struct PreviewDraw {
    agent: String,
    serial: u64,
    kind: CursorKind,
    grant: ProcessGrant,
    app: String,
    worker: Arc<PreviewWorker>,
    call: Option<Arc<PreviewCall>>,
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
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn listen_for_turn_hints(&self, transport: Arc<dyn crate::turn_hints::Transport>) {
        self.0.turn_hints.get_or_init(|| {
            let weak = Arc::downgrade(&self.0);
            crate::turn_hints::Listener::new(
                transport,
                Duration::from_millis(IDLE_FADE_AFTER_MS + IDLE_FADE_MS),
                move |notice| {
                    if let Some(state) = weak.upgrade() {
                        Coordinator(state).turn_hint(notice);
                    }
                },
            )
        });
    }

    #[cfg(any(target_os = "macos", test))]
    fn note_queued_badge(&self, agent: &str) {
        // A real helper reports successful writes through State::settle. A
        // memory-only transport treats a queued line as already written.
        if !self
            .0
            .writes_confirmed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            if let Some(listener) = self.0.turn_hints.get() {
                listener.drawn(agent);
            }
        }
    }

    /// The desk probe measures the same helper generation the transport owns,
    /// without a wrapper process or a pid file next to the build output.
    #[cfg(all(target_os = "macos", feature = "desk-probe"))]
    #[doc(hidden)]
    pub fn helper_pid_for_probe(&self) -> Option<u32> {
        self.0
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|generation| generation.pid)
    }

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

    /// Whether anything is drawn: the agent cursor is on (`agent_cursor` in
    /// the config) and not shut down.
    pub(crate) fn enabled(&self) -> bool {
        self.0.sender.get().is_some() && !self.0.stopped.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Tell `worker` of every end from now on: it hides the agent's preview
    /// before the hide line goes out.
    pub(crate) fn on_end(&self, worker: std::sync::Weak<PreviewWorker>) {
        let mut ends = self
            .0
            .preview_ends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ends.retain(|end| end.strong_count() > 0);
        ends.push(worker);
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
        self.end_locked(agent, &mut drawn);
        drop(drawn);
        self.finish_end(agent);
    }

    fn end_locked(&self, agent: &str, drawn: &mut Drawn) {
        drawn.active.remove(agent);
        #[cfg(any(target_os = "macos", test))]
        if let Some(listener) = self.0.turn_hints.get() {
            listener.ended(agent);
        }
        if drawn.ended_at.len() >= RECORD_CAP && !drawn.ended_at.contains_key(agent) {
            // Each entry only matters for the few milliseconds a geometry read
            // can still be running, so forgetting old ones loses nothing real.
            drawn.ended_at.clear();
        }
        drawn.ended_at.insert(
            agent.to_owned(),
            self.0.serial.load(std::sync::atomic::Ordering::SeqCst),
        );
        // The preview goes with the badge: nothing more is captured or timed
        // for it, and a later action shows it in a new generation. Hidden
        // while the record is held, so a preview about to be shown for an
        // action scheduled before this end either is shown first and hidden
        // here, or sees the end and is not shown.
        let ends: Vec<_> = self
            .0
            .preview_ends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        for worker in ends {
            worker.hide(agent);
        }
        // The helper takes the badge off the screen, so the agent's next
        // picture is a new appearance.
        drawn.tips.remove(agent);
        // Sent while holding the record, so a picture whose read finishes now
        // either goes out before this hide or sees the end and is dropped.
        self.send_line(CursorLine::Hide(CursorHide::new(agent)));
    }

    fn finish_end(&self, agent: &str) {
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
        let follow = Follow {
            id,
            serial: event.serial,
            source: source.clone(),
            window: window.clone(),
            element,
            base_window,
            // The frame the picture itself was drawn from, read with it.
            base_element: event.target,
            _watch: None,
        };
        {
            // Publish before installing the observer: it can report as soon
            // as it is registered, even before watch_cursor_window returns.
            // Checked and inserted under the record's lock, the same lock
            // `end` takes before removing the follow, so an end is either
            // seen here or removes this entry afterwards.
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
        // No locks across the platform call: it may call back synchronously.
        let watch = source.watch_cursor_window(
            &window,
            Box::new(move |change| {
                if let Some(state) = state.upgrade() {
                    Coordinator(state).window_changed(&followed, id, change);
                }
            }),
        );
        // `None` means this platform watches no windows at all (the trait's
        // default), so there is nothing to follow and the badge keeps its old
        // place until it fades. A platform that can watch but fails to install
        // a complete watch reports `Gone` through `changed` instead, which
        // hides the badge.
        let mut follows = self.follows();
        if let Some(follow) = follows.get_mut(agent).filter(|follow| follow.id == id) {
            if let Some(watch) = watch {
                follow._watch = Some(watch);
            } else {
                follows.remove(agent);
            }
        }
        // If an end, replacement or Gone report removed the entry during
        // installation, the returned watch is dropped rather than revived.
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
        if change == WindowChange::Gone {
            // Use the same lock order as picture publication and turn end.
            // A late report from an older watch must not hide a newer picture.
            let mut drawn = self.drawn();
            let mut follows = self.follows();
            let Some(follow) = follows.get(agent).filter(|follow| follow.id == id) else {
                return;
            };
            let serial = follow.serial;
            follows.remove(agent);
            if drawn
                .tips
                .get(agent)
                .is_some_and(|tip| tip.serial == serial)
            {
                drawn.tips.remove(agent);
                self.send_line(CursorLine::Hide(CursorHide::new(agent)));
            }
            // No restore notification is watched: a later action may draw a
            // fresh badge, but restoring the window alone leaves it hidden.
            return;
        }
        let current = {
            let follows = self.follows();
            let Some(follow) = follows.get(agent).filter(|follow| follow.id == id) else {
                // A watch already replaced or removed; its report is stale.
                return;
            };
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

    /// Core's fallback notification ends the active badges drawn by its scope.
    /// Live hints use the agent identity and runner sequence instead; both
    /// paths consume the same active appearance under the drawing lock.
    ///
    /// Badges are matched on the daemon-stamped `scope_ref`, the only session
    /// name a computer call carries. `session_ref` is the harness runner's own
    /// ref. When a live start has associated an agent with a runner session,
    /// the fallback must agree with that session too.
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
        let _ = outcome;
        let Some(scope_ref) = scope_ref else {
            return false;
        };
        let mut drawn = self.drawn();
        let agents: Vec<String> = drawn
            .active
            .iter()
            .filter(|(agent, session)| {
                session
                    .as_ref()
                    .is_some_and(|session| session.scope_ref == scope_ref)
                    && drawn
                        .hint_sessions
                        .get(*agent)
                        .is_none_or(|(_, session)| session == session_ref)
            })
            .map(|(agent, _)| agent.clone())
            .collect();
        let matched = !agents.is_empty();
        for agent in &agents {
            self.end_locked(agent, &mut drawn);
        }
        drop(drawn);
        for agent in &agents {
            self.finish_end(agent);
        }
        matched
    }

    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn turn_hint(&self, notice: crate::turn_hints::Notice) -> bool {
        if self.0.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let mut drawn = self.drawn();
        let key = (notice.module, notice.session.clone(), notice.agent.clone());
        if drawn
            .hint_sequences
            .get(&key)
            .is_some_and(|seq| notice.seq <= *seq)
        {
            return false;
        }
        if drawn.hint_sequences.len() >= RECORD_CAP && !drawn.hint_sequences.contains_key(&key) {
            // Missing a cosmetic hint is safer than forgetting a known start
            // and then accepting an older end for a badge already tracked.
            return false;
        }
        drawn.hint_sequences.insert(key, notice.seq);
        if notice.kind == crate::turn_hints::Kind::Started {
            drawn
                .hint_sessions
                .insert(notice.agent, (notice.module, notice.session));
            return false;
        }
        if !drawn.active.contains_key(&notice.agent)
            || drawn
                .hint_sessions
                .get(&notice.agent)
                .is_some_and(|(module, session)| {
                    *module != notice.module || *session != notice.session
                })
        {
            return false;
        }
        self.end_locked(&notice.agent, &mut drawn);
        drop(drawn);
        self.finish_end(&notice.agent);
        crate::turn_hints::HINT_GAUGES.matched();
        true
    }

    /// Remember who is drawing this badge, before any read starts, so an end
    /// that arrives while the read is still running still finds it.
    fn record(&self, identity: &Identity) {
        let agent = &identity.badge;
        if let Some(call) = &identity.call {
            call.note_cursor_agent(agent);
        }
        let mut drawn = self.drawn();
        if drawn.active.len() >= RECORD_CAP && !drawn.active.contains_key(agent) {
            drawn.active.clear();
        }
        drawn.active.insert(agent.clone(), identity.session.clone());
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
        #[cfg(any(target_os = "macos", test))]
        self.note_queued_badge(&agent);
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
    pub(crate) fn send_preview(&self, preview: CursorPreview) -> bool {
        self.send_line(CursorLine::Preview(preview))
    }

    /// Queue a frame for an agent's preview. It never waits and never starts
    /// the helper, and it is not an action: the badge's idle clock is not
    /// restarted by it. At most one frame per agent waits for the pipe; a
    /// newer one replaces it. A frame over `MAX_FRAME_BYTES` is dropped.
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
    #[cfg(test)]
    pub(crate) fn schedule_preview_motion(
        &self,
        motion: CursorPreviewMotion,
        thumbnail: [f64; 2],
    ) -> Arrival {
        if !self.enabled() || !thumbnail.iter().all(|v| v.is_finite() && *v > 0.0) {
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
        let sent =
            self.send_preview_motion(&mut self.drawn(), motion, thumbnail, serial, scheduled);
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
            preview_call: None,
        }
    }

    /// Choose the motion for `motion` from where its badge last was, put
    /// the line on the pipe and record where the badge now is. Answers how
    /// an action waits for it, or `None` when nothing will be drawn.
    fn send_preview_motion(
        &self,
        drawn: &mut Drawn,
        mut motion: CursorPreviewMotion,
        thumbnail: [f64; 2],
        serial: u64,
        now: tokio::time::Instant,
    ) -> Option<Sent> {
        let agent = motion.pmotion_agent.clone();
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
            now,
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
            #[cfg(any(target_os = "macos", test))]
            self.note_queued_badge(&agent);
        }
        sent.flatten().map(|written| Sent {
            duration: Duration::from_secs_f64(chosen.duration_ms / 1000.0),
            written,
        })
    }

    /// Schedule a background-mode action's badge inside its agent's preview.
    ///
    /// The agent's preview slot is taken first, so a fourth agent learns at
    /// once that it gets no preview: it then gets no badge and no arrival
    /// wait, and its call's reply says `preview: "not_shown_capacity"`.
    /// Otherwise, within the same read budget as an on-screen picture, the
    /// window the action addresses is read (`preview_window`, one read for
    /// its id and bounds), the preview is shown or retargeted to it, and the
    /// badge moves inside it to the addressed element's visible centre (or
    /// the exact point) as a `PreviewMotion` line, which the action waits
    /// for as it would for a picture. A preview showing the application's
    /// icon, an element with no geometry in that window, or a read that
    /// finds nothing makes no motion and no wait.
    ///
    /// Nothing is ever drawn on the screen from here: a window that cannot
    /// be read means no badge and no wait for this action, because an
    /// on-screen badge would point at whatever covers the application.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn schedule_in_preview(
        &self,
        identity: Identity,
        kind: CursorKind,
        grant: ProcessGrant,
        source: Arc<dyn AppStateSource>,
        aim: ReadAim,
        point: Option<[f64; 2]>,
        preview: PreviewAim,
    ) -> Arrival {
        if !self.enabled() {
            return Arrival::none();
        }
        let agent = identity.badge.clone();
        if preview.worker.reserve(&agent).is_none() {
            if let Some(call) = &preview.call {
                call.note_not_shown_capacity();
            }
            return Arrival::none();
        }
        // Numbered before it is recorded: an end that lands in between then
        // counts this badge as scheduled before it, and drops it.
        let serial = self
            .0
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.record(&identity);
        self.refresh_reduce_motion();
        let (decided, decision) = oneshot::channel();
        let arrival = Arrival {
            decision: Some(decision),
            scheduled: tokio::time::Instant::now(),
            queued: Arc::default(),
            watch: Some(BadgeWatch {
                cursor: self.clone(),
                agent: agent.clone(),
                serial,
            }),
            preview_call: preview.call.clone(),
        };
        let decision = (
            decided,
            arrival.queued.clone(),
            arrival.scheduled + ARRIVAL_CAP,
        );
        let cursor = self.clone();
        tokio::spawn(async move {
            let avatar_agent = identity.avatar_agent;
            let (read_source, read_grant) = (source.clone(), grant.clone());
            let (frontmost, bundle) = (preview.frontmost.clone(), preview.bundle.clone());
            let choice = preview.window;
            let read = tokio::task::spawn_blocking(move || {
                background_read(
                    read_source.as_ref(),
                    &read_grant,
                    kind,
                    aim,
                    point,
                    choice,
                    frontmost.as_ref(),
                    bundle.as_ref(),
                )
            });
            match tokio::time::timeout(READ_BUDGET, read).await {
                Ok(Ok(Some(aimed))) => {
                    cursor
                        .draw_in_preview(
                            aimed,
                            PreviewDraw {
                                agent,
                                serial,
                                kind,
                                grant,
                                app: preview.app,
                                worker: preview.worker,
                                call: preview.call,
                            },
                            avatar_agent,
                            decision,
                        )
                        .await;
                }
                // No window could be read, or the read failed or ran out of
                // time: `decided` is dropped, so nothing is drawn and
                // nothing is waited for.
                _ => preview.worker.release_unshown(&agent),
            }
        });
        arrival
    }

    /// Show the agent's preview of the window read for its action and move
    /// its badge there, then answer the action waiting for it.
    async fn draw_in_preview(
        &self,
        aimed: PreviewAimed,
        draw: PreviewDraw,
        avatar_agent: Option<String>,
        (decided, queued, cap): Decision,
    ) {
        let PreviewDraw {
            agent,
            serial,
            kind,
            grant,
            app,
            worker,
            call,
        } = draw;
        let now = tokio::time::Instant::now();
        let sent = {
            // Held across the show, the same record `end` hides previews
            // under: an end either comes first and is seen here, or comes
            // after and hides the preview shown here.
            let mut drawn = self.drawn();
            if drawn
                .ended_at
                .get(&agent)
                .is_some_and(|ended| serial < *ended)
            {
                drop(drawn);
                worker.release_unshown(&agent);
                return;
            }
            let outcome = worker.show(PreviewRequest {
                agent: agent.clone(),
                target: grant,
                window: aimed.window,
                app,
                icon_path: aimed.icon_path,
                label: aimed.label,
                backing_scale: PREVIEW_BACKING_SCALE,
            });
            match outcome {
                ShowOutcome::NotShownCapacity => {
                    if let Some(call) = &call {
                        call.note_not_shown_capacity();
                    }
                    None
                }
                ShowOutcome::Shown {
                    generation,
                    thumbnail,
                    icon,
                    ..
                } => {
                    if let Some(call) = &call {
                        call.showing(&worker, &agent);
                    }
                    match aimed.to.filter(|_| !icon) {
                        Some((to, target)) => self.send_preview_motion(
                            &mut drawn,
                            CursorPreviewMotion {
                                pmotion_agent: agent.clone(),
                                pmotion_serial: serial,
                                pmotion_generation: generation,
                                pmotion_window: aimed.window.id,
                                pmotion_kind: kind,
                                pmotion_to: to,
                                pmotion_target: target,
                                // Chosen as the line is sent.
                                pmotion_motion: PictureMotion::still(),
                            },
                            thumbnail,
                            serial,
                            now,
                        ),
                        None => None,
                    }
                }
            }
        };
        let drew = sent.is_some();
        tokio::spawn(self.clone().decide(decided, sent, queued, cap));
        #[cfg(target_os = "macos")]
        if drew {
            self.send_avatar(
                avatar_agent,
                CursorEvent {
                    initial: agent.chars().next().unwrap_or('A').to_ascii_uppercase(),
                    agent,
                    // Ignored for a badge inside a preview.
                    to: [0.0, 0.0],
                    target: None,
                    resting: true,
                    label: None,
                    kind,
                    serial,
                    avatar_rgba: None,
                    avatar_update: false,
                    avatar_tint: None,
                    motion: PictureMotion::still(),
                },
            )
            .await;
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (drew, avatar_agent);
    }

    /// The whole optional read has a deadline. A slow AX reply may still finish
    /// on its blocking thread, but it can never emit a late picture or hold an
    /// action. Do not change a retained AX element's timeout: dispatch shares it.
    ///
    /// Actions schedule their badges through `preview_call::Badges`, which
    /// picks the screen or the preview; this draws on the screen alone.
    #[cfg(test)]
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
            preview_call: None,
        };
        let (queued, cap) = (arrival.queued.clone(), arrival.scheduled + ARRIVAL_CAP);
        tokio::spawn(async move {
            let agent = identity.badge;
            let avatar_agent = identity.avatar_agent;
            let (read_source, read_grant) = (source.clone(), grant.clone());
            let read = tokio::task::spawn_blocking(move || {
                screen_read(
                    read_source.as_ref(),
                    &read_grant,
                    kind,
                    aim,
                    point,
                    agent,
                    serial,
                )
            });
            // A read that fails or runs out of time drops `decided`, which
            // tells a waiting action that no badge will be drawn.
            if let Ok(Ok(Some((event, followed_element)))) =
                tokio::time::timeout(READ_BUDGET, read).await
            {
                cursor
                    .draw_on_screen(
                        event,
                        followed_element,
                        grant,
                        source,
                        avatar_agent,
                        (decided, queued, cap),
                    )
                    .await;
            }
        });
        arrival
    }

    /// Send an on-screen picture whose geometry was read, answer the action
    /// waiting for it through `decided`, then follow its window and bring in
    /// the agent's avatar.
    async fn draw_on_screen(
        &self,
        event: CursorEvent,
        followed_element: Option<ElementHandle>,
        grant: ProcessGrant,
        source: Arc<dyn AppStateSource>,
        avatar_agent: Option<String>,
        (decided, queued, cap): Decision,
    ) {
        #[cfg(not(target_os = "macos"))]
        let _ = &avatar_agent;
        // A badge for an agent whose avatar colour is already known
        // starts in that colour rather than the neutral one.
        #[cfg(target_os = "macos")]
        let event = {
            let mut event = event;
            if let (Some(agent), Some(avatars)) = (avatar_agent.as_deref(), self.0.avatars.get()) {
                event.avatar_tint = avatars.known_tint(agent).flatten();
            }
            event
        };
        // Its own task: the wait for the write must not hold up the
        // window watch or the avatar below.
        let sent = self.send_unless_ended(event.clone());
        tokio::spawn(self.clone().decide(decided, sent, queued, cap));
        // Off the read's deadline: following the window is a nicety
        // that must never hold up or drop the picture itself.
        let follower = self.clone();
        let followed = event.clone();
        let _ = tokio::task::spawn_blocking(move || {
            follower.follow(&followed, &grant, &source, followed_element)
        })
        .await;
        #[cfg(target_os = "macos")]
        self.send_avatar(avatar_agent, event).await;
    }

    /// Fetch the agent's avatar and send it as an update to `event`'s badge,
    /// which shows it in whichever space the badge is drawn.
    #[cfg(target_os = "macos")]
    async fn send_avatar(&self, avatar_agent: Option<String>, event: CursorEvent) {
        if let (Some(agent), Some(avatars)) = (avatar_agent, self.0.avatars.get()) {
            if let Some(rendered) = avatars.fetch_and_render(&agent).await {
                let mut update = event;
                update.avatar_rgba = Some(rendered.pixels);
                update.avatar_tint = rendered.tint;
                update.avatar_update = true;
                self.send(update);
            }
        }
    }

    /// Signal before browser teardown starts. Reaping and any blocked pipe write
    /// belong to the transport thread, never to the twenty-second drain budget.
    pub fn shutdown(&self) {
        #[cfg(any(target_os = "macos", test))]
        if let Some(listener) = self.0.turn_hints.get() {
            listener.shutdown();
        }
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
    /// For a badge inside the background-mode preview, the call it belongs
    /// to: a wait that reaches the cap ahead of the badge says so there, and
    /// the reply carries `preview: "not_synchronized"`.
    preview_call: Option<Arc<PreviewCall>>,
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
            preview_call: None,
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
                    if let Some(call) = &self.preview_call {
                        call.note_not_synchronized();
                    }
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
            preview_call: None,
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

    #[cfg(test)]
    pub(crate) fn send_scheduled_for_test(&self, event: CursorEvent) {
        self.send_unless_ended(event);
    }
}

/// The geometry read for an on-screen picture, on a blocking thread: the
/// picture to send and the element it was aimed at, or `None` when nothing
/// should be drawn.
fn screen_read(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
    kind: CursorKind,
    aim: ReadAim,
    point: Option<[f64; 2]>,
    agent: String,
    serial: u64,
) -> Option<(CursorEvent, Option<ElementHandle>)> {
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
    if point.is_none() && frame.is_none() && matches!(kind, CursorKind::Press | CursorKind::Write) {
        return None;
    }
    let to = source.visible_cursor_point(grant, point, frame)?;
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
}

/// The geometry read for a background-mode badge, on a blocking thread.
///
/// The preview's window is read first, as one id and its bounds
/// (`preview_window`), and the badge is placed relative to that same window:
/// an element action's element, the focused element for `keys` and `type`,
/// and for a read its element (or the focused one) when it lies in the
/// window. An exact point (a press on an image point) is where the tip goes.
/// A press or a write with no geometry in the window makes no motion. With
/// no window at all, `None`: nothing is drawn.
#[allow(clippy::too_many_arguments)]
fn background_read(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
    kind: CursorKind,
    aim: ReadAim,
    point: Option<[f64; 2]>,
    choice: WindowChoice,
    frontmost: &(dyn Fn(&ProcessGrant) -> Option<u32> + Send + Sync),
    bundle: &(dyn Fn(&ProcessGrant) -> Option<String> + Send + Sync),
) -> Option<PreviewAimed> {
    let which = match (choice, aim.preferred.as_ref()) {
        (WindowChoice::Element, Some(element)) => PreviewWindowSource::Element(element),
        (WindowChoice::Element, None) => PreviewWindowSource::Focused(None),
        (WindowChoice::Frontmost, _) => PreviewWindowSource::Frontmost(frontmost(grant)),
    };
    let window = preview_window(source, grant, which)?;
    let mut frame = aim
        .preferred
        .as_ref()
        .and_then(|element| source.cursor_frame(element));
    if kind == CursorKind::Reading && frame.is_none() {
        frame = aim
            .focused
            .as_ref()
            .and_then(|element| source.cursor_frame(element));
    }
    let label = match (kind, aim.preferred.as_ref()) {
        // A read's badge has no label, so it reads no title.
        (CursorKind::Reading, _) => None,
        (_, Some(element)) => {
            let (title, secure) = source.cursor_label(element).unwrap_or((None, true));
            label(kind, title.as_deref(), secure)
        }
        (_, None) => label(kind, None, false),
    };
    let target = frame.and_then(|frame| window.visible_target(frame));
    let to = match point.and_then(|point| window.relative(point)) {
        Some(tip) => Some((tip, target.unwrap_or(tip))),
        None => target.map(|target| (target, target)),
    };
    Some(PreviewAimed {
        window,
        to,
        label,
        icon_path: bundle(grant),
    })
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
        if written && matches!(line, CursorLine::Frame(_)) {
            state
                .gauges
                .get()
                .copied()
                .unwrap_or(&PREVIEW_GAUGES)
                .frame_written();
        }
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
        #[cfg(any(target_os = "macos", test))]
        let badge = match line {
            CursorLine::Picture(event) => !event.avatar_update && !event.agent.is_empty(),
            CursorLine::PreviewMotion(_) => true,
            _ => false,
        };
        #[cfg(any(target_os = "macos", test))]
        if written.is_some() && badge && !self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            let drawn = self
                .drawn
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !drawn
                .ended_at
                .get(&key.0)
                .is_some_and(|ended| key.1 < *ended)
            {
                if let Some(listener) = self.turn_hints.get() {
                    listener.drawn(&key.0);
                }
            }
        }
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
    let helper = helper_transport::shared();
    write_lines(&state, &mut rx, |event| {
        let written = helper.write(&state, event);
        *state
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = written.generation;
        state.helper_down.store(
            written.generation.is_none(),
            std::sync::atomic::Ordering::Release,
        );
        written.written
    });
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

    /// Count written frame lines in `gauges` instead of the process's.
    #[cfg(test)]
    pub(crate) fn counting_frames_in(self, gauges: &'static PreviewGauges) -> Self {
        let _ = self.0.gauges.set(gauges);
        self
    }

    /// How many awaited lines the writer has settled so far.
    #[cfg(test)]
    fn settled(&self) -> usize {
        self.0.settled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn unavailable_startup_binary_refuses_launch_and_is_reported_in_health() {
        assert!(super::helper_launch_path(None).is_none());
        let report = crate::with_process_gauges(crate::HealthState::new().report());
        let subc_protocol::session::ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = report
        else {
            panic!("health metrics");
        };
        assert_eq!(metrics["cursorHelperBinaryUnavailable"], true);
    }

    use super::*;
    use crate::test_support::HANG_GUARD;
    use cerebellum_computer::cursor::MAX_FRAME_BYTES;

    /// Geometry that takes the given time to read.
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
            )
        });
        let scheduled = tokio::time::timeout(HANG_GUARD, scheduling).await;
        if scheduled.is_err() {
            let _ = release_tx.send(());
            panic!("scheduling waited for the blocked geometry read");
        }
        let arrival = scheduled.unwrap().unwrap();
        tokio::time::timeout(HANG_GUARD, started_rx)
            .await
            .expect("the geometry worker never started")
            .unwrap();
        let runtime_work = tokio::time::timeout(HANG_GUARD, tokio::spawn(async { "completed" }))
            .await
            .expect("the runtime stopped dispatching while geometry was blocked")
            .unwrap();
        assert_eq!(runtime_work, "completed");
        // The geometry is still held. Its decision must finish without a
        // picture, rather than merely leaving the helper quiet for a while.
        assert!(receiver.try_recv().is_err());
        let decision = arrival.decision.expect("a scheduled geometry decision");
        tokio::time::timeout(HANG_GUARD, async {
            tokio::select! {
                result = decision => assert!(result.is_err(), "a timed-out read drops its decision"),
                line = receiver.recv() => panic!("late geometry reached the helper: {line:?}"),
            }
        })
        .await
        .expect("the blocked geometry read never reached its deadline");
        release_tx.send(()).unwrap();
        tokio::time::timeout(HANG_GUARD, finished_rx)
            .await
            .expect("the released geometry worker did not finish")
            .unwrap();
        assert!(receiver.try_recv().is_err(), "a late picture was sent");
    }

    /// Await a worker without letting an idle runtime advance paused time past
    /// its geometry deadline. Real time is used only to detect a hung test.
    async fn frozen_step<F: Future>(step: F) -> F::Output {
        tokio::pin!(step);
        let start = std::time::Instant::now();
        loop {
            tokio::select! {
                biased;
                result = &mut step => return result,
                () = tokio::task::yield_now() => {}
            }
            assert!(start.elapsed() < HANG_GUARD, "the frozen step hung");
        }
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
            preview_call: None,
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

    #[tokio::test(start_paused = true)]
    async fn a_picture_scheduled_before_an_end_does_not_bring_the_badge_back() {
        let (cursor, mut receiver) = Coordinator::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let geometry = Arc::new(HeldGeometry {
            started: std::sync::Mutex::new(Some(started_tx)),
            release: std::sync::Mutex::new(Some(release_rx)),
            finished: std::sync::Mutex::new(Some(finished_tx)),
        });
        let schedule = || {
            cursor.schedule(
                Identity::for_test("agent-a", None, None),
                CursorKind::Press,
                grant(),
                geometry.clone(),
                Some(
                    cerebellum_computer::app_state::source::RawElement::fixture(1, "AXButton")
                        .handle,
                ),
                // The fixture shows a picture only where it is told to aim.
                Some([1.0, 1.0]),
            )
        };
        let arrival = schedule();
        frozen_step(started_rx).await.unwrap();
        cursor.end("agent-a");
        let hide = receiver.try_recv().expect("end sends a hide synchronously");
        assert_eq!(hidden(hide), "agent-a");
        release_tx.send(()).unwrap();
        frozen_step(finished_rx).await.unwrap();
        // Keep Tokio time frozen while the blocking worker completes, so the
        // geometry deadline cannot expire and discard the read before the
        // ended-agent check suppresses its picture.
        let decision = arrival.decision.expect("a scheduled geometry decision");
        frozen_step(async {
            tokio::select! {
                result = decision => assert!(matches!(result, Ok(None))),
                line = receiver.recv() => panic!("the ended badge was redrawn: {line:?}"),
            }
        })
        .await;
        assert!(receiver.try_recv().is_err());
        schedule();
        let picture = frozen_step(receiver.recv())
            .await
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
        watch_release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        refuse_watch: std::sync::atomic::AtomicBool,
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
                watch_release: std::sync::Mutex::new(None),
                refuse_watch: std::sync::atomic::AtomicBool::new(false),
            })
        }

        fn live(&self) -> usize {
            self.live.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn created(&self) -> usize {
            self.watches.lock().unwrap().len()
        }

        /// Hold the next watch's return after its callback is live, so a
        /// report during observer installation does not depend on scheduling.
        fn hold_next_watch(&self) -> std::sync::mpsc::Sender<()> {
            let (release, held) = std::sync::mpsc::channel();
            *self.watch_release.lock().unwrap() = Some(held);
            release
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
            if self.refuse_watch.load(std::sync::atomic::Ordering::SeqCst) {
                return None;
            }
            self.watches.lock().unwrap().push(Arc::from(changed));
            self.live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let held = self.watch_release.lock().unwrap().take();
            if let Some(held) = held {
                held.recv_timeout(HANG_GUARD)
                    .expect("released window watch installation");
            }
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
        next_line_for(receiver, "a cursor line").await
    }

    async fn next_line_for(receiver: &mut mpsc::Receiver<CursorLine>, what: &str) -> CursorLine {
        tokio::time::timeout(HANG_GUARD, receiver.recv())
            .await
            .unwrap_or_else(|error| panic!("{what} before HANG_GUARD: {error}"))
            .unwrap()
    }

    fn no_line(receiver: &mut mpsc::Receiver<CursorLine>, why: &str) {
        // FollowGeometry::fire runs the callback, including its helper send,
        // synchronously. There is no producer left to wait for after it returns.
        if let Ok(line) = receiver.try_recv() {
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
        let release = geometry.hold_next_watch();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        let picture = next_line_for(&mut receiver, "the initial picture")
            .await
            .picture()
            .unwrap();
        assert_eq!(picture.to, [445.0, 131.0], "the element's centre");
        until("watched the window", || geometry.live() == 1).await;

        // The person drags the window 120 right and 40 up.
        FollowGeometry::shift(&geometry.window_frame, [120.0, -40.0, 0.0, 0.0]);
        geometry.fire(0, WindowChange::Moved);
        release.send(()).unwrap();
        assert_eq!(
            next_line_for(&mut receiver, "the first move Follow").await,
            CursorLine::Follow(CursorFollow {
                agent: AGENT.into(),
                serial: picture.serial,
                offset: [120.0, -40.0],
            })
        );
        until("finished installing the watch", || {
            cursor
                .follows()
                .get(AGENT)
                .is_some_and(|follow| follow._watch.is_some())
        })
        .await;

        // Then widens it from the left edge: the element is laid out again
        // and is now 90 right and 40 up of where the picture was drawn.
        FollowGeometry::shift(&geometry.window_frame, [-60.0, 0.0, 60.0, 0.0]);
        FollowGeometry::shift(&geometry.element_frame, [90.0, -40.0, 0.0, 0.0]);
        geometry.fire(0, WindowChange::Resized);
        assert_eq!(
            next_line_for(&mut receiver, "the resize Follow").await,
            CursorLine::Follow(CursorFollow {
                agent: AGENT.into(),
                serial: picture.serial,
                offset: [90.0, -40.0],
            })
        );

        // A minimized, closed or app-hidden window must not leave its badge
        // floating over whatever is underneath it.
        geometry.fire(0, WindowChange::Gone);
        assert_eq!(hidden(next_line(&mut receiver).await), AGENT);
        assert!(!cursor.drawn().tips.contains_key(AGENT));
        assert_eq!(geometry.live(), 0, "the closed window's watch was kept");
        geometry.fire(0, WindowChange::Moved);
        no_line(&mut receiver, "a released watch still reported");
    }

    #[tokio::test]
    async fn a_followed_window_gone_hides_the_badge_immediately() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = FollowGeometry::new();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        next_line(&mut receiver).await.picture().unwrap();
        until("installed the window watch", || {
            cursor
                .follows()
                .get(AGENT)
                .is_some_and(|follow| follow._watch.is_some())
        })
        .await;

        geometry.fire(0, WindowChange::Gone);
        assert_eq!(
            hidden(
                receiver
                    .try_recv()
                    .expect("window gone must hide immediately")
            ),
            AGENT
        );
        assert!(!cursor.drawn().tips.contains_key(AGENT));
        assert!(!cursor.drawn().ended_at.contains_key(AGENT));
        assert_eq!(geometry.live(), 0);
        geometry.fire(0, WindowChange::Moved);
        no_line(&mut receiver, "a restored window revived the badge");
    }

    #[tokio::test]
    async fn a_platform_without_window_watches_keeps_the_badge_unfollowed() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = FollowGeometry::new();
        geometry
            .refuse_watch
            .store(true, std::sync::atomic::Ordering::SeqCst);
        schedule_on(&cursor, &geometry, CursorKind::Press);
        next_line(&mut receiver).await.picture().unwrap();
        until("dropped the unwatchable follow", || {
            cursor.follows().is_empty()
        })
        .await;
        no_line(
            &mut receiver,
            "a platform without window watches hid the badge",
        );
        assert!(cursor.drawn().tips.contains_key(AGENT));
        assert_eq!(geometry.live(), 0);
    }

    #[tokio::test]
    async fn an_older_window_gone_report_does_not_hide_a_new_picture() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = FollowGeometry::new();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        let first = next_line(&mut receiver).await.picture().unwrap();
        until("installed the window watch", || {
            cursor
                .follows()
                .get(AGENT)
                .is_some_and(|follow| follow._watch.is_some())
        })
        .await;

        // The new picture is queued before its replacement watch is installed.
        let mut newer = picture(AGENT);
        newer.serial = first.serial + 1;
        cursor.send_unless_ended(newer.clone());
        next_line(&mut receiver).await.picture().unwrap();
        geometry.fire(0, WindowChange::Gone);
        no_line(&mut receiver, "the old window hid a newer picture");
        assert_eq!(cursor.drawn().tips[AGENT].serial, newer.serial);
        assert_eq!(geometry.live(), 0);
    }

    #[tokio::test]
    async fn a_window_closed_during_watch_installation_is_not_followed() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = FollowGeometry::new();
        let release = geometry.hold_next_watch();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        next_line(&mut receiver).await.picture().unwrap();
        until("registered the callback", || geometry.live() == 1).await;

        geometry.fire(0, WindowChange::Gone);
        assert!(!cursor.follows().contains_key(AGENT));
        assert_eq!(hidden(next_line(&mut receiver).await), AGENT);
        release.send(()).unwrap();
        until("released the closed window's watch", || {
            geometry.live() == 0
        })
        .await;
        assert!(!cursor.follows().contains_key(AGENT));
        geometry.fire(0, WindowChange::Moved);
        no_line(
            &mut receiver,
            "a closed window's installing watch was revived",
        );
    }

    #[tokio::test]
    async fn ending_a_badge_during_watch_installation_drops_the_returned_watch() {
        let (cursor, mut receiver) = Coordinator::channel();
        let geometry = FollowGeometry::new();
        let release = geometry.hold_next_watch();
        schedule_on(&cursor, &geometry, CursorKind::Press);
        next_line(&mut receiver).await.picture().unwrap();
        until("registered the callback", || geometry.live() == 1).await;

        cursor.end(AGENT);
        assert_eq!(hidden(next_line(&mut receiver).await), AGENT);
        assert!(!cursor.follows().contains_key(AGENT));
        release.send(()).unwrap();
        until("released the ended badge's watch", || geometry.live() == 0).await;
        assert!(!cursor.follows().contains_key(AGENT));
        geometry.fire(0, WindowChange::Moved);
        no_line(
            &mut receiver,
            "an ended badge's installing watch was revived",
        );
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
            geometry.created() == 2
                && geometry.live() == 1
                && cursor
                    .follows()
                    .get(AGENT)
                    .is_some_and(|follow| follow._watch.is_some())
        })
        .await;
        FollowGeometry::shift(&geometry.window_frame, [5.0, 5.0, 0.0, 0.0]);
        geometry.fire(0, WindowChange::Moved);
        no_line(&mut receiver, "the replaced watch moved the badge");

        // The turn ends: the badge hides and its window is no longer watched.
        cursor.end(AGENT);
        assert_eq!(hidden(next_line(&mut receiver).await), AGENT);
        assert_eq!(geometry.live(), 0, "the hidden badge's watch was kept");
        geometry.fire(1, WindowChange::Moved);
        no_line(&mut receiver, "a hidden badge was moved");
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

/// Drawing and safety queries share one serialized, process-lifetime helper
/// transport. Disabling badges never disables or shuts down the query service.
#[cfg(target_os = "macos")]
mod helper_transport {
    use super::*;
    use cerebellum_computer::pointer_query::{self, QueryProvider};
    use cerebellum_macos::ProcessGeneration;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc as pipe,
    };

    static SHARED: OnceLock<Service> = OnceLock::new();

    pub(super) fn shared() -> &'static Service {
        SHARED.get_or_init(|| Service::start(NativeLauncher))
    }

    pub(super) fn install_queries() {
        pointer_query::set_provider(Some(shared().provider()));
        let service = shared().clone();
        pointer_query::set_prewarm_provider(Some(Arc::new(move |deadline| {
            service.prewarm(deadline)
        })));
    }

    pub(super) fn shutdown() {
        pointer_query::set_provider(None);
        pointer_query::set_prewarm_provider(None);
        if let Some(service) = SHARED.get() {
            service.stop();
        }
    }

    trait Helper: Send + 'static {
        fn alive(&self) -> bool;
        fn generation(&self) -> ProcessGeneration;
        fn write(&mut self, bytes: &[u8]) -> bool;
        fn wait_ready(&mut self, deadline: Instant) -> Result<(), &'static str>;
        fn query(
            &mut self,
            point: [f64; 2],
            deadline: Instant,
        ) -> Result<Option<u32>, &'static str>;
    }

    trait Launcher: Send + 'static {
        type Helper: Helper;
        fn screen_unlocked(&self) -> bool;
        fn launch(&mut self, deadline: Option<Instant>) -> Result<Self::Helper, &'static str>;
        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    #[derive(Default)]
    pub(super) struct Written {
        pub(super) written: bool,
        pub(super) generation: Option<ProcessGeneration>,
    }

    enum Command {
        Prewarm {
            deadline: Instant,
            reply: pipe::SyncSender<Result<(), &'static str>>,
        },
        Visual {
            owner: Arc<State>,
            bytes: Vec<u8>,
            launches: bool,
            reply: pipe::SyncSender<Written>,
        },
        Query {
            point: [f64; 2],
            deadline: Instant,
            reply: pipe::SyncSender<Result<Option<u32>, &'static str>>,
        },
        Stop,
    }

    #[derive(Clone)]
    pub(super) struct Service {
        tx: pipe::SyncSender<Command>,
        stopped: Arc<AtomicBool>,
    }

    impl Service {
        fn start<L: Launcher>(launcher: L) -> Self {
            let (tx, rx) = pipe::sync_channel(CAPACITY);
            let stopped = Arc::new(AtomicBool::new(false));
            let ending = stopped.clone();
            if std::thread::Builder::new()
                .name("agent-helper-transport".into())
                .spawn(move || {
                    let mut worker = Worker {
                        launcher,
                        helper: None,
                        restarts: RestartLimit::default(),
                    };
                    while let Ok(command) = rx.recv() {
                        if ending.load(Ordering::Acquire) {
                            break;
                        }
                        match command {
                            Command::Prewarm { deadline, reply } => {
                                let result = worker.ensure(true, Some(deadline)).and_then(|()| {
                                    worker.helper.as_mut().unwrap().wait_ready(deadline)
                                });
                                let _ = reply.try_send(result);
                            }
                            Command::Query {
                                point,
                                deadline,
                                reply,
                            } => {
                                let result = worker.ensure(true, Some(deadline)).and_then(|()| {
                                    worker.helper.as_mut().unwrap().query(point, deadline)
                                });
                                if matches!(
                                    result,
                                    Err("mouse-down recipient helper disconnected"
                                        | "mouse-down recipient helper request write failed"
                                        | "mouse-down recipient helper reply malformed")
                                ) {
                                    worker.helper.take();
                                }
                                let _ = reply.try_send(result);
                            }
                            Command::Visual {
                                owner,
                                bytes,
                                launches,
                                reply,
                            } => {
                                // Cosmetic writes retain their existing launch behavior,
                                // but reuse the same helper process and restart allowance.
                                let mut written = Written::default();
                                if !owner.stopped.load(Ordering::Acquire)
                                    && worker.ensure(launches, None).is_ok()
                                    && !owner.stopped.load(Ordering::Acquire)
                                {
                                    let helper = worker.helper.as_mut().unwrap();
                                    written.written = helper.write(&bytes);
                                    if written.written {
                                        written.generation = Some(helper.generation());
                                    } else {
                                        worker.helper.take();
                                    }
                                }
                                let _ = reply.try_send(written);
                            }
                            Command::Stop => break,
                        }
                    }
                })
                .is_err()
            {
                stopped.store(true, Ordering::Release);
            }
            Self { tx, stopped }
        }

        fn provider(&self) -> QueryProvider {
            let service = self.clone();
            Arc::new(move |point, deadline| service.query(point, deadline))
        }

        fn prewarm(&self, deadline: Instant) -> Result<(), &'static str> {
            if self.stopped.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err("mouse-down recipient helper launch budget exceeded");
            }
            let (reply, answer) = pipe::sync_channel(1);
            self.tx
                .try_send(Command::Prewarm { deadline, reply })
                .map_err(|_| "mouse-down recipient helper transport busy or unavailable")?;
            answer
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| "mouse-down recipient helper launch budget exceeded")?
        }

        fn query(&self, point: [f64; 2], deadline: Instant) -> Result<Option<u32>, &'static str> {
            if self.stopped.load(Ordering::Acquire) {
                return Err("mouse-down recipient helper transport stopped");
            }
            if Instant::now() >= deadline {
                return Err("mouse-down recipient helper launch/query budget exceeded");
            }
            let (reply, answer) = pipe::sync_channel(1);
            self.tx
                .try_send(Command::Query {
                    point,
                    deadline,
                    reply,
                })
                .map_err(|_| "mouse-down recipient helper transport busy or unavailable")?;
            let result = answer
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| "mouse-down recipient helper launch/query budget exceeded")?;
            if Instant::now() >= deadline {
                return Err("mouse-down recipient helper launch/query budget exceeded");
            }
            result
        }

        pub(super) fn write(&self, owner: &Arc<State>, line: &CursorLine) -> Written {
            let Some(bytes) = line.encode_line() else {
                return Written::default();
            };
            let (reply, answer) = pipe::sync_channel(1);
            if self.stopped.load(Ordering::Acquire)
                || self
                    .tx
                    .try_send(Command::Visual {
                        owner: owner.clone(),
                        bytes,
                        launches: line.launches_helper(),
                        reply,
                    })
                    .is_err()
            {
                return Written::default();
            }
            answer.recv().unwrap_or_default()
        }

        fn stop(&self) {
            self.stopped.store(true, Ordering::Release);
            let _ = self.tx.try_send(Command::Stop);
        }
    }

    struct Worker<L: Launcher> {
        launcher: L,
        helper: Option<L::Helper>,
        restarts: RestartLimit,
    }

    impl<L: Launcher> Worker<L> {
        fn ensure(
            &mut self,
            launches: bool,
            deadline: Option<Instant>,
        ) -> Result<(), &'static str> {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err("mouse-down recipient helper launch budget exceeded");
            }
            if !self.launcher.screen_unlocked() {
                return Err("mouse-down recipient helper screen locked or unreadable");
            }
            if self.helper.as_ref().is_some_and(|helper| !helper.alive()) {
                self.helper.take();
            }
            if self.helper.is_none() {
                if !launches {
                    return Err("mouse-down recipient helper unavailable");
                }
                if !self.restarts.admit(self.launcher.now()) {
                    return Err("mouse-down recipient helper restart limit reached");
                }
                let helper = self.launcher.launch(deadline)?;
                // A slow spawn may finish after its caller has already refused.
                // Drop that child rather than retain a late startup as readiness.
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err("mouse-down recipient helper launch budget exceeded");
                }
                self.helper = Some(helper);
            }
            Ok(())
        }
    }

    struct NativeLauncher;
    struct NativeHelper {
        child: cerebellum_macos::ReleasedChild,
        pipe: Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>>,
        client: pointer_query::Client,
    }

    impl Drop for NativeHelper {
        fn drop(&mut self) {
            cerebellum_macos::register_cursor_generation(None);
        }
    }

    impl Helper for NativeHelper {
        fn alive(&self) -> bool {
            let generation = self.child.generation();
            cerebellum_macos::process_start_time_micros(generation.pid)
                == Some(generation.start_time_micros)
        }
        fn generation(&self) -> ProcessGeneration {
            self.child.generation()
        }
        fn wait_ready(&mut self, deadline: Instant) -> Result<(), &'static str> {
            if Instant::now() >= deadline {
                return Err("mouse-down recipient helper launch budget exceeded");
            }
            self.client
                .wait_ready(deadline.saturating_duration_since(Instant::now()))
        }
        fn write(&mut self, bytes: &[u8]) -> bool {
            use std::io::Write;
            self.pipe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .write_all(bytes)
                .is_ok()
        }
        fn query(
            &mut self,
            point: [f64; 2],
            deadline: Instant,
        ) -> Result<Option<u32>, &'static str> {
            if Instant::now() >= deadline {
                return Err("mouse-down recipient helper query budget exceeded");
            }
            self.client.window_at(
                point,
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(pointer_query::QUERY_TIMEOUT),
            )
        }
    }

    impl Launcher for NativeLauncher {
        type Helper = NativeHelper;
        fn screen_unlocked(&self) -> bool {
            cerebellum_macos::screen_is_locked() == Some(false)
        }
        fn launch(&mut self, deadline: Option<Instant>) -> Result<NativeHelper, &'static str> {
            use pointer_query::{Client, Reply, MAX_REPLY_BYTES};
            use std::io::{BufRead, Read};
            let pinned = HELPER_EXECUTABLE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let executable = helper_launch_path(pinned.as_ref())
                .ok_or("mouse-down recipient helper pinned executable unavailable")?;
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err("mouse-down recipient helper launch budget exceeded");
            }
            let (barred, pipe, replies) =
                cerebellum_macos::spawn_barred_cursor(&executable, &["--agent-cursor".into()])
                    .map_err(|_| "mouse-down recipient helper spawn failed")?;
            if !pinned
                .as_ref()
                .is_some_and(|pin| pin.accepts_child(barred.generation().pid))
            {
                HELPER_BINARY_UNAVAILABLE.store(true, Ordering::Relaxed);
                return Err("mouse-down recipient helper pinned child verification failed");
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err("mouse-down recipient helper launch budget exceeded");
            }
            let child = barred
                .release()
                .map_err(|_| "mouse-down recipient helper release failed")?;
            drop(pinned);
            let pipe: Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>> =
                Arc::new(std::sync::Mutex::new(Box::new(std::fs::File::from(pipe))));
            let (tx, rx) = pipe::sync_channel(32);
            std::thread::Builder::new()
                .name("cursor-pointer-replies".into())
                .spawn(move || {
                    let mut reader = std::io::BufReader::new(std::fs::File::from(replies));
                    loop {
                        let mut line = Vec::new();
                        let read = reader
                            .by_ref()
                            .take(MAX_REPLY_BYTES + 1)
                            .read_until(b'\n', &mut line);
                        if !matches!(read, Ok(1..)) {
                            break;
                        }
                        let reply =
                            if line.len() as u64 > MAX_REPLY_BYTES || line.last() != Some(&b'\n') {
                                Err("mouse-down recipient helper reply malformed")
                            } else {
                                serde_json::from_slice::<Reply>(&line)
                                    .map_err(|_| "mouse-down recipient helper reply malformed")
                            };
                        let malformed = reply.is_err();
                        if tx.try_send(reply).is_err() || malformed {
                            break;
                        }
                    }
                })
                .map_err(|_| "mouse-down recipient helper reply reader start failed")?;
            cerebellum_macos::register_cursor_generation(Some(child.generation()));
            Ok(NativeHelper {
                child,
                client: Client::new(pipe.clone(), rx),
                pipe,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        struct Stats {
            launches: usize,
            writes: usize,
            queries: usize,
            preparations: usize,
            alive: bool,
            now: Instant,
        }
        struct FakeLauncher {
            stats: Arc<Mutex<Stats>>,
            screen: Option<bool>,
            fail: bool,
        }
        struct FakeHelper(Arc<Mutex<Stats>>);
        impl Helper for FakeHelper {
            fn alive(&self) -> bool {
                self.0.lock().unwrap().alive
            }
            fn generation(&self) -> ProcessGeneration {
                ProcessGeneration {
                    pid: 42,
                    start_time_micros: 123,
                }
            }
            fn wait_ready(&mut self, _: Instant) -> Result<(), &'static str> {
                self.0.lock().unwrap().preparations += 1;
                Ok(())
            }
            fn write(&mut self, _: &[u8]) -> bool {
                self.0.lock().unwrap().writes += 1;
                true
            }
            fn query(&mut self, _: [f64; 2], _: Instant) -> Result<Option<u32>, &'static str> {
                self.0.lock().unwrap().queries += 1;
                Ok(Some(77))
            }
        }
        impl Launcher for FakeLauncher {
            type Helper = FakeHelper;
            fn screen_unlocked(&self) -> bool {
                self.screen == Some(false)
            }
            fn now(&self) -> Instant {
                self.stats.lock().unwrap().now
            }
            fn launch(&mut self, _: Option<Instant>) -> Result<FakeHelper, &'static str> {
                let mut stats = self.stats.lock().unwrap();
                stats.launches += 1;
                if self.fail {
                    return Err("mouse-down recipient helper pinned executable unavailable");
                }
                stats.alive = true;
                Ok(FakeHelper(self.stats.clone()))
            }
        }
        fn fixture(screen: Option<bool>, fail: bool) -> (Service, Arc<Mutex<Stats>>) {
            let stats = Arc::new(Mutex::new(Stats {
                launches: 0,
                writes: 0,
                queries: 0,
                preparations: 0,
                alive: false,
                now: Instant::now(),
            }));
            (
                Service::start(FakeLauncher {
                    stats: stats.clone(),
                    screen,
                    fail,
                }),
                stats,
            )
        }
        fn deadline() -> Instant {
            Instant::now() + Duration::from_millis(50)
        }

        #[test]
        fn prewarmed_helper_is_reused_by_the_bracket_query_without_drawing() {
            let (service, stats) = fixture(Some(false), false);
            assert_eq!(service.prewarm(deadline()), Ok(()));
            {
                let stats = stats.lock().unwrap();
                assert_eq!(stats.launches, 1);
                assert_eq!(stats.preparations, 1);
                assert_eq!(stats.queries, 0);
                assert_eq!(stats.writes, 0);
            }
            assert_eq!(service.query([10.0, 20.0], deadline()), Ok(Some(77)));
            let stats = stats.lock().unwrap();
            assert_eq!(
                stats.launches, 1,
                "the bracket must reuse the prepared child"
            );
            assert_eq!(stats.queries, 1);
            assert_eq!(stats.writes, 0);
            service.stop();
        }

        #[test]
        fn failed_prewarm_preserves_the_restart_limit_and_query_refusal() {
            let (service, stats) = fixture(Some(false), true);
            assert_eq!(
                service.prewarm(deadline()),
                Err("mouse-down recipient helper pinned executable unavailable")
            );
            assert_eq!(
                service.query([10.0, 20.0], deadline()),
                Err("mouse-down recipient helper restart limit reached")
            );
            let stats = stats.lock().unwrap();
            assert_eq!(stats.launches, 1);
            assert_eq!(stats.queries, 0);
            assert_eq!(stats.writes, 0);
            service.stop();
        }

        #[test]
        fn pointer_query_launches_without_a_badge_even_when_cursor_drawing_is_off() {
            for drawing in [false, true] {
                let (cursor, mut visual_lines) = Coordinator::channel();
                cursor.enable(drawing);
                assert_eq!(cursor.enabled(), drawing);
                while visual_lines.try_recv().is_ok() {}
                let (service, stats) = fixture(Some(false), false);
                let query = service.provider();
                assert_eq!(query([10.0, 20.0], deadline()), Ok(Some(77)));
                cursor.end("agent-with-no-badge");
                assert_eq!(query([10.0, 20.0], deadline()), Ok(Some(77)));
                let stats = stats.lock().unwrap();
                assert_eq!((stats.launches, stats.queries, stats.writes), (1, 2, 0));
                assert!(
                    !matches!(visual_lines.try_recv(), Ok(line) if !matches!(line, CursorLine::Hide(_)))
                );
                service.stop();
            }
        }

        #[test]
        fn pointer_query_launch_failure_names_the_failed_step() {
            let (service, stats) = fixture(Some(false), true);
            assert_eq!(
                service.query([10.0, 20.0], deadline()),
                Err("mouse-down recipient helper pinned executable unavailable")
            );
            assert_eq!(stats.lock().unwrap().launches, 1);
            assert_eq!(stats.lock().unwrap().queries, 0);
            service.stop();
        }

        #[test]
        fn locked_or_unreadable_screen_never_launches_a_query_helper() {
            for screen in [None, Some(true)] {
                let (service, stats) = fixture(screen, false);
                assert_eq!(
                    service.prewarm(deadline()),
                    Err("mouse-down recipient helper screen locked or unreadable")
                );
                assert_eq!(
                    service.query([10.0, 20.0], deadline()),
                    Err("mouse-down recipient helper screen locked or unreadable")
                );
                assert_eq!(stats.lock().unwrap().launches, 0);
                service.stop();
            }
        }

        #[test]
        fn queries_and_visuals_share_the_same_child_and_restart_limit() {
            let (service, stats) = fixture(Some(false), false);
            assert!(
                service
                    .write(
                        &Arc::new(State::default()),
                        &CursorLine::Picture(CursorEvent {
                            agent: "agent".into(),
                            initial: 'A',
                            to: [10.0, 20.0],
                            target: None,
                            resting: true,
                            label: None,
                            kind: CursorKind::Reading,
                            serial: 1,
                            avatar_rgba: None,
                            avatar_update: false,
                            avatar_tint: None,
                            motion: PictureMotion::still(),
                        })
                    )
                    .written
            );
            assert_eq!(service.query([10.0, 20.0], deadline()), Ok(Some(77)));
            {
                let mut stats = stats.lock().unwrap();
                assert_eq!(stats.launches, 1);
                stats.alive = false;
                stats.now += Duration::from_secs(61);
            }
            assert_eq!(service.query([10.0, 20.0], deadline()), Ok(Some(77)));
            {
                let mut stats = stats.lock().unwrap();
                assert_eq!(stats.launches, 2);
                stats.alive = false;
                stats.now += Duration::from_secs(61);
            }
            assert_eq!(
                service.query([10.0, 20.0], deadline()),
                Err("mouse-down recipient helper restart limit reached")
            );
            assert_eq!(stats.lock().unwrap().launches, 2);
            service.stop();
        }

        #[test]
        fn an_expired_fronting_budget_never_starts_a_helper() {
            let (service, stats) = fixture(Some(false), false);
            assert_eq!(
                service.query([10.0, 20.0], Instant::now()),
                Err("mouse-down recipient helper launch/query budget exceeded")
            );
            assert_eq!(stats.lock().unwrap().launches, 0);
            service.stop();
        }

        #[test]
        fn slow_launch_cannot_extend_the_call_budget_or_issue_a_late_query() {
            slow_launch(false);
        }

        #[test]
        fn timed_out_prewarm_leaves_the_later_query_fail_closed() {
            slow_launch(true);
        }

        fn slow_launch(prewarm: bool) {
            struct SlowLauncher {
                started: pipe::SyncSender<()>,
                release: pipe::Receiver<()>,
                dropped: pipe::SyncSender<()>,
                queries: Arc<std::sync::atomic::AtomicUsize>,
            }
            struct LateHelper(pipe::SyncSender<()>, Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for LateHelper {
                fn drop(&mut self) {
                    let _ = self.0.try_send(());
                }
            }
            impl Helper for LateHelper {
                fn alive(&self) -> bool {
                    true
                }
                fn wait_ready(&mut self, _: Instant) -> Result<(), &'static str> {
                    panic!("late helper must be dropped before readiness")
                }
                fn generation(&self) -> ProcessGeneration {
                    ProcessGeneration {
                        pid: 42,
                        start_time_micros: 123,
                    }
                }
                fn write(&mut self, _: &[u8]) -> bool {
                    panic!("no visual command")
                }
                fn query(&mut self, _: [f64; 2], _: Instant) -> Result<Option<u32>, &'static str> {
                    self.1.fetch_add(1, Ordering::Relaxed);
                    Ok(Some(77))
                }
            }
            impl Launcher for SlowLauncher {
                type Helper = LateHelper;
                fn screen_unlocked(&self) -> bool {
                    true
                }
                fn launch(&mut self, _: Option<Instant>) -> Result<LateHelper, &'static str> {
                    self.started.send(()).unwrap();
                    self.release.recv().unwrap();
                    Ok(LateHelper(self.dropped.clone(), self.queries.clone()))
                }
            }
            let (start, started) = pipe::sync_channel(1);
            let (release, released) = pipe::sync_channel(1);
            let (drop, dropped) = pipe::sync_channel(1);
            let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let service = Service::start(SlowLauncher {
                started: start,
                release: released,
                dropped: drop,
                queries: queries.clone(),
            });
            let query = service.clone();
            let call = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_millis(100);
                if prewarm {
                    query.prewarm(deadline)
                } else {
                    query.query([10.0, 20.0], deadline).map(|_| ())
                }
            });
            started.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(
                call.join().unwrap(),
                Err(if prewarm {
                    "mouse-down recipient helper launch budget exceeded"
                } else {
                    "mouse-down recipient helper launch/query budget exceeded"
                })
            );
            release.send(()).unwrap();
            dropped.recv_timeout(Duration::from_secs(1)).unwrap();
            if prewarm {
                assert_eq!(
                    service.query([10.0, 20.0], deadline()),
                    Err("mouse-down recipient helper restart limit reached")
                );
            }
            assert_eq!(queries.load(Ordering::Relaxed), 0);
            service.stop();
        }
    }
}
