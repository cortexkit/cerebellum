//! The background-mode preview: which agents show one and in which slot,
//! which window each shows, and the one worker that captures their frames.
//!
//! In background mode an agent acts in an application without bringing it
//! forward, so the person cannot see what it is doing. Each agent then gets a
//! small preview of the window it acts in, drawn by the agent-cursor helper
//! in one of `PREVIEW_SLOTS` slots at the top right of the screen. This module
//! decides everything about those previews that does not need the helper:
//!
//! - Slots are handed out top-down in the order agents first act, at most
//!   three; a freed slot goes to the next new agent and the others never
//!   move. A fourth agent gets no preview (`not_shown_capacity`).
//! - Which window a preview shows, read once as an id and its bounds
//!   together, so the frame captured and the badge's position mapped into
//!   the thumbnail always describe the same window.
//! - When frames are captured. Capture happens here, in the module, which
//!   holds Screen Recording; the helper only draws. One preview worker per
//!   computer plane (a running module has one plane) captures for every
//!   agent, off the action path, on two threads of its own (one follows the
//!   schedule, one makes the native requests): no action waits for it. At
//!   most one native capture request is outstanding at a time,
//!   counting one whose wait ended without an answer; until it answers, no
//!   other request is made, each agent's refreshes collapse into one for its
//!   latest window, and every preview shows the application's icon. A frame
//!   that answers late is sent only if its preview still shows that window
//!   in the same generation. A hidden preview has no capture and no timer.
//! - A preview whose agent has not acted for the badge's idle timeout is
//!   taken for hidden, as the helper hides it then: its slot is free for the
//!   next agent, and it is never refreshed again. Nothing times this; it is
//!   noticed the next time an agent asks for a slot.
//! - A minimized window shows the application's icon with `minimized`, and
//!   nothing is captured of it.
//! - Without `preview_capture_admitted` (set only when this build carries
//!   both the `capture_review_revision` and the
//!   `app_use_fronting_review_revision` release attestations) nothing is
//!   ever captured: previews show the application's icon with
//!   `capture_refused`.
//!
//! These pixels leave the module outside capture custody. They are never
//! model-visible, never retained and never journaled.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cerebellum_computer::app_state::source::{AppStateSource, ElementHandle};
use cerebellum_computer::capture::{CaptureBackend, ScopedCaptureController};
use cerebellum_computer::cursor::{
    CursorFrame, CursorPreview, PreviewFallback, IDLE_FADE_AFTER_MS, IDLE_FADE_MS, PREVIEW_SLOTS,
};
use cerebellum_computer::platform::ProcessGrant;
use cerebellum_computer::preview_layout::{thumbnail_size, PREVIEW_WIDTH};

/// How long the worker waits for a native capture request to answer. A
/// request still unanswered after this stays outstanding: no other request
/// is made until it answers, and meanwhile every preview shows its icon.
pub(crate) const PREVIEW_CAPTURE_TIMEOUT_MS: u64 = 2_000;
/// While an agent's action is in flight its preview is refreshed at most
/// once in this many milliseconds: twice a second.
pub(crate) const IN_FLIGHT_REFRESH_MS: u64 = 500;
/// How long after its agent's last action a preview is gone: the helper
/// fades the badge, and the preview with it, after this long.
const PREVIEW_IDLE: Duration = Duration::from_millis(IDLE_FADE_AFTER_MS + IDLE_FADE_MS);

/// How much work the preview has done since the process started, for the
/// module's health reply: capture requests made and frame lines written to
/// the helper. Counts only, naming no agent, window or application, so a
/// desk probe can tell an idle preview costs nothing. Plain atomics: reading
/// them takes no lock the preview holds.
#[derive(Debug, Default)]
pub(crate) struct PreviewGauges {
    capture_requests: AtomicU64,
    frames_written: AtomicU64,
}

impl PreviewGauges {
    pub(crate) const fn new() -> Self {
        Self {
            capture_requests: AtomicU64::new(0),
            frames_written: AtomicU64::new(0),
        }
    }

    /// Capture requests handed to the capture backend.
    pub(crate) fn capture_requests(&self) -> u64 {
        self.capture_requests.load(Ordering::Relaxed)
    }

    /// Frame lines written to the helper's pipe.
    pub(crate) fn frames_written(&self) -> u64 {
        self.frames_written.load(Ordering::Relaxed)
    }

    pub(crate) fn frame_written(&self) {
        self.frames_written.fetch_add(1, Ordering::Relaxed);
    }

    fn capture_requested(&self) {
        self.capture_requests.fetch_add(1, Ordering::Relaxed);
    }
}

/// The process's preview gauges, reported as `previewCaptureRequests` and
/// `previewFramesWritten`. Tests that count exactly give their worker and
/// cursor gauges of their own, since other tests capture in parallel.
pub(crate) static PREVIEW_GAUGES: PreviewGauges = PreviewGauges::new();

/// Which preview slot each agent holds, top-down from 0.
///
/// A new agent takes the topmost free slot. An agent keeps its slot until
/// its preview is hidden; the freed slot goes to the next new agent, and no
/// other preview moves up to fill it, so a person never sees a preview jump.
#[derive(Debug, Default)]
pub(crate) struct SlotLayout {
    slots: [Option<String>; PREVIEW_SLOTS as usize],
}

impl SlotLayout {
    /// The agent's slot, taking the topmost free one for an agent without
    /// one. `None` when all slots are held by other agents.
    pub(crate) fn assign(&mut self, agent: &str) -> Option<u8> {
        if let Some(slot) = self.slot_of(agent) {
            return Some(slot);
        }
        let free = self.slots.iter().position(Option::is_none)?;
        self.slots[free] = Some(agent.to_owned());
        u8::try_from(free).ok()
    }

    /// Free the agent's slot, returning which it was.
    pub(crate) fn release(&mut self, agent: &str) -> Option<u8> {
        let slot = self.slot_of(agent)?;
        self.slots[usize::from(slot)] = None;
        Some(slot)
    }

    pub(crate) fn slot_of(&self, agent: &str) -> Option<u8> {
        self.slots
            .iter()
            .position(|held| held.as_deref() == Some(agent))
            .and_then(|slot| u8::try_from(slot).ok())
    }
}

/// The window a preview shows: its window-server id and its frame (x, y,
/// width, height in global top-down screen points), read together. The id
/// names the window that is captured; the frame maps the acted-on point into
/// the thumbnail. Both come from one read, so they cannot describe two
/// different windows.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PreviewWindow {
    pub(crate) id: u32,
    pub(crate) bounds: [f64; 4],
    /// The window read as minimized, so there is nothing of it to capture
    /// and the preview shows the application's icon. An unreadable answer
    /// is not minimized: capture is tried, with all its own checks.
    pub(crate) minimized: bool,
}

impl PreviewWindow {
    /// `None` unless the frame is finite and has an area.
    pub(crate) fn new(id: u32, bounds: [f64; 4]) -> Option<Self> {
        (bounds.iter().all(|v| v.is_finite()) && bounds[2] > 0.0 && bounds[3] > 0.0).then_some(
            Self {
                id,
                bounds,
                minimized: false,
            },
        )
    }

    /// The window's width and height, which give the thumbnail its shape.
    pub(crate) fn aspect(&self) -> [f64; 2] {
        [self.bounds[2], self.bounds[3]]
    }

    /// The thumbnail's image size in points, exactly as the helper draws it
    /// (`preview_layout::thumbnail_size`, the one definition both programs
    /// compile): the badge's glides inside it are timed by their length in
    /// these points, and its frames are captured at this size.
    pub(crate) fn thumbnail(&self) -> [f64; 2] {
        // `new` admits only a finite shape with an area, which always has a
        // layout; the fallback is never reached.
        thumbnail_size(self.aspect()).unwrap_or([PREVIEW_WIDTH, PREVIEW_WIDTH])
    }

    /// The largest frame worth capturing, in pixels: the thumbnail's size in
    /// points times the display's backing scale (2 on a Retina display).
    pub(crate) fn capture_max_px(&self, backing_scale: f64) -> [u32; 2] {
        let scale = if backing_scale.is_finite() && backing_scale > 0.0 {
            backing_scale
        } else {
            1.0
        };
        self.thumbnail()
            .map(|side| (side * scale).round().clamp(1.0, f64::from(u32::MAX)) as u32)
    }

    /// `point` (global top-down screen points) as a position in the window,
    /// each coordinate from 0 at its left or top edge to 1 at its right or
    /// bottom edge. `None` outside the window.
    pub(crate) fn relative(&self, point: [f64; 2]) -> Option<[f64; 2]> {
        let [x, y, width, height] = self.bounds;
        let relative = [(point[0] - x) / width, (point[1] - y) / height];
        relative
            .iter()
            .all(|v| v.is_finite() && (0.0..=1.0).contains(v))
            .then_some(relative)
    }

    /// Where the badge points for an element whose frame is `element`: the
    /// centre of the part of it inside the window, as a position in the
    /// window. `None` when no part of it is inside, which means no motion.
    pub(crate) fn visible_target(&self, element: [f64; 4]) -> Option<[f64; 2]> {
        if !element.iter().all(|v| v.is_finite()) {
            return None;
        }
        let [x, y, width, height] = self.bounds;
        let left = element[0].max(x);
        let top = element[1].max(y);
        let right = (element[0] + element[2]).min(x + width);
        let bottom = (element[1] + element[3]).min(y + height);
        if right <= left || bottom <= top {
            return None;
        }
        self.relative([(left + right) / 2.0, (top + bottom) / 2.0])
    }
}

/// Which window an action's preview shows. This one definition serves both
/// the frame's capture and the badge's mapping.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PreviewWindowSource<'a> {
    /// An action on an element, or on a point read off an image (resolved
    /// to the element there), including `write_text` to a window that is not
    /// focused: the addressed element's own window.
    Element(&'a ElementHandle),
    /// `keys` and `type`: the window of the application's focused element,
    /// as the action already read it, or with none its focused window.
    Focused(Option<&'a ElementHandle>),
    /// `read_state` with no element: the application's frontmost window,
    /// as the window server's front-to-back list names it
    /// (`frontmost_window_id`). `None` when it has none.
    Frontmost(Option<u32>),
}

/// The window an action's preview shows, as its id and bounds read together
/// from that window's own accessibility element, and whether it is
/// minimized. `None` when it cannot be read, or when the frontmost window
/// the list names is not the one the application reports, which leaves the
/// preview where it was rather than pointing it at a window nobody asked
/// for.
pub(crate) fn preview_window(
    source: &dyn AppStateSource,
    target: &ProcessGrant,
    which: PreviewWindowSource<'_>,
) -> Option<PreviewWindow> {
    let (window, expected) = match which {
        PreviewWindowSource::Element(element) => {
            (source.cursor_window(target, Some(element))?, None)
        }
        PreviewWindowSource::Focused(focused) => (source.cursor_window(target, focused)?, None),
        PreviewWindowSource::Frontmost(id) => (source.cursor_window(target, None)?, Some(id?)),
    };
    let id = source.element_window_number(&window)?;
    if expected.is_some_and(|expected| expected != id) {
        return None;
    }
    let mut read = PreviewWindow::new(id, source.cursor_frame(&window)?)?;
    read.minimized = source.window_minimized(&window) == Some(true);
    Some(read)
}

/// What an action asks the preview to show: one agent's preview of one
/// window of one application.
#[derive(Clone, Debug)]
pub(crate) struct PreviewRequest {
    pub(crate) agent: String,
    pub(crate) target: ProcessGrant,
    pub(crate) window: PreviewWindow,
    /// The application's name, shown on the preview.
    pub(crate) app: String,
    /// The application bundle's absolute path. The helper loads the icon
    /// from it when the preview has no frame to show.
    pub(crate) icon_path: Option<String>,
    /// The action's label as `cursor::label` makes it; `None` for a read.
    pub(crate) label: Option<String>,
    /// The display's backing scale: pixels per point.
    pub(crate) backing_scale: f64,
}

/// Whether an agent's preview is showing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ShowOutcome {
    /// Shown in `slot`. `thumbnail` is the image's size in points, which the
    /// badge's motion inside the preview is measured in. `icon` says the
    /// preview shows the application's icon instead of a frame (capture not
    /// admitted or refused, a capture stuck, or a minimized window): the
    /// badge then makes no motion there and the action waits for nothing.
    Shown {
        slot: u8,
        generation: u64,
        thumbnail: [f64; 2],
        icon: bool,
    },
    /// Every slot is held by another agent. This agent gets no preview, no
    /// badge and no arrival wait, and its reply says
    /// `preview: "not_shown_capacity"`.
    NotShownCapacity,
}

/// Why a preview shows the application's icon instead of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IconCause {
    /// Capture is not admitted, or the last capture of this window failed.
    Refused,
    /// Another capture request has gone unanswered past its wait, so no
    /// capture can be made for anyone until it answers.
    Stalled,
    /// The window is minimized: there is nothing to capture until a later
    /// action finds it shown again.
    Minimized,
}

/// One capture request: one agent's window, at the size its thumbnail
/// needs.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CaptureJob {
    pub(crate) id: u64,
    pub(crate) agent: String,
    /// The preview's generation when the request was made. The frame is
    /// sent only if the preview is still in this generation.
    pub(crate) generation: u64,
    pub(crate) window: u32,
    pub(crate) target: ProcessGrant,
    pub(crate) max_px: [u32; 2],
}

/// A captured preview frame: a JPEG and its size in pixels.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PreviewJpeg {
    pub(crate) size: [u32; 2],
    pub(crate) jpeg: Vec<u8>,
}

/// A capture produced no frame: permission not live, an owner check that
/// failed, a window that is gone, or any other refusal. There is nothing
/// to say about it beyond the icon the preview then shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreviewRefused;

/// What the worker does next.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Step {
    /// Preview lines to send now: previews switching to their icon.
    pub(crate) lines: Vec<CursorPreview>,
    /// A capture to request now.
    pub(crate) submit: Option<CaptureJob>,
    /// When to look again if nothing changes before then. `None` means only
    /// when something changes: no timer runs.
    pub(crate) wake_at: Option<Instant>,
}

/// What a capture's answer sends.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Answer {
    pub(crate) frame: Option<CursorFrame>,
    pub(crate) lines: Vec<CursorPreview>,
}

struct Shown {
    /// The preview as last shown, without any icon fallback.
    line: CursorPreview,
    icon_path: Option<String>,
    target: ProcessGrant,
    max_px: [u32; 2],
    icon: Option<IconCause>,
    /// A refresh was asked for and not yet requested.
    wants: bool,
    /// An action is in flight, so the preview refreshes on a timer.
    in_flight: bool,
    last_submit: Option<Instant>,
    /// When its agent last showed it or started or settled an action. Past
    /// `PREVIEW_IDLE` after this, with no action in flight, the helper has
    /// faded it out, and it counts as hidden.
    last_active: Instant,
}

impl Shown {
    /// The preview line as it should be drawn now: with the icon when there
    /// is no frame to show.
    fn shown_line(&self) -> CursorPreview {
        let mut line = self.line.clone();
        if let Some(icon) = self.icon {
            line.preview_fallback = Some(match icon {
                IconCause::Minimized => PreviewFallback::Minimized,
                IconCause::Refused | IconCause::Stalled => PreviewFallback::CaptureRefused,
            });
            line.preview_icon_path = self.icon_path.clone();
            if !line.valid() {
                // An icon path the helper would refuse; the preview still
                // says why it has no frame.
                line.preview_icon_path = None;
            }
        }
        line
    }

    fn generation(&self) -> u64 {
        self.line.preview_generation
    }

    fn window(&self) -> u32 {
        self.line.preview_window
    }

    /// Whether the helper has faded it out by `now`: no action in flight and
    /// none for `PREVIEW_IDLE`.
    fn idle(&self, now: Instant) -> bool {
        !self.in_flight && now.saturating_duration_since(self.last_active) >= PREVIEW_IDLE
    }
}

struct Outstanding {
    job: u64,
    submitted: Instant,
    /// Its wait has ended without an answer. It still counts as outstanding
    /// until it answers.
    timed_out: bool,
}

/// The previews and their capture timing, with time passed in: every rule
/// in the module header is decided here, so it is tested on every host
/// without a thread or a real clock.
pub(crate) struct Schedule {
    capture_admitted: bool,
    capture_timeout: Duration,
    slots: SlotLayout,
    shown: BTreeMap<String, Shown>,
    /// The last generation handed out, for every agent alike: a preview
    /// shown after a hide always gets a newer generation than the hidden
    /// one, without remembering agents whose preview is gone.
    generations: u64,
    jobs: u64,
    outstanding: Option<Outstanding>,
}

impl Schedule {
    pub(crate) fn new(capture_admitted: bool, capture_timeout: Duration) -> Self {
        Self {
            capture_admitted,
            capture_timeout,
            slots: SlotLayout::default(),
            shown: BTreeMap::new(),
            generations: 0,
            jobs: 0,
            outstanding: None,
        }
    }

    /// Hold a slot for the agent before its window is read, so whether it
    /// gets a preview is known at once: `None` when every slot is held by
    /// another agent (`not_shown_capacity`). A preview gone idle by `now`
    /// counts as hidden and frees its slot first.
    pub(crate) fn reserve(&mut self, agent: &str, now: Instant) -> Option<u8> {
        self.expire_idle(now);
        self.slots.assign(agent)
    }

    /// Give back a slot `reserve` held for an agent whose preview was then
    /// not shown after all (its window could not be read). A preview already
    /// showing keeps its slot.
    pub(crate) fn release_unshown(&mut self, agent: &str) {
        if !self.shown.contains_key(agent) {
            self.slots.release(agent);
        }
    }

    /// Whether the agent's preview is showing at `now`.
    pub(crate) fn is_shown(&self, agent: &str, now: Instant) -> bool {
        self.shown.get(agent).is_some_and(|shown| !shown.idle(now))
    }

    /// Forget every preview the helper has faded out by `now`, freeing its
    /// slot. A later action shows it anew, in a new generation.
    fn expire_idle(&mut self, now: Instant) {
        let idle: Vec<String> = self
            .shown
            .iter()
            .filter(|(_, shown)| shown.idle(now))
            .map(|(agent, _)| agent.clone())
            .collect();
        for agent in idle {
            self.hide(&agent);
        }
    }

    /// Show the agent's preview of `request.window`, or keep showing it with
    /// the new label. Another window or application is a retarget and gets
    /// a new generation, so a frame of the old window is never drawn into
    /// it. Returns the line to send, which is `None` only when no slot is
    /// free.
    pub(crate) fn show(
        &mut self,
        request: PreviewRequest,
        now: Instant,
    ) -> (ShowOutcome, Option<CursorPreview>) {
        self.expire_idle(now);
        let Some(slot) = self.slots.assign(&request.agent) else {
            return (ShowOutcome::NotShownCapacity, None);
        };
        let previous = self.shown.remove(&request.agent);
        let same = previous.as_ref().filter(|previous| {
            previous.window() == request.window.id && previous.target == request.target
        });
        let generation = match same {
            Some(previous) => previous.generation(),
            None => {
                self.generations += 1;
                self.generations
            }
        };
        let minimized = request.window.minimized;
        let icon = if !self.capture_admitted {
            Some(IconCause::Refused)
        } else if self.outstanding.as_ref().is_some_and(|out| out.timed_out) {
            Some(IconCause::Stalled)
        } else {
            // A minimized window shown again is captured again.
            same.and_then(|previous| previous.icon)
                .filter(|icon| *icon != IconCause::Minimized)
        };
        // Nothing of a minimized window can be captured, whatever else holds.
        let icon = if minimized {
            Some(IconCause::Minimized)
        } else {
            icon
        };
        let shown = Shown {
            line: CursorPreview {
                preview_agent: request.agent.clone(),
                preview_generation: generation,
                preview_slot: slot,
                preview_window: request.window.id,
                preview_app: request.app,
                preview_aspect: request.window.aspect(),
                preview_label: request.label,
                preview_fallback: None,
                preview_icon_path: None,
            },
            icon_path: request.icon_path,
            target: request.target,
            max_px: request.window.capture_max_px(request.backing_scale),
            icon,
            wants: self.capture_admitted && !minimized,
            in_flight: previous.as_ref().is_some_and(|previous| previous.in_flight),
            last_submit: previous.as_ref().and_then(|previous| previous.last_submit),
            last_active: now,
        };
        let line = shown.shown_line();
        let icon = shown.icon.is_some();
        self.shown.insert(request.agent, shown);
        (
            ShowOutcome::Shown {
                slot,
                generation,
                thumbnail: request.window.thumbnail(),
                icon,
            },
            Some(line),
        )
    }

    /// The agent's preview is hidden: its slot is freed, and nothing more is
    /// captured or timed for it. A request already outstanding for it still
    /// counts until it answers, and its frame is never sent.
    pub(crate) fn hide(&mut self, agent: &str) -> bool {
        self.slots.release(agent);
        self.shown.remove(agent).is_some()
    }

    /// An action of the agent's has started: its preview refreshes at most
    /// twice a second until the action settles.
    pub(crate) fn action_started(&mut self, agent: &str, now: Instant) {
        if let Some(shown) = self.shown.get_mut(agent) {
            shown.in_flight = true;
            shown.last_active = now;
        }
    }

    /// An action of the agent's has settled: its preview refreshes once.
    pub(crate) fn action_settled(&mut self, agent: &str, now: Instant) {
        if let Some(shown) = self.shown.get_mut(agent) {
            shown.in_flight = false;
            shown.wants = self.capture_admitted && shown.icon != Some(IconCause::Minimized);
            shown.last_active = now;
        }
    }

    /// Whether a capture request is outstanding, answered or not past its
    /// wait.
    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> bool {
        self.outstanding.is_some()
    }

    /// What to do at `now`.
    pub(crate) fn next(&mut self, now: Instant) -> Step {
        let mut step = Step::default();
        if let Some(outstanding) = &mut self.outstanding {
            if !outstanding.timed_out {
                let deadline = outstanding.submitted + self.capture_timeout;
                if now < deadline {
                    step.wake_at = Some(deadline);
                    return step;
                }
                outstanding.timed_out = true;
                for shown in self.shown.values_mut() {
                    if shown.icon.is_none() {
                        shown.icon = Some(IconCause::Stalled);
                        step.lines.push(shown.shown_line());
                    }
                }
            }
            // Nothing more until the request answers, however late.
            return step;
        }
        if !self.capture_admitted {
            return step;
        }
        let refresh = Duration::from_millis(IN_FLIGHT_REFRESH_MS);
        let chosen = self
            .shown
            .iter()
            .filter(|(_, shown)| shown.icon != Some(IconCause::Minimized))
            .filter(|(_, shown)| {
                shown.wants
                    || (shown.in_flight && shown.last_submit.is_none_or(|at| now >= at + refresh))
            })
            // The longest-waiting preview first, so one agent's busy timer
            // cannot starve another's refresh.
            .min_by_key(|(_, shown)| shown.last_submit)
            .map(|(agent, _)| agent.clone());
        if let Some(agent) = chosen {
            if let Some(shown) = self.shown.get_mut(&agent) {
                shown.wants = false;
                shown.last_submit = Some(now);
                self.jobs += 1;
                self.outstanding = Some(Outstanding {
                    job: self.jobs,
                    submitted: now,
                    timed_out: false,
                });
                step.submit = Some(CaptureJob {
                    id: self.jobs,
                    agent,
                    generation: shown.generation(),
                    window: shown.window(),
                    target: shown.target.clone(),
                    max_px: shown.max_px,
                });
                step.wake_at = Some(now + self.capture_timeout);
                return step;
            }
        }
        step.wake_at = self
            .shown
            .values()
            .filter(|shown| shown.in_flight && shown.icon != Some(IconCause::Minimized))
            .filter_map(|shown| shown.last_submit.map(|at| at + refresh))
            .min();
        step
    }

    /// The request `job` answered with `result`. Its frame is sent only
    /// while the agent's preview still shows the same window in the same
    /// generation; a failed capture shows the icon and sends no frame.
    pub(crate) fn answered(
        &mut self,
        job: &CaptureJob,
        result: Result<PreviewJpeg, PreviewRefused>,
    ) -> Answer {
        let mut answer = Answer::default();
        if self
            .outstanding
            .as_ref()
            .is_some_and(|outstanding| outstanding.job == job.id)
        {
            let stalled = self
                .outstanding
                .take()
                .is_some_and(|outstanding| outstanding.timed_out);
            if stalled {
                // Every preview that fell back to its icon while this
                // request was stuck gets one fresh capture.
                for shown in self.shown.values_mut() {
                    if shown.icon == Some(IconCause::Stalled) {
                        shown.wants = true;
                    }
                }
            }
        }
        let Some(shown) = self
            .shown
            .get_mut(&job.agent)
            .filter(|shown| shown.generation() == job.generation && shown.window() == job.window)
        else {
            return answer;
        };
        if shown.icon == Some(IconCause::Minimized) {
            // Asked for before the window was minimized: nothing to show.
            return answer;
        }
        let frame = result
            .ok()
            .map(|jpeg| {
                CursorFrame::new(
                    job.agent.clone(),
                    job.generation,
                    job.window,
                    jpeg.size,
                    &jpeg.jpeg,
                )
            })
            .filter(CursorFrame::valid);
        match frame {
            Some(frame) => {
                shown.icon = None;
                answer.frame = Some(frame);
            }
            None => {
                let had_icon = shown.icon.is_some();
                shown.icon = Some(IconCause::Refused);
                if !had_icon {
                    answer.lines.push(shown.shown_line());
                }
            }
        }
        answer
    }
}

/// Where preview lines go: the agent-cursor helper's pipe.
pub(crate) trait PreviewOutput: Send + Sync {
    /// Send a preview line. It may start the helper.
    fn preview(&self, line: CursorPreview) -> bool;
    /// Queue a frame. It never starts the helper.
    fn frame(&self, frame: CursorFrame) -> bool;
}

impl PreviewOutput for super::cursor::Coordinator {
    fn preview(&self, line: CursorPreview) -> bool {
        self.send_preview(line)
    }

    fn frame(&self, frame: CursorFrame) -> bool {
        self.send_frame(frame)
    }
}

/// Takes one preview frame, blocking until the capture answers.
pub(crate) trait PreviewCapturer: Send + Sync {
    fn capture(&self, job: &CaptureJob) -> Result<PreviewJpeg, PreviewRefused>;
}

/// Captures through a fresh capture backend and controller for each
/// request, bound to that request's grant, so every capture checks live
/// permission and the window's verified owner itself.
pub(crate) struct BackendPreviewCapture<F> {
    backend: F,
    epoch: Instant,
}

impl<F> BackendPreviewCapture<F> {
    pub(crate) fn new(backend: F) -> Self {
        Self {
            backend,
            epoch: Instant::now(),
        }
    }
}

impl<F, B> PreviewCapturer for BackendPreviewCapture<F>
where
    F: Fn() -> B + Send + Sync,
    B: CaptureBackend,
{
    fn capture(&self, job: &CaptureJob) -> Result<PreviewJpeg, PreviewRefused> {
        let mut controller =
            ScopedCaptureController::with_v1_bounds((self.backend)(), job.target.clone())
                .map_err(|_| PreviewRefused)?;
        let now_ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        let frame = controller
            .capture_window_for_preview(now_ms, &job.window.to_string(), job.max_px)
            .map_err(|_| PreviewRefused)?;
        Ok(PreviewJpeg {
            size: [frame.width_px, frame.height_px],
            jpeg: frame.jpeg,
        })
    }
}

/// Captures nothing: what a plane built without a platform capture uses.
/// Such a plane's capture is also never admitted, so this is never asked.
pub(crate) struct NoPreviewCapture;

impl PreviewCapturer for NoPreviewCapture {
    fn capture(&self, _job: &CaptureJob) -> Result<PreviewJpeg, PreviewRefused> {
        Err(PreviewRefused)
    }
}

/// The platform's own capture, through a backend the preview worker builds
/// for itself.
// Tests capture through in-memory backends instead.
#[cfg_attr(test, allow(dead_code))]
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn native_preview_capture(
) -> BackendPreviewCapture<fn() -> super::NativeComputerCaptureBackend> {
    BackendPreviewCapture::new(super::native_capture_backend)
}

/// A computer plane's preview: how it captures, whether this build may
/// capture at all (`preview_capture_admitted`), and its one worker, started
/// the first time a background-mode action shows a preview. A plane whose
/// agent cursor is off, or that only ever serves foreground mode, never
/// starts it: no thread, no capture, no timer.
pub(crate) struct PreviewPlane {
    capturer: Arc<dyn PreviewCapturer>,
    capture_admitted: bool,
    frontmost: super::cursor::FrontmostWindow,
    bundle: super::cursor::BundlePath,
    worker: std::sync::OnceLock<Arc<PreviewWorker>>,
}

impl PreviewPlane {
    pub(crate) fn new(
        capturer: Arc<dyn PreviewCapturer>,
        capture_admitted: bool,
        frontmost: super::cursor::FrontmostWindow,
        bundle: super::cursor::BundlePath,
    ) -> Self {
        Self {
            capturer,
            capture_admitted,
            frontmost,
            bundle,
            worker: std::sync::OnceLock::new(),
        }
    }

    /// A preview that captures nothing: every preview shows the
    /// application's icon with `capture_refused`.
    pub(crate) fn without_capture() -> Self {
        Self::new(
            Arc::new(NoPreviewCapture),
            false,
            platform_frontmost_window(),
            platform_bundle_path(),
        )
    }

    /// The worker, started now if it is not running, drawing through
    /// `cursor` and told of each of its ends.
    pub(crate) fn worker(&self, cursor: &super::cursor::Coordinator) -> Arc<PreviewWorker> {
        self.worker
            .get_or_init(|| {
                let worker = Arc::new(PreviewWorker::spawn(
                    Arc::new(cursor.clone()),
                    self.capturer.clone(),
                    self.capture_admitted,
                ));
                cursor.on_end(Arc::downgrade(&worker));
                worker
            })
            .clone()
    }

    /// The worker if it was started.
    pub(crate) fn running(&self) -> Option<&Arc<PreviewWorker>> {
        self.worker.get()
    }

    pub(crate) fn frontmost(&self) -> super::cursor::FrontmostWindow {
        self.frontmost.clone()
    }

    pub(crate) fn bundle(&self) -> super::cursor::BundlePath {
        self.bundle.clone()
    }
}

/// The application bundle a process runs from, as the platform reads it
/// (the executable's path cut back to its `.app`); nothing elsewhere.
pub(crate) fn platform_bundle_path() -> super::cursor::BundlePath {
    #[cfg(target_os = "macos")]
    {
        Arc::new(|grant: &ProcessGrant| cerebellum_macos::application_bundle_path(grant.pid))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(|_: &ProcessGrant| None)
    }
}

/// The window server's frontmost window of a process, as the platform
/// reads it; nothing where there is no window server to ask.
pub(crate) fn platform_frontmost_window() -> super::cursor::FrontmostWindow {
    #[cfg(target_os = "macos")]
    {
        Arc::new(|grant: &ProcessGrant| cerebellum_macos::frontmost_window_id(grant.pid))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(|_: &ProcessGrant| None)
    }
}

struct Locked {
    schedule: Schedule,
    stopped: bool,
}

struct Shared {
    locked: Mutex<Locked>,
    changed: Condvar,
    output: Arc<dyn PreviewOutput>,
    gauges: &'static PreviewGauges,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Locked> {
        self.locked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A computer plane's one preview worker. The action path tells it what to
/// show, hide and refresh, and never waits on it: each call takes a lock
/// that no capture is ever made under, sends at most one line without
/// waiting, and returns.
///
/// Two threads serve it. The worker thread follows the schedule and hands
/// capture requests on; the capture thread makes one native request at a
/// time and hands its answer back. A request that does not answer holds
/// only the capture thread, which is why it can be counted as outstanding
/// for as long as it takes.
pub(crate) struct PreviewWorker {
    shared: Arc<Shared>,
}

impl PreviewWorker {
    pub(crate) fn spawn(
        output: Arc<dyn PreviewOutput>,
        capturer: Arc<dyn PreviewCapturer>,
        capture_admitted: bool,
    ) -> Self {
        Self::spawn_with(
            output,
            capturer,
            capture_admitted,
            Duration::from_millis(PREVIEW_CAPTURE_TIMEOUT_MS),
            &PREVIEW_GAUGES,
        )
    }

    /// `spawn`, counting its capture requests in `gauges`.
    #[cfg(test)]
    pub(crate) fn spawn_counting(
        output: Arc<dyn PreviewOutput>,
        capturer: Arc<dyn PreviewCapturer>,
        capture_admitted: bool,
        gauges: &'static PreviewGauges,
    ) -> Self {
        Self::spawn_with(
            output,
            capturer,
            capture_admitted,
            Duration::from_millis(PREVIEW_CAPTURE_TIMEOUT_MS),
            gauges,
        )
    }

    fn spawn_with(
        output: Arc<dyn PreviewOutput>,
        capturer: Arc<dyn PreviewCapturer>,
        capture_admitted: bool,
        capture_timeout: Duration,
        gauges: &'static PreviewGauges,
    ) -> Self {
        let shared = Arc::new(Shared {
            locked: Mutex::new(Locked {
                schedule: Schedule::new(capture_admitted, capture_timeout),
                stopped: false,
            }),
            changed: Condvar::new(),
            output,
            gauges,
        });
        let (jobs, requests) = std::sync::mpsc::channel::<CaptureJob>();
        let answering = shared.clone();
        // If either thread cannot start, requests are never answered or
        // never made, and previews keep their icon: nothing waits on them.
        let _ = std::thread::Builder::new()
            .name("agent-preview-capture".into())
            .spawn(move || {
                for job in requests {
                    answering.gauges.capture_requested();
                    let result = capturer.capture(&job);
                    let mut locked = answering.lock();
                    let answer = locked.schedule.answered(&job, result);
                    // Sent under the lock, so a hide that bumps the
                    // generation either comes first and stops the frame, or
                    // comes after the frame is already queued for the
                    // helper.
                    for line in answer.lines {
                        answering.output.preview(line);
                    }
                    if let Some(frame) = answer.frame {
                        answering.output.frame(frame);
                    }
                    drop(locked);
                    answering.changed.notify_all();
                }
            });
        let worker = shared.clone();
        let _ = std::thread::Builder::new()
            .name("agent-preview".into())
            .spawn(move || run(&worker, &jobs));
        Self { shared }
    }

    /// Hold a slot for the agent, as `Schedule::reserve` decides.
    pub(crate) fn reserve(&self, agent: &str) -> Option<u8> {
        self.shared.lock().schedule.reserve(agent, Instant::now())
    }

    /// Give back a slot held for a preview that was not shown.
    pub(crate) fn release_unshown(&self, agent: &str) {
        self.shared.lock().schedule.release_unshown(agent);
    }

    /// Whether the agent's preview is showing.
    pub(crate) fn is_shown(&self, agent: &str) -> bool {
        self.shared.lock().schedule.is_shown(agent, Instant::now())
    }

    /// Show or retarget the agent's preview, as `Schedule::show` decides.
    pub(crate) fn show(&self, request: PreviewRequest) -> ShowOutcome {
        let mut locked = self.shared.lock();
        let (outcome, line) = locked.schedule.show(request, Instant::now());
        if let Some(line) = line {
            self.shared.output.preview(line);
        }
        drop(locked);
        self.shared.changed.notify_all();
        outcome
    }

    /// Hide the agent's preview. The caller sends the agent's hide line,
    /// which takes its badge and preview off the screen.
    pub(crate) fn hide(&self, agent: &str) {
        self.shared.lock().schedule.hide(agent);
        self.shared.changed.notify_all();
    }

    pub(crate) fn action_started(&self, agent: &str) {
        self.shared
            .lock()
            .schedule
            .action_started(agent, Instant::now());
        self.shared.changed.notify_all();
    }

    pub(crate) fn action_settled(&self, agent: &str) {
        self.shared
            .lock()
            .schedule
            .action_settled(agent, Instant::now());
        self.shared.changed.notify_all();
    }

    #[cfg(test)]
    fn outstanding(&self) -> bool {
        self.shared.lock().schedule.outstanding()
    }
}

impl Drop for PreviewWorker {
    fn drop(&mut self) {
        self.shared.lock().stopped = true;
        self.shared.changed.notify_all();
    }
}

/// The worker thread: follow the schedule, sleeping until its next timer
/// or until something changes. With nothing in flight it has no timer.
fn run(shared: &Shared, jobs: &std::sync::mpsc::Sender<CaptureJob>) {
    let mut locked = shared.lock();
    loop {
        if locked.stopped {
            return;
        }
        let step = locked.schedule.next(Instant::now());
        for line in step.lines {
            shared.output.preview(line);
        }
        if let Some(job) = step.submit {
            if jobs.send(job).is_err() {
                return;
            }
            continue;
        }
        locked = match step.wake_at {
            Some(at) => {
                shared
                    .changed
                    .wait_timeout(locked, at.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0
            }
            None => shared
                .changed
                .wait(locked)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, ElementActionError, FixtureElementToken, RawAppState, ReadBounds,
    };
    use cerebellum_computer::capture::{EnumeratedWindow, InMemoryCaptureBackend, WindowFrame};
    use cerebellum_computer::platform::PermissionLiveness;

    fn grant(pid: u32) -> ProcessGrant {
        ProcessGrant {
            pid,
            bundle_identity: format!("com.example.app{pid}"),
            process_generation_evidence: format!("generation-{pid}"),
        }
    }

    fn request(agent: &str, window: u32) -> PreviewRequest {
        PreviewRequest {
            agent: agent.into(),
            target: grant(42),
            window: PreviewWindow::new(window, [0.0, 0.0, 1600.0, 900.0]).unwrap(),
            app: "Mail".into(),
            icon_path: Some("/Applications/Mail.app".into()),
            label: Some("Pressing Send".into()),
            backing_scale: 2.0,
        }
    }

    fn jpeg() -> PreviewJpeg {
        PreviewJpeg {
            size: [4, 3],
            jpeg: vec![0xFF, 0xD8, 0xFF, 0xD9],
        }
    }

    fn shown_slot(outcome: ShowOutcome) -> u8 {
        match outcome {
            ShowOutcome::Shown { slot, .. } => slot,
            ShowOutcome::NotShownCapacity => panic!("not shown"),
        }
    }

    fn admitted() -> Schedule {
        Schedule::new(true, Duration::from_millis(PREVIEW_CAPTURE_TIMEOUT_MS))
    }

    fn icon(line: &CursorPreview) -> bool {
        line.preview_fallback == Some(PreviewFallback::CaptureRefused)
    }

    #[test]
    fn slots_fill_top_down_reuse_a_freed_slot_and_never_compact() {
        let mut schedule = admitted();
        for (agent, slot) in [("a", 0), ("b", 1), ("c", 2)] {
            let (outcome, line) = schedule.show(request(agent, 10), Instant::now());
            assert_eq!(shown_slot(outcome), slot);
            assert_eq!(line.unwrap().preview_slot, slot);
        }
        assert!(schedule.hide("b"));
        // The agent below keeps its slot; the gap is not closed.
        let (outcome, _) = schedule.show(request("c", 10), Instant::now());
        assert_eq!(shown_slot(outcome), 2);
        // The next new agent takes the freed slot.
        let (outcome, _) = schedule.show(request("d", 10), Instant::now());
        assert_eq!(shown_slot(outcome), 1);
        // A slot freed at the top goes to the next new agent, not to one
        // already showing below it.
        assert!(schedule.hide("a"));
        let (outcome, _) = schedule.show(request("d", 10), Instant::now());
        assert_eq!(shown_slot(outcome), 1);
        let (outcome, _) = schedule.show(request("e", 10), Instant::now());
        assert_eq!(shown_slot(outcome), 0);
    }

    #[test]
    fn a_fourth_agent_gets_not_shown_capacity_and_no_capture() {
        let mut schedule = admitted();
        let now = Instant::now();
        for agent in ["a", "b", "c"] {
            schedule.show(request(agent, 10), Instant::now());
        }
        let (outcome, line) = schedule.show(request("d", 10), Instant::now());
        assert_eq!(outcome, ShowOutcome::NotShownCapacity);
        assert_eq!(line, None);
        schedule.action_started("d", Instant::now());
        schedule.action_settled("d", Instant::now());
        let mut captured = Vec::new();
        let mut at = now;
        while let Some(job) = schedule.next(at).submit {
            captured.push(job.agent.clone());
            schedule.answered(&job, Ok(jpeg()));
            at += Duration::from_millis(1);
        }
        assert_eq!(captured, ["a", "b", "c"]);
    }

    #[test]
    fn without_capture_admitted_every_preview_shows_its_icon_and_nothing_is_captured() {
        let mut schedule = Schedule::new(false, Duration::from_millis(PREVIEW_CAPTURE_TIMEOUT_MS));
        let now = Instant::now();
        let (outcome, line) = schedule.show(request("a", 10), Instant::now());
        assert_eq!(shown_slot(outcome), 0);
        let line = line.unwrap();
        assert!(icon(&line));
        assert_eq!(
            line.preview_icon_path.as_deref(),
            Some("/Applications/Mail.app")
        );
        assert!(line.valid());
        schedule.action_started("a", Instant::now());
        for later in [0, 500, 1_000, 5_000] {
            let step = schedule.next(now + Duration::from_millis(later));
            assert_eq!(step.submit, None, "captured at {later} ms");
            assert_eq!(step.wake_at, None, "a timer runs with nothing to capture");
        }
        schedule.action_settled("a", Instant::now());
        assert_eq!(schedule.next(now).submit, None);
    }

    #[test]
    fn a_hidden_preview_has_no_capture_and_no_timer() {
        let mut schedule = admitted();
        let now = Instant::now();
        schedule.show(request("a", 10), Instant::now());
        schedule.action_started("a", Instant::now());
        let job = schedule.next(now).submit.expect("a first frame");
        schedule.answered(&job, Ok(jpeg()));
        let step = schedule.next(now + Duration::from_millis(40));
        assert_eq!(step.submit, None);
        assert_eq!(step.wake_at, Some(now + Duration::from_millis(500)));

        assert!(schedule.hide("a"));
        schedule.action_settled("a", Instant::now());
        schedule.action_started("a", Instant::now());
        for later in [40, 500, 1_000, 60_000] {
            let step = schedule.next(now + Duration::from_millis(later));
            assert_eq!(step.submit, None, "captured at {later} ms while hidden");
            assert_eq!(step.wake_at, None, "a timer runs while hidden");
            assert!(step.lines.is_empty());
        }
    }

    /// The helper fades an agent's preview out once the agent has not
    /// acted for the badge's idle timeout. The module then takes it for
    /// hidden: its slot goes to the next new agent, nothing is captured or
    /// timed for it, and its agent's next action shows it in a new
    /// generation. No timer runs while waiting for that.
    #[test]
    fn an_idle_preview_frees_its_slot_and_is_never_refreshed() {
        let mut schedule = admitted();
        let now = Instant::now();
        let mut first = 0;
        for agent in ["a", "b", "c"] {
            let (outcome, _) = schedule.show(request(agent, 10), now);
            if let ShowOutcome::Shown { generation, .. } = outcome {
                if agent == "a" {
                    first = generation;
                }
            }
            schedule.action_started(agent, now);
            schedule.action_settled(agent, now);
        }
        while let Some(job) = schedule.next(now).submit {
            schedule.answered(&job, Ok(jpeg()));
        }
        let step = schedule.next(now);
        assert_eq!(step.wake_at, None, "a timer runs while waiting to idle");
        // Just before the timeout every slot is still held.
        let almost = now + PREVIEW_IDLE - Duration::from_millis(1);
        assert_eq!(schedule.reserve("d", almost), None);
        assert!(schedule.is_shown("a", almost));
        // At it, every idle preview is gone: a new agent takes the top
        // slot, and nothing more is captured for the idle ones.
        let idle = now + PREVIEW_IDLE;
        assert!(!schedule.is_shown("a", idle));
        assert_eq!(schedule.reserve("d", idle), Some(0));
        let step = schedule.next(idle);
        assert_eq!(step.submit, None, "an idle preview was captured");
        assert_eq!(step.wake_at, None, "an idle preview has a timer");
        // The idle agent's next action shows its preview anew.
        let (ShowOutcome::Shown { generation, .. }, _) = schedule.show(request("a", 10), idle)
        else {
            panic!("not shown");
        };
        assert!(generation > first);
    }

    #[test]
    fn an_action_in_flight_refreshes_at_most_twice_a_second() {
        let mut schedule = admitted();
        let now = Instant::now();
        schedule.show(request("a", 10), Instant::now());
        schedule.action_started("a", Instant::now());
        let mut submitted = Vec::new();
        for at in (0..=1_400).step_by(20) {
            let at = now + Duration::from_millis(at);
            if let Some(job) = schedule.next(at).submit {
                submitted.push(at.duration_since(now).as_millis());
                schedule.answered(&job, Ok(jpeg()));
            }
        }
        assert_eq!(submitted, [0, 500, 1_000]);
        // Settling asks for one more at once.
        schedule.action_settled("a", Instant::now());
        let at = now + Duration::from_millis(1_420);
        let job = schedule.next(at).submit.expect("a refresh after settling");
        schedule.answered(&job, Ok(jpeg()));
        let step = schedule.next(at + Duration::from_millis(1));
        assert_eq!(step.submit, None);
        assert_eq!(step.wake_at, None, "a timer runs with no action in flight");
    }

    /// An unanswered request blocks every other one, for every agent, until
    /// it answers, however late. Meanwhile refreshes collapse into one per
    /// agent for its latest window, and once the wait ends every preview
    /// shows its icon.
    #[test]
    fn an_unanswered_request_blocks_every_other_and_refreshes_coalesce() {
        let mut schedule = admitted();
        let now = Instant::now();
        schedule.show(request("a", 10), Instant::now());
        let first = schedule.next(now).submit.expect("a's first frame");
        assert_eq!(first.agent, "a");
        schedule.show(request("b", 20), Instant::now());
        for _ in 0..3 {
            schedule.action_started("a", Instant::now());
            schedule.action_settled("a", Instant::now());
            schedule.action_started("b", Instant::now());
            schedule.action_settled("b", Instant::now());
        }
        schedule.show(request("b", 21), Instant::now());
        let step = schedule.next(now + Duration::from_millis(1_999));
        assert_eq!(step.submit, None);
        assert_eq!(
            step.wake_at,
            Some(now + Duration::from_millis(PREVIEW_CAPTURE_TIMEOUT_MS))
        );

        let step = schedule.next(now + Duration::from_millis(2_000));
        assert_eq!(step.submit, None);
        let icons: Vec<&str> = step
            .lines
            .iter()
            .filter(|line| icon(line))
            .map(|line| line.preview_agent.as_str())
            .collect();
        assert_eq!(icons, ["a", "b"]);
        assert_eq!(
            step.wake_at, None,
            "a timer runs while waiting for the answer"
        );
        // A preview shown while the request is stuck shows its icon at once.
        let (_, line) = schedule.show(request("c", 30), Instant::now());
        assert!(icon(&line.unwrap()));
        for later in [2_500, 10_000, 600_000] {
            assert_eq!(
                schedule.next(now + Duration::from_millis(later)).submit,
                None,
                "a second request at {later} ms"
            );
        }

        assert!(schedule.hide("a"));
        let late = schedule.answered(&first, Ok(jpeg()));
        assert_eq!(late, Answer::default(), "a hidden preview got its frame");
        let mut captured = Vec::new();
        let mut at = now + Duration::from_millis(600_001);
        while let Some(job) = schedule.next(at).submit {
            captured.push((job.agent.clone(), job.window));
            schedule.answered(&job, Ok(jpeg()));
            at += Duration::from_millis(1);
        }
        assert_eq!(captured, [("b".to_string(), 21), ("c".to_string(), 30)]);
    }

    #[test]
    fn a_late_frame_is_sent_only_for_the_current_generation() {
        let mut schedule = admitted();
        let now = Instant::now();
        let (
            ShowOutcome::Shown {
                generation: first_generation,
                ..
            },
            _,
        ) = schedule.show(request("a", 10), Instant::now())
        else {
            panic!("not shown");
        };
        let old = schedule.next(now).submit.unwrap();
        // The same window again keeps the generation; another window
        // raises it.
        let (
            ShowOutcome::Shown {
                generation: same, ..
            },
            _,
        ) = schedule.show(request("a", 10), Instant::now())
        else {
            panic!("not shown");
        };
        assert_eq!(same, first_generation);
        let (ShowOutcome::Shown { generation, .. }, _) =
            schedule.show(request("a", 11), Instant::now())
        else {
            panic!("not shown");
        };
        assert!(generation > first_generation);
        assert_eq!(schedule.answered(&old, Ok(jpeg())), Answer::default());

        let current = schedule.next(now).submit.unwrap();
        assert_eq!((current.window, current.generation), (11, generation));
        let frame = schedule.answered(&current, Ok(jpeg())).frame.unwrap();
        assert_eq!(frame.frame_agent, "a");
        assert_eq!(frame.frame_generation, generation);
        assert_eq!(frame.frame_window, 11);
        assert!(frame.valid());

        // Hidden and shown again on the same window: a new generation, and
        // a frame asked for before the hide is not drawn into it.
        let before_hide = {
            schedule.action_settled("a", Instant::now());
            schedule.next(now).submit.unwrap()
        };
        schedule.hide("a");
        let (
            ShowOutcome::Shown {
                generation: again, ..
            },
            _,
        ) = schedule.show(request("a", 11), Instant::now())
        else {
            panic!("not shown");
        };
        assert!(again > generation);
        assert_eq!(
            schedule.answered(&before_hide, Ok(jpeg())),
            Answer::default()
        );
    }

    #[test]
    fn a_failed_capture_sends_no_frame_and_shows_the_icon_once() {
        let mut schedule = admitted();
        let now = Instant::now();
        let (_, line) = schedule.show(request("a", 10), Instant::now());
        assert!(!icon(&line.unwrap()));
        let job = schedule.next(now).submit.unwrap();
        let answer = schedule.answered(&job, Err(PreviewRefused));
        assert_eq!(answer.frame, None);
        assert_eq!(answer.lines.len(), 1);
        assert!(icon(&answer.lines[0]));
        schedule.action_settled("a", Instant::now());
        let job = schedule.next(now).submit.unwrap();
        assert_eq!(
            schedule.answered(&job, Err(PreviewRefused)),
            Answer::default()
        );
        // A frame that would not fit its line is a failed capture too.
        schedule.action_settled("a", Instant::now());
        let job = schedule.next(now).submit.unwrap();
        let oversized = PreviewJpeg {
            size: [4, 3],
            jpeg: vec![1; cerebellum_computer::cursor::MAX_FRAME_BYTES + 1],
        };
        assert_eq!(schedule.answered(&job, Ok(oversized)).frame, None);
        schedule.action_settled("a", Instant::now());
        let job = schedule.next(now).submit.unwrap();
        assert!(schedule.answered(&job, Ok(jpeg())).frame.is_some());
    }

    #[test]
    fn the_thumbnail_is_the_helpers_own_letterboxed_thumbnail() {
        // The helper's thumbnail: the 280-point preview less its insets,
        // and at most as tall as a 360-point preview leaves room for under
        // its caption. The module measures glides and sizes captures in
        // exactly these points.
        let wide = PreviewWindow::new(1, [0.0, 0.0, 1920.0, 1080.0]).unwrap();
        assert_eq!(wide.thumbnail(), [268.0, 150.75]);
        assert_eq!(Some(wide.thumbnail()), thumbnail_size([1920.0, 1080.0]));
        assert_eq!(wide.capture_max_px(2.0), [536, 302]);
        let tall = PreviewWindow::new(1, [0.0, 0.0, 600.0, 1200.0]).unwrap();
        assert_eq!(tall.thumbnail(), [157.0, 314.0]);
        assert_eq!(Some(tall.thumbnail()), thumbnail_size([600.0, 1200.0]));
        assert_eq!(tall.capture_max_px(2.0), [314, 628]);
        assert_eq!(PreviewWindow::new(1, [0.0, 0.0, 0.0, 10.0]), None);
    }

    #[test]
    fn an_element_partly_outside_the_window_targets_its_visible_centre() {
        let window = PreviewWindow::new(1, [100.0, 50.0, 800.0, 600.0]).unwrap();
        assert_eq!(
            window.visible_target([500.0, 350.0, 100.0, 100.0]),
            Some([0.5625, 0.583_333_333_333_333_4])
        );
        // Half of it hangs off the right edge: the centre of what is inside.
        assert_eq!(
            window.visible_target([850.0, 50.0, 100.0, 60.0]),
            Some([0.968_75, 0.05])
        );
        assert_eq!(window.visible_target([950.0, 50.0, 100.0, 60.0]), None);
        assert_eq!(window.relative([99.0, 60.0]), None);
    }

    /// Two windows of one application: window 10 in front with element 1,
    /// and window 11 behind it with element 2, which is also focused.
    struct TwoWindows;

    fn token(handle: &ElementHandle) -> u64 {
        handle.identity_hash()
    }

    fn element(number: u64) -> ElementHandle {
        Arc::new(FixtureElementToken(number))
    }

    impl AppStateSource for TwoWindows {
        fn read_app_state(
            &self,
            _target: &ProcessGrant,
            _bounds: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            Err(AppStateReadError::UnsupportedOnPlatform)
        }

        fn cursor_window(
            &self,
            _target: &ProcessGrant,
            element_handle: Option<&ElementHandle>,
        ) -> Option<ElementHandle> {
            match element_handle.map(token) {
                Some(1) | None => Some(element(100)),
                Some(2) => Some(element(110)),
                Some(_) => None,
            }
        }

        fn cursor_frame(&self, handle: &ElementHandle) -> Option<[f64; 4]> {
            match token(handle) {
                100 => Some([0.0, 0.0, 1600.0, 900.0]),
                110 => Some([200.0, 100.0, 800.0, 600.0]),
                1 => Some([10.0, 10.0, 50.0, 20.0]),
                2 => Some([400.0, 250.0, 100.0, 50.0]),
                _ => None,
            }
        }

        fn element_window_number(&self, handle: &ElementHandle) -> Option<u32> {
            match token(handle) {
                100 => Some(10),
                110 => Some(11),
                _ => None,
            }
        }

        fn focused_element(
            &self,
            _target: &ProcessGrant,
        ) -> Result<Option<ElementHandle>, ElementActionError> {
            Ok(Some(element(2)))
        }
    }

    /// The window an action's preview shows is read once, and the same
    /// value names the captured window and maps the element into the
    /// thumbnail. An element in the application's second window retargets
    /// the preview there, and so does a key action whose focus is there.
    #[test]
    fn the_target_window_is_one_definition_for_capture_and_mapping() {
        let source = TwoWindows;
        let target = grant(42);
        let second = element(2);
        let window = preview_window(&source, &target, PreviewWindowSource::Element(&second))
            .expect("the element's window");
        assert_eq!(window.id, 11);
        assert_eq!(window.bounds, [200.0, 100.0, 800.0, 600.0]);
        let focus = source.focused_element(&target).unwrap();
        let focused = preview_window(
            &source,
            &target,
            PreviewWindowSource::Focused(focus.as_ref()),
        )
        .unwrap();
        assert_eq!(focused, window);
        let first = element(1);
        let front = preview_window(&source, &target, PreviewWindowSource::Element(&first)).unwrap();
        assert_eq!(front.id, 10);
        assert_eq!(
            preview_window(&source, &target, PreviewWindowSource::Frontmost(Some(10))),
            Some(front)
        );
        // The list's frontmost window is not the one the application
        // reports: no target rather than a guess.
        assert_eq!(
            preview_window(&source, &target, PreviewWindowSource::Frontmost(Some(11))),
            None
        );
        assert_eq!(
            preview_window(&source, &target, PreviewWindowSource::Frontmost(None)),
            None
        );

        let mut schedule = admitted();
        let mut shown = request("a", 0);
        shown.window = window;
        let (ShowOutcome::Shown { thumbnail, .. }, Some(line)) =
            schedule.show(shown, Instant::now())
        else {
            panic!("not shown");
        };
        assert_eq!(line.preview_window, 11);
        assert_eq!(line.preview_aspect, [800.0, 600.0]);
        assert_eq!(thumbnail, [268.0, 201.0]);
        let job = schedule.next(Instant::now()).submit.unwrap();
        assert_eq!(job.window, 11);
        assert_eq!(job.max_px, [536, 402]);
        let frame = source.cursor_frame(&second).unwrap();
        assert_eq!(
            window.visible_target(frame),
            Some([0.3125, 0.291_666_666_666_666_7])
        );
    }

    fn enumerated(id: &str, owner: &ProcessGrant) -> EnumeratedWindow {
        EnumeratedWindow {
            window_id: id.into(),
            owner_identity: owner.clone(),
            owner_identity_verified: true,
            frame: WindowFrame {
                x: 0,
                y: 0,
                width: 1600,
                height: 900,
            },
            accessibility_root: None,
        }
    }

    fn job(window: u32) -> CaptureJob {
        CaptureJob {
            id: 1,
            agent: "a".into(),
            generation: 1,
            window,
            target: grant(42),
            max_px: [560, 315],
        }
    }

    /// The preview of a second window that is not in front captures that
    /// window, not the application's front one.
    #[test]
    fn a_preview_of_a_non_front_second_window_captures_that_window() {
        let capture = BackendPreviewCapture::new(|| {
            let owner = grant(42);
            let mut backend = InMemoryCaptureBackend::default();
            backend.set_windows(vec![enumerated("10", &owner), enumerated("11", &owner)]);
            backend.set_frontmost_window(Some("10".into()));
            backend.set_vision_frame("10", 3200, 1800, vec![0xFF, 0xD8, 10]);
            backend.set_vision_frame("11", 3200, 1800, vec![0xFF, 0xD8, 11]);
            backend
        });
        let frame = capture.capture(&job(11)).unwrap();
        assert_eq!(frame.jpeg, [0xFF, 0xD8, 11]);
        assert_eq!(frame.size, [560, 315]);
    }

    /// A window id that now belongs to another process, or Screen
    /// Recording that is not live, gives no frame: the preview shows its
    /// icon instead.
    #[test]
    fn a_reused_window_id_or_non_live_permission_produces_no_frame() {
        let reused = BackendPreviewCapture::new(|| {
            let mut backend = InMemoryCaptureBackend::default();
            backend.set_windows(vec![enumerated("11", &grant(77))]);
            backend.set_vision_frame("11", 800, 600, vec![0xFF, 0xD8]);
            backend
        });
        let not_live = BackendPreviewCapture::new(|| {
            let mut backend = InMemoryCaptureBackend::default();
            backend.set_windows(vec![enumerated("11", &grant(42))]);
            backend.set_vision_frame("11", 800, 600, vec![0xFF, 0xD8]);
            backend.set_permission_liveness(PermissionLiveness::Unavailable);
            backend
        });
        for capture in [&reused as &dyn PreviewCapturer, &not_live] {
            let mut schedule = admitted();
            schedule.show(request("a", 11), Instant::now());
            let job = schedule.next(Instant::now()).submit.unwrap();
            let result = capture.capture(&job);
            assert_eq!(result, Err(PreviewRefused));
            let answer = schedule.answered(&job, result);
            assert_eq!(answer.frame, None);
            assert_eq!(answer.lines.len(), 1);
            assert!(icon(&answer.lines[0]));
        }
    }

    #[derive(Debug, PartialEq)]
    enum Sent {
        Preview(CursorPreview),
        Frame(CursorFrame),
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<Sent>>);

    impl Recorder {
        fn sent(&self) -> MutexGuard<'_, Vec<Sent>> {
            self.0.lock().unwrap()
        }

        fn frames(&self, agent: &str) -> usize {
            self.sent()
                .iter()
                .filter(|sent| matches!(sent, Sent::Frame(frame) if frame.frame_agent == agent))
                .count()
        }

        fn icon_shown(&self, agent: &str) -> bool {
            self.sent().iter().rev().find_map(|sent| match sent {
                Sent::Preview(line) if line.preview_agent == agent => Some(icon(line)),
                _ => None,
            }) == Some(true)
        }
    }

    impl PreviewOutput for Recorder {
        fn preview(&self, line: CursorPreview) -> bool {
            self.sent().push(Sent::Preview(line));
            true
        }

        fn frame(&self, frame: CursorFrame) -> bool {
            self.sent().push(Sent::Frame(frame));
            true
        }
    }

    /// A capture that does not answer until the test opens it, like a
    /// native request whose callback is late.
    #[derive(Default)]
    struct Held {
        calls: Mutex<u32>,
        open: Mutex<bool>,
        opened: Condvar,
    }

    impl Held {
        fn calls(&self) -> u32 {
            *self.calls.lock().unwrap()
        }

        fn open(&self) {
            *self.open.lock().unwrap() = true;
            self.opened.notify_all();
        }
    }

    impl PreviewCapturer for Held {
        fn capture(&self, _job: &CaptureJob) -> Result<PreviewJpeg, PreviewRefused> {
            *self.calls.lock().unwrap() += 1;
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.opened.wait(open).unwrap();
            }
            Ok(jpeg())
        }
    }

    fn wait_for(what: &str, condition: impl Fn() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < crate::test_support::HANG_GUARD,
                "never happened: {what}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The worker's wait for the first request is short here, so its
    /// timing out is reached quickly; nothing is asserted about how long
    /// anything takes.
    const SHORT_WAIT: Duration = Duration::from_millis(20);

    /// A request whose answer does not come, repeated refreshes, a hide,
    /// then the late answer: one native request in all, and no frame.
    #[test]
    fn an_unanswered_capture_then_hide_then_late_answer_sends_no_frame() {
        let output = Arc::new(Recorder::default());
        let held = Arc::new(Held::default());
        let worker = PreviewWorker::spawn_with(
            output.clone(),
            held.clone(),
            true,
            SHORT_WAIT,
            &PREVIEW_GAUGES,
        );
        worker.show(request("a", 10));
        wait_for("the first request", || held.calls() == 1);
        for _ in 0..5 {
            worker.action_started("a");
            worker.action_settled("a");
        }
        wait_for("the icon after the wait ended", || output.icon_shown("a"));
        assert!(worker.outstanding());
        worker.hide("a");
        held.open();
        wait_for("the late answer", || !worker.outstanding());
        assert_eq!(held.calls(), 1);
        assert_eq!(output.frames("a"), 0);
    }

    /// Agent A's request is outstanding when agent B acts: B's calls return
    /// without waiting for it, no second native request is made, and B's
    /// preview shows its icon. Once A's answers, B gets its frame.
    #[test]
    fn another_agents_action_during_an_outstanding_capture_shows_its_icon_and_is_not_held() {
        let output = Arc::new(Recorder::default());
        let held = Arc::new(Held::default());
        let worker = PreviewWorker::spawn_with(
            output.clone(),
            held.clone(),
            true,
            SHORT_WAIT,
            &PREVIEW_GAUGES,
        );
        worker.show(request("a", 10));
        wait_for("a's request", || held.calls() == 1);
        wait_for("a's icon after the wait ended", || output.icon_shown("a"));

        // Each of these returns while a's request is still held.
        let outcome = worker.show(request("b", 20));
        worker.action_started("b");
        worker.action_settled("b");
        assert_eq!(shown_slot(outcome), 1);
        assert!(output.icon_shown("b"));
        assert_eq!(held.calls(), 1);
        assert!(worker.outstanding());

        held.open();
        wait_for("b's frame", || output.frames("b") >= 1);
        assert!(held.calls() >= 2);
    }

    /// Without capture admitted, the worker shows the icon and makes no
    /// capture request.
    #[test]
    fn without_capture_admitted_the_worker_shows_the_icon_and_requests_nothing() {
        let output = Arc::new(Recorder::default());
        let held = Arc::new(Held::default());
        held.open();
        let worker = PreviewWorker::spawn(output.clone(), held.clone(), false);
        worker.show(request("a", 10));
        worker.action_started("a");
        worker.action_settled("a");
        assert!(output.icon_shown("a"));
        assert!(!worker.outstanding());
        assert_eq!(held.calls(), 0);
    }
}
