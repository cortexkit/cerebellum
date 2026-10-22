//! Ephemeral cursor pictures, not input events. No request body belongs here.

use serde::{Deserialize, Serialize};

/// The avatar raster's side in pixels. The avatar is drawn 31 points across
/// inside its chip and a Retina display draws each point as two pixels, so 64
/// pixels keep the avatar sharp; a smaller raster is upscaled and blurs into
/// an unrecognisable blob.
pub const AVATAR_SIZE: u32 = 64;
/// The longest pipe line. The largest is a preview frame: a JPEG of at most
/// `MAX_FRAME_BYTES` (160 KiB), which base64 writes as about 214 KiB, plus
/// the frame's other fields. An avatar update (64 x 64 x 4 bytes, each
/// written in JSON as at most three digits and a comma, so 64 KiB) is the
/// next largest.
pub const MAX_CURSOR_LINE: usize = 256 * 1024;
/// The largest preview frame, in JPEG bytes once its base64 is decoded. A
/// larger frame is dropped rather than sent or drawn.
pub const MAX_FRAME_BYTES: usize = 160 * 1024;
/// The preview slots, top-down: at most this many agents show a preview.
pub const PREVIEW_SLOTS: u8 = 3;
/// The longest application name a preview line carries, in characters.
const MAX_APP_NAME_CHARS: usize = 128;
/// The longest icon path a preview line carries, in bytes.
const MAX_ICON_PATH_BYTES: usize = 4096;
const MAX_LABEL_CHARS: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    Press,
    Write,
    Type,
    Keys,
    Reading,
}

impl CursorKind {
    fn verb(self) -> &'static str {
        match self {
            Self::Press => "Pressing",
            Self::Write | Self::Type => "Typing in",
            Self::Keys => "Keys in",
            Self::Reading => "Reading",
        }
    }
}

/// The only string derived from an element is its title, never its value.
/// Secure or unclassified elements must not supply a title to this function.
/// Reads carry no label at all: the picture only says where the agent is
/// looking, and a caption on every read would be noise over the app.
pub fn label(kind: CursorKind, title: Option<&str>, secure: bool) -> Option<String> {
    if secure || kind == CursorKind::Reading {
        return None;
    }
    let mut result = kind.verb().to_owned();
    if let Some(title) = title.filter(|title| !title.is_empty()) {
        result.push(' ');
        result.extend(title.chars().filter(|c| !c.is_control()));
    }
    // A cut title ends in an ellipsis so the pill never shows a word that
    // looks complete but is not ("Pressing 07 Prompt sur").
    if result.chars().count() > MAX_LABEL_CHARS {
        let mut cut: String = result.chars().take(MAX_LABEL_CHARS - 1).collect();
        cut.push('…');
        return Some(cut);
    }
    Some(result)
}

/// Closed pipe vocabulary: there is no text, value, chord or request payload.
/// Unknown fields are refused rather than accidentally forwarding typed text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorEvent {
    pub agent: String,
    pub initial: char,
    /// Where the pointer's tip goes, in global top-down screen points.
    pub to: [f64; 2],
    /// The acted-on element's frame (x, y, width, height), when one is known.
    /// The label pill is placed so it never covers this rectangle.
    pub target: Option<[f64; 4]>,
    /// `to` is only a place to appear (the window's content centre), not a
    /// target: a cursor that is already showing stays where it is.
    pub resting: bool,
    pub label: Option<String>,
    pub kind: CursorKind,
    pub serial: u64,
    pub avatar_rgba: Option<Vec<u8>>,
    pub avatar_update: bool,
    /// The colour read from the agent's avatar, when it is known; the badge
    /// is drawn in the accent it gives. Left out of the line when unknown, so
    /// a picture without it keeps the shape it had before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_tint: Option<AvatarTint>,
    /// How the badge reaches `to`, and how long it takes. The module chooses
    /// it and waits exactly this long before it sends the action, and the
    /// helper animates exactly this, so the two cannot disagree. Required on
    /// every picture: a helper never works out a motion of its own.
    pub motion: PictureMotion,
}

/// How a picture's badge reaches its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MotionStyle {
    /// The badge appears on the target with its entry animation.
    Entry,
    /// The badge glides there from wherever it is.
    Glide,
}

/// The motion the module chose for one picture.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PictureMotion {
    pub style: MotionStyle,
    /// How long after the picture arrives the badge's tip is on `to`, ms.
    pub duration_ms: f64,
    /// Whether the motion is the Reduce Motion form: a plain fade for an
    /// entry, a fade-move for a glide.
    pub reduce_motion: bool,
}

impl PictureMotion {
    /// The motion for a picture whose badge is not on screen yet (`first`)
    /// or rests `distance` points from its new target. This is the one place
    /// the module works a motion out; the helper only follows it.
    pub fn chosen(distance: f64, first: bool, reduce_motion: bool) -> Self {
        Self {
            style: if first {
                MotionStyle::Entry
            } else {
                MotionStyle::Glide
            },
            duration_ms: tip_arrival_ms(distance, first, reduce_motion),
            reduce_motion,
        }
    }

    /// A badge that stays where it is, or a line that moves nothing.
    pub fn still() -> Self {
        Self {
            style: MotionStyle::Glide,
            duration_ms: 0.0,
            reduce_motion: false,
        }
    }

    /// No motion longer than the longest the timeline ever gives.
    pub fn valid(&self) -> bool {
        self.duration_ms.is_finite() && (0.0..=LONGEST_ARRIVAL_MS).contains(&self.duration_ms)
    }
}

impl CursorEvent {
    pub fn encode_line(&self) -> Option<Vec<u8>> {
        if !self.valid() {
            return None;
        }
        let mut line = serde_json::to_vec(self).ok()?;
        line.push(b'\n');
        (line.len() <= MAX_CURSOR_LINE).then_some(line)
    }

    pub fn valid(&self) -> bool {
        self.to.iter().all(|v| v.is_finite())
            && self
                .target
                .is_none_or(|frame| frame.iter().all(|v| v.is_finite()))
            && self
                .avatar_rgba
                .as_ref()
                .is_none_or(|rgba| rgba.len() == (AVATAR_SIZE * AVATAR_SIZE * 4) as usize)
            && (!self.avatar_update || self.avatar_rgba.is_some())
            && self.avatar_tint.is_none_or(AvatarTint::valid)
            && self.motion.valid()
    }
}

/// Take one agent's picture off the screen now, rather than waiting for it to
/// fade after the agent stops acting. It names only the agent; there is nothing
/// else in it that could leak. `hide` is always true on the wire so the line is
/// self-describing, and the helper refuses a line with `hide: false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorHide {
    pub hide: bool,
    pub agent: String,
}

impl CursorHide {
    pub fn new(agent: impl Into<String>) -> Self {
        Self {
            hide: true,
            agent: agent.into(),
        }
    }
}

/// One line of the helper's stdin pipe: a picture to show or move, one
/// agent's picture to hide, the window under one agent's picture having
/// moved, or one of the three lines of the background-mode preview (the
/// preview itself, a frame of its window, and the badge's motion inside it).
/// Untagged, so a picture line keeps exactly the shape it had before the
/// others existed. Every shape refuses unknown fields, and no two share a
/// required field set (the preview lines' fields each carry their shape's
/// prefix), so a line decodes as at most one of them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CursorLine {
    Picture(CursorEvent),
    Hide(CursorHide),
    Follow(CursorFollow),
    Preview(CursorPreview),
    Frame(CursorFrame),
    PreviewMotion(CursorPreviewMotion),
}

/// Why a preview shows the application's icon instead of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewFallback {
    /// The target window is minimized, so there is nothing to capture.
    Minimized,
    /// The capture was refused: no live Screen Recording permission, a
    /// failed owner check, or a capture still outstanding.
    CaptureRefused,
}

/// Show one agent's preview, or point it at another window. It names the
/// agent, the slot it is drawn in, the window it shows and that window's
/// shape, plus the application's name and the action's label, which are the
/// only words it carries. With a fallback it shows the application's icon,
/// loaded by the helper from the application bundle at `preview_icon_path`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorPreview {
    pub preview_agent: String,
    /// Raised by the module at every hide and retarget. The helper drops a
    /// frame or motion from an older generation.
    pub preview_generation: u64,
    /// Which of the `PREVIEW_SLOTS` slots, top-down, from 0.
    pub preview_slot: u8,
    /// The window shown, by its window-server id.
    pub preview_window: u32,
    pub preview_app: String,
    /// The window's width and height, for the thumbnail's aspect ratio.
    pub preview_aspect: [f64; 2],
    /// The action's label as `label` makes it, or null for a read. Required
    /// on the line even when null, so a preview line can never be mistaken
    /// for another shape that lacks it.
    #[serde(deserialize_with = "Option::deserialize")]
    pub preview_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_fallback: Option<PreviewFallback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_icon_path: Option<String>,
}

impl CursorPreview {
    pub fn valid(&self) -> bool {
        let words_ok = |text: &str, most: usize| {
            text.chars().count() <= most && !text.chars().any(char::is_control)
        };
        self.preview_slot < PREVIEW_SLOTS
            && self
                .preview_aspect
                .iter()
                .all(|v| v.is_finite() && *v > 0.0)
            && words_ok(&self.preview_app, MAX_APP_NAME_CHARS)
            && self
                .preview_label
                .as_deref()
                .is_none_or(|label| words_ok(label, MAX_LABEL_CHARS))
            // An icon is shown only in place of a frame, and only from an
            // absolute bundle path.
            && self.preview_icon_path.as_deref().is_none_or(|path| {
                self.preview_fallback.is_some()
                    && path.starts_with('/')
                    && path.len() <= MAX_ICON_PATH_BYTES
                    && !path.chars().any(char::is_control)
            })
    }
}

/// One captured frame of the window an agent's preview shows. It never
/// creates or revives a preview: the helper draws it only into a preview of
/// the same generation and window that is still showing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorFrame {
    pub frame_agent: String,
    pub frame_generation: u64,
    pub frame_window: u32,
    /// The JPEG's size in pixels.
    pub frame_w: u32,
    pub frame_h: u32,
    /// The JPEG, standard base64 with padding.
    pub frame_jpeg: String,
}

impl CursorFrame {
    /// A frame of `jpeg`, encoded for the line.
    pub fn new(
        agent: impl Into<String>,
        generation: u64,
        window: u32,
        size: [u32; 2],
        jpeg: &[u8],
    ) -> Self {
        Self {
            frame_agent: agent.into(),
            frame_generation: generation,
            frame_window: window,
            frame_w: size[0],
            frame_h: size[1],
            frame_jpeg: base64_encode(jpeg),
        }
    }

    /// A frame is drawn only when it has pixels and its JPEG is at most
    /// `MAX_FRAME_BYTES` once decoded.
    pub fn valid(&self) -> bool {
        self.frame_w > 0
            && self.frame_h > 0
            && base64_decoded_len(&self.frame_jpeg)
                .is_some_and(|len| (1..=MAX_FRAME_BYTES).contains(&len))
    }

    /// The JPEG's bytes, or `None` when the base64 is malformed.
    pub fn jpeg(&self) -> Option<Vec<u8>> {
        base64_decode(&self.frame_jpeg)
    }
}

/// The badge's motion inside an agent's preview. Its points are relative to
/// the window the preview shows, each coordinate normalized to 0..1; the
/// helper places them in its slot. Like a picture's, its motion is the one the
/// module chose and times the action by, and the helper animates exactly it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorPreviewMotion {
    pub pmotion_agent: String,
    pub pmotion_serial: u64,
    pub pmotion_generation: u64,
    pub pmotion_window: u32,
    pub pmotion_kind: CursorKind,
    /// Where the pointer's tip goes.
    pub pmotion_to: [f64; 2],
    /// The acted-on element's visible centre.
    pub pmotion_target: [f64; 2],
    pub pmotion_motion: PictureMotion,
}

impl CursorPreviewMotion {
    pub fn valid(&self) -> bool {
        self.pmotion_to
            .iter()
            .chain(&self.pmotion_target)
            .all(|v| v.is_finite() && (0.0..=1.0).contains(v))
            && self.pmotion_motion.valid()
    }
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |word, (at, byte)| {
            word | u32::from(*byte) << (16 - 8 * at)
        });
        for at in 0..4 {
            if at <= chunk.len() {
                out.push(BASE64_ALPHABET[(word >> (18 - 6 * at)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The value of one base64 character, or `None` for any other byte.
fn base64_value(byte: u8) -> Option<u32> {
    BASE64_ALPHABET
        .iter()
        .position(|c| *c == byte)
        .map(|at| at as u32)
}

/// How many bytes `text` decodes to, without decoding it, or `None` when it
/// is not padded standard base64.
fn base64_decoded_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|c| **c == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - padding];
    if !body
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
    {
        return None;
    }
    Some(bytes.len() / 4 * 3 - padding)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let len = base64_decoded_len(text)?;
    let mut out = Vec::with_capacity(len);
    for chunk in text.as_bytes().chunks(4) {
        let mut word = 0u32;
        let mut present = 0;
        for (at, byte) in chunk.iter().enumerate() {
            if *byte != b'=' {
                word |= base64_value(*byte)? << (18 - 6 * at);
                present += 1;
            }
        }
        for at in 0..present - 1 {
            out.push((word >> (16 - 8 * at)) as u8);
        }
    }
    (out.len() == len).then_some(out)
}

/// The farthest a followed element may be reported to have moved, in points:
/// well past any arrangement of displays, so only a malformed report is
/// refused.
const MAX_FOLLOW_OFFSET: f64 = 100_000.0;

/// The element under one agent's badge moved because its window was moved or
/// resized, so the badge moves with it. It names the agent, the picture event
/// it belongs to, and a distance; nothing about the element or its window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorFollow {
    pub agent: String,
    /// The picture event the badge was last drawn for. The helper ignores a
    /// report for any other event: the badge has moved on since.
    pub serial: u64,
    /// How far the element has moved in total since that event, in points.
    /// A total rather than a step, so a report lost on a full pipe is made
    /// good by the next one.
    pub offset: [f64; 2],
}

impl CursorFollow {
    pub fn valid(&self) -> bool {
        self.offset
            .iter()
            .all(|v| v.is_finite() && v.abs() <= MAX_FOLLOW_OFFSET)
    }
}

/// What happened to the window an agent's badge rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowChange {
    Moved,
    Resized,
    /// The window closed or its application quit: there is nothing left to
    /// follow, and the badge stays where it last was.
    Gone,
}

fn frame_valid(frame: [f64; 4]) -> bool {
    frame.iter().all(|v| v.is_finite()) && frame[2] > 0.0 && frame[3] > 0.0
}

/// How far a badge's element has moved since its event, from the frames read
/// then (`base_*`) and now, or `None` when there is nothing trustworthy to go
/// on, which leaves the badge where it is rather than sending it anywhere
/// odd.
///
/// A moved window carries its whole content with it, so the element has
/// moved exactly as far as the window's origin. A resize can lay the content
/// out again, so the element's own frame is the better answer when it can
/// still be read; when it cannot (it scrolled away or was removed), the badge
/// keeps its offset from the window's top-left corner.
pub fn follow_offset(
    change: WindowChange,
    base_window: [f64; 4],
    window: [f64; 4],
    base_element: Option<[f64; 4]>,
    element: Option<[f64; 4]>,
) -> Option<[f64; 2]> {
    let delta = |from: [f64; 4], to: [f64; 4]| [to[0] - from[0], to[1] - from[1]];
    if change == WindowChange::Gone || !frame_valid(base_window) || !frame_valid(window) {
        return None;
    }
    let offset = match (change, base_element, element) {
        (WindowChange::Resized, Some(base), Some(now)) if frame_valid(base) && frame_valid(now) => {
            delta(base, now)
        }
        _ => delta(base_window, window),
    };
    offset
        .iter()
        .all(|v| v.abs() <= MAX_FOLLOW_OFFSET)
        .then_some(offset)
}

impl CursorLine {
    pub fn encode_line(&self) -> Option<Vec<u8>> {
        if !self.valid() {
            return None;
        }
        let mut line = match self {
            Self::Picture(event) => return event.encode_line(),
            Self::Hide(hide) => serde_json::to_vec(hide).ok()?,
            Self::Follow(follow) => serde_json::to_vec(follow).ok()?,
            Self::Preview(preview) => serde_json::to_vec(preview).ok()?,
            Self::Frame(frame) => serde_json::to_vec(frame).ok()?,
            Self::PreviewMotion(motion) => serde_json::to_vec(motion).ok()?,
        };
        line.push(b'\n');
        (line.len() <= MAX_CURSOR_LINE).then_some(line)
    }

    pub fn valid(&self) -> bool {
        match self {
            Self::Picture(event) => event.valid(),
            Self::Hide(hide) => hide.hide,
            Self::Follow(follow) => follow.valid(),
            Self::Preview(preview) => preview.valid(),
            Self::Frame(frame) => frame.valid(),
            Self::PreviewMotion(motion) => motion.valid(),
        }
    }

    /// Whether this line may start the helper when it is not running. Only
    /// a picture or a preview shows something new. With no helper there is
    /// no badge and no preview, so a hide, a follow, a frame or a motion
    /// inside a preview has nothing to act on, and none of them ever starts
    /// a helper just to be drawn.
    pub fn launches_helper(&self) -> bool {
        matches!(self, Self::Picture(_) | Self::Preview(_))
    }

    /// The agent this line is about.
    pub fn agent(&self) -> &str {
        match self {
            Self::Picture(event) => &event.agent,
            Self::Hide(hide) => &hide.agent,
            Self::Follow(follow) => &follow.agent,
            Self::Preview(preview) => &preview.preview_agent,
            Self::Frame(frame) => &frame.frame_agent,
            Self::PreviewMotion(motion) => &motion.pmotion_agent,
        }
    }

    /// The picture this line carries, if it is a picture.
    pub fn picture(self) -> Option<CursorEvent> {
        match self {
            Self::Picture(event) => Some(event),
            _ => None,
        }
    }
}

/// The helper's record of the previews it shows, deciding which preview
/// lines it draws. Host-neutral, so the rules are tested on every host.
///
/// - A preview line shows or retargets the agent's preview, unless its
///   generation is older than that agent's last hide or retarget.
/// - A frame or a motion is drawn only into the agent's preview that is
///   showing, of the same generation and window. A frame never creates or
///   revives a preview: after a hide, or once the preview has idled out, it
///   draws nothing.
/// - A preview line or a motion is an action and restarts the idle clock; a
///   frame never does, so a preview that only receives frames still idles
///   out on time.
#[derive(Default)]
pub struct PreviewGate {
    shown: std::collections::HashMap<String, GatedPreview>,
    /// For each agent, the oldest generation a preview line may still have:
    /// one past the generation it last hid or replaced.
    floors: std::collections::HashMap<String, u64>,
}

struct GatedPreview {
    generation: u64,
    window: u32,
    last_action: std::time::Instant,
}

/// Bounds the per-agent generation floors, far past the agents one person
/// runs at once.
const GATE_RECORD_CAP: usize = 256;

impl PreviewGate {
    /// Whether to draw `line`, received at `now`. Lines that are not about a
    /// preview are always drawn, apart from a hide, which also takes the
    /// agent's preview away.
    pub fn admit(&mut self, line: &CursorLine, now: std::time::Instant) -> bool {
        let idle_after = std::time::Duration::from_millis(IDLE_FADE_AFTER_MS + IDLE_FADE_MS);
        match line {
            CursorLine::Picture(_) | CursorLine::Follow(_) => true,
            CursorLine::Hide(hide) => {
                if let Some(gone) = self.shown.remove(&hide.agent) {
                    self.raise_floor(&hide.agent, gone.generation + 1);
                }
                true
            }
            CursorLine::Preview(preview) => {
                let agent = &preview.preview_agent;
                if preview.preview_generation < self.floors.get(agent).copied().unwrap_or_default()
                {
                    return false;
                }
                self.raise_floor(agent, preview.preview_generation);
                self.shown.insert(
                    agent.clone(),
                    GatedPreview {
                        generation: preview.preview_generation,
                        window: preview.preview_window,
                        last_action: now,
                    },
                );
                true
            }
            CursorLine::Frame(frame) => self
                .showing(&frame.frame_agent, now, idle_after)
                .is_some_and(|shown| {
                    shown.generation == frame.frame_generation && shown.window == frame.frame_window
                }),
            CursorLine::PreviewMotion(motion) => {
                let Some(shown) =
                    self.showing(&motion.pmotion_agent, now, idle_after)
                        .filter(|shown| {
                            shown.generation == motion.pmotion_generation
                                && shown.window == motion.pmotion_window
                        })
                else {
                    return false;
                };
                shown.last_action = now;
                true
            }
        }
    }

    /// Whether the agent's preview is showing.
    pub fn shows(&self, agent: &str) -> bool {
        self.shown.contains_key(agent)
    }

    /// The agent's preview, unless it has idled out by `now`, in which case
    /// it is gone for good: only a new preview line shows it again.
    fn showing(
        &mut self,
        agent: &str,
        now: std::time::Instant,
        idle_after: std::time::Duration,
    ) -> Option<&mut GatedPreview> {
        let idled = self
            .shown
            .get(agent)
            .is_some_and(|shown| now.saturating_duration_since(shown.last_action) >= idle_after);
        if idled {
            if let Some(gone) = self.shown.remove(agent) {
                self.raise_floor(agent, gone.generation + 1);
            }
            return None;
        }
        self.shown.get_mut(agent)
    }

    fn raise_floor(&mut self, agent: &str, floor: u64) {
        if self.floors.len() >= GATE_RECORD_CAP && !self.floors.contains_key(agent) {
            // Each floor only matters while an older line can still be on
            // its way, so forgetting them all loses nothing real.
            self.floors.clear();
        }
        let at = self.floors.entry(agent.to_owned()).or_default();
        *at = (*at).max(floor);
    }
}

// The glide and entry timings live in one file shared with the helper's
// crate, so the helper's animation and the module's wait for it agree.
pub use crate::cursor_timeline::{
    duration_ms, entry_ms, tip_arrival_ms, IDLE_FADE_AFTER_MS, IDLE_FADE_MS, LONGEST_ARRIVAL_MS,
    LONGEST_GLIDE_MS,
};
const TAP_MS: f64 = 180.0;
const SETTLE_MS: f64 = 220.0;

/// The tip's position along a glide. Progress eases out (fast start, gentle
/// landing) and the path bows slightly to one side so the motion reads as a
/// hand moving, not a sliding rectangle. The bow is perpendicular to the
/// straight line, so progress toward the target never goes backwards, and both
/// endpoints are exact. With Reduce Motion there is no path: the picture stays
/// put while it fades out, then appears at the target (see `fade_alpha`).
pub fn position(from: [f64; 2], to: [f64; 2], fraction: f64, reduce_motion: bool) -> [f64; 2] {
    if fraction >= 1.0 {
        return to;
    }
    if fraction <= 0.0 || !fraction.is_finite() {
        return from;
    }
    if reduce_motion {
        return if fraction < 0.5 { from } else { to };
    }
    let s = 1.0 - (1.0 - fraction).powi(3);
    let (dx, dy) = (to[0] - from[0], to[1] - from[1]);
    let length = dx.hypot(dy);
    if length <= f64::EPSILON || !length.is_finite() {
        return to;
    }
    // Rotated so a rightward move bows upward on a top-down screen.
    let bow = (length * 0.1).min(32.0) * 4.0 * s * (1.0 - s) / length;
    [from[0] + dx * s + dy * bow, from[1] + dy * s - dx * bow]
}

/// The pointer's scale after it lands, applied about the tip so the tip stays on
/// the target. A press dips to 0.9 and back like a tap; anything else swells
/// 4% and back as a settle. Reduce Motion keeps the scale at exactly 1.
pub fn settle_scale(since_arrival_ms: f64, press: bool, reduce_motion: bool) -> f64 {
    if reduce_motion || !since_arrival_ms.is_finite() || since_arrival_ms < 0.0 {
        return 1.0;
    }
    let (length, depth) = if press {
        (TAP_MS, -0.1)
    } else {
        (SETTLE_MS, 0.04)
    };
    if since_arrival_ms >= length {
        return 1.0;
    }
    1.0 + depth * (since_arrival_ms / length * std::f64::consts::PI).sin()
}

/// Opacity during a move. Only the Reduce Motion fade-move changes it: fully
/// visible at both ends, invisible at the midpoint where `position` jumps.
pub fn fade_alpha(fraction: f64, reduce_motion: bool) -> f64 {
    if !reduce_motion || !fraction.is_finite() || !(0.0..1.0).contains(&fraction) {
        return 1.0;
    }
    (2.0 * fraction - 1.0).abs()
}

/// The side of the square, in pixels, that an avatar is averaged down to
/// before its colour is read. The Alfonso phone app reads its agents' colours
/// from exactly this many pixels (24 x 24), so a badge here takes the same
/// colour as the agent's page there.
pub const TINT_SAMPLE_SIDE: usize = 24;
/// The side, in pixels, the avatar is rendered at before it is averaged
/// down: the phone draws the creature 44 points across on a 3x screen.
pub const TINT_RENDER_SIDE: u32 = 132;

/// An agent's colour as read from its avatar: HSV hue and saturation, each in
/// [0, 1].
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvatarTint {
    pub hue: f64,
    pub saturation: f64,
}

impl AvatarTint {
    pub fn valid(self) -> bool {
        [self.hue, self.saturation]
            .iter()
            .all(|v| v.is_finite() && (0.0..=1.0).contains(v))
    }
}

/// The phone's colour reading, ported from the Alfonso app's
/// `CreatureTint.dominantHue(of:)`: the hue of the creature's colourful
/// pixels, weighted toward the most saturated ones. `pixels` is premultiplied
/// RGBA, 8 bits per channel, in any order (the phone reads a 24 x 24 bitmap).
/// `None` when no pixel counts, which draws the neutral colour.
///
/// A pixel counts only when it is mostly opaque (edges blend into whatever is
/// behind), not near-black (outlines and the ground shadow) and not grey or
/// near-white (eyes, highlights). Its colour is un-premultiplied first, so a
/// half-transparent pixel is judged by its own colour, not by how dark the
/// premultiplication made it. Each counting pixel weighs its opacity times
/// its saturation squared, so a few vivid patches outweigh a large dull body.
/// Hue is a circle, so it is averaged as one: 0.97 and 0.03 are both red, and
/// their mean is 0.0, not the 0.5 (cyan) a plain mean would give.
pub fn avatar_tint(pixels: &[u8]) -> Option<AvatarTint> {
    let (mut cos, mut sin, mut saturation, mut weights) = (0.0, 0.0, 0.0, 0.0);
    for pixel in pixels.as_chunks::<4>().0 {
        let alpha = f64::from(pixel[3]) / 255.0;
        if alpha <= 0.6 {
            continue;
        }
        let [r, g, b] = [0, 1, 2].map(|channel| f64::from(pixel[channel]) / 255.0 / alpha);
        let top = r.max(g).max(b);
        let bottom = r.min(g).min(b);
        let delta = top - bottom;
        if top <= 0.2 || delta <= 0.12 {
            continue;
        }
        let sixths = if top == r {
            ((g - b) / delta).rem_euclid(6.0)
        } else if top == g {
            (b - r) / delta + 2.0
        } else {
            (r - g) / delta + 4.0
        };
        let hue = sixths / 6.0;
        let pixel_saturation = delta / top;
        let weight = alpha * pixel_saturation * pixel_saturation;
        let angle = std::f64::consts::TAU * hue;
        cos += weight * angle.cos();
        sin += weight * angle.sin();
        saturation += weight * pixel_saturation;
        weights += weight;
    }
    if weights <= 0.0 {
        return None;
    }
    // A tiny negative angle wraps to exactly 1.0 in floating point, which
    // is the same hue as 0.0; keep the result in [0, 1).
    let hue = (sin.atan2(cos) / std::f64::consts::TAU).rem_euclid(1.0);
    Some(AvatarTint {
        hue: if hue >= 1.0 { 0.0 } else { hue },
        saturation: saturation / weights,
    })
}

/// Average a square premultiplied RGBA image of `side` pixels down to `out`
/// pixels a side, each output pixel the area-weighted mean of the source
/// pixels it covers (partly covered ones count by the part covered).
/// Averaging premultiplied values keeps a transparent pixel's colour from
/// bleeding into its neighbours. Empty when `pixels` is not `side` square.
pub fn area_average(pixels: &[u8], side: usize, out: usize) -> Vec<u8> {
    if side == 0 || out == 0 || pixels.len() != side * side * 4 {
        return Vec::new();
    }
    let scale = side as f64 / out as f64;
    // For one output row or column: each source index it covers, and how
    // much of that source pixel lies inside it.
    let spans: Vec<Vec<(usize, f64)>> = (0..out)
        .map(|index| {
            let (start, end) = (index as f64 * scale, (index + 1) as f64 * scale);
            (start.floor() as usize..(end.ceil() as usize).min(side))
                .map(|source| {
                    let covered = end.min(source as f64 + 1.0) - start.max(source as f64);
                    (source, covered)
                })
                .filter(|(_, covered)| *covered > 0.0)
                .collect()
        })
        .collect();
    let area = scale * scale;
    let mut result = Vec::with_capacity(out * out * 4);
    for rows in &spans {
        for columns in &spans {
            let mut sum = [0.0; 4];
            for &(y, height) in rows {
                for &(x, width) in columns {
                    let at = (y * side + x) * 4;
                    for (channel, total) in sum.iter_mut().enumerate() {
                        *total += f64::from(pixels[at + channel]) * height * width;
                    }
                }
            }
            result.extend(sum.map(|total| (total / area).round().clamp(0.0, 255.0) as u8));
        }
    }
    result
}

/// The neutral colours drawn when an agent's avatar colour is unknown or its
/// avatar has no colourful pixels: a warm grey, as on the phone.
pub const NEUTRAL_LIGHT: [f64; 3] = [0.52, 0.49, 0.45];
pub const NEUTRAL_DARK: [f64; 3] = [0.66, 0.63, 0.59];

/// An agent's accent for Light and for Dark mode, sRGB in [0, 1].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Accents {
    pub light: [f64; 3],
    pub dark: [f64; 3],
}

/// The phone's accents for a tint, from `CreatureTint.init(creature:)`. The
/// saturation is held between 0.38 and 0.62, so a dull creature still gets a
/// visible colour and a vivid one does not glare; Dark mode takes a brighter,
/// slightly less saturated version so it stands out on dark windows.
pub fn accents(tint: Option<AvatarTint>) -> Accents {
    let Some(tint) = tint.filter(|tint| tint.valid()) else {
        return Accents {
            light: NEUTRAL_LIGHT,
            dark: NEUTRAL_DARK,
        };
    };
    let saturation = tint.saturation.clamp(0.38, 0.62);
    Accents {
        light: hsb_to_rgb(tint.hue, saturation, 0.60),
        dark: hsb_to_rgb(tint.hue, saturation * 0.85, 0.82),
    }
}

/// HSB (HSV), each in [0, 1], to sRGB in [0, 1].
pub fn hsb_to_rgb(hue: f64, saturation: f64, brightness: f64) -> [f64; 3] {
    let sixths = hue.rem_euclid(1.0) * 6.0;
    let sector = sixths.floor();
    let f = sixths - sector;
    let (v, s) = (brightness, saturation);
    let (p, q, t) = (v * (1.0 - s), v * (1.0 - s * f), v * (1.0 - s * (1.0 - f)));
    match sector as u8 {
        0 => [v, t, p],
        1 => [q, v, p],
        2 => [p, v, t],
        3 => [p, q, v],
        4 => [t, p, v],
        _ => [v, p, q],
    }
}

/// sRGB in [0, 1] to HSB (HSV), each in [0, 1].
pub fn rgb_to_hsb(colour: [f64; 3]) -> [f64; 3] {
    let [r, g, b] = colour;
    let top = r.max(g).max(b);
    let delta = top - r.min(g).min(b);
    let hue = if delta <= 0.0 {
        0.0
    } else if top == r {
        ((g - b) / delta).rem_euclid(6.0) / 6.0
    } else if top == g {
        ((b - r) / delta + 2.0) / 6.0
    } else {
        ((r - g) / delta + 4.0) / 6.0
    };
    let saturation = if top <= 0.0 { 0.0 } else { delta / top };
    [hue, saturation, top]
}

/// WCAG relative luminance of an sRGB colour.
pub fn luminance(colour: [f64; 3]) -> f64 {
    let linear = |c: f64| {
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(colour[0]) + 0.7152 * linear(colour[1]) + 0.0722 * linear(colour[2])
}

/// The WCAG contrast of white text on `colour`.
pub fn white_contrast(colour: [f64; 3]) -> f64 {
    1.05 / (luminance(colour) + 0.05)
}

/// The contrast white label text needs on its pill: WCAG's level for body
/// text, which a 12-point label is.
pub const PILL_CONTRAST: f64 = 4.5;

/// The label pill's fill for an accent: the accent's own hue and saturation,
/// darkened only as far as white text needs to reach `PILL_CONTRAST`. The
/// pointer and ring take the accent itself; the pill carries words, and some
/// of the phone's accents (above all the brighter Dark mode ones) are too
/// light for white text on them to be read easily. An accent that already
/// gives enough contrast is left as it is.
pub fn pill_colour(accent: [f64; 3]) -> [f64; 3] {
    if white_contrast(accent) >= PILL_CONTRAST {
        return accent;
    }
    let [hue, saturation, brightness] = rgb_to_hsb(accent);
    // Luminance only grows with brightness, so the brightest acceptable
    // value is found by halving the interval; `low` always passes.
    let (mut low, mut high) = (0.0, brightness);
    for _ in 0..48 {
        let middle = (low + high) / 2.0;
        if white_contrast(hsb_to_rgb(hue, saturation, middle)) >= PILL_CONTRAST {
            low = middle;
        } else {
            high = middle;
        }
    }
    hsb_to_rgb(hue, saturation, low)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One opaque pixel of the given HSB colour, 8-bit premultiplied RGBA.
    fn opaque(hue: f64, saturation: f64, brightness: f64) -> [u8; 4] {
        let [r, g, b] = hsb_to_rgb(hue, saturation, brightness).map(|c| (c * 255.0).round() as u8);
        [r, g, b, 255]
    }

    fn tint_of(pixels: &[[u8; 4]]) -> Option<AvatarTint> {
        avatar_tint(pixels.as_flattened())
    }

    /// The distance between two hues around the colour circle.
    fn hue_gap(a: f64, b: f64) -> f64 {
        let gap = (a - b).rem_euclid(1.0);
        gap.min(1.0 - gap)
    }

    #[test]
    fn tint_skips_transparent_dark_and_grey_pixels() {
        // Opacity: at most 0.6 is skipped (153 / 255 is exactly 0.6).
        assert_eq!(tint_of(&[[153, 0, 0, 153]]), None);
        assert!(tint_of(&[[154, 0, 0, 154]]).is_some());
        // Brightness: a brightest channel of at most 0.2 is an outline or
        // shadow (51 / 255 is exactly 0.2).
        assert_eq!(tint_of(&[[51, 0, 0, 255]]), None);
        assert!(tint_of(&[[52, 0, 0, 255]]).is_some());
        // Spread: channels within 0.12 of each other are grey (30 / 255 is
        // just under it, 31 / 255 just over).
        assert_eq!(tint_of(&[[200, 170, 170, 255]]), None);
        assert!(tint_of(&[[200, 169, 169, 255]]).is_some());
        // A skipped pixel does not pull the hue either: vivid blue pixels that
        // fail each rule leave a single red pixel's hue alone.
        let tint = tint_of(&[
            [255, 0, 0, 255],
            [0, 0, 153, 153],
            [0, 0, 51, 255],
            [170, 170, 200, 255],
        ])
        .unwrap();
        assert_eq!((tint.hue, tint.saturation), (0.0, 1.0));
    }

    #[test]
    fn tint_weighs_each_pixel_by_opacity_times_saturation_squared() {
        // Pure red (saturation 1) and a pale green (saturation s = 1 - 128/255,
        // about 0.498), both opaque: weights 1 and s^2. The saturation is
        // their weighted mean, (1 + s^2 x s) / (1 + s^2), about 0.90; a weight
        // of plain saturation would give (1 + s x s) / (1 + s), about 0.83.
        let s = 1.0 - 128.0 / 255.0;
        let tint = tint_of(&[[255, 0, 0, 255], [128, 255, 128, 255]]).unwrap();
        let mean = (1.0 + s * s * s) / (1.0 + s * s);
        assert!((tint.saturation - mean).abs() < 1e-9, "{}", tint.saturation);
        // The heavier red pulls the hue toward itself, short of the midpoint.
        assert!(tint.hue > 0.0 && tint.hue < 1.0 / 6.0, "{}", tint.hue);
        // Opacity counts linearly: the same red at 0.8 opacity weighs 0.8.
        let tint = tint_of(&[[204, 0, 0, 204], [128, 255, 128, 255]]).unwrap();
        let mean = (0.8 + s * s * s) / (0.8 + s * s);
        assert!((tint.saturation - mean).abs() < 1e-9, "{}", tint.saturation);
    }

    #[test]
    fn tint_hue_is_a_circular_mean() {
        // Two reds either side of 0: their mean is red, not cyan.
        let tint = tint_of(&[opaque(0.97, 1.0, 1.0), opaque(0.03, 1.0, 1.0)]).unwrap();
        assert!(hue_gap(tint.hue, 0.0) < 0.005, "{}", tint.hue);
        assert!((0.0..1.0).contains(&tint.hue));
        // Weighted toward the heavier side, still across the wrap.
        let tint = tint_of(&[
            opaque(0.95, 1.0, 1.0),
            opaque(0.95, 1.0, 1.0),
            opaque(0.03, 1.0, 1.0),
        ])
        .unwrap();
        assert!(tint.hue > 0.95 && tint.hue < 1.0, "{}", tint.hue);
    }

    #[test]
    fn tint_un_premultiplies_before_judging_a_pixel() {
        // A dark red at 0.7 opacity: its own brightest channel is 0.25, over
        // the 0.2 cut, but premultiplied it is stored as 45 / 255 = 0.176.
        let tint = tint_of(&[[45, 0, 0, 179]]).expect("judged by its own colour");
        assert_eq!(tint.hue, 0.0);
        // A pink at 0.7 opacity: premultiplied its channels are 29 / 255 =
        // 0.11 apart (too grey to count), un-premultiplied 0.16 apart.
        assert!(tint_of(&[[179, 150, 150, 179]]).is_some());
    }

    #[test]
    fn no_colourful_pixel_gives_the_neutral_accent() {
        assert_eq!(tint_of(&[]), None);
        assert_eq!(
            tint_of(&[[0, 0, 0, 0], [20, 20, 20, 255], [240, 240, 235, 255]]),
            None
        );
        let neutral = accents(None);
        assert_eq!(neutral.light, [0.52, 0.49, 0.45]);
        assert_eq!(neutral.dark, [0.66, 0.63, 0.59]);
        // A malformed tint is treated the same way.
        let malformed = AvatarTint {
            hue: f64::NAN,
            saturation: 0.5,
        };
        assert_eq!(accents(Some(malformed)), neutral);
    }

    fn close(a: [f64; 3], b: [f64; 3]) -> bool {
        a.iter().zip(b).all(|(a, b)| (a - b).abs() < 1e-9)
    }

    #[test]
    fn light_and_dark_accents_follow_the_phone_formulas() {
        let tint = AvatarTint {
            hue: 0.0,
            saturation: 0.5,
        };
        let both = accents(Some(tint));
        // Light: HSB(0, 0.5, 0.60).
        assert!(close(both.light, [0.60, 0.30, 0.30]), "{:?}", both.light);
        // Dark: HSB(0, 0.5 x 0.85, 0.82).
        assert!(close(
            both.dark,
            [0.82, 0.82 * (1.0 - 0.425), 0.82 * (1.0 - 0.425)]
        ));
        // A blue hue lands in the blue sector.
        let blue = accents(Some(AvatarTint {
            hue: 2.0 / 3.0,
            saturation: 0.5,
        }));
        assert!(close(blue.light, [0.30, 0.30, 0.60]), "{:?}", blue.light);
    }

    #[test]
    fn accent_saturation_is_held_between_0_38_and_0_62() {
        let at = |saturation: f64| {
            accents(Some(AvatarTint {
                hue: 0.0,
                saturation,
            }))
        };
        let saturation_of = |colour: [f64; 3]| rgb_to_hsb(colour)[1];
        assert!((saturation_of(at(0.1).light) - 0.38).abs() < 1e-9);
        assert!((saturation_of(at(0.1).dark) - 0.38 * 0.85).abs() < 1e-9);
        assert!((saturation_of(at(0.9).light) - 0.62).abs() < 1e-9);
        assert!((saturation_of(at(0.9).dark) - 0.62 * 0.85).abs() < 1e-9);
        assert!((saturation_of(at(0.5).light) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn the_pill_darkens_the_accent_just_enough_for_white_text() {
        let mut darkened = 0;
        for step in 0..=100 {
            let hue = f64::from(step) / 100.0;
            for saturation in [0.0, 0.3, 0.5, 0.9] {
                let both = accents(Some(AvatarTint { hue, saturation }));
                for accent in [both.light, both.dark, NEUTRAL_LIGHT, NEUTRAL_DARK] {
                    let pill = pill_colour(accent);
                    let contrast = white_contrast(pill);
                    assert!(
                        contrast >= PILL_CONTRAST,
                        "{accent:?} gives {contrast:.2}:1"
                    );
                    let [accent_hue, accent_saturation, accent_brightness] = rgb_to_hsb(accent);
                    let [pill_hue, pill_saturation, pill_brightness] = rgb_to_hsb(pill);
                    assert!(
                        hue_gap(pill_hue, accent_hue) < 1e-9,
                        "{accent:?} -> {pill:?}"
                    );
                    assert!((pill_saturation - accent_saturation).abs() < 1e-9);
                    if pill != accent {
                        darkened += 1;
                        // No darker than needed: a little brighter fails.
                        let brighter =
                            hsb_to_rgb(pill_hue, pill_saturation, pill_brightness + 0.002);
                        assert!(white_contrast(brighter) < PILL_CONTRAST);
                        assert!(pill_brightness < accent_brightness);
                    }
                }
            }
        }
        assert!(
            darkened > 0,
            "the phone's accents are too light for white text"
        );
    }

    #[test]
    fn area_average_weighs_partly_covered_pixels_by_the_part_covered() {
        // 3 pixels down to 2: each output pixel covers one whole source pixel
        // and half of the middle one.
        let row = |values: [u8; 3]| values.map(|v| [v, v, v, 255]);
        let image: Vec<[u8; 4]> = (0..3).flat_map(|_| row([0, 90, 180])).collect();
        let out = area_average(image.as_flattened(), 3, 2);
        assert_eq!(out.len(), 2 * 2 * 4);
        // (0 x 1 + 90 x 0.5) / 1.5 = 30, (90 x 0.5 + 180 x 1) / 1.5 = 150.
        assert_eq!(&out[0..4], &[30, 30, 30, 255]);
        assert_eq!(&out[4..8], &[150, 150, 150, 255]);
        // The phone's sizes: a uniform 132-pixel image stays that colour.
        let uniform = [10u8, 120, 200, 255].repeat(132 * 132);
        let out = area_average(&uniform, 132, TINT_SAMPLE_SIDE);
        assert_eq!(out, [10u8, 120, 200, 255].repeat(24 * 24));
        assert!(area_average(&uniform, 131, 24).is_empty());
    }

    #[test]
    fn glide_time_grows_with_distance_within_its_bounds() {
        assert_eq!(duration_ms(0.0, false), 0.0);
        assert_eq!(duration_ms(f64::NAN, false), 0.0);
        assert_eq!(duration_ms(-50.0, false), 0.0);
        assert_eq!(duration_ms(4.0, false), 181.0);
        assert_eq!(duration_ms(400.0, false), 280.0);
        assert_eq!(duration_ms(10_000.0, false), 450.0);
        let mut last = 0.0;
        for d in [1.0, 10.0, 100.0, 500.0, 1000.0, 2000.0] {
            let ms = duration_ms(d, false);
            assert!((180.0..=450.0).contains(&ms), "{d} -> {ms}");
            assert!(ms >= last, "longer moves never get faster");
            last = ms;
        }
        // Reduce Motion: a short fade-move, the same for every distance.
        assert_eq!(duration_ms(10.0, true), 140.0);
        assert_eq!(duration_ms(5000.0, true), 140.0);
        assert_eq!(duration_ms(0.0, true), 0.0);
    }

    #[test]
    fn every_picture_line_carries_the_motion_the_module_chose() {
        let event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 2.0],
            target: None,
            resting: false,
            label: None,
            kind: CursorKind::Press,
            serial: 3,
            avatar_rgba: None,
            avatar_update: false,
            avatar_tint: None,
            motion: PictureMotion::chosen(400.0, false, true),
        };
        assert_eq!(
            event.motion,
            PictureMotion {
                style: MotionStyle::Glide,
                duration_ms: 140.0,
                reduce_motion: true,
            }
        );
        assert_eq!(
            PictureMotion::chosen(400.0, true, false).style,
            MotionStyle::Entry
        );
        let line = event.encode_line().unwrap();
        assert_eq!(serde_json::from_slice::<CursorEvent>(&line).unwrap(), event);
        // A picture without a motion is no picture: the helper never makes
        // one up.
        let mut value = serde_json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().remove("motion");
        assert!(serde_json::from_value::<CursorEvent>(value).is_err());
        // Nor one longer than the timeline ever gives, or malformed.
        for duration_ms in [LONGEST_ARRIVAL_MS + 1.0, -1.0, f64::NAN] {
            let mut bad = event.clone();
            bad.motion.duration_ms = duration_ms;
            assert!(bad.encode_line().is_none(), "{duration_ms}");
        }
    }

    #[test]
    fn a_first_appearance_arrives_when_its_entry_ends_and_a_later_event_when_its_glide_does() {
        // A first appearance plays its entry on the target whatever the
        // distance: 1040 ms, or a 300 ms fade under Reduce Motion.
        for distance in [0.0, 400.0, 10_000.0] {
            assert_eq!(tip_arrival_ms(distance, true, false), 1040.0);
            assert_eq!(tip_arrival_ms(distance, true, true), 300.0);
        }
        // Every later event glides.
        assert_eq!(tip_arrival_ms(400.0, false, false), 280.0);
        assert_eq!(tip_arrival_ms(10_000.0, false, false), 450.0);
        assert_eq!(tip_arrival_ms(400.0, false, true), 140.0);
        assert_eq!(tip_arrival_ms(0.0, false, false), 0.0);
        // Nothing takes longer than the longest arrival, which is the entry.
        assert_eq!(LONGEST_ARRIVAL_MS, 1040.0);
        assert_eq!(LONGEST_GLIDE_MS, 450.0);
        assert_eq!(entry_ms(false), LONGEST_ARRIVAL_MS);
    }

    #[test]
    fn glide_endpoints_are_exact_and_progress_is_monotonic_along_a_slight_arc() {
        let (a, b) = ([10.0, -20.0], [410.0, 280.0]);
        assert_eq!(position(a, b, 0.0, false), a);
        assert_eq!(position(a, b, -1.0, false), a);
        assert_eq!(position(a, b, f64::NAN, false), a);
        assert_eq!(position(a, b, 1.0, false), b);
        assert_eq!(position(a, b, 1.5, false), b);
        let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
        let length = dx.hypot(dy);
        let mut last_progress = 0.0;
        let mut widest = 0.0_f64;
        for step in 1..100 {
            let p = position(a, b, f64::from(step) / 100.0, false);
            let progress = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (length * length);
            assert!(progress > last_progress, "step {step} went backwards");
            last_progress = progress;
            widest = widest.max(((p[0] - a[0]) * dy - (p[1] - a[1]) * dx).abs() / length);
        }
        // The curve is visible but gentle: at most a tenth of the distance and
        // never more than 32 points off the straight line.
        assert!(widest > 20.0 && widest <= 32.0, "bow {widest}");
        // Ease-out: more than half the way is covered in the first third.
        let third = position(a, b, 1.0 / 3.0, false);
        assert!(((third[0] - a[0]) * dx + (third[1] - a[1]) * dy) / (length * length) > 0.6);
    }

    #[test]
    fn reduce_motion_is_a_fade_move_with_no_arc_and_no_overshoot() {
        let (a, b) = ([10.0, -20.0], [410.0, 280.0]);
        for step in 0..50 {
            assert_eq!(position(a, b, f64::from(step) / 100.0, true), a);
        }
        for step in 50..=100 {
            assert_eq!(position(a, b, f64::from(step) / 100.0, true), b);
        }
        assert_eq!(fade_alpha(0.0, true), 1.0);
        assert_eq!(fade_alpha(0.25, true), 0.5);
        assert_eq!(fade_alpha(0.5, true), 0.0);
        assert_eq!(fade_alpha(1.0, true), 1.0);
        for step in 0..=100 {
            let t = f64::from(step) / 100.0;
            assert_eq!(fade_alpha(t, false), 1.0);
            assert_eq!(settle_scale(t * 300.0, true, true), 1.0);
            assert_eq!(settle_scale(t * 300.0, false, true), 1.0);
        }
    }

    #[test]
    fn settle_overshoots_four_percent_and_a_press_taps_down_to_nine_tenths() {
        assert_eq!(settle_scale(-1.0, false, false), 1.0);
        assert_eq!(settle_scale(0.0, false, false), 1.0);
        assert!((settle_scale(SETTLE_MS / 2.0, false, false) - 1.04).abs() < 1e-12);
        assert_eq!(settle_scale(SETTLE_MS, false, false), 1.0);
        assert!((settle_scale(TAP_MS / 2.0, true, false) - 0.9).abs() < 1e-12);
        assert_eq!(settle_scale(TAP_MS, true, false), 1.0);
        assert_eq!(settle_scale(f64::NAN, true, false), 1.0);
        for step in 0..=100 {
            let t = f64::from(step) * 3.0;
            assert!((1.0..=1.04 + 1e-12).contains(&settle_scale(t, false, false)));
            assert!((0.9 - 1e-12..=1.0).contains(&settle_scale(t, true, false)));
        }
    }

    #[test]
    fn cursor_labels_cut_characters_and_suppress_passwords() {
        assert_eq!(
            label(CursorKind::Press, Some("Send"), false).as_deref(),
            Some("Pressing Send")
        );
        assert_eq!(
            label(CursorKind::Type, Some(&"界".repeat(30)), false)
                .unwrap()
                .chars()
                .count(),
            24
        );
        assert_eq!(
            label(CursorKind::Write, Some("planted password label"), true),
            None
        );
    }

    #[test]
    fn pipe_vocabulary_cannot_carry_typed_text() {
        let event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 2.0],
            target: Some([0.0, 0.0, 20.0, 20.0]),
            resting: false,
            label: label(CursorKind::Type, Some("Message"), false),
            kind: CursorKind::Type,
            serial: 0,
            avatar_rgba: None,
            avatar_update: false,
            avatar_tint: None,
            motion: PictureMotion::chosen(400.0, false, false),
        };
        let encoded = event.encode_line().unwrap();
        assert_eq!(encoded.iter().filter(|c| **c == b'\n').count(), 1);
        let mut value = serde_json::to_value(&event).unwrap();
        for field in ["text", "value", "keys", "request"] {
            value[field] = serde_json::json!("planted typed secret");
            assert!(serde_json::from_value::<CursorEvent>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(
            serde_json::from_slice::<CursorEvent>(&encoded).unwrap(),
            event
        );
        // The helper decodes the wider line type; planted fields must not
        // slip through as a hide either.
        for field in ["text", "value", "keys", "request"] {
            value[field] = serde_json::json!("planted typed secret");
            assert!(serde_json::from_value::<CursorLine>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(
            serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
            CursorLine::Picture(event)
        );
    }

    #[test]
    fn hide_line_names_only_the_agent_and_refuses_extras() {
        let line = CursorLine::Hide(CursorHide::new("agent-a"));
        let encoded = line.encode_line().unwrap();
        assert_eq!(encoded, b"{\"hide\":true,\"agent\":\"agent-a\"}\n");
        assert_eq!(
            serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
            line
        );
        for planted in [
            r#"{"hide":true,"agent":"a","text":"planted typed secret"}"#,
            r#"{"hide":true}"#,
        ] {
            assert!(serde_json::from_str::<CursorLine>(planted).is_err());
        }
        let refused: CursorLine = serde_json::from_str(r#"{"hide":false,"agent":"a"}"#).unwrap();
        assert!(!refused.valid());
        assert!(refused.encode_line().is_none());
    }

    #[test]
    fn follow_line_names_only_agent_serial_and_offset_and_refuses_extras() {
        let line = CursorLine::Follow(CursorFollow {
            agent: "agent-a".into(),
            serial: 4,
            offset: [120.0, -30.5],
        });
        let encoded = line.encode_line().unwrap();
        assert_eq!(
            encoded,
            b"{\"agent\":\"agent-a\",\"serial\":4,\"offset\":[120.0,-30.5]}\n"
        );
        assert_eq!(
            serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
            line
        );
        for planted in [
            r#"{"agent":"a","serial":1,"offset":[1.0,2.0],"title":"planted"}"#,
            r#"{"agent":"a","offset":[1.0,2.0]}"#,
        ] {
            assert!(serde_json::from_str::<CursorLine>(planted).is_err());
        }
        for offset in [[f64::NAN, 0.0], [0.0, 2.0 * MAX_FOLLOW_OFFSET]] {
            let line = CursorLine::Follow(CursorFollow {
                agent: "a".into(),
                serial: 1,
                offset,
            });
            assert!(!line.valid());
            assert!(line.encode_line().is_none());
        }
        // A hide still decodes as a hide, not a follow, and the reverse.
        let hide: CursorLine = serde_json::from_str(r#"{"hide":true,"agent":"a"}"#).unwrap();
        assert!(matches!(hide, CursorLine::Hide(_)));
    }

    #[test]
    fn a_moved_window_moves_the_badge_by_its_origin_and_a_resize_follows_the_element() {
        let window = [100.0, 80.0, 800.0, 600.0];
        let element = [400.0, 120.0, 90.0, 22.0];
        let moved = [250.0, 40.0, 800.0, 600.0];
        assert_eq!(
            follow_offset(WindowChange::Moved, window, moved, Some(element), None),
            Some([150.0, -40.0])
        );
        // Resized from the left edge: the origin moved 60 left, but the
        // element is laid out again and moved only 20.
        let resized = [40.0, 80.0, 860.0, 600.0];
        assert_eq!(
            follow_offset(
                WindowChange::Resized,
                window,
                resized,
                Some(element),
                Some([380.0, 120.0, 90.0, 22.0])
            ),
            Some([-20.0, 0.0])
        );
        // The element can no longer be read: keep the offset from the
        // window's top-left corner.
        assert_eq!(
            follow_offset(WindowChange::Resized, window, resized, Some(element), None),
            Some([-60.0, 0.0])
        );
        // Nothing trustworthy: no move at all, never a jump to the origin.
        assert_eq!(
            follow_offset(WindowChange::Gone, window, moved, None, None),
            None
        );
        for broken in [[f64::NAN, 0.0, 10.0, 10.0], [0.0, 0.0, 0.0, 0.0]] {
            assert_eq!(
                follow_offset(WindowChange::Moved, window, broken, None, None),
                None
            );
            assert_eq!(
                follow_offset(WindowChange::Moved, broken, window, None, None),
                None
            );
        }
    }

    #[test]
    fn cursor_pipe_bounds_pixels_and_rejects_malformed_updates() {
        let mut event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 2.0],
            target: None,
            resting: false,
            label: None,
            kind: CursorKind::Press,
            serial: 7,
            avatar_rgba: Some(vec![255; (AVATAR_SIZE * AVATAR_SIZE * 4) as usize]),
            avatar_update: true,
            avatar_tint: None,
            motion: PictureMotion::chosen(0.0, true, false),
        };
        let line = event.encode_line().unwrap();
        assert!(line.len() <= MAX_CURSOR_LINE);
        assert_eq!(serde_json::from_slice::<CursorEvent>(&line).unwrap(), event);
        // The avatar's colour rides with its pixels, and a malformed one is
        // refused like malformed pixels.
        event.avatar_tint = Some(AvatarTint {
            hue: 0.95,
            saturation: 0.6,
        });
        let line = event.encode_line().unwrap();
        assert!(line.len() <= MAX_CURSOR_LINE);
        assert_eq!(serde_json::from_slice::<CursorEvent>(&line).unwrap(), event);
        event.avatar_tint = Some(AvatarTint {
            hue: 1.5,
            saturation: 0.6,
        });
        assert!(event.encode_line().is_none());
        event.avatar_tint = None;
        event.avatar_rgba.as_mut().unwrap().pop();
        assert!(event.encode_line().is_none());
        event.avatar_rgba = None;
        assert!(!event.valid());
        event.avatar_update = false;
        assert!(event.encode_line().is_some());
        event.target = Some([0.0, f64::NAN, 1.0, 1.0]);
        assert!(event.encode_line().is_none());
    }

    fn sample_picture() -> CursorEvent {
        CursorEvent {
            agent: "agent-a".into(),
            initial: 'A',
            to: [1.0, 2.0],
            target: Some([0.0, 0.0, 20.0, 20.0]),
            resting: false,
            label: label(CursorKind::Press, Some("Send"), false),
            kind: CursorKind::Press,
            serial: 3,
            avatar_rgba: None,
            avatar_update: false,
            avatar_tint: None,
            motion: PictureMotion::chosen(400.0, false, false),
        }
    }

    fn sample_preview() -> CursorPreview {
        CursorPreview {
            preview_agent: "agent-a".into(),
            preview_generation: 4,
            preview_slot: 1,
            preview_window: 77,
            preview_app: "Mail".into(),
            preview_aspect: [1200.0, 800.0],
            preview_label: label(CursorKind::Press, Some("Send"), false),
            preview_fallback: None,
            preview_icon_path: None,
        }
    }

    fn sample_frame() -> CursorFrame {
        CursorFrame::new(
            "agent-a",
            4,
            77,
            [560, 374],
            &[0xff, 0xd8, 0xff, 0xe0, 1, 2, 3],
        )
    }

    fn sample_motion() -> CursorPreviewMotion {
        CursorPreviewMotion {
            pmotion_agent: "agent-a".into(),
            pmotion_serial: 9,
            pmotion_generation: 4,
            pmotion_window: 77,
            pmotion_kind: CursorKind::Press,
            pmotion_to: [0.25, 0.75],
            pmotion_target: [0.25, 0.75],
            pmotion_motion: PictureMotion::chosen(140.0, false, false),
        }
    }

    fn every_shape() -> Vec<(&'static str, CursorLine)> {
        vec![
            ("picture", CursorLine::Picture(sample_picture())),
            ("hide", CursorLine::Hide(CursorHide::new("agent-a"))),
            (
                "follow",
                CursorLine::Follow(CursorFollow {
                    agent: "agent-a".into(),
                    serial: 3,
                    offset: [1.0, 2.0],
                }),
            ),
            ("preview", CursorLine::Preview(sample_preview())),
            ("frame", CursorLine::Frame(sample_frame())),
            ("pmotion", CursorLine::PreviewMotion(sample_motion())),
        ]
    }

    /// The names of every line shape `value` decodes as on its own.
    fn shapes_of(value: &serde_json::Value) -> Vec<&'static str> {
        let as_shape = |ok: bool, name: &'static str| ok.then_some(name);
        [
            as_shape(
                serde_json::from_value::<CursorEvent>(value.clone()).is_ok(),
                "picture",
            ),
            as_shape(
                serde_json::from_value::<CursorHide>(value.clone()).is_ok(),
                "hide",
            ),
            as_shape(
                serde_json::from_value::<CursorFollow>(value.clone()).is_ok(),
                "follow",
            ),
            as_shape(
                serde_json::from_value::<CursorPreview>(value.clone()).is_ok(),
                "preview",
            ),
            as_shape(
                serde_json::from_value::<CursorFrame>(value.clone()).is_ok(),
                "frame",
            ),
            as_shape(
                serde_json::from_value::<CursorPreviewMotion>(value.clone()).is_ok(),
                "pmotion",
            ),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    #[test]
    fn every_line_shape_decodes_as_itself_and_no_other() {
        for (name, line) in every_shape() {
            let encoded = line.encode_line().expect(name);
            assert_eq!(encoded.iter().filter(|c| **c == b'\n').count(), 1);
            assert_eq!(
                serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
                line,
                "{name}"
            );
            let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(shapes_of(&value), [name], "{name}");
            // A line missing any one field is never a different shape, and a
            // preview line missing any required field is no shape at all.
            for field in value.as_object().unwrap().keys() {
                let mut missing = value.clone();
                missing.as_object_mut().unwrap().remove(field);
                let shapes = shapes_of(&missing);
                assert!(
                    shapes.iter().all(|shape| *shape == name),
                    "{name} without {field} decoded as {shapes:?}"
                );
                let required = matches!(name, "preview" | "frame" | "pmotion")
                    && !matches!(field.as_str(), "preview_fallback" | "preview_icon_path");
                assert!(
                    !required || shapes.is_empty(),
                    "{name} without {field} decoded as {shapes:?}"
                );
            }
        }
        // A read's preview has no label, but still says so on the line.
        let mut read = sample_preview();
        read.preview_label = None;
        let encoded = CursorLine::Preview(read.clone()).encode_line().unwrap();
        assert!(String::from_utf8_lossy(&encoded).contains("\"preview_label\":null"));
        assert_eq!(
            serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
            CursorLine::Preview(read)
        );
        // A fallback with its icon path decodes too.
        let mut fallback = sample_preview();
        fallback.preview_fallback = Some(PreviewFallback::CaptureRefused);
        fallback.preview_icon_path = Some("/Applications/Mail.app".into());
        let encoded = CursorLine::Preview(fallback.clone()).encode_line().unwrap();
        assert!(String::from_utf8_lossy(&encoded).contains("\"capture_refused\""));
        assert_eq!(
            serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
            CursorLine::Preview(fallback)
        );
    }

    #[test]
    fn preview_lines_refuse_planted_text_fields() {
        for (name, line) in every_shape() {
            let mut value = serde_json::to_value(&line).unwrap();
            for field in ["text", "value", "keys", "request"] {
                value[field] = serde_json::json!("planted typed secret");
                assert!(
                    serde_json::from_value::<CursorLine>(value.clone()).is_err(),
                    "{name} took {field}"
                );
                value.as_object_mut().unwrap().remove(field);
            }
        }
    }

    #[test]
    fn a_preview_motion_carries_the_module_motion_through_a_round_trip() {
        // A first appearance, a later glide, and each under Reduce Motion.
        for (distance, first, reduce_motion) in [
            (0.0, true, false),
            (140.0, false, false),
            (140.0, false, true),
            (0.0, true, true),
        ] {
            let mut motion = sample_motion();
            motion.pmotion_motion = PictureMotion::chosen(distance, first, reduce_motion);
            let line = CursorLine::PreviewMotion(motion.clone());
            let decoded =
                serde_json::from_slice::<CursorLine>(&line.encode_line().unwrap()).unwrap();
            let CursorLine::PreviewMotion(decoded) = decoded else {
                panic!("decoded as {decoded:?}");
            };
            assert_eq!(decoded, motion);
            // The helper animates for exactly the serialized duration, which
            // is the one the module's arrival wait is timed by.
            assert_eq!(
                decoded.pmotion_motion.duration_ms,
                tip_arrival_ms(distance, first, reduce_motion)
            );
            assert_eq!(
                decoded.pmotion_motion.style == MotionStyle::Entry,
                first,
                "{distance} {first} {reduce_motion}"
            );
            assert_eq!(decoded.pmotion_motion.reduce_motion, reduce_motion);
        }
        // A motion without its motion, or out of the window, is no line.
        let mut value = serde_json::to_value(sample_motion()).unwrap();
        value.as_object_mut().unwrap().remove("pmotion_motion");
        assert!(serde_json::from_value::<CursorLine>(value).is_err());
        for to in [[1.5, 0.5], [-0.1, 0.5], [f64::NAN, 0.5]] {
            let mut outside = sample_motion();
            outside.pmotion_to = to;
            assert!(CursorLine::PreviewMotion(outside).encode_line().is_none());
        }
    }

    #[test]
    fn an_oversized_frame_is_dropped_and_the_largest_fits_one_line() {
        assert_eq!(MAX_CURSOR_LINE, 256 * 1024);
        assert_eq!(MAX_FRAME_BYTES, 160 * 1024);
        let jpeg: Vec<u8> = (0..MAX_FRAME_BYTES)
            .map(|at| (at * 7 % 256) as u8)
            .collect();
        let largest = CursorFrame::new("agent-a", 1, 77, [3840, 2160], &jpeg);
        let line = CursorLine::Frame(largest.clone());
        let encoded = line.encode_line().expect("the largest frame is sent");
        assert!(encoded.len() <= MAX_CURSOR_LINE, "{}", encoded.len());
        let decoded = serde_json::from_slice::<CursorLine>(&encoded).unwrap();
        assert_eq!(decoded, line);
        assert_eq!(largest.jpeg().unwrap(), jpeg);

        let mut over = jpeg.clone();
        over.push(0);
        let oversized = CursorFrame::new("agent-a", 1, 77, [3840, 2160], &over);
        assert!(!oversized.valid());
        assert!(CursorLine::Frame(oversized).encode_line().is_none());

        let mut broken = sample_frame();
        for jpeg in ["", "abc", "ab=c", "a===", "ab$="] {
            broken.frame_jpeg = jpeg.into();
            assert!(!broken.valid(), "{jpeg:?}");
        }
        let mut empty = sample_frame();
        empty.frame_w = 0;
        assert!(!empty.valid());
    }

    #[test]
    fn frame_base64_is_standard_and_padded() {
        for (bytes, text) in [
            (&b"f"[..], "Zg=="),
            (&b"fo"[..], "Zm8="),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg=="),
            (&b"foobar"[..], "Zm9vYmFy"),
            (&[0xfb, 0xff][..], "+/8="),
        ] {
            assert_eq!(base64_encode(bytes), text);
            assert_eq!(base64_decoded_len(text), Some(bytes.len()));
            assert_eq!(base64_decode(text).as_deref(), Some(bytes));
        }
    }

    #[test]
    fn preview_lines_are_bounded() {
        assert!(sample_preview().valid());
        let refused: [fn(&mut CursorPreview); 6] = [
            |p| p.preview_slot = PREVIEW_SLOTS,
            |p| p.preview_aspect = [0.0, 800.0],
            |p| p.preview_aspect = [f64::INFINITY, 800.0],
            |p| p.preview_label = Some("x".repeat(MAX_LABEL_CHARS + 1)),
            |p| p.preview_icon_path = Some("/Applications/Mail.app".into()),
            |p| {
                p.preview_fallback = Some(PreviewFallback::Minimized);
                p.preview_icon_path = Some("Mail.app".into());
            },
        ];
        for (at, refuse) in refused.iter().enumerate() {
            let mut preview = sample_preview();
            refuse(&mut preview);
            assert!(!preview.valid(), "case {at}");
            assert!(CursorLine::Preview(preview).encode_line().is_none());
        }
        let mut icon = sample_preview();
        icon.preview_fallback = Some(PreviewFallback::Minimized);
        assert!(icon.valid(), "a fallback may come without an icon path");
    }

    #[test]
    fn only_a_picture_or_a_preview_launches_the_helper() {
        for (name, line) in every_shape() {
            assert_eq!(
                line.launches_helper(),
                matches!(name, "picture" | "preview"),
                "{name}"
            );
            assert_eq!(line.agent(), "agent-a");
        }
    }

    fn frame_for(generation: u64, window: u32) -> CursorLine {
        CursorLine::Frame(CursorFrame::new(
            "agent-a",
            generation,
            window,
            [10, 10],
            &[1, 2, 3],
        ))
    }

    fn preview_for(generation: u64, window: u32) -> CursorLine {
        let mut preview = sample_preview();
        preview.preview_generation = generation;
        preview.preview_window = window;
        CursorLine::Preview(preview)
    }

    fn motion_for(generation: u64, window: u32) -> CursorLine {
        let mut motion = sample_motion();
        motion.pmotion_generation = generation;
        motion.pmotion_window = window;
        CursorLine::PreviewMotion(motion)
    }

    #[test]
    fn a_frame_never_creates_a_preview_and_a_late_frame_after_hide_draws_nothing() {
        let start = std::time::Instant::now();
        let mut gate = PreviewGate::default();
        assert!(!gate.admit(&frame_for(4, 77), start), "no preview yet");
        assert!(!gate.shows("agent-a"), "a frame created a preview");
        assert!(gate.admit(&preview_for(4, 77), start));
        assert!(gate.admit(&frame_for(4, 77), start));
        assert!(gate.admit(&motion_for(4, 77), start));
        assert!(gate.admit(&CursorLine::Hide(CursorHide::new("agent-a")), start));
        assert!(!gate.shows("agent-a"));
        // The frame captured before the hide arrives after it.
        assert!(!gate.admit(&frame_for(4, 77), start), "a late frame drew");
        assert!(!gate.admit(&motion_for(4, 77), start), "a late motion drew");
        assert!(!gate.shows("agent-a"), "a late frame revived the preview");
        // So does a preview line from before the hide.
        assert!(!gate.admit(&preview_for(4, 77), start));
        // The next action's preview shows it again, at a newer generation.
        assert!(gate.admit(&preview_for(5, 77), start));
        assert!(gate.admit(&frame_for(5, 77), start));
    }

    #[test]
    fn a_retarget_drops_older_frames_and_frames_of_another_window() {
        let start = std::time::Instant::now();
        let mut gate = PreviewGate::default();
        assert!(gate.admit(&preview_for(4, 77), start));
        assert!(gate.admit(&preview_for(5, 78), start), "retargeted");
        assert!(!gate.admit(&frame_for(4, 77), start), "an older generation");
        assert!(!gate.admit(&motion_for(4, 77), start));
        assert!(!gate.admit(&frame_for(5, 77), start), "another window");
        assert!(!gate.admit(&frame_for(6, 78), start), "a newer generation");
        assert!(!gate.admit(&preview_for(4, 77), start), "an older retarget");
        assert!(gate.admit(&frame_for(5, 78), start));
        // Another agent's preview is its own.
        let mut other = sample_frame();
        other.frame_agent = "agent-b".into();
        assert!(!gate.admit(&CursorLine::Frame(other), start));
    }

    #[test]
    fn a_frame_after_the_idle_timeout_draws_nothing_and_never_restarts_the_clock() {
        let idle = std::time::Duration::from_millis(IDLE_FADE_AFTER_MS + IDLE_FADE_MS);
        let step = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();
        let mut gate = PreviewGate::default();
        assert!(gate.admit(&preview_for(4, 77), start));
        // Frames keep arriving twice a second; none of them is an action.
        let mut at = start;
        while at + step < start + idle {
            at += step;
            assert!(gate.admit(&frame_for(4, 77), at));
        }
        assert!(!gate.admit(&frame_for(4, 77), start + idle), "idled out");
        assert!(!gate.shows("agent-a"));
        assert!(!gate.admit(&frame_for(4, 77), start + idle + step));
        assert!(!gate.admit(&motion_for(4, 77), start + idle + step));

        // A motion is an action: it restarts the clock.
        let mut gate = PreviewGate::default();
        assert!(gate.admit(&preview_for(4, 77), start));
        assert!(gate.admit(&motion_for(4, 77), start + idle - step));
        assert!(gate.admit(&frame_for(4, 77), start + idle));
        assert!(!gate.admit(&frame_for(4, 77), start + idle - step + idle));
    }
}
