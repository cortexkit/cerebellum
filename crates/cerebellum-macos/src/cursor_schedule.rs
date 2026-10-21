//! Host-neutral lifetime and wake decisions for ephemeral cursor pictures,
//! and the clocks and curves that animate them.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::cursor_geometry::{aim_rotation, shortest_turn, wrap_angle, CHIP_CENTER};

const FRAME_INTERVAL: Duration = Duration::from_nanos(1_000_000_000 / 60);
const MAX_PICTURES: usize = 64;

/// The most a picture's animation clock moves on between two frames: three
/// 60 Hz frames. A frame that arrives on time, or one or two frames late,
/// advances the animation by the real time that passed, so on-time motion
/// keeps its exact speed. A frame that arrives much later (because macOS
/// throttled the helper's wake-ups, or the main thread was busy) advances it
/// by only this much: the glide runs slower instead of skipping straight to
/// its end, so the person still sees the badge travel and never sees it jump.
pub(crate) const MAX_FRAME_STEP: Duration = Duration::from_millis(50);

/// How far into its animation a picture is, in ms of animation shown.
///
/// The glide, settle and entry are functions of time, and the helper used to
/// feed them wall-clock time since the event. If the helper's wake-ups came
/// late, the first frame after a 300 ms glide began could already be past
/// its end, and the badge was drawn once at the start and once at the
/// destination: a jump. This clock moves at most `MAX_FRAME_STEP` per frame,
/// so every frame that is drawn shows a step of the motion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FrameClock {
    last: Instant,
    shown_ms: f64,
}

impl FrameClock {
    pub(crate) fn start(now: Instant) -> Self {
        Self {
            last: now,
            shown_ms: 0.0,
        }
    }

    /// The animation time to draw at `now`, which is also when this frame is
    /// drawn. A `now` earlier than the last frame does not run time backwards.
    pub(crate) fn advance(&mut self, now: Instant) -> f64 {
        let step = now.saturating_duration_since(self.last).min(MAX_FRAME_STEP);
        self.last = self.last.max(now);
        self.shown_ms += step.as_secs_f64() * 1000.0;
        self.shown_ms
    }
}

// The entry's whole length, shared with the module, which waits for the
// entry to end before a first action is sent.
pub(crate) use crate::cursor_timeline::{ENTRY_MS, REDUCED_ENTRY_MS};
/// The avatar alone fades in, at its large entry size, over this long.
const ENTRY_POP_MS: f64 = 200.0;
/// Then it shrinks from here to the end of the entry.
const ENTRY_SHRINK_FROM_MS: f64 = 360.0;
/// The pointer and the label grow and fade in from here to the end.
const ENTRY_POINTER_FROM_MS: f64 = 520.0;
/// The pointer's scale about its tip when it starts to grow in.
pub(crate) const ENTRY_POINTER_SCALE: f64 = 0.5;

/// One frame of a first appearance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct EntryFrame {
    /// The chip's progress from its large entry place on the tip (0) to its
    /// resting place and size (1); see `cursor_geometry::chip_at`.
    pub chip: f64,
    /// How far the pointer and label have come in: their opacity, and the
    /// pointer's scale from `ENTRY_POINTER_SCALE` (0) to full size (1).
    pub pointer: f64,
    /// The whole picture's opacity.
    pub alpha: f64,
}

impl EntryFrame {
    pub(crate) const REST: Self = Self {
        chip: 1.0,
        pointer: 1.0,
        alpha: 1.0,
    };

    /// The pointer's scale about the tip for this frame.
    pub(crate) fn pointer_scale(self) -> f64 {
        ENTRY_POINTER_SCALE + (1.0 - ENTRY_POINTER_SCALE) * self.pointer
    }
}

fn ease_out(t: f64) -> f64 {
    1.0 - (1.0 - t).powi(3)
}

fn ease_in_out(t: f64) -> f64 {
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
    }
}

/// The share of the span from `from` to `to` ms that `elapsed` has covered.
fn share(elapsed: f64, from: f64, to: f64) -> f64 {
    ((elapsed - from) / (to - from)).clamp(0.0, 1.0)
}

/// The entry's frame `elapsed_ms` into it, or `None` once it is over: the
/// full entry, or under Reduce Motion the plain fade, at their usual lengths.
pub(crate) fn entry_frame(elapsed_ms: f64, reduce_motion: bool) -> Option<EntryFrame> {
    shaped_entry_frame(
        elapsed_ms,
        EntryShape {
            total_ms: if reduce_motion {
                REDUCED_ENTRY_MS
            } else {
                ENTRY_MS
            },
            fade_only: reduce_motion,
        },
    )
}

/// How one appearance enters: over `total_ms`, either the full entry with its
/// phases stretched or squeezed to that length, or a plain fade.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct EntryShape {
    pub total_ms: f64,
    pub fade_only: bool,
}

/// An entry's frame `elapsed_ms` into it, or `None` once it is over. A
/// malformed time ends it: a badge must never be left half-entered.
pub(crate) fn shaped_entry_frame(elapsed_ms: f64, shape: EntryShape) -> Option<EntryFrame> {
    let total = shape.total_ms;
    if !elapsed_ms.is_finite() || !total.is_finite() || elapsed_ms >= total {
        return None;
    }
    let elapsed = elapsed_ms.max(0.0);
    if shape.fade_only {
        return Some(EntryFrame {
            alpha: share(elapsed, 0.0, total),
            ..EntryFrame::REST
        });
    }
    // The phases keep their places as shares of the whole entry.
    let scale = total / ENTRY_MS;
    Some(EntryFrame {
        chip: ease_in_out(share(elapsed, ENTRY_SHRINK_FROM_MS * scale, total)),
        pointer: ease_out(share(elapsed, ENTRY_POINTER_FROM_MS * scale, total)),
        alpha: ease_out(share(elapsed, 0.0, ENTRY_POP_MS * scale)),
    })
}

/// Whether a picture has appeared yet and, while it is still appearing, its
/// entry clock. One lives in each picture, and a picture lives from its
/// agent's first event until it is hidden, so the entry plays once per
/// appearance: later actions only glide, and a badge shown again after a
/// hide is a new picture with an entry of its own.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Appearance {
    shown: bool,
    entry: Option<(FrameClock, EntryShape)>,
}

impl Appearance {
    /// An event arrived. Answers whether this is the first appearance, which
    /// starts an entry of the given shape.
    pub(crate) fn on_event(&mut self, now: Instant, shape: EntryShape) -> bool {
        if self.shown {
            return false;
        }
        self.shown = true;
        self.entry = Some((FrameClock::start(now), shape));
        true
    }

    pub(crate) fn entering(&self) -> bool {
        self.entry.is_some()
    }

    /// The entry frame to draw at `now`; the resting frame once it is over.
    pub(crate) fn frame(&mut self, now: Instant) -> EntryFrame {
        let Some((clock, shape)) = self.entry.as_mut() else {
            return EntryFrame::REST;
        };
        match shaped_entry_frame(clock.advance(now), *shape) {
            Some(frame) => frame,
            None => {
                self.entry = None;
                EntryFrame::REST
            }
        }
    }
}

/// The motion the module chose for one picture, as the helper receives it on
/// the picture's line. The helper animates exactly this and never works out
/// a length or a style of its own: the module waits exactly `duration_ms`
/// before it sends the action, so the badge must be on its target by then.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PictureTiming {
    /// The module expects the badge to appear with its entry; otherwise to
    /// glide from where it is.
    pub entry: bool,
    pub duration_ms: f64,
    pub reduce_motion: bool,
}

/// One picture event, as the helper received it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PictureAim {
    pub to: [f64; 2],
    pub resting: bool,
    pub press: bool,
    pub timing: PictureTiming,
}

/// Start one picture event with the module's chosen motion, from wherever
/// the badge really is. Answers the tip's destination and whether this is
/// the picture's first appearance.
///
/// The module's idea of whether the badge is on screen can be out of date
/// (the helper faded it out, or never drew it). Either way the badge is on
/// its target, fully shown, after exactly `duration_ms`: a glide for a badge
/// the helper is not showing appears on its target with a plain fade over
/// that time, and an entry for a badge already on screen glides there over
/// that time.
pub(crate) fn begin_picture(
    appearance: &mut Appearance,
    motion: &mut BadgeMotion,
    aim: PictureAim,
    now: Instant,
) -> ([f64; 2], bool) {
    let timing = aim.timing;
    let shape = EntryShape {
        total_ms: timing.duration_ms,
        fade_only: timing.reduce_motion || !timing.entry,
    };
    let first = appearance.on_event(now, shape);
    let to = motion.on_event(
        MotionEvent {
            to: aim.to,
            resting: aim.resting,
            first,
            press: aim.press,
            reduce_motion: timing.reduce_motion,
            duration_ms: timing.duration_ms,
        },
        now,
    );
    (to, first)
}

/// How long a badge takes to change colour, in ms: when its agent's avatar
/// colour arrives after the badge appeared in the neutral one, or the system
/// switches between Light and Dark mode. Long enough to read as a change of
/// tint rather than a flicker, short enough to be done before the next
/// action.
pub(crate) const COLOUR_FADE_MS: f64 = 200.0;

/// The colours a badge is drawn in, sRGB in [0, 1]: the pointer and the
/// chip's ring, then the label pill.
pub(crate) type Colours = [[f64; 3]; 2];

/// A badge's colours, cross-faded from one set to the next.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ColourFade {
    from: Colours,
    to: Colours,
    shown: Colours,
    clock: Option<FrameClock>,
}

impl ColourFade {
    pub(crate) fn new(colours: Colours) -> Self {
        Self {
            from: colours,
            to: colours,
            shown: colours,
            clock: None,
        }
    }

    /// Change to `colours`: at once when `fade` is false (a badge that is
    /// only now appearing), otherwise by a cross-fade from the colours shown
    /// now, so a change mid-fade carries on from where it is.
    pub(crate) fn set(&mut self, colours: Colours, now: Instant, fade: bool) {
        if colours == self.to && (fade || self.clock.is_none()) {
            return;
        }
        self.to = colours;
        if fade {
            self.from = self.shown;
            self.clock = Some(FrameClock::start(now));
        } else {
            self.from = colours;
            self.shown = colours;
            self.clock = None;
        }
    }

    /// The colours to draw at `now`, and whether they are still changing.
    pub(crate) fn frame(&mut self, now: Instant) -> (Colours, bool) {
        let Some(clock) = self.clock.as_mut() else {
            return (self.shown, false);
        };
        let progress = (clock.advance(now) / COLOUR_FADE_MS).clamp(0.0, 1.0);
        if progress >= 1.0 {
            self.clock = None;
            self.shown = self.to;
            return (self.shown, false);
        }
        let eased = ease_in_out(progress);
        for (part, (from, to)) in self.shown.iter_mut().zip(self.from.iter().zip(self.to)) {
            for (channel, (a, b)) in part.iter_mut().zip(from.iter().zip(to)) {
                *channel = a + (b - a) * eased;
            }
        }
        (self.shown, true)
    }
}

/// Motion curves, supplied by the platform-neutral crate where they are
/// tested on every host.
#[derive(Clone, Copy)]
pub struct CursorMotion {
    /// Glide length in ms from the distance and the Reduce Motion setting.
    pub duration_ms: fn(f64, bool) -> f64,
    /// The tip's position for a glide fraction in [0, 1].
    pub position: fn([f64; 2], [f64; 2], f64, bool) -> [f64; 2],
    /// Scale about the tip, from ms since arrival, press or not, Reduce Motion.
    pub settle_scale: fn(f64, bool, bool) -> f64,
    /// Opacity factor for a glide fraction (the Reduce Motion fade-move).
    pub fade_alpha: fn(f64, bool) -> f64,
}

/// One 60 Hz frame, in ms: how far ahead a picture looks to decide whether its
/// landing motion still needs another frame.
const ONE_FRAME_MS: f64 = 1000.0 / 60.0;

/// How long a dragged window must stay still before the badge flies back
/// onto its element. While a person drags a window, the accessibility move
/// reports come in bursts with short gaps between them, and the hand often
/// pauses for a moment without letting go. 700 ms outlasts those gaps and
/// pauses, so the badge flies once, after the drag, instead of setting off in
/// every pause and being pulled away again by the next burst.
pub(crate) const WINDOW_QUIET: Duration = Duration::from_millis(700);

/// How long the swinging pointer takes to turn to a newly reported
/// direction, in ms. Move reports arrive in bursts; easing each turn over a
/// few frames joins them into one smooth sweep instead of a series of jumps.
pub(crate) const HAND_EASE_MS: f64 = 120.0;

/// What the pointer is doing relative to the chip.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Hand {
    /// In its resting place, pointing at the target with its tip on it.
    Off,
    /// The window under the target is moving. The chip holds still and the
    /// pointer turns about it, from `from` toward `to` (rotations from the
    /// resting direction, in radians, not wrapped, so the turn between them
    /// is the short one picked when the report came in).
    Swinging {
        from: f64,
        to: f64,
        ease: FrameClock,
        /// The latest move report; the badge flies back once the window has
        /// been still for `WINDOW_QUIET` after it.
        last_move: Instant,
    },
    /// The badge is gliding to its target (the window came to rest, or a new
    /// action aims elsewhere) and the pointer turns from `from` back to its
    /// resting direction along the way, arriving exactly with the glide.
    Returning { from: f64 },
}

/// One event's aim, as the helper received it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct MotionEvent {
    /// The tip's destination, global top-down points.
    pub to: [f64; 2],
    /// `to` is only somewhere to appear: a shown badge stays where it is.
    pub resting: bool,
    /// The picture's first appearance, which enters rather than glides.
    pub first: bool,
    /// A press lands with a tap rather than a settle.
    pub press: bool,
    pub reduce_motion: bool,
    /// How long the glide takes, as the module chose it.
    pub duration_ms: f64,
}

/// Where a picture is and what its pointer does on one frame.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct MotionFrame {
    /// Where the tip of the standard resting badge would be: the panel is
    /// placed for it, and the chip's centre is this plus `CHIP_CENTER`
    /// whatever the pointer does.
    pub tip: [f64; 2],
    /// How far the pointer is turned about the chip's centre from its
    /// resting direction, radians; exactly 0 in the resting badge.
    pub rotation: f64,
    /// The pointer's own opacity: 0 while Reduce Motion hides it during a
    /// window drag instead of swinging it.
    pub pointer_alpha: f64,
    /// The pointer is off its resting place (swinging, or turning back on a
    /// glide): the label stays hidden and the panel must hold every angle.
    pub hand: bool,
    /// The landing scale about the tip.
    pub scale: f64,
    /// The Reduce Motion fade-move's opacity factor.
    pub alpha: f64,
    pub need: PictureNeed,
}

/// A picture's movement: its glides between targets, the landing settle,
/// following a moved window, and the clock-hand swing while that window is
/// dragged. It knows nothing of windows or drawing, so every state change
/// is tested on any host; the helper draws what `frame` answers.
///
/// A dragged window reports its moves in bursts. Gliding the whole badge to
/// each report made it stutter after the window, so instead the chip holds
/// still and only the pointer turns toward where the element now is; once
/// the window has been still for `WINDOW_QUIET`, the badge flies there in one
/// glide while the pointer turns back into its resting place.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct BadgeMotion {
    from: [f64; 2],
    to: [f64; 2],
    current: [f64; 2],
    duration_ms: f64,
    reduce: bool,
    press: bool,
    /// Whether the landing settle or tap plays after the glide. Not on a
    /// first appearance (the entry is that picture's landing) and not after
    /// following a window (the agent did nothing).
    settles: bool,
    /// Time into the current glide and settle.
    glide: FrameClock,
    /// How far the window under the target has moved since the latest event.
    follow: FollowOffset,
    hand: Hand,
    /// The pointer's rotation on the latest frame drawn: where a new turn
    /// starts from, so the pointer never jumps.
    rotation: f64,
}

impl BadgeMotion {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            from: [0.0, 0.0],
            to: [0.0, 0.0],
            current: [0.0, 0.0],
            duration_ms: 0.0,
            reduce: false,
            press: false,
            settles: false,
            glide: FrameClock::start(now),
            follow: FollowOffset::default(),
            hand: Hand::Off,
            rotation: 0.0,
        }
    }

    /// Where the badge was last drawn (the resting tip's place).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn current(&self) -> [f64; 2] {
        self.current
    }

    /// The pointer is off its resting place.
    pub(crate) fn hand(&self) -> bool {
        !matches!(self.hand, Hand::Off)
    }

    /// An agent event arrived. Answers the tip's destination, which the
    /// badge's layout is computed for.
    pub(crate) fn on_event(&mut self, event: MotionEvent, now: Instant) -> [f64; 2] {
        self.reduce = event.reduce_motion;
        self.press = event.press;
        // A window move reported from here on counts from this event.
        self.follow = FollowOffset::default();
        let stays = event.resting && !event.first;
        if stays && self.hand() {
            // A read with nothing to aim at aims nowhere new: the badge keeps
            // following the window it is already following.
            return self.to;
        }
        let to = if stays { self.current } else { event.to };
        self.to = to;
        self.from = self.current;
        self.glide = FrameClock::start(now);
        if event.first {
            // A first appearance does not glide in from anywhere: the badge
            // starts on the target, and the entry animation (not a settle)
            // is what marks its arrival there.
            self.from = to;
            self.current = to;
            self.duration_ms = 0.0;
            self.settles = false;
        } else {
            // The module's length, never one worked out here: it waits exactly
            // this long before it sends the action.
            self.duration_ms = event.duration_ms.max(0.0);
            self.settles = true;
        }
        // A new aim ends a swing; the pointer turns back to rest on the way
        // to the new target rather than snapping there.
        self.hand = if self.hand() || self.rotation != 0.0 {
            Hand::Returning {
                from: wrap_angle(self.rotation),
            }
        } else {
            Hand::Off
        };
        to
    }

    /// The window under the target moved, by `offset` in total since the
    /// latest event. Answers whether anything changed. During a first
    /// appearance the badge simply moves with the window, as its chip is not
    /// yet in the resting place a swing turns about.
    pub(crate) fn on_follow(&mut self, offset: [f64; 2], now: Instant, entering: bool) -> bool {
        let Some(by) = self.follow.step(offset) else {
            return false;
        };
        let shift = |point: &mut [f64; 2]| {
            point[0] += by[0];
            point[1] += by[1];
        };
        if entering {
            for point in [&mut self.from, &mut self.to, &mut self.current] {
                shift(point);
            }
            return true;
        }
        // Only the target moves; the chip stays where it was last drawn.
        shift(&mut self.to);
        self.settles = false;
        let chip = [
            self.current[0] + CHIP_CENTER[0],
            self.current[1] + CHIP_CENTER[1],
        ];
        let to = if self.reduce {
            // Reduce Motion: no swing; the pointer is hidden instead.
            0.0
        } else {
            // The aimed direction, reached by the short way round from where
            // the pointer is drawn now. A target on the chip's very centre
            // has no direction; the pointer then holds its course.
            let previous = match self.hand {
                Hand::Swinging { to, .. } => to,
                _ => self.rotation,
            };
            aim_rotation(chip, self.to).map_or(previous, |aim| {
                self.rotation + shortest_turn(self.rotation, aim)
            })
        };
        self.hand = Hand::Swinging {
            from: self.rotation,
            to,
            ease: FrameClock::start(now),
            last_move: now,
        };
        true
    }

    /// The window has been still long enough: glide to the target, turning
    /// the pointer back to rest on the way.
    fn fly_back(&mut self, now: Instant, curves: &CursorMotion) {
        self.from = self.current;
        self.duration_ms = (curves.duration_ms)(distance(self.from, self.to), self.reduce);
        self.glide = FrameClock::start(now);
        self.settles = false;
        self.hand = Hand::Returning {
            from: wrap_angle(self.rotation),
        };
    }

    /// The frame to draw at `now`, which is also when it is drawn.
    pub(crate) fn frame(&mut self, now: Instant, curves: &CursorMotion) -> MotionFrame {
        if let Hand::Swinging {
            from,
            to,
            ref mut ease,
            last_move,
        } = self.hand
        {
            let still_for = now.saturating_duration_since(last_move);
            if still_for < WINDOW_QUIET {
                let progress = (ease.advance(now) / HAND_EASE_MS).clamp(0.0, 1.0);
                self.rotation = from + (to - from) * ease_out(progress);
                let turning = progress < 1.0 && self.rotation != to;
                return MotionFrame {
                    tip: self.current,
                    rotation: self.rotation,
                    pointer_alpha: if self.reduce { 0.0 } else { 1.0 },
                    hand: true,
                    scale: 1.0,
                    alpha: 1.0,
                    // Once the pointer has turned, nothing moves until the
                    // next report or the end of the quiet period: sleep.
                    need: if turning {
                        PictureNeed::Frames
                    } else {
                        PictureNeed::WakeAfter(WINDOW_QUIET - still_for)
                    },
                };
            }
            self.fly_back(now, curves);
        }
        let elapsed = self.glide.advance(now);
        let fraction = if self.duration_ms <= 0.0 {
            1.0
        } else {
            elapsed / self.duration_ms
        };
        self.current = (curves.position)(self.from, self.to, fraction, self.reduce);
        let (settles, press, reduce) = (self.settles, self.press, self.reduce);
        let settle = |at: f64| {
            if settles {
                (curves.settle_scale)(at, press, reduce)
            } else {
                1.0
            }
        };
        let since_arrival = elapsed - self.duration_ms;
        let scale = settle(since_arrival);
        let (rotation, pointer_alpha) = match self.hand {
            Hand::Returning { .. } if fraction >= 1.0 => {
                self.hand = Hand::Off;
                (0.0, 1.0)
            }
            // Reduce Motion: the pointer, hidden during the drag, comes back
            // with the badge as it fades in at the target.
            Hand::Returning { .. } if self.reduce => (0.0, if fraction < 0.5 { 0.0 } else { 1.0 }),
            // Eased like the glide itself, so the turn and the flight end
            // together.
            Hand::Returning { from } => (from * (1.0 - ease_out(fraction.max(0.0))), 1.0),
            _ => (0.0, 1.0),
        };
        self.rotation = rotation;
        // Still moving while the glide runs, while the landing scale is off
        // 1, or while it will be off 1 one frame from now: the settle starts
        // at exactly 1, so the landing frame alone cannot tell.
        let moving = fraction < 1.0 || scale != 1.0 || settle(since_arrival + ONE_FRAME_MS) != 1.0;
        MotionFrame {
            tip: self.current,
            rotation,
            pointer_alpha,
            hand: self.hand(),
            scale,
            alpha: (curves.fade_alpha)(fraction, self.reduce),
            need: moving.into(),
        }
    }
}

fn distance(from: [f64; 2], to: [f64; 2]) -> f64 {
    (to[0] - from[0]).hypot(to[1] - from[1])
}

/// The window a badge rests on was moved: the main process reports the
/// element's total offset since the badge's latest event, and this keeps how
/// much of it the picture has already been moved by. Reporting the total
/// rather than each step means a report lost on a full pipe costs nothing:
/// the next one carries the whole offset again.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct FollowOffset {
    applied: [f64; 2],
}

impl FollowOffset {
    /// How far to move the picture for a reported total `offset`, or `None`
    /// for a malformed or unchanged one.
    pub(crate) fn step(&mut self, offset: [f64; 2]) -> Option<[f64; 2]> {
        if !offset.iter().all(|v| v.is_finite()) || offset == self.applied {
            return None;
        }
        let by = [offset[0] - self.applied[0], offset[1] - self.applied[1]];
        self.applied = offset;
        Some(by)
    }
}

/// The power assertion a helper takes while it animates, so that macOS does
/// not nap it or coalesce its frame timers. Only the decision lives here: it
/// is held exactly while the schedule asks for frames, and never while every
/// picture rests or none is shown, so a resting badge costs no CPU and keeps
/// no assertion alive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActivityGate {
    held: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActivityChange {
    Begin,
    End,
}

impl ActivityGate {
    /// What to do with the assertion before waiting as `wait` says.
    pub(crate) fn before_wait(&mut self, wait: Wait) -> Option<ActivityChange> {
        let wanted = matches!(wait, Wait::Frame(_));
        if wanted == self.held {
            return None;
        }
        self.held = wanted;
        Some(if wanted {
            ActivityChange::Begin
        } else {
            ActivityChange::End
        })
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> bool {
        self.held
    }
}

/// How long a picture stays fully visible after its agent's last event.
///
/// The badge means "this agent is using the computer", the way ChatGPT's agent
/// cursor stays on screen for the whole time its agent works, not a flash per
/// action. Agents pause between actions for minutes at a time, to think, read,
/// or write a long reply, and a badge that dims during such a pause looks
/// like the agent has gone. So a resting badge stays at full opacity; the
/// normal way it leaves is an explicit end (the turn ended, the route closed,
/// the call was cancelled), which hides it at once. This timeout is only the
/// safety net for an end signal that never arrives: two minutes outlasts an
/// ordinary pause between actions while not leaving a stale badge on screen
/// for long if an end is lost. Shared with the module, which treats an action
/// after the fade as a new first appearance.
pub(crate) const IDLE_FADE_AFTER: Duration =
    Duration::from_millis(crate::cursor_timeline::IDLE_FADE_AFTER_MS);

/// The fade itself stays short: once the agent is idle, the badge should go.
const FADE: Duration = Duration::from_millis(crate::cursor_timeline::IDLE_FADE_MS);

/// What a drawn picture still needs from the helper's loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PictureNeed {
    /// It is at rest: nothing changes until the next event.
    Rest,
    /// It is moving: draw it again next frame.
    Frames,
    /// Nothing moves now, but it must be looked at again after this long
    /// (when a dragged window has been still long enough for the badge to
    /// fly back). The loop sleeps until then, drawing nothing in between.
    WakeAfter(Duration),
}

impl From<bool> for PictureNeed {
    fn from(moving: bool) -> Self {
        if moving {
            Self::Frames
        } else {
            Self::Rest
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum PictureStep {
    Draw { elapsed_ms: f64, alpha: f64 },
    Hide,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wait {
    /// Nothing is on screen: block until the next event, with no timer at all.
    Event,
    /// Something is gliding, pulsing or fading: draw again after this interval.
    Frame(Duration),
    /// Everything on screen is resting: nothing changes until the next event
    /// or until this much time has passed, when the oldest picture starts to
    /// fade or a picture asked to be looked at again (a dragged window has
    /// been still long enough). No frames are drawn in between.
    Timed(Duration),
}

struct LivePicture<P> {
    picture: P,
    /// The agent's latest event; both the glide and the idle clock count from it.
    started: Instant,
}

pub(crate) struct CursorSchedule<P> {
    pictures: BTreeMap<String, LivePicture<P>>,
}

impl<P> CursorSchedule<P> {
    pub(crate) fn new() -> Self {
        Self {
            pictures: BTreeMap::new(),
        }
    }

    /// Every event restarts its agent's idle clock, so a busy agent's badge
    /// never fades between actions.
    pub(crate) fn picture_for_event(
        &mut self,
        agent: String,
        now: Instant,
        create: impl FnOnce() -> P,
    ) -> Option<&mut P> {
        if !self.pictures.contains_key(&agent) && self.pictures.len() >= MAX_PICTURES {
            return None;
        }
        let live = self.pictures.entry(agent).or_insert_with(|| LivePicture {
            picture: create(),
            started: now,
        });
        live.started = now;
        Some(&mut live.picture)
    }

    /// A late raster may decorate a live picture, but must not revive it or
    /// restart its glide and idle clock.
    pub(crate) fn picture_for_update(&mut self, agent: &str) -> Option<&mut P> {
        self.pictures.get_mut(agent).map(|live| &mut live.picture)
    }

    /// The agent is done: hide its picture now, with no fade, and release it.
    /// A later event from the same agent creates a fresh picture.
    pub(crate) fn end(&mut self, agent: &str, apply: impl FnOnce(&mut P, PictureStep)) {
        if let Some(mut live) = self.pictures.remove(agent) {
            apply(&mut live.picture, PictureStep::Hide);
        }
    }

    /// Draw every live picture once, and hide a fully faded one exactly once,
    /// then release it. `apply` answers what a drawn picture still needs: a
    /// plain `bool` says whether it is still moving (gliding or pulsing), and
    /// a `PictureNeed` can also ask to be woken later; its answer for `Hide`
    /// is ignored.
    ///
    /// Only moving or fading pictures need frames. Resting ones ask for a wait
    /// until the first fade starts or the earliest wake-up a picture asked
    /// for, and an empty schedule has no timer at all.
    pub(crate) fn advance<N: Into<PictureNeed>>(
        &mut self,
        now: Instant,
        mut apply: impl FnMut(&mut P, PictureStep) -> N,
    ) -> Wait {
        let mut needs_frames = false;
        let mut next_fade: Option<Duration> = None;
        let sooner = |next: &mut Option<Duration>, at: Duration| {
            *next = Some(next.map_or(at, |next| next.min(at)));
        };
        self.pictures.retain(|_, live| {
            let idle = now.saturating_duration_since(live.started);
            let elapsed_ms = idle.as_secs_f64() * 1000.0;
            let fading_ms = idle.saturating_sub(IDLE_FADE_AFTER).as_secs_f64() * 1000.0;
            let alpha = (1.0 - fading_ms / (FADE.as_secs_f64() * 1000.0)).clamp(0.0, 1.0);
            if alpha == 0.0 {
                apply(&mut live.picture, PictureStep::Hide);
                return false;
            }
            let need = apply(&mut live.picture, PictureStep::Draw { elapsed_ms, alpha }).into();
            if need == PictureNeed::Frames || idle >= IDLE_FADE_AFTER {
                needs_frames = true;
            } else {
                sooner(&mut next_fade, IDLE_FADE_AFTER - idle);
                if let PictureNeed::WakeAfter(after) = need {
                    sooner(&mut next_fade, after);
                }
            }
            true
        });
        if needs_frames {
            Wait::Frame(FRAME_INTERVAL)
        } else if let Some(until_fade) = next_fade {
            Wait::Timed(until_fade)
        } else {
            Wait::Event
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn ms(duration: Duration) -> f64 {
        duration.as_secs_f64() * 1000.0
    }

    /// One `advance` at `at`, with every drawn picture already at rest. Returns
    /// what each picture was told to do and the wait the schedule asked for.
    fn resting_steps<P: Copy>(
        schedule: &mut CursorSchedule<P>,
        at: Instant,
    ) -> (Vec<(P, PictureStep)>, Wait) {
        let mut steps = Vec::new();
        let wait = schedule.advance(at, |picture, step| {
            steps.push((*picture, step));
            false
        });
        (steps, wait)
    }

    fn alpha(steps: &[((), PictureStep)]) -> Option<f64> {
        match steps {
            [((), PictureStep::Draw { alpha, .. })] => Some(*alpha),
            [((), PictureStep::Hide)] => Some(0.0),
            [] => None,
            other => panic!("one picture, one step: {other:?}"),
        }
    }

    #[test]
    fn late_avatar_updates_cannot_revive_or_extend_a_picture() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::<u32>::new();
        assert!(schedule.picture_for_update("agent").is_none());
        schedule.picture_for_event("agent".into(), start, || 7);
        *schedule.picture_for_update("agent").unwrap() = 8;
        // Fully faded at 30.25 s; the update above must not have pushed that.
        assert_eq!(
            resting_steps(&mut schedule, start + IDLE_FADE_AFTER + FADE).1,
            Wait::Event
        );
        assert!(schedule.picture_for_update("agent").is_none());
    }

    #[test]
    fn resting_badge_stays_fully_opaque_while_its_agent_works() {
        // An agent that acts once and then thinks or writes for minutes is
        // still working: its badge must neither dim nor ask for frames. These
        // are wall-clock times on purpose, not offsets from the timeout, so a
        // short timeout (the old 30 seconds, which greyed the badge out in the
        // middle of a turn) fails here.
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("agent".into(), start, || ());
        for at in [1, 29, 31, 60, 90, 119] {
            let (steps, wait) = resting_steps(&mut schedule, start + SECOND * at);
            assert_eq!(alpha(&steps), Some(1.0), "dimmed at {at} s of rest");
            assert!(
                matches!(wait, Wait::Timed(_)),
                "a resting badge asked for {wait:?} at {at} s"
            );
        }
    }

    #[test]
    fn idle_timeout_fades_the_picture_then_drops_it_and_asks_for_no_frames() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("agent".into(), start, || ());
        let (steps, _) = resting_steps(&mut schedule, start + IDLE_FADE_AFTER - SECOND);
        assert_eq!(alpha(&steps), Some(1.0), "just before the timeout");
        let (steps, wait) = resting_steps(&mut schedule, start + IDLE_FADE_AFTER + FADE / 2);
        assert_eq!(alpha(&steps), Some(0.5), "half way through the fade");
        assert_eq!(wait, Wait::Frame(FRAME_INTERVAL), "a fade is animated");
        let (steps, wait) = resting_steps(&mut schedule, start + IDLE_FADE_AFTER + FADE);
        assert_eq!(steps, [((), PictureStep::Hide)]);
        assert_eq!(wait, Wait::Event);
        // Dropped: never drawn again, no frame and no timer requested, and a
        // late avatar has nothing to decorate.
        let wait = schedule.advance::<bool>(start + IDLE_FADE_AFTER * 2, |_, step| {
            panic!("a faded picture was given {step:?}")
        });
        assert_eq!(wait, Wait::Event);
        assert!(schedule.picture_for_update("agent").is_none());
    }

    #[test]
    fn an_event_restarts_the_idle_clock() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("agent".into(), start, || ());
        let half = IDLE_FADE_AFTER / 2;
        resting_steps(&mut schedule, start + half);
        schedule.picture_for_event("agent".into(), start + half, || ());
        for at in [IDLE_FADE_AFTER, half + IDLE_FADE_AFTER] {
            let (steps, _) = resting_steps(&mut schedule, start + at);
            assert_eq!(alpha(&steps), Some(1.0), "at {at:?}");
        }
        let (steps, _) = resting_steps(&mut schedule, start + half + IDLE_FADE_AFTER + FADE);
        assert_eq!(steps, [((), PictureStep::Hide)]);
    }

    #[test]
    fn end_removes_the_picture_at_once_and_asks_for_no_more_frames() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("ending".into(), start, || "first");
        // Still gliding when the turn ends: it needs frames until the end.
        assert_eq!(
            schedule.advance(start, |_, _| true),
            Wait::Frame(FRAME_INTERVAL)
        );
        let mut removed = Vec::new();
        schedule.end("ending", |picture, step| removed.push((*picture, step)));
        assert_eq!(
            removed,
            [("first", PictureStep::Hide)],
            "end must take the window off the screen, once"
        );
        // Released: nothing left to hide twice, no frame or timer is asked
        // for, and a late raster has no target.
        schedule.end("ending", |_, _| panic!("already hidden"));
        assert_eq!(
            schedule.advance::<bool>(start + SECOND, |_, step| panic!(
                "ended picture got {step:?}"
            )),
            Wait::Event
        );
        assert!(schedule.picture_for_update("ending").is_none());

        // Ending one agent leaves another agent's picture alone.
        schedule.picture_for_event("ending".into(), start, || "first");
        schedule.picture_for_event("other".into(), start, || "other");
        schedule.end("ending", |_, _| {});
        let (steps, _) = resting_steps(&mut schedule, start + SECOND);
        assert_eq!(
            steps,
            [(
                "other",
                PictureStep::Draw {
                    elapsed_ms: 1000.0,
                    alpha: 1.0
                }
            )],
        );
        let mut created = false;
        schedule.picture_for_event("ending".into(), start + SECOND * 2, || {
            created = true;
            "second"
        });
        assert!(created, "a new event after an end draws a fresh picture");
        assert_eq!(*schedule.picture_for_update("ending").unwrap(), "second");
    }

    #[test]
    fn resting_picture_asks_for_a_timed_wait_not_frame_ticks() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("agent".into(), start, || ());
        // While the picture is still gliding or pulsing it needs frames.
        assert_eq!(
            schedule.advance(start, |_, _| true),
            Wait::Frame(FRAME_INTERVAL)
        );
        // Once it is at rest, the only thing left to wait for is the fade.
        assert_eq!(
            resting_steps(&mut schedule, start + SECOND).1,
            Wait::Timed(IDLE_FADE_AFTER - SECOND)
        );

        // The helper's loop over twenty resting seconds: a glide of about half
        // a second, then one sleep to the fade deadline. No frame ticks while
        // the badge just sits there.
        let mut now = start;
        let mut wakes = 0;
        let mut frames_at_rest = 0;
        while now < start + SECOND * 20 {
            wakes += 1;
            let wait = schedule.advance(now, |_, _| now < start + Duration::from_millis(500));
            match wait {
                Wait::Frame(interval) => {
                    if now >= start + Duration::from_millis(500) {
                        frames_at_rest += 1;
                    }
                    now += interval;
                }
                Wait::Timed(until) => now += until,
                Wait::Event => panic!("the picture is still live"),
            }
        }
        assert_eq!(frames_at_rest, 0);
        assert!(wakes <= 32, "{wakes} wakes for a resting badge");
    }

    #[test]
    fn earliest_fade_deadline_wins_across_resting_pictures() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("old".into(), start, || ());
        schedule.picture_for_event("new".into(), start + SECOND * 10, || ());
        assert_eq!(
            resting_steps(&mut schedule, start + SECOND * 12).1,
            Wait::Timed(IDLE_FADE_AFTER - SECOND * 12)
        );
    }

    #[test]
    fn faded_picture_is_dropped_and_never_ticked_again() {
        let start = Instant::now();
        let fade_start = start + IDLE_FADE_AFTER;
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("old".into(), start, || "old");
        schedule.picture_for_event("live".into(), start + SECOND, || "live");
        let (steps, _) = resting_steps(&mut schedule, fade_start + FADE / 2);
        assert!(steps.contains(&(
            "old",
            PictureStep::Draw {
                elapsed_ms: ms(IDLE_FADE_AFTER + FADE / 2),
                alpha: 0.5,
            }
        )));
        let (steps, _) = resting_steps(&mut schedule, fade_start + FADE);
        assert_eq!(
            steps,
            [
                (
                    "live",
                    PictureStep::Draw {
                        elapsed_ms: ms(IDLE_FADE_AFTER + FADE - SECOND),
                        alpha: 1.0
                    }
                ),
                ("old", PictureStep::Hide),
            ]
        );
        assert_eq!(schedule.pictures.len(), 1);
        let (steps, _) = resting_steps(&mut schedule, fade_start + SECOND / 2);
        assert_eq!(
            steps,
            [(
                "live",
                PictureStep::Draw {
                    elapsed_ms: ms(IDLE_FADE_AFTER + SECOND / 2 - SECOND),
                    alpha: 1.0
                }
            )]
        );
    }

    #[test]
    fn no_live_pictures_blocks_until_an_event() {
        let mut schedule = CursorSchedule::<()>::new();
        assert_eq!(
            schedule.advance::<bool>(Instant::now(), |_, _| panic!("no picture to tick")),
            Wait::Event
        );
    }

    #[test]
    fn new_event_resumes_sixty_hz_ticks_after_last_picture_fades() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("agent".into(), start, || ());
        resting_steps(&mut schedule, start + IDLE_FADE_AFTER + FADE);
        let arrival = start + SECOND * 60;
        schedule.picture_for_event("agent".into(), arrival, || ());
        let mut steps = Vec::new();
        assert_eq!(
            schedule.advance(arrival, |_, step| {
                steps.push(step);
                true
            }),
            Wait::Frame(Duration::from_nanos(16_666_666))
        );
        assert_eq!(
            steps,
            [PictureStep::Draw {
                elapsed_ms: 0.0,
                alpha: 1.0
            }]
        );
    }

    const FRAME: Duration = FRAME_INTERVAL;

    /// The glide fractions a picture draws for frames arriving every
    /// `interval`, through the same clock the helper's pictures use. A frame
    /// is drawn when the event arrives and then once per wake, until the glide
    /// is done.
    fn glide_fractions(glide_ms: f64, interval: Duration) -> Vec<f64> {
        let start = Instant::now();
        let mut clock = FrameClock::start(start);
        let mut fractions = Vec::new();
        let mut now = start;
        loop {
            let fraction = (clock.advance(now) / glide_ms).min(1.0);
            fractions.push(fraction);
            if fraction >= 1.0 {
                return fractions;
            }
            now += interval;
        }
    }

    fn intermediate(fractions: &[f64]) -> usize {
        fractions.iter().filter(|f| **f > 0.0 && **f < 1.0).count()
    }

    #[test]
    fn on_time_frames_follow_the_wall_clock_exactly() {
        let start = Instant::now();
        let mut clock = FrameClock::start(start);
        for frame in 1..=30u32 {
            let shown = clock.advance(start + FRAME * frame);
            assert!((shown - ms(FRAME * frame)).abs() < 1e-6, "frame {frame}");
        }
        // A frame or two late still catches up in full.
        let late = clock.advance(start + FRAME * 30 + Duration::from_millis(40));
        assert!((late - ms(FRAME * 30 + Duration::from_millis(40))).abs() < 1e-6);
        // Time never runs backwards.
        assert_eq!(clock.advance(start), late);
    }

    #[test]
    fn a_glide_draws_intermediate_positions_even_when_frames_are_throttled() {
        // A 280 ms glide (a 400-point move) at 60 Hz: one step per frame.
        let on_time = glide_fractions(280.0, FRAME);
        assert!(intermediate(&on_time) >= 15, "{on_time:?}");
        // The same glide when macOS delays the helper's wake-ups to half a
        // second, as a napping background process sees: with wall-clock time
        // the very first wake is already past the end, which is the jump the
        // badge used to make. The frame clock still draws the way there.
        for throttled in [Duration::from_millis(250), Duration::from_millis(500)] {
            let fractions = glide_fractions(280.0, throttled);
            assert!(
                intermediate(&fractions) >= 5,
                "{throttled:?}: {fractions:?}"
            );
            for pair in fractions.windows(2) {
                assert!(
                    (pair[1] - pair[0]) * 280.0 <= ms(MAX_FRAME_STEP) + 1e-6,
                    "one frame skipped {:?} of the glide",
                    pair
                );
            }
        }
    }

    #[test]
    fn the_activity_is_held_only_while_frames_are_needed_and_never_at_rest() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        let mut gate = ActivityGate::default();
        // Nothing shown: no assertion, no timer.
        let wait = schedule.advance(start, |_, _| false);
        assert_eq!(wait, Wait::Event);
        assert_eq!(gate.before_wait(wait), None);
        assert!(!gate.held());
        // An event starts a glide: frames, and the assertion with them.
        schedule.picture_for_event("agent".into(), start, || ());
        let mut now = start;
        let mut changes = Vec::new();
        let mut held_at_rest = 0;
        let mut frames = 0;
        while now < start + SECOND * 5 {
            let moving = now < start + Duration::from_millis(500);
            let wait = schedule.advance(now, |_, _| moving);
            changes.extend(gate.before_wait(wait));
            if !moving && gate.held() {
                held_at_rest += 1;
            }
            match wait {
                Wait::Frame(interval) => {
                    assert!(gate.held(), "a frame wait without the assertion");
                    frames += 1;
                    now += interval;
                }
                Wait::Timed(_) => {
                    assert!(!gate.held(), "a resting badge kept the assertion");
                    // The helper sleeps here until an event; jump ahead.
                    now += SECOND;
                }
                Wait::Event => panic!("the picture is still live"),
            }
        }
        assert!(frames >= 29, "{frames} frames for half a second of motion");
        assert_eq!(held_at_rest, 0);
        assert_eq!(
            changes,
            [ActivityChange::Begin, ActivityChange::End],
            "taken once for the glide, released once at rest"
        );
        // Hidden: still nothing held.
        schedule.end("agent", |_, _| {});
        assert_eq!(gate.before_wait(schedule.advance(now, |_, _| false)), None);
        assert!(!gate.held());
    }

    #[test]
    fn the_entry_takes_about_twice_as_long_while_reduce_motion_stays_short() {
        assert!((1000.0..=1100.0).contains(&ENTRY_MS));
        assert_eq!(REDUCED_ENTRY_MS, 300.0);
        let first = entry_frame(0.0, false).unwrap();
        assert_eq!(first.chip, 0.0, "the avatar starts large, on the target");
        assert_eq!(first.pointer, 0.0, "the pointer is not there yet");
        assert_eq!(first.alpha, 0.0, "faded in from nothing");
        // Shortly in, the avatar is fully visible and still large, alone.
        let popped = entry_frame(ENTRY_SHRINK_FROM_MS, false).unwrap();
        assert_eq!((popped.alpha, popped.chip, popped.pointer), (1.0, 0.0, 0.0));
        // Every quantity moves one way only, smoothly, with no frame-to-frame
        // jump larger than an eighth of its range.
        let mut last = first;
        for step in 1..ENTRY_MS as u32 {
            let frame = entry_frame(f64::from(step), false).unwrap();
            for (now, before) in [
                (frame.chip, last.chip),
                (frame.pointer, last.pointer),
                (frame.alpha, last.alpha),
            ] {
                assert!(now >= before && now - before < 0.125, "at {step} ms");
            }
            last = frame;
        }
        assert!(last.chip > 0.99 && last.pointer > 0.99 && last.alpha == 1.0);
        assert_eq!(entry_frame(ENTRY_MS, false), None);
        assert_eq!(entry_frame(f64::NAN, false), None);
        assert_eq!(EntryFrame::REST.pointer_scale(), 1.0);
        assert_eq!(first.pointer_scale(), ENTRY_POINTER_SCALE);
    }

    #[test]
    fn under_reduce_motion_the_entry_is_a_plain_fade_with_no_scaling() {
        let mut frames = 0;
        let mut last_alpha = -1.0;
        for step in 0..1000u32 {
            let Some(frame) = entry_frame(f64::from(step), true) else {
                break;
            };
            frames += 1;
            // Resting size and place, full-size pointer: only opacity moves.
            assert_eq!(frame.chip, 1.0, "the chip scaled at {step} ms");
            assert_eq!(frame.pointer, 1.0, "the pointer scaled at {step} ms");
            assert!(frame.alpha > last_alpha);
            last_alpha = frame.alpha;
        }
        assert!(frames > 0, "Reduce Motion still fades the badge in");
        assert_eq!(entry_frame(REDUCED_ENTRY_MS, true), None);
    }

    #[test]
    fn the_entry_runs_once_per_appearance() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::<Appearance>::new();
        let mut entries = 0;
        let event = |schedule: &mut CursorSchedule<Appearance>, at: Instant| {
            schedule
                .picture_for_event("agent".into(), at, Appearance::default)
                .unwrap()
                .on_event(
                    at,
                    EntryShape {
                        total_ms: ENTRY_MS,
                        fade_only: false,
                    },
                )
        };
        entries += usize::from(event(&mut schedule, start));
        // More actions, during the entry and after it: no second entry, and
        // the one running carries on from where it was.
        let mut now = start;
        while now < start + Duration::from_millis(ENTRY_SHRINK_FROM_MS as u64 + 100) {
            now += FRAME;
            schedule.picture_for_update("agent").unwrap().frame(now);
        }
        entries += usize::from(event(&mut schedule, now));
        let appearance = schedule.picture_for_update("agent").unwrap();
        assert!(appearance.entering());
        now += FRAME;
        let mid = appearance.frame(now);
        assert!(mid.chip > 0.0 && mid.chip < 1.0, "{mid:?}");
        while appearance.entering() {
            now += FRAME;
            appearance.frame(now);
        }
        assert_eq!(appearance.frame(now), EntryFrame::REST);
        for later in [1, 2, 30] {
            entries += usize::from(event(&mut schedule, start + SECOND * later));
            assert!(!schedule.picture_for_update("agent").unwrap().entering());
        }
        assert_eq!(entries, 1);
        // Hidden at the turn's end: the next action is a new appearance, and
        // it enters again.
        schedule.end("agent", |_, _| {});
        entries += usize::from(event(&mut schedule, start + SECOND * 40));
        assert_eq!(entries, 2);
        assert!(schedule.picture_for_update("agent").unwrap().entering());
    }

    #[test]
    fn a_new_colour_cross_fades_in_over_about_200_ms_instead_of_snapping() {
        const GREY: Colours = [[0.52, 0.49, 0.45], [0.40, 0.38, 0.35]];
        const ROSE: Colours = [[0.60, 0.30, 0.40], [0.50, 0.25, 0.33]];
        let start = Instant::now();
        let mut colours = ColourFade::new(GREY);
        assert_eq!(colours.frame(start), (GREY, false), "at rest, no frames");
        colours.set(ROSE, start, true);
        let mut shown = Vec::new();
        let mut now = start;
        loop {
            let (frame, changing) = colours.frame(now);
            shown.push(frame);
            if !changing {
                break;
            }
            now += FRAME;
        }
        assert_eq!(shown[0], GREY, "starts from the colour on screen");
        assert_eq!(*shown.last().unwrap(), ROSE);
        let took = now - start;
        assert!(
            (Duration::from_millis(190)..=Duration::from_millis(220)).contains(&took),
            "{took:?}"
        );
        // Every frame between is a step of the way, never a jump to the end.
        assert!(shown.len() >= 11, "{} frames", shown.len());
        for pair in shown.windows(2) {
            let step = (pair[1][0][0] - pair[0][0][0]).abs();
            assert!(step < 0.25 * (ROSE[0][0] - GREY[0][0]), "{pair:?}");
        }
        // A change in the middle of a fade carries on from where it is.
        colours.set(GREY, now, true);
        let (half_way, _) = colours.frame(now + Duration::from_millis(100));
        colours.set(ROSE, now + Duration::from_millis(100), true);
        assert_eq!(colours.frame(now + Duration::from_millis(100)).0, half_way);
        // A badge only now appearing takes its colour at once.
        colours.set(GREY, now, false);
        assert_eq!(colours.frame(now), (GREY, false));
    }

    #[test]
    fn follow_offsets_move_a_picture_by_the_change_only_and_survive_a_lost_report() {
        let mut follow = FollowOffset::default();
        assert_eq!(follow.step([0.0, 0.0]), None, "no change, no move");
        assert_eq!(follow.step([100.0, 40.0]), Some([100.0, 40.0]));
        // A report for [150, 40] was lost on a full pipe; the next carries
        // the whole offset, so the picture lands exactly where it should.
        assert_eq!(follow.step([180.0, 60.0]), Some([80.0, 20.0]));
        assert_eq!(follow.step([180.0, 60.0]), None);
        assert_eq!(follow.step([f64::NAN, 0.0]), None);
        assert_eq!(follow.step([180.0, 60.0]), None);
    }

    // The clock-hand swing while a followed window is dragged.

    use crate::cursor_geometry::{hand_radius, turn_point};

    fn test_duration(distance: f64, reduce: bool) -> f64 {
        if distance < 0.5 {
            0.0
        } else if reduce {
            140.0
        } else {
            300.0
        }
    }

    fn test_position(from: [f64; 2], to: [f64; 2], fraction: f64, reduce: bool) -> [f64; 2] {
        if fraction >= 1.0 {
            return to;
        }
        if fraction <= 0.0 {
            return from;
        }
        if reduce {
            return if fraction < 0.5 { from } else { to };
        }
        let s = ease_out(fraction);
        [
            from[0] + (to[0] - from[0]) * s,
            from[1] + (to[1] - from[1]) * s,
        ]
    }

    fn test_fade(fraction: f64, reduce: bool) -> f64 {
        if !reduce || !(0.0..1.0).contains(&fraction) {
            return 1.0;
        }
        (2.0 * fraction - 1.0).abs()
    }

    /// Curves shaped like the module's: a 300 ms glide (140 ms under Reduce
    /// Motion, as a fade that jumps at its midpoint) and no settle, so a
    /// glide that is over is plainly at rest.
    const CURVES: CursorMotion = CursorMotion {
        duration_ms: test_duration,
        position: test_position,
        settle_scale: |_, _, _| 1.0,
        fade_alpha: test_fade,
    };

    const START: [f64; 2] = [500.0, 400.0];
    const DRAG: [f64; 2] = [140.0, -60.0];

    fn aim(to: [f64; 2], reduce_motion: bool) -> MotionEvent {
        MotionEvent {
            to,
            resting: false,
            first: false,
            press: true,
            reduce_motion,
            duration_ms: test_duration(1.0, reduce_motion),
        }
    }

    /// A badge that appeared on `START` and has finished drawing its arrival.
    fn resting_badge(start: Instant, reduce_motion: bool) -> BadgeMotion {
        let mut motion = BadgeMotion::new(start);
        motion.on_event(
            MotionEvent {
                first: true,
                ..aim(START, reduce_motion)
            },
            start,
        );
        let frame = motion.frame(start, &CURVES);
        assert_eq!(frame.need, PictureNeed::Rest);
        motion
    }

    /// Frames at 60 Hz from `from` until the picture stops asking for them.
    /// Returns every frame drawn and when the last one was.
    fn frames_until_still(motion: &mut BadgeMotion, from: Instant) -> (Vec<MotionFrame>, Instant) {
        let mut frames = Vec::new();
        let mut now = from;
        loop {
            let frame = motion.frame(now, &CURVES);
            frames.push(frame);
            if frame.need != PictureNeed::Frames {
                return (frames, now);
            }
            assert!(frames.len() < 1000, "never came to rest");
            now += FRAME;
        }
    }

    fn add(a: [f64; 2], b: [f64; 2]) -> [f64; 2] {
        [a[0] + b[0], a[1] + b[1]]
    }

    /// Where the pointer's tip is drawn on screen for a frame.
    fn drawn_tip(frame: &MotionFrame) -> [f64; 2] {
        add(frame.tip, turn_point([0.0, 0.0], frame.rotation))
    }

    fn chip(frame: &MotionFrame) -> [f64; 2] {
        add(frame.tip, CHIP_CENTER)
    }

    /// The resting badge with its tip on `target`: what every landing must
    /// end in.
    fn resting_on(target: [f64; 2]) -> MotionFrame {
        MotionFrame {
            tip: target,
            rotation: 0.0,
            pointer_alpha: 1.0,
            hand: false,
            scale: 1.0,
            alpha: 1.0,
            need: PictureNeed::Rest,
        }
    }

    #[test]
    fn a_window_move_while_resting_swings_the_pointer_and_leaves_the_avatar_still() {
        let start = Instant::now();
        let mut motion = resting_badge(start, false);
        let before = motion.frame(start, &CURVES);
        let moved = start + SECOND;
        assert!(motion.on_follow(DRAG, moved, false));
        let (frames, _) = frames_until_still(&mut motion, moved);
        for frame in &frames {
            assert!(frame.hand, "{frame:?}");
            assert_eq!(chip(frame), chip(&before), "the avatar chased the window");
        }
        // The pointer has left the element; it did not move with it.
        assert_ne!(frames.last().unwrap().rotation, 0.0);
    }

    #[test]
    fn the_swinging_pointer_orbits_the_avatar_aims_at_the_target_and_turns_the_short_way() {
        let start = Instant::now();
        let mut motion = resting_badge(start, false);
        let moved = start + SECOND;
        motion.on_follow(DRAG, moved, false);
        let (frames, settled_at) = frames_until_still(&mut motion, moved);
        // A few frames of easing (about 120 ms), never a jump to the end.
        assert!(frames.len() >= 6, "{} frames", frames.len());
        assert!(settled_at - moved <= Duration::from_millis(150));
        let target = add(START, DRAG);
        for frame in &frames {
            let tip = drawn_tip(frame);
            let from_chip = [tip[0] - chip(frame)[0], tip[1] - chip(frame)[1]];
            assert!((from_chip[0].hypot(from_chip[1]) - hand_radius()).abs() < 1e-9);
        }
        let last = frames.last().unwrap();
        let tip = drawn_tip(last);
        let to_tip = [tip[0] - chip(last)[0], tip[1] - chip(last)[1]];
        let to_target = [target[0] - chip(last)[0], target[1] - chip(last)[1]];
        let cross = to_tip[0] * to_target[1] - to_tip[1] * to_target[0];
        let along = to_tip[0] * to_target[0] + to_tip[1] * to_target[1];
        assert!(
            cross.abs() < 1e-6 && along > 0.0,
            "points along {to_tip:?}, target is along {to_target:?}"
        );
        // Then nothing moves until the quiet period is over: no frames.
        assert_eq!(
            last.need,
            PictureNeed::WakeAfter(WINDOW_QUIET - (settled_at - moved))
        );

        // Further reports turn it the short way round, even across the back
        // where the angle wraps.
        let mut motion = resting_badge(start, false);
        let centre = add(START, CHIP_CENTER);
        let rest = crate::cursor_geometry::rest_angle();
        // A target in the direction that is `rotation` past the resting one,
        // given as the total offset from the element's first place.
        let toward = |rotation: f64| {
            let angle = rest + rotation.to_radians();
            let target = [
                centre[0] + 300.0 * angle.cos(),
                centre[1] + 300.0 * angle.sin(),
            ];
            [target[0] - START[0], target[1] - START[1]]
        };
        let mut now = start + SECOND;
        motion.on_follow(toward(170.0), now, false);
        let (frames, at) = frames_until_still(&mut motion, now);
        let before = frames.last().unwrap().rotation;
        assert!((before.to_degrees() - 170.0).abs() < 1e-6, "{before}");
        now = at + FRAME;
        motion.on_follow(toward(-170.0), now, false);
        let (frames, _) = frames_until_still(&mut motion, now);
        // 20 degrees on through the back, not 340 back the long way.
        for frame in &frames {
            let degrees = frame.rotation.to_degrees();
            assert!(
                (170.0 - 1e-6..=190.0 + 1e-6).contains(&degrees),
                "{degrees}"
            );
        }
        let after = frames.last().unwrap().rotation.to_degrees();
        assert!((after - 190.0).abs() < 1e-6, "{after}");
    }

    #[test]
    fn after_the_window_keeps_still_the_badge_flies_back_into_its_resting_layout() {
        let start = Instant::now();
        let mut motion = resting_badge(start, false);
        let moved = start + SECOND;
        motion.on_follow(DRAG, moved, false);
        let (frames, _) = frames_until_still(&mut motion, moved);
        let swung = *frames.last().unwrap();
        // Just short of the quiet period: still swinging, still waiting.
        let waiting = motion.frame(moved + WINDOW_QUIET - FRAME, &CURVES);
        assert!(waiting.hand && waiting.tip == START);
        assert_eq!(waiting.need, PictureNeed::WakeAfter(FRAME));
        // At the end of it the flight starts from where the chip was.
        let quiet = moved + WINDOW_QUIET;
        let (frames, _) = frames_until_still(&mut motion, quiet);
        assert_eq!(frames[0].tip, START);
        assert_eq!(frames[0].need, PictureNeed::Frames);
        assert!(frames.len() >= 15, "a glide, not a jump: {}", frames.len());
        // The pointer turns back steadily as the badge flies.
        let mut turned = swung.rotation.abs();
        for frame in &frames {
            assert!(frame.rotation.abs() <= turned + 1e-12, "{frame:?}");
            turned = frame.rotation.abs();
        }
        // And lands exactly in the standard resting layout on the target.
        assert_eq!(*frames.last().unwrap(), resting_on(add(START, DRAG)));
        assert_eq!(drawn_tip(frames.last().unwrap()), add(START, DRAG));
    }

    #[test]
    fn a_window_move_within_the_quiet_period_restarts_it() {
        let start = Instant::now();
        let mut motion = resting_badge(start, false);
        let first = start + SECOND;
        motion.on_follow(DRAG, first, false);
        frames_until_still(&mut motion, first);
        let second = first + Duration::from_millis(500);
        motion.on_follow(add(DRAG, [30.0, 10.0]), second, false);
        frames_until_still(&mut motion, second);
        // A frame past 700 ms since the first report, but only about 200 ms
        // since the second.
        let frame = motion.frame(first + WINDOW_QUIET + FRAME, &CURVES);
        assert!(frame.hand && frame.tip == START, "{frame:?}");
        assert_eq!(
            frame.need,
            PictureNeed::WakeAfter(second + WINDOW_QUIET - (first + WINDOW_QUIET + FRAME))
        );
        let (frames, _) = frames_until_still(&mut motion, second + WINDOW_QUIET);
        assert_eq!(frames[0].need, PictureNeed::Frames, "the flight starts");
        assert_eq!(
            *frames.last().unwrap(),
            resting_on(add(START, add(DRAG, [30.0, 10.0])))
        );
    }

    #[test]
    fn a_new_action_during_the_swing_cancels_it_and_glides_to_the_new_target() {
        let start = Instant::now();
        let mut motion = resting_badge(start, false);
        let moved = start + SECOND;
        motion.on_follow(DRAG, moved, false);
        frames_until_still(&mut motion, moved);
        let elsewhere = [900.0, 700.0];
        let acted = moved + Duration::from_millis(300);
        assert_eq!(motion.on_event(aim(elsewhere, false), acted), elsewhere);
        let (frames, landed) = frames_until_still(&mut motion, acted);
        // It glides from where the chip held still, turning the pointer back.
        assert_eq!(frames[0].tip, START);
        assert!(frames.len() >= 15, "a glide, not a jump: {}", frames.len());
        assert_eq!(*frames.last().unwrap(), resting_on(elsewhere));
        // The quiet period of the old drag no longer sends it anywhere.
        let later = motion.frame(landed.max(moved + WINDOW_QUIET) + SECOND, &CURVES);
        assert_eq!(later, resting_on(elsewhere));
    }

    #[test]
    fn under_reduce_motion_a_drag_hides_the_pointer_then_the_badge_fades_in_on_the_target() {
        let start = Instant::now();
        let mut motion = resting_badge(start, true);
        let moved = start + SECOND;
        motion.on_follow(DRAG, moved, false);
        let hidden = motion.frame(moved, &CURVES);
        assert_eq!(hidden.rotation, 0.0, "no swing under Reduce Motion");
        assert_eq!(hidden.pointer_alpha, 0.0, "the pointer hides instead");
        assert_eq!(hidden.tip, START);
        // Nothing to animate while the window moves: sleep out the quiet.
        assert_eq!(hidden.need, PictureNeed::WakeAfter(WINDOW_QUIET));
        let (frames, _) = frames_until_still(&mut motion, moved + WINDOW_QUIET);
        let mut faded_out = false;
        for frame in &frames {
            assert_eq!(frame.rotation, 0.0, "swung during the fade: {frame:?}");
            // The badge never travels: it is at the old place or the new.
            assert!(
                frame.tip == START || frame.tip == add(START, DRAG),
                "{frame:?}"
            );
            if frame.tip == START {
                assert_eq!(frame.pointer_alpha, 0.0);
            }
            faded_out |= frame.alpha < 0.2;
        }
        assert!(faded_out, "a fade, not a jump");
        assert_eq!(*frames.last().unwrap(), resting_on(add(START, DRAG)));
    }

    #[test]
    fn waiting_out_the_quiet_period_draws_no_frames_and_holds_no_activity() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::<BadgeMotion>::new();
        let mut gate = ActivityGate::default();
        schedule
            .picture_for_event("agent".into(), start, || resting_badge(start, false))
            .unwrap();
        let moved = start + SECOND;
        let mut now = moved;
        let mut followed = false;
        let mut frames_while_waiting = 0;
        let mut timed_waits = 0;
        let mut flew = false;
        while now < moved + SECOND * 3 {
            if !followed && now >= moved {
                let badge = schedule.picture_for_update("agent").unwrap();
                badge.on_follow(DRAG, now, false);
                followed = true;
            }
            let wait = schedule.advance(now, |badge, step| match step {
                PictureStep::Draw { .. } => badge.frame(now, &CURVES).need,
                PictureStep::Hide => PictureNeed::Rest,
            });
            gate.before_wait(wait);
            let easing = now < moved + Duration::from_millis(150);
            let flying = now >= moved + WINDOW_QUIET;
            match wait {
                Wait::Frame(interval) => {
                    assert!(gate.held());
                    if !easing && !flying {
                        frames_while_waiting += 1;
                    }
                    flew |= flying;
                    now += interval;
                }
                Wait::Timed(until) => {
                    assert!(!gate.held(), "a waiting badge kept the activity");
                    if !flying {
                        timed_waits += 1;
                        // Woken exactly when the quiet period ends.
                        assert_eq!(now + until, moved + WINDOW_QUIET);
                    }
                    now += until;
                }
                Wait::Event => panic!("the picture is still live"),
            }
        }
        assert_eq!(frames_while_waiting, 0);
        assert_eq!(timed_waits, 1, "one sleep across the quiet period");
        assert!(flew, "the flight back drew frames");
        assert!(!gate.held(), "released once the badge landed");
    }

    /// The module waits exactly the length it put on the picture's line
    /// before it sends the action, so the helper must have the badge on its
    /// target, fully shown and with no entry still playing, exactly then: not
    /// sooner (the badge would sit there before the click) and not later (the
    /// click would land first). The lengths here are ones the helper's own
    /// curves would never give, so a helper that worked out its own length
    /// instead of following the line arrives at the wrong time. It holds for
    /// every case of the module's view being out of date: an entry for a
    /// badge the helper already shows, and a glide for one it does not.
    #[test]
    fn the_helper_reaches_the_target_when_the_picture_line_says() {
        const STEP: Duration = Duration::from_millis(1);
        let across = [START[0] + 3000.0, START[1] + 2000.0];
        let short = [START[0] + 3.0, START[1] + 4.0];
        for reduce in [false, true] {
            for (shown, entry, to, length) in [
                (false, true, across, 777.0),
                (false, true, across, 0.0),
                (true, false, short, 123.0),
                (true, false, across, 411.0),
                // The module thought the badge was gone, but it is on screen.
                (true, true, across, 640.0),
                // The module thought the badge was on screen, but it is gone.
                (false, false, across, 333.0),
                (false, false, short, 0.0),
            ] {
                let start = Instant::now();
                let mut appearance = Appearance::default();
                let mut motion = BadgeMotion::new(start);
                let mut now = start;
                let timing = |entry: bool, duration_ms: f64| PictureTiming {
                    entry,
                    duration_ms,
                    reduce_motion: reduce,
                };
                if shown {
                    // A badge already shown, its entry over, resting on START.
                    begin_picture(
                        &mut appearance,
                        &mut motion,
                        PictureAim {
                            to: START,
                            resting: false,
                            press: true,
                            timing: timing(true, 500.0),
                        },
                        now,
                    );
                    while appearance.entering() {
                        now += STEP;
                        appearance.frame(now);
                        motion.frame(now, &CURVES);
                    }
                }
                let sent = now;
                let (_, first) = begin_picture(
                    &mut appearance,
                    &mut motion,
                    PictureAim {
                        to,
                        resting: false,
                        press: true,
                        timing: timing(entry, length),
                    },
                    sent,
                );
                assert_eq!(first, !shown);
                let arrived = loop {
                    let frame = motion.frame(now, &CURVES);
                    let entered = appearance.frame(now);
                    if frame.tip == to && frame.alpha == 1.0 && entered == EntryFrame::REST {
                        break now;
                    }
                    now += STEP;
                    assert!(now - sent < SECOND * 5, "the badge never arrived");
                };
                let took = ms(arrived - sent);
                assert!(
                    (took - length).abs() <= ms(STEP),
                    "shown {shown}, entry {entry}, reduce {reduce}, to {to:?}: the line said \
                     {length} ms and the helper took {took} ms"
                );
            }
        }
    }
}
