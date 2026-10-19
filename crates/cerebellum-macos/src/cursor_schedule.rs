//! Host-neutral lifetime and wake decisions for ephemeral cursor pictures,
//! and the clocks and curves that animate them.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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

/// How long a first appearance takes, in ms: the avatar pops in large on the
/// target, holds a moment, then shrinks onto its place behind the pointer as
/// the pointer and label come in. The original entry felt too quick, so each
/// phase now takes twice as long while the gentler Reduce Motion fade stays short.
pub(crate) const ENTRY_MS: f64 = 1040.0;
/// The avatar alone fades in, at its large entry size, over this long.
const ENTRY_POP_MS: f64 = 200.0;
/// Then it shrinks from here to the end of the entry.
const ENTRY_SHRINK_FROM_MS: f64 = 360.0;
/// The pointer and the label grow and fade in from here to the end.
const ENTRY_POINTER_FROM_MS: f64 = 520.0;
/// Under Reduce Motion an entry is a plain fade of the resting badge, with
/// no scaling and no travel.
const REDUCED_ENTRY_MS: f64 = 300.0;
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

/// The entry's frame `elapsed_ms` into it, or `None` once it is over. A
/// malformed time ends it: a badge must never be left half-entered.
pub(crate) fn entry_frame(elapsed_ms: f64, reduce_motion: bool) -> Option<EntryFrame> {
    let total = if reduce_motion {
        REDUCED_ENTRY_MS
    } else {
        ENTRY_MS
    };
    if !elapsed_ms.is_finite() || elapsed_ms >= total {
        return None;
    }
    let elapsed = elapsed_ms.max(0.0);
    if reduce_motion {
        return Some(EntryFrame {
            alpha: share(elapsed, 0.0, total),
            ..EntryFrame::REST
        });
    }
    Some(EntryFrame {
        chip: ease_in_out(share(elapsed, ENTRY_SHRINK_FROM_MS, total)),
        pointer: ease_out(share(elapsed, ENTRY_POINTER_FROM_MS, total)),
        alpha: ease_out(share(elapsed, 0.0, ENTRY_POP_MS)),
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
    entry: Option<(FrameClock, bool)>,
}

impl Appearance {
    /// An event arrived. Answers whether this is the first appearance, which
    /// starts the entry.
    pub(crate) fn on_event(&mut self, now: Instant, reduce_motion: bool) -> bool {
        if self.shown {
            return false;
        }
        self.shown = true;
        self.entry = Some((FrameClock::start(now), reduce_motion));
        true
    }

    pub(crate) fn entering(&self) -> bool {
        self.entry.is_some()
    }

    /// The entry frame to draw at `now`; the resting frame once it is over.
    pub(crate) fn frame(&mut self, now: Instant) -> EntryFrame {
        let Some((clock, reduce)) = self.entry.as_mut() else {
            return EntryFrame::REST;
        };
        match entry_frame(clock.advance(now), *reduce) {
            Some(frame) => frame,
            None => {
                self.entry = None;
                EntryFrame::REST
            }
        }
    }
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
/// for long if an end is lost.
pub(crate) const IDLE_FADE_AFTER: Duration = Duration::from_secs(2 * 60);

/// The fade itself stays short: once the agent is idle, the badge should go.
const FADE: Duration = Duration::from_millis(250);

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
    /// fade. No frames are drawn in between.
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
    /// then release it. `apply` answers whether a drawn picture is still
    /// moving (gliding or pulsing); its answer for `Hide` is ignored.
    ///
    /// Only moving or fading pictures need frames. Resting ones ask for a wait
    /// until the first fade starts, and an empty schedule has no timer at all.
    pub(crate) fn advance(
        &mut self,
        now: Instant,
        mut apply: impl FnMut(&mut P, PictureStep) -> bool,
    ) -> Wait {
        let mut needs_frames = false;
        let mut next_fade: Option<Duration> = None;
        self.pictures.retain(|_, live| {
            let idle = now.saturating_duration_since(live.started);
            let elapsed_ms = idle.as_secs_f64() * 1000.0;
            let fading_ms = idle.saturating_sub(IDLE_FADE_AFTER).as_secs_f64() * 1000.0;
            let alpha = (1.0 - fading_ms / (FADE.as_secs_f64() * 1000.0)).clamp(0.0, 1.0);
            if alpha == 0.0 {
                apply(&mut live.picture, PictureStep::Hide);
                return false;
            }
            let moving = apply(&mut live.picture, PictureStep::Draw { elapsed_ms, alpha });
            if moving || idle >= IDLE_FADE_AFTER {
                needs_frames = true;
            } else {
                let until_fade = IDLE_FADE_AFTER - idle;
                next_fade = Some(next_fade.map_or(until_fade, |next| next.min(until_fade)));
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
        let wait = schedule.advance(start + IDLE_FADE_AFTER * 2, |_, step| {
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
            schedule.advance(start + SECOND, |_, step| panic!(
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
            schedule.advance(Instant::now(), |_, _| panic!("no picture to tick")),
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
                .on_event(at, false)
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
}
