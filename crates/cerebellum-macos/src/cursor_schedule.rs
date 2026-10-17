//! Host-neutral lifetime and wake decisions for ephemeral cursor pictures.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const FRAME_INTERVAL: Duration = Duration::from_nanos(1_000_000_000 / 60);
const MAX_PICTURES: usize = 64;

/// How long a picture stays fully visible after its agent's last event.
///
/// The badge means "this agent is using the computer", the way ChatGPT's agent
/// cursor stays on screen for the whole time its agent works, not a flash per
/// action. Agents pause between actions to think, read, or wait on a person, so
/// the badge rests at its last spot and only fades once its agent has sent no
/// event for this long. An explicit end (route closed, call cancelled) hides it
/// sooner; this is the fallback for an agent that simply stops.
pub(crate) const IDLE_FADE_AFTER: Duration = Duration::from_secs(30);

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
    fn picture_stays_fully_visible_for_29_seconds_then_fades_after_30() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("agent".into(), start, || ());
        for second in [0, 1, 10, 29] {
            let (steps, _) = resting_steps(&mut schedule, start + SECOND * second);
            assert_eq!(alpha(&steps), Some(1.0), "at {second} s");
        }
        let (steps, wait) = resting_steps(&mut schedule, start + SECOND * 30 + FADE / 2);
        assert_eq!(alpha(&steps), Some(0.5), "half way through the fade");
        assert_eq!(wait, Wait::Frame(FRAME_INTERVAL), "a fade is animated");
        let (steps, wait) = resting_steps(&mut schedule, start + SECOND * 30 + FADE);
        assert_eq!(steps, [((), PictureStep::Hide)]);
        assert_eq!(wait, Wait::Event);
    }

    #[test]
    fn event_at_20_seconds_keeps_the_picture_visible_until_50() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("agent".into(), start, || ());
        resting_steps(&mut schedule, start + SECOND * 20);
        schedule.picture_for_event("agent".into(), start + SECOND * 20, || ());
        for second in [21, 31, 40, 49, 50] {
            let (steps, _) = resting_steps(&mut schedule, start + SECOND * second);
            assert_eq!(alpha(&steps), Some(1.0), "at {second} s");
        }
        let (steps, _) = resting_steps(&mut schedule, start + SECOND * 50 + FADE);
        assert_eq!(steps, [((), PictureStep::Hide)]);
    }

    #[test]
    fn end_hides_at_once_and_a_later_event_creates_it_again() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("ending".into(), start, || "first");
        schedule.picture_for_event("other".into(), start, || "other");
        let mut hidden = Vec::new();
        schedule.end("ending", |picture, step| hidden.push((*picture, step)));
        assert_eq!(hidden, [("first", PictureStep::Hide)]);
        // Released: nothing left to hide twice, and a late raster has no target.
        schedule.end("ending", |_, _| panic!("already hidden"));
        assert!(schedule.picture_for_update("ending").is_none());
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
            "ending one agent leaves another agent's picture alone"
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
            Wait::Timed(SECOND * 18)
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
                elapsed_ms: 30_125.0,
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
                        elapsed_ms: 29_250.0,
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
                    elapsed_ms: 29_500.0,
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
}
