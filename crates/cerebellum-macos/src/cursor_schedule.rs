//! Host-neutral lifetime and wake decisions for ephemeral cursor pictures.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const FRAME_INTERVAL: Duration = Duration::from_nanos(1_000_000_000 / 60);
const MAX_PICTURES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum PictureStep {
    Draw { elapsed_ms: f64, alpha: f64 },
    Hide,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wait {
    Event,
    Frame(Duration),
}

struct LivePicture<P> {
    picture: P,
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
    /// restart its glide and fade timer.
    pub(crate) fn picture_for_update(&mut self, agent: &str) -> Option<&mut P> {
        self.pictures.get_mut(agent).map(|live| &mut live.picture)
    }

    /// Hide a fully faded picture exactly once, then release it. Only retained
    /// pictures need another frame; an empty schedule has no timer to service.
    pub(crate) fn advance(
        &mut self,
        now: Instant,
        mut apply: impl FnMut(&mut P, PictureStep),
    ) -> Wait {
        self.pictures.retain(|_, live| {
            let elapsed_ms = now.saturating_duration_since(live.started).as_secs_f64() * 1000.0;
            let alpha = (1.0 - (elapsed_ms - 1500.0).max(0.0) / 250.0).clamp(0.0, 1.0);
            if alpha == 0.0 {
                apply(&mut live.picture, PictureStep::Hide);
                false
            } else {
                apply(&mut live.picture, PictureStep::Draw { elapsed_ms, alpha });
                true
            }
        });
        if self.pictures.is_empty() {
            Wait::Event
        } else {
            Wait::Frame(FRAME_INTERVAL)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_avatar_updates_cannot_revive_or_extend_a_picture() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::<u32>::new();
        assert!(schedule.picture_for_update("agent").is_none());
        schedule.picture_for_event("agent".into(), start, || 7);
        *schedule.picture_for_update("agent").unwrap() = 8;
        assert_eq!(
            schedule.advance(start + Duration::from_secs(2), |_, _| {}),
            Wait::Event
        );
        assert!(schedule.picture_for_update("agent").is_none());
    }

    #[test]
    fn faded_picture_is_dropped_and_never_ticked_again() {
        let start = Instant::now();
        let mut schedule = CursorSchedule::new();
        schedule.picture_for_event("old".into(), start, || "old");
        schedule.picture_for_event("live".into(), start + Duration::from_secs(1), || "live");
        let mut steps = Vec::new();
        schedule.advance(start + Duration::from_millis(1625), |picture, step| {
            steps.push((*picture, step));
        });
        assert!(steps.contains(&(
            "old",
            PictureStep::Draw {
                elapsed_ms: 1625.0,
                alpha: 0.5,
            }
        )));
        steps.clear();
        schedule.advance(start + Duration::from_millis(1750), |picture, step| {
            steps.push((*picture, step));
        });
        assert_eq!(
            steps,
            [
                (
                    "live",
                    PictureStep::Draw {
                        elapsed_ms: 750.0,
                        alpha: 1.0
                    }
                ),
                ("old", PictureStep::Hide),
            ]
        );
        assert_eq!(schedule.pictures.len(), 1);
        steps.clear();
        schedule.advance(start + Duration::from_secs(2), |picture, step| {
            steps.push((*picture, step));
        });
        assert_eq!(
            steps,
            [(
                "live",
                PictureStep::Draw {
                    elapsed_ms: 1000.0,
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
        schedule.advance(start + Duration::from_secs(2), |_, _| {});
        let arrival = start + Duration::from_secs(30);
        schedule.picture_for_event("agent".into(), arrival, || ());
        let mut steps = Vec::new();
        assert_eq!(
            schedule.advance(arrival, |_, step| steps.push(step)),
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
