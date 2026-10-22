//! Host-neutral rules for the background-mode previews the helper shows.
//!
//! A preview is one more kind of helper window beside the agent badge: a
//! small picture of the window an agent works in, in the top-right corner of
//! the screen, with that agent's badge moving inside it rather than on the
//! real screen, where another window may cover the app. The drawing lives in
//! `cursor_overlay` and is macOS only. This file decides what each preview
//! line changes, when a preview needs frames and when it is gone, so those
//! rules are tested on every host.
//!
//! - A preview line shows or retargets the agent's preview in its slot. One
//!   whose generation is older than the preview it would replace is dropped.
//! - A frame or a motion acts only on the agent's preview that is showing, of
//!   the same generation and window. A frame never creates or revives a
//!   preview and never restarts its idle clock; a motion is an action and
//!   does restart it.
//! - The badge inside a preview follows the motion on its line exactly, as
//!   the on-screen badge follows its picture line.
//! - A hidden preview is gone: it draws nothing and asks the helper's loop for
//!   no frames and no timer.

use std::time::Instant;

use crate::cursor_schedule::{
    begin_picture, Appearance, BadgeMotion, CursorMotion, CursorSchedule, EntryFrame, PictureAim,
    PictureNeed, PictureStep, PictureTiming, Wait,
};
use crate::preview_layout::{
    preview_layout, slot_max_height, slot_origin, thumbnail_point, PreviewLayout, PreviewRect,
};

/// Why a preview shows the application's icon instead of its window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewFallback {
    /// The window is minimized, so there is nothing to show of it.
    Minimized,
    /// The module could not capture the window.
    CaptureRefused,
}

/// Show one agent's preview, or point it at another window.
#[derive(Clone, Debug, PartialEq)]
pub struct OverlayPreview {
    pub agent: String,
    /// Raised by the module at every hide and retarget.
    pub generation: u64,
    /// The slot it is drawn in, top-down from 0.
    pub slot: u8,
    /// The window shown, by its window-server id.
    pub window: u32,
    /// The application's name, shown under the thumbnail.
    pub app: String,
    /// The window's width and height, for the thumbnail's shape.
    pub aspect: [f64; 2],
    /// The action's label, shown beside the name; none for a read.
    pub label: Option<String>,
    pub fallback: Option<PreviewFallback>,
    /// The application bundle the icon is loaded from when there is a
    /// fallback.
    pub icon_path: Option<String>,
}

/// One captured frame of the window a preview shows.
#[derive(Clone, Debug, PartialEq)]
pub struct OverlayFrame {
    pub agent: String,
    pub generation: u64,
    pub window: u32,
    /// The image's width and height in pixels.
    pub size: [u32; 2],
    /// The JPEG itself, already decoded from the line's base64.
    pub jpeg: Vec<u8>,
}

/// The badge's motion inside an agent's preview.
#[derive(Clone, Debug, PartialEq)]
pub struct OverlayPreviewMotion {
    pub agent: String,
    pub generation: u64,
    pub window: u32,
    /// A press lands with a tap rather than a settle.
    pub press: bool,
    /// Where the tip goes, as its place in the window: each coordinate from
    /// 0 (left or top) to 1 (right or bottom).
    pub to: [f64; 2],
    /// How the badge gets there and how long it takes, as the module chose
    /// it and times the action by. The helper follows it exactly.
    pub motion: PictureTiming,
}

/// The badge inside a preview on one frame, relative to the preview's
/// top-left corner, top-down.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct BadgeDraw {
    pub tip: [f64; 2],
    /// The landing scale about the tip.
    pub scale: f64,
    /// How far its entry has got, when it is appearing.
    pub entry: EntryFrame,
    /// The badge's opacity: its entry's and the Reduce Motion fade-move's.
    pub alpha: f64,
}

/// What draws one preview: the macOS window, or a recorder in tests.
pub(crate) trait PreviewSurface {
    /// Show `preview` laid out as `layout`, its top-left corner at `origin`
    /// (global top-down points). `window_changed` says it now shows another
    /// window, so the previous window's frame must no longer be drawn.
    fn show(
        &mut self,
        preview: &OverlayPreview,
        layout: &PreviewLayout,
        origin: [f64; 2],
        window_changed: bool,
    );
    /// Draw a captured frame of the window shown.
    fn frame(&mut self, frame: OverlayFrame);
    /// Draw one animation frame: the badge, if it has been sent anywhere
    /// yet, and the whole preview at `alpha` (below 1 only while it fades
    /// out after its agent has been idle too long).
    fn draw(&mut self, badge: Option<BadgeDraw>, alpha: f64);
    /// Take the preview off the screen for good, now, with no fade.
    fn remove(&mut self);
}

/// One preview the helper shows.
pub(crate) struct LivePreview<S> {
    generation: u64,
    window: u32,
    slot: u8,
    layout: PreviewLayout,
    /// The badge, once a motion has sent it somewhere in this window.
    badge: Option<PreviewBadge>,
    surface: S,
}

/// The badge inside one preview: the same appearance and motion the
/// on-screen badge uses, in the preview's own points.
struct PreviewBadge {
    appearance: Appearance,
    motion: BadgeMotion,
}

impl PreviewBadge {
    fn frame(&mut self, now: Instant, curves: &CursorMotion) -> (BadgeDraw, PictureNeed) {
        let frame = self.motion.frame(now, curves);
        let entry = self.appearance.frame(now);
        let need = if self.appearance.entering() {
            PictureNeed::Frames
        } else {
            frame.need
        };
        let draw = BadgeDraw {
            tip: frame.tip,
            scale: frame.scale,
            entry,
            alpha: frame.alpha * entry.alpha,
        };
        (draw, need)
    }
}

/// Every preview the helper shows, one per agent.
pub(crate) struct Previews<S> {
    schedule: CursorSchedule<LivePreview<S>>,
}

impl<S: PreviewSurface> Previews<S> {
    pub(crate) fn new() -> Self {
        Self {
            schedule: CursorSchedule::new(),
        }
    }

    /// Show or retarget the agent's preview on a screen whose usable area
    /// (below the menu bar, beside the Dock) is `screen`. Answers whether
    /// the line was drawn. Another agent's preview still in the same slot
    /// gives way to it, so two previews never overlap.
    pub(crate) fn on_preview(
        &mut self,
        preview: OverlayPreview,
        screen: PreviewRect,
        now: Instant,
        create: impl FnOnce() -> S,
    ) -> bool {
        let Some(origin) = slot_origin(screen, preview.slot) else {
            return false;
        };
        let Some(layout) = preview_layout(preview.aspect, slot_max_height(screen.height)) else {
            return false;
        };
        if self
            .schedule
            .picture_for_update(&preview.agent)
            .is_some_and(|shown| preview.generation < shown.generation)
        {
            return false;
        }
        let slot = preview.slot;
        if let Some(other) = self
            .schedule
            .find(|agent, live| agent != preview.agent && live.slot == slot)
        {
            self.hide(&other);
        }
        let Some(live) = self
            .schedule
            .picture_for_event(preview.agent.clone(), now, || LivePreview {
                generation: preview.generation,
                window: preview.window,
                slot,
                layout,
                badge: None,
                surface: create(),
            })
        else {
            return false;
        };
        let window_changed = live.window != preview.window;
        if window_changed {
            // Another window is another place for the badge: its next
            // motion there is a first appearance, with an entry.
            live.badge = None;
        }
        live.generation = preview.generation;
        live.window = preview.window;
        live.slot = slot;
        live.layout = layout;
        live.surface.show(&preview, &layout, origin, window_changed);
        true
    }

    /// Draw a frame into the agent's preview, if it shows that generation
    /// and window. Answers whether it was drawn. It never creates or revives
    /// a preview and never restarts its idle clock.
    pub(crate) fn on_frame(&mut self, frame: OverlayFrame) -> bool {
        let Some(live) = self.schedule.picture_for_update(&frame.agent) else {
            return false;
        };
        if live.generation != frame.generation || live.window != frame.window {
            return false;
        }
        live.surface.frame(frame);
        true
    }

    /// Start the badge's motion inside the agent's preview, if it shows that
    /// generation and window and the point lies in the window. Answers
    /// whether it was drawn; one that is drawn restarts the idle clock.
    pub(crate) fn on_motion(&mut self, motion: OverlayPreviewMotion, now: Instant) -> bool {
        let to = self
            .schedule
            .picture_for_update(&motion.agent)
            .filter(|live| live.generation == motion.generation && live.window == motion.window)
            .and_then(|live| thumbnail_point(live.layout.thumbnail, motion.to));
        let (Some(to), Some(live)) = (to, self.schedule.touch(&motion.agent, now)) else {
            return false;
        };
        let badge = live.badge.get_or_insert_with(|| PreviewBadge {
            appearance: Appearance::default(),
            motion: BadgeMotion::new(now),
        });
        begin_picture(
            &mut badge.appearance,
            &mut badge.motion,
            PictureAim {
                to,
                resting: false,
                press: motion.press,
                timing: motion.motion,
            },
            now,
        );
        true
    }

    /// The agent is done: take its preview away now, with no fade.
    pub(crate) fn hide(&mut self, agent: &str) {
        self.schedule.end(agent, |live, _| live.surface.remove());
    }

    /// The agent's preview, to change how it looks (its avatar) without
    /// restarting its idle clock; `None` when it is not showing.
    pub(crate) fn surface_for_update(&mut self, agent: &str) -> Option<&mut S> {
        self.schedule
            .picture_for_update(agent)
            .map(|live| &mut live.surface)
    }

    /// Draw every preview once, remove one whose idle fade is over, and
    /// answer how long the helper's loop may wait: frames only while a badge
    /// moves or a preview fades, a timer for the earliest idle fade while
    /// they rest, and nothing at all once none is showing.
    pub(crate) fn advance(&mut self, now: Instant, curves: &CursorMotion) -> Wait {
        self.schedule.advance(now, |live, step| match step {
            PictureStep::Draw { alpha, .. } => {
                let (badge, need) = match live.badge.as_mut() {
                    Some(badge) => {
                        let (draw, need) = badge.frame(now, curves);
                        (Some(draw), need)
                    }
                    None => (None, PictureNeed::Rest),
                };
                live.surface.draw(badge, alpha);
                need
            }
            PictureStep::Hide => {
                live.surface.remove();
                PictureNeed::Rest
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    use super::*;
    use crate::cursor_schedule::{sooner_wait, IDLE_FADE_AFTER};
    use crate::cursor_timeline::IDLE_FADE_MS;
    use crate::preview_layout::PREVIEW_MAX_HEIGHT;

    const SECOND: Duration = Duration::from_secs(1);
    const FADE: Duration = Duration::from_millis(IDLE_FADE_MS);
    /// A screen tall enough that every slot is full height.
    const SCREEN: PreviewRect = PreviewRect::new(0.0, 25.0, 1728.0, 1200.0);
    const WINDOW: u32 = 7;
    const ASPECT: [f64; 2] = [1600.0, 1000.0];

    /// Everything the previews asked their surfaces to do, in order.
    #[derive(Clone, Debug, PartialEq)]
    enum Call {
        Show {
            agent: String,
            generation: u64,
            origin: [f64; 2],
            window_changed: bool,
        },
        Frame(u64),
        Draw(Option<BadgeDraw>, f64),
        Remove(String),
    }

    struct Recorder {
        agent: String,
        log: Rc<RefCell<Vec<Call>>>,
    }

    impl PreviewSurface for Recorder {
        fn show(
            &mut self,
            preview: &OverlayPreview,
            _layout: &PreviewLayout,
            origin: [f64; 2],
            window_changed: bool,
        ) {
            self.log.borrow_mut().push(Call::Show {
                agent: preview.agent.clone(),
                generation: preview.generation,
                origin,
                window_changed,
            });
        }

        fn frame(&mut self, frame: OverlayFrame) {
            self.log.borrow_mut().push(Call::Frame(frame.generation));
        }

        fn draw(&mut self, badge: Option<BadgeDraw>, alpha: f64) {
            self.log.borrow_mut().push(Call::Draw(badge, alpha));
        }

        fn remove(&mut self) {
            self.log.borrow_mut().push(Call::Remove(self.agent.clone()));
        }
    }

    fn ease_out(t: f64) -> f64 {
        1.0 - (1.0 - t).powi(3)
    }

    /// Curves shaped like the module's, with no settle, so a landed badge
    /// is plainly at rest. Their own glide length (300 ms) is never what a
    /// line says, so a helper that used it instead of the line's would land
    /// at the wrong time.
    const CURVES: CursorMotion = CursorMotion {
        duration_ms: |distance, _| if distance < 0.5 { 0.0 } else { 300.0 },
        position: |from, to, fraction, _| {
            if fraction >= 1.0 {
                return to;
            }
            let s = ease_out(fraction.max(0.0));
            [
                from[0] + (to[0] - from[0]) * s,
                from[1] + (to[1] - from[1]) * s,
            ]
        },
        settle_scale: |_, _, _| 1.0,
        fade_alpha: |_, _| 1.0,
    };

    struct Harness {
        previews: Previews<Recorder>,
        log: Rc<RefCell<Vec<Call>>>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                previews: Previews::new(),
                log: Rc::default(),
            }
        }

        fn preview(
            &mut self,
            agent: &str,
            generation: u64,
            slot: u8,
            window: u32,
            at: Instant,
        ) -> bool {
            let log = self.log.clone();
            let name = agent.to_owned();
            self.previews.on_preview(
                OverlayPreview {
                    agent: agent.into(),
                    generation,
                    slot,
                    window,
                    app: "Mail".into(),
                    aspect: ASPECT,
                    label: Some("Pressing Send".into()),
                    fallback: None,
                    icon_path: None,
                },
                SCREEN,
                at,
                move || Recorder { agent: name, log },
            )
        }

        fn frame(&mut self, agent: &str, generation: u64, window: u32) -> bool {
            self.previews.on_frame(OverlayFrame {
                agent: agent.into(),
                generation,
                window,
                size: [400, 250],
                jpeg: vec![0xff, 0xd8, 0xff, 0xd9],
            })
        }

        fn motion(
            &mut self,
            agent: &str,
            generation: u64,
            window: u32,
            to: [f64; 2],
            timing: PictureTiming,
            at: Instant,
        ) -> bool {
            self.previews.on_motion(
                OverlayPreviewMotion {
                    agent: agent.into(),
                    generation,
                    window,
                    press: true,
                    to,
                    motion: timing,
                },
                at,
            )
        }

        fn advance(&mut self, at: Instant) -> Wait {
            self.previews.advance(at, &CURVES)
        }

        fn take(&self) -> Vec<Call> {
            std::mem::take(&mut *self.log.borrow_mut())
        }
    }

    fn glide(duration_ms: f64) -> PictureTiming {
        PictureTiming {
            entry: false,
            duration_ms,
            reduce_motion: false,
        }
    }

    fn entry(duration_ms: f64) -> PictureTiming {
        PictureTiming {
            entry: true,
            ..glide(duration_ms)
        }
    }

    fn thumbnail() -> PreviewRect {
        preview_layout(ASPECT, PREVIEW_MAX_HEIGHT)
            .unwrap()
            .thumbnail
    }

    /// The helper-side half of "while hidden, no frames and no timers": once
    /// its preview is hidden, nothing about it is drawn, no late frame or
    /// motion brings it back, and the helper's loop blocks with no timer.
    #[test]
    fn a_hidden_preview_draws_nothing_and_asks_for_no_frames_and_no_timer() {
        let start = Instant::now();
        let mut h = Harness::new();
        assert_eq!(h.advance(start), Wait::Event, "nothing shown yet");
        assert!(h.preview("agent", 1, 0, WINDOW, start));
        // Shown and resting: no frames, only the idle-fade timer.
        assert!(matches!(h.advance(start), Wait::Timed(_)));
        assert!(h.motion("agent", 1, WINDOW, [0.5, 0.5], entry(1040.0), start));
        assert!(
            matches!(h.advance(start), Wait::Frame(_)),
            "the entry plays"
        );
        h.take();

        let hidden = start + Duration::from_millis(200);
        h.previews.hide("agent");
        assert_eq!(h.take(), [Call::Remove("agent".into())]);
        // Mid-entry when it was hidden, yet nothing is drawn and the loop
        // waits for the next event with no timer at all.
        assert_eq!(h.advance(hidden), Wait::Event);
        // Late lines for the hidden preview neither draw nor revive it.
        assert!(!h.frame("agent", 1, WINDOW));
        assert!(!h.motion("agent", 1, WINDOW, [0.2, 0.2], glide(200.0), hidden));
        for later in [hidden, hidden + SECOND, hidden + IDLE_FADE_AFTER * 2] {
            assert_eq!(h.advance(later), Wait::Event);
            // With no badge on screen either, the helper's loop blocks.
            assert_eq!(sooner_wait(Wait::Event, h.advance(later)), Wait::Event);
        }
        assert_eq!(h.take(), [], "a hidden preview was drawn");
        assert!(h.previews.surface_for_update("agent").is_none());
    }

    #[test]
    fn frames_never_create_revive_or_keep_alive_a_preview() {
        let start = Instant::now();
        let mut h = Harness::new();
        assert!(!h.frame("agent", 1, WINDOW), "a frame created a preview");
        assert_eq!(h.advance(start), Wait::Event);
        assert!(h.preview("agent", 1, 0, WINDOW, start));
        h.take();
        // A frame every ten seconds right up to the idle timeout.
        let mut at = start;
        while at + SECOND * 10 < start + IDLE_FADE_AFTER {
            at += SECOND * 10;
            assert!(h.frame("agent", 1, WINDOW));
            h.advance(at);
        }
        h.take();
        // The frames did not restart the idle clock: it fades out on time.
        h.advance(start + IDLE_FADE_AFTER + FADE);
        assert_eq!(h.take(), [Call::Remove("agent".into())]);
        assert!(!h.frame("agent", 1, WINDOW), "a frame revived it");
        assert_eq!(
            h.advance(start + IDLE_FADE_AFTER + FADE + SECOND),
            Wait::Event
        );
        assert_eq!(h.take(), []);
    }

    #[test]
    fn a_motion_is_an_action_and_restarts_the_idle_clock() {
        let start = Instant::now();
        let mut h = Harness::new();
        assert!(h.preview("agent", 1, 0, WINDOW, start));
        let acted = start + SECOND * 60;
        assert!(h.motion("agent", 1, WINDOW, [0.5, 0.5], glide(0.0), acted));
        h.take();
        h.advance(start + IDLE_FADE_AFTER + FADE);
        assert!(
            !h.take().contains(&Call::Remove("agent".into())),
            "idled out though it acted a minute in"
        );
        h.advance(acted + IDLE_FADE_AFTER + FADE);
        assert!(h.take().contains(&Call::Remove("agent".into())));
    }

    #[test]
    fn stale_generations_and_other_windows_are_dropped() {
        let start = Instant::now();
        let mut h = Harness::new();
        assert!(h.preview("agent", 5, 0, WINDOW, start));
        assert!(!h.frame("agent", 4, WINDOW), "older generation");
        assert!(
            !h.frame("agent", 6, WINDOW),
            "newer generation not yet shown"
        );
        assert!(!h.frame("agent", 5, WINDOW + 1), "another window");
        assert!(!h.frame("someone-else", 5, WINDOW), "another agent");
        assert!(!h.motion("agent", 4, WINDOW, [0.5, 0.5], glide(0.0), start));
        assert!(!h.motion("agent", 5, WINDOW + 1, [0.5, 0.5], glide(0.0), start));
        assert!(
            !h.preview("agent", 4, 0, WINDOW, start),
            "an older preview line"
        );
        assert!(h.frame("agent", 5, WINDOW));
        assert!(h.motion("agent", 5, WINDOW, [0.5, 0.5], glide(0.0), start));
        // A point outside the window lands nowhere.
        assert!(!h.motion("agent", 5, WINDOW, [1.5, 0.5], glide(0.0), start));
        h.take();
        // Retargeted to another window: the old generation's lines are stale.
        assert!(h.preview("agent", 6, 0, WINDOW + 1, start));
        assert!(!h.frame("agent", 5, WINDOW));
        assert!(!h.motion("agent", 5, WINDOW, [0.5, 0.5], glide(0.0), start));
        assert!(h.frame("agent", 6, WINDOW + 1));
        let calls = h.take();
        assert!(
            matches!(
                &calls[..],
                [
                    Call::Show {
                        generation: 6,
                        window_changed: true,
                        ..
                    },
                    Call::Frame(6)
                ]
            ),
            "{calls:?}"
        );
    }

    #[test]
    fn previews_stack_in_their_slots_and_a_taken_slot_gives_way() {
        let start = Instant::now();
        let mut h = Harness::new();
        for (slot, agent) in ["a", "b", "c"].iter().enumerate() {
            assert!(h.preview(agent, 1, slot as u8, WINDOW, start));
        }
        let origins: Vec<[f64; 2]> = h
            .take()
            .into_iter()
            .map(|call| match call {
                Call::Show { origin, .. } => origin,
                other => panic!("{other:?}"),
            })
            .collect();
        for (slot, origin) in origins.iter().enumerate() {
            assert_eq!(Some(*origin), slot_origin(SCREEN, slot as u8));
        }
        assert!(
            !h.preview("d", 1, 3, WINDOW, start),
            "there is no fourth slot"
        );
        // A new agent given a slot another still holds takes it over.
        assert!(h.preview("d", 1, 1, WINDOW, start));
        let calls = h.take();
        assert_eq!(calls[0], Call::Remove("b".into()), "{calls:?}");
        assert!(h.previews.surface_for_update("b").is_none());
        assert!(h.previews.surface_for_update("a").is_some());
    }

    /// The module holds each action until the moment on its motion line, so
    /// the badge must be on the mapped spot, fully shown, exactly then, with
    /// lengths the helper's own curves would never give. A move to another
    /// window starts the badge over with an entry.
    #[test]
    fn the_badge_lands_in_the_preview_when_the_motion_line_says() {
        const STEP: Duration = Duration::from_millis(1);
        let start = Instant::now();
        let mut h = Harness::new();
        assert!(h.preview("agent", 1, 0, WINDOW, start));
        // How long after `sent` the badge landed on `to`, in ms, and whether
        // it played an entry on the way.
        let land = |h: &mut Harness, sent: Instant, to: [f64; 2]| -> (f64, bool) {
            let target = thumbnail_point(thumbnail(), to).unwrap();
            let mut now = sent;
            let mut entered = false;
            loop {
                h.take();
                h.advance(now);
                let drawn = h.take().into_iter().find_map(|call| match call {
                    Call::Draw(badge, _) => badge,
                    _ => None,
                });
                let badge = drawn.expect("the badge was drawn");
                entered |= badge.entry != EntryFrame::REST;
                if badge.tip == target && badge.alpha == 1.0 && badge.entry == EntryFrame::REST {
                    return ((now - sent).as_secs_f64() * 1000.0, entered);
                }
                now += STEP;
                assert!(now - sent < SECOND * 5, "the badge never landed");
            }
        };
        let mut sent = start;
        for (timing, to) in [
            (entry(777.0), [0.25, 0.75]),
            (glide(333.0), [0.9, 0.1]),
            (glide(0.0), [0.5, 0.5]),
            (glide(411.0), [0.0, 1.0]),
        ] {
            assert!(h.motion("agent", 1, WINDOW, to, timing, sent));
            let (took, entered) = land(&mut h, sent, to);
            assert_eq!(entered, timing.entry, "{timing:?}");
            assert!(
                (took - timing.duration_ms).abs() <= 1.0,
                "the line said {} ms and the badge took {took} ms",
                timing.duration_ms
            );
            sent += SECOND * 2;
            // At rest once landed: no frames.
            assert!(matches!(h.advance(sent), Wait::Timed(_)));
        }
        // Another window: the next motion is a first appearance.
        assert!(h.preview("agent", 2, 0, WINDOW + 1, sent));
        assert!(h.motion("agent", 2, WINDOW + 1, [0.5, 0.5], entry(640.0), sent));
        let (took, entered) = land(&mut h, sent, [0.5, 0.5]);
        assert!(entered, "the badge did not enter in the new window");
        assert!((took - 640.0).abs() <= 1.0, "{took} ms");
    }
}
