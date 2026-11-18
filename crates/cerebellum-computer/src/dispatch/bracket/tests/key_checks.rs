//! A keystroke unit posted while its target is in front checks focus,
//! cancellation and the bracket's deadline before each of its own key
//! posts, not only once before the unit.

use super::*;
use crate::platform::{
    post_event_sequence_fronted, PerProcessEventTransport, PostCallFailure, PostCallMade,
    ProcessEventRefusal, ProcessEventTarget, ProcessGenerationReading, SyntheticStep,
    SyntheticStepRole, VisibilityMemo, WindowServerVisibility, VISIBLE_READING_MAX_AGE,
};
use std::cell::{Cell, RefCell};

const GENERATION: u64 = 42;
/// Each post call takes this long on the fake clock.
const POST_MS: u64 = 10;

/// What the keyboard sees: the clock, the frontmost application, and every
/// event posted, in order. `switch_after_posts` brings `THIRD` to the front
/// once that many events were posted.
struct Keyboard {
    now: Cell<u64>,
    frontmost: Cell<Option<u32>>,
    posted: RefCell<Vec<&'static str>>,
    switch_after_posts: Option<usize>,
}

impl Keyboard {
    fn new() -> Self {
        Self {
            now: Cell::new(0),
            frontmost: Cell::new(Some(TARGET)),
            posted: RefCell::new(Vec::new()),
            switch_after_posts: None,
        }
    }
}

struct Transport<'a>(&'a Keyboard);

impl PerProcessEventTransport for Transport<'_> {
    type Event = &'static str;

    fn process_generation(&mut self, _pid: u32) -> ProcessGenerationReading {
        ProcessGenerationReading::Started(GENERATION)
    }
    fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
        WindowServerVisibility::Visible
    }
    fn post_to_pid(
        &mut self,
        _pid: u32,
        event: &'static str,
    ) -> Result<PostCallMade, PostCallFailure> {
        let keyboard = self.0;
        keyboard.posted.borrow_mut().push(event);
        keyboard.now.set(keyboard.now.get() + POST_MS);
        if keyboard.switch_after_posts == Some(keyboard.posted.borrow().len()) {
            keyboard.frontmost.set(Some(THIRD));
        }
        Ok(PostCallMade::public_core_graphics())
    }
}

fn press(event: &'static str) -> SyntheticStep<&'static str> {
    SyntheticStep {
        role: SyntheticStepRole::Press,
        event,
    }
}

fn release(event: &'static str) -> SyntheticStep<&'static str> {
    SyntheticStep {
        role: SyntheticStepRole::Release,
        event,
    }
}

/// Command+V as a chord: the modifier stays down across the key's press.
fn paste() -> Vec<SyntheticStep<&'static str>> {
    vec![
        press("cmd down"),
        press("v down"),
        release("v up"),
        release("cmd up"),
    ]
}

/// Typed "ab": two keys, each pressed and released.
fn two_keys() -> Vec<SyntheticStep<&'static str>> {
    vec![
        press("a down"),
        release("a up"),
        press("b down"),
        release("b up"),
    ]
}

fn post(
    keyboard: &Keyboard,
    steps: Vec<SyntheticStep<&'static str>>,
    deadline_ms: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<crate::platform::SequencePostReport, SequencePostFailure> {
    let mut checks = FrontedKeyChecks {
        target_pid: TARGET,
        deadline_ms,
        now_ms: || keyboard.now.get(),
        frontmost_pid: || keyboard.frontmost.get(),
        cutoff: None,
    };
    post_event_sequence_fronted(
        ProcessEventTarget {
            pid: TARGET,
            start_time_micros: GENERATION,
        },
        steps,
        &mut Transport(keyboard),
        &mut VisibilityMemo::new(VISIBLE_READING_MAX_AGE),
        cancelled,
        &mut checks,
    )
}

#[test]
fn a_key_post_after_focus_moves_is_refused_and_the_held_modifier_released() {
    let mut keyboard = Keyboard::new();
    keyboard.switch_after_posts = Some(1);
    let failure = post(&keyboard, paste(), 1_000, &|| false).unwrap_err();
    assert_eq!(*keyboard.posted.borrow(), ["cmd down", "cmd up"]);
    assert_eq!(failure.refusal, ProcessEventRefusal::Cancelled);
    assert_eq!(
        failure.held_state,
        HeldStateDisposition::Released { posts_returned: 1 }
    );
    assert_eq!(failure.posts_returned, 1);
}

#[test]
fn a_key_post_at_the_deadline_is_refused() {
    let keyboard = Keyboard::new();
    // The first key's press and release take 20 ms; the second key would
    // start past the 15 ms deadline.
    let failure = post(&keyboard, two_keys(), 15, &|| false).unwrap_err();
    assert_eq!(*keyboard.posted.borrow(), ["a down", "a up"]);
    assert_eq!(failure.refusal, ProcessEventRefusal::Cancelled);
    assert_eq!(failure.held_state, HeldStateDisposition::NoneHeld);
}

#[test]
fn cancellation_between_key_posts_stops_the_unit_and_releases_the_modifier() {
    let keyboard = Keyboard::new();
    let cancelled = || !keyboard.posted.borrow().is_empty();
    let failure = post(&keyboard, paste(), 1_000, &cancelled).unwrap_err();
    assert_eq!(*keyboard.posted.borrow(), ["cmd down", "cmd up"]);
    assert_eq!(
        failure.held_state,
        HeldStateDisposition::Released { posts_returned: 1 }
    );
}

#[test]
fn a_unit_that_stays_in_front_and_inside_the_deadline_posts_every_key() {
    let keyboard = Keyboard::new();
    let report = post(&keyboard, paste(), 1_000, &|| false).unwrap();
    assert_eq!(report.posts_returned, 4);
    assert_eq!(
        *keyboard.posted.borrow(),
        ["cmd down", "v down", "v up", "cmd up"]
    );
}
