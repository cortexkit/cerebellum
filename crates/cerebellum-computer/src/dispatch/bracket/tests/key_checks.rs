//! A keystroke unit posted while its target is in front checks focus,
//! cancellation and the bracket's deadline before each of its own key
//! posts, not only once before the unit.

use super::*;
use crate::platform::{
    post_event_sequence_fronted, FinalPostCheck, PerProcessEventTransport, PostCallFailure,
    PostCallMade, ProcessEventRefusal, ProcessEventTarget, ProcessGenerationReading, SyntheticStep,
    SyntheticStepRole, VisibilityMemo, WindowServerVisibility, VISIBLE_READING_MAX_AGE,
};
use std::cell::{Cell, RefCell};

const GENERATION: u64 = 42;
/// Each post call takes this long on the fake clock.
const POST_MS: u64 = 10;

/// What changes while the window server's listing of the target is read, a
/// query that can block for a while on a busy desk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuringListing {
    Nothing,
    FocusMoves,
    DeadlinePasses,
    CutoffFires,
}

/// What the keyboard sees: the clock, the frontmost application, and every
/// event posted, in order. `switch_after_posts` brings `THIRD` to the front
/// once that many events were posted.
struct Keyboard {
    now: Cell<u64>,
    generation: Cell<u64>,
    replace_during_focus: bool,
    replace_during_preparation: bool,
    frontmost: Cell<Option<u32>>,
    posted: RefCell<Vec<&'static str>>,
    switch_after_posts: Option<usize>,
    during_listing: Cell<DuringListing>,
    gate: CutoffGate,
    /// Whether input counted as held while each post call was in progress,
    /// one entry per post: a restore must wait while it does.
    held_during_post: RefCell<Vec<bool>>,
    record_hold_during_post: bool,
    /// The transport's own preparation for each post (an authentication
    /// object, say) takes this long on the fake clock.
    preparation_ms: u64,
    /// The process-generation reading with this number (from 1) takes past
    /// any deadline on the fake clock.
    slow_generation_read: Option<usize>,
    /// During the process-generation reading with this number (from 1),
    /// another application comes to the front; the target keeps its process.
    focus_moves_during_generation_read: Option<usize>,
    generation_reads: Cell<usize>,
    /// The unit is stopped while focus is being read.
    stop_during_focus_read: bool,
    stopped: Cell<bool>,
}

impl Keyboard {
    fn new() -> Self {
        Self {
            now: Cell::new(0),
            generation: Cell::new(GENERATION),
            replace_during_focus: false,
            replace_during_preparation: false,
            frontmost: Cell::new(Some(TARGET)),
            posted: RefCell::new(Vec::new()),
            switch_after_posts: None,
            during_listing: Cell::new(DuringListing::Nothing),
            gate: CutoffGate::new(),
            held_during_post: RefCell::new(Vec::new()),
            record_hold_during_post: false,
            preparation_ms: 0,
            slow_generation_read: None,
            focus_moves_during_generation_read: None,
            generation_reads: Cell::new(0),
            stop_during_focus_read: false,
            stopped: Cell::new(false),
        }
    }
}

struct Transport<'a>(&'a Keyboard);

impl PerProcessEventTransport for Transport<'_> {
    type Event = &'static str;

    fn process_generation(&mut self, _pid: u32) -> ProcessGenerationReading {
        let keyboard = self.0;
        let reads = keyboard.generation_reads.get() + 1;
        keyboard.generation_reads.set(reads);
        if keyboard.slow_generation_read == Some(reads) {
            keyboard.now.set(keyboard.now.get() + 1_000);
        }
        if keyboard.focus_moves_during_generation_read == Some(reads) {
            keyboard.frontmost.set(Some(THIRD));
        }
        ProcessGenerationReading::Started(keyboard.generation.get())
    }
    fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
        let keyboard = self.0;
        match keyboard.during_listing.get() {
            DuringListing::Nothing => {}
            DuringListing::FocusMoves => keyboard.frontmost.set(Some(THIRD)),
            DuringListing::DeadlinePasses => keyboard.now.set(keyboard.now.get() + 1_000),
            DuringListing::CutoffFires => {
                // The restore reserve starts while the listing is read.
                keyboard.gate.set_bound(
                    std::time::Instant::now() - std::time::Duration::from_millis(1),
                    std::time::Instant::now() + std::time::Duration::from_secs(3600),
                );
            }
        }
        WindowServerVisibility::Visible
    }
    fn post_to_pid(
        &mut self,
        _pid: u32,
        event: &'static str,
    ) -> Result<PostCallMade, PostCallFailure> {
        let keyboard = self.0;
        if keyboard.record_hold_during_post {
            keyboard
                .held_during_post
                .borrow_mut()
                .push(keyboard.gate.input_held());
        }
        keyboard.posted.borrow_mut().push(event);
        keyboard.now.set(keyboard.now.get() + POST_MS);
        if keyboard.switch_after_posts == Some(keyboard.posted.borrow().len()) {
            keyboard.frontmost.set(Some(THIRD));
        }
        Ok(PostCallMade::public_core_graphics())
    }
    fn post_to_pid_after(
        &mut self,
        pid: u32,
        event: &'static str,
        last_check: &mut FinalPostCheck<'_>,
    ) -> Result<PostCallMade, ProcessEventRefusal> {
        let keyboard = self.0;
        keyboard
            .now
            .set(keyboard.now.get() + keyboard.preparation_ms);
        if keyboard.replace_during_preparation {
            keyboard.generation.set(GENERATION + 1);
        }
        last_check(&mut || self.process_generation(pid))?;
        self.post_to_pid(pid, event)
            .map_err(ProcessEventRefusal::PostCallFailed)
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
    post_with(
        keyboard,
        steps,
        deadline_ms,
        cancelled,
        &mut VisibilityMemo::new(VISIBLE_READING_MAX_AGE),
        None,
    )
}

fn post_with(
    keyboard: &Keyboard,
    steps: Vec<SyntheticStep<&'static str>>,
    deadline_ms: u64,
    cancelled: &dyn Fn() -> bool,
    visibility: &mut VisibilityMemo,
    cutoff: Option<&CutoffGate>,
) -> Result<crate::platform::SequencePostReport, SequencePostFailure> {
    let mut checks = FrontedKeyChecks {
        target_pid: TARGET,
        deadline_ms,
        now_ms: || keyboard.now.get(),
        frontmost_pid: || {
            if keyboard.replace_during_focus {
                keyboard.generation.set(GENERATION + 1);
            }
            if keyboard.stop_during_focus_read {
                keyboard.stopped.set(true);
            }
            keyboard.frontmost.get()
        },
        cutoff,
    };
    post_event_sequence_fronted(
        ProcessEventTarget {
            pid: TARGET,
            start_time_micros: GENERATION,
        },
        steps,
        &mut Transport(keyboard),
        visibility,
        cancelled,
        &mut checks,
    )
}

/// A key whose listing read is slow, while something that forbids the post
/// happens during that read.
fn post_one_key_while(change: DuringListing, cancelled: &dyn Fn() -> bool) -> Keyboard {
    let keyboard = Keyboard::new();
    keyboard.during_listing.set(change);
    let failure = post_with(
        &keyboard,
        vec![press("a down"), release("a up")],
        500,
        cancelled,
        &mut VisibilityMemo::uncached(),
        Some(&keyboard.gate),
    )
    .unwrap_err();
    assert_eq!(
        failure.refusal,
        ProcessEventRefusal::Cancelled,
        "{change:?}"
    );
    assert_eq!(failure.posts_returned, 0, "{change:?}");
    assert_eq!(
        failure.held_state,
        HeldStateDisposition::NoneHeld,
        "{change:?}"
    );
    keyboard
}

#[test]
fn focus_moving_during_the_listing_read_refuses_the_post() {
    let keyboard = post_one_key_while(DuringListing::FocusMoves, &|| false);
    assert!(keyboard.posted.borrow().is_empty());
}

#[test]
fn the_deadline_passing_during_the_listing_read_refuses_the_post() {
    let keyboard = post_one_key_while(DuringListing::DeadlinePasses, &|| false);
    assert!(keyboard.posted.borrow().is_empty());
}

#[test]
fn the_cutoff_passing_during_the_listing_read_refuses_the_post() {
    let keyboard = post_one_key_while(DuringListing::CutoffFires, &|| false);
    assert!(keyboard.posted.borrow().is_empty());
    assert!(
        !keyboard.gate.input_held(),
        "nothing was committed, so nothing holds up the restore"
    );
}

#[test]
fn a_stop_during_the_listing_read_refuses_the_post() {
    let listed = Cell::new(false);
    let keyboard = Keyboard::new();
    // Cancellation is first read before the listing, when it is still clear,
    // and becomes true once the listing has been read.
    struct Watching<'a>(&'a Keyboard, &'a Cell<bool>);
    impl PerProcessEventTransport for Watching<'_> {
        type Event = &'static str;
        fn process_generation(&mut self, pid: u32) -> ProcessGenerationReading {
            Transport(self.0).process_generation(pid)
        }
        fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
            self.1.set(true);
            WindowServerVisibility::Visible
        }
        fn post_to_pid(
            &mut self,
            pid: u32,
            event: &'static str,
        ) -> Result<PostCallMade, PostCallFailure> {
            Transport(self.0).post_to_pid(pid, event)
        }
    }
    let mut checks = FrontedKeyChecks {
        target_pid: TARGET,
        deadline_ms: 500,
        now_ms: || keyboard.now.get(),
        frontmost_pid: || keyboard.frontmost.get(),
        cutoff: None,
    };
    let failure = post_event_sequence_fronted(
        ProcessEventTarget {
            pid: TARGET,
            start_time_micros: GENERATION,
        },
        vec![press("a down"), release("a up")],
        &mut Watching(&keyboard, &listed),
        &mut VisibilityMemo::uncached(),
        &|| listed.get(),
        &mut checks,
    )
    .unwrap_err();
    assert_eq!(failure.posts_returned, 0);
    assert!(keyboard.posted.borrow().is_empty());
}

#[test]
fn a_self_contained_post_holds_the_cutoff_while_it_is_in_flight() {
    let mut keyboard = Keyboard::new();
    keyboard.record_hold_during_post = true;
    post_with(
        &keyboard,
        vec![SyntheticStep {
            role: SyntheticStepRole::SelfContained,
            event: "scroll",
        }],
        500,
        &|| false,
        &mut VisibilityMemo::uncached(),
        Some(&keyboard.gate),
    )
    .unwrap();
    assert_eq!(
        *keyboard.held_during_post.borrow(),
        [true],
        "input counts as held while the post is in flight"
    );
    assert!(
        !keyboard.gate.input_held(),
        "once the post returned nothing is held, so the restore may start"
    );
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

/// Post one key, pressed and released, with the cutoff gate, and expect the
/// press to be refused with nothing posted.
fn refused_before_any_post(keyboard: &Keyboard) {
    let failure = post_with(
        keyboard,
        vec![press("a down"), release("a up")],
        500,
        &|| keyboard.stopped.get(),
        &mut VisibilityMemo::uncached(),
        Some(&keyboard.gate),
    )
    .unwrap_err();
    assert_eq!(failure.refusal, ProcessEventRefusal::Cancelled);
    assert_eq!(failure.posts_returned, 0);
    assert!(keyboard.posted.borrow().is_empty());
}

#[test]
fn a_pid_replaced_during_focus_or_transport_preparation_never_receives_the_post() {
    for replace_during_focus in [true, false] {
        let mut keyboard = Keyboard::new();
        keyboard.replace_during_focus = replace_during_focus;
        keyboard.replace_during_preparation = !replace_during_focus;
        let failure = post_with(
            &keyboard,
            vec![press("a down"), release("a up")],
            500,
            &|| false,
            &mut VisibilityMemo::uncached(),
            Some(&keyboard.gate),
        )
        .unwrap_err();
        assert_eq!(
            failure.refusal,
            ProcessEventRefusal::ProcessReplaced {
                expected_start_time_micros: GENERATION,
                observed_start_time_micros: GENERATION + 1,
            }
        );
        assert!(keyboard.posted.borrow().is_empty());
    }
}

#[test]
fn the_deadline_passing_during_the_transports_preparation_refuses_the_post() {
    let mut keyboard = Keyboard::new();
    keyboard.preparation_ms = 1_000;
    refused_before_any_post(&keyboard);
}

#[test]
fn the_deadline_passing_during_the_final_generation_lookup_refuses_the_post() {
    let mut keyboard = Keyboard::new();
    // The first reading comes with the listing read; the second is the
    // final lookup just before the post.
    keyboard.slow_generation_read = Some(2);
    refused_before_any_post(&keyboard);
}

#[test]
fn focus_moving_during_the_final_generation_lookup_refuses_the_post() {
    let mut keyboard = Keyboard::new();
    // The first reading comes with the listing read; the second is the
    // final lookup just before the post. The process is not replaced, so
    // the lookup itself passes.
    keyboard.focus_moves_during_generation_read = Some(2);
    refused_before_any_post(&keyboard);
}

#[test]
fn a_stop_during_the_focus_read_refuses_the_post() {
    let mut keyboard = Keyboard::new();
    keyboard.stop_during_focus_read = true;
    refused_before_any_post(&keyboard);
}

#[test]
fn the_absolute_deadline_refuses_the_post_even_without_a_cutoff_bound() {
    let keyboard = Keyboard::new();
    keyboard.now.set(600);
    assert!(!keyboard.gate.closed(), "the gate itself has no bound yet");
    refused_before_any_post(&keyboard);
}
