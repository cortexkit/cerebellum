use cerebellum_computer::platform::process_event::{
    post_event_sequence_paced, HeldStateDisposition, PerProcessEventTransport, PostCallFailure,
    PostCallMade, ProcessEventTarget, ProcessGenerationReading, SyntheticStep, SyntheticStepRole,
    WindowServerVisibility,
};
use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

// A controlled editor finishes committing its caret on a later render frame.
// A character posted before that commit inserts at the stale, initial caret.
#[derive(Default)]
struct ControlledEditor {
    value: String,
    now: Duration,
    last_character: Option<Duration>,
    posts: usize,
    generations: usize,
    waits: Vec<Duration>,
    cancel_on_wait: Option<Rc<Cell<bool>>>,
}

const EDITOR_COMMIT: Duration = Duration::from_millis(16);

impl PerProcessEventTransport for ControlledEditor {
    type Event = (char, bool);

    fn wait_between_characters(&mut self, interval: Duration) {
        self.waits.push(interval);
        self.now += interval;
        if let Some(cancelled) = &self.cancel_on_wait {
            cancelled.set(true);
        }
    }

    fn process_generation(&mut self, _: u32) -> ProcessGenerationReading {
        self.generations += 1;
        ProcessGenerationReading::Started(1)
    }

    fn window_server_visibility(&mut self, _: u32) -> WindowServerVisibility {
        WindowServerVisibility::Visible
    }

    fn post_to_pid(
        &mut self,
        _: u32,
        (character, down): Self::Event,
    ) -> Result<PostCallMade, PostCallFailure> {
        self.posts += 1;
        if down {
            if self
                .last_character
                .is_some_and(|last| self.now - last >= EDITOR_COMMIT)
            {
                self.value.push(character);
            } else {
                self.value.insert(0, character);
            }
            self.last_character = Some(self.now);
        }
        Ok(PostCallMade::public_core_graphics())
    }
}

fn type_into(
    editor: &mut ControlledEditor,
    text: &str,
    interval: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), HeldStateDisposition> {
    let steps = text
        .chars()
        .flat_map(|character| {
            [
                SyntheticStep {
                    event: (character, true),
                    role: SyntheticStepRole::Press,
                },
                SyntheticStep {
                    event: (character, false),
                    role: SyntheticStepRole::Release,
                },
            ]
        })
        .collect();
    post_event_sequence_paced(
        ProcessEventTarget {
            pid: 42,
            start_time_micros: 1,
        },
        steps,
        interval,
        editor,
        cancelled,
    )
    .map(|_| ())
    .map_err(|failure| failure.held_state)
}

#[test]
fn paced_typing_keeps_a_controlled_editors_characters_in_order() {
    let mut editor = ControlledEditor::default();
    let text = "badge check three 🦀";
    type_into(
        &mut editor,
        text,
        Duration::from_millis(crate::budgets::TYPE_CHARACTER_INTERVAL_MS),
        &|| false,
    )
    .unwrap();
    assert_eq!(editor.value, text);
    assert_eq!(editor.posts, text.chars().count() * 2);
    assert_eq!(editor.generations, editor.posts * 2);
    assert_eq!(editor.waits.len(), text.chars().count() - 1);
}

#[test]
fn controlled_editor_reverses_a_burst_but_accepts_a_committed_caret() {
    for (interval, expected) in [
        (Duration::ZERO, "eerht kcehc egdab"),
        (Duration::from_millis(10), "eerht kcehc egdab"),
        (EDITOR_COMMIT, "badge check three"),
    ] {
        let mut editor = ControlledEditor::default();
        type_into(&mut editor, "badge check three", interval, &|| false).unwrap();
        assert_eq!(editor.value, expected, "cadence {interval:?}");
    }
}

#[test]
fn cancellation_during_the_character_gap_posts_no_next_press() {
    let cancelled = Rc::new(Cell::new(false));
    let mut editor = ControlledEditor {
        cancel_on_wait: Some(cancelled.clone()),
        ..Default::default()
    };
    assert_eq!(
        type_into(
            &mut editor,
            "ab",
            Duration::from_millis(crate::budgets::TYPE_CHARACTER_INTERVAL_MS),
            &|| cancelled.get()
        ),
        Err(HeldStateDisposition::NoneHeld)
    );
    assert_eq!(editor.value, "a");
    assert_eq!(editor.posts, 2);
    assert_eq!(editor.waits.len(), 1);
}
