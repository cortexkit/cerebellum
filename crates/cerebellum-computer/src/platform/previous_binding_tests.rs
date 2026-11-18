//! The previous application's binding: made once before the front, never
//! replaced, and handed to the restore as a value.

use super::{PreviousBinding, PreviousSlot};

const PREVIOUS: u32 = 100;
const STARTED: u64 = 42;

#[test]
fn a_failed_initial_bind_admits_no_restore_write_ever() {
    let mut slot = PreviousSlot::default();
    assert!(slot.bind_once(PREVIOUS, |_| None), "the one bind happened");
    assert_eq!(slot.identity(), None);
    // A later lookup would succeed, but nothing binds again.
    assert!(!slot.bind_once(PREVIOUS, |_| Some(STARTED)));
    assert_eq!(slot.identity(), None, "the failed bind stands");
}

#[test]
fn a_bound_previous_keeps_the_first_process_generation() {
    let mut slot = PreviousSlot::default();
    assert_eq!(slot.identity(), None);
    assert!(slot.bind_once(PREVIOUS, |_| Some(STARTED)));
    // A second bind, here to a replacement process, changes nothing.
    assert!(!slot.bind_once(PREVIOUS, |_| Some(STARTED + 1)));
    assert_eq!(slot.identity(), Some((PREVIOUS, STARTED)));
}

#[test]
fn a_binding_is_a_value_that_reads_the_start_time_once() {
    let mut reads = 0;
    let binding = PreviousBinding::bind(PREVIOUS, |pid| {
        reads += 1;
        assert_eq!(pid, PREVIOUS);
        Some(STARTED)
    });
    let moved = binding;
    assert_eq!(reads, 1);
    assert_eq!(moved.identity(), Some((PREVIOUS, STARTED)));
    assert_eq!(moved, binding, "a copy carries the same identity");
}
