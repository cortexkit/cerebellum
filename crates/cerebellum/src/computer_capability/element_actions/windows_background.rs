use super::{ElementJournal, JournalStorage, Redactor, SeverityTaxonomy, Value};
use crate::computer_capability::fronting::{Fronting, Restore};
use cerebellum_core::config::AppUse;
use cerebellum_windows::{
    foreground_window_number, last_input_tick, process_start_time, window_owner, ProcessStartTime,
};

#[derive(Clone, Copy, Debug, Default)]
struct Sample {
    hwnd: Option<u32>,
    owner: Option<(u32, u64)>,
    last_input: Option<u32>,
}

impl Sample {
    fn now() -> Self {
        let hwnd = foreground_window_number();
        let last_input = last_input_tick();
        let owner = hwnd.and_then(|hwnd| {
            let (pid, _) = window_owner(hwnd).ok()?;
            match process_start_time(pid) {
                ProcessStartTime::Started(start) => Some((pid, start)),
                _ => None,
            }
        });
        Self {
            hwnd,
            owner,
            last_input,
        }
    }

    fn change_to(self, after: Self) -> Option<Fronting> {
        let changed = self.hwnd != after.hwnd
            || matches!((self.owner, after.owner), (Some(old), Some(new)) if old != new);
        if !changed {
            return None;
        }
        let person =
            matches!((self.last_input, after.last_input), (Some(old), Some(new)) if old != new);
        let mut report = Fronting::untouched(AppUse::Background);
        report.person_input_during_fronting = person;
        report.restore = if person {
            Restore::SkippedPerson
        } else {
            Restore::LeftInFront
        };
        Some(report)
    }
}

pub(super) fn sample_mutation<T>(mutate: impl FnOnce() -> T) -> (T, Option<Fronting>) {
    sample_with(Sample::now, mutate)
}

fn sample_with<T>(
    mut sample: impl FnMut() -> Sample,
    mutate: impl FnOnce() -> T,
) -> (T, Option<Fronting>) {
    let before = sample();
    let result = mutate();
    (result, before.change_to(sample()))
}

pub(super) fn apply<R: Redactor, T: SeverityTaxonomy, S: JournalStorage>(
    change: Option<Fronting>,
    journal: &mut ElementJournal<'_, R, T, S>,
    mut reply: Value,
) -> Value {
    if let Some(change) = change {
        journal.set_fronting(change.record());
        change.apply(&mut reply);
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn addressed_error_still_discloses_foreground_change() {
        use serde_json::json;

        let old = Sample {
            hwnd: Some(1),
            owner: Some((7, 100)),
            last_input: Some(80),
        };
        for (after, expected) in [
            (
                Sample {
                    hwnd: Some(2),
                    ..old
                },
                "left_in_front",
            ),
            (
                Sample {
                    owner: Some((7, 101)),
                    last_input: Some(90),
                    ..old
                },
                "skipped_person",
            ),
        ] {
            let current = Cell::new(old);
            let (result, change) = sample_with(
                || current.get(),
                || {
                    current.set(after);
                    Err::<(), _>("provider returned an error")
                },
            );
            assert_eq!(result, Err("provider returned an error"));
            let mut reply = json!({"outcome":"no_press_action"});
            change.unwrap().apply(&mut reply);
            assert_eq!(reply["outcome"], "no_press_action");
            assert_eq!(reply["fronting"]["mode"], "background");
            assert_eq!(reply["fronting"]["fronted"], false);
            assert_eq!(reply["fronting"]["purpose"], "none");
            assert_eq!(reply["fronting"]["restore"], expected);
        }
        assert!(sample_with(|| old, || Ok::<_, ()>(())).1.is_none());
    }
}
