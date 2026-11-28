use super::{ElementJournal, JournalStorage, Redactor, SeverityTaxonomy, Value};
use crate::computer_capability::fronting::Fronting;
use cerebellum_computer::platform::{windows::fronting::BackgroundForeground, ProcessGrant};

pub(super) fn sample_mutation<T>(
    target: &ProcessGrant,
    admitted: bool,
    mutate: impl FnOnce() -> T,
) -> (T, Option<Fronting>) {
    sample_with(BackgroundForeground::sample(), mutate, |before| {
        before
            .after_mutation(admitted, target)
            .map(Fronting::windows_background)
    })
}

fn sample_with<T, S>(
    before: S,
    mutate: impl FnOnce() -> T,
    finish: impl FnOnce(S) -> Option<Fronting>,
) -> (T, Option<Fronting>) {
    let result = mutate();
    (result, finish(before))
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
    use cerebellum_computer::platform::windows::fronting::BackgroundRestore;
    use std::cell::Cell;

    #[test]
    fn addressed_error_still_discloses_foreground_change() {
        use serde_json::json;

        for (status, expected) in [
            (BackgroundRestore::Restored, "restored"),
            (BackgroundRestore::LeftInFront, "left_in_front"),
            (BackgroundRestore::Failed, "failed"),
            (
                BackgroundRestore::SkippedPerson { input: true },
                "skipped_person",
            ),
        ] {
            let mutated = Cell::new(false);
            let (result, change) = sample_with(
                (),
                || {
                    mutated.set(true);
                    Err::<(), _>("provider returned an error")
                },
                |_| {
                    assert!(mutated.get());
                    Some(Fronting::windows_background(status))
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
        assert!(sample_with((), || Ok::<_, ()>(()), |_| None).1.is_none());
    }
}
