use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundRestore {
    Restored,
    LeftInFront,
    Failed,
    SkippedPerson { input: bool },
}

/// Sample before a mutation or a launch that posts no synthetic input. Keep
/// the original process object through the write and any attempted restore.
pub struct BackgroundForeground {
    number: Option<u32>,
    binding: Option<Binding>,
    last_input: Option<u32>,
}

impl BackgroundForeground {
    pub fn sample() -> Self {
        let last_input = last_input_tick();
        let number = foreground_window_number();
        let binding = number.and_then(|number| Binding::read(number, None));
        Self {
            number,
            binding,
            last_input,
        }
    }

    pub fn after_mutation(
        self,
        admitted: bool,
        target: &ProcessGrant,
    ) -> Option<BackgroundRestore> {
        self.finish(admitted, |after| {
            after.pid() == target.pid
                && generation(&after.target).is_some_and(|start| {
                    target.process_generation_evidence.parse::<u64>() == Ok(start)
                })
        })
    }

    pub fn after_launch(
        self,
        admitted: bool,
        opened_pid: Option<u32>,
        principal: &str,
        deadline: Instant,
    ) -> Option<BackgroundRestore> {
        self.finish(admitted, |after| {
            // A pid in an open result is not a grant. Verify the actual
            // foreground process against the admitted launch principal.
            opened_pid == Some(after.pid())
                && super::super::identity::live_identity(after.pid(), deadline).is_ok_and(
                    |identity| {
                        identity.principal.to_string() == principal
                            && generation(&after.target) == Some(identity.generation)
                    },
                )
        })
    }

    fn finish(
        self,
        admitted: bool,
        belongs_to_target: impl FnOnce(&Binding) -> bool,
    ) -> Option<BackgroundRestore> {
        let after = Self::sample();
        let changed = self.number != after.number
            || match (&self.binding, &after.binding) {
                (Some(before), Some(after)) => before.proof != after.proof,
                _ => false,
            };
        if !changed {
            return None;
        }
        Some(after_change(
            (self.last_input, after.last_input),
            admitted,
            |input| {
                let (Some(before), Some(after)) = (&self.binding, &after.binding) else {
                    return BackgroundRestore::LeftInFront;
                };
                if !belongs_to_target(after) {
                    return BackgroundRestore::LeftInFront;
                }
                let Some(_lane) = take_foreground_lane() else {
                    return BackgroundRestore::LeftInFront;
                };
                restore(before, after, input)
            },
        ))
    }
}

fn after_change(
    ticks: (Option<u32>, Option<u32>),
    admitted: bool,
    try_restore: impl FnOnce(u32) -> BackgroundRestore,
) -> BackgroundRestore {
    match ticks {
        (Some(before), Some(after)) if before != after => {
            BackgroundRestore::SkippedPerson { input: true }
        }
        (Some(before), Some(_)) if admitted => try_restore(before),
        _ => BackgroundRestore::LeftInFront,
    }
}

fn restore(before: &Binding, after: &Binding, input: u32) -> BackgroundRestore {
    let changed_input = |now: Option<u32>| match now {
        Some(now) if now != input => Some(BackgroundRestore::SkippedPerson { input: true }),
        None => Some(BackgroundRestore::LeftInFront),
        _ => None,
    };
    if let Some(stop) = changed_input(last_input_tick()) {
        return stop;
    }
    if !desktop_safe() || !after.safe_integrity() {
        return BackgroundRestore::LeftInFront;
    }
    if !before.current() || !before.safe_integrity() {
        return BackgroundRestore::Failed;
    }
    if !after.is_foreground() {
        return BackgroundRestore::SkippedPerson { input: false };
    }
    if let Some(stop) = changed_input(last_input_tick()) {
        return stop;
    }
    // Exactly one request, to the retained original HWND, followed by a
    // reading. A refusal does not authorize another attempt.
    if foreground_window_number() != Some(after.number) {
        return BackgroundRestore::SkippedPerson { input: false };
    }
    if set_foreground_window(before.number) && before.is_foreground() {
        BackgroundRestore::Restored
    } else {
        BackgroundRestore::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_change_only_enters_restore_with_review_and_unchanged_readable_input() {
        let tick = Some(71);
        for (ticks, admitted, expected) in [
            ((tick, tick), false, BackgroundRestore::LeftInFront),
            ((tick, None), true, BackgroundRestore::LeftInFront),
            ((None, tick), true, BackgroundRestore::LeftInFront),
            (
                (tick, Some(72)),
                true,
                BackgroundRestore::SkippedPerson { input: true },
            ),
        ] {
            assert_eq!(
                after_change(ticks, admitted, |_| panic!("restore not admitted")),
                expected
            );
        }
        assert_eq!(
            after_change((tick, tick), true, |saved| {
                assert_eq!(Some(saved), tick);
                BackgroundRestore::Restored
            }),
            BackgroundRestore::Restored
        );
    }
}
