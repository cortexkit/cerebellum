use super::{ElementActionError, ReadError, ReadResult};
use cerebellum_windows::{ScopedUia, UiaElementRef, UiaPatterns};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PressPattern {
    Invoke,
    Toggle,
    SelectionItem,
    ExpandCollapse,
}

impl PressPattern {
    pub fn first(patterns: UiaPatterns) -> Option<Self> {
        [
            (patterns.invoke, Self::Invoke),
            (patterns.toggle, Self::Toggle),
            (patterns.selection_item, Self::SelectionItem),
            (patterns.expand_collapse, Self::ExpandCollapse),
        ]
        .into_iter()
        .find_map(|(available, pattern)| available.then_some(pattern))
    }

    pub fn run(
        self,
        uia: &ScopedUia,
        window: u32,
        runtime_id: &[i32],
        before: impl FnOnce(&UiaElementRef) -> ReadResult<()>,
    ) -> ReadResult<()> {
        match self {
            Self::Invoke => uia.invoke_at(window, runtime_id, before),
            Self::Toggle => uia.toggle_at(window, runtime_id, before),
            Self::SelectionItem => uia.select_item_at(window, runtime_id, before),
            Self::ExpandCollapse => uia.expand_collapse_at(window, runtime_id, |found, state| {
                before(found)?;
                match state {
                    0 => Ok(true),  // Collapsed
                    1 => Ok(false), // Expanded
                    _ => Err(ReadError::Unsupported),
                }
            }),
        }
    }
}

pub(super) fn mutation_error(error: ReadError) -> ElementActionError {
    match error {
        // A provider can finish after the caller stops waiting for the worker.
        // Never invite the caller to repeat an action that may already have run.
        ReadError::Deadline => ElementActionError::Indeterminate,
        error => error.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_pattern_precedence() {
        let mut facts = UiaPatterns {
            invoke: true,
            toggle: true,
            selection_item: true,
            expand_collapse: true,
            value_read_only: Some(false),
        };
        assert_eq!(PressPattern::first(facts), Some(PressPattern::Invoke));
        facts.invoke = false;
        assert_eq!(PressPattern::first(facts), Some(PressPattern::Toggle));
        facts.toggle = false;
        assert_eq!(
            PressPattern::first(facts),
            Some(PressPattern::SelectionItem)
        );
        facts.selection_item = false;
        assert_eq!(
            PressPattern::first(facts),
            Some(PressPattern::ExpandCollapse)
        );
        facts.expand_collapse = false;
        assert_eq!(PressPattern::first(facts), None);
    }
}
