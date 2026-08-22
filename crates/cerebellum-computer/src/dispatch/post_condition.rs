//! What an action claims will be true afterwards, in a closed vocabulary.
//!
//! Delivering an action is not evidence that it happened. An accessibility
//! action reporting success means the application's handler returned, and some
//! applications return success from a handler that forwards nothing. So every
//! action declares, before it is delivered, an observable condition that will
//! hold if it worked -- and that condition is checked afterwards against a
//! fresh read.
//!
//! THE VOCABULARY IS CLOSED, and this is the point of the module. The
//! surrounding types carried the condition as a free-form string, which cannot
//! be checked: an observer given text it does not recognise has no way to say
//! whether the condition held, and the honest answer it must give --
//! indeterminate -- is indistinguishable from an action that genuinely could
//! not be observed. Every condition here is one this module knows how to
//! evaluate against an accessibility element, so an unrecognised condition
//! cannot be constructed rather than being reported at observation time.
//!
//! Each variant names something the reader actually reports. Nothing here can
//! express a condition about pixels, timing, or another process, because none
//! of those are observable through the seam that checks it.

use crate::platform::{AccessibilityElementName, AccessibilityReadbackAttribute};
use serde::{Deserialize, Serialize};

/// A condition an action claims will hold once it has taken effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PostCondition {
    /// The element carries keyboard focus.
    ///
    /// What a click on a text field claims. Focus is reported by the element
    /// itself rather than inferred from what was clicked.
    ElementFocused { element: AccessibilityElementName },

    /// The element's value reads as the expected text.
    ///
    /// What typing claims. Compared exactly: a value that merely contains the
    /// expected text would also match a field that already held it plus
    /// something else, which is a different outcome from the one claimed.
    ElementValueEquals {
        element: AccessibilityElementName,
        expected: String,
    },

    /// The element's enabled state changed to the expected one.
    ///
    /// What invoking a control that disables itself claims, and the weakest
    /// useful condition: many actions change nothing else observable.
    ElementEnabledIs {
        element: AccessibilityElementName,
        expected: bool,
    },

    /// The element is no longer present in the tree.
    ///
    /// What dismissing a dialog or closing a panel claims. Absence is stated
    /// separately from a changed attribute because an element that has gone
    /// cannot report anything about itself.
    ElementAbsent { element: AccessibilityElementName },

    /// A named element exists that did not before.
    ///
    /// What opening a menu or a dialog claims. The observation is existence
    /// only: what the new element contains is a separate question needing a
    /// separate read.
    ElementPresent { element: AccessibilityElementName },
}

impl PostCondition {
    /// The exact accessibility key for the element this condition is about.
    ///
    /// Every condition names exactly one, which lets an observer scope each
    /// readback to that element instead of materializing the full tree.
    pub fn element(&self) -> &AccessibilityElementName {
        match self {
            Self::ElementFocused { element }
            | Self::ElementValueEquals { element, .. }
            | Self::ElementEnabledIs { element, .. }
            | Self::ElementAbsent { element }
            | Self::ElementPresent { element } => element,
        }
    }

    /// The only attribute the scoped readback needs after naming the element.
    pub const fn readback_attribute(&self) -> AccessibilityReadbackAttribute {
        match self {
            Self::ElementFocused { .. } => AccessibilityReadbackAttribute::Focused,
            Self::ElementValueEquals { .. } => AccessibilityReadbackAttribute::Value,
            Self::ElementEnabledIs { .. } => AccessibilityReadbackAttribute::Enabled,
            Self::ElementAbsent { .. } | Self::ElementPresent { .. } => {
                AccessibilityReadbackAttribute::Presence
            }
        }
    }

    /// Whether the condition expects the element to be gone.
    ///
    /// An observer must know this before reading: for every other condition a
    /// missing element means the action did not work, and for this one it means
    /// it did. Without the distinction a failed read and a satisfied condition
    /// look identical.
    pub const fn expects_absence(&self) -> bool {
        matches!(self, Self::ElementAbsent { .. })
    }
}

/// What an element looked like when the condition was checked.
///
/// Deliberately smaller than the reader's element type: only the attributes a
/// condition can be written about. A wider observation would let a caller read
/// application content through the effect-checking path, which exists to
/// answer one yes-or-no question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedElement {
    pub present: bool,
    pub focused: Option<bool>,
    pub enabled: Option<bool>,
    pub value: Option<String>,
}

impl ObservedElement {
    /// The observation for an element that is not in the tree.
    pub const fn absent() -> Self {
        Self {
            present: false,
            focused: None,
            enabled: None,
            value: None,
        }
    }
}

/// Whether a condition held, or could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionOutcome {
    /// The condition held.
    Satisfied,
    /// The condition did not hold, and the observation was good enough to say so.
    Unsatisfied,
    /// The element could not report the attribute the condition is about.
    ///
    /// Distinct from unsatisfied, and the distinction is the whole reason this
    /// is not a boolean. An attribute an application does not expose says
    /// nothing about whether the action worked, while an attribute that
    /// disagrees says it did not. Reporting the first as the second would fail
    /// actions that succeeded, on applications that are merely quiet.
    Indeterminate,
}

/// Check a condition against what the element reported.
///
/// Absence is decided first, because every other condition reads an attribute
/// of an element that has to exist. A missing element makes those conditions
/// UNSATISFIED rather than indeterminate: the element being gone is a definite
/// observation, not a failure to observe.
pub fn evaluate(condition: &PostCondition, observed: &ObservedElement) -> ConditionOutcome {
    if condition.expects_absence() {
        return if observed.present {
            ConditionOutcome::Unsatisfied
        } else {
            ConditionOutcome::Satisfied
        };
    }

    // Every remaining condition reads an attribute of an element that has to
    // exist, so a missing one answers all of them the same way: the action did
    // not do what it claimed. UNSATISFIED rather than indeterminate, because the
    // element being gone is a definite observation rather than a failure to
    // observe.
    if !observed.present {
        return ConditionOutcome::Unsatisfied;
    }

    match condition {
        PostCondition::ElementPresent { .. } => ConditionOutcome::Satisfied,
        PostCondition::ElementAbsent { .. } => ConditionOutcome::Unsatisfied,
        PostCondition::ElementFocused { .. } => match observed.focused {
            Some(true) => ConditionOutcome::Satisfied,
            Some(false) => ConditionOutcome::Unsatisfied,
            None => ConditionOutcome::Indeterminate,
        },
        PostCondition::ElementEnabledIs { expected, .. } => match observed.enabled {
            Some(actual) if actual == *expected => ConditionOutcome::Satisfied,
            Some(_) => ConditionOutcome::Unsatisfied,
            None => ConditionOutcome::Indeterminate,
        },
        PostCondition::ElementValueEquals { expected, .. } => match &observed.value {
            Some(actual) if actual == expected => ConditionOutcome::Satisfied,
            Some(_) => ConditionOutcome::Unsatisfied,
            None => ConditionOutcome::Indeterminate,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(
        focused: Option<bool>,
        enabled: Option<bool>,
        value: Option<&str>,
    ) -> ObservedElement {
        ObservedElement {
            present: true,
            focused,
            enabled,
            value: value.map(str::to_string),
        }
    }

    /// An attribute the application does not expose is indeterminate, not failed.
    ///
    /// The distinction this type exists for. An action that worked against a
    /// quiet application would otherwise be reported as having failed, and a
    /// caller acting on that would retry something that already happened --
    /// which for anything that mutates is worse than not checking at all.
    #[test]
    fn an_unreported_attribute_is_indeterminate_rather_than_unsatisfied() {
        let condition = PostCondition::ElementFocused {
            element: AccessibilityElementName::identifier("field-1"),
        };
        assert_eq!(
            evaluate(&condition, &observed(None, None, None)),
            ConditionOutcome::Indeterminate
        );
        assert_eq!(
            evaluate(&condition, &observed(Some(false), None, None)),
            ConditionOutcome::Unsatisfied
        );
        assert_eq!(
            evaluate(&condition, &observed(Some(true), None, None)),
            ConditionOutcome::Satisfied
        );
    }

    /// A value condition compares exactly.
    ///
    /// Containment would also match a field that held the expected text plus
    /// whatever was already there, which is a different outcome from the one
    /// the action claimed.
    #[test]
    fn a_value_condition_is_not_satisfied_by_a_superstring() {
        let condition = PostCondition::ElementValueEquals {
            element: AccessibilityElementName::identifier("field-1"),
            expected: "hello".to_string(),
        };
        assert_eq!(
            evaluate(&condition, &observed(None, None, Some("hello"))),
            ConditionOutcome::Satisfied
        );
        assert_eq!(
            evaluate(&condition, &observed(None, None, Some("hello there"))),
            ConditionOutcome::Unsatisfied
        );
        assert_eq!(
            evaluate(&condition, &observed(None, None, Some(""))),
            ConditionOutcome::Unsatisfied
        );
    }

    /// A missing element satisfies an absence condition and fails every other.
    ///
    /// Both directions asserted, because the absence case inverts the meaning
    /// of a failed read: for every other condition a missing element means the
    /// action did not work, and for this one it means it did.
    #[test]
    fn absence_satisfies_only_the_condition_that_expects_it() {
        let gone = ObservedElement::absent();

        assert_eq!(
            evaluate(
                &PostCondition::ElementAbsent {
                    element: AccessibilityElementName::identifier("dialog-1"),
                },
                &gone
            ),
            ConditionOutcome::Satisfied
        );
        assert_eq!(
            evaluate(
                &PostCondition::ElementFocused {
                    element: AccessibilityElementName::identifier("dialog-1"),
                },
                &gone
            ),
            ConditionOutcome::Unsatisfied
        );
        assert_eq!(
            evaluate(
                &PostCondition::ElementPresent {
                    element: AccessibilityElementName::identifier("dialog-1"),
                },
                &gone
            ),
            ConditionOutcome::Unsatisfied
        );
    }

    /// An element that is present fails an absence condition.
    #[test]
    fn a_present_element_fails_an_absence_condition() {
        assert_eq!(
            evaluate(
                &PostCondition::ElementAbsent {
                    element: AccessibilityElementName::identifier("dialog-1"),
                },
                &observed(None, None, None)
            ),
            ConditionOutcome::Unsatisfied
        );
    }

    /// An enabled condition tells both states apart from an element that does
    /// not report one.
    #[test]
    fn an_enabled_condition_reads_both_directions() {
        let expect_disabled = PostCondition::ElementEnabledIs {
            element: AccessibilityElementName::identifier("save"),
            expected: false,
        };
        assert_eq!(
            evaluate(&expect_disabled, &observed(None, Some(false), None)),
            ConditionOutcome::Satisfied
        );
        assert_eq!(
            evaluate(&expect_disabled, &observed(None, Some(true), None)),
            ConditionOutcome::Unsatisfied
        );
        assert_eq!(
            evaluate(&expect_disabled, &observed(None, None, None)),
            ConditionOutcome::Indeterminate
        );
    }

    /// Every condition names its element with the dispatch key type.
    ///
    /// This is the type-level sharing assertion: a predicate cannot introduce a
    /// second identifier-only target dialect while every variant stores
    /// `AccessibilityElementName`. Written out per variant so adding one without
    /// the shared key fails here.
    #[test]
    fn every_condition_uses_the_dispatch_accessibility_key_type() {
        let conditions = [
            PostCondition::ElementFocused {
                element: AccessibilityElementName::identifier("a"),
            },
            PostCondition::ElementValueEquals {
                element: AccessibilityElementName::identifier("b"),
                expected: String::new(),
            },
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("c"),
                expected: true,
            },
            PostCondition::ElementAbsent {
                element: AccessibilityElementName::identifier("d"),
            },
            PostCondition::ElementPresent {
                element: AccessibilityElementName::identifier("e"),
            },
        ];
        let named: Vec<&AccessibilityElementName> =
            conditions.iter().map(PostCondition::element).collect();
        let expected = ["a", "b", "c", "d", "e"].map(AccessibilityElementName::identifier);
        assert_eq!(named, expected.iter().collect::<Vec<_>>());
    }

    /// A condition survives being written out and read back.
    ///
    /// It is recorded before the action is delivered and read again afterwards
    /// to check it, so a representation that dropped a field would compare the
    /// action against a weaker claim than the one it made.
    #[test]
    fn a_condition_survives_serialization() {
        let condition = PostCondition::ElementValueEquals {
            element: AccessibilityElementName::role_and_title("AXTextField", "Account"),
            expected: "typed text".to_string(),
        };
        let bytes = serde_json::to_vec(&condition).expect("serializes");
        let restored: PostCondition = serde_json::from_slice(&bytes).expect("round trips");
        assert_eq!(restored, condition);
    }
}
