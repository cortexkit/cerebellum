//! Platform-neutral description of one synthetic input action.
//!
//! A [`SyntheticAction`] says WHAT to type, press, scroll, or point at without
//! naming any platform event type. The macOS driver translates it into
//! CoreGraphics events at the boundary; this module never sees one. The
//! translation order is fixed here as a role plan, so the decision of which
//! event presses, moves, or releases is tested on every host rather than only
//! where the framework exists.

use super::process_event::SyntheticStepRole;
use serde::{Deserialize, Serialize};

/// Modifier flags carried by one key combination.
///
/// The names follow the keys a user presses rather than one platform's flag
/// constants; each driver maps them onto its own modifier bits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticKeyModifiers {
    pub command: bool,
    pub shift: bool,
    pub option: bool,
    pub control: bool,
    /// Windows key. It is rejected by the macOS wire decoder rather than
    /// silently translated into a different modifier.
    #[serde(default)]
    pub windows: bool,
}

impl SyntheticKeyModifiers {
    pub const NONE: Self = Self {
        command: false,
        shift: false,
        option: false,
        control: false,
        windows: false,
    };
}

/// The non-modifier key in a combination, named rather than numbered.
///
/// Names match the keys on a keyboard, not any platform's keycode table, so a
/// request means the same thing to every driver. Each platform driver maps the
/// name onto its own code; a name it cannot map is a request error, never a
/// guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyntheticKey {
    A,
    S,
    D,
    F,
    H,
    G,
    Z,
    X,
    C,
    V,
    Section,
    B,
    Q,
    W,
    E,
    R,
    Y,
    T,
    Digit1,
    Digit2,
    Digit3,
    Digit4,
    Digit5,
    Digit6,
    Digit7,
    Digit8,
    Digit9,
    Digit0,
    Equal,
    Minus,
    RightBracket,
    O,
    U,
    LeftBracket,
    I,
    P,
    Return,
    L,
    J,
    Quote,
    K,
    Semicolon,
    Backslash,
    Comma,
    Slash,
    N,
    M,
    Period,
    Tab,
    Space,
    Grave,
    Backspace,
    Escape,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    F13,
    F14,
    F15,
    F16,
    F17,
    F18,
    F19,
    F20,
    KeypadDecimal,
    KeypadMultiply,
    KeypadPlus,
    KeypadClear,
    KeypadDivide,
    KeypadEnter,
    KeypadMinus,
    KeypadEqual,
    Keypad0,
    Keypad1,
    Keypad2,
    Keypad3,
    Keypad4,
    Keypad5,
    Keypad6,
    Keypad7,
    Keypad8,
    Keypad9,
    Help,
    Home,
    PageUp,
    ForwardDelete,
    End,
    PageDown,
    LeftArrow,
    RightArrow,
    DownArrow,
    UpArrow,
}

/// The unit a scroll-wheel delta is expressed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticScrollUnit {
    Line,
    Pixel,
}

/// Which way a scroll-wheel event turns the content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticScrollAxis {
    /// Up and down, the wheel every mouse has. The default, so a recorded
    /// scroll from before the axis existed reads back as the vertical one it
    /// was.
    #[default]
    Vertical,
    /// Left and right.
    Horizontal,
}

/// A point in global display coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SyntheticPoint {
    pub x: f64,
    pub y: f64,
}

/// One synthetic input action, described without any platform event type.
///
/// `PartialEq` but not `Eq`: the pointer variants carry floating-point
/// coordinates, and pretending those have a total equality would be a lie the
/// type system would happily repeat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticAction {
    /// Type text as one key-down/key-up pair per Unicode scalar. Text goes
    /// through the Unicode path so it does not depend on a keyboard layout.
    TypeText { text: String },
    /// Press and release one key while holding the given modifiers.
    KeyCombination {
        key: SyntheticKey,
        modifiers: SyntheticKeyModifiers,
    },
    /// Turn the scroll wheel by `delta` units along `axis`.
    Scroll {
        unit: SyntheticScrollUnit,
        delta: i32,
        #[serde(default)]
        axis: SyntheticScrollAxis,
    },
    /// Move the pointer to a point without pressing any button.
    MovePointer { point: SyntheticPoint },
    /// Press and release the left button at a point, without dragging.
    ClickPointer { point: SyntheticPoint },
    /// Press the left button at `from`, drag to `to`, and release there.
    DragPointer {
        from: SyntheticPoint,
        to: SyntheticPoint,
    },
}

impl SyntheticAction {
    pub fn takeover_action(&self) -> Option<cerebellum_core::consent::TakeoverAction> {
        use cerebellum_core::consent::TakeoverAction;
        Some(match self {
            Self::MovePointer { .. } => TakeoverAction::Move,
            Self::ClickPointer { .. } => TakeoverAction::Click,
            Self::DragPointer { .. } => TakeoverAction::Drag,
            Self::Scroll { .. } => TakeoverAction::Scroll,
            Self::TypeText { .. } | Self::KeyCombination { .. } => return None,
        })
    }

    pub fn type_text(text: impl Into<String>) -> Self {
        Self::TypeText { text: text.into() }
    }

    pub fn key_combination(key: SyntheticKey, modifiers: SyntheticKeyModifiers) -> Self {
        Self::KeyCombination { key, modifiers }
    }

    /// A vertical scroll.
    pub fn scroll(unit: SyntheticScrollUnit, delta: i32) -> Self {
        Self::scroll_along(SyntheticScrollAxis::Vertical, unit, delta)
    }

    pub fn scroll_along(axis: SyntheticScrollAxis, unit: SyntheticScrollUnit, delta: i32) -> Self {
        Self::Scroll { unit, delta, axis }
    }

    pub fn move_pointer(point: SyntheticPoint) -> Self {
        Self::MovePointer { point }
    }

    pub fn drag_pointer(from: SyntheticPoint, to: SyntheticPoint) -> Self {
        Self::DragPointer { from, to }
    }

    /// Whether this action is addressed by coordinates rather than delivered
    /// to whatever has focus inside the target process.
    pub fn is_coordinate_addressed(&self) -> bool {
        matches!(
            self,
            Self::MovePointer { .. } | Self::DragPointer { .. } | Self::ClickPointer { .. }
        )
    }

    /// The role of every event this action expands into, in posting order.
    ///
    /// This is the one place the expansion is decided. The macOS driver zips
    /// the events it constructs with these roles, so the plan a test reads on
    /// any host is the plan the framework events follow on a Mac.
    pub fn step_roles(&self) -> Vec<SyntheticStepRole> {
        use SyntheticStepRole::{Press, Release, SelfContained};
        match self {
            Self::TypeText { text } => (0..text.chars().count())
                .flat_map(|_| [Press, Release])
                .collect(),
            Self::KeyCombination { .. } | Self::ClickPointer { .. } => vec![Press, Release],
            Self::Scroll { .. } | Self::MovePointer { .. } => vec![SelfContained],
            Self::DragPointer { .. } => vec![Press, SelfContained, Release],
        }
    }

    /// How many events the platform will be asked to post.
    ///
    /// Derived from the payload rather than stated by the caller, because a
    /// stated count can disagree with the events actually sent and nothing
    /// downstream could tell which one was true.
    pub fn planned_event_count(&self) -> usize {
        self.step_roles().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SyntheticStepRole::{Press, Release, SelfContained};

    fn point(x: f64, y: f64) -> SyntheticPoint {
        SyntheticPoint { x, y }
    }

    #[test]
    fn each_action_expands_to_the_events_its_meaning_requires() {
        let cases: [(SyntheticAction, Vec<SyntheticStepRole>, bool); 5] = [
            (
                SyntheticAction::type_text("aé—"),
                vec![Press, Release, Press, Release, Press, Release],
                false,
            ),
            (
                SyntheticAction::key_combination(SyntheticKey::K, SyntheticKeyModifiers::NONE),
                vec![Press, Release],
                false,
            ),
            (
                SyntheticAction::scroll(SyntheticScrollUnit::Line, -3),
                vec![SelfContained],
                false,
            ),
            (
                SyntheticAction::move_pointer(point(10.0, 20.0)),
                vec![SelfContained],
                true,
            ),
            (
                SyntheticAction::drag_pointer(point(1.0, 2.0), point(3.0, 4.0)),
                vec![Press, SelfContained, Release],
                true,
            ),
        ];

        for (action, roles, coordinate_addressed) in cases {
            assert_eq!(action.step_roles(), roles, "wrong plan for {action:?}");
            assert_eq!(action.planned_event_count(), roles.len());
            assert_eq!(action.is_coordinate_addressed(), coordinate_addressed);
        }
    }

    #[test]
    fn an_empty_text_plans_no_events_so_a_caller_cannot_claim_otherwise() {
        let action = SyntheticAction::type_text("");
        assert_eq!(action.planned_event_count(), 0);
        assert_eq!(action.step_roles(), Vec::new());
    }

    #[test]
    fn the_five_actions_are_distinguishable_by_their_plans() {
        let plans = [
            SyntheticAction::type_text("ab").step_roles(),
            SyntheticAction::key_combination(SyntheticKey::A, SyntheticKeyModifiers::NONE)
                .step_roles(),
            SyntheticAction::scroll(SyntheticScrollUnit::Pixel, 9).step_roles(),
            SyntheticAction::move_pointer(point(0.0, 0.0)).step_roles(),
            SyntheticAction::drag_pointer(point(0.0, 0.0), point(1.0, 1.0)).step_roles(),
        ];
        // Text of two characters and a drag both contain three or more events;
        // the combination, scroll, and move are told apart by role and count.
        assert_eq!(plans[0].len(), 4);
        assert_eq!(plans[1].len(), 2);
        assert_eq!(plans[2], vec![SelfContained]);
        assert_eq!(plans[3], vec![SelfContained]);
        assert_eq!(plans[4], vec![Press, SelfContained, Release]);
    }
}

#[cfg(test)]
mod click_tests {
    use super::*;

    #[test]
    fn a_click_has_only_a_paired_press_and_release() {
        let click = SyntheticAction::ClickPointer {
            point: SyntheticPoint { x: 12.0, y: 34.0 },
        };
        assert_eq!(
            click.step_roles(),
            [SyntheticStepRole::Press, SyntheticStepRole::Release]
        );
    }
}
