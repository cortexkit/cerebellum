//! Translation of neutral synthetic actions into CoreGraphics event steps.
//!
//! This module is the ONLY place the computer plane's platform-neutral
//! `SyntheticAction` meets `cerebellum-macos` event construction. The neutral
//! side decides what the action means and in what order events post; this side
//! only names the framework keycode and unit for each neutral name, and zips
//! the constructed events with the neutral plan's roles.

use super::synthetic::{
    SyntheticAction, SyntheticKey, SyntheticKeyModifiers, SyntheticPoint, SyntheticScrollAxis,
    SyntheticScrollUnit,
};
use super::{DriverError, SyntheticStep};
use cerebellum_macos::{EventPoint, KeyModifiers, OwnedCgEvent, ScrollUnit, VirtualKey};

/// Map a neutral key name onto the macOS virtual keycode for it.
///
/// Total on purpose: there is no fallback arm, so a name added to the neutral
/// vocabulary stops the build here rather than silently pressing whichever key
/// a catch-all happened to map to.
fn macos_virtual_key(key: SyntheticKey) -> VirtualKey {
    match key {
        SyntheticKey::A => VirtualKey::A,
        SyntheticKey::S => VirtualKey::S,
        SyntheticKey::D => VirtualKey::D,
        SyntheticKey::F => VirtualKey::F,
        SyntheticKey::H => VirtualKey::H,
        SyntheticKey::G => VirtualKey::G,
        SyntheticKey::Z => VirtualKey::Z,
        SyntheticKey::X => VirtualKey::X,
        SyntheticKey::C => VirtualKey::C,
        SyntheticKey::V => VirtualKey::V,
        SyntheticKey::Section => VirtualKey::Section,
        SyntheticKey::B => VirtualKey::B,
        SyntheticKey::Q => VirtualKey::Q,
        SyntheticKey::W => VirtualKey::W,
        SyntheticKey::E => VirtualKey::E,
        SyntheticKey::R => VirtualKey::R,
        SyntheticKey::Y => VirtualKey::Y,
        SyntheticKey::T => VirtualKey::T,
        SyntheticKey::Digit1 => VirtualKey::Digit1,
        SyntheticKey::Digit2 => VirtualKey::Digit2,
        SyntheticKey::Digit3 => VirtualKey::Digit3,
        SyntheticKey::Digit4 => VirtualKey::Digit4,
        SyntheticKey::Digit5 => VirtualKey::Digit5,
        SyntheticKey::Digit6 => VirtualKey::Digit6,
        SyntheticKey::Digit7 => VirtualKey::Digit7,
        SyntheticKey::Digit8 => VirtualKey::Digit8,
        SyntheticKey::Digit9 => VirtualKey::Digit9,
        SyntheticKey::Digit0 => VirtualKey::Digit0,
        SyntheticKey::Equal => VirtualKey::Equal,
        SyntheticKey::Minus => VirtualKey::Minus,
        SyntheticKey::RightBracket => VirtualKey::RightBracket,
        SyntheticKey::O => VirtualKey::O,
        SyntheticKey::U => VirtualKey::U,
        SyntheticKey::LeftBracket => VirtualKey::LeftBracket,
        SyntheticKey::I => VirtualKey::I,
        SyntheticKey::P => VirtualKey::P,
        SyntheticKey::Return => VirtualKey::Return,
        SyntheticKey::L => VirtualKey::L,
        SyntheticKey::J => VirtualKey::J,
        SyntheticKey::Quote => VirtualKey::Quote,
        SyntheticKey::K => VirtualKey::K,
        SyntheticKey::Semicolon => VirtualKey::Semicolon,
        SyntheticKey::Backslash => VirtualKey::Backslash,
        SyntheticKey::Comma => VirtualKey::Comma,
        SyntheticKey::Slash => VirtualKey::Slash,
        SyntheticKey::N => VirtualKey::N,
        SyntheticKey::M => VirtualKey::M,
        SyntheticKey::Period => VirtualKey::Period,
        SyntheticKey::Tab => VirtualKey::Tab,
        SyntheticKey::Space => VirtualKey::Space,
        SyntheticKey::Grave => VirtualKey::Grave,
        SyntheticKey::Backspace => VirtualKey::Backspace,
        SyntheticKey::Escape => VirtualKey::Escape,
        SyntheticKey::F1 => VirtualKey::F1,
        SyntheticKey::F2 => VirtualKey::F2,
        SyntheticKey::F3 => VirtualKey::F3,
        SyntheticKey::F4 => VirtualKey::F4,
        SyntheticKey::F5 => VirtualKey::F5,
        SyntheticKey::F6 => VirtualKey::F6,
        SyntheticKey::F7 => VirtualKey::F7,
        SyntheticKey::F8 => VirtualKey::F8,
        SyntheticKey::F9 => VirtualKey::F9,
        SyntheticKey::F10 => VirtualKey::F10,
        SyntheticKey::F11 => VirtualKey::F11,
        SyntheticKey::F12 => VirtualKey::F12,
        SyntheticKey::F13 => VirtualKey::F13,
        SyntheticKey::F14 => VirtualKey::F14,
        SyntheticKey::F15 => VirtualKey::F15,
        SyntheticKey::F16 => VirtualKey::F16,
        SyntheticKey::F17 => VirtualKey::F17,
        SyntheticKey::F18 => VirtualKey::F18,
        SyntheticKey::F19 => VirtualKey::F19,
        SyntheticKey::F20 => VirtualKey::F20,
        SyntheticKey::KeypadDecimal => VirtualKey::KeypadDecimal,
        SyntheticKey::KeypadMultiply => VirtualKey::KeypadMultiply,
        SyntheticKey::KeypadPlus => VirtualKey::KeypadPlus,
        SyntheticKey::KeypadClear => VirtualKey::KeypadClear,
        SyntheticKey::KeypadDivide => VirtualKey::KeypadDivide,
        SyntheticKey::KeypadEnter => VirtualKey::KeypadEnter,
        SyntheticKey::KeypadMinus => VirtualKey::KeypadMinus,
        SyntheticKey::KeypadEqual => VirtualKey::KeypadEqual,
        SyntheticKey::Keypad0 => VirtualKey::Keypad0,
        SyntheticKey::Keypad1 => VirtualKey::Keypad1,
        SyntheticKey::Keypad2 => VirtualKey::Keypad2,
        SyntheticKey::Keypad3 => VirtualKey::Keypad3,
        SyntheticKey::Keypad4 => VirtualKey::Keypad4,
        SyntheticKey::Keypad5 => VirtualKey::Keypad5,
        SyntheticKey::Keypad6 => VirtualKey::Keypad6,
        SyntheticKey::Keypad7 => VirtualKey::Keypad7,
        SyntheticKey::Keypad8 => VirtualKey::Keypad8,
        SyntheticKey::Keypad9 => VirtualKey::Keypad9,
        SyntheticKey::Help => VirtualKey::Help,
        SyntheticKey::Home => VirtualKey::Home,
        SyntheticKey::PageUp => VirtualKey::PageUp,
        SyntheticKey::ForwardDelete => VirtualKey::ForwardDelete,
        SyntheticKey::End => VirtualKey::End,
        SyntheticKey::PageDown => VirtualKey::PageDown,
        SyntheticKey::LeftArrow => VirtualKey::LeftArrow,
        SyntheticKey::RightArrow => VirtualKey::RightArrow,
        SyntheticKey::DownArrow => VirtualKey::DownArrow,
        SyntheticKey::UpArrow => VirtualKey::UpArrow,
    }
}

fn macos_modifiers(modifiers: SyntheticKeyModifiers) -> KeyModifiers {
    KeyModifiers {
        command: modifiers.command,
        shift: modifiers.shift,
        option: modifiers.option,
        control: modifiers.control,
    }
}

fn macos_point(point: SyntheticPoint) -> EventPoint {
    EventPoint {
        x: point.x,
        y: point.y,
    }
}

/// Map a construction failure onto a named driver error.
///
/// Every `InputEventConstructionError` is handled explicitly rather than
/// through a catch-all, so a variant added later stops the build here. The
/// reason is static text because `DriverError` is platform-neutral and cannot
/// name the framework error type.
fn map_event_construction_error(
    error: cerebellum_macos::InputEventConstructionError,
) -> DriverError {
    use cerebellum_macos::InputEventConstructionError as Construction;
    let reason: &'static str = match error {
        Construction::EventSourceUnavailable => "CoreGraphics could not create an event source",
        Construction::TextKeyDownUnavailable { .. } => {
            "CoreGraphics could not create a text key-down event"
        }
        Construction::TextKeyUpUnavailable { .. } => {
            "CoreGraphics could not create a text key-up event"
        }
        Construction::KeyCombinationDownUnavailable => {
            "CoreGraphics could not create the combination key-down event"
        }
        Construction::KeyCombinationUpUnavailable => {
            "CoreGraphics could not create the combination key-up event"
        }
        Construction::ScrollUnavailable => "CoreGraphics could not create the scroll event",
        Construction::ClickPressUnavailable => {
            "CoreGraphics could not create the click press event"
        }
        Construction::ClickReleaseUnavailable => {
            "CoreGraphics could not create the click release event"
        }
        Construction::MouseMoveUnavailable => "CoreGraphics could not create the mouse-move event",
        Construction::HeartbeatMarkerUnavailable => {
            "CoreGraphics could not create the observer heartbeat marker"
        }
        Construction::DragPressUnavailable => "CoreGraphics could not create the drag press event",
        Construction::DragMoveUnavailable => "CoreGraphics could not create the drag move event",
        Construction::DragReleaseUnavailable => {
            "CoreGraphics could not create the drag release event"
        }
    };
    DriverError::EventConstructionFailed(reason)
}

/// Translate a neutral action into the events the platform will be asked to
/// post, zipped with the roles the neutral plan assigns them.
///
/// The roles come from `SyntheticAction::step_roles`, not from a second
/// expansion decided here, so the posting order a test reads on any host is
/// the order these events follow on a Mac. A length mismatch would mean the
/// constructors and the plan disagree about the same action, which is a
/// defect to stop on rather than to reconcile.
pub fn synthetic_event_steps(
    action: &SyntheticAction,
) -> Result<Vec<SyntheticStep<OwnedCgEvent>>, DriverError> {
    if matches!(
        action,
        SyntheticAction::KeyCombination {
            modifiers: SyntheticKeyModifiers { windows: true, .. },
            ..
        }
    ) {
        return Err(DriverError::InvalidRequest(
            "Windows modifier is unsupported on macOS",
        ));
    }
    let roles = action.step_roles();
    let events: Vec<OwnedCgEvent> = match action {
        SyntheticAction::TypeText { text } => {
            cerebellum_macos::text_input_events(text).map_err(map_event_construction_error)?
        }
        SyntheticAction::KeyCombination { key, modifiers } => {
            let [down, up] = cerebellum_macos::key_combination_events(
                macos_virtual_key(*key),
                macos_modifiers(*modifiers),
            )
            .map_err(map_event_construction_error)?;
            vec![down, up]
        }
        SyntheticAction::Scroll { unit, delta, axis } => {
            let unit = match unit {
                SyntheticScrollUnit::Line => ScrollUnit::Line,
                SyntheticScrollUnit::Pixel => ScrollUnit::Pixel,
            };
            let event = match axis {
                SyntheticScrollAxis::Vertical => cerebellum_macos::scroll_wheel_event(unit, *delta),
                SyntheticScrollAxis::Horizontal => {
                    cerebellum_macos::horizontal_scroll_wheel_event(unit, *delta)
                }
            };
            vec![event.map_err(map_event_construction_error)?]
        }
        SyntheticAction::MovePointer { point } => {
            vec![cerebellum_macos::mouse_move_event(macos_point(*point))
                .map_err(map_event_construction_error)?]
        }
        SyntheticAction::ClickPointer { point } => {
            cerebellum_macos::mouse_click_events(macos_point(*point))
                .map_err(map_event_construction_error)?
                .into_iter()
                .collect()
        }
        SyntheticAction::DragPointer { from, to } => {
            let [press, drag, release] =
                cerebellum_macos::mouse_drag_events(macos_point(*from), macos_point(*to))
                    .map_err(map_event_construction_error)?;
            vec![press, drag, release]
        }
    };
    assert_eq!(
        roles.len(),
        events.len(),
        "the event constructors and the neutral plan disagree about this action"
    );
    Ok(roles
        .into_iter()
        .zip(events)
        .map(|(role, event)| SyntheticStep { role, event })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_modifier_is_refused_before_macos_event_construction() {
        let action = SyntheticAction::key_combination(
            SyntheticKey::L,
            SyntheticKeyModifiers {
                windows: true,
                ..SyntheticKeyModifiers::NONE
            },
        );

        assert!(matches!(
            synthetic_event_steps(&action),
            Err(DriverError::InvalidRequest(
                "Windows modifier is unsupported on macOS"
            ))
        ));
    }
}
