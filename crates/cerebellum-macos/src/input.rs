//! CoreGraphics input-event construction without targeting or delivery.

use std::fmt;

/// Modifier flags carried by one key combination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyModifiers {
    pub command: bool,
    pub shift: bool,
    pub option: bool,
    pub control: bool,
}

impl KeyModifiers {
    pub const NONE: Self = Self {
        command: false,
        shift: false,
        option: false,
        control: false,
    };
}

/// macOS virtual keycodes for the non-modifier key in a combination.
///
/// These are the stable virtual codes from `<HIToolbox/Events.h>`. They name
/// physical keys for shortcuts; text does not use this table because text must
/// follow the Unicode path regardless of the active keyboard layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum VirtualKey {
    A = 0x00,
    S = 0x01,
    D = 0x02,
    F = 0x03,
    H = 0x04,
    G = 0x05,
    Z = 0x06,
    X = 0x07,
    C = 0x08,
    V = 0x09,
    Section = 0x0a,
    B = 0x0b,
    Q = 0x0c,
    W = 0x0d,
    E = 0x0e,
    R = 0x0f,
    Y = 0x10,
    T = 0x11,
    Digit1 = 0x12,
    Digit2 = 0x13,
    Digit3 = 0x14,
    Digit4 = 0x15,
    Digit6 = 0x16,
    Digit5 = 0x17,
    Equal = 0x18,
    Digit9 = 0x19,
    Digit7 = 0x1a,
    Minus = 0x1b,
    Digit8 = 0x1c,
    Digit0 = 0x1d,
    RightBracket = 0x1e,
    O = 0x1f,
    U = 0x20,
    LeftBracket = 0x21,
    I = 0x22,
    P = 0x23,
    Return = 0x24,
    L = 0x25,
    J = 0x26,
    Quote = 0x27,
    K = 0x28,
    Semicolon = 0x29,
    Backslash = 0x2a,
    Comma = 0x2b,
    Slash = 0x2c,
    N = 0x2d,
    M = 0x2e,
    Period = 0x2f,
    Tab = 0x30,
    Space = 0x31,
    Grave = 0x32,
    Backspace = 0x33,
    Escape = 0x35,
    F17 = 0x40,
    KeypadDecimal = 0x41,
    KeypadMultiply = 0x43,
    KeypadPlus = 0x45,
    KeypadClear = 0x47,
    KeypadDivide = 0x4b,
    KeypadEnter = 0x4c,
    KeypadMinus = 0x4e,
    F18 = 0x4f,
    F19 = 0x50,
    KeypadEqual = 0x51,
    Keypad0 = 0x52,
    Keypad1 = 0x53,
    Keypad2 = 0x54,
    Keypad3 = 0x55,
    Keypad4 = 0x56,
    Keypad5 = 0x57,
    Keypad6 = 0x58,
    Keypad7 = 0x59,
    F20 = 0x5a,
    Keypad8 = 0x5b,
    Keypad9 = 0x5c,
    F5 = 0x60,
    F6 = 0x61,
    F7 = 0x62,
    F3 = 0x63,
    F8 = 0x64,
    F9 = 0x65,
    F11 = 0x67,
    F13 = 0x69,
    F16 = 0x6a,
    F14 = 0x6b,
    F10 = 0x6d,
    F12 = 0x6f,
    F15 = 0x71,
    Help = 0x72,
    Home = 0x73,
    PageUp = 0x74,
    ForwardDelete = 0x75,
    F4 = 0x76,
    End = 0x77,
    F2 = 0x78,
    PageDown = 0x79,
    F1 = 0x7a,
    LeftArrow = 0x7b,
    RightArrow = 0x7c,
    DownArrow = 0x7d,
    UpArrow = 0x7e,
}

impl VirtualKey {
    pub const fn key_code(self) -> u16 {
        self as u16
    }
}

/// The unit CoreGraphics uses to interpret a scroll-wheel delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollUnit {
    Line,
    Pixel,
}

/// A point in macOS global display coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EventPoint {
    pub x: f64,
    pub y: f64,
}

/// Which CoreGraphics event-source state table a seconds-since-input reading
/// is taken from.
///
/// The tables are not interchangeable. Synthetic events in this crate are
/// created from HID system state, so a reading from that table may be reset by
/// our own posts while combined session state is not, or the reverse. The seam
/// reports the number from the table the caller named; it does not pick one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSourceStateTable {
    /// `kCGEventSourceStateHIDSystemState`.
    HidSystem,
    /// `kCGEventSourceStateCombinedSessionState`.
    CombinedSession,
}

impl EventSourceStateTable {
    /// The integer CoreGraphics uses for this table (`CGEventSourceStateID`).
    pub const fn raw_id(self) -> i32 {
        match self {
            Self::CombinedSession => 0,
            Self::HidSystem => 1,
        }
    }
}

/// What macOS says about this process's Input Monitoring grant.
///
/// Three states rather than a bool, because "not yet decided" is a real
/// answer distinct from a refusal: an undetermined grant becomes granted the
/// moment a user approves a prompt, while a denial stands until they change
/// it in System Settings. Collapsing them would tell an operator to go
/// change a setting that does not yet have a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMonitoringAccess {
    Granted,
    Denied,
    Undetermined,
    /// IOKit answered with a value this build does not recognise. Carried
    /// rather than folded into Denied so an OS change is visible as itself.
    Unrecognised(u32),
}

/// The exact CoreGraphics allocation that failed while building input events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputEventConstructionError {
    EventSourceUnavailable,
    TextKeyDownUnavailable { character_index: usize },
    TextKeyUpUnavailable { character_index: usize },
    KeyCombinationDownUnavailable,
    KeyCombinationUpUnavailable,
    ScrollUnavailable,
    MouseMoveUnavailable,
    HeartbeatMarkerUnavailable,
    DragPressUnavailable,
    DragMoveUnavailable,
    DragReleaseUnavailable,
}

impl fmt::Display for InputEventConstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventSourceUnavailable => write!(f, "CoreGraphics could not create an event source"),
            Self::TextKeyDownUnavailable { character_index } => write!(
                f,
                "CoreGraphics could not create the text key-down event at character {character_index}"
            ),
            Self::TextKeyUpUnavailable { character_index } => write!(
                f,
                "CoreGraphics could not create the text key-up event at character {character_index}"
            ),
            Self::KeyCombinationDownUnavailable => {
                write!(f, "CoreGraphics could not create the combination key-down event")
            }
            Self::KeyCombinationUpUnavailable => {
                write!(f, "CoreGraphics could not create the combination key-up event")
            }
            Self::ScrollUnavailable => {
                write!(f, "CoreGraphics could not create the scroll event")
            }
            Self::MouseMoveUnavailable => {
                write!(f, "CoreGraphics could not create the mouse-move event")
            }
            Self::HeartbeatMarkerUnavailable => {
                write!(f, "CoreGraphics could not create the observer heartbeat marker")
            }
            Self::DragPressUnavailable => {
                write!(f, "CoreGraphics could not create the drag press event")
            }
            Self::DragMoveUnavailable => {
                write!(f, "CoreGraphics could not create the drag move event")
            }
            Self::DragReleaseUnavailable => {
                write!(f, "CoreGraphics could not create the drag release event")
            }
        }
    }
}

impl std::error::Error for InputEventConstructionError {}

#[cfg(target_os = "macos")]
mod framework {
    use objc2_core_foundation::{CFRetained, CGPoint};

    // The Input Monitoring TCC service, read through IOKit's non-prompting
    // query. There is no objc2 binding for it, so it is declared here in the
    // one crate permitted to hold unsafe rather than reaching for it from a
    // caller that forbids it.
    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOHIDCheckAccess(request: u32) -> u32;
    }

    /// Read the Input Monitoring grant without prompting.
    ///
    /// `kIOHIDRequestTypeListenEvent` (1) is the listening grant, which is what
    /// System Settings calls Input Monitoring. This does NOT request access:
    /// `IOHIDRequestAccess` is the prompting call and is deliberately not used,
    /// matching how the accessibility probe avoids its prompting variant.
    pub fn input_monitoring_access() -> InputMonitoringAccess {
        const LISTEN_EVENT: u32 = 1;
        hid_access(LISTEN_EVENT)
    }

    /// Read the event-posting grant without prompting.
    ///
    /// `kIOHIDRequestTypePostEvent` (0) is the posting side of the same TCC
    /// pair. Read separately from the listening grant because the frozen
    /// vocabulary names them as separate requirements: `computer.takeover_move` needs
    /// only monitoring, while typing needs posting too, and one reading
    /// substituted for the other would answer a question nobody asked.
    pub fn event_post_access() -> InputMonitoringAccess {
        const POST_EVENT: u32 = 0;
        hid_access(POST_EVENT)
    }

    fn hid_access(request: u32) -> InputMonitoringAccess {
        // SAFETY: takes an integer request kind, returns an integer status, and
        // presents no prompt. It performs no input action.
        match unsafe { IOHIDCheckAccess(request) } {
            0 => InputMonitoringAccess::Granted,
            1 => InputMonitoringAccess::Denied,
            2 => InputMonitoringAccess::Undetermined,
            other => InputMonitoringAccess::Unrecognised(other),
        }
    }
    use objc2_core_graphics::{
        CGEvent, CGEventField, CGEventFlags, CGEventSource, CGEventSourceStateID, CGEventType,
        CGMouseButton, CGScrollEventUnit,
    };

    use super::{
        EventPoint, EventSourceStateTable, InputEventConstructionError, InputMonitoringAccess,
        KeyModifiers, ScrollUnit, VirtualKey,
    };
    use crate::OwnedCgEvent;

    fn event_source() -> Result<CFRetained<CGEventSource>, InputEventConstructionError> {
        CGEventSource::new(CGEventSourceStateID::HIDSystemState)
            .ok_or(InputEventConstructionError::EventSourceUnavailable)
    }

    /// A mouse-move built from a PRIVATE event source, for measurement only.
    ///
    /// Production events come from `HIDSystemState`, and a measured consequence
    /// is that posting one resets the hardware idle table -- the machine reads
    /// "just touched" because we touched it. Whether a private-state source
    /// leaves that table alone is the question this exists to let a probe ask.
    /// It is not a second construction path for dispatch: nothing in the
    /// computer crate calls it, and the thin-seam tests keep it that way.
    pub fn mouse_move_event_from_private_source(
        point: EventPoint,
    ) -> Result<OwnedCgEvent, InputEventConstructionError> {
        let source = CGEventSource::new(CGEventSourceStateID::Private)
            .ok_or(InputEventConstructionError::EventSourceUnavailable)?;
        let event = CGEvent::new_mouse_event(
            Some(&source),
            CGEventType::MouseMoved,
            CGPoint::new(point.x, point.y),
            CGMouseButton::Left,
        )
        .ok_or(InputEventConstructionError::MouseMoveUnavailable)?;
        CGEvent::set_flags(Some(&event), CGEventFlags::empty());
        Ok(event)
    }

    /// Build a no-displacement mouse event carrying an observer nonce.
    ///
    /// The marker enters at the session tap through the production post function.
    /// It uses the current pointer location so the liveness probe cannot move the
    /// cursor before the observer has proved it can see input.
    pub fn heartbeat_marker_event(nonce: u64) -> Result<OwnedCgEvent, InputEventConstructionError> {
        let source = event_source()?;
        let current = CGEvent::new(Some(&source))
            .ok_or(InputEventConstructionError::HeartbeatMarkerUnavailable)?;
        let marker = CGEvent::new_mouse_event(
            Some(&source),
            CGEventType::MouseMoved,
            CGEvent::location(Some(&current)),
            CGMouseButton::Left,
        )
        .ok_or(InputEventConstructionError::HeartbeatMarkerUnavailable)?;
        CGEvent::set_flags(Some(&marker), CGEventFlags::empty());
        CGEvent::set_integer_value_field(
            Some(&marker),
            CGEventField::EventSourceUserData,
            nonce as i64,
        );
        Ok(marker)
    }

    /// Seconds since any input event in `table`, as CoreGraphics reports it.
    ///
    /// Uses `kCGAnyInputEventType`. The objc2 binding skips that constant; the
    /// header defines it as `(CGEventType)(~0)`.
    pub fn seconds_since_last_input(table: EventSourceStateTable) -> f64 {
        const ANY_INPUT_EVENT_TYPE: CGEventType = CGEventType(u32::MAX);
        CGEventSource::seconds_since_last_event_type(
            CGEventSourceStateID(table.raw_id()),
            ANY_INPUT_EVENT_TYPE,
        )
    }

    fn modifier_flags(modifiers: KeyModifiers) -> CGEventFlags {
        let mut flags = CGEventFlags::empty();
        if modifiers.command {
            flags.insert(CGEventFlags::MaskCommand);
        }
        if modifiers.shift {
            flags.insert(CGEventFlags::MaskShift);
        }
        if modifiers.option {
            flags.insert(CGEventFlags::MaskAlternate);
        }
        if modifiers.control {
            flags.insert(CGEventFlags::MaskControl);
        }
        flags
    }

    fn keyboard_event(
        source: &CGEventSource,
        key_code: u16,
        key_down: bool,
        flags: CGEventFlags,
        failure: InputEventConstructionError,
    ) -> Result<OwnedCgEvent, InputEventConstructionError> {
        let event = CGEvent::new_keyboard_event(Some(source), key_code, key_down).ok_or(failure)?;
        // Every keyboard event receives its complete flag set. CoreGraphics may
        // initialize an HID-state source from physical modifier state, so merely
        // omitting flags would not mean "no modifiers" and could turn later
        // plain input into a shortcut.
        CGEvent::set_flags(Some(&event), flags);
        Ok(event)
    }

    /// Build one key-down/key-up pair for each Unicode scalar in `text`.
    ///
    /// The events contain UTF-16 through `CGEventKeyboardSetUnicodeString`, so
    /// their meaning does not depend on a keyboard layout or an ASCII key table.
    /// They carry no target or focus operation and can be passed directly to the
    /// crate's per-process delivery primitive.
    pub fn text_input_events(text: &str) -> Result<Vec<OwnedCgEvent>, InputEventConstructionError> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        let source = event_source()?;
        let mut events = Vec::with_capacity(text.chars().count().saturating_mul(2));
        for (character_index, character) in text.chars().enumerate() {
            let mut utf16 = [0_u16; 2];
            let utf16 = character.encode_utf16(&mut utf16);
            let down = keyboard_event(
                &source,
                0,
                true,
                CGEventFlags::empty(),
                InputEventConstructionError::TextKeyDownUnavailable { character_index },
            )?;
            let up = keyboard_event(
                &source,
                0,
                false,
                CGEventFlags::empty(),
                InputEventConstructionError::TextKeyUpUnavailable { character_index },
            )?;

            // SAFETY: `utf16` points to one encoded Rust `char` (one or two u16
            // values) and remains alive for both calls. Each call copies exactly
            // that reported number of values before returning.
            unsafe {
                CGEvent::keyboard_set_unicode_string(Some(&down), utf16.len() as _, utf16.as_ptr());
                CGEvent::keyboard_set_unicode_string(Some(&up), utf16.len() as _, utf16.as_ptr());
            }
            events.extend([down, up]);
        }
        Ok(events)
    }

    /// Build a key-down/key-up pair carrying one macOS virtual keycode.
    ///
    /// `key` carries a hardware-independent macOS virtual keycode, not a Unicode
    /// value. Text uses [`text_input_events`] instead so it remains layout
    /// independent.
    pub fn key_combination_events(
        key: VirtualKey,
        modifiers: KeyModifiers,
    ) -> Result<[OwnedCgEvent; 2], InputEventConstructionError> {
        let source = event_source()?;
        let flags = modifier_flags(modifiers);
        let down = keyboard_event(
            &source,
            key.key_code(),
            true,
            flags,
            InputEventConstructionError::KeyCombinationDownUnavailable,
        )?;
        let up = keyboard_event(
            &source,
            key.key_code(),
            false,
            flags,
            InputEventConstructionError::KeyCombinationUpUnavailable,
        )?;
        Ok([down, up])
    }

    /// Build one vertical scroll-wheel event.
    pub fn scroll_wheel_event(
        unit: ScrollUnit,
        delta: i32,
    ) -> Result<OwnedCgEvent, InputEventConstructionError> {
        let source = event_source()?;
        let unit = match unit {
            ScrollUnit::Line => CGScrollEventUnit::Line,
            ScrollUnit::Pixel => CGScrollEventUnit::Pixel,
        };
        let event = CGEvent::new_scroll_wheel_event2(Some(&source), unit, 1, delta, 0, 0)
            .ok_or(InputEventConstructionError::ScrollUnavailable)?;
        CGEvent::set_flags(Some(&event), CGEventFlags::empty());
        Ok(event)
    }

    /// Build one horizontal scroll-wheel event.
    ///
    /// A two-wheel event whose first (vertical) wheel is still and whose
    /// second carries the delta: CoreGraphics numbers the horizontal wheel
    /// second. The delta's sign follows the same convention as the vertical
    /// event's.
    pub fn horizontal_scroll_wheel_event(
        unit: ScrollUnit,
        delta: i32,
    ) -> Result<OwnedCgEvent, InputEventConstructionError> {
        let source = event_source()?;
        let unit = match unit {
            ScrollUnit::Line => CGScrollEventUnit::Line,
            ScrollUnit::Pixel => CGScrollEventUnit::Pixel,
        };
        let event = CGEvent::new_scroll_wheel_event2(Some(&source), unit, 2, 0, delta, 0)
            .ok_or(InputEventConstructionError::ScrollUnavailable)?;
        CGEvent::set_flags(Some(&event), CGEventFlags::empty());
        Ok(event)
    }

    /// Build one mouse-move event at `point` without posting it.
    pub fn mouse_move_event(
        point: EventPoint,
    ) -> Result<OwnedCgEvent, InputEventConstructionError> {
        let source = event_source()?;
        let event = CGEvent::new_mouse_event(
            Some(&source),
            CGEventType::MouseMoved,
            CGPoint::new(point.x, point.y),
            CGMouseButton::Left,
        )
        .ok_or(InputEventConstructionError::MouseMoveUnavailable)?;
        CGEvent::set_flags(Some(&event), CGEventFlags::empty());
        Ok(event)
    }

    /// Build left-button press, drag, and release events without posting them.
    pub fn mouse_drag_events(
        from: EventPoint,
        to: EventPoint,
    ) -> Result<[OwnedCgEvent; 3], InputEventConstructionError> {
        let source = event_source()?;
        let press = CGEvent::new_mouse_event(
            Some(&source),
            CGEventType::LeftMouseDown,
            CGPoint::new(from.x, from.y),
            CGMouseButton::Left,
        )
        .ok_or(InputEventConstructionError::DragPressUnavailable)?;
        let drag = CGEvent::new_mouse_event(
            Some(&source),
            CGEventType::LeftMouseDragged,
            CGPoint::new(to.x, to.y),
            CGMouseButton::Left,
        )
        .ok_or(InputEventConstructionError::DragMoveUnavailable)?;
        let release = CGEvent::new_mouse_event(
            Some(&source),
            CGEventType::LeftMouseUp,
            CGPoint::new(to.x, to.y),
            CGMouseButton::Left,
        )
        .ok_or(InputEventConstructionError::DragReleaseUnavailable)?;
        for event in [&press, &drag, &release] {
            CGEvent::set_flags(Some(event), CGEventFlags::empty());
        }
        Ok([press, drag, release])
    }
}

#[cfg(target_os = "macos")]
pub use framework::{
    event_post_access, heartbeat_marker_event, horizontal_scroll_wheel_event,
    input_monitoring_access, key_combination_events, mouse_drag_events, mouse_move_event,
    mouse_move_event_from_private_source, scroll_wheel_event, seconds_since_last_input,
    text_input_events,
};

#[cfg(test)]
mod platform_neutral_tests {
    use std::collections::HashSet;

    use super::{EventSourceStateTable, InputEventConstructionError, VirtualKey};

    #[test]
    fn virtual_keys_carry_the_macos_hardware_codes() {
        assert_eq!(VirtualKey::A.key_code(), 0x00);
        assert_eq!(VirtualKey::Q.key_code(), 0x0c);
        assert_eq!(VirtualKey::K.key_code(), 0x28);
        assert_eq!(VirtualKey::Backspace.key_code(), 0x33);
        assert_eq!(VirtualKey::Escape.key_code(), 0x35);
    }

    #[test]
    fn every_framework_construction_failure_has_a_distinct_typed_cause() {
        let failures = [
            InputEventConstructionError::EventSourceUnavailable,
            InputEventConstructionError::TextKeyDownUnavailable { character_index: 2 },
            InputEventConstructionError::TextKeyUpUnavailable { character_index: 2 },
            InputEventConstructionError::KeyCombinationDownUnavailable,
            InputEventConstructionError::KeyCombinationUpUnavailable,
            InputEventConstructionError::ScrollUnavailable,
            InputEventConstructionError::MouseMoveUnavailable,
            InputEventConstructionError::HeartbeatMarkerUnavailable,
            InputEventConstructionError::DragPressUnavailable,
            InputEventConstructionError::DragMoveUnavailable,
            InputEventConstructionError::DragReleaseUnavailable,
        ];

        assert_eq!(HashSet::from(failures).len(), failures.len());
    }

    #[test]
    fn hid_system_and_combined_session_are_distinct_tables() {
        assert_ne!(
            EventSourceStateTable::HidSystem,
            EventSourceStateTable::CombinedSession
        );
        // The integers CoreGraphics uses: CombinedSessionState = 0, HIDSystemState = 1.
        assert_eq!(EventSourceStateTable::CombinedSession.raw_id(), 0);
        assert_eq!(EventSourceStateTable::HidSystem.raw_id(), 1);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod framework_tests {
    use objc2_core_graphics::{CGEvent, CGEventField, CGEventFlags, CGEventType};

    use super::{
        key_combination_events, mouse_drag_events, mouse_move_event, scroll_wheel_event,
        text_input_events, EventPoint, KeyModifiers, ScrollUnit, VirtualKey,
    };

    fn unicode_string(event: &CGEvent) -> String {
        let mut length = 0;
        // SAFETY: `length` is a valid output pointer, and CoreGraphics permits a
        // null string buffer when the maximum length is zero.
        unsafe {
            CGEvent::keyboard_get_unicode_string(Some(event), 0, &mut length, std::ptr::null_mut());
        }
        let mut utf16 = vec![0_u16; length as usize];
        // SAFETY: the vector holds exactly `length` writable u16 values and both
        // pointers remain valid until the call returns.
        unsafe {
            CGEvent::keyboard_get_unicode_string(
                Some(event),
                length,
                &mut length,
                utf16.as_mut_ptr(),
            );
        }
        utf16.truncate(length as usize);
        String::from_utf16(&utf16).expect("the constructor stored valid UTF-16")
    }

    fn assert_point(event: &CGEvent, expected: EventPoint) {
        let actual = CGEvent::location(Some(event));
        assert_eq!((actual.x, actual.y), (expected.x, expected.y));
    }

    #[test]
    fn text_events_round_trip_unicode_types_and_plain_flags() {
        let events = text_input_events("a—é").expect("construct text events");
        assert_eq!(events.len(), 6);

        for (pair, expected) in events.as_chunks::<2>().0.iter().zip(["a", "—", "é"]) {
            assert_eq!(CGEvent::r#type(Some(&pair[0])), CGEventType::KeyDown);
            assert_eq!(CGEvent::r#type(Some(&pair[1])), CGEventType::KeyUp);
            assert_eq!(unicode_string(&pair[0]), expected);
            assert_eq!(unicode_string(&pair[1]), expected);
            assert_eq!(CGEvent::flags(Some(&pair[0])), CGEventFlags::empty());
            assert_eq!(CGEvent::flags(Some(&pair[1])), CGEventFlags::empty());
        }
    }

    #[test]
    fn key_combination_events_carry_the_keycode_type_and_exact_modifiers() {
        let events = key_combination_events(
            VirtualKey::K,
            KeyModifiers {
                command: true,
                shift: true,
                option: true,
                control: true,
            },
        )
        .expect("construct key combination");
        let expected_flags = CGEventFlags::MaskCommand
            | CGEventFlags::MaskShift
            | CGEventFlags::MaskAlternate
            | CGEventFlags::MaskControl;

        assert_eq!(CGEvent::r#type(Some(&events[0])), CGEventType::KeyDown);
        assert_eq!(CGEvent::r#type(Some(&events[1])), CGEventType::KeyUp);
        for event in &events {
            assert_eq!(
                CGEvent::integer_value_field(Some(event), CGEventField::KeyboardEventKeycode),
                i64::from(VirtualKey::K.key_code())
            );
            assert_eq!(CGEvent::flags(Some(event)), expected_flags);
        }
    }

    #[test]
    fn a_command_modifier_is_absent_from_the_next_plain_combination() {
        let command = key_combination_events(
            VirtualKey::C,
            KeyModifiers {
                command: true,
                ..KeyModifiers::NONE
            },
        )
        .expect("construct command combination");
        assert!(CGEvent::flags(Some(&command[0])).contains(CGEventFlags::MaskCommand));

        let plain = key_combination_events(VirtualKey::A, KeyModifiers::NONE)
            .expect("construct following plain combination");
        for event in &plain {
            assert_eq!(CGEvent::flags(Some(event)), CGEventFlags::empty());
        }
    }

    #[test]
    fn scroll_events_carry_type_unit_and_delta() {
        for (unit, delta, delta_field, continuous) in [
            (
                ScrollUnit::Line,
                -7,
                CGEventField::ScrollWheelEventDeltaAxis1,
                0,
            ),
            (
                ScrollUnit::Pixel,
                19,
                CGEventField::ScrollWheelEventPointDeltaAxis1,
                1,
            ),
        ] {
            let event = scroll_wheel_event(unit, delta).expect("construct scroll event");
            assert_eq!(CGEvent::r#type(Some(&event)), CGEventType::ScrollWheel);
            assert_eq!(
                CGEvent::integer_value_field(Some(&event), delta_field),
                i64::from(delta)
            );
            assert_eq!(
                CGEvent::integer_value_field(
                    Some(&event),
                    CGEventField::ScrollWheelEventIsContinuous,
                ),
                continuous
            );
            assert_eq!(CGEvent::flags(Some(&event)), CGEventFlags::empty());
        }
    }

    /// The horizontal event puts its delta on the second wheel and leaves the
    /// vertical one still, so it scrolls sideways and never up or down.
    #[test]
    fn horizontal_scroll_moves_only_the_second_wheel() {
        let event = super::horizontal_scroll_wheel_event(ScrollUnit::Line, -4)
            .expect("construct horizontal scroll event");
        assert_eq!(CGEvent::r#type(Some(&event)), CGEventType::ScrollWheel);
        assert_eq!(
            CGEvent::integer_value_field(Some(&event), CGEventField::ScrollWheelEventDeltaAxis2),
            -4
        );
        assert_eq!(
            CGEvent::integer_value_field(Some(&event), CGEventField::ScrollWheelEventDeltaAxis1),
            0
        );
        assert_eq!(CGEvent::flags(Some(&event)), CGEventFlags::empty());
    }

    #[test]
    fn mouse_move_carries_its_type_point_and_plain_flags() {
        let point = EventPoint {
            x: 123.5,
            y: 456.25,
        };
        let event = mouse_move_event(point).expect("construct mouse move");

        assert_eq!(CGEvent::r#type(Some(&event)), CGEventType::MouseMoved);
        assert_point(&event, point);
        assert_eq!(CGEvent::flags(Some(&event)), CGEventFlags::empty());
    }

    #[test]
    fn drag_carries_press_move_release_types_points_and_plain_flags() {
        let from = EventPoint { x: 10.0, y: 20.0 };
        let to = EventPoint { x: 90.0, y: 120.0 };
        let events = mouse_drag_events(from, to).expect("construct drag events");

        assert_eq!(
            CGEvent::r#type(Some(&events[0])),
            CGEventType::LeftMouseDown
        );
        assert_eq!(
            CGEvent::r#type(Some(&events[1])),
            CGEventType::LeftMouseDragged
        );
        assert_eq!(CGEvent::r#type(Some(&events[2])), CGEventType::LeftMouseUp);
        assert_point(&events[0], from);
        assert_point(&events[1], to);
        assert_point(&events[2], to);
        for event in &events {
            assert_eq!(CGEvent::flags(Some(event)), CGEventFlags::empty());
        }
    }
}
