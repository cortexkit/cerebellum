//! Windows input planning, recipient checks, and the held-key release lane.

use super::{desktop_safe, now_ms, Binding, NativeObserver};
use crate::dispatch::{CutoffGate, UnitPosted};
use crate::platform::blocked_chord::{
    blocked_chord, windows_app_chord_supported, BlockedChordPlatform,
};
use crate::platform::process_event::{
    HeldStateDisposition, ProcessEventRefusal, SequencePostFailure,
};
use crate::platform::synthetic::{SyntheticAction, SyntheticKey, SyntheticKeyModifiers};
use crate::platform::windows::app_state::{input_focus, InputFocus, ReadError};
use cerebellum_windows::RawInputPost;
use std::time::{Duration, Instant};
use unicode_segmentation::UnicodeSegmentation;

// Provisional until posting and caret reads are measured inside the bracket.
// An unreviewed build must not advertise these rows.
pub(super) const WINDOWS_PIECE_MAX_UTF16: usize = 32;
pub(super) const WINDOWS_CARET_READ_MAX_UTF16: u32 = 4096;

pub(super) struct Piece {
    events: Vec<RawInputPost>,
    text: Option<TextLength>,
}

#[derive(Clone, Copy)]
struct TextLength {
    body: usize,
    newline: bool,
}

pub(super) struct Sequence {
    pieces: Vec<Piece>,
    focus: InputFocus,
    confirmed_caret: Option<usize>,
    newline_width: Option<usize>,
    pub(super) confirmed: usize,
    pub(super) unverified: usize,
    pub(super) uncertain: Option<usize>,
}

pub(super) fn failure(reason: &'static str) -> SequencePostFailure {
    SequencePostFailure {
        refusal: ProcessEventRefusal::WindowServerUnreadable {
            reason: reason.into(),
        },
        posts_returned: 0,
        held_state: HeldStateDisposition::NoneHeld,
    }
}

fn vk(key: u16, up: bool, extended: bool) -> RawInputPost {
    RawInputPost::VirtualKey { key, up, extended }
}

fn text_piece(text: &str) -> Piece {
    let newline = text.ends_with('\n');
    let body = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let mut events: Vec<_> = body
        .encode_utf16()
        .flat_map(|unit| {
            [
                RawInputPost::Unicode { unit, up: false },
                RawInputPost::Unicode { unit, up: true },
            ]
        })
        .collect();
    if newline {
        // Both EDIT and RichEdit insert their native line ending on Return.
        events.extend([vk(0x0D, false, false), vk(0x0D, true, false)]);
    }
    Piece {
        events,
        text: Some(TextLength {
            body: body.encode_utf16().count(),
            newline,
        }),
    }
}

fn split_text(text: &str) -> Result<Vec<Piece>, &'static str> {
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut units = 0;
    for (index, grapheme) in text.grapheme_indices(true) {
        let length = grapheme.encode_utf16().count();
        if length > WINDOWS_PIECE_MAX_UTF16 {
            return Err("grapheme_too_long");
        }
        if units + length > WINDOWS_PIECE_MAX_UTF16 {
            pieces.push(text_piece(&text[start..index]));
            start = index;
            units = 0;
        }
        units += length;
        if grapheme.ends_with('\n') {
            let end = index + grapheme.len();
            pieces.push(text_piece(&text[start..end]));
            start = end;
            units = 0;
        }
    }
    if start < text.len() {
        pieces.push(text_piece(&text[start..]));
    }
    if pieces.is_empty() {
        Err("input_empty")
    } else {
        Ok(pieces)
    }
}

fn key_code(key: SyntheticKey) -> Option<(u16, bool)> {
    use SyntheticKey::*;
    let ordinary = match key {
        A => 0x41,
        B => 0x42,
        C => 0x43,
        D => 0x44,
        E => 0x45,
        F => 0x46,
        G => 0x47,
        H => 0x48,
        I => 0x49,
        J => 0x4A,
        K => 0x4B,
        L => 0x4C,
        M => 0x4D,
        N => 0x4E,
        O => 0x4F,
        P => 0x50,
        Q => 0x51,
        R => 0x52,
        S => 0x53,
        T => 0x54,
        U => 0x55,
        V => 0x56,
        W => 0x57,
        X => 0x58,
        Y => 0x59,
        Z => 0x5A,
        Digit0 => 0x30,
        Digit1 => 0x31,
        Digit2 => 0x32,
        Digit3 => 0x33,
        Digit4 => 0x34,
        Digit5 => 0x35,
        Digit6 => 0x36,
        Digit7 => 0x37,
        Digit8 => 0x38,
        Digit9 => 0x39,
        F1 => 0x70,
        F2 => 0x71,
        F3 => 0x72,
        F4 => 0x73,
        F5 => 0x74,
        F6 => 0x75,
        F7 => 0x76,
        F8 => 0x77,
        F9 => 0x78,
        F10 => 0x79,
        F11 => 0x7A,
        F12 => 0x7B,
        F13 => 0x7C,
        F14 => 0x7D,
        F15 => 0x7E,
        F16 => 0x7F,
        F17 => 0x80,
        F18 => 0x81,
        F19 => 0x82,
        F20 => 0x83,
        Keypad0 => 0x60,
        Keypad1 => 0x61,
        Keypad2 => 0x62,
        Keypad3 => 0x63,
        Keypad4 => 0x64,
        Keypad5 => 0x65,
        Keypad6 => 0x66,
        Keypad7 => 0x67,
        Keypad8 => 0x68,
        Keypad9 => 0x69,
        KeypadMultiply => 0x6A,
        KeypadPlus => 0x6B,
        KeypadMinus => 0x6D,
        KeypadDecimal => 0x6E,
        Backspace => 0x08,
        Tab => 0x09,
        KeypadClear => 0x0C,
        Return => 0x0D,
        Escape => 0x1B,
        Space => 0x20,
        Help => 0x2F,
        KeypadDivide => return Some((0x6F, true)),
        KeypadEnter => return Some((0x0D, true)),
        PageUp => return Some((0x21, true)),
        PageDown => return Some((0x22, true)),
        End => return Some((0x23, true)),
        Home => return Some((0x24, true)),
        LeftArrow => return Some((0x25, true)),
        UpArrow => return Some((0x26, true)),
        RightArrow => return Some((0x27, true)),
        DownArrow => return Some((0x28, true)),
        ForwardDelete => return Some((0x2E, true)),
        // OEM keys vary with the layout. Do not guess which key was meant.
        Section | Equal | Minus | RightBracket | LeftBracket | Quote | Semicolon | Backslash
        | Comma | Slash | Period | Grave | KeypadEqual => return None,
    };
    Some((ordinary, false))
}

pub fn chord_supported(key: SyntheticKey, modifiers: SyntheticKeyModifiers) -> bool {
    blocked_chord(modifiers, key, BlockedChordPlatform::Windows).is_none()
        && windows_app_chord_supported(modifiers, key, false)
        && key_code(key).is_some()
}

fn chord_piece(
    key: SyntheticKey,
    mods: SyntheticKeyModifiers,
    desk: bool,
) -> Result<Piece, &'static str> {
    if !chord_supported(key, mods) || !windows_app_chord_supported(mods, key, desk) {
        return Err("key_unsupported");
    }
    let (key, extended) = key_code(key).ok_or("key_unsupported")?;
    let modifiers = [
        (mods.control, 0xA2),
        (mods.option, 0xA4),
        (mods.shift, 0xA0),
    ];
    let mut events: Vec<_> = modifiers
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, key)| vk(*key, false, false))
        .collect();
    events.extend([vk(key, false, extended), vk(key, true, extended)]);
    events.extend(
        modifiers
            .iter()
            .rev()
            .filter(|(on, _)| *on)
            .map(|(_, key)| vk(*key, true, false)),
    );
    Ok(Piece { events, text: None })
}

fn read_focus(target: &Binding, text: bool, end: Instant) -> Result<InputFocus, &'static str> {
    input_focus(
        target.pid(),
        target.target_start,
        target.number,
        target.proof.clone(),
        text.then_some(WINDOWS_CARET_READ_MAX_UTF16),
        end,
    )
    .map_err(|error| match error {
        ReadError::Unsupported => "secure_field_focused",
        ReadError::Bound => "caret_too_long",
        _ => "focus_unreadable",
    })
}

impl Sequence {
    pub(super) fn prepare(
        action: &SyntheticAction,
        target: &Binding,
        end: Instant,
    ) -> Result<Self, &'static str> {
        let (pieces, text) = match action {
            SyntheticAction::TypeText { text } => (split_text(text)?, true),
            SyntheticAction::KeyCombination { key, modifiers } => (
                vec![chord_piece(*key, *modifiers, target.is_shell_desktop())?],
                false,
            ),
            _ => return Err("input_unsupported"),
        };
        let focus = read_focus(target, text, end)?;
        if pieces.len() > 1 && focus.caret.is_none() {
            return Err("caret_unavailable");
        }
        Ok(Self {
            pieces,
            focus,
            confirmed_caret: None,
            newline_width: None,
            confirmed: 0,
            unverified: 0,
            uncertain: None,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.pieces.len()
    }

    fn read_same_focus(
        &self,
        target: &Binding,
        text: bool,
        end: Instant,
    ) -> Result<InputFocus, &'static str> {
        let focus = read_focus(target, text, end)?;
        if !self.focus.element.same_element(focus.element.as_ref()) {
            return Err("focus_changed");
        }
        Ok(focus)
    }
}

pub(super) fn query(target: &Binding, end: Instant) -> bool {
    target.is_foreground() && read_focus(target, false, end).is_ok() && target.is_foreground()
}

struct PostBound<'a> {
    end: Instant,
    deadline_ms: u64,
    cutoff: Option<&'a CutoffGate>,
    cancelled: &'a dyn Fn() -> bool,
}

fn recipient(target: &Binding) -> Result<(), &'static str> {
    if !desktop_safe() || !target.is_foreground() {
        return Err("foreground_changed");
    }
    if !target.safe_integrity() {
        return Err("target_elevated");
    }
    Ok(())
}

impl Sequence {
    pub(super) fn post(
        &mut self,
        index: usize,
        target: &Binding,
        observer: &NativeObserver,
        deadline_ms: u64,
        cutoff: Option<&CutoffGate>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<UnitPosted, SequencePostFailure> {
        let end = Instant::now() + Duration::from_millis(deadline_ms.saturating_sub(now_ms()));
        let end = cutoff
            .and_then(CutoffGate::reserve_start)
            .map_or(end, |reserve| reserve.min(end));
        self.deliver(
            index,
            target,
            observer,
            PostBound {
                end,
                deadline_ms,
                cutoff,
                cancelled,
            },
        )
    }

    fn deliver(
        &mut self,
        index: usize,
        target: &Binding,
        observer: &NativeObserver,
        bound: PostBound<'_>,
    ) -> Result<UnitPosted, SequencePostFailure> {
        use super::observer::MARKER;
        let piece = &self.pieces[index];
        recipient(target).map_err(failure)?;
        self.read_same_focus(target, false, bound.end)
            .map_err(failure)?;
        if observer.person() {
            return Err(failure("person_active"));
        }
        if observer.held() {
            return Err(failure("held_input_unconfirmed"));
        }
        if observer.lost() {
            return Err(failure("observer_lost"));
        }
        let start = if piece.text.is_some() {
            let focus = self
                .read_same_focus(target, true, bound.end)
                .map_err(failure)?;
            if index > 0 && focus.caret != self.confirmed_caret.map(|start| (start, 0)) {
                return Err(failure("caret_changed"));
            }
            if self.focus.caret.is_some() != focus.caret.is_some() {
                return Err(failure("caret_unavailable"));
            }
            focus.caret.map(|(start, _)| start)
        } else {
            None
        };
        let mut events = piece.events.clone();
        // Inserting the sentinel at the tail of the same SendInput call also
        // fences a focus/foreground change during routing of that batch.
        events.push(MARKER);
        let counts = observer.counts();
        recipient(target).map_err(failure)?;
        if observer.person() {
            return Err(failure("person_active"));
        }
        if (bound.cancelled)()
            || Instant::now() >= bound.end
            || bound.cutoff.is_some_and(|gate| !gate.begin_post(true))
        {
            return Err(SequencePostFailure {
                refusal: ProcessEventRefusal::Cancelled,
                ..failure("cancelled")
            });
        }
        observer.track_route(target.number);
        let sent = observer.post(&events);
        let payload = sent.min(piece.events.len());
        let mut held_state = HeldStateDisposition::NoneHeld;
        let mut fenced_posts = payload;
        let mut marker_posted = sent == events.len();
        if !marker_posted && recipient(target).is_ok() && now_ms() < bound.deadline_ms {
            let mut release = releases(&events[..payload]);
            let ups = release.len();
            release.push(MARKER);
            let cleanup = observer.post(&release);
            fenced_posts += cleanup.min(ups);
            marker_posted = cleanup == release.len();
            if ups != 0 {
                held_state = if cleanup >= ups {
                    HeldStateDisposition::Released {
                        posts_returned: ups as u64,
                    }
                } else {
                    HeldStateDisposition::Unknown
                };
            }
        } else if !marker_posted && !releases(&events[..payload]).is_empty() {
            held_state = HeldStateDisposition::Unknown;
        }
        let fenced = observer.fence(counts, fenced_posts, bound.deadline_ms) && marker_posted;
        if observer.automation_held()
            || (!fenced
                && (held_state != HeldStateDisposition::NoneHeld
                    || !releases(&events[..payload]).is_empty()))
        {
            held_state = HeldStateDisposition::Unknown;
        }
        let uncertain = |reason| SequencePostFailure {
            posts_returned: payload as u64,
            held_state,
            ..failure(reason)
        };
        let result = if !fenced {
            Err(uncertain("observer_lost"))
        } else if observer.person() {
            Err(uncertain("person_active"))
        } else if sent != events.len() || observer.route_changed() || recipient(target).is_err() {
            Err(uncertain("piece_uncertain"))
        } else {
            self.confirm_piece(target, observer, &bound, start, piece.text)
                .map_err(uncertain)
        };
        observer.stop_tracking_route();
        if result.is_err() && payload != 0 {
            self.uncertain = Some(index + 1);
        }
        result.map(|()| UnitPosted {
            posts_returned: payload as u64,
            generation_verifications: payload as u64,
        })
    }

    fn confirm_piece(
        &mut self,
        target: &Binding,
        observer: &NativeObserver,
        bound: &PostBound<'_>,
        start: Option<usize>,
        text: Option<TextLength>,
    ) -> Result<(), &'static str> {
        loop {
            if observer.person() {
                return Err("person_active");
            }
            if observer.route_changed() || (bound.cancelled)() || Instant::now() >= bound.end {
                return Err("piece_uncertain");
            }
            let track = start.zip(text);
            let focused = self
                .read_same_focus(target, track.is_some(), bound.end)
                .map_err(|_| "piece_uncertain")?;
            if observer.route_changed() || recipient(target).is_err() || Instant::now() >= bound.end
            {
                return Err("piece_uncertain");
            }
            if observer.person() {
                return Err("person_active");
            }
            let Some((start, text)) = track else {
                self.unverified += 1;
                return Ok(());
            };
            if let Some((cursor, 0)) = focused.caret {
                if let Some(width) = matches_advance(cursor, start, text, self.newline_width) {
                    if text.newline {
                        self.newline_width = Some(width);
                    }
                    self.confirmed_caret = Some(cursor);
                    self.confirmed += 1;
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn matches_advance(
    cursor: usize,
    start: usize,
    length: TextLength,
    newline_width: Option<usize>,
) -> Option<usize> {
    let width = cursor.checked_sub(start.checked_add(length.body)?)?;
    let matches = if length.newline {
        newline_width.map_or((1..=2).contains(&width), |known| known == width)
    } else {
        width == 0
    };
    matches.then_some(width)
}

/// Compute only the paired ups for the accepted prefix, in reverse order.
fn releases(prefix: &[RawInputPost]) -> Vec<RawInputPost> {
    let mut down = Vec::new();
    for event in prefix {
        match *event {
            RawInputPost::VirtualKey {
                key,
                up: false,
                extended,
            } => down.push(vk(key, true, extended)),
            RawInputPost::Unicode { unit, up: false } => {
                down.push(RawInputPost::Unicode { unit, up: true })
            }
            _ => {
                if down.last() == Some(event) {
                    down.pop();
                }
            }
        }
    }
    down.reverse();
    down
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grapheme_boundaries_keep_emoji_flags_and_combining_text_whole() {
        for (cluster, units) in [("👩‍💻", 5), ("🇳🇱", 4), ("e\u{301}", 2)] {
            let pieces = split_text(&format!("{}{cluster}z", "a".repeat(31))).unwrap();
            assert_eq!(pieces.len(), 2);
            assert_eq!(pieces[0].text.unwrap().body, 31);
            assert_eq!(pieces[1].text.unwrap().body, units + 1);
            assert_eq!(pieces[1].events.len(), (units + 1) * 2);
        }
    }

    #[test]
    fn overlong_grapheme_refuses_the_entire_text() {
        let text = format!("already a piece\nx{}", "\u{301}".repeat(32));
        assert_eq!(split_text(&text).err(), Some("grapheme_too_long"));
    }

    #[test]
    fn line_breaks_end_pieces_and_learn_cr_or_crlf() {
        let pieces = split_text("12\n34\r\n56").unwrap();
        assert_eq!(pieces.len(), 3);
        assert!(pieces[0].text.unwrap().newline && pieces[1].text.unwrap().newline);
        assert!(!pieces[2].text.unwrap().newline);
        for width in [1, 2] {
            let text = pieces[1].text.unwrap();
            assert_eq!(matches_advance(12 + width, 10, text, None), Some(width));
            assert_eq!(
                matches_advance(12 + width, 10, text, Some(width)),
                Some(width)
            );
            assert_eq!(matches_advance(15 - width, 10, text, Some(width)), None);
            assert_eq!(matches_advance(12, 10, text, None), None);
        }
    }

    #[test]
    fn a_short_chord_post_releases_only_its_still_down_prefix() {
        let chord = chord_piece(
            SyntheticKey::A,
            SyntheticKeyModifiers {
                control: true,
                shift: true,
                ..SyntheticKeyModifiers::NONE
            },
            false,
        )
        .unwrap();
        assert_eq!(
            releases(&chord.events[..3]),
            [
                vk(0x41, true, false),
                vk(0xA0, true, false),
                vk(0xA2, true, false),
            ]
        );
        assert_eq!(
            releases(&chord.events[..4]),
            [vk(0xA0, true, false), vk(0xA2, true, false)]
        );
        assert!(releases(&chord.events).is_empty());
    }
}
