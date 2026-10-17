//! Ephemeral cursor pictures, not input events. No request body belongs here.

use serde::{Deserialize, Serialize};

pub const AVATAR_SIZE: u32 = 32;
pub const MAX_CURSOR_LINE: usize = 24_576;
const MAX_LABEL_CHARS: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    Press,
    Write,
    Type,
    Keys,
    Reading,
}

impl CursorKind {
    fn verb(self) -> &'static str {
        match self {
            Self::Press => "Pressing",
            Self::Write | Self::Type => "Typing in",
            Self::Keys => "Keys in",
            Self::Reading => "Reading",
        }
    }
}

/// The only string derived from an element is its title, never its value.
/// Secure or unclassified elements must not supply a title to this function.
/// Reads carry no label at all: the picture only says where the agent is
/// looking, and a caption on every read would be noise over the app.
pub fn label(kind: CursorKind, title: Option<&str>, secure: bool) -> Option<String> {
    if secure || kind == CursorKind::Reading {
        return None;
    }
    let mut result = kind.verb().to_owned();
    if let Some(title) = title.filter(|title| !title.is_empty()) {
        result.push(' ');
        result.extend(title.chars().filter(|c| !c.is_control()));
    }
    // A cut title ends in an ellipsis so the pill never shows a word that
    // looks complete but is not ("Pressing 07 Prompt sur").
    if result.chars().count() > MAX_LABEL_CHARS {
        let mut cut: String = result.chars().take(MAX_LABEL_CHARS - 1).collect();
        cut.push('…');
        return Some(cut);
    }
    Some(result)
}

/// Closed pipe vocabulary: there is no text, value, chord or request payload.
/// Unknown fields are refused rather than accidentally forwarding typed text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorEvent {
    pub agent: String,
    pub initial: char,
    /// Where the arrow's tip goes, in global top-down screen points.
    pub to: [f64; 2],
    /// The acted-on element's frame (x, y, width, height), when one is known.
    /// The label pill is placed so it never covers this rectangle.
    pub target: Option<[f64; 4]>,
    /// `to` is only a place to appear (the window's content centre), not a
    /// target: a cursor that is already showing stays where it is.
    pub resting: bool,
    pub label: Option<String>,
    pub kind: CursorKind,
    pub serial: u64,
    pub avatar_rgba: Option<Vec<u8>>,
    pub avatar_update: bool,
}

impl CursorEvent {
    pub fn encode_line(&self) -> Option<Vec<u8>> {
        if !self.valid() {
            return None;
        }
        let mut line = serde_json::to_vec(self).ok()?;
        line.push(b'\n');
        (line.len() <= MAX_CURSOR_LINE).then_some(line)
    }

    pub fn valid(&self) -> bool {
        self.to.iter().all(|v| v.is_finite())
            && self
                .target
                .is_none_or(|frame| frame.iter().all(|v| v.is_finite()))
            && self
                .avatar_rgba
                .as_ref()
                .is_none_or(|rgba| rgba.len() == (AVATAR_SIZE * AVATAR_SIZE * 4) as usize)
            && (!self.avatar_update || self.avatar_rgba.is_some())
    }
}

/// Glide time grows with distance, from a quick 180 ms hop to a 450 ms
/// cross-screen move, so short moves feel snappy and long ones stay legible.
/// With Reduce Motion the picture does a short fade-move instead of gliding.
/// A zero or malformed distance needs no glide at all.
pub fn duration_ms(distance: f64, reduce_motion: bool) -> f64 {
    let distance = if distance.is_finite() {
        distance.max(0.0)
    } else {
        0.0
    };
    if distance < 0.5 {
        return 0.0;
    }
    if reduce_motion {
        return REDUCED_MOVE_MS;
    }
    (180.0 + distance * 0.25).min(450.0)
}

const REDUCED_MOVE_MS: f64 = 140.0;
const TAP_MS: f64 = 180.0;
const SETTLE_MS: f64 = 220.0;

/// The tip's position along a glide. Progress eases out (fast start, gentle
/// landing) and the path bows slightly to one side so the motion reads as a
/// hand moving, not a sliding rectangle. The bow is perpendicular to the
/// straight line, so progress toward the target never goes backwards, and both
/// endpoints are exact. With Reduce Motion there is no path: the picture stays
/// put while it fades out, then appears at the target (see `fade_alpha`).
pub fn position(from: [f64; 2], to: [f64; 2], fraction: f64, reduce_motion: bool) -> [f64; 2] {
    if fraction >= 1.0 {
        return to;
    }
    if fraction <= 0.0 || !fraction.is_finite() {
        return from;
    }
    if reduce_motion {
        return if fraction < 0.5 { from } else { to };
    }
    let s = 1.0 - (1.0 - fraction).powi(3);
    let (dx, dy) = (to[0] - from[0], to[1] - from[1]);
    let length = dx.hypot(dy);
    if length <= f64::EPSILON || !length.is_finite() {
        return to;
    }
    // Rotated so a rightward move bows upward on a top-down screen.
    let bow = (length * 0.1).min(32.0) * 4.0 * s * (1.0 - s) / length;
    [from[0] + dx * s + dy * bow, from[1] + dy * s - dx * bow]
}

/// The arrow's scale after it lands, applied about the tip so the tip stays on
/// the target. A press dips to 0.9 and back like a tap; anything else swells
/// 4% and back as a settle. Reduce Motion keeps the scale at exactly 1.
pub fn settle_scale(since_arrival_ms: f64, press: bool, reduce_motion: bool) -> f64 {
    if reduce_motion || !since_arrival_ms.is_finite() || since_arrival_ms < 0.0 {
        return 1.0;
    }
    let (length, depth) = if press {
        (TAP_MS, -0.1)
    } else {
        (SETTLE_MS, 0.04)
    };
    if since_arrival_ms >= length {
        return 1.0;
    }
    1.0 + depth * (since_arrival_ms / length * std::f64::consts::PI).sin()
}

/// Opacity during a move. Only the Reduce Motion fade-move changes it: fully
/// visible at both ends, invisible at the midpoint where `position` jumps.
pub fn fade_alpha(fraction: f64, reduce_motion: bool) -> f64 {
    if !reduce_motion || !fraction.is_finite() || !(0.0..1.0).contains(&fraction) {
        return 1.0;
    }
    (2.0 * fraction - 1.0).abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glide_time_grows_with_distance_within_its_bounds() {
        assert_eq!(duration_ms(0.0, false), 0.0);
        assert_eq!(duration_ms(f64::NAN, false), 0.0);
        assert_eq!(duration_ms(-50.0, false), 0.0);
        assert_eq!(duration_ms(4.0, false), 181.0);
        assert_eq!(duration_ms(400.0, false), 280.0);
        assert_eq!(duration_ms(10_000.0, false), 450.0);
        let mut last = 0.0;
        for d in [1.0, 10.0, 100.0, 500.0, 1000.0, 2000.0] {
            let ms = duration_ms(d, false);
            assert!((180.0..=450.0).contains(&ms), "{d} -> {ms}");
            assert!(ms >= last, "longer moves never get faster");
            last = ms;
        }
        // Reduce Motion: a short fade-move, the same for every distance.
        assert_eq!(duration_ms(10.0, true), REDUCED_MOVE_MS);
        assert_eq!(duration_ms(5000.0, true), REDUCED_MOVE_MS);
        assert_eq!(duration_ms(0.0, true), 0.0);
    }

    #[test]
    fn glide_endpoints_are_exact_and_progress_is_monotonic_along_a_slight_arc() {
        let (a, b) = ([10.0, -20.0], [410.0, 280.0]);
        assert_eq!(position(a, b, 0.0, false), a);
        assert_eq!(position(a, b, -1.0, false), a);
        assert_eq!(position(a, b, f64::NAN, false), a);
        assert_eq!(position(a, b, 1.0, false), b);
        assert_eq!(position(a, b, 1.5, false), b);
        let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
        let length = dx.hypot(dy);
        let mut last_progress = 0.0;
        let mut widest = 0.0_f64;
        for step in 1..100 {
            let p = position(a, b, f64::from(step) / 100.0, false);
            let progress = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (length * length);
            assert!(progress > last_progress, "step {step} went backwards");
            last_progress = progress;
            widest = widest.max(((p[0] - a[0]) * dy - (p[1] - a[1]) * dx).abs() / length);
        }
        // The curve is visible but gentle: at most a tenth of the distance and
        // never more than 32 points off the straight line.
        assert!(widest > 20.0 && widest <= 32.0, "bow {widest}");
        // Ease-out: more than half the way is covered in the first third.
        let third = position(a, b, 1.0 / 3.0, false);
        assert!(((third[0] - a[0]) * dx + (third[1] - a[1]) * dy) / (length * length) > 0.6);
    }

    #[test]
    fn reduce_motion_is_a_fade_move_with_no_arc_and_no_overshoot() {
        let (a, b) = ([10.0, -20.0], [410.0, 280.0]);
        for step in 0..50 {
            assert_eq!(position(a, b, f64::from(step) / 100.0, true), a);
        }
        for step in 50..=100 {
            assert_eq!(position(a, b, f64::from(step) / 100.0, true), b);
        }
        assert_eq!(fade_alpha(0.0, true), 1.0);
        assert_eq!(fade_alpha(0.25, true), 0.5);
        assert_eq!(fade_alpha(0.5, true), 0.0);
        assert_eq!(fade_alpha(1.0, true), 1.0);
        for step in 0..=100 {
            let t = f64::from(step) / 100.0;
            assert_eq!(fade_alpha(t, false), 1.0);
            assert_eq!(settle_scale(t * 300.0, true, true), 1.0);
            assert_eq!(settle_scale(t * 300.0, false, true), 1.0);
        }
    }

    #[test]
    fn settle_overshoots_four_percent_and_a_press_taps_down_to_nine_tenths() {
        assert_eq!(settle_scale(-1.0, false, false), 1.0);
        assert_eq!(settle_scale(0.0, false, false), 1.0);
        assert!((settle_scale(SETTLE_MS / 2.0, false, false) - 1.04).abs() < 1e-12);
        assert_eq!(settle_scale(SETTLE_MS, false, false), 1.0);
        assert!((settle_scale(TAP_MS / 2.0, true, false) - 0.9).abs() < 1e-12);
        assert_eq!(settle_scale(TAP_MS, true, false), 1.0);
        assert_eq!(settle_scale(f64::NAN, true, false), 1.0);
        for step in 0..=100 {
            let t = f64::from(step) * 3.0;
            assert!((1.0..=1.04 + 1e-12).contains(&settle_scale(t, false, false)));
            assert!((0.9 - 1e-12..=1.0).contains(&settle_scale(t, true, false)));
        }
    }

    #[test]
    fn cursor_labels_cut_characters_and_suppress_passwords() {
        assert_eq!(
            label(CursorKind::Press, Some("Send"), false).as_deref(),
            Some("Pressing Send")
        );
        assert_eq!(
            label(CursorKind::Type, Some(&"界".repeat(30)), false)
                .unwrap()
                .chars()
                .count(),
            24
        );
        assert_eq!(
            label(CursorKind::Write, Some("planted password label"), true),
            None
        );
    }

    #[test]
    fn pipe_vocabulary_cannot_carry_typed_text() {
        let event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 2.0],
            target: Some([0.0, 0.0, 20.0, 20.0]),
            resting: false,
            label: label(CursorKind::Type, Some("Message"), false),
            kind: CursorKind::Type,
            serial: 0,
            avatar_rgba: None,
            avatar_update: false,
        };
        let encoded = event.encode_line().unwrap();
        assert_eq!(encoded.iter().filter(|c| **c == b'\n').count(), 1);
        let mut value = serde_json::to_value(&event).unwrap();
        for field in ["text", "value", "keys", "request"] {
            value[field] = serde_json::json!("planted typed secret");
            assert!(serde_json::from_value::<CursorEvent>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(
            serde_json::from_slice::<CursorEvent>(&encoded).unwrap(),
            event
        );
    }

    #[test]
    fn cursor_pipe_bounds_pixels_and_rejects_malformed_updates() {
        let mut event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 2.0],
            target: None,
            resting: false,
            label: None,
            kind: CursorKind::Press,
            serial: 7,
            avatar_rgba: Some(vec![255; (AVATAR_SIZE * AVATAR_SIZE * 4) as usize]),
            avatar_update: true,
        };
        let line = event.encode_line().unwrap();
        assert!(line.len() <= MAX_CURSOR_LINE);
        assert_eq!(serde_json::from_slice::<CursorEvent>(&line).unwrap(), event);
        event.avatar_rgba.as_mut().unwrap().pop();
        assert!(event.encode_line().is_none());
        event.avatar_rgba = None;
        assert!(!event.valid());
        event.avatar_update = false;
        assert!(event.encode_line().is_some());
        event.target = Some([0.0, f64::NAN, 1.0, 1.0]);
        assert!(event.encode_line().is_none());
    }
}
