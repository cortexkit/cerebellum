//! Ephemeral cursor pictures, not input events. No request body belongs here.

use serde::{Deserialize, Serialize};

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
pub fn label(kind: CursorKind, title: Option<&str>, secure: bool) -> Option<String> {
    if secure {
        return None;
    }
    let mut result = kind.verb().to_owned();
    if let Some(title) = title.filter(|title| !title.is_empty()) {
        result.push(' ');
        result.extend(title.chars().filter(|c| !c.is_control()));
    }
    Some(result.chars().take(24).collect())
}

/// Closed pipe vocabulary: there is no text, value, chord or request payload.
/// Unknown fields are refused rather than accidentally forwarding typed text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorEvent {
    pub agent: String,
    pub initial: char,
    pub to: [f64; 2],
    pub width: f64,
    pub label: Option<String>,
    pub kind: CursorKind,
}

impl CursorEvent {
    pub fn encode_line(&self) -> Option<Vec<u8>> {
        if !self.to.iter().all(|v| v.is_finite()) || !self.width.is_finite() {
            return None;
        }
        let mut line = serde_json::to_vec(self).ok()?;
        line.push(b'\n');
        (line.len() <= 4096).then_some(line)
    }
}

/// Fitts timing, using the cua cursor overlay's MIT reference formula with a
/// smaller ceiling. A zero-width or malformed target uses a one-point width.
pub fn duration_ms(distance: f64, width: f64, reduce_motion: bool) -> f64 {
    if reduce_motion {
        return 0.0;
    }
    let distance = if distance.is_finite() {
        distance.max(0.0)
    } else {
        0.0
    };
    let width = if width.is_finite() {
        width.max(1.0)
    } else {
        1.0
    };
    (150.0 + 120.0 * (distance / width + 1.0).log2()).clamp(250.0, 450.0)
}

/// Minimum jerk has zero velocity and acceleration at both ends.
pub fn position(from: [f64; 2], to: [f64; 2], fraction: f64, reduce_motion: bool) -> [f64; 2] {
    if reduce_motion || fraction >= 1.0 {
        return to;
    }
    if fraction <= 0.0 || !fraction.is_finite() {
        return from;
    }
    let t = fraction;
    let s = t * t * t * (10.0 + t * (-15.0 + 6.0 * t));
    [
        from[0] + (to[0] - from[0]) * s,
        from[1] + (to[1] - from[1]) * s,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glide_bounds_endpoints_and_reduce_motion() {
        for d in [0.0, 10.0, 100.0, 10000.0, f64::NAN] {
            assert!((250.0..=450.0).contains(&duration_ms(d, 24.0, false)));
        }
        assert_eq!(duration_ms(100.0, 10.0, false), 450.0);
        assert_eq!(duration_ms(0.0, 10.0, false), 250.0);
        let (a, b) = ([10.0, -20.0], [200.0, 400.0]);
        assert_eq!(position(a, b, 0.0, false), a);
        assert_eq!(position(a, b, 1.0, false), b);
        assert_eq!(position(a, b, 0.5, false), [105.0, 190.0]);
        assert_eq!(position(a, b, 0.0, true), b);
        assert_eq!(duration_ms(100.0, 2.0, true), 0.0);
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
            width: 20.0,
            label: label(CursorKind::Type, Some("Message"), false),
            kind: CursorKind::Type,
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
}
