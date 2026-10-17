//! Ephemeral cursor pictures, not input events. No request body belongs here.

use serde::{Deserialize, Serialize};

pub const AVATAR_SIZE: u32 = 32;
pub const MAX_CURSOR_LINE: usize = 24_576;

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
            && self.width.is_finite()
            && self
                .avatar_rgba
                .as_ref()
                .is_none_or(|rgba| rgba.len() == (AVATAR_SIZE * AVATAR_SIZE * 4) as usize)
            && (!self.avatar_update || self.avatar_rgba.is_some())
    }
}

/// Take one agent's picture off the screen now, rather than waiting for it to
/// fade after the agent stops acting. It names only the agent; there is nothing
/// else in it that could leak. `hide` is always true on the wire so the line is
/// self-describing, and the helper refuses a line with `hide: false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorHide {
    pub hide: bool,
    pub agent: String,
}

impl CursorHide {
    pub fn new(agent: impl Into<String>) -> Self {
        Self {
            hide: true,
            agent: agent.into(),
        }
    }
}

/// One line of the helper's stdin pipe: a picture to show or move, or one
/// agent's picture to hide. Untagged, so a picture line keeps exactly the shape
/// it had before hiding existed. Both shapes refuse unknown fields, and they
/// share no required field set, so a line decodes as at most one of them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CursorLine {
    Picture(CursorEvent),
    Hide(CursorHide),
}

impl CursorLine {
    pub fn encode_line(&self) -> Option<Vec<u8>> {
        match self {
            Self::Picture(event) => event.encode_line(),
            Self::Hide(hide) => {
                if !self.valid() {
                    return None;
                }
                let mut line = serde_json::to_vec(hide).ok()?;
                line.push(b'\n');
                (line.len() <= MAX_CURSOR_LINE).then_some(line)
            }
        }
    }

    pub fn valid(&self) -> bool {
        match self {
            Self::Picture(event) => event.valid(),
            Self::Hide(hide) => hide.hide,
        }
    }

    /// The picture this line carries, if it is not a hide.
    pub fn picture(self) -> Option<CursorEvent> {
        match self {
            Self::Picture(event) => Some(event),
            Self::Hide(_) => None,
        }
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
        // The helper decodes the wider line type; planted fields must not
        // slip through as a hide either.
        for field in ["text", "value", "keys", "request"] {
            value[field] = serde_json::json!("planted typed secret");
            assert!(serde_json::from_value::<CursorLine>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(
            serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
            CursorLine::Picture(event)
        );
    }

    #[test]
    fn hide_line_names_only_the_agent_and_refuses_extras() {
        let line = CursorLine::Hide(CursorHide::new("agent-a"));
        let encoded = line.encode_line().unwrap();
        assert_eq!(encoded, b"{\"hide\":true,\"agent\":\"agent-a\"}\n");
        assert_eq!(
            serde_json::from_slice::<CursorLine>(&encoded).unwrap(),
            line
        );
        for planted in [
            r#"{"hide":true,"agent":"a","text":"planted typed secret"}"#,
            r#"{"hide":true}"#,
        ] {
            assert!(serde_json::from_str::<CursorLine>(planted).is_err());
        }
        let refused: CursorLine = serde_json::from_str(r#"{"hide":false,"agent":"a"}"#).unwrap();
        assert!(!refused.valid());
        assert!(refused.encode_line().is_none());
    }

    #[test]
    fn cursor_pipe_bounds_pixels_and_rejects_malformed_updates() {
        let mut event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 2.0],
            width: 24.0,
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
    }
}
