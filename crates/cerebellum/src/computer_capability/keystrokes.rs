//! What the keystroke rows check and report around a dispatch: the secure
//! field check before anything is posted, what a background target needs,
//! how a fronting bracket's result reads on the wire, and whether typed text
//! can be shown to have arrived.

use cerebellum_computer::app_state::source::{AppStateSource, ElementHandle};
use cerebellum_computer::dispatch::{BracketReport, DispatchError, RestoreStatus};
use cerebellum_computer::platform::ProcessGrant;
use serde_json::{json, Value};

/// The target's focused element as it was before anything was posted, kept
/// so typed text can be looked for in what changed.
pub(crate) struct TargetFocus {
    pub handle: ElementHandle,
    pub before: Option<String>,
}

/// Why keystrokes were refused before anything was posted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FocusRefusal {
    /// The focused element is a secure text field.
    Secure,
    /// The target's focus could not be read, so a secure field could not be
    /// ruled out.
    Unreadable,
}

impl FocusRefusal {
    pub(crate) fn reply(self) -> Value {
        match self {
            Self::Secure => json!({
                "outcome": "secure_field_refused",
                "reason": "secure_field_focused",
                "remedy": "the application's focused element is a secure text field; nothing was \
                           posted. Ask the person to type it themselves",
            }),
            Self::Unreadable => json!({
                "outcome": "secure_field_refused",
                "reason": "focus_unreadable",
                "remedy": "the application's focused element could not be read, so a secure \
                           field could not be ruled out; nothing was posted. Read the state and \
                           use write_text on a settable element instead",
            }),
        }
    }
}

/// Read the target application's own focused element and refuse a secure
/// one. `Ok(None)` when the application reports nothing focused: there is no
/// field to protect, and nothing to confirm typing against either.
pub(crate) fn read_target_focus(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
) -> Result<Option<TargetFocus>, FocusRefusal> {
    let Some(handle) = source
        .focused_element(grant)
        .map_err(|_| FocusRefusal::Unreadable)?
    else {
        return Ok(None);
    };
    let facts = source
        .element_facts(&handle)
        .map_err(|_| FocusRefusal::Unreadable)?;
    if facts.is_secure() {
        return Err(FocusRefusal::Secure);
    }
    let before = source.text_value(&handle).ok().flatten();
    Ok(Some(TargetFocus { handle, before }))
}

/// The refusal for a background target in a build whose fronting bracket is
/// not admitted. The remedy names only what this build can do.
pub(crate) fn needs_foreground_reply() -> Value {
    json!({
        "outcome": "keystrokes_need_foreground",
        "remedy": "the application is not frontmost, and keystrokes posted to an application in \
                   the background are dropped by some applications, so nothing was posted. Read \
                   its state and use write_text on a settable element, or ask the person to \
                   bring the application to the front and retry",
    })
}

/// What a bracket that ran to the end says about fronting: whether the
/// target was brought forward and the previous application put back inside
/// the bound, and when not, which condition failed.
pub(crate) fn bracket_fronting(
    bracket: &BracketReport,
    bound_ms: u64,
) -> (bool, Option<&'static str>) {
    if bracket.held(bound_ms) {
        return (true, None);
    }
    let reason = if bracket.longest_fronted_interval_ms > bound_ms {
        "fronting_bound_exceeded"
    } else {
        "fronting_unavailable"
    };
    (false, Some(reason))
}

/// A dispatch refusal on the wire, with a remedy for the fronting ones.
pub(crate) fn dispatch_refusal_reply(refusal: &DispatchError) -> Value {
    let mut reply = super::synthetic_dispatch_refusal(refusal);
    let remedy = match refusal {
        DispatchError::FrontingFailed => Some(
            "the application did not come to the front in time, so nothing more was posted; \
             use write_text on a settable element, or retry",
        ),
        DispatchError::FrontingBoundExceeded => Some(
            "the keystrokes could not be posted inside the time the application may stay in \
             front; use write_text on a settable element, or send shorter text",
        ),
        DispatchError::FrontingRestoreFailed => {
            Some("the previous application could not be brought back, so nothing more was posted")
        }
        _ => None,
    };
    if let Some(remedy) = remedy {
        reply["remedy"] = json!(remedy);
    }
    reply
}

/// Replace the reply with `restore_failed` when a bracket could not put the
/// previous application back, naming what it left in front. The person's
/// next keystrokes go to that application, so this outranks every other
/// outcome, delivered or not.
pub(crate) fn disclose_failed_restore(
    reply: &mut Value,
    bracket: &BracketReport,
    target: &ProcessGrant,
) {
    let RestoreStatus::Failed { left_in_front } = bracket.restore else {
        return;
    };
    let left = match left_in_front {
        Some(pid) if pid == target.pid => {
            reply["bundle_identity"] = json!(target.bundle_identity);
            format!("{} (pid {pid})", target.bundle_identity)
        }
        Some(pid) => format!("the application with pid {pid}"),
        None => "an application that could not be identified".to_string(),
    };
    let previous = bracket.previous_frontmost.map_or_else(
        || "the previous application".to_string(),
        |pid| format!("pid {pid}"),
    );
    reply["outcome"] = json!("restore_failed");
    reply["posts_returned"] = json!(bracket.posts_returned);
    reply["target_fronted"] = json!(false);
    reply["containment_forfeited_because"] = json!("fronting_unavailable");
    reply["remedy"] = json!(format!(
        "{left} was left in front and {previous} could not be brought back; tell the person \
         before anything else, since their keystrokes now go to {left}"
    ));
}

/// Whether this call's typed text shows in the focused element: its value
/// changed from the one read before posting, and the text is inside the part
/// that changed. A field that already held the text, and did not change,
/// proves nothing.
pub(crate) fn typed_text_arrived(
    source: &dyn AppStateSource,
    focus: &TargetFocus,
    text: &str,
) -> bool {
    let Some(before) = focus.before.as_deref() else {
        return false;
    };
    let Ok(Some(after)) = source.text_value(&focus.handle) else {
        return false;
    };
    changed_part(before, &after).is_some_and(|inserted| inserted.contains(text))
}

/// The part of `after` that is not shared with `before` at either end, or
/// `None` when the two are equal.
pub(crate) fn changed_part<'a>(before: &str, after: &'a str) -> Option<&'a str> {
    if before == after {
        return None;
    }
    let prefix = before
        .char_indices()
        .zip(after.chars())
        .find(|((_, left), right)| left != right)
        .map_or_else(|| before.len().min(after.len()), |((index, _), _)| index);
    // Ensure the prefix ends on a boundary of `after` as well; it does,
    // because the shared prefix is the same characters in both.
    let before_rest = &before[prefix..];
    let after_rest = &after[prefix..];
    let suffix = before_rest
        .chars()
        .rev()
        .zip(after_rest.chars().rev())
        .take_while(|(left, right)| left == right)
        .map(|(_, right)| right.len_utf8())
        .sum::<usize>();
    Some(&after_rest[..after_rest.len() - suffix])
}

#[cfg(test)]
mod tests {
    use super::changed_part;

    #[test]
    fn the_changed_part_is_what_was_inserted() {
        assert_eq!(changed_part("abc", "abXYc"), Some("XY"));
        assert_eq!(
            changed_part("hello hello", "hello hellohello"),
            Some("hello")
        );
        assert_eq!(changed_part("", "hi"), Some("hi"));
        assert_eq!(changed_part("same", "same"), None);
        assert_eq!(changed_part("héllo", "héXllo"), Some("X"));
    }
}
