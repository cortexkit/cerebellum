//! What the keystroke rows check and report around a dispatch: the secure
//! field check before anything is posted, what a background target needs,
//! how a fronting bracket's result reads on the wire, and whether typed text
//! can be shown to have arrived.

use cerebellum_computer::app_state::source::{
    AppStateSource, ElementHandle, RawElement, ReadBounds,
};
use cerebellum_computer::dispatch::{BracketReport, BracketStop, DispatchError, RestoreStatus};
use cerebellum_computer::platform::{HeldStateDisposition, ProcessEventRefusal, ProcessGrant};
use serde_json::{json, Value};

/// Mark a keystroke refusal as one that made no post call at all.
///
/// A refusal otherwise reads `effect_indeterminate`, which tells a caller
/// the keys may have landed, so it will not retry. When no post call was
/// made nothing can have reached the application, and saying
/// `not_dispatched` is what lets a caller retry instead of stopping. This
/// is deliberately a different word from `no_effect_observed`, which claims
/// the effect was looked for and not seen -- that does not make a retry
/// safe, since the keys may still arrive.
///
/// Call this only where it is certain no post call was made: before the
/// dispatch, or where [`post_call_made`] answers `Some(false)`.
///
/// The remedy is left as the refusal wrote it: the effect status is the
/// signal, and the computer tool's description tells the model what
/// `not_dispatched` means.
pub(crate) fn refused_before_posting(mut reply: Value) -> Value {
    reply["effect_status"] = json!("not_dispatched");
    reply["posts_returned"] = json!(0);
    reply
}

/// Whether a keystroke dispatch that ended in `refusal` made any post call,
/// or `None` when that is not known.
///
/// `posts_returned` alone is NOT the answer, although it looks like it: it
/// counts post calls that returned, so a sequence whose very first post
/// call failed reports 0 even though a call was made -- and a failed post
/// call is uncertain, the event may have gone out. Only refusals that stop
/// before the call (a routing check such as the process having gone, or a
/// cancel seen before posting) leave 0 meaning "no call was made". Releases
/// posted to undo held keys are post calls too.
///
/// The count comes from the fronting bracket's report when there was one,
/// and otherwise from the sequence report the refusal carries. Any other
/// refusal carries no count, so whether it posted is unknown and it must
/// stay `effect_indeterminate`.
pub(crate) fn post_call_made(
    refusal: &DispatchError,
    bracket: Option<&BracketReport>,
) -> Option<bool> {
    let failed_call =
        |refusal: &ProcessEventRefusal| matches!(refusal, ProcessEventRefusal::PostCallFailed(_));
    let released = |held: &HeldStateDisposition| matches!(held, HeldStateDisposition::Released { posts_returned } if *posts_returned > 0);
    let from_refusal = match refusal {
        DispatchError::Cancelled {
            posts_returned,
            held_state,
        } => Some(*posts_returned > 0 || released(held_state)),
        DispatchError::SyntheticSequenceFailed {
            posts_returned,
            refusal,
            held_state,
        } => Some(*posts_returned > 0 || failed_call(refusal) || released(held_state)),
        // Stopped at the gate before the intent was committed: no post call.
        DispatchError::DispatchStopped => Some(false),
        _ => None,
    };
    match bracket {
        Some(bracket) => {
            let failed = matches!(
                &bracket.stop,
                Some(BracketStop::PostFailed(failure))
                    if failed_call(&failure.refusal) || released(&failure.held_state)
            );
            Some(bracket.posts_returned > 0 || failed || from_refusal == Some(true))
        }
        None => from_refusal,
    }
}

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

/// Whether a keystroke action must pass the secure-field focus check before
/// it is posted. Only a single navigation key with no modifier can skip it
/// (Shift is allowed with Tab alone, for Shift+Tab): Escape, the four arrows,
/// Tab, Home, End, Page Up and Page Down produce no characters and cannot
/// paste, so they cannot put a secret into a field. Return, Delete and
/// Backspace edit what is there, any character key types, and Command,
/// Control or Option chords can paste (Command+V), so all of those keep the
/// check, as does typed text.
pub(crate) fn needs_secure_field_check(
    action: &cerebellum_computer::platform::SyntheticAction,
) -> bool {
    use cerebellum_computer::platform::{SyntheticAction, SyntheticKey};
    let SyntheticAction::KeyCombination { key, modifiers } = action else {
        return true;
    };
    let navigation = matches!(
        key,
        SyntheticKey::Escape
            | SyntheticKey::LeftArrow
            | SyntheticKey::RightArrow
            | SyntheticKey::UpArrow
            | SyntheticKey::DownArrow
            | SyntheticKey::Tab
            | SyntheticKey::Home
            | SyntheticKey::End
            | SyntheticKey::PageUp
            | SyntheticKey::PageDown
    );
    let other_modifier =
        modifiers.command || modifiers.control || modifiers.option || modifiers.windows;
    let shift_allowed = !modifiers.shift || *key == SyntheticKey::Tab;
    !(navigation && !other_modifier && shift_allowed)
}

/// Read the target application's own focused element and refuse a secure
/// one. `Ok(None)` requires a complete fallback read with no focused element:
/// an unreadable or cut tree cannot establish the absence of a secure field.
///
/// Some applications report no focused element at the application level
/// while one of their elements carries its own focused flag: a backgrounded
/// Electron app does (Discord's message box, measured on the desk). For
/// those the application is read once and the element marked focused is
/// used, because otherwise both the secure-field check and the readback that
/// confirms typing would silently have nothing to look at.
pub(crate) fn read_target_focus(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
) -> Result<Option<TargetFocus>, FocusRefusal> {
    let handle = match source
        .focused_element(grant)
        .map_err(|_| FocusRefusal::Unreadable)?
    {
        Some(handle) => handle,
        None => match flagged_focus(source, grant)? {
            Some(handle) => handle,
            None => return Ok(None),
        },
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

/// The one element below the windows that carries its own focused flag, when
/// the application reports none. A secure field among several flagged
/// elements refuses, since which one receives the keystrokes cannot be
/// told; several without a secure one leave nothing to confirm against.
fn flagged_focus(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
) -> Result<Option<ElementHandle>, FocusRefusal> {
    fn collect(nodes: &[RawElement], out: &mut Vec<ElementHandle>) {
        for node in nodes {
            let container = matches!(
                node.role.as_deref(),
                Some("AXWindow" | "AXApplication" | "AXMenuBar")
            );
            if node.focused && !container {
                out.push(node.handle.clone());
            }
            collect(&node.children, out);
        }
    }
    let read = source
        .read_app_state(grant, ReadBounds::default())
        .map_err(|_| FocusRefusal::Unreadable)?;
    let mut flagged = Vec::new();
    collect(&read.roots, &mut flagged);
    for handle in &flagged {
        let facts = source
            .element_facts(handle)
            .map_err(|_| FocusRefusal::Unreadable)?;
        if facts.is_secure() {
            return Err(FocusRefusal::Secure);
        }
    }
    if flagged.is_empty() && (read.read_bound_reached || read.unreadable_subtrees > 0) {
        return Err(FocusRefusal::Unreadable);
    }
    Ok(match flagged.len() {
        1 => flagged.pop(),
        _ => None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyDelivery {
    PerProcess,
    BringForward,
    Refuse,
}

/// Background delivery loses shortcut modifiers even when key posts return.
/// Shift alone still describes typing and needs no foreground takeover.
pub(crate) fn key_delivery(
    action: &cerebellum_computer::platform::SyntheticAction,
    frontmost: bool,
    takeover_held: bool,
) -> KeyDelivery {
    let shortcut = matches!(action,
        cerebellum_computer::platform::SyntheticAction::KeyCombination { modifiers, .. }
        if modifiers.command || modifiers.control || modifiers.option);
    if frontmost || !shortcut {
        KeyDelivery::PerProcess
    } else if takeover_held {
        KeyDelivery::BringForward
    } else {
        KeyDelivery::Refuse
    }
}

pub(crate) fn modifier_chord_refusal() -> Value {
    json!({
        "outcome": "modifier_chord_needs_foreground",
        "reason": "modifier_chord_needs_foreground",
        "remedy": "background applications do not reliably receive shortcut modifiers; use the equivalent accessibility action or ask for takeover",
    })
}

/// The refusal for a chord the operating system acts on outside the
/// application, such as Spotlight or the application switcher, from a caller
/// without the takeover grant. The app grant covers only what is done inside
/// the application, so it is refused whether or not the application is in
/// front, and the remedy names the grant that would admit it.
pub(crate) fn system_chord_refusal() -> Value {
    json!({
        "outcome": "modifier_chord_needs_foreground",
        "reason": "modifier_chord_needs_foreground",
        "remedy": "this chord is a system shortcut that acts outside the application, which the \
                   app grant does not cover, so nothing was posted. It needs the takeover \
                   permission, control of your mouse and keyboard: ask for takeover and retry, \
                   or use the equivalent accessibility action",
    })
}

/// The reply for a keystroke whose route refused it, and whether the app
/// grant's admission details are added to it.
pub(crate) fn chord_refusal_reply(
    refusal: super::fronting::ChordRefusal,
    system_wide: bool,
) -> (Value, bool) {
    use super::fronting::ChordRefusal;
    match refusal {
        ChordRefusal::TakeoverNotForFlows => (
            crate::computer_grants::ConsentRefusal::Unavailable {
                reason: "takeover_not_for_flows",
                remedy: "fronting keys requires an attended session",
            }
            .reply(None),
            false,
        ),
        ChordRefusal::ModifierChordNeedsForeground if system_wide => (system_chord_refusal(), true),
        ChordRefusal::ModifierChordNeedsForeground => (modifier_chord_refusal(), true),
        ChordRefusal::KeystrokesNeedForeground => (needs_foreground_reply(), true),
    }
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
            "the application would have stayed in front longer than allowed, so posting stopped; \
             posts_returned says how many keystrokes were already sent. Read the field before \
             retrying, and use write_text on a settable element or send shorter text",
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
    inserted_text_arrived(before, &after, text)
}

fn inserted_text_arrived(before: &str, after: &str, text: &str) -> bool {
    changed_part(before, after).is_some_and(|inserted| inserted.contains(text))
}

fn inserted_text_reversed(before: &str, after: &str, text: &str) -> bool {
    let reversed: String = text.chars().rev().collect();
    reversed != text && changed_part(before, after) == Some(reversed.as_str())
}

/// A diagnostic only: an exact reversed insertion is not successful delivery.
/// Missing or placeholder-only accessibility values cannot establish this diagnosis.
pub(crate) fn typed_text_reversed(
    source: &dyn AppStateSource,
    focus: &TargetFocus,
    text: &str,
) -> bool {
    let Some(before) = focus.before.as_deref() else {
        return false;
    };
    source
        .text_value(&focus.handle)
        .ok()
        .flatten()
        .is_some_and(|after| inserted_text_reversed(before, &after, text))
}

/// Poll [`typed_text_arrived`] until it holds, `deadline` passes or `stopped`
/// answers true, checking at least once unless already stopped. The posts
/// returning says nothing about when the application renders them, so a
/// single read taken at once reports text that is about to appear as
/// unconfirmed. Once the call has been answered (`stopped`), nobody reads the
/// confirmation, and polling on would keep the application marked busy for
/// every later call.
pub(crate) fn await_typed_text(
    source: &dyn AppStateSource,
    focus: &TargetFocus,
    text: &str,
    deadline: std::time::Duration,
    stopped: &dyn Fn() -> bool,
) -> bool {
    const POLL: std::time::Duration = std::time::Duration::from_millis(50);
    let until = std::time::Instant::now() + deadline;
    loop {
        if stopped() {
            return false;
        }
        if typed_text_arrived(source, focus, text) {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= until {
            return false;
        }
        std::thread::sleep(POLL.min(until - now));
    }
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
#[path = "typing_pacing_tests.rs"]
mod pacing_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversed_typed_text_is_diagnosed_but_never_confirmed() {
        for (before, after, text) in [
            ("", "eerht kcehc egdab", "badge check three"),
            ("prefix[]suffix", "prefix[🦀ba]suffix", "ab🦀"),
        ] {
            assert!(!inserted_text_arrived(before, after, text));
            assert!(inserted_text_reversed(before, after, text));
        }
        assert!(!inserted_text_reversed("", "abba", "abba"));
        assert!(!inserted_text_reversed(
            "Search CortexKit",
            "Search CortexKit",
            "badge"
        ));
        assert!(!inserted_text_reversed("", "unrelated", "badge"));
        assert!(inserted_text_arrived(
            "",
            "badge check three",
            "badge check three"
        ));
    }

    /// A bracket that posted every unit but held the target in front past the
    /// bound reports the keystrokes as delivered with the overrun named, never
    /// as fronted and never as a refusal. One inside the bound is fronted with
    /// no forfeiture.
    #[test]
    fn a_bracket_that_overran_the_bound_is_disclosed_on_a_delivered_reply() {
        let report = |longest_fronted_interval_ms| BracketReport {
            previous_frontmost: Some(100),
            chunks: 1,
            units_posted: 1,
            posts_returned: 2,
            generation_verifications: 4,
            longest_fronted_interval_ms,
            slowest_unit_ms: 4,
            slowest_restore_ms: 50,
            restore: RestoreStatus::Restored,
            stop: None,
        };
        assert_eq!(
            bracket_fronting(&report(104), 100),
            (false, Some("fronting_bound_exceeded"))
        );
        assert_eq!(bracket_fronting(&report(90), 100), (true, None));
    }

    #[test]
    fn key_delivery_decision_covers_foreground_takeover_and_plain_typing() {
        use cerebellum_computer::platform::{SyntheticAction, SyntheticKey, SyntheticKeyModifiers};
        for foreground in [true, false] {
            for takeover in [true, false] {
                assert_eq!(
                    key_delivery(&SyntheticAction::type_text("x"), foreground, takeover),
                    KeyDelivery::PerProcess
                );
                for modifiers in [
                    SyntheticKeyModifiers::default(),
                    SyntheticKeyModifiers {
                        shift: true,
                        ..Default::default()
                    },
                ] {
                    assert_eq!(
                        key_delivery(
                            &SyntheticAction::KeyCombination {
                                key: SyntheticKey::A,
                                modifiers
                            },
                            foreground,
                            takeover
                        ),
                        KeyDelivery::PerProcess
                    );
                }
                for modifiers in [
                    SyntheticKeyModifiers {
                        command: true,
                        ..Default::default()
                    },
                    SyntheticKeyModifiers {
                        control: true,
                        ..Default::default()
                    },
                    SyntheticKeyModifiers {
                        option: true,
                        ..Default::default()
                    },
                ] {
                    assert_eq!(
                        key_delivery(
                            &SyntheticAction::KeyCombination {
                                key: SyntheticKey::A,
                                modifiers
                            },
                            foreground,
                            takeover
                        ),
                        if foreground {
                            KeyDelivery::PerProcess
                        } else if takeover {
                            KeyDelivery::BringForward
                        } else {
                            KeyDelivery::Refuse
                        }
                    );
                }
            }
        }
    }

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
