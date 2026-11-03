//! Positive accessibility (AX) sensitivity evidence for raw pointer targets. Drawn content
//! without AX semantics cannot reveal a credential or payment form; readable
//! canvases remain usable under takeover. This is not pixel classification.

use super::source::{AppStateSource, ElementFacts, ElementHandle, HitScope};
use crate::platform::ProcessGrant;

/// Exact window number, not just application identity: a same-application
/// sheet covering the point is a different target and must refuse too.
pub fn pointer_target_contained(
    source: &dyn AppStateSource,
    target: &ProcessGrant,
    point: (f64, f64),
    window: u32,
) -> bool {
    pointer_target_check(source, target, point, window).is_ok()
}

/// Preserve the failed query step instead of turning helper failure into a match.
pub fn pointer_target_check(
    source: &dyn AppStateSource,
    target: &ProcessGrant,
    point: (f64, f64),
    window: u32,
) -> Result<(), &'static str> {
    if source.pointer_recipient(point)? != Some(window) {
        return Err("mouse-down recipient window changed or unavailable");
    }
    if !pointer_target_safe(source, target, point, window) {
        return Err("pointer accessibility sensitivity step failed");
    }
    Ok(())
}

fn hazardous(facts: &ElementFacts) -> bool {
    facts.is_secure()
        || (matches!(facts.role.as_deref(), Some("AXMenuItem" | "AXMenuBarItem"))
            && facts
                .title
                .as_deref()
                .is_some_and(super::render::is_session_ending_title))
}

/// A readable, non-sensitive path must reach the exact imaged window. A lost
/// parent, missing role, foreign owner, cycle or bounded-out path refuses.
fn safe_path(
    source: &dyn AppStateSource,
    mut element: ElementHandle,
    pid: u32,
    window: u32,
) -> bool {
    for _ in 0..64 {
        let Ok(facts) = source.element_facts(&element) else {
            return false;
        };
        if facts.role.is_none() || facts.pid.is_some_and(|owner| owner != pid) || hazardous(&facts)
        {
            return false;
        }
        if facts.role.as_deref() == Some("AXWindow") {
            return source.element_window_number(&element) == Some(window);
        }
        match source.element_parent(&element) {
            Ok(Some(parent)) => element = parent,
            _ => return false,
        }
    }
    false
}

/// Re-read the pointed-at path and focused field in that window. Do not infer
/// permission/payment semantics from labels: system sheets are rejected by
/// exact-window/owner containment, not a word list. Inline drawn sensitive
/// forms without AX evidence are an explicit limitation of raw takeover.
pub fn pointer_target_safe(
    source: &dyn AppStateSource,
    target: &ProcessGrant,
    point: (f64, f64),
    window: u32,
) -> bool {
    let Ok(Some((element, owner))) =
        source.element_at(HitScope::Application { pid: target.pid }, point)
    else {
        return false;
    };
    if owner.is_some_and(|owner| owner != target.pid)
        || !safe_path(source, element, target.pid, window)
    {
        return false;
    }
    match source.focused_element(target) {
        Ok(Some(focused)) => match source.element_window_number(&focused) {
            Some(focused_window) if focused_window != window => true,
            Some(_) => safe_path(source, focused, target.pid, window),
            None => false,
        },
        Ok(None) => true,
        Err(_) => false,
    }
}
