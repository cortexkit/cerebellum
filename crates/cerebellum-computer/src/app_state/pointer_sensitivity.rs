//! Positive accessibility (AX) sensitivity evidence for raw pointer targets. Drawn content
//! without AX semantics cannot reveal a credential or payment form; readable
//! canvases remain usable under takeover. This is not pixel classification.

use super::source::{AppStateSource, ElementFacts, ElementHandle};
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
    pointer_target_check_until(
        source,
        target,
        point,
        window,
        std::time::Instant::now() + crate::pointer_query::QUERY_TIMEOUT,
    )
}

/// Use the caller's existing deadline for helper startup and the recipient
/// reply, rather than starting a new budget when posting.
pub fn pointer_target_check_until(
    source: &dyn AppStateSource,
    target: &ProcessGrant,
    point: (f64, f64),
    window: u32,
    deadline: std::time::Instant,
) -> Result<(), &'static str> {
    if source.pointer_recipient_until(point, deadline)? != Some(window) {
        return Err("pointer recipient window changed or unavailable");
    }
    if !pointer_target_safe(source, target, point, window) {
        return Err("pointer accessibility sensitivity step failed");
    }
    Ok(())
}

fn hazardous(facts: &ElementFacts, windows: bool) -> bool {
    facts.is_secure()
        || hazardous_role_title(facts.role.as_deref(), facts.title.as_deref(), windows)
}

pub(crate) fn hazardous_role_title(role: Option<&str>, title: Option<&str>, windows: bool) -> bool {
    role == Some("AXSecureTextField")
        || (matches!(role, Some("AXMenuItem" | "AXMenuBarItem"))
            && title
                .is_some_and(|title| super::render::is_session_ending_title_for(title, windows)))
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
        if facts.role.is_none()
            || facts.pid.is_some_and(|owner| owner != pid)
            || hazardous(&facts, element.uses_windows_menu_titles())
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
    let Ok(Some((element, owner))) = source.element_at_for_target(target, point) else {
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
