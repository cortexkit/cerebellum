//! Reconcile a press reply's AX window identities with a late WindowServer list.

use std::time::Instant;

use cerebellum_computer::app_state::person::{person_change, Reading, SeenMarks};
use cerebellum_computer::app_state::session::{AppStateSessions, ElementResolution, SessionRead};
use cerebellum_computer::app_state::source::AppStateSource;
use cerebellum_computer::platform::ProcessGrant;
use serde_json::Value;

use crate::browser::state_text::STATE_TEXT_FIELD;

fn quiet_since(source: &dyn AppStateSource, grant: &ProcessGrant, at: Instant) -> bool {
    matches!(source.hardware_input(grant),
        Ok((since, latest)) if since <= at && latest.is_none_or(|input| input <= at))
}

/// Keep the earlier WindowServer sample. A later check may substitute the
/// AX inventory only after the server catches up to that exact set. The
/// caller supplies a reply not scoped to a filter or a particular subtree.
pub(super) fn certify_press_reply_windows(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    grant: &ProcessGrant,
    conversation: &str,
    read: &SessionRead,
    reply: &Value,
    press_at: Instant,
) {
    let replacement = match reply["state_report"].as_str() {
        Some("replacement") => true,
        Some("diff") => false,
        _ => return,
    };
    if !read.complete || read.diff.added.is_empty() || reply.get("truncation").is_some() {
        return;
    }
    let Some(text) = reply[STATE_TEXT_FIELD].as_str() else {
        return;
    };
    let windows: Vec<_> = read
        .roots
        .iter()
        .filter(|node| node.description.role.as_deref() == Some("AXWindow"))
        .collect();
    if !windows.iter().any(|window| {
        window
            .element_id
            .as_ref()
            .is_some_and(|id| read.diff.added.contains(id))
    }) {
        return;
    }
    let Some(mut seen) = sessions.last_seen(conversation, grant) else {
        return;
    };
    let (Reading::Read(previous), Reading::Read(focused), Reading::Read(Some(focused_window))) =
        (&seen.windows, &seen.focused, &seen.window)
    else {
        return;
    };
    let resolve = |id: &str| match sessions.resolve(conversation, id) {
        ElementResolution::Live { handle, .. } => Some(handle),
        _ => None,
    };
    // The independent marks must agree with the focus in the AX reply, not
    // just with one another on the next call.
    match (focused, read.focused_element_id.as_deref()) {
        (Some(mark), Some(id)) if resolve(id).is_some_and(|h| mark.same_element(h.as_ref())) => {}
        (None, None) => {}
        _ => return,
    }
    let mut expected = Vec::with_capacity(windows.len());
    let mut focused_window_shown = false;
    for (index, window) in windows.iter().enumerate() {
        let Some(id) = window.element_id.as_deref() else {
            return;
        };
        let Some(handle) = resolve(id) else {
            return;
        };
        let Some(number) = source.element_window_number(&handle) else {
            return;
        };
        // A replacement names its first window in the header. The other
        // windows must have their own line in the outline or the diff.
        let shown = (replacement && index == 0)
            || text.lines().any(|line| {
                let line = line.trim_start();
                let line = line.strip_prefix("+ ").unwrap_or(line);
                line.split_whitespace().next() == Some(id)
            });
        if !previous.contains(&number) && (!shown || !read.diff.added.iter().any(|new| new == id)) {
            return;
        }
        if (shown || previous.contains(&number))
            && window.description.markers.contains(&"focused")
            && focused_window.handle.same_element(handle.as_ref())
        {
            focused_window_shown = true;
        }
        expected.push(number);
    }
    expected.sort_unstable();
    if !focused_window_shown
        || expected.windows(2).any(|pair| pair[0] == pair[1])
        || expected.len() <= previous.len()
        || !previous.iter().all(|number| expected.contains(number))
        || !quiet_since(source, grant, press_at)
    {
        return;
    }
    seen.press_reply_windows = Some(expected);
    sessions.remember_seen(conversation, grant, seen);
}

pub(super) fn quiet_reply_window_change(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
    seen: &SeenMarks,
    now: &SeenMarks,
) -> bool {
    let (Some(expected), Reading::Read(actual)) = (&seen.press_reply_windows, &now.windows) else {
        return false;
    };
    if expected != actual
        || !matches!(now.focused, Reading::Read(_))
        || !matches!(now.window, Reading::Read(Some(_)))
    {
        return false;
    }
    let from_reply = SeenMarks {
        windows: Reading::Read(expected.clone()),
        ..seen.clone()
    };
    person_change(&from_reply, now, false, None).is_none() && quiet_since(source, grant, seen.at)
}
