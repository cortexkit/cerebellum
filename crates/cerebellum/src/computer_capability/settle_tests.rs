//! What an action reply's diff says after the settle that follows a press,
//! against fixture applications whose reads change on a script, one step per
//! whole read. None of them needs a real application, so they run on every
//! platform.

use super::element_actions::{
    add_diff_view, settle_and_observe_view, PersonWatch, PressedElement, CHANGE_UNCONFIRMED,
    NO_CHANGE_SEEN, PRESSED_ELEMENT_CHANGED,
};
use super::StateView;
use crate::browser::state_text::STATE_TEXT_FIELD;
use cerebellum_computer::app_state::render::ObservedNode;
use cerebellum_computer::app_state::session::AppStateSessions;
use cerebellum_computer::app_state::source::{
    AppStateReadError, AppStateSource, ElementHandle, ElementReadError, ElementValue,
    FixtureElementToken, RawAppState, RawElement, ReadBounds,
};
use cerebellum_computer::platform::ProcessGrant;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONVERSATION: &str = "settle-reply";
const FLEET: u64 = 5;
const CHAT: u64 = 6;

fn grant() -> ProcessGrant {
    ProcessGrant {
        pid: 91,
        bundle_identity: "com.example.tabs".into(),
        process_generation_evidence: "generation-91".into(),
    }
}

/// The application's state at one moment: whether an unnamed group holds
/// focus (losing it is a redraw the diff does not show: an unnamed group
/// with no state has no line of its own), which tab is selected, and
/// whether the read reached everything.
#[derive(Clone, Copy)]
struct Moment {
    group_focused: bool,
    fleet_selected: bool,
    complete: bool,
    /// Whether a partial read still reaches the tabs.
    tabs_readable: bool,
}

const BEFORE: Moment = Moment {
    group_focused: true,
    fleet_selected: false,
    complete: true,
    tabs_readable: true,
};

fn tab(token: u64, title: &str, selected: bool) -> RawElement {
    let mut tab = RawElement::fixture(token, "AXRadioButton")
        .with_subrole("AXTabButton")
        .titled(title);
    tab.value = ElementValue::Boolean(selected);
    tab.selected = selected;
    tab
}

fn tree(moment: Moment) -> RawAppState {
    let mut group = RawElement::fixture(2, "AXGroup");
    group.focused = moment.group_focused;
    let mut children = vec![group];
    // Lines no press changes, so a change to two tabs and a group is a few
    // changed lines rather than most of the window, which would be shown as a
    // replaced state instead of a diff.
    children.extend(
        (0..8).map(|row| {
            RawElement::fixture(100 + row, "AXStaticText").titled(&format!("Row {row}"))
        }),
    );
    if moment.complete || moment.tabs_readable {
        children.push(tab(FLEET, "Fleet", moment.fleet_selected));
        children.push(tab(CHAT, "Chat", !moment.fleet_selected));
    }
    RawAppState {
        roots: vec![RawElement::fixture(1, "AXWindow")
            .titled("Alfonso")
            .with_children(children)],
        focused: None,
        unreadable_subtrees: if moment.complete { 0 } else { 87 },
        read_bound_reached: false,
    }
}

/// An application that shows `script[n]` to its n-th whole read after the
/// press, and the last moment after that. A read of one element alone shows
/// it as the next whole read will: the element is read just before it.
struct ScriptedApp {
    script: Vec<Moment>,
    whole_reads: Mutex<usize>,
    /// Whether a read of the pressed element alone is answered at all.
    element_readable: bool,
}

impl ScriptedApp {
    fn new(script: Vec<Moment>) -> Self {
        Self {
            script,
            whole_reads: Mutex::new(0),
            element_readable: true,
        }
    }

    fn now(&self) -> Moment {
        let reads = *self.whole_reads.lock().unwrap();
        self.script[reads.min(self.script.len() - 1)]
    }

    fn whole_reads(&self) -> usize {
        *self.whole_reads.lock().unwrap()
    }
}

impl AppStateSource for ScriptedApp {
    fn read_app_state(
        &self,
        _target: &ProcessGrant,
        _bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        let read = tree(self.now());
        *self.whole_reads.lock().unwrap() += 1;
        Ok(read)
    }

    fn read_element_state(
        &self,
        _target: &ProcessGrant,
        element: &ElementHandle,
        _bounds: ReadBounds,
        _expand_menus: bool,
    ) -> Result<RawAppState, ElementReadError> {
        if !self.element_readable {
            return Err(ElementReadError::Unreadable);
        }
        let token = element.identity_hash();
        let moment = self.now();
        let element = tab(
            token,
            if token == FLEET { "Fleet" } else { "Chat" },
            (token == FLEET) == moment.fleet_selected,
        );
        Ok(RawAppState {
            roots: vec![element],
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        })
    }
}

fn find_id(roots: &[ObservedNode], title: &str) -> Option<String> {
    roots.iter().find_map(|node| {
        if node.description.label == title {
            node.element_id.clone()
        } else {
            find_id(&node.children, title)
        }
    })
}

/// The conversation reads the application as it was before the press, then
/// presses the Fleet tab; the reply is what the press would carry.
fn press_reply(app: &ScriptedApp, watch_pressed: bool, bound: Duration) -> Value {
    let sessions = AppStateSessions::new();
    let before = sessions.observe(CONVERSATION, &grant(), &tree(BEFORE));
    let fleet_id = find_id(&before.roots, "Fleet").expect("the tab is numbered");
    let handle: ElementHandle = Arc::new(FixtureElementToken(FLEET));
    let settled = settle_and_observe_view(
        app,
        &sessions,
        CONVERSATION,
        &grant(),
        bound,
        false,
        PersonWatch::NotWatched,
        watch_pressed.then_some(PressedElement {
            element_id: &fleet_id,
            handle: &handle,
        }),
    );
    let mut reply = json!({"outcome": "completed"});
    add_diff_view(&mut reply, settled.as_ref(), &StateView::default());
    reply
}

fn state_text(reply: &Value) -> &str {
    reply[STATE_TEXT_FIELD]
        .as_str()
        .expect("the reply has state text")
}

/// The press first takes focus from an unnamed group, which the diff does not
/// show, in a read that could not reach everything; the tab reads selected
/// only from the second read on. The reply shows the tab's change rather
/// than "No change seen".
#[test]
fn a_tab_that_shows_its_press_a_read_late_is_reported_changed() {
    let app = ScriptedApp::new(vec![
        Moment {
            group_focused: false,
            complete: false,
            ..BEFORE
        },
        Moment {
            group_focused: false,
            fleet_selected: true,
            ..BEFORE
        },
    ]);
    let reply = press_reply(&app, true, Duration::from_secs(2));
    let text = state_text(&reply);
    assert!(
        !text.contains("No change seen"),
        "the press changed the tab: {reply}"
    );
    assert_eq!(reply["state_report"], "diff", "{reply}");
    assert!(
        text.lines()
            .any(|line| line.starts_with('~') && line.contains("Fleet")),
        "the pressed tab's new line is shown: {reply}"
    );
    assert!(
        app.whole_reads() < 10,
        "the settle stopped once the tab changed, not at its bound: {} reads",
        app.whole_reads()
    );
}

/// A complete read after the whole settle that equals the read before the
/// press still says "No change seen".
#[test]
fn a_complete_unchanged_read_after_the_whole_settle_says_no_change_seen() {
    let app = ScriptedApp::new(vec![BEFORE]);
    let reply = press_reply(&app, true, Duration::from_millis(200));
    assert!(
        state_text(&reply).starts_with(NO_CHANGE_SEEN),
        "nothing changed and everything was read: {reply}"
    );
}

/// The same holds when the pressed element cannot be read alone.
#[test]
fn an_unwatchable_element_with_a_complete_unchanged_read_says_no_change_seen() {
    let mut app = ScriptedApp::new(vec![BEFORE]);
    app.element_readable = false;
    let reply = press_reply(&app, true, Duration::from_millis(200));
    assert!(state_text(&reply).starts_with(NO_CHANGE_SEEN), "{reply}");
}

/// Reads that stay partial for the whole settle cannot say nothing changed:
/// the change may be in the part they did not reach.
#[test]
fn partial_reads_with_no_change_say_the_change_is_not_confirmed() {
    let app = ScriptedApp::new(vec![Moment {
        complete: false,
        ..BEFORE
    }]);
    let reply = press_reply(&app, true, Duration::from_millis(200));
    let text = state_text(&reply);
    assert!(text.starts_with(CHANGE_UNCONFIRMED), "{reply}");
    assert!(!text.contains("No change seen"), "{reply}");
}

/// A settle that stopped on a difference the diff does not show (here an
/// unnamed group losing focus, with no pressed element to watch) has not
/// seen the action's effect, so its empty diff is not "No change seen".
#[test]
fn a_settle_stopped_by_an_unshown_difference_does_not_say_no_change_seen() {
    let app = ScriptedApp::new(vec![
        Moment {
            group_focused: false,
            ..BEFORE
        },
        Moment {
            group_focused: false,
            fleet_selected: true,
            ..BEFORE
        },
    ]);
    let reply = press_reply(&app, false, Duration::from_secs(2));
    let text = state_text(&reply);
    assert!(text.starts_with(CHANGE_UNCONFIRMED), "{reply}");
}

/// When the pressed element's own line changed but the whole read could not
/// reach it, the reply says the element changed rather than nothing did.
#[test]
fn a_pressed_element_change_the_read_missed_is_reported() {
    let app = ScriptedApp::new(vec![Moment {
        fleet_selected: true,
        complete: false,
        tabs_readable: false,
        ..BEFORE
    }]);
    let reply = press_reply(&app, true, Duration::from_secs(2));
    let text = state_text(&reply);
    assert!(text.starts_with(PRESSED_ELEMENT_CHANGED), "{reply}");
    assert!(
        app.whole_reads() < 10,
        "the settle stopped once the element changed: {} reads",
        app.whole_reads()
    );
}
