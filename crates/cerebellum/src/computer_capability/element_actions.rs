//! The element actions: pressing an element named by id, pressing whatever a
//! point in a returned image lands on, and writing text into an element.
//!
//! All three act through accessibility on an element of one application
//! session, so none of them moves the pointer, posts an event or brings a
//! window forward. The application they act in is the one the element id or
//! image names, never the frontmost one, and its process generation is checked
//! again before anything is done: an id from a process that has since
//! restarted names nothing.
//!
//! Each reply carries the diff from the conversation's last state read, taken
//! after a short wait for the application to show the effect, as text in the
//! read's own line grammar.
//!
//! A request may also name the application with `target`. The element or
//! image already decides which application is acted in, so the target only
//! guards against a caller that confused two applications' ids: one naming
//! another application is refused, and otherwise it changes nothing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cerebellum_computer::app_state::person::{person_change, PersonChange, Reading, SeenMarks};
use cerebellum_computer::app_state::render::is_session_ending_title;
use cerebellum_computer::app_state::session::{Adoption, AppStateSessions, SessionRead};

// One reply field name for both planes, so a host lifts browser and computer
// state into text by the same key.
use crate::browser::state_text::STATE_TEXT_FIELD;
use cerebellum_computer::app_state::source::{
    AppStateSource, ElementActionError, ElementFacts, ElementHandle, HitScope, ReadBounds,
    TextAttribute,
};
use cerebellum_computer::audit::{
    AccessibilityReadScope, ActuationElementIdentity, ActuationIntent, AuditToken,
    ComputerCapability, ComputerPlaneDescriptor, FrontingRecord, ObservationState,
};
use cerebellum_computer::dispatch::MutationGate;
use cerebellum_computer::grounding::ContainmentRung;
use cerebellum_computer::platform::vocabulary::{
    frozen_row_bound_ms, frozen_row_effect_deadline_ms,
};
use cerebellum_computer::platform::{AccessibilityElementName, ProcessGrant};
use cerebellum_core::journal::{
    DispatchCommitmentToken, JournalIdentity, JournalStorage, Redactor, SeverityTaxonomy,
};
use serde_json::{json, Value};

use super::action_effects::{append_lines, ActionEffects};
use super::cursor::{Arrival, BadgeWatch, Landing};
use super::press_reply_windows::{certify_press_reply_windows, quiet_reply_window_change};
use crate::computer_grants::{ConsentContext, ConsentRefusal, GrantAdmission};
use crate::management::ManagementPlane;
use crate::CancelHandle;
use cerebellum_core::config::AppUse;

/// How often the state is re-read while waiting for an action's effect.
const SETTLE_POLL: Duration = Duration::from_millis(50);

/// The longest an action waits for its effect to show before taking the
/// diff, from the row's own settle bound. A row that declares none (keys)
/// waits the 500 ms the element rows declare, since its diff is taken the
/// same way.
pub(crate) fn settle_bound(capability: ComputerCapability) -> Duration {
    Duration::from_millis(
        frozen_row_bound_ms(
            capability.capability_id(),
            "maximum_accessibility_tree_settle_interval_ms",
        )
        .unwrap_or(500),
    )
}

/// The longest an action waits to see its own effect, from the row's
/// effect-observation deadline. A row that declares none waits one second.
pub(crate) fn effect_deadline(capability: ComputerCapability) -> Duration {
    Duration::from_millis(frozen_row_effect_deadline_ms(capability.capability_id()).unwrap_or(1000))
}

fn invalid(field: &str, reason: &str) -> Value {
    json!({"outcome": "invalid_request", "field": field, "reason": reason})
}

pub(crate) fn stale_element_reply() -> Value {
    json!({
        "outcome": "stale_element",
        "remedy": "this element id names no live element of the application's current state; \
                   call read_state again and use an id from that read",
    })
}

/// The refusal for an element id from an earlier run of the module: its
/// number may now name a different element, so nothing is done with it.
pub(crate) fn previous_run_reply() -> Value {
    json!({
        "outcome": "stale_element",
        "remedy": "read_state again; ids from before a restart no longer apply",
    })
}

/// The reply for an action that waited for its badge and was cancelled
/// before it was sent: by the caller, or by the agent's turn ending while the
/// badge was still on its way. Nothing was pressed or written.
pub(crate) fn cancelled_before_dispatch_reply() -> Value {
    json!({
        "outcome": "cancelled",
        "detail": {"dispatched": false, "step": "dispatch", "reason": "cancelled"},
        "remedy": "the call was cancelled before the action was sent; nothing was done",
    })
}

/// Why an action that waited for its badge will not be sent. Nothing was
/// sent for it.
pub(super) enum Held {
    /// The call was cancelled, or the agent's badge was ended, while it waited.
    Cancelled,
    /// The call's work deadline passed, or its dispatch gate closed.
    Stopped,
    /// The person used the application while the badge travelled; the reply
    /// says how.
    Refused(Value),
}

impl Held {
    /// The reply an element action gives for it.
    fn reply(self) -> Value {
        match self {
            Self::Cancelled => cancelled_before_dispatch_reply(),
            Self::Stopped => super::quarantine::stopped_before_dispatch_reply(),
            Self::Refused(reply) => reply,
        }
    }
}

/// Wait for the badge an action scheduled, within the call's work budget.
/// `Ok` says whether a badge was drawn.
async fn badge_landing(arrival: Arrival, cancel: &CancelHandle) -> Result<bool, Held> {
    let work = super::quarantine::CallWork::current();
    let deadline = tokio::time::Instant::from_std(work.deadline());
    match arrival
        .wait(deadline, cancel.cancelled(), || work.stopped())
        .await
    {
        Landing::Arrived { drawn } => Ok(drawn),
        Landing::Cancelled | Landing::Ended => Err(Held::Cancelled),
        Landing::Stopped => Err(Held::Stopped),
    }
}

/// The call's dispatch gate for an action that showed a badge. It also
/// refuses once that badge was ended after the action scheduled it (the
/// agent's turn ended, or its route closed): the check is made at the moment
/// the action would be sent, so an end that lands while the element is still
/// being checked still stops it.
pub(super) struct BadgeGate {
    call: Arc<dyn MutationGate>,
    watch: Option<BadgeWatch>,
    ended: AtomicBool,
}

impl BadgeGate {
    pub(super) fn new(call: Arc<dyn MutationGate>, watch: Option<BadgeWatch>) -> Arc<Self> {
        Arc::new(Self {
            call,
            watch,
            ended: AtomicBool::new(false),
        })
    }

    /// Whether this gate refused the action because the badge was ended.
    pub(super) fn refused_for_end(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

impl MutationGate for BadgeGate {
    fn begin_mutation(&self) -> bool {
        if self.watch.as_ref().is_some_and(BadgeWatch::ended) {
            self.ended.store(true, Ordering::SeqCst);
            return false;
        }
        self.call.begin_mutation()
    }

    fn stopped(&self) -> bool {
        self.call.stopped()
    }
}

/// The refusal for an action on an application the person used since this
/// conversation was last shown it. Nothing was done, so after a read the
/// action may be tried again.
pub(crate) fn state_changed_by_person_reply(app_name: &str, change: PersonChange) -> Value {
    json!({
        "outcome": "state_changed_by_person",
        "reason": change.as_str(),
        "remedy": format!(
            "The person used {app_name} since your last read. Call read_state, then act on what \
             it shows."
        ),
    })
}

/// Whether the person used the application since the conversation was last
/// shown it, by a read or an action reply's diff. `None` when it was never
/// shown this process, since there is then nothing to compare against.
///
/// Focus and window changes remain usable even when hardware observation is
/// unavailable. Only a frontmost target requires continuous input coverage.
pub(crate) fn person_change_since_seen(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
) -> Result<Option<PersonChange>, ()> {
    let Some(seen) = sessions.last_seen(conversation_key, grant) else {
        return Ok(None);
    };
    let now = SeenMarks::read(source, grant);
    if quiet_reply_window_change(source, grant, &seen, &now) {
        return Ok(None);
    }
    if let Some(change) = person_change(&seen, &now, false, None) {
        return Ok(Some(change));
    }
    match source.frontmost_pid() {
        Some(pid) if pid != grant.pid => Ok(None),
        Some(_) => match source.hardware_input(grant) {
            Ok((since, latest)) if since <= seen.at => Ok(person_change(&seen, &now, true, latest)),
            _ => Err(()),
        },
        None => Err(()),
    }
}

/// What the check before an element or keystroke action found.
#[derive(Debug)]
pub(crate) enum PersonCheck {
    /// Nothing changed since the conversation last saw the application.
    Unchanged,
    /// The person may have used the application: refuse.
    Changed(PersonChange),
    /// Only the application's focused element moved, and nobody touched a
    /// key, button or scroll wheel since the marks were taken: the
    /// application moved its own focus, often in answer to the agent's own
    /// last action. The marks are refreshed; the line says where focus went.
    AppMovedFocus(String),
}

/// [`person_change_since_seen`] for the check made before an element or
/// keystroke action, which also tells an application's own focus move from
/// the person's.
///
/// A changed focused element counts as the application's own move only when
/// all of these hold: the focused window is the same one with the same title
/// (a new window can be a dialog the agent has not seen), the application is
/// frontmost, the hardware-input observer has covered the whole interval
/// since the marks were taken without a gap, and it saw no key, button or
/// scroll input in that interval. Anything less refuses as before.
pub(crate) fn person_check_before_action(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
) -> Result<PersonCheck, ()> {
    let Some(seen) = sessions.last_seen(conversation_key, grant) else {
        return Ok(PersonCheck::Unchanged);
    };
    let now = SeenMarks::read(source, grant);
    if quiet_reply_window_change(source, grant, &seen, &now) {
        return Ok(PersonCheck::Unchanged);
    }
    // Autosave can retitle the same window after our input returns. A title
    // alone is not evidence of a person when the input watcher covered the
    // entire interval and saw no hardware input. Keep window identity, window
    // inventory and focus strict, including for a background application.
    if seen.after_agent_input
        && matches!((&seen.window, &now.window),
            (Reading::Read(Some(before)), Reading::Read(Some(after)))
                if before.handle.same_element(after.handle.as_ref()))
        && matches!((&seen.windows, &now.windows),
            (Reading::Read(before), Reading::Read(after)) if before == after)
        && matches!(source.hardware_input(grant),
            Ok((since, latest)) if since <= seen.at && latest.is_none_or(|at| at <= seen.at))
    {
        let without_title = SeenMarks {
            window: now.window.clone(),
            ..seen.clone()
        };
        if person_change(&without_title, &now, false, None).is_none() {
            return Ok(PersonCheck::Unchanged);
        }
    }
    match person_change(&seen, &now, false, None) {
        Some(PersonChange::FocusChanged) => {
            // Compared with the new focused element in place of the old one,
            // so only the window is left to differ.
            let window_only = SeenMarks {
                focused: now.focused.clone(),
                ..seen.clone()
            };
            let unchanged_window = person_change(&window_only, &now, false, None).is_none();
            let unobserved_interval = source.frontmost_pid() == Some(grant.pid)
                && matches!(
                    source.hardware_input(grant),
                    Ok((since, latest))
                        if since <= seen.at && latest.is_none_or(|at| at <= seen.at)
                );
            if !(unchanged_window && unobserved_interval) {
                return Ok(PersonCheck::Changed(PersonChange::FocusChanged));
            }
            let line = focus_moved_line(source, &now);
            sessions.remember_seen(conversation_key, grant, now);
            Ok(PersonCheck::AppMovedFocus(line))
        }
        Some(change) => Ok(PersonCheck::Changed(change)),
        None => match source.frontmost_pid() {
            Some(pid) if pid != grant.pid => Ok(PersonCheck::Unchanged),
            Some(_) => match source.hardware_input(grant) {
                Ok((since, latest)) if since <= seen.at => {
                    Ok(person_change(&seen, &now, true, latest)
                        .map_or(PersonCheck::Unchanged, PersonCheck::Changed))
                }
                _ => Err(()),
            },
            None => Err(()),
        },
    }
}

/// The reply line for an application's own focus move, naming the element
/// that now has focus by its title, or by its role when it has none.
fn focus_moved_line(source: &dyn AppStateSource, now: &SeenMarks) -> String {
    let facts = match &now.focused {
        Reading::Read(Some(handle)) => source.element_facts(handle).ok(),
        _ => None,
    };
    let title = facts
        .as_ref()
        .and_then(|facts| facts.title.as_deref())
        .map(cerebellum_computer::app_state::render::one_line)
        .filter(|title| !title.is_empty());
    let element = match (
        title,
        facts.as_ref().and_then(|facts| facts.role.as_deref()),
    ) {
        (Some(title), _) => format!("\"{title}\""),
        (None, Some(role)) => format!("a {}", role.strip_prefix("AX").unwrap_or(role)),
        (None, None) => "another element".to_string(),
    };
    format!("Focus moved to {element} on its own since your last read.")
}

fn blocked_menu_item_reply() -> Value {
    json!({
        "outcome": "blocked_menu_item",
        "remedy": "this menu item ends or suspends the person's session, or empties the Trash; \
                   no grant admits pressing it, so ask the person to do it themselves",
    })
}

/// The longest element title an `element_disabled` remedy quotes.
const DISABLED_LABEL_CHARS: usize = 60;

/// The refusal for a press on an element the application reports disabled.
/// Nothing was sent. The element is named by its title when it has one, made
/// one line and cut short, and otherwise by its id. `background` says the
/// application is known not to be frontmost; only then does the remedy say
/// that an inactive application's window buttons can stay disabled.
pub(crate) fn element_disabled_reply(
    title: Option<&str>,
    element_id: &str,
    background: bool,
) -> Value {
    let title = title
        .map(cerebellum_computer::app_state::render::one_line)
        .filter(|title| !title.is_empty());
    let label = match title {
        Some(title) if title.chars().count() > DISABLED_LABEL_CHARS => {
            let cut: String = title.chars().take(DISABLED_LABEL_CHARS).collect();
            format!("{}…", cut.trim_end())
        }
        Some(title) => title,
        None => format!("Element {element_id}"),
    };
    let background = if background {
        " A background app's window buttons can stay disabled until the app is active."
    } else {
        ""
    };
    json!({
        "outcome": "element_disabled",
        "remedy": format!(
            "{label} is disabled, so pressing it would do nothing.{background} Read the app \
             again after its state changes."
        ),
    })
}

fn audit_unavailable_reply(acted: bool) -> Value {
    if acted {
        json!({
            "outcome": "audit_unavailable",
            "reason": "outcome_not_recorded",
            "remedy": "the action was sent but its outcome could not be journaled; read the \
                       state to see what happened before doing anything else",
        })
    } else {
        json!({
            "outcome": "audit_unavailable",
            "remedy": "the action could not be journaled, so it was not sent; retry later",
        })
    }
}

/// Fields a request may carry, refusing any other. Which of them are
/// required is each parser's own check.
fn object_with_fields<'a>(
    arguments: &'a Value,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, Value> {
    let Some(object) = arguments.as_object() else {
        return Err(invalid("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !fields.contains(&field.as_str()))
        .min()
    {
        return Err(invalid(field, "unknown_field"));
    }
    Ok(object)
}

fn required_string(object: &serde_json::Map<String, Value>, field: &str) -> Result<String, Value> {
    match object.get(field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::String(_)) => Err(invalid(field, "empty_value")),
        Some(_) => Err(invalid(field, "wrong_type")),
        None => Err(invalid(field, "missing_field")),
    }
}

/// Every field `computer.press_element` accepts, and the ones it requires.
pub(crate) const PRESS_ELEMENT_FIELDS: [&str; 6] = [
    "element_id",
    "element_ids",
    "target",
    "role_filter",
    "text_filter",
    "zoom",
];
#[cfg(test)]
pub(crate) const PRESS_ELEMENT_REQUIRED: [&str; 0] = [];
/// Every field `computer.press_point` accepts, and the ones it requires.
pub(crate) const PRESS_POINT_FIELDS: [&str; 7] = [
    "image_id",
    "target",
    "x",
    "y",
    "role_filter",
    "text_filter",
    "zoom",
];
#[cfg(test)]
pub(crate) const PRESS_POINT_REQUIRED: [&str; 3] = ["image_id", "x", "y"];
/// Every field `computer.write_text` accepts, and the ones it requires.
pub(crate) const WRITE_TEXT_FIELDS: [&str; 7] = [
    "element_id",
    "target",
    "text",
    "write_mode",
    "role_filter",
    "text_filter",
    "zoom",
];
#[cfg(test)]
pub(crate) const WRITE_TEXT_REQUIRED: [&str; 3] = ["element_id", "text", "write_mode"];

/// The optional `target` an element action carries.
fn optional_target(object: &serde_json::Map<String, Value>) -> Result<Option<String>, Value> {
    match object.get("target") {
        None => Ok(None),
        Some(_) => required_string(object, "target").map(Some),
    }
}

pub(crate) struct ParsedPressElement {
    pub element_ids: Vec<String>,
    pub batch: bool,
    pub target: Option<String>,
    pub view: super::StateView,
}

pub(crate) fn parse_press_element(arguments: &Value) -> Result<ParsedPressElement, Value> {
    let object = object_with_fields(arguments, &PRESS_ELEMENT_FIELDS)?;
    let batch = object.contains_key("element_ids");
    let element_ids = match (object.get("element_id"), object.get("element_ids")) {
        (Some(_), Some(_)) => return Err(invalid("element_ids", "mutually_exclusive")),
        (Some(_), None) => vec![required_string(object, "element_id")?],
        (None, Some(Value::Array(ids))) if !ids.is_empty() && ids.len() <= 8 => ids
            .iter()
            .map(|id| {
                id.as_str()
                    .filter(|id| !id.trim().is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("element_ids", "wrong_type"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        (None, Some(Value::Array(_))) => return Err(invalid("element_ids", "out_of_bounds")),
        (None, Some(_)) => return Err(invalid("element_ids", "wrong_type")),
        (None, None) => return Err(invalid("element_id", "missing_field")),
    };
    Ok(ParsedPressElement {
        element_ids,
        batch,
        target: optional_target(object)?,
        view: super::parse_state_view(object)?,
    })
}

pub(crate) struct ParsedPressPoint {
    pub image_id: String,
    pub target: Option<String>,
    pub x: u64,
    pub y: u64,
}

pub(crate) fn parse_press_point(arguments: &Value) -> Result<ParsedPressPoint, Value> {
    let object = object_with_fields(arguments, &PRESS_POINT_FIELDS)?;
    super::parse_state_view(object)?;
    let image_id = required_string(object, "image_id")?;
    let target = optional_target(object)?;
    let coordinate = |field: &str| match object.get(field) {
        Some(value) => value.as_u64().ok_or_else(|| invalid(field, "wrong_type")),
        None => Err(invalid(field, "missing_field")),
    };
    Ok(ParsedPressPoint {
        image_id,
        target,
        x: coordinate("x")?,
        y: coordinate("y")?,
    })
}

/// How `write_text` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteMode {
    /// Set the element's whole value.
    ReplaceValue,
    /// Replace the current selection, which is the caret when nothing is
    /// selected.
    InsertAtCaret,
}

pub(crate) struct ParsedWriteText {
    pub element_id: String,
    pub target: Option<String>,
    pub text: String,
    pub mode: WriteMode,
}

pub(crate) fn parse_write_text(arguments: &Value) -> Result<ParsedWriteText, Value> {
    let object = object_with_fields(arguments, &WRITE_TEXT_FIELDS)?;
    super::parse_state_view(object)?;
    let element_id = required_string(object, "element_id")?;
    let target = optional_target(object)?;
    // Empty text is allowed: replacing a value with nothing clears it.
    let text = match object.get("text") {
        Some(Value::String(text)) => text.clone(),
        Some(_) => return Err(invalid("text", "wrong_type")),
        None => return Err(invalid("text", "missing_field")),
    };
    if text.chars().count() > 4_096 {
        return Err(invalid("text", "exceeds_maximum"));
    }
    let mode = match object.get("write_mode") {
        Some(Value::String(mode)) if mode == "replace_value" => WriteMode::ReplaceValue,
        Some(Value::String(mode)) if mode == "insert_at_caret" => WriteMode::InsertAtCaret,
        Some(Value::String(_)) => return Err(invalid("write_mode", "unknown_value")),
        Some(_) => return Err(invalid("write_mode", "wrong_type")),
        None => return Err(invalid("write_mode", "missing_field")),
    };
    Ok(ParsedWriteText {
        element_id,
        target,
        text,
        mode,
    })
}

/// How admitting an action on a session's application ended.
pub(crate) enum SessionAdmission {
    Admitted(ProcessGrant, GrantAdmission),
    /// The session's process is no longer the one answering to its bundle
    /// identity, so its ids and images name nothing.
    Gone,
    /// The grant was refused; the reply says why.
    Refused(Value),
}

/// Hold the app grant for the application an element id or image names, and
/// confirm the process it was read from is still the one running.
///
/// The grant subject is the session's own bundle identity. The generation is
/// checked before asking, so nobody is asked about a process that has gone,
/// and again after a wait, so the action lands on the process the person
/// agreed about.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn admit_session_app(
    management: &ManagementPlane,
    executable: &super::ExecutableReader,
    consent: &ConsentContext,
    cancel: &CancelHandle,
    bundle_identity: &str,
    pid: u32,
    process_generation: &str,
    name_application_on_denial: bool,
) -> SessionAdmission {
    let same_process = |grant: &ProcessGrant| {
        grant.pid == pid && grant.process_generation_evidence == process_generation
    };
    let Ok(grant) = management.resolve_process(bundle_identity) else {
        return SessionAdmission::Gone;
    };
    if !same_process(&grant) {
        return SessionAdmission::Gone;
    }
    // A development build its driver may use is admitted as if an "always"
    // app grant were held: nobody is asked and nothing is stored.
    if super::operator_apps::admits_development_build(
        management,
        &consent.caller,
        executable,
        &grant,
    ) {
        return SessionAdmission::Admitted(grant, GrantAdmission::default());
    }
    let need = management.app_need(bundle_identity, &grant, management.application_name(&grant));
    let admission = match management
        .computer_grants()
        .require(&need, consent, cancel)
        .await
    {
        Ok(admission) => admission,
        Err(ConsentRefusal::Cancelled) => {
            return SessionAdmission::Refused(json!({
                "outcome": "cancelled",
                "remedy": "the call was cancelled while it waited for the person; nothing was done",
            }))
        }
        Err(refusal) => {
            return SessionAdmission::Refused(
                refusal.reply(name_application_on_denial.then_some(bundle_identity)),
            )
        }
    };
    let grant = if admission.waited {
        match management.resolve_process(bundle_identity) {
            Ok(grant) if same_process(&grant) => grant,
            _ => return SessionAdmission::Gone,
        }
    } else {
        grant
    };
    SessionAdmission::Admitted(grant, admission)
}

/// The role as the journal may record it: an accessibility role constant, or
/// `AXUnknown`. A role is a string the application supplies, and the journal
/// never records application text.
fn journal_role(facts: Option<&ElementFacts>) -> &'static str {
    const KNOWN_ROLES: &[&str] = &[
        "AXApplication",
        "AXBrowser",
        "AXBusyIndicator",
        "AXButton",
        "AXCell",
        "AXCheckBox",
        "AXColorWell",
        "AXColumn",
        "AXComboBox",
        "AXDateField",
        "AXDisclosureTriangle",
        "AXDockItem",
        "AXDrawer",
        "AXGrid",
        "AXGroup",
        "AXGrowArea",
        "AXHelpTag",
        "AXImage",
        "AXIncrementor",
        "AXLayoutArea",
        "AXLayoutItem",
        "AXLevelIndicator",
        "AXLink",
        "AXList",
        "AXMatte",
        "AXMenu",
        "AXMenuBar",
        "AXMenuBarItem",
        "AXMenuButton",
        "AXMenuItem",
        "AXOutline",
        "AXPopUpButton",
        "AXPopover",
        "AXProgressIndicator",
        "AXRadioButton",
        "AXRadioGroup",
        "AXRelevanceIndicator",
        "AXRow",
        "AXRuler",
        "AXRulerMarker",
        "AXScrollArea",
        "AXScrollBar",
        "AXSheet",
        "AXSlider",
        "AXSplitGroup",
        "AXSplitter",
        "AXStaticText",
        "AXSystemWide",
        "AXTabGroup",
        "AXTable",
        "AXTextArea",
        "AXTextField",
        "AXToolbar",
        "AXValueIndicator",
        "AXWebArea",
        "AXWindow",
    ];
    let role = facts.and_then(|facts| facts.role.as_deref());
    KNOWN_ROLES
        .iter()
        .copied()
        .find(|known| Some(*known) == role)
        .unwrap_or("AXUnknown")
}

fn descriptor(capability: ComputerCapability) -> ComputerPlaneDescriptor {
    ComputerPlaneDescriptor::new(
        capability,
        ContainmentRung::SemanticElement,
        ObservationState::HumanUnobserved,
    )
}

/// The journal side of one element action: which capability, which element
/// by its session id, the element's role and how it ended. Never the text
/// written, never a label or value.
pub(crate) struct ElementJournal<'a, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    /// The call's handle on the shared audit: each step locks it briefly.
    /// The intent's commit first asks the call's dispatch gate, so a call
    /// already answered sends nothing.
    pub audit: AuditToken<R, T, S>,
    pub identity: JournalIdentity,
    pub capability: ComputerCapability,
    grant: &'a ProcessGrant,
    pending: Option<(DispatchCommitmentToken, String)>,
    recorded: bool,
    /// How the action used the front of the screen, written under
    /// `fronting` in the rows this journal finalizes or rejects.
    fronting: Option<FrontingRecord>,
    /// A refusal held back until [`ElementJournal::finish`], for a press made
    /// while its application was brought forward: the row then records how
    /// that front ended, which is known only after the restore decision.
    held_refusal: Option<(String, String)>,
    hold_refusals: bool,
    pub(super) effects: ActionEffects,
}

impl<'a, R, T, S> ElementJournal<'a, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    pub(crate) fn new(
        audit: AuditToken<R, T, S>,
        identity: JournalIdentity,
        capability: ComputerCapability,
        grant: &'a ProcessGrant,
    ) -> Self {
        Self {
            audit,
            identity,
            capability,
            grant,
            pending: None,
            recorded: false,
            fronting: None,
            held_refusal: None,
            hold_refusals: false,
            effects: ActionEffects::default(),
        }
    }

    /// Record `fronting` on the rows written from now on.
    pub(crate) fn set_fronting(&mut self, fronting: FrontingRecord) {
        self.fronting = Some(fronting);
    }

    /// Hold a refusal back until `finish`, so its row carries the fronting
    /// set by then.
    pub(crate) fn hold_refusals(&mut self) {
        self.hold_refusals = true;
    }

    fn with_fronting(&self, mut row: Value) -> Vec<u8> {
        if let Some(fronting) = &self.fronting {
            row["fronting"] = json!(fronting);
        }
        row.to_string().into_bytes()
    }

    /// Record a refusal decided after the element was found, before anything
    /// was sent to it.
    fn refused(&mut self, role: &str, outcome: &str) -> Result<(), ()> {
        self.recorded = true;
        if self.hold_refusals {
            self.held_refusal = Some((role.to_owned(), outcome.to_owned()));
            return Ok(());
        }
        self.write_refusal(role, outcome)
    }

    fn write_refusal(&mut self, role: &str, outcome: &str) -> Result<(), ()> {
        let material = self
            .with_fronting(json!({"outcome": outcome, "role": role, "grant_identity": self.grant}));
        self.audit
            .reject(self.identity.clone(), descriptor(self.capability), material)
            .map_err(|_| ())
    }

    /// Record what is about to be sent, before it is sent.
    pub(super) fn intent(
        &mut self,
        grant: &ProcessGrant,
        element_id: &str,
        action: &str,
        role: &str,
    ) -> Result<DispatchCommitmentToken, IntentRefused> {
        let descriptor = descriptor(self.capability);
        let identity = self.identity.clone();
        let handle = self
            .audit
            .with_audit(|audit| audit.reserve(identity, descriptor.clone()))
            .map_err(|_| IntentRefused::AuditUnavailable)?;
        // Ask the call's dispatch gate before committing the intent: the call
        // may have been answered (deadline, cancel, drain) while this worker
        // ran, and then nothing more is sent.
        if !self.audit.gate().begin_mutation() {
            self.recorded = true;
            let _ = self.audit.finalize_rejected(
                handle,
                json!({"outcome": "dispatch_stopped", "role": role, "grant_identity": grant})
                    .to_string()
                    .into_bytes(),
            );
            return Err(IntentRefused::Stopped);
        }
        self.audit
            .with_audit(|audit| {
                audit.commit_actuation_intent(
                    handle,
                    &descriptor,
                    &ActuationIntent {
                        element: Some(ActuationElementIdentity {
                            matched_by: AccessibilityElementName::Identifier(
                                element_id.to_string(),
                            ),
                            alternate_name: None,
                        }),
                        action: format!("{action} {role}"),
                        grant_identity: grant.clone(),
                    },
                )
            })
            .map_err(|_| IntentRefused::AuditUnavailable)
    }

    pub(super) fn outcome(
        &mut self,
        token: DispatchCommitmentToken,
        outcome: &str,
    ) -> Result<(), ()> {
        // The post-action diff also reads the tree and may re-enable a renderer.
        // Finalize after that read so its state change stays on this action's row.
        self.pending = Some((token, outcome.to_string()));
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<(), ()> {
        if let Some((role, outcome)) = self.held_refusal.take() {
            self.write_refusal(&role, &outcome)
        } else if let Some((token, outcome)) = self.pending.take() {
            let result = self.with_fronting(json!({"outcome": outcome}));
            self.audit
                .finalize_dispatched(token, result, Vec::new())
                .map_err(|_| ())
        } else if !self.recorded
            && cerebellum_computer::audit::AccessibilityReadScope::current().is_some()
        {
            self.audit
                .record_accessibility_read(
                    self.identity.clone(),
                    self.capability,
                    self.grant,
                    || (),
                )
                .map_err(|_| ())
        } else {
            Ok(())
        }
    }
}

/// Why an element action's intent was not committed.
pub(super) enum IntentRefused {
    /// The journal could not record the intent, so nothing is sent.
    AuditUnavailable,
    /// The call was answered before the action could start.
    Stopped,
}

impl IntentRefused {
    pub(super) fn reply(self) -> Value {
        match self {
            Self::AuditUnavailable => audit_unavailable_reply(false),
            Self::Stopped => super::quarantine::stopped_before_dispatch_reply(),
        }
    }
}

/// The actions an element advertises, as a refusal may name them: only the
/// standard accessibility action constants, with any other name counted
/// rather than quoted, since an application can name a custom action with any
/// text it likes.
fn describe_actions(actions: &[String]) -> String {
    let standard: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|action| {
            action.len() <= 48
                && action.strip_prefix("AX").is_some_and(|rest| {
                    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphabetic())
                })
        })
        .collect();
    let custom = actions.len() - standard.len();
    let mut described = if standard.is_empty() {
        "no standard actions".to_string()
    } else {
        standard.join(", ")
    };
    if custom > 0 {
        described.push_str(&format!(" and {custom} custom action(s)"));
    }
    described
}

/// Whether an element, as it is now, is a session-ending menu item. Checked
/// at press time as well as when the tree is rendered, because a hit test
/// finds elements no rendered tree showed and a title can change after a read.
fn is_blocked_menu_item(facts: &ElementFacts) -> bool {
    matches!(facts.role.as_deref(), Some("AXMenuItem" | "AXMenuBarItem"))
        && facts.title.as_deref().is_some_and(is_session_ending_title)
}

fn is_menu_bar_command(
    source: &dyn AppStateSource,
    facts: &ElementFacts,
    handle: &ElementHandle,
) -> bool {
    if facts.role.as_deref() != Some("AXMenuItem") {
        return false;
    }
    let mut current = handle.clone();
    for role in ["AXMenu", "AXMenuBarItem", "AXMenuBar"] {
        let Ok(Some(parent)) = source.element_parent(&current) else {
            return false;
        };
        let Ok(parent_facts) = source.element_facts(&parent) else {
            return false;
        };
        if parent_facts.role.as_deref() != Some(role)
            || matches!((facts.pid, parent_facts.pid), (Some(item), Some(owner)) if item != owner)
        {
            return false;
        }
        current = parent;
    }
    true
}

fn press_available(
    source: &dyn AppStateSource,
    facts: &ElementFacts,
    handle: &ElementHandle,
    capability: ComputerCapability,
) -> Result<&'static str, Value> {
    if is_blocked_menu_item(facts) {
        return Err(blocked_menu_item_reply());
    }
    // On ordinary content AXShowMenu opens a context menu, not the element's
    // primary action. Use it only for controls whose role is to open a menu.
    let action = if facts.actions.iter().any(|action| action == "AXPress") {
        "AXPress"
    } else if matches!(
        facts.role.as_deref(),
        Some("AXPopUpButton" | "AXMenuButton" | "AXComboBox")
    ) && facts.actions.iter().any(|action| action == "AXShowMenu")
    {
        "AXShowMenu"
    } else {
        return Err(json!({
            "outcome": "no_press_action",
            "reason": "press_not_offered",
            "remedy": format!(
                "this element offers {}, not a press for this role; nothing was done and the \
                 pointer was not used. Choose a nearby element that can be pressed, or call \
                 read_state for a fresh read",
                describe_actions(&facts.actions)
            ),
        }));
    };
    if capability == ComputerCapability::PressElement
        && source.reports_screen_geometry()
        && !super::action_effects::has_screen_position(source, handle)
        // Closed menu bar commands have no position but still accept AXPress.
        && !is_menu_bar_command(source, facts, handle)
    {
        return Err(json!({
            "outcome": "no_press_action",
            "remedy": "this element isn't visible on screen, so its effect can't be seen; nothing was pressed. Call read_state and choose a visible element, or ask the person",
        }));
    }
    Ok(action)
}

/// Activate one element, preferring a press to opening its menu, and journal
/// the action sent. The caller adds the observed diff to a completed reply.
pub(crate) fn press_blocking<R, T, S>(
    source: &dyn AppStateSource,
    journal: &mut ElementJournal<'_, R, T, S>,
    grant: &ProcessGrant,
    element_id: &str,
    handle: &ElementHandle,
) -> Value
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    let facts = match source.element_facts(handle) {
        Ok(facts) if facts.pid.is_none_or(|pid| pid == grant.pid) => facts,
        _ => return stale_element_reply(),
    };
    let role = journal_role(Some(&facts));
    let action = match press_available(source, &facts, handle, journal.capability) {
        Ok(action) => action,
        Err(reply) => {
            if journal
                .refused(role, reply["outcome"].as_str().expect("refusal outcome"))
                .is_err()
            {
                return audit_unavailable_reply(false);
            }
            return reply;
        }
    };
    // Read just before dispatch, after the checks above: an action on an
    // element the application reports disabled does nothing, and saying so is
    // better than a completed reply with no effect. An unreadable state is
    // unknown, not disabled, so dispatch is still allowed.
    if source.element_enabled(handle) == Some(false) {
        if journal.refused(role, "element_disabled").is_err() {
            return audit_unavailable_reply(false);
        }
        let background = source
            .frontmost_pid()
            .is_some_and(|frontmost| frontmost != grant.pid);
        return element_disabled_reply(facts.title.as_deref(), element_id, background);
    }
    let token = match journal.intent(grant, element_id, action, role) {
        Ok(token) => token,
        Err(refused) => return refused.reply(),
    };
    journal.effects = ActionEffects::before(source, grant);
    let dispatched = match action {
        "AXShowMenu" => source.show_menu(handle),
        _ => source.press(handle),
    };
    journal.effects.sample(source, grant);
    let (outcome, reply) = match dispatched {
        Ok(()) => ("completed", json!({"outcome": "completed"})),
        // The action was sent and no answer came back in time: it may have
        // happened, so this is never a refusal that is safe to retry.
        Err(ElementActionError::Indeterminate) => (
            "dispatch_outcome_unknown",
            json!({
                "outcome": "dispatch_outcome_unknown",
                "effect_status": "effect_indeterminate",
                "detail": {
                    "reason": "application_did_not_answer",
                    "dispatched": true,
                    "step": "dispatch",
                    "call": action,
                    "held_state": "none_held",
                },
                "remedy": "read the state before retrying",
            }),
        ),
        Err(ElementActionError::Gone) => ("stale_element", stale_element_reply()),
        Err(_) => (
            "no_press_action",
            json!({
                "outcome": "no_press_action",
                "reason": "press_refused",
                "remedy": if action == "AXShowMenu" {
                    "the application refused to open the menu; read the state to see whether \
                     anything changed before trying again"
                } else {
                    "the application refused the press; read the state to see whether \
                     anything changed before trying again"
                },
            }),
        ),
    };
    if journal.outcome(token, outcome).is_err() {
        return audit_unavailable_reply(true);
    }
    reply
}

/// The byte offset in `text` of a position counted in UTF-16 code units, the
/// way the accessibility API counts a selection. `None` when the position is
/// past the end or inside a character.
fn utf16_to_byte_offset(text: &str, utf16: usize) -> Option<usize> {
    let mut units = 0;
    for (byte, character) in text.char_indices() {
        if units == utf16 {
            return Some(byte);
        }
        units += character.len_utf16();
        if units > utf16 {
            return None;
        }
    }
    (units == utf16).then_some(text.len())
}

/// What the value must read back as after inserting `text` over the
/// selection `(start, length)` of `before`.
pub(crate) fn expected_after_insert(
    before: &str,
    selection: (usize, usize),
    text: &str,
) -> Option<String> {
    let start = utf16_to_byte_offset(before, selection.0)?;
    let end = utf16_to_byte_offset(before, selection.0.checked_add(selection.1)?)?;
    Some(format!("{}{}{}", &before[..start], text, &before[end..]))
}

/// Write text into one element, journaling the attempt, and confirm it by
/// reading the value back until it matches or `readback_bound` passes.
///
/// Native fields may update asynchronously, so confirmation polls their value.
/// Web editors must never receive AXValue or AXSelectedText writes: those can
/// bypass the editor's state and leave the visible text impossible to edit.
pub(crate) fn write_blocking<R, T, S>(
    source: &dyn AppStateSource,
    journal: &mut ElementJournal<'_, R, T, S>,
    grant: &ProcessGrant,
    handle: &ElementHandle,
    request: &ParsedWriteText,
    readback_bound: Duration,
) -> Value
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    let ParsedWriteText {
        element_id,
        text,
        mode,
        target: _,
    } = request;
    let (element_id, text, mode) = (element_id.as_str(), text.as_str(), *mode);
    let facts = match source.element_facts(handle) {
        Ok(facts) if facts.pid.is_none_or(|pid| pid == grant.pid) => facts,
        _ => return stale_element_reply(),
    };
    let role = journal_role(Some(&facts));
    // Decided before anything is written: a secure field is refused whatever
    // else about it would allow the write.
    if facts.is_secure() {
        if journal.refused(role, "secure_field_refused").is_err() {
            return audit_unavailable_reply(false);
        }
        return json!({
            "outcome": "secure_field_refused",
            "remedy": "this is a secure text field; nothing was written. Ask the person to fill \
                       it in themselves",
        });
    }
    match web_ancestry(source, grant, handle) {
        Some(true) => {
            if journal.refused(role, "web_content_needs_type").is_err() {
                return audit_unavailable_reply(false);
            }
            return json!({
                "outcome": "web_content_needs_type",
                "reason": "web_content_needs_type",
                "remedy": "web editors must be typed into; press_element the field to place the caret, then use type, which appends at the caret and confirms by readback. To replace the whole text, press_element the field, then write_text with write_mode replace_value",
            });
        }
        Some(false) => {}
        None => return stale_element_reply(),
    }
    let (settable, attribute, action) = match mode {
        WriteMode::ReplaceValue => (facts.value_settable, TextAttribute::Value, "AXValue"),
        WriteMode::InsertAtCaret => (
            facts.selected_text_settable,
            TextAttribute::SelectedText,
            "AXSelectedText",
        ),
    };
    if !settable {
        if journal.refused(role, "element_not_settable").is_err() {
            return audit_unavailable_reply(false);
        }
        return json!({
            "outcome": "element_not_settable",
            "remedy": "this element's text cannot be written through accessibility; nothing \
                       was written. Use type with this application as target to send keystrokes \
                       instead, or pick a settable element from read_state",
        });
    }
    let expected = match mode {
        WriteMode::ReplaceValue => text.to_string(),
        WriteMode::InsertAtCaret => {
            let before = source.text_value(handle);
            let selection = source.selected_range(handle);
            match (before, selection) {
                (Ok(Some(before)), Ok(Some(selection))) => {
                    match expected_after_insert(&before, selection, text) {
                        Some(expected) => expected,
                        None => {
                            return caret_unknown(journal, role);
                        }
                    }
                }
                _ => return caret_unknown(journal, role),
            }
        }
    };
    let token = match journal.intent(grant, element_id, action, role) {
        Ok(token) => token,
        Err(refused) => return refused.reply(),
    };
    // One attempt. Whether the application accepted the message or not, the
    // value read back is what decides, and nothing is retried as keystrokes.
    journal.effects = ActionEffects::before(source, grant);
    let written = source.write_text(handle, attribute, text);
    journal.effects.sample(source, grant);
    let deadline = Instant::now() + readback_bound;
    let confirmed = written.is_ok()
        && loop {
            journal.effects.sample(source, grant);
            if matches!(source.text_value(handle), Ok(Some(after)) if after == expected) {
                break true;
            }
            let now = Instant::now();
            if now >= deadline {
                break false;
            }
            std::thread::sleep(SETTLE_POLL.min(deadline - now));
        };
    let (outcome, reply) = if confirmed {
        (
            "completed",
            json!({"outcome": "completed", "effect_status": "effect_observed"}),
        )
    } else {
        (
            "delivery_unconfirmed",
            json!({
                "outcome": "delivery_unconfirmed",
                "effect_status": "effect_indeterminate",
                "reason": if written.is_err() { "write_refused" } else { "readback_mismatch" },
                "remedy": "the element's value did not read back as the write should have left \
                           it; read the state before writing again, and do not retry by typing",
            }),
        )
    };
    if journal.outcome(token, outcome).is_err() {
        return audit_unavailable_reply(true);
    }
    reply
}

/// Follow only the addressed element's parents. Unlike a whole-app read,
/// these reads do not enable renderer accessibility through AXManualAccessibility.
/// Native and web fields can expose the same role, so an unknown or cyclic
/// ancestry must not be treated as native.
pub(super) fn web_ancestry(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
    handle: &ElementHandle,
) -> Option<bool> {
    let mut current = handle.clone();
    let mut visited: Vec<ElementHandle> = Vec::new();
    for _ in 0..64 {
        if visited.iter().any(|old| old.same_element(current.as_ref())) {
            return None;
        }
        let facts = source.element_facts(&current).ok()?;
        if facts.pid.is_some_and(|pid| pid != grant.pid) {
            return None;
        }
        match facts.role.as_deref()? {
            "AXWebArea" => return Some(true),
            "AXWindow" | "AXApplication" => return Some(false),
            _ => {}
        }
        let parent = source.element_parent(&current).ok()??;
        visited.push(current);
        current = parent;
    }
    None
}

fn caret_unknown<R, T, S>(journal: &mut ElementJournal<'_, R, T, S>, role: &str) -> Value
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    if journal.refused(role, "caret_position_unknown").is_err() {
        return audit_unavailable_reply(false);
    }
    json!({
        "outcome": "caret_position_unknown",
        "remedy": "the element's value or selection could not be read, so an insert could not be \
                   confirmed; nothing was written. Use write_mode replace_value instead",
    })
}

/// The result of hit-testing a point of an image.
pub(crate) enum PointHit {
    Element(ElementHandle),
    Nothing,
}

/// Find the element of the session's own application at a desktop point.
///
/// The hit test is scoped to that application, so an element of another
/// application on top of it is not what is found; an element reported as
/// belonging to another process anyway is treated as no hit.
pub(crate) fn hit_test(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
    point: (f64, f64),
) -> PointHit {
    match source.element_at(HitScope::Application { pid: grant.pid }, point) {
        Ok(Some((handle, owner))) if owner.is_none_or(|owner| owner == grant.pid) => {
            PointHit::Element(handle)
        }
        _ => PointHit::Nothing,
    }
}

/// Give a hit element an id in the session so the diff can name it.
pub(crate) fn adopt(
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
    handle: &ElementHandle,
) -> Result<String, Value> {
    match sessions.adopt(conversation_key, grant, handle) {
        Adoption::Numbered(id) => Ok(id),
        Adoption::Refusing => Err(blocked_menu_item_reply()),
        // Still pressable; it just cannot be named in the diff.
        Adoption::Full | Adoption::NoSession => Ok("unnumbered".to_string()),
    }
}

/// Whether a settle watches for the person's input while it polls.
pub(crate) enum PersonWatch<'a> {
    /// The action did not bring the application to the front, so the
    /// person's input goes where they aim it and is left to the next person
    /// check. Each read keeps the ordinary read budget
    /// ([`ReadBounds::default`]): a shorter one returns partial trees from
    /// slow applications such as Finder, and a partial tree would show up as
    /// removed lines in the reply and become the next baseline.
    NotWatched,
    /// The application is in front for this action. The closure is asked
    /// before and after every read and answers `true` once the person has
    /// acted; the settle then returns at once so the caller can restore.
    Watched(&'a mut dyn FnMut() -> bool),
    /// Not in front, as [`Self::NotWatched`], but the call may be answered
    /// while the settle runs. The closure is asked before and after every
    /// read and answers `true` once the call has been stopped; the settle then
    /// returns `None` without reading again, so an answered call's worker
    /// does not keep its application marked busy.
    StopWhen(&'a dyn Fn() -> bool),
}

/// The element an action pressed, watched while the settle waits.
///
/// Some applications show a press on the pressed element itself a frame or
/// two after they redraw something else (a tab's value turns true after the
/// focus moved). Watching the element's own line lets the settle wait for
/// that, rather than stopping at the first redraw and replying before the
/// press shows.
#[derive(Clone, Copy)]
pub(crate) struct PressedElement<'a> {
    /// The element's id in the conversation's session, which names its line
    /// in the read taken before the press.
    pub(crate) element_id: &'a str,
    pub(crate) handle: &'a ElementHandle,
}

/// How far an action reply's "no change" can be trusted when its diff shows
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmptyDiff {
    /// The settle ran its whole bound without seeing a difference, and the
    /// last read was complete and equal to the read before the action.
    Confirmed,
    /// The settle stopped early on a difference the diff does not show, or
    /// its last read was partial: the effect may still be arriving.
    Unconfirmed,
    /// The pressed element's own line changed, but the read the diff comes
    /// from does not show its new line.
    PressedElementChanged,
}

/// What a settle saw after an action: the read the reply's diff comes from,
/// and how far an empty diff in it can be trusted.
#[derive(Debug, Clone)]
pub(crate) struct SettledView {
    pub(crate) read: SessionRead,
    pub(crate) empty_diff: EmptyDiff,
}

/// Wait for an effect without moving the baseline during polling. Only the
/// final read becomes the baseline and the conversation's last-seen focus,
/// so the reply's diff is always against the read taken before the action.
///
/// Without a pressed element to watch, the settle stops at the first read
/// that differs from that baseline. With one whose line the baseline holds,
/// it reads that element alone before each whole read, stops as soon as the
/// element's own line has changed, and otherwise stops on a difference only
/// once two reads in a row show the same tree: a redraw elsewhere can come a
/// frame before the press shows on the element.
///
/// With [`PersonWatch::Watched`], the settle returns without another read
/// once the person has acted. There is no final diff after interruption: an
/// AX read would delay the restore and could absorb the person's input into
/// the baseline. Each watched read is bounded by the time left in the settle
/// window, so the application is not held in front for the ordinary
/// four-second read budget, and a read that stops at that bound is partial:
/// it is neither shown nor adopted as the baseline, and the settle returns
/// `None` (no diff) rather than a wrong diff.
#[allow(clippy::too_many_arguments)]
pub(crate) fn settle_and_observe_view(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
    bound: Duration,
    expand_menus: bool,
    mut watch: PersonWatch<'_>,
    pressed: Option<PressedElement<'_>>,
    mut effects: Option<&mut ActionEffects>,
) -> Option<SettledView> {
    let deadline = Instant::now() + bound;
    let watched = matches!(watch, PersonWatch::Watched(_));
    let mut person_acted = || match &mut watch {
        PersonWatch::NotWatched => false,
        PersonWatch::Watched(acted) => acted(),
        PersonWatch::StopWhen(stopped) => stopped(),
    };
    let before = sessions.latest(conversation_key, grant);
    let had_baseline = before.is_some();
    // The pressed element's line in the read before the press. Without it
    // there is nothing to compare the element against, so it is not watched.
    let pressed_before = pressed.and_then(|pressed| {
        let line = line_signature(&before.as_ref()?.roots, pressed.element_id)?;
        Some((pressed, line))
    });
    let mut previous_tree: Option<Vec<(u64, String)>> = None;
    loop {
        let interrupted = person_acted();
        if interrupted {
            return None;
        }
        let pressed_changed = pressed_before.as_ref().is_some_and(|(pressed, line)| {
            pressed_line_now(source, grant, pressed.handle, deadline)
                .is_some_and(|now| now != *line)
        });
        let seen = SeenMarks::read(source, grant);
        let bounds = if watched {
            ReadBounds {
                timeout: deadline.saturating_duration_since(Instant::now()),
                ..ReadBounds::default()
            }
        } else {
            ReadBounds::default()
        };
        let raw = if expand_menus {
            source.read_app_state_expanding_menus(grant, bounds)
        } else {
            source.read_app_state(grant, bounds)
        };
        if let Some(effects) = effects.as_deref_mut() {
            effects.sample(source, grant);
        }
        if person_acted() {
            return None;
        }
        match raw {
            // Only the shortened watched bound is treated as truncation.
            // Unreadable subtrees are not caused by that bound and are
            // adopted as before.
            Ok(read) if watched && read.read_bound_reached => return None,
            Ok(read) => {
                let at_deadline = Instant::now() >= deadline;
                let differs = sessions.differs_from_baseline(conversation_key, grant, &read);
                let tree = pressed_before.is_some().then(|| tree_lines(&read));
                let stopped_changing = differs && tree.is_some() && tree == previous_tree;
                let done = at_deadline
                    || pressed_changed
                    || if pressed_before.is_some() {
                        stopped_changing
                    } else {
                        differs
                    };
                if done {
                    let observed = sessions.observe(conversation_key, grant, &read);
                    let seen = SeenMarks {
                        after_agent_input: true,
                        ..seen
                    };
                    sessions.remember_seen(conversation_key, grant, seen);
                    let pressed_shown = pressed_before.as_ref().is_some_and(|(pressed, _)| {
                        let id = pressed.element_id;
                        observed.diff.changed.iter().any(|changed| changed == id)
                            || observed.diff.added.iter().any(|added| added == id)
                    });
                    let empty_diff = if pressed_changed && !pressed_shown {
                        EmptyDiff::PressedElementChanged
                    } else if !read.is_complete() {
                        EmptyDiff::Unconfirmed
                    } else if !had_baseline {
                        // With no earlier read the diff is empty by
                        // construction; a complete read is all there is.
                        EmptyDiff::Confirmed
                    } else if at_deadline && !differs && !pressed_changed {
                        EmptyDiff::Confirmed
                    } else {
                        EmptyDiff::Unconfirmed
                    };
                    return Some(SettledView {
                        read: observed,
                        empty_diff,
                    });
                }
                previous_tree = tree;
            }
            // Nothing could be read, so nothing is known about what changed.
            Err(_) => return None,
        }
        std::thread::sleep(SETTLE_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// The line signature an element had in a read, found by its id.
fn line_signature(
    roots: &[cerebellum_computer::app_state::render::ObservedNode],
    element_id: &str,
) -> Option<String> {
    let mut stack: Vec<_> = roots.iter().collect();
    while let Some(node) = stack.pop() {
        if node.element_id.as_deref() == Some(element_id) {
            return Some(node.description.signature());
        }
        stack.extend(&node.children);
    }
    None
}

/// The pressed element's line as it reads now, from a read of that element
/// alone (no children), bounded by the time left in the settle. `None` when
/// the time is up or the element cannot be read.
fn pressed_line_now(
    source: &dyn AppStateSource,
    grant: &ProcessGrant,
    handle: &ElementHandle,
    deadline: Instant,
) -> Option<String> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return None;
    }
    let bounds = ReadBounds {
        max_elements: 1,
        max_depth: 0,
        timeout,
    };
    let read = source
        .read_element_state(grant, handle, bounds, false)
        .ok()?;
    let element = read.roots.first()?;
    Some(cerebellum_computer::app_state::render::describe(element).signature())
}

/// Every element of a read with its line, in reading order: two reads with
/// the same lines show the same tree, so the application has stopped
/// changing between them.
fn tree_lines(read: &cerebellum_computer::app_state::source::RawAppState) -> Vec<(u64, String)> {
    let mut lines = Vec::new();
    let mut stack: Vec<_> = read.roots.iter().rev().collect();
    while let Some(element) = stack.pop() {
        lines.push((
            element.handle.identity_hash(),
            cerebellum_computer::app_state::render::describe(element).signature(),
        ));
        stack.extend(element.children.iter().rev());
    }
    lines.push((read.unreadable_subtrees as u64, String::new()));
    lines
}

/// What an action reply says when the application could not be read after
/// the action: nothing is known of what changed, which is not "nothing
/// changed".
const DIFF_UNREADABLE: &str =
    "The application could not be read after the action, so what changed is unknown; \
     read_state to see its state.\n";

/// The line the read grammar gives a diff with nothing in it. Kept only when
/// the settle confirmed it ([`EmptyDiff::Confirmed`]).
pub(crate) const NO_CHANGE_SEEN: &str = "No change seen since the last read.\n";

/// What an empty diff says instead when the settle could not confirm that
/// nothing changed: it stopped on a difference the diff does not show, or
/// its last read was partial.
pub(crate) const CHANGE_UNCONFIRMED: &str =
    "No change confirmed yet: the application was still updating, or could not be read in \
     full, when this reply was taken, so the action's effect may not show here yet. \
     read_state again before acting or pressing again.\n";

/// What a reply adds when the pressed element's own line changed but the
/// read its diff comes from does not show the new line.
pub(crate) const PRESSED_ELEMENT_CHANGED: &str =
    "The pressed element's own state changed, but the read after the press did not show \
     its new line. read_state to see it before acting or pressing again.\n";

/// Add what an action changed to its reply, as text in the read grammar,
/// with the cap's disclosure, the focused element and how much of the read
/// behind it could not be opened.
#[cfg(test)]
pub(crate) fn add_diff(reply: &mut Value, observed: Option<&SettledView>) {
    add_diff_view(reply, observed, &super::StateView::default());
}

pub(crate) fn add_diff_view(
    reply: &mut Value,
    settled: Option<&SettledView>,
    view: &super::StateView,
) {
    let Some(settled) = settled else {
        reply[STATE_TEXT_FIELD] = json!(DIFF_UNREADABLE);
        reply["unreadable_subtrees"] = json!(1);
        return;
    };
    let observed = &settled.read;
    use cerebellum_computer::app_state::render::{render_change_report, render_diff, StateHeader};
    let rendered = render_change_report(
        &StateHeader {
            app_name: "Application state",
            focused_element_id: observed.focused_element_id.as_deref(),
        },
        observed,
        &view.request(),
    );
    reply["state_report"] = json!(rendered.kind);
    if view.zoom.is_some() {
        reply["zoom_found"] = json!(rendered.zoom_found);
    }
    let mut text = rendered.text;
    if rendered.kind == "diff" {
        // "No change seen" is a claim that the read after the action equals
        // the read before it; it stays only where the settle confirmed that.
        let empty = text.starts_with(NO_CHANGE_SEEN);
        match (settled.empty_diff, empty) {
            (EmptyDiff::Confirmed, _) => {}
            (EmptyDiff::Unconfirmed, true) => {
                text.replace_range(..NO_CHANGE_SEEN.len(), CHANGE_UNCONFIRMED);
            }
            (EmptyDiff::PressedElementChanged, true) => {
                text.replace_range(..NO_CHANGE_SEEN.len(), PRESSED_ELEMENT_CHANGED);
            }
            (EmptyDiff::PressedElementChanged, false) => text.push_str(PRESSED_ELEMENT_CHANGED),
            (EmptyDiff::Unconfirmed, false) => {}
        }
    } else if view.zoom.is_some() || !view.roles.is_empty() || view.text.is_some() {
        // A requested slice can hide every changed line. Use the same settled
        // read as the ordinary diff, not another read or just the matches.
        let diff = render_diff(
            &observed.roots,
            &observed.diff,
            observed.focused_element_id.as_deref(),
        );
        let status = if diff.text.starts_with(NO_CHANGE_SEEN) {
            match settled.empty_diff {
                EmptyDiff::Confirmed => NO_CHANGE_SEEN.to_string(),
                EmptyDiff::Unconfirmed => CHANGE_UNCONFIRMED.to_string(),
                EmptyDiff::PressedElementChanged => PRESSED_ELEMENT_CHANGED.to_string(),
            }
        } else {
            // Count change lines, including those omitted by the diff cap,
            // but not the focused-element footer or the cap disclosure.
            let changed = diff
                .text
                .lines()
                .filter(|line| {
                    line.starts_with("+ ")
                        || line.starts_with("~ ")
                        || line.starts_with("Removed element IDs: ")
                })
                .count()
                + diff.truncation.map_or(0, |cap| cap.omitted_elements);
            let lines = if changed == 1 { "line" } else { "lines" };
            let mut status = format!(
                "{changed} {lines} changed; read_state without a filter to see them all.\n"
            );
            if settled.empty_diff == EmptyDiff::PressedElementChanged {
                status.push_str(PRESSED_ELEMENT_CHANGED);
            }
            status
        };
        text.insert_str(0, &status);
    }
    reply[STATE_TEXT_FIELD] = json!(text);
    if let Some(truncation) = rendered.truncation {
        reply["truncation"] = json!({
            "reason": truncation.reason.as_str(),
            "omitted_elements": truncation.omitted_elements,
        });
    }
    if let Some(focused) = &observed.focused_element_id {
        reply["focused_element_id"] = json!(focused);
    }
    reply["unreadable_subtrees"] = json!(observed.unreadable_subtrees);
}

/// Whether an element action's `target` names the application the element
/// belongs to: its bundle identity, or the name it runs under.
///
/// A name is checked against the running applications; when they cannot be
/// read, a name cannot be confirmed or denied and is let through, because
/// the element already decides where the action lands. A bundle identity
/// needs no list to compare.
pub(crate) fn target_names_application(
    source: &dyn AppStateSource,
    target: &str,
    bundle_identity: &str,
    pid: u32,
) -> bool {
    let wanted = target.trim();
    if wanted.eq_ignore_ascii_case(bundle_identity) {
        return true;
    }
    match source.running_apps() {
        Ok(apps) => apps
            .iter()
            .any(|app| app.pid == pid && app.name.trim().eq_ignore_ascii_case(wanted)),
        Err(_) => !super::looks_like_bundle_identity(wanted),
    }
}

/// The refusal for a `target` naming another application than the element's.
pub(crate) fn target_mismatch_reply(target: &str) -> Value {
    json!({
        "outcome": "target_mismatch",
        "target": target,
        "remedy": "target names a different application from the one this element or image \
                   belongs to, so nothing was done; drop target, or use an id read from the \
                   application target names",
    })
}

/// Who presses, for which call, and through which capability.
struct PressCall<'a> {
    identity: JournalIdentity,
    management: &'a ManagementPlane,
    consent: &'a ConsentContext,
    cancel: &'a CancelHandle,
    sessions: Arc<AppStateSessions>,
    capability: ComputerCapability,
}

enum PressTarget {
    Element {
        element_id: String,
        handle: ElementHandle,
    },
    Point {
        point: (f64, f64),
        /// The window-server number of the window the image shows; `None`
        /// when the image was registered without one.
        window_number: Option<u32>,
        /// The application's name, for the refusal's remedy.
        application_name: String,
    },
}

/// Whether the element a point hit sits in the window the image shows.
///
/// The hit test is scoped to the application, not to a window, so it finds
/// the topmost element of that application at the point in any of its
/// windows: with a second window of the same application in front, that is
/// an element the image does not show. Only a positive identification of the
/// hit element's window as the imaged one counts; a window that cannot be
/// read, or an image with no remembered window, is not a match.
pub(crate) fn hit_is_in_imaged_window(
    source: &dyn AppStateSource,
    handle: &ElementHandle,
    window_number: Option<u32>,
) -> bool {
    match window_number {
        Some(expected) => source.element_window_number(handle) == Some(expected),
        None => false,
    }
}

/// The refusal for a point that does not land in the window the image shows,
/// or whose window could not be confirmed. Nothing was pressed or posted.
pub(crate) fn point_in_another_window_reply(application_name: &str, posted: &str) -> Value {
    json!({
        "outcome": "point_in_another_window",
        "remedy": format!(
            "the point lands on a different window of {application_name} than the image shows, \
             or that window could not be confirmed, so {posted}; read the app again and act by \
             element id, or bring that window forward"
        ),
    })
}

impl<B, R, T, S, D> super::ComputerPlane<B, R, T, S, D>
where
    B: cerebellum_computer::capture::CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: cerebellum_computer::platform::PlatformDriver + 'static,
{
    /// `computer.press_element`: press an element named by a state read.
    pub(super) async fn serve_press_element<C: cerebellum_core::clock::MonotonicClock>(
        &self,
        arguments: &Value,
        context: super::ServeContext<'_, C>,
    ) -> Value {
        let parsed = match parse_press_element(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };
        if !parsed.batch {
            return self
                .serve_press_single(
                    &parsed.element_ids[0],
                    parsed.target,
                    parsed.view,
                    context,
                    Vec::new(),
                )
                .await
                .into_reply();
        }
        let sessions = context.management.app_state_sessions();
        let conversation = &context.identity.conversation_key;
        // A batch holds the first application's serialization lane throughout.
        // Refuse a different application's id at its step rather than acting
        // in an application whose lane this call does not own.
        let first = sessions.resolve(conversation, &parsed.element_ids[0]);
        let grant = match first {
            cerebellum_computer::app_state::session::ElementResolution::Live {
                bundle_identity,
                pid,
                process_generation,
                ..
            } => Some(ProcessGrant {
                bundle_identity,
                pid,
                process_generation_evidence: process_generation,
            }),
            _ => None,
        };
        let before = grant
            .as_ref()
            .and_then(|grant| sessions.latest(conversation, grant));
        let mut steps = Vec::new();
        let mut reply = json!({"outcome":"completed"});
        let mut acted = false;
        let mut unreadable = false;
        // Whether any step's own settle left its effect unconfirmed: the
        // combined diff below can then not claim that nothing changed either.
        let mut step_empty_diff = EmptyDiff::Confirmed;
        // A batch brings its application forward at most once: the step that
        // needs it fronts, presses the rest of the batch with the application
        // in front, and makes one restore decision after the last of them.
        let mut batch_ending = None;
        let mut effects = Vec::new();
        let work = super::quarantine::CallWork::current();
        let mut index = 0;
        'steps: while index < parsed.element_ids.len() {
            let id = &parsed.element_ids[index];
            // Once the call has been answered, no later step starts: not its
            // press, and not the reads that would precede it.
            if index > 0 && work.stopped() {
                reply = super::quarantine::stopped_before_dispatch_reply();
                reply["stopped_at"] = json!(index + 1);
                break;
            }
            let different_app = match (grant.as_ref(), sessions.resolve(conversation, id)) {
                (
                    Some(first),
                    cerebellum_computer::app_state::session::ElementResolution::Live {
                        bundle_identity,
                        pid,
                        process_generation,
                        ..
                    },
                ) => {
                    first.bundle_identity != bundle_identity
                        || first.pid != pid
                        || first.process_generation_evidence != process_generation
                }
                _ => false,
            };
            let done = if different_app {
                PressDone::alone(target_mismatch_reply("batch application"))
            } else {
                let later = grant.as_ref().map_or_else(Vec::new, |first| {
                    same_application_steps(
                        sessions,
                        conversation,
                        first,
                        &parsed.element_ids[index + 1..],
                    )
                });
                self.serve_press_single(
                    id,
                    parsed.target.clone(),
                    super::StateView::default(),
                    context.clone(),
                    later,
                )
                .await
            };
            if done.ending.is_some() {
                batch_ending = done.ending;
            }
            for line in done.effects {
                if !effects.contains(&line) {
                    effects.push(line);
                }
            }
            for (offset, step_reply) in std::iter::once(done.reply).chain(done.later).enumerate() {
                let step = index + offset;
                reply = step_reply;
                let success = reply["outcome"] == "completed";
                acted |= success;
                unreadable |= success && reply[STATE_TEXT_FIELD] == DIFF_UNREADABLE;
                let step_text = reply[STATE_TEXT_FIELD].as_str().unwrap_or_default();
                if success && step_text.contains(PRESSED_ELEMENT_CHANGED) {
                    step_empty_diff = EmptyDiff::PressedElementChanged;
                } else if success
                    && step_text.starts_with(CHANGE_UNCONFIRMED)
                    && step_empty_diff == EmptyDiff::Confirmed
                {
                    step_empty_diff = EmptyDiff::Unconfirmed;
                }
                steps.push(json!({
                    "step": step + 1,
                    "element_id": parsed.element_ids[step],
                    "outcome": reply["outcome"],
                }));
                if !success {
                    reply["stopped_at"] = json!(step + 1);
                    break 'steps;
                }
            }
            index = steps.len();
        }
        if acted {
            if unreadable {
                add_diff_view(&mut reply, None, &parsed.view);
            } else if let Some(after) = grant
                .as_ref()
                .and_then(|grant| sessions.latest(conversation, grant))
            {
                let combined = if let Some(before) = before {
                    after.compared_with(&before)
                } else {
                    after
                };
                reply.as_object_mut().unwrap().remove("truncation");
                let empty_diff = if step_empty_diff == EmptyDiff::Confirmed && !combined.complete {
                    EmptyDiff::Unconfirmed
                } else {
                    step_empty_diff
                };
                add_diff_view(
                    &mut reply,
                    Some(&SettledView {
                        read: combined,
                        empty_diff,
                    }),
                    &parsed.view,
                );
            }
        }
        reply["steps"] = json!(steps);
        if let Some(ending) = &batch_ending {
            ending.apply(&mut reply);
        }
        append_lines(&mut reply, &effects);
        reply
    }

    async fn serve_press_single<C: cerebellum_core::clock::MonotonicClock>(
        &self,
        element_id: &str,
        target: Option<String>,
        view: super::StateView,
        context: super::ServeContext<'_, C>,
        later: Vec<PressStep>,
    ) -> PressDone {
        let element_id = element_id.to_owned();
        let super::ServeContext {
            cancel,
            identity,
            management,
            consent,
            ..
        } = context;
        let sessions = management.app_state_sessions().clone();
        let conversation_key = identity.conversation_key.clone();
        let (handle, bundle_identity, pid, generation) =
            match sessions.resolve(&conversation_key, &element_id) {
                cerebellum_computer::app_state::session::ElementResolution::Live {
                    handle,
                    bundle_identity,
                    pid,
                    process_generation,
                } => (handle, bundle_identity, pid, process_generation),
                cerebellum_computer::app_state::session::ElementResolution::Refusing => {
                    return PressDone::alone(blocked_menu_item_reply())
                }
                cerebellum_computer::app_state::session::ElementResolution::Stale => {
                    return PressDone::alone(stale_element_reply())
                }
                cerebellum_computer::app_state::session::ElementResolution::PreviousRun => {
                    return PressDone::alone(previous_run_reply())
                }
            };
        if let Some(refusal) = self.check_target(target, &bundle_identity, pid).await {
            return PressDone::alone(refusal);
        }
        let (grant, admission) = match admit_session_app(
            management,
            &self.process_executable,
            &consent,
            &cancel,
            &bundle_identity,
            pid,
            &generation,
            false,
        )
        .await
        {
            SessionAdmission::Admitted(grant, admission) => (grant, admission),
            SessionAdmission::Gone => return PressDone::alone(stale_element_reply()),
            SessionAdmission::Refused(reply) => return PressDone::alone(reply),
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return PressDone::alone(locked);
        }
        if let Some(mut refusal) = self
            .refuse_if_person_changed(management, &conversation_key, &grant)
            .await
        {
            admission.decorate(&mut refusal);
            return PressDone::alone(refusal);
        }
        let mut done = self
            .press_and_diff(
                PressCall {
                    identity,
                    management,
                    consent: &consent,
                    cancel: &cancel,
                    sessions,
                    capability: ComputerCapability::PressElement,
                },
                grant,
                PressTarget::Element { element_id, handle },
                view,
                later,
            )
            .await;
        admission.decorate(&mut done.reply);
        done
    }

    /// `computer.press_point`: press whatever element of the image's own
    /// application is at a pixel of that image.
    pub(super) async fn serve_press_point<C: cerebellum_core::clock::MonotonicClock>(
        &self,
        arguments: &Value,
        context: super::ServeContext<'_, C>,
    ) -> Value {
        let parsed = match parse_press_point(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };
        let view = super::parse_state_view(arguments.as_object().expect("parsed object"))
            .expect("validated view");
        let super::ServeContext {
            cancel,
            identity,
            management,
            consent,
            ..
        } = context;
        let sessions = management.app_state_sessions().clone();
        let conversation_key = identity.conversation_key.clone();
        let image_unknown = || {
            json!({
                "outcome": "image_reference_unknown",
                "remedy": "this image_id names no image this conversation holds for a running \
                           application; call read_state with include_image and use that image",
            })
        };
        let Some(image) = sessions.resolve_image(&conversation_key, &parsed.image_id) else {
            return image_unknown();
        };
        if let Some(refusal) = self
            .check_target(parsed.target.clone(), &image.bundle_identity, image.pid)
            .await
        {
            return refusal;
        }
        if parsed.x >= u64::from(image.width_px) || parsed.y >= u64::from(image.height_px) {
            return json!({
                "outcome": "point_out_of_bounds",
                "remedy": format!(
                    "the point must lie inside the image, which is {} by {} pixels",
                    image.width_px, image.height_px
                ),
            });
        }
        let (grant, admission) = match admit_session_app(
            management,
            &self.process_executable,
            &consent,
            &cancel,
            &image.bundle_identity,
            image.pid,
            &image.process_generation,
            true,
        )
        .await
        {
            SessionAdmission::Admitted(grant, admission) => (grant, admission),
            SessionAdmission::Gone => return image_unknown(),
            SessionAdmission::Refused(reply) => return reply,
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return locked;
        }
        if let Some(mut refusal) = self
            .refuse_if_person_changed(management, &conversation_key, &grant)
            .await
        {
            admission.decorate(&mut refusal);
            return refusal;
        }
        let point = image
            .mapping
            .pixel_to_desktop(parsed.x as f64, parsed.y as f64);
        let window_number = sessions.image_window(&conversation_key, &parsed.image_id);
        let application_name = management.application_name(&grant);
        let mut reply = self
            .press_and_diff(
                PressCall {
                    identity,
                    management,
                    consent: &consent,
                    cancel: &cancel,
                    sessions,
                    capability: ComputerCapability::PressPoint,
                },
                grant,
                PressTarget::Point {
                    point,
                    window_number,
                    application_name,
                },
                view,
                Vec::new(),
            )
            .await
            .into_reply();
        admission.decorate(&mut reply);
        reply
    }

    /// `computer.write_text`: write text into an element through
    /// accessibility and confirm it by reading the value back.
    pub(super) async fn serve_write_text<C: cerebellum_core::clock::MonotonicClock>(
        &self,
        arguments: &Value,
        context: super::ServeContext<'_, C>,
    ) -> Value {
        let parsed = match parse_write_text(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };
        let view = super::parse_state_view(arguments.as_object().expect("parsed object"))
            .expect("validated view");
        let super::ServeContext {
            cancel,
            identity,
            management,
            consent,
            grantee,
            clock,
            now_ms,
        } = context;
        let sessions = management.app_state_sessions().clone();
        let conversation_key = identity.conversation_key.clone();
        let (handle, bundle_identity, pid, generation) =
            match sessions.resolve(&conversation_key, &parsed.element_id) {
                cerebellum_computer::app_state::session::ElementResolution::Live {
                    handle,
                    bundle_identity,
                    pid,
                    process_generation,
                } => (handle, bundle_identity, pid, process_generation),
                cerebellum_computer::app_state::session::ElementResolution::PreviousRun => {
                    return previous_run_reply()
                }
                // A session-ending menu item has no text to write, and its id
                // was never shown; it names nothing writable.
                _ => return stale_element_reply(),
            };
        if let Some(refusal) = self
            .check_target(parsed.target.clone(), &bundle_identity, pid)
            .await
        {
            return refusal;
        }
        let (grant, admission) = match admit_session_app(
            management,
            &self.process_executable,
            &consent,
            &cancel,
            &bundle_identity,
            pid,
            &generation,
            false,
        )
        .await
        {
            SessionAdmission::Admitted(grant, admission) => (grant, admission),
            SessionAdmission::Gone => return stale_element_reply(),
            SessionAdmission::Refused(reply) => return reply,
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return locked;
        }
        if let Some(mut refusal) = self
            .refuse_if_person_changed(management, &conversation_key, &grant)
            .await
        {
            admission.decorate(&mut refusal);
            return refusal;
        }
        let work = super::quarantine::CallWork::current();
        if let Some(mut busy) = work.bind(&self.serializer.quarantine, &grant).await {
            admission.decorate(&mut busy);
            return busy;
        }
        if parsed.mode == WriteMode::ReplaceValue {
            let source = self.app_state_source.clone();
            let check_grant = grant.clone();
            let check_handle = handle.clone();
            let check_work = work.clone();
            let web = tokio::task::spawn_blocking(move || {
                let _ax = check_work.bound_ax();
                let facts = source.element_facts(&check_handle).ok()?;
                (!facts.is_secure())
                    .then(|| web_ancestry(source.as_ref(), &check_grant, &check_handle))
                    .flatten()
            })
            .await
            .unwrap_or(None);
            if web == Some(true) {
                let replacement = super::web_replace::WebReplacement {
                    element_id: parsed.element_id.clone(),
                    handle,
                    grant: grant.clone(),
                    text: parsed.text.clone(),
                };
                let (capability, mut input) = if parsed.text.is_empty() {
                    (
                        ComputerCapability::Keys,
                        json!({"target": bundle_identity, "keys": ["backspace"]}),
                    )
                } else {
                    (
                        ComputerCapability::Type,
                        json!({"target": bundle_identity, "text": parsed.text}),
                    )
                };
                for field in ["zoom", "text_filter", "role_filter"] {
                    if let Some(value) = arguments.get(field) {
                        input[field] = value.clone();
                    }
                }
                return super::web_replace::write_reply(
                    Box::pin(self.serve_synthetic_prepared(
                        capability,
                        &input,
                        super::ServeContext {
                            cancel,
                            identity,
                            management,
                            consent,
                            grantee,
                            clock,
                            now_ms,
                        },
                        Some(replacement),
                    ))
                    .await,
                );
            }
        }
        let foreground = self
            .front_for_foreground(super::fronting::FrontCall {
                grant: &grant,
                consent: &consent,
                cancel: &cancel,
                management,
                conversation_key: &conversation_key,
                input_follows: true,
            })
            .await;
        if let Some(mut refusal) =
            foreground.and_then(|front| front.refusal(&management.application_name(&grant)))
        {
            admission.decorate(&mut refusal);
            return refusal;
        }
        let source = self.app_state_source.clone();
        let settle = settle_bound(ComputerCapability::WriteText);
        // The preview shows the addressed element's own window, whether or
        // not it is the focused one.
        let arrival = self.badges(management.application_name(&grant)).schedule(
            super::cursor::Identity::current(identity.agent_project_id.clone()),
            cerebellum_computer::cursor::CursorKind::Write,
            grant.clone(),
            super::cursor::ReadAim {
                preferred: Some(handle.clone()),
                focused: None,
            },
            None,
            super::cursor::WindowChoice::Element,
        );
        let watch = arrival.watch();
        if let Err(held) = self
            .hold_for_badge(arrival, &cancel, management, &conversation_key, &grant)
            .await
        {
            let mut refusal = held.reply();
            admission.decorate(&mut refusal);
            return refusal;
        }
        let gate = BadgeGate::new(work.gate(), watch);
        let audit = AuditToken::new(self.audit.clone(), gate.clone());
        // The write's own row records any front this call made.
        super::fronting::action_row_started();
        let mut reply = tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _scope = AccessibilityReadScope::new(grant.pid, None);
            let mut journal =
                ElementJournal::new(audit, identity, ComputerCapability::WriteText, &grant);
            let written = write_blocking(
                source.as_ref(),
                &mut journal,
                &grant,
                &handle,
                &parsed,
                settle,
            );
            let mut reply = if gate.refused_for_end() {
                cancelled_before_dispatch_reply()
            } else {
                written
            };
            if matches!(
                reply["outcome"].as_str(),
                Some("completed" | "delivery_unconfirmed")
            ) {
                let observed = settle_and_observe_view(
                    source.as_ref(),
                    &sessions,
                    &conversation_key,
                    &grant,
                    settle,
                    sessions.zoom_expands_menus(&conversation_key, &grant, view.zoom.as_deref()),
                    PersonWatch::NotWatched,
                    None,
                    Some(&mut journal.effects),
                );
                add_diff_view(&mut reply, observed.as_ref(), &view);
            }
            append_lines(&mut reply, &journal.effects.lines);
            if journal.finish().is_err() {
                return audit_unavailable_reply(true);
            }
            reply
        })
        .await
        .unwrap_or_else(|_| audit_unavailable_reply(true));
        if let Some(front) = foreground {
            front.fronting.apply(&mut reply);
        }
        admission.decorate(&mut reply);
        reply
    }

    /// Hold an action until its badge is on what it acts on, so the action
    /// and the badge's tap happen together. When a badge was drawn, the
    /// person had time to use the application while it travelled, so that is
    /// asked again here, right before the action is sent. `Err` says why the
    /// action will not be sent; nothing was sent for it.
    ///
    /// The wait counts against the call's work budget: past the work
    /// deadline, or once the call's dispatch gate closes, the action is not
    /// sent and the reply is the usual before-dispatch one.
    pub(super) async fn hold_for_badge(
        &self,
        arrival: Arrival,
        cancel: &CancelHandle,
        management: &ManagementPlane,
        conversation_key: &str,
        grant: &ProcessGrant,
    ) -> Result<(), Held> {
        let screen_window = arrival.screen_window();
        let badge = arrival.watch();
        if !badge_landing(arrival, cancel).await? {
            return Ok(());
        }
        // A drawn on-screen badge gave the person time to minimize the target
        // or hide its app. Do not press into the window that has since left.
        // No-picture actions and background previews keep their usual dispatch.
        if let Some(window) = screen_window.get() {
            let source = self.app_state_source.clone();
            let checked = grant.clone();
            let window = window.clone();
            let work = super::quarantine::CallWork::current();
            let visible = tokio::task::spawn_blocking(move || {
                let _ax = work.bound_ax();
                source.application_hidden(&checked) == Some(false)
                    && source.window_minimized(&window) == Some(false)
            })
            .await;
            if !matches!(visible, Ok(true)) {
                if let Some(badge) = badge {
                    badge.hide();
                }
                return Err(Held::Refused(json!({
                    "outcome": "state_changed_by_person",
                    "reason": "window_changed",
                    "remedy": "The target window left the screen while the badge travelled, or its visibility could no longer be read. Nothing was sent. Call read_state, then act on what it shows.",
                })));
            }
        }
        match self
            .refuse_if_person_changed(management, conversation_key, grant)
            .await
        {
            Some(refusal) => Err(Held::Refused(refusal)),
            None => Ok(()),
        }
    }

    /// The refusal for an action on an application the person used since
    /// this conversation was last shown it, or `None` when it may go ahead.
    ///
    /// Asked after the grant is held and before anything is sent, so a
    /// refusal has done nothing and a read followed by a retry is safe. The
    /// element and keystroke rows ask it; reads, waits and takeover pointer
    /// actions do not. The takeover actions are left out because they
    /// already refuse while the person is active.
    pub(super) async fn refuse_if_person_changed(
        &self,
        management: &ManagementPlane,
        conversation_key: &str,
        grant: &ProcessGrant,
    ) -> Option<Value> {
        let source = self.app_state_source.clone();
        let sessions = management.app_state_sessions().clone();
        let conversation_key = conversation_key.to_string();
        let checked = grant.clone();
        let change = tokio::task::spawn_blocking(move || {
            let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(checked.pid, None);
            person_check_before_action(source.as_ref(), &sessions, &conversation_key, &checked)
        })
        .await;
        match change {
            Ok(Ok(PersonCheck::Changed(change))) => Some(state_changed_by_person_reply(
                &management.application_name(grant),
                change,
            )),
            Ok(Ok(PersonCheck::Unchanged)) => None,
            Ok(Ok(PersonCheck::AppMovedFocus(line))) => {
                super::quarantine::CallWork::current().disclose(line);
                None
            }
            _ => Some(json!({
                "outcome": "observer_unavailable",
                "reason": "hardware_input_observer_unavailable",
                "remedy": "The module could not tell whether the person is using this app. \
                           Nothing was sent. Call read_state again after the hardware observer \
                           recovers to establish a new covered interval. Check hardwareInputObserver \
                           in module health; if Input Monitoring is unavailable, restore access \
                           and restart the module before reading again.",
            })),
        }
    }

    /// The refusal for an element action whose `target` names another
    /// application than the one the element or image belongs to, or `None`
    /// when it names that one or there is no target. Checked before any
    /// grant is asked for, so nobody is asked about an action that will not
    /// happen.
    async fn check_target(
        &self,
        target: Option<String>,
        bundle_identity: &str,
        pid: u32,
    ) -> Option<Value> {
        let target = target?;
        let source = self.app_state_source.clone();
        let bundle_identity = bundle_identity.to_string();
        let checked = target.clone();
        let matches = tokio::task::spawn_blocking(move || {
            target_names_application(source.as_ref(), &checked, &bundle_identity, pid)
        })
        .await
        .unwrap_or(false);
        (!matches).then(|| target_mismatch_reply(&target))
    }

    /// Press an element and, when the press went through, wait for its effect
    /// and add the diff. The press waits for the agent's badge to reach the
    /// element first, so the badge's tap and the press happen together.
    async fn press_and_diff(
        &self,
        call: PressCall<'_>,
        grant: ProcessGrant,
        target: PressTarget,
        view: super::StateView,
        later: Vec<PressStep>,
    ) -> PressDone {
        let PressCall {
            identity,
            management,
            consent,
            cancel,
            sessions,
            capability,
        } = call;
        let work = super::quarantine::CallWork::current();
        if let Some(busy) = work.bind(&self.serializer.quarantine, &grant).await {
            return PressDone::alone(busy);
        }
        let source = self.app_state_source.clone();
        let settle = settle_bound(capability);
        // Capture the acting agent on the async side: Tokio task-local
        // session identity does not follow work onto a blocking thread.
        let cursor_identity = super::cursor::Identity::current(identity.agent_project_id.clone());
        let conversation_key = identity.conversation_key.clone();
        // A point names no element, so the element under it is found first.
        // `reads` carries what that hit test's accessibility reads found on to
        // the press's own journal row.
        let (element_id, handle, point, reads) = match target {
            PressTarget::Element { element_id, handle } => (element_id, handle, None, None),
            PressTarget::Point {
                point,
                window_number,
                application_name,
            } => {
                let mut audit = AuditToken::new(self.audit.clone(), work.gate());
                let (source, sessions, grant, identity, work) = (
                    source.clone(),
                    sessions.clone(),
                    grant.clone(),
                    identity.clone(),
                    work.clone(),
                );
                let found = tokio::task::spawn_blocking(move || {
                    let _ax = work.bound_ax();
                    let _scope = AccessibilityReadScope::new(grant.pid, None);
                    let hit = hit_test(source.as_ref(), &grant, point);
                    let found = match hit {
                        // Checked before the element is given an id, so an
                        // element of a window the image does not show is
                        // neither numbered nor pressed.
                        PointHit::Element(handle)
                            if !hit_is_in_imaged_window(source.as_ref(), &handle, window_number) =>
                        {
                            Err(point_in_another_window_reply(
                                &application_name,
                                "nothing was pressed and the pointer was not used",
                            ))
                        }
                        PointHit::Element(handle) => adopt(&sessions, &identity.conversation_key, &grant, &handle)
                            .map(|id| (id, handle)),
                        PointHit::Nothing => Err(json!({
                            "outcome": "no_element_at_point",
                            "remedy": "nothing of this application is at that point; nothing was pressed and the pointer was not used. Read the state again and choose an element",
                        })),
                    };
                    match found {
                        Ok((id, handle)) => Ok((id, handle, AccessibilityReadScope::current())),
                        Err(reply) => {
                            if audit.record_accessibility_read(identity, capability, &grant, || ()).is_err() {
                                return Err(audit_unavailable_reply(false));
                            }
                            Err(reply)
                        }
                    }
                })
                .await
                .unwrap_or_else(|_| Err(audit_unavailable_reply(false)));
                match found {
                    Ok((id, handle, reads)) => (id, handle, Some([point.0, point.1]), reads),
                    Err(reply) => {
                        super::fronting::action_row_started();
                        return PressDone::alone(reply);
                    }
                }
            }
        };
        // Check refusals that cannot benefit from fronting before drawing a
        // Pressing badge. Recheck at dispatch as the element may change while
        // the badge travels.
        let preflight = {
            let source = source.clone();
            let grant = grant.clone();
            let handle = handle.clone();
            let work = work.clone();
            let identity = identity.clone();
            let audit = AuditToken::new(self.audit.clone(), work.gate());
            tokio::task::spawn_blocking(move || {
                let _ax = work.bound_ax();
                let _scope = AccessibilityReadScope::new(grant.pid, None);
                let mut journal = ElementJournal::new(audit, identity, capability, &grant);
                let refusal = match source.element_facts(&handle) {
                    Ok(facts) if facts.pid.is_none_or(|pid| pid == grant.pid) => {
                        press_available(source.as_ref(), &facts, &handle, capability)
                            .err()
                            .map(|reply| {
                                let role = journal_role(Some(&facts));
                                if journal
                                    .refused(
                                        role,
                                        reply["outcome"].as_str().expect("refusal outcome"),
                                    )
                                    .is_err()
                                {
                                    audit_unavailable_reply(false)
                                } else {
                                    reply
                                }
                            })
                    }
                    _ => Some(stale_element_reply()),
                };
                if journal.finish().is_err() {
                    return Some(audit_unavailable_reply(false));
                }
                refusal
            })
            .await
            .unwrap_or_else(|_| Some(audit_unavailable_reply(false)))
        };
        if let Some(refusal) = preflight {
            return PressDone::alone(refusal);
        }
        let foreground = self
            .front_for_foreground(super::fronting::FrontCall {
                grant: &grant,
                consent,
                cancel,
                management,
                conversation_key: &identity.conversation_key,
                input_follows: true,
            })
            .await;
        if let Some(refusal) =
            foreground.and_then(|front| front.refusal(&management.application_name(&grant)))
        {
            return PressDone::alone(refusal);
        }
        // A press can bring its application forward only when the element
        // reads disabled while the application is in the background, and
        // only in background mode: foreground mode has already brought it
        // forward. The pre-read is one blocking hop, before any lock, and is
        // journaled as an accessibility read; no `element_disabled` refusal
        // is recorded for it.
        let mut needs_front = false;
        let admission = self.fronting_admission(consent, false);
        if admission.mode == AppUse::Background && admission.may_front().is_ok() {
            let mut audit = AuditToken::new(self.audit.clone(), work.gate());
            let (source, read_grant, identity, work, handle) = (
                source.clone(),
                grant.clone(),
                identity.clone(),
                work.clone(),
                handle.clone(),
            );
            let pre_read = tokio::task::spawn_blocking(move || {
                let _ax = work.bound_ax();
                let grant = read_grant;
                let _scope = AccessibilityReadScope::new(grant.pid, None);
                let pre_read = cerebellum_computer::dispatch::PressPreRead {
                    enabled: source.element_enabled(&handle),
                    frontmost: source.frontmost_pid(),
                };
                audit
                    .record_accessibility_read(identity, capability, &grant, || ())
                    .map(|_| pre_read)
                    .map_err(|_| audit_unavailable_reply(false))
            })
            .await
            .unwrap_or_else(|_| Err(audit_unavailable_reply(false)));
            match pre_read {
                Ok(pre_read) => needs_front = pre_read.needs_front(grant.pid),
                Err(reply) => return PressDone::alone(reply),
            }
        }
        // The preview shows the pressed element's own window: for a point
        // press, the element found under the point.
        let badges = self.badges(management.application_name(&grant));
        let arrival = badges.schedule(
            cursor_identity,
            cerebellum_computer::cursor::CursorKind::Press,
            grant.clone(),
            super::cursor::ReadAim {
                preferred: Some(handle.clone()),
                focused: None,
            },
            point,
            super::cursor::WindowChoice::Element,
        );
        let watch = arrival.watch();
        if let Err(held) = self
            .hold_for_badge(arrival, cancel, management, &conversation_key, &grant)
            .await
        {
            let reply = held.reply();
            if point.is_none() {
                return PressDone::alone(reply);
            }
            // The hit test read the application; journal that read, as a
            // refused hit test does. That row is this action's own.
            super::fronting::action_row_started();
            let mut audit = AuditToken::new(self.audit.clone(), work.gate());
            return PressDone::alone(
                tokio::task::spawn_blocking(move || {
                    let _ax = work.bound_ax();
                    let _scope = AccessibilityReadScope::new(grant.pid, reads);
                    if audit
                        .record_accessibility_read(identity, capability, &grant, || ())
                        .is_err()
                    {
                        return audit_unavailable_reply(false);
                    }
                    reply
                })
                .await
                .unwrap_or_else(|_| audit_unavailable_reply(false)),
            );
        }
        let gate = BadgeGate::new(work.gate(), watch);
        // The press's own row records any front this call made.
        super::fronting::action_row_started();
        if needs_front {
            let later = (!later.is_empty()).then(|| {
                fronted_press::later_steps(
                    &badges,
                    management,
                    &self.process_executable,
                    consent,
                    &grant,
                    &identity.agent_project_id,
                    later,
                )
            });
            return self
                .press_fronted(FrontedPress {
                    identity,
                    management,
                    consent,
                    cancel,
                    sessions,
                    capability,
                    grant,
                    element_id,
                    handle,
                    reads,
                    gate,
                    work,
                    settle,
                    view,
                    later,
                })
                .await;
        }
        let audit = AuditToken::new(self.audit.clone(), gate.clone());
        let fronting = foreground.map_or_else(
            || super::fronting::Fronting::untouched(admission.mode),
            |front| front.fronting,
        );
        let (mut reply, effects) = tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _scope = AccessibilityReadScope::new(grant.pid, reads);
            let mut journal = ElementJournal::new(audit, identity.clone(), capability, &grant);
            if let Some(record) = fronting.row_record() {
                journal.set_fronting(record);
            }
            let press_at = Instant::now();
            let mut reply =
                press_blocking(source.as_ref(), &mut journal, &grant, &element_id, &handle);
            if gate.refused_for_end() {
                reply = cancelled_before_dispatch_reply();
            }
            let observed = if reply["outcome"] == "completed" {
                let observed = settle_and_observe_view(
                    source.as_ref(),
                    &sessions,
                    &identity.conversation_key,
                    &grant,
                    settle,
                    sessions.zoom_expands_menus(
                        &identity.conversation_key,
                        &grant,
                        view.zoom.as_deref(),
                    ),
                    PersonWatch::NotWatched,
                    Some(PressedElement {
                        element_id: &element_id,
                        handle: &handle,
                    }),
                    Some(&mut journal.effects),
                );
                add_diff_view(&mut reply, observed.as_ref(), &view);
                observed
            } else {
                None
            };
            if journal.finish().is_err() {
                reply = audit_unavailable_reply(true);
            } else if view.zoom.is_none() && view.roles.is_empty() && view.text.is_none() {
                if let Some(observed) = &observed {
                    certify_press_reply_windows(
                        source.as_ref(),
                        &sessions,
                        &grant,
                        &identity.conversation_key,
                        &observed.read,
                        &reply,
                        press_at,
                    );
                }
            }
            (reply, journal.effects.lines)
        })
        .await
        .unwrap_or_else(|_| (audit_unavailable_reply(true), Vec::new()));
        if let Some(front) = foreground {
            front.fronting.apply(&mut reply);
        }
        PressDone {
            effects,
            ..PressDone::alone(reply)
        }
    }
}

#[path = "fronted_press.rs"]
mod fronted_press;
use fronted_press::{FrontedEnding, FrontedPress, PressStep};

/// What one press ended with, or, when the press brought its application
/// forward in a batch, what that fronted run of the batch's presses did.
struct PressDone {
    reply: Value,
    effects: Vec<String>,
    /// The replies of the later batch steps the fronted run attempted, in
    /// order; empty for a press that ran alone.
    later: Vec<Value>,
    /// How the fronted run ended. It belongs on the reply that ends the
    /// action: the press's own for a single press, the batch's for a batch.
    ending: Option<FrontedEnding>,
}

impl PressDone {
    fn alone(reply: Value) -> Self {
        Self {
            reply,
            effects: Vec::new(),
            later: Vec::new(),
            ending: None,
        }
    }

    /// The reply of a press that is the whole action.
    fn into_reply(self) -> Value {
        let mut reply = self.reply;
        if let Some(ending) = &self.ending {
            ending.apply(&mut reply);
        }
        append_lines(&mut reply, &self.effects);
        reply
    }
}

/// The later steps of a batch that a fronted run may press: the ids after the
/// current one, up to the first that does not name a live element of the
/// batch's application. That one is left to the batch, which refuses it at
/// its own step once the run is over.
fn same_application_steps(
    sessions: &AppStateSessions,
    conversation_key: &str,
    first: &ProcessGrant,
    ids: &[String],
) -> Vec<PressStep> {
    ids.iter()
        .map_while(|id| match sessions.resolve(conversation_key, id) {
            cerebellum_computer::app_state::session::ElementResolution::Live {
                handle,
                bundle_identity,
                pid,
                process_generation,
            } if bundle_identity == first.bundle_identity
                && pid == first.pid
                && process_generation == first.process_generation_evidence =>
            {
                Some(PressStep {
                    element_id: id.clone(),
                    handle,
                })
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, FixtureElementToken, RawAppState,
    };
    use cerebellum_computer::audit::redaction::ExcludeApplicationText;
    use cerebellum_computer::audit::ComputerAudit;
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_core::journal::{InMemoryJournalStorage, JournalConfig};
    use std::sync::Mutex;

    struct MenuSource {
        role: Option<&'static str>,
        actions: Vec<String>,
        calls: Mutex<Vec<&'static str>>,
        enabled: bool,
        indeterminate: bool,
    }

    impl MenuSource {
        fn new(actions: &[&str]) -> Self {
            Self {
                role: Some("AXPopUpButton"),
                actions: actions.iter().map(|action| (*action).into()).collect(),
                calls: Mutex::new(Vec::new()),
                enabled: true,
                indeterminate: false,
            }
        }
    }

    impl AppStateSource for MenuSource {
        fn reports_screen_geometry(&self) -> bool {
            true
        }
        fn element_frame(&self, _: &ElementHandle) -> Option<[f64; 4]> {
            Some([10.0, 10.0, 20.0, 20.0])
        }
        fn display_frames(&self) -> Option<Vec<[f64; 4]>> {
            Some(vec![[0.0, 0.0, 100.0, 100.0]])
        }
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            unreachable!("dispatch does not read the state tree")
        }

        fn element_facts(&self, _: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
            Ok(ElementFacts {
                role: self.role.map(str::to_owned),
                actions: self.actions.clone(),
                ..Default::default()
            })
        }

        fn element_enabled(&self, _: &ElementHandle) -> Option<bool> {
            Some(self.enabled)
        }

        fn press(&self, _: &ElementHandle) -> Result<(), ElementActionError> {
            self.calls.lock().unwrap().push("AXPress");
            Ok(())
        }

        fn show_menu(&self, _: &ElementHandle) -> Result<(), ElementActionError> {
            self.calls.lock().unwrap().push("AXShowMenu");
            if self.indeterminate {
                Err(ElementActionError::Indeterminate)
            } else {
                Ok(())
            }
        }
    }

    fn press_fixture(source: &MenuSource) -> Value {
        let custody = CaptureCustody::new(
            CustodyBounds {
                maximum_verification_duration_ms: 100,
                maximum_pin_lifetime_ms: 100,
                maximum_concurrently_pinned_artifacts: 2,
                maximum_total_pinned_artifact_bytes: 1000,
                maximum_custody_attachment_bytes: 1000,
            },
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
        .unwrap();
        let audit = ComputerAudit::new(
            ExcludeApplicationText,
            cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
            JournalConfig {
                journal_retention_bytes: 20000,
                journal_max_entry_bytes: 4000,
            },
            InMemoryJournalStorage::default(),
            custody,
        )
        .unwrap();
        let grant = ProcessGrant {
            pid: 42,
            bundle_identity: "com.example.Editor".into(),
            process_generation_evidence: "generation-42".into(),
        };
        let mut identity = cerebellum_computer::audit::journal_identity(
            "direct:agent",
            "conversation",
            "project",
            cerebellum_core::identity::SessionKind::Primary,
        );
        identity.witness = crate::fixture_dispatch_witness();
        let token = AuditToken::new(
            Arc::new(Mutex::new(audit)),
            Arc::new(super::super::quarantine::ArbiterGate(None)),
        );
        let mut journal =
            ElementJournal::new(token, identity, ComputerCapability::PressElement, &grant);
        let handle: ElementHandle = Arc::new(FixtureElementToken(1));
        let reply = press_blocking(source, &mut journal, &grant, "e1", &handle);
        journal.finish().unwrap();
        reply
    }

    #[test]
    fn a_menu_only_element_dispatches_show_menu() {
        for role in ["AXPopUpButton", "AXMenuButton", "AXComboBox"] {
            let mut source = MenuSource::new(&["AXShowMenu", "AXScrollToVisible"]);
            source.role = Some(role);
            let reply = press_fixture(&source);
            assert_eq!(reply["outcome"], "completed", "{role}: {reply}");
            assert_eq!(*source.calls.lock().unwrap(), ["AXShowMenu"]);
        }
    }

    #[test]
    fn a_context_menu_only_element_is_not_pressed() {
        for role in [
            Some("AXStaticText"),
            Some("AXGroup"),
            Some("AXButton"),
            Some("AXLink"),
            Some("AXUnknown"),
            None,
        ] {
            let mut source = MenuSource::new(&["AXShowMenu"]);
            source.role = role;
            let reply = press_fixture(&source);
            assert_eq!(reply["outcome"], "no_press_action", "{role:?}: {reply}");
            assert_eq!(reply["reason"], "press_not_offered", "{reply}");
            assert!(source.calls.lock().unwrap().is_empty(), "{role:?}");
        }
    }

    #[test]
    fn a_press_action_takes_precedence_over_show_menu() {
        let source = MenuSource::new(&["AXShowMenu", "AXPress"]);
        let reply = press_fixture(&source);
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert_eq!(*source.calls.lock().unwrap(), ["AXPress"]);
    }

    #[test]
    fn a_disabled_menu_button_never_dispatches() {
        let mut source = MenuSource::new(&["AXShowMenu"]);
        source.enabled = false;
        assert_eq!(press_fixture(&source)["outcome"], "element_disabled");
        assert!(source.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_menu_dispatch_timeout_names_show_menu_and_is_not_safe_to_retry() {
        let mut source = MenuSource::new(&["AXShowMenu"]);
        source.indeterminate = true;
        let reply = press_fixture(&source);
        assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
        assert_eq!(reply["detail"]["call"], "AXShowMenu");
        assert_eq!(reply["detail"]["dispatched"], true);
        assert_eq!(*source.calls.lock().unwrap(), ["AXShowMenu"]);
    }

    /// Offsets are UTF-16 code units, so a caret after an emoji (two units)
    /// lands after it in the UTF-8 text rather than inside it.
    #[test]
    fn an_insert_after_a_non_bmp_character_is_placed_after_it() {
        assert_eq!(
            expected_after_insert("a😀b", (3, 0), "X").as_deref(),
            Some("a😀Xb")
        );
        assert_eq!(expected_after_insert("a😀b", (2, 0), "X"), None);
        assert_eq!(
            expected_after_insert("hello", (1, 3), "EY").as_deref(),
            Some("hEYo")
        );
        assert_eq!(expected_after_insert("hi", (1, 5), "X"), None);
    }

    /// A call whose work deadline passes, or whose dispatch gate closes (its
    /// route envelope ran out), while its badge is still on the way is not
    /// sent: the reply is the usual before-dispatch deadline one, never an
    /// unknown outcome.
    #[tokio::test(start_paused = true)]
    async fn a_deadline_during_the_badge_wait_replies_before_dispatch() {
        use super::super::quarantine::CallWork;
        let before_dispatch = json!({
            "outcome": "action_deadline_exceeded",
            "detail": {"dispatched": false, "step": "dispatch"},
        });
        let landing = || Arrival::landing_at(tokio::time::Instant::now() + Duration::from_secs(1));

        // The call's work budget ends 100 ms in; the badge lands at 1 s.
        let work = CallWork::new(None, Duration::from_millis(100), None, None);
        let start = tokio::time::Instant::now();
        let reply = work
            .scope(badge_landing(landing(), &CancelHandle::pending()))
            .await
            .map_err(Held::reply)
            .expect_err("a call out of time is not sent");
        assert_eq!(reply, before_dispatch);
        assert!(tokio::time::Instant::now() - start < Duration::from_secs(1));

        // The route's envelope runs out at 200 ms and closes the gate.
        let request = subc_protocol::Frame::build_with_version(
            crate::PROTOCOL_VERSION,
            subc_protocol::FrameType::Request,
            crate::control_flags(),
            1,
            1,
            1,
            serde_json::to_vec(&json!({"name": "computer_use"})).unwrap(),
        )
        .unwrap();
        let terminal = Arc::new(crate::TerminalArbiter::new(request));
        let work = CallWork::new(Some(terminal.clone()), Duration::from_secs(60), None, None);
        let cancel = CancelHandle::pending();
        let (reply, ()) = tokio::join!(work.scope(badge_landing(landing(), &cancel)), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            terminal.stop(crate::TerminalCause::Deadline);
        });
        assert_eq!(
            reply
                .map_err(Held::reply)
                .expect_err("a stopped call is not sent"),
            before_dispatch
        );
    }

    #[test]
    fn only_standard_action_names_are_quoted() {
        assert_eq!(
            describe_actions(&["AXShowMenu".into(), "Name:open\nevil".into()]),
            "AXShowMenu and 1 custom action(s)"
        );
        assert_eq!(describe_actions(&[]), "no standard actions");
    }
}
