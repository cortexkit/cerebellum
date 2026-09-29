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
//! after a short wait for the application to show the effect.

use std::time::{Duration, Instant};

use cerebellum_computer::app_state::render::is_session_ending_title;
use cerebellum_computer::app_state::session::{Adoption, AppStateSessions, StateDiff};
use cerebellum_computer::app_state::source::{
    AppStateSource, ElementActionError, ElementFacts, ElementHandle, HitScope, ReadBounds,
    TextAttribute,
};
use cerebellum_computer::audit::{
    ActuationElementIdentity, ActuationIntent, ComputerAudit, ComputerCapability,
    ComputerPlaneDescriptor, ObservationState,
};
use cerebellum_computer::grounding::ContainmentRung;
use cerebellum_computer::platform::vocabulary::frozen_row_bound_ms;
use cerebellum_computer::platform::{AccessibilityElementName, ProcessGrant};
use cerebellum_core::journal::{
    DispatchCommitmentToken, JournalIdentity, JournalStorage, Redactor, SeverityTaxonomy,
};
use serde_json::{json, Value};

use crate::computer_grants::{ConsentContext, ConsentRefusal, GrantAdmission};
use crate::management::ManagementPlane;
use crate::CancelHandle;

/// How often the state is re-read while waiting for an action's effect.
const SETTLE_POLL: Duration = Duration::from_millis(50);

/// The most element ids one diff lists across its three arrays. Past it the
/// rest are counted in `truncation`, which keeps an action's reply well under
/// the 64 KB every reply is held to even with long session tokens.
pub(crate) const MAX_DIFF_ENTRIES: usize = 1_500;

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

fn blocked_menu_item_reply() -> Value {
    json!({
        "outcome": "blocked_menu_item",
        "remedy": "this menu item ends or suspends the person's session, or empties the Trash; \
                   no grant admits pressing it, so ask the person to do it themselves",
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

/// Fields a request may carry, refusing any other; every listed field is
/// required.
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

/// Every field `computer.press_element` accepts; all are required.
pub(crate) const PRESS_ELEMENT_FIELDS: [&str; 1] = ["element_id"];
/// Every field `computer.press_point` accepts; all are required.
pub(crate) const PRESS_POINT_FIELDS: [&str; 3] = ["image_id", "x", "y"];
/// Every field `computer.write_text` accepts; all are required.
pub(crate) const WRITE_TEXT_FIELDS: [&str; 3] = ["element_id", "text", "write_mode"];

pub(crate) fn parse_press_element(arguments: &Value) -> Result<String, Value> {
    let object = object_with_fields(arguments, &PRESS_ELEMENT_FIELDS)?;
    required_string(object, "element_id")
}

pub(crate) struct ParsedPressPoint {
    pub image_id: String,
    pub x: u64,
    pub y: u64,
}

pub(crate) fn parse_press_point(arguments: &Value) -> Result<ParsedPressPoint, Value> {
    let object = object_with_fields(arguments, &PRESS_POINT_FIELDS)?;
    let image_id = required_string(object, "image_id")?;
    let coordinate = |field: &str| match object.get(field) {
        Some(value) => value.as_u64().ok_or_else(|| invalid(field, "wrong_type")),
        None => Err(invalid(field, "missing_field")),
    };
    Ok(ParsedPressPoint {
        image_id,
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
    pub text: String,
    pub mode: WriteMode,
}

pub(crate) fn parse_write_text(arguments: &Value) -> Result<ParsedWriteText, Value> {
    let object = object_with_fields(arguments, &WRITE_TEXT_FIELDS)?;
    let element_id = required_string(object, "element_id")?;
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
pub(crate) async fn admit_session_app(
    management: &ManagementPlane,
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
fn journal_role(facts: Option<&ElementFacts>) -> String {
    match facts.and_then(|facts| facts.role.as_deref()) {
        Some(role)
            if role.len() <= 48
                && role.strip_prefix("AX").is_some_and(|rest| {
                    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphabetic())
                }) =>
        {
            role.to_string()
        }
        _ => "AXUnknown".to_string(),
    }
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
    pub audit: &'a mut ComputerAudit<R, T, S>,
    pub identity: JournalIdentity,
    pub capability: ComputerCapability,
}

impl<R, T, S> ElementJournal<'_, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    /// Record a refusal decided after the element was found, before anything
    /// was sent to it.
    fn refused(&mut self, role: &str, outcome: &str) -> Result<(), ()> {
        let handle = self
            .audit
            .reserve(self.identity.clone(), descriptor(self.capability))
            .map_err(|_| ())?;
        self.audit
            .finalize_rejected(
                handle,
                json!({"outcome": outcome, "role": role})
                    .to_string()
                    .into_bytes(),
            )
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Record what is about to be sent, before it is sent.
    fn intent(
        &mut self,
        grant: &ProcessGrant,
        element_id: &str,
        action: &str,
        role: &str,
    ) -> Result<DispatchCommitmentToken, ()> {
        let descriptor = descriptor(self.capability);
        let handle = self
            .audit
            .reserve(self.identity.clone(), descriptor.clone())
            .map_err(|_| ())?;
        self.audit
            .commit_actuation_intent(
                handle,
                &descriptor,
                &ActuationIntent {
                    element: Some(ActuationElementIdentity {
                        matched_by: AccessibilityElementName::Identifier(element_id.to_string()),
                        alternate_name: None,
                    }),
                    action: format!("{action} {role}"),
                    grant_identity: grant.clone(),
                },
            )
            .map_err(|_| ())
    }

    fn outcome(&mut self, token: DispatchCommitmentToken, outcome: &str) -> Result<(), ()> {
        self.audit
            .finalize_dispatched(
                token,
                json!({"outcome": outcome}).to_string().into_bytes(),
                Vec::new(),
            )
            .map(|_| ())
            .map_err(|_| ())
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

/// Press one element, journaling the attempt. Returns the reply so far; the
/// caller adds the diff to a completed one.
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
    if is_blocked_menu_item(&facts) {
        if journal.refused(&role, "blocked_menu_item").is_err() {
            return audit_unavailable_reply(false);
        }
        return blocked_menu_item_reply();
    }
    if !facts.actions.iter().any(|action| action == "AXPress") {
        if journal.refused(&role, "no_press_action").is_err() {
            return audit_unavailable_reply(false);
        }
        return json!({
            "outcome": "no_press_action",
            "reason": "press_not_offered",
            "remedy": format!(
                "this element offers {}, not a press; nothing was done and the pointer was not \
                 used. Choose another element from read_state",
                describe_actions(&facts.actions)
            ),
        });
    }
    let Ok(token) = journal.intent(grant, element_id, "AXPress", &role) else {
        return audit_unavailable_reply(false);
    };
    let (outcome, reply) = match source.press(handle) {
        Ok(()) => ("completed", json!({"outcome": "completed"})),
        Err(ElementActionError::Gone) => ("stale_element", stale_element_reply()),
        Err(_) => (
            "no_press_action",
            json!({
                "outcome": "no_press_action",
                "reason": "press_refused",
                "remedy": "the application refused the press; read the state to see whether \
                           anything changed before trying again",
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
        if journal.refused(&role, "secure_field_refused").is_err() {
            return audit_unavailable_reply(false);
        }
        return json!({
            "outcome": "secure_field_refused",
            "remedy": "this is a secure text field; nothing was written. Ask the person to fill \
                       it in themselves",
        });
    }
    let tree = match source.read_app_state(grant, ReadBounds::default()) {
        Ok(tree) => tree,
        Err(_) => return stale_element_reply(),
    };
    match web_ancestry(&tree.roots, handle, false) {
        Some(true) => {
            if journal.refused(&role, "web_content_needs_type").is_err() {
                return audit_unavailable_reply(false);
            }
            return json!({
                "outcome": "web_content_needs_type",
                "reason": "web_content_needs_type",
                "remedy": "web editors must be typed into; press_element the field to place the caret, then use type, which appends at the caret and confirms by readback. To replace existing text, clear it first",
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
        if journal.refused(&role, "element_not_settable").is_err() {
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
                            return caret_unknown(journal, &role);
                        }
                    }
                }
                _ => return caret_unknown(journal, &role),
            }
        }
    };
    let Ok(token) = journal.intent(grant, element_id, action, &role) else {
        return audit_unavailable_reply(false);
    };
    // One attempt. Whether the application accepted the message or not, the
    // value read back is what decides, and nothing is retried as keystrokes.
    let written = source.write_text(handle, attribute, text);
    let deadline = Instant::now() + readback_bound;
    let confirmed = written.is_ok()
        && loop {
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

/// Find the target in the read tree rather than guessing from its field role:
/// native and web text fields can expose the same accessibility role.
fn web_ancestry(
    nodes: &[cerebellum_computer::app_state::source::RawElement],
    handle: &ElementHandle,
    inside_web: bool,
) -> Option<bool> {
    for node in nodes {
        let inside_web = inside_web || node.role.as_deref() == Some("AXWebArea");
        if node.handle.same_element(handle.as_ref()) {
            return Some(inside_web);
        }
        if let Some(found) = web_ancestry(&node.children, handle, inside_web) {
            return Some(found);
        }
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

/// Wait up to `bound` for the application's state to differ from the
/// conversation's baseline, then diff against it and make that read the new
/// baseline. An unchanged state after the bound is reported as an empty diff.
pub(crate) fn settle_and_observe(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
    bound: Duration,
) -> (StateDiff, Option<String>, usize) {
    let deadline = Instant::now() + bound;
    loop {
        match source.read_app_state(grant, ReadBounds::default()) {
            Ok(read) => {
                if Instant::now() >= deadline
                    || sessions.differs_from_baseline(conversation_key, grant, &read)
                {
                    let observed = sessions.observe(conversation_key, grant, &read);
                    return (
                        observed.diff,
                        observed.focused_element_id,
                        observed.unreadable_subtrees,
                    );
                }
            }
            // Nothing could be read, so nothing is known about what changed.
            Err(_) => return (StateDiff::default(), None, 1),
        }
        std::thread::sleep(SETTLE_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Add a diff to a reply, cutting it to [`MAX_DIFF_ENTRIES`] ids and saying
/// how many were left out.
pub(crate) fn add_diff(
    reply: &mut Value,
    diff: StateDiff,
    focused_element_id: Option<String>,
    unreadable_subtrees: usize,
) {
    let mut room = MAX_DIFF_ENTRIES;
    let mut omitted = 0;
    let mut listed = |ids: Vec<String>| -> Vec<Value> {
        let keep = ids.len().min(room);
        room -= keep;
        omitted += ids.len() - keep;
        ids.into_iter()
            .take(keep)
            .map(|element_id| json!({"element_id": element_id}))
            .collect()
    };
    reply["changed"] = Value::Array(listed(diff.changed));
    reply["added"] = Value::Array(listed(diff.added));
    reply["removed"] = Value::Array(listed(diff.removed));
    if omitted > 0 {
        reply["truncation"] = json!({"reason": "element_cap_reached", "omitted_elements": omitted});
    }
    if let Some(focused) = focused_element_id {
        reply["focused_element_id"] = json!(focused);
    }
    reply["unreadable_subtrees"] = json!(unreadable_subtrees);
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
        let element_id = match parse_press_element(arguments) {
            Ok(element_id) => element_id,
            Err(refusal) => return refusal,
        };
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
                    return blocked_menu_item_reply()
                }
                cerebellum_computer::app_state::session::ElementResolution::Stale => {
                    return stale_element_reply()
                }
            };
        let (grant, admission) = match admit_session_app(
            management,
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
        let mut reply = self
            .press_and_diff(
                identity,
                sessions,
                ComputerCapability::PressElement,
                grant,
                element_id,
                handle,
            )
            .await;
        admission.decorate(&mut reply);
        reply
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
        let point = image
            .mapping
            .pixel_to_desktop(parsed.x as f64, parsed.y as f64);
        let source = self.app_state_source.clone();
        let hit_grant = grant.clone();
        let hit = tokio::task::spawn_blocking(move || hit_test(source.as_ref(), &hit_grant, point))
            .await
            .unwrap_or(PointHit::Nothing);
        let PointHit::Element(handle) = hit else {
            let mut reply = json!({
                "outcome": "no_element_at_point",
                "remedy": "nothing of this application is at that point; nothing was pressed and \
                           the pointer was not used. Read the state again and choose an element",
            });
            admission.decorate(&mut reply);
            return reply;
        };
        let element_id = match adopt(&sessions, &conversation_key, &grant, &handle) {
            Ok(element_id) => element_id,
            Err(mut refusal) => {
                admission.decorate(&mut refusal);
                return refusal;
            }
        };
        let mut reply = self
            .press_and_diff(
                identity,
                sessions,
                ComputerCapability::PressPoint,
                grant,
                element_id,
                handle,
            )
            .await;
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
            match sessions.resolve(&conversation_key, &parsed.element_id) {
                cerebellum_computer::app_state::session::ElementResolution::Live {
                    handle,
                    bundle_identity,
                    pid,
                    process_generation,
                } => (handle, bundle_identity, pid, process_generation),
                // A session-ending menu item has no text to write, and its id
                // was never shown; it names nothing writable.
                _ => return stale_element_reply(),
            };
        let (grant, admission) = match admit_session_app(
            management,
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
        let audit = self.audit.clone();
        let source = self.app_state_source.clone();
        let settle = settle_bound(ComputerCapability::WriteText);
        let mut reply = tokio::task::spawn_blocking(move || {
            let written = {
                let mut audit = audit.blocking_lock();
                let mut journal = ElementJournal {
                    audit: &mut audit,
                    identity,
                    capability: ComputerCapability::WriteText,
                };
                write_blocking(
                    source.as_ref(),
                    &mut journal,
                    &grant,
                    &handle,
                    &parsed,
                    settle,
                )
            };
            let mut reply = written;
            if matches!(
                reply["outcome"].as_str(),
                Some("completed" | "delivery_unconfirmed")
            ) {
                let (diff, focused, unreadable) = settle_and_observe(
                    source.as_ref(),
                    &sessions,
                    &conversation_key,
                    &grant,
                    settle,
                );
                add_diff(&mut reply, diff, focused, unreadable);
            }
            reply
        })
        .await
        .unwrap_or_else(|_| audit_unavailable_reply(true));
        admission.decorate(&mut reply);
        reply
    }

    /// Press an element and, when the press went through, wait for its effect
    /// and add the diff.
    async fn press_and_diff(
        &self,
        identity: JournalIdentity,
        sessions: std::sync::Arc<AppStateSessions>,
        capability: ComputerCapability,
        grant: ProcessGrant,
        element_id: String,
        handle: ElementHandle,
    ) -> Value {
        let audit = self.audit.clone();
        let source = self.app_state_source.clone();
        let settle = settle_bound(capability);
        tokio::task::spawn_blocking(move || {
            let mut reply = {
                let mut audit = audit.blocking_lock();
                let mut journal = ElementJournal {
                    audit: &mut audit,
                    identity: identity.clone(),
                    capability,
                };
                press_blocking(source.as_ref(), &mut journal, &grant, &element_id, &handle)
            };
            if reply["outcome"] == "completed" {
                let (diff, focused, unreadable) = settle_and_observe(
                    source.as_ref(),
                    &sessions,
                    &identity.conversation_key,
                    &grant,
                    settle,
                );
                add_diff(&mut reply, diff, focused, unreadable);
            }
            reply
        })
        .await
        .unwrap_or_else(|_| audit_unavailable_reply(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn only_standard_action_names_are_quoted() {
        assert_eq!(
            describe_actions(&["AXShowMenu".into(), "Name:open\nevil".into()]),
            "AXShowMenu and 1 custom action(s)"
        );
        assert_eq!(describe_actions(&[]), "no standard actions");
    }
}
