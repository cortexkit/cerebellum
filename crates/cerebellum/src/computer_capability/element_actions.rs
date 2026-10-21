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

use cerebellum_computer::app_state::person::{person_change, PersonChange, SeenMarks};
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
    ComputerCapability, ComputerPlaneDescriptor, ObservationState,
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

use super::cursor::{Arrival, BadgeWatch, Landing};
use crate::computer_grants::{ConsentContext, ConsentRefusal, GrantAdmission};
use crate::management::ManagementPlane;
use crate::CancelHandle;

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
    /// The call's handle on the shared audit: each step locks it briefly.
    /// The intent's commit first asks the call's dispatch gate, so a call
    /// already answered sends nothing.
    pub audit: AuditToken<R, T, S>,
    pub identity: JournalIdentity,
    pub capability: ComputerCapability,
    grant: &'a ProcessGrant,
    pending: Option<(DispatchCommitmentToken, String)>,
    recorded: bool,
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
        }
    }

    /// Record a refusal decided after the element was found, before anything
    /// was sent to it.
    fn refused(&mut self, role: &str, outcome: &str) -> Result<(), ()> {
        self.recorded = true;
        self.audit
            .reject(
                self.identity.clone(),
                descriptor(self.capability),
                json!({"outcome": outcome, "role": role, "grant_identity": self.grant})
                    .to_string()
                    .into_bytes(),
            )
            .map_err(|_| ())
    }

    /// Record what is about to be sent, before it is sent.
    fn intent(
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

    fn outcome(&mut self, token: DispatchCommitmentToken, outcome: &str) -> Result<(), ()> {
        // The post-action diff also reads the tree and may re-enable a renderer.
        // Finalize after that read so its state change stays on this action's row.
        self.pending = Some((token, outcome.to_string()));
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ()> {
        if let Some((token, outcome)) = self.pending.take() {
            self.audit
                .finalize_dispatched(
                    token,
                    json!({"outcome": outcome}).to_string().into_bytes(),
                    Vec::new(),
                )
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
enum IntentRefused {
    /// The journal could not record the intent, so nothing is sent.
    AuditUnavailable,
    /// The call was answered before the action could start.
    Stopped,
}

impl IntentRefused {
    fn reply(self) -> Value {
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
    // Read just before pressing, after the checks above: a press on an
    // element the application reports disabled does nothing, and saying so is
    // better than a completed reply with no effect. An unreadable state is
    // unknown, not disabled, so it presses as before.
    if source.element_enabled(handle) == Some(false) {
        if journal.refused(&role, "element_disabled").is_err() {
            return audit_unavailable_reply(false);
        }
        let background = source
            .frontmost_pid()
            .is_some_and(|frontmost| frontmost != grant.pid);
        return element_disabled_reply(facts.title.as_deref(), element_id, background);
    }
    let token = match journal.intent(grant, element_id, "AXPress", &role) {
        Ok(token) => token,
        Err(refused) => return refused.reply(),
    };
    let (outcome, reply) = match source.press(handle) {
        Ok(()) => ("completed", json!({"outcome": "completed"})),
        // The press was sent and no answer came back in time: it may have
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
                    "call": "AXPress",
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
    let token = match journal.intent(grant, element_id, action, &role) {
        Ok(token) => token,
        Err(refused) => return refused.reply(),
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

/// Wait for an effect without moving the baseline during polling. Only the
/// final read becomes the baseline and the conversation's last-seen focus.
pub(crate) fn settle_and_observe_view(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
    bound: Duration,
    expand_menus: bool,
) -> Option<SessionRead> {
    let deadline = Instant::now() + bound;
    loop {
        let seen = SeenMarks::read(source, grant);
        let raw = if expand_menus {
            source.read_app_state_expanding_menus(grant, ReadBounds::default())
        } else {
            source.read_app_state(grant, ReadBounds::default())
        };
        match raw {
            Ok(read) => {
                if Instant::now() >= deadline
                    || sessions.differs_from_baseline(conversation_key, grant, &read)
                {
                    let observed = sessions.observe(conversation_key, grant, &read);
                    sessions.remember_seen(conversation_key, grant, seen);
                    return Some(observed);
                }
            }
            // Nothing could be read, so nothing is known about what changed.
            Err(_) => return None,
        }
        std::thread::sleep(SETTLE_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// What an action reply says when the application could not be read after
/// the action: nothing is known of what changed, which is not "nothing
/// changed".
const DIFF_UNREADABLE: &str =
    "The application could not be read after the action, so what changed is unknown; \
     read_state to see its state.\n";

/// Add what an action changed to its reply, as text in the read grammar,
/// with the cap's disclosure, the focused element and how much of the read
/// behind it could not be opened.
#[cfg(test)]
pub(crate) fn add_diff(reply: &mut Value, observed: Option<&SessionRead>) {
    add_diff_view(reply, observed, &super::StateView::default());
}

pub(crate) fn add_diff_view(
    reply: &mut Value,
    observed: Option<&SessionRead>,
    view: &super::StateView,
) {
    let Some(observed) = observed else {
        reply[STATE_TEXT_FIELD] = json!(DIFF_UNREADABLE);
        reply["unreadable_subtrees"] = json!(1);
        return;
    };
    use cerebellum_computer::app_state::render::{render_change_report, StateHeader};
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
    reply[STATE_TEXT_FIELD] = json!(rendered.text);
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
                .serve_press_single(&parsed.element_ids[0], parsed.target, parsed.view, context)
                .await;
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
        let work = super::quarantine::CallWork::current();
        for (index, id) in parsed.element_ids.iter().enumerate() {
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
            reply = if different_app {
                target_mismatch_reply("batch application")
            } else {
                self.serve_press_single(
                    id,
                    parsed.target.clone(),
                    super::StateView::default(),
                    context.clone(),
                )
                .await
            };
            let success = reply["outcome"] == "completed";
            acted |= success;
            unreadable |= success && reply[STATE_TEXT_FIELD] == DIFF_UNREADABLE;
            steps.push(json!({"step":index + 1, "element_id":id, "outcome":reply["outcome"]}));
            if !success {
                reply["stopped_at"] = json!(index + 1);
                break;
            }
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
                add_diff_view(&mut reply, Some(&combined), &parsed.view);
            }
        }
        reply["steps"] = json!(steps);
        reply
    }

    async fn serve_press_single<C: cerebellum_core::clock::MonotonicClock>(
        &self,
        element_id: &str,
        target: Option<String>,
        view: super::StateView,
        context: super::ServeContext<'_, C>,
    ) -> Value {
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
                    return blocked_menu_item_reply()
                }
                cerebellum_computer::app_state::session::ElementResolution::Stale => {
                    return stale_element_reply()
                }
                cerebellum_computer::app_state::session::ElementResolution::PreviousRun => {
                    return previous_run_reply()
                }
            };
        if let Some(refusal) = self.check_target(target, &bundle_identity, pid).await {
            return refusal;
        }
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
        if let Some(mut refusal) = self
            .refuse_if_person_changed(management, &conversation_key, &grant)
            .await
        {
            admission.decorate(&mut refusal);
            return refusal;
        }
        let mut reply = self
            .press_and_diff(
                PressCall {
                    identity,
                    management,
                    cancel: &cancel,
                    sessions,
                    capability: ComputerCapability::PressElement,
                },
                grant,
                PressTarget::Element { element_id, handle },
                view,
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
        if let Some(mut busy) = work.bind(&self.serializer.quarantine, &grant) {
            admission.decorate(&mut busy);
            return busy;
        }
        let source = self.app_state_source.clone();
        let settle = settle_bound(ComputerCapability::WriteText);
        let arrival = self.cursor.schedule(
            super::cursor::Identity::current(identity.agent_project_id.clone()),
            cerebellum_computer::cursor::CursorKind::Write,
            grant.clone(),
            self.app_state_source.clone(),
            Some(handle.clone()),
            None,
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
                );
                add_diff_view(&mut reply, observed.as_ref(), &view);
            }
            if journal.finish().is_err() {
                return audit_unavailable_reply(true);
            }
            reply
        })
        .await
        .unwrap_or_else(|_| audit_unavailable_reply(true));
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
        if !badge_landing(arrival, cancel).await? {
            return Ok(());
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
            person_change_since_seen(source.as_ref(), &sessions, &conversation_key, &checked)
        })
        .await;
        match change {
            Ok(Ok(Some(change))) => Some(state_changed_by_person_reply(
                &management.application_name(grant),
                change,
            )),
            Ok(Ok(None)) => None,
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
    ) -> Value {
        let PressCall {
            identity,
            management,
            cancel,
            sessions,
            capability,
        } = call;
        let work = super::quarantine::CallWork::current();
        if let Some(busy) = work.bind(&self.serializer.quarantine, &grant) {
            return busy;
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
                    Err(reply) => return reply,
                }
            }
        };
        let arrival = self.cursor.schedule(
            cursor_identity,
            cerebellum_computer::cursor::CursorKind::Press,
            grant.clone(),
            source.clone(),
            Some(handle.clone()),
            point,
        );
        let watch = arrival.watch();
        if let Err(held) = self
            .hold_for_badge(arrival, cancel, management, &conversation_key, &grant)
            .await
        {
            let reply = held.reply();
            if point.is_none() {
                return reply;
            }
            // The hit test read the application; journal that read, as a
            // refused hit test does.
            let mut audit = AuditToken::new(self.audit.clone(), work.gate());
            return tokio::task::spawn_blocking(move || {
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
            .unwrap_or_else(|_| audit_unavailable_reply(false));
        }
        let gate = BadgeGate::new(work.gate(), watch);
        let audit = AuditToken::new(self.audit.clone(), gate.clone());
        tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _scope = AccessibilityReadScope::new(grant.pid, reads);
            let mut journal = ElementJournal::new(audit, identity.clone(), capability, &grant);
            let mut reply =
                press_blocking(source.as_ref(), &mut journal, &grant, &element_id, &handle);
            if gate.refused_for_end() {
                reply = cancelled_before_dispatch_reply();
            }
            if reply["outcome"] == "completed" {
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
                );
                add_diff_view(&mut reply, observed.as_ref(), &view);
            }
            if journal.finish().is_err() {
                return audit_unavailable_reply(true);
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
