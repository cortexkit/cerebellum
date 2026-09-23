//! Identity facts accepted on a route bind and the profile-boundary policy.
//!
//! Cerebellum consumes identity from the daemon-accepted bind facts. It does not
//! inspect tool request bodies for identity and it does not mint identity:
//! - **conversation-key** is the wire session id from `BindIdentity::session`.
//! - **agentProjectId** and **sessionKind** are stamped admission facts.
//! - **principal** is the daemon-stamped bind fact.
//! - **effective capability scope** is the admitted capability scope.
//!
//! Profile resolution is policy only. This module intentionally does not open a
//! browser, a profile registry, or profile storage.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use subc_protocol::{BindIdentity, Principal, RouteTarget};

/// The alfonso-core-stamped session kind, read verbatim from the bind facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Primary,
    Subagent,
    Ephemeral,
}

impl SessionKind {
    /// Parse a session-kind string stamped on the bind. Returns `None` for an
    /// unknown value; callers can choose a fail-closed or compatibility policy.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(kind: &str) -> Option<Self> {
        match kind {
            "primary" => Some(Self::Primary),
            "subagent" => Some(Self::Subagent),
            "ephemeral" => Some(Self::Ephemeral),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Subagent => "subagent",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// The profile disposition for a session kind, per the boundary policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDisposition {
    Durable,
    Disposable,
    None,
}

impl ProfileDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Disposable => "disposable",
            Self::None => "none",
        }
    }

    pub fn for_session_kind(kind: SessionKind) -> Self {
        match kind {
            SessionKind::Primary => Self::Durable,
            SessionKind::Subagent => Self::Disposable,
            SessionKind::Ephemeral => Self::None,
        }
    }
}

/// The logical key used by the future profile-storage slice.
///
/// The key is deliberately a value type rather than a handle to storage. The
/// identity slice only computes this key; it never resolves or opens a profile.
pub type LogicalProfileKey = (String, String);

/// The result of the profile-boundary policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileResolution {
    pub profile_disposition: ProfileDisposition,
    pub profile_name: Option<String>,
    pub logical_profile_key: Option<LogicalProfileKey>,
}

impl ProfileResolution {
    fn for_identity(
        identity: &RouteIdentity,
        logical_profile_key: Option<LogicalProfileKey>,
    ) -> Self {
        match identity.session_kind {
            SessionKind::Primary => Self {
                profile_disposition: ProfileDisposition::Durable,
                profile_name: Some("default".to_string()),
                logical_profile_key,
            },
            SessionKind::Subagent => Self {
                profile_disposition: ProfileDisposition::Disposable,
                profile_name: Some("default".to_string()),
                logical_profile_key,
            },
            SessionKind::Ephemeral => Self {
                profile_disposition: ProfileDisposition::None,
                profile_name: None,
                logical_profile_key: None,
            },
        }
    }
}

/// The three identity facts read from a route bind, plus the resolved
/// disposition used by capability policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteIdentity {
    /// The wire session-id (conversation-key), read verbatim from the bind.
    pub conversation_key: String,
    /// The durable profile owner, read verbatim from accepted bind facts.
    pub agent_project_id: String,
    /// The alfonso-core-stamped session kind.
    pub session_kind: SessionKind,
    /// The resolved profile disposition for this session kind.
    pub profile_disposition: ProfileDisposition,
    /// The project root remains available as routing metadata, but is not used
    /// when an admitted agentProjectId is present.
    pub project_root: PathBuf,
}

impl RouteIdentity {
    /// Build identity from a bind without admission extensions.
    ///
    /// This compatibility constructor supports older wire fixtures that do not
    /// include daemon-accepted admission facts. New route handling should use
    /// [`Self::from_accepted_bind`], which consumes those facts.
    pub fn from_bind(identity: &BindIdentity, principal: &Option<Principal>) -> Self {
        Self::from_accepted_bind(identity, principal, None)
    }

    /// Read identity from the accepted bind facts. `admission_facts` is already
    /// carried by the daemon's `route.bind`; tool request bodies are not involved.
    pub fn from_accepted_bind(
        identity: &BindIdentity,
        _principal: &Option<Principal>,
        admission_facts: Option<&Value>,
    ) -> Self {
        let conversation_key = identity.session.clone();
        let agent_project_id = agent_project_id_from_facts(identity, admission_facts);
        let session_kind = session_kind_from_facts(admission_facts);
        let profile_disposition = ProfileDisposition::for_session_kind(session_kind);
        Self {
            conversation_key,
            agent_project_id,
            session_kind,
            profile_disposition,
            project_root: identity.project_root.clone(),
        }
    }

    /// Compute the logical profile key without opening profile storage.
    pub fn logical_profile_key(&self) -> Option<LogicalProfileKey> {
        match self.session_kind {
            SessionKind::Primary => Some((self.agent_project_id.clone(), "default".to_string())),
            SessionKind::Subagent => {
                Some((self.agent_project_id.clone(), self.conversation_key.clone()))
            }
            SessionKind::Ephemeral => None,
        }
    }

    /// Resolve the logical profile boundary without opening profile storage.
    pub fn resolve_profile(&self) -> ProfileResolution {
        let logical_profile_key = self.logical_profile_key();
        #[cfg(any(test, feature = "test-observer"))]
        record_test_observation(self, logical_profile_key.clone());
        ProfileResolution::for_identity(self, logical_profile_key)
    }
}

/// Which of this module's advertised surfaces a route reaches.
///
/// The daemon binds a route to one surface, and the two this module could serve
/// take DIFFERENT REQUEST ENVELOPES: a tool call carries `{name, arguments}`
/// while a management operation carries `{method, params}`. So a request cannot
/// be parsed until the surface is known.
///
/// Retained from the bind rather than inferred from the request, because
/// inferring it means accepting whichever envelope a body happens to resemble —
/// and a caller could then reach a management operation by sending a tool-shaped
/// body, or the reverse. Which surface a caller reached is the daemon's
/// statement, and it belongs to the route rather than to any request on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSurface {
    /// Tool calls.
    Tools,
    /// Management operations.
    Management,
    /// A surface this module does not advertise.
    ///
    /// Kept as a value rather than refused at bind, so a request arriving on
    /// such a route is refused with the surface named. Treating it as either of
    /// the others would serve one surface's callers from the other's envelope.
    Unsupported,
}

impl RouteSurface {
    /// Read the surface from the target the daemon bound.
    pub fn from_target(target: &RouteTarget) -> Self {
        match target {
            RouteTarget::ToolProvider { .. } => Self::Tools,
            RouteTarget::ManagementSurface { .. } => Self::Management,
            RouteTarget::InternalService { .. } => Self::Unsupported,
        }
    }
}

/// Why a route's attested facts do not admit a control operation.
///
/// One variant per REMEDY rather than per condition, because the remedy is
/// what a refused caller acts on. Two unattested facts with the same cause get
/// one variant: a route opened by anything other than the daemon's configured
/// admission carrier carries no admission facts at all, and naming only the
/// first missing fact would read as a carrier that stamped some and dropped one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOperationRefusal {
    /// Neither fact is attested: the route did not come through the carrier.
    AdmissionFactsAbsent,
    /// Session kind is attested and project id is not: the carrier dropped it.
    AgentProjectIdUnattested,
    /// Project id is attested and session kind is not: the carrier dropped it.
    SessionKindUnattested,
    /// Both facts are attested and the carrier did not grant this operation.
    OperationNotGranted,
}

impl ControlOperationRefusal {
    /// Every variant, for callers that declare the reply vocabulary.
    pub const ALL: [Self; 4] = [
        Self::AdmissionFactsAbsent,
        Self::AgentProjectIdUnattested,
        Self::SessionKindUnattested,
        Self::OperationNotGranted,
    ];

    /// The wire reason code.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::AdmissionFactsAbsent => "admission_facts_absent",
            Self::AgentProjectIdUnattested => "agent_project_id_unattested",
            Self::SessionKindUnattested => "session_kind_unattested",
            Self::OperationNotGranted => "operation_not_granted",
        }
    }

    /// What the refused caller does next.
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::AdmissionFactsAbsent => {
                "this route carries no admission facts: they are stamped only when the daemon's \
                 configured admission carrier opens the route, so a route opened any other way \
                 cannot perform control operations; call through the carrier"
            }
            Self::AgentProjectIdUnattested => {
                "the admission carrier stamped this route without agentProjectId; a caller cannot \
                 supply it, so report this to whoever operates the carrier"
            }
            Self::SessionKindUnattested => {
                "the admission carrier stamped this route without sessionKind; a caller cannot \
                 supply it, so report this to whoever operates the carrier"
            }
            Self::OperationNotGranted => {
                "the admission carrier did not grant this operation on this route; its \
                 browserControlOperations list must include it"
            }
        }
    }
}

/// Facts retained after a route bind has passed principal admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBindFacts {
    pub identity: RouteIdentity,
    pub principal: Option<Principal>,
    /// True only when the project id came from daemon admission facts rather
    /// than the caller-controlled project-root compatibility fallback.
    pub agent_project_id_attested: bool,
    /// True only when daemon facts explicitly identify the session kind; the
    /// compatibility default to `primary` is not attested and therefore must not
    /// authorize durable storage.
    pub session_kind_attested: bool,
    /// Exact control-operation identifiers admitted by daemon authority.
    pub control_operations: Vec<String>,
    /// `None` means the legacy bind had no explicit scope and receives the
    /// module's first-party default. `Some(empty)` is an explicitly empty scope.
    pub effective_capability_scope: Option<Vec<String>>,
    /// Reverse-request families the consumer declared it can service, such as
    /// asking a human a question.
    ///
    /// A DECLARATION, NOT A GRANT, and the distinction decides how it may be
    /// used. The consumer states this about itself and nothing verifies it, so
    /// its presence is not evidence that anyone is listening — a consumer that
    /// over-declares produces a question nobody answers. It may therefore be
    /// read to decide whether asking is worth attempting, and never to conclude
    /// that an unanswered question means refusal.
    ///
    /// Absent means no capability rather than an unknown one, so a bind that
    /// omits it is treated exactly as one that declares nothing.
    pub consumer_capabilities: Vec<String>,
    /// Which surface this route reaches, so a request on it is parsed as the
    /// envelope that surface uses rather than as whichever one it resembles.
    pub surface: RouteSurface,
}

impl AcceptedBindFacts {
    pub fn from_bind(
        identity: &BindIdentity,
        principal: Option<Principal>,
        admission_facts: Option<&Value>,
        consumer_capabilities: Option<&[String]>,
        target: &RouteTarget,
    ) -> Self {
        Self {
            identity: RouteIdentity::from_accepted_bind(identity, &principal, admission_facts),
            principal,
            agent_project_id_attested: admitted_agent_project_id(admission_facts).is_some(),
            session_kind_attested: admitted_session_kind(admission_facts).is_some(),
            control_operations: control_operations_from_facts(admission_facts),
            effective_capability_scope: effective_capability_scope_from_facts(admission_facts),
            consumer_capabilities: consumer_capabilities.unwrap_or_default().to_vec(),
            surface: RouteSurface::from_target(target),
        }
    }

    /// Whether the consumer declared it can relay a question to a human.
    ///
    /// True means asking is worth attempting, never that an answer will arrive.
    pub fn declares_elicitation(&self) -> bool {
        self.consumer_capabilities
            .iter()
            .any(|family| family == ELICITATION_CAPABILITY)
    }

    /// Whether daemon-attested bind facts admit this control operation. Caller
    /// request fields cannot substitute for missing identity or authority facts.
    pub fn allows_control_operation(&self, operation: &str) -> bool {
        self.control_operation_refusal(operation).is_none()
    }

    /// Which attested fact fails to admit this control operation, if any.
    ///
    /// Three independent facts decide admission, and a single boolean hides the
    /// one thing a refused caller needs: whether to change how the route is
    /// opened, or report a defect in whatever opened it. Without a reason on
    /// the reply, the only record of which fact failed is the daemon's log,
    /// which a caller cannot read.
    pub fn control_operation_refusal(&self, operation: &str) -> Option<ControlOperationRefusal> {
        match (self.agent_project_id_attested, self.session_kind_attested) {
            (false, false) => return Some(ControlOperationRefusal::AdmissionFactsAbsent),
            (false, true) => return Some(ControlOperationRefusal::AgentProjectIdUnattested),
            (true, false) => return Some(ControlOperationRefusal::SessionKindUnattested),
            (true, true) => {}
        }
        if self
            .control_operations
            .iter()
            .any(|allowed| allowed == operation)
        {
            None
        } else {
            Some(ControlOperationRefusal::OperationNotGranted)
        }
    }

    /// Whether the accepted scope permits a capability. This uses only facts
    /// retained from `route.bind`; callers cannot widen it through a request.
    pub fn allows_capability(&self, capability: &str) -> bool {
        let Some(scope) = &self.effective_capability_scope else {
            return true;
        };
        scope.iter().any(|entry| {
            entry == "*"
                || entry == capability
                || (entry.ends_with(":*") && capability.starts_with(&entry[..entry.len() - 1]))
        })
    }
}

/// The reverse-request family that carries a question to a human, as spelled on
/// the wire.
pub const ELICITATION_CAPABILITY: &str = "elicitation";

fn admission_object(facts: Option<&Value>) -> Option<&serde_json::Map<String, Value>> {
    let root = facts?.as_object()?;
    Some(root)
}

/// Look up a fact using the fleet's camelCase spelling and the Rust-facing
/// snake_case spelling. The small set of nested containers keeps the parser
/// tolerant of the carrier envelope while avoiding any request-body fallback.
fn fact<'a>(facts: Option<&'a Value>, names: &[&str]) -> Option<&'a Value> {
    let root = admission_object(facts)?;
    let containers = std::iter::once(root).chain(
        ["accepted", "bind", "bind_identity", "identity"]
            .into_iter()
            .filter_map(|name| root.get(name).and_then(Value::as_object)),
    );
    for object in containers {
        for name in names {
            if let Some(value) = object.get(*name) {
                return Some(value);
            }
        }
    }
    None
}

fn admitted_agent_project_id(facts: Option<&Value>) -> Option<&str> {
    fact(
        facts,
        &[
            "agentProjectId",
            "agent_project_id",
            "projectId",
            "project_id",
        ],
    )
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
}

fn agent_project_id_from_facts(identity: &BindIdentity, facts: Option<&Value>) -> String {
    admitted_agent_project_id(facts)
        .map(ToOwned::to_owned)
        // Old wire fixtures predate the admitted project id. Keeping a stable
        // project-root fallback preserves those fixtures; admitted facts always win.
        //
        // SAFETY OF THIS FALLBACK IS NOT LOCAL. `project_root` arrives in
        // `BindIdentity`, which the daemon relays verbatim from the caller, so a
        // substituted value is caller-chosen rather than attested. What keeps that
        // out of durable storage is that both durable paths refuse a bind whose
        // facts are not daemon-attested BEFORE reading this field:
        // `profile::StampedBindContext::validate` and `journal_pin`'s
        // `validate_bind_facts` each require attested provenance and a present
        // `agent_project_id`, with no substitution of their own. This value
        // therefore reaches only policy resolution that opens no profile storage.
        // Extending a compatibility path to durable state means reproducing those
        // refusals, not reusing this fallback.
        .unwrap_or_else(|| identity.project_root.to_string_lossy().into_owned())
}

fn admitted_session_kind(facts: Option<&Value>) -> Option<SessionKind> {
    fact(facts, &["sessionKind", "session_kind"])
        .and_then(Value::as_str)
        .and_then(SessionKind::from_str)
}

fn session_kind_from_facts(facts: Option<&Value>) -> SessionKind {
    // An absent or unrecognised kind resolves to Primary for identity purposes.
    // That default is not an attestation: the durable disposition path refuses
    // a kind nobody stamped, so a compatibility bind still resolves as Primary
    // without selecting the durable profile.
    admitted_session_kind(facts).unwrap_or(SessionKind::Primary)
}

fn control_operations_from_facts(facts: Option<&Value>) -> Vec<String> {
    fact(facts, &["browserControlOperations"])
        .and_then(Value::as_array)
        .map(|operations| {
            operations
                .iter()
                .filter_map(Value::as_str)
                .filter(|operation| {
                    matches!(
                        *operation,
                        "browser.launch" | "browser.status" | "browser.close"
                    )
                })
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn effective_capability_scope_from_facts(facts: Option<&Value>) -> Option<Vec<String>> {
    let value = fact(
        facts,
        &[
            "effectiveCapabilityScope",
            "effective_capability_scope",
            "capabilityScope",
            "capability_scope",
        ],
    )?;
    if let Some(scope) = value.as_str() {
        return Some(vec![scope.to_string()]);
    }
    if let Some(scope) = value.as_array() {
        return Some(
            scope
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
        );
    }
    let object = value.as_object()?;
    ["capabilities", "allowed", "tools"]
        .iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_array)
        .map(|scope| {
            scope
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
}

#[cfg(any(test, feature = "test-observer"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityResolutionObservation {
    pub conversation_key: String,
    pub agent_project_id: String,
    pub session_kind: SessionKind,
    pub logical_profile_key: Option<LogicalProfileKey>,
}

#[cfg(any(test, feature = "test-observer"))]
mod test_observer {
    use std::sync::{Mutex, OnceLock};

    use super::{IdentityResolutionObservation, LogicalProfileKey, RouteIdentity};

    static OBSERVATIONS: OnceLock<Mutex<Vec<IdentityResolutionObservation>>> = OnceLock::new();

    pub(super) fn record(identity: &RouteIdentity, logical_profile_key: Option<LogicalProfileKey>) {
        let observations = OBSERVATIONS.get_or_init(|| Mutex::new(Vec::new()));
        if let Ok(mut observations) = observations.lock() {
            observations.push(IdentityResolutionObservation {
                conversation_key: identity.conversation_key.clone(),
                agent_project_id: identity.agent_project_id.clone(),
                session_kind: identity.session_kind,
                logical_profile_key,
            });
        }
    }

    pub(super) fn take() -> Vec<IdentityResolutionObservation> {
        let observations = OBSERVATIONS.get_or_init(|| Mutex::new(Vec::new()));
        observations
            .lock()
            .map(|mut observations| std::mem::take(&mut *observations))
            .unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-observer"))]
fn record_test_observation(
    identity: &RouteIdentity,
    logical_profile_key: Option<LogicalProfileKey>,
) {
    test_observer::record(identity, logical_profile_key);
}

/// Drain observations produced by the test-only identity-resolution observer.
#[cfg(any(test, feature = "test-observer"))]
pub fn take_test_observations() -> Vec<IdentityResolutionObservation> {
    test_observer::take()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_route() -> RouteTarget {
        RouteTarget::ToolProvider {
            module_id: "cerebellum".to_string(),
        }
    }

    fn bind_identity(project_root: &str, session: &str) -> BindIdentity {
        BindIdentity::new(project_root, "opencode", session)
    }

    fn facts(project: &str, kind: &str) -> Value {
        serde_json::json!({
            "agentProjectId": project,
            "sessionKind": kind,
            "effectiveCapabilityScope": ["browser.status"],
        })
    }

    #[test]
    fn session_kind_round_trips() {
        for kind in [
            SessionKind::Primary,
            SessionKind::Subagent,
            SessionKind::Ephemeral,
        ] {
            assert_eq!(SessionKind::from_str(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn unknown_session_kind_is_none() {
        assert!(SessionKind::from_str("unknown").is_none());
    }

    #[test]
    fn profile_disposition_matches_session_kind() {
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Primary),
            ProfileDisposition::Durable
        );
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Subagent),
            ProfileDisposition::Disposable
        );
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Ephemeral),
            ProfileDisposition::None
        );
    }

    #[test]
    fn primary_resolves_default_durable_profile() {
        let identity = bind_identity("/tmp/project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-project", "primary")),
        );
        assert_eq!(
            route.resolve_profile(),
            ProfileResolution {
                profile_disposition: ProfileDisposition::Durable,
                profile_name: Some("default".to_string()),
                logical_profile_key: Some(("pj-project".to_string(), "default".to_string())),
            }
        );
    }

    #[test]
    fn subagent_resolves_conversation_scoped_disposable_profile() {
        let identity = bind_identity("/tmp/project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-project", "subagent")),
        );
        assert_eq!(
            route.resolve_profile(),
            ProfileResolution {
                profile_disposition: ProfileDisposition::Disposable,
                profile_name: Some("default".to_string()),
                logical_profile_key: Some(("pj-project".to_string(), "conversation-1".to_string())),
            }
        );
    }

    #[test]
    fn ephemeral_resolves_without_profile_name_or_key() {
        let identity = bind_identity("/tmp/project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-project", "ephemeral")),
        );
        assert_eq!(
            route.resolve_profile(),
            ProfileResolution {
                profile_disposition: ProfileDisposition::None,
                profile_name: None,
                logical_profile_key: None,
            }
        );
    }

    #[test]
    fn admitted_project_and_conversation_facts_are_not_request_fields() {
        let identity = bind_identity("/tmp/request-body-project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-accepted", "subagent")),
        );
        assert_eq!(route.agent_project_id, "pj-accepted");
        assert_eq!(route.conversation_key, "conversation-1");
    }

    /// `BindIdentity.project_id` (subc-protocol 0.20) is relayed by the daemon
    /// verbatim from the caller and is not attested. The durable-profile
    /// authority is the carrier-stamped `agentProjectId` in the admission
    /// facts; a caller-supplied id on the bind identity must neither become
    /// the route's project id nor count as attested provenance. A regression
    /// that read the new field here would let any bound caller name the
    /// durable profile it wants to open.
    #[test]
    fn a_caller_supplied_bind_identity_project_id_is_not_attested_provenance() {
        let mut bind = bind_identity("/caller/project", "conversation-1");
        bind.project_id = Some("pj-caller-claimed".to_string());

        let route = RouteIdentity::from_accepted_bind(&bind, &Some(Principal::Direct), None);
        assert_ne!(route.agent_project_id, "pj-caller-claimed");

        let accepted =
            AcceptedBindFacts::from_bind(&bind, Some(Principal::Direct), None, None, &tool_route());
        assert!(
            !accepted.agent_project_id_attested,
            "a project id on the bind identity is caller-chosen and must not read as attested"
        );
    }

    #[test]
    fn control_operation_requires_attested_project_kind_and_operation() {
        let bind = bind_identity("/caller/project", "conversation-1");
        let accepted = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            Some(&serde_json::json!({
                "agentProjectId": "pj-accepted",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["browser.launch"],
                "browserControlOperations": ["browser.launch"],
            })),
            None,
            &tool_route(),
        );
        assert!(accepted.allows_control_operation("browser.launch"));
        assert!(!accepted.allows_control_operation("browser.status"));

        for facts in [
            serde_json::json!({
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["browser.launch"],
                "browserControlOperations": ["browser.launch"],
            }),
            serde_json::json!({
                "agentProjectId": "pj-accepted",
                "effectiveCapabilityScope": ["browser.launch"],
                "browserControlOperations": ["browser.launch"],
            }),
        ] {
            let accepted = AcceptedBindFacts::from_bind(
                &bind,
                Some(Principal::Direct),
                Some(&facts),
                None,
                &tool_route(),
            );
            assert!(!accepted.allows_control_operation("browser.launch"));
        }
    }

    /// Each refusal names the fact that failed, as a literal wire code.
    ///
    /// The expected codes are written out rather than read back through
    /// `reason_code`, so a mapping that swapped two codes fails here instead of
    /// agreeing with itself. The no-facts case is the one a directly opened
    /// route produces, and it must not be reported as a carrier that dropped a
    /// single fact.
    #[test]
    fn a_control_refusal_names_the_fact_that_failed() {
        let bind = bind_identity("/caller/project", "conversation-1");
        let refusal = |facts: Option<serde_json::Value>| {
            AcceptedBindFacts::from_bind(
                &bind,
                Some(Principal::Direct),
                facts.as_ref(),
                None,
                &tool_route(),
            )
            .control_operation_refusal("browser.status")
            .map(ControlOperationRefusal::reason_code)
        };
        let granted = serde_json::json!(["browser.status"]);

        assert_eq!(refusal(None), Some("admission_facts_absent"));
        assert_eq!(
            refusal(Some(serde_json::json!({
                "sessionKind": "primary",
                "browserControlOperations": granted,
            }))),
            Some("agent_project_id_unattested")
        );
        assert_eq!(
            refusal(Some(serde_json::json!({
                "agentProjectId": "pj-accepted",
                "browserControlOperations": granted,
            }))),
            Some("session_kind_unattested")
        );
        assert_eq!(
            refusal(Some(serde_json::json!({
                "agentProjectId": "pj-accepted",
                "sessionKind": "primary",
                "browserControlOperations": ["browser.launch"],
            }))),
            Some("operation_not_granted")
        );
        assert_eq!(
            refusal(Some(serde_json::json!({
                "agentProjectId": "pj-accepted",
                "sessionKind": "primary",
                "browserControlOperations": granted,
            }))),
            None
        );
    }

    #[test]
    fn explicit_scope_is_enforced_without_request_body_input() {
        let bind = bind_identity("/tmp/project", "conversation-1");
        let accepted = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            Some(&serde_json::json!({
                "effective_capability_scope": ["other.capability"]
            })),
            None,
            &tool_route(),
        );
        assert!(!accepted.allows_capability("browser.status"));
    }

    /// The surface a route reaches is read from the bind, not from a request.
    ///
    /// The two surfaces this module could serve take different request
    /// envelopes, so parsing a request requires knowing which one arrived on.
    /// Inferring it from the body would let a caller reach one surface by
    /// sending the other's shape.
    #[test]
    fn each_route_target_names_its_surface() {
        let bind = bind_identity("/tmp/project", "conversation-1");

        let tools = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            None,
            None,
            &RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        );
        assert_eq!(tools.surface, RouteSurface::Tools);

        let management = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            None,
            None,
            &RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
        );
        assert_eq!(management.surface, RouteSurface::Management);
    }

    /// A surface this module does not advertise is named as unsupported.
    ///
    /// Not folded into either served surface: a request arriving on it must be
    /// refused with the surface named, and mapping it onto one of the others
    /// would serve that surface's callers from a route bound to something else.
    #[test]
    fn an_unadvertised_surface_is_neither_of_the_served_ones() {
        let bind = bind_identity("/tmp/project", "conversation-1");
        let internal = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            None,
            None,
            &RouteTarget::InternalService {
                module_id: "cerebellum".to_string(),
                service_id: "anything".to_string(),
            },
        );
        assert_eq!(internal.surface, RouteSurface::Unsupported);
    }

    /// A consumer that declares nothing can relay nothing.
    ///
    /// Absence must not read as an unknown the module resolves optimistically:
    /// attempting to ask a consumer that never claimed it could relay produces a
    /// question nobody receives, and the silence is indistinguishable from a
    /// human declining.
    #[test]
    fn a_bind_declaring_no_capabilities_cannot_relay_a_question() {
        let bind = bind_identity("/tmp/project", "conversation-1");
        let absent =
            AcceptedBindFacts::from_bind(&bind, Some(Principal::Direct), None, None, &tool_route());
        assert!(!absent.declares_elicitation());

        let empty = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            None,
            Some(&[]),
            &tool_route(),
        );
        assert!(!empty.declares_elicitation());
    }

    /// The declaration is read per family, not as a blanket claim.
    ///
    /// A consumer that services sampling has said nothing about reaching a
    /// human, so treating any non-empty declaration as elicitation would ask a
    /// consumer that never offered to answer.
    #[test]
    fn only_the_elicitation_family_admits_asking_a_human() {
        let bind = bind_identity("/tmp/project", "conversation-1");
        let other = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            None,
            Some(&["sampling".to_string(), "roots".to_string()]),
            &tool_route(),
        );
        assert!(!other.declares_elicitation());

        let declared = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            None,
            Some(&["sampling".to_string(), "elicitation".to_string()]),
            &tool_route(),
        );
        assert!(declared.declares_elicitation());
    }

    #[test]
    fn observer_records_identity_and_logical_key() {
        let identity = bind_identity("/tmp/project", "conversation-observed");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-observed", "subagent")),
        );
        let _ = route.resolve_profile();
        let observations = take_test_observations();
        assert!(observations.iter().any(|observation| {
            observation.conversation_key == "conversation-observed"
                && observation.agent_project_id == "pj-observed"
                && observation.session_kind == SessionKind::Subagent
                && observation.logical_profile_key
                    == Some((
                        "pj-observed".to_string(),
                        "conversation-observed".to_string(),
                    ))
        }));
    }

    #[test]
    fn legacy_bind_defaults_to_primary() {
        let identity = bind_identity("/tmp/project", "session-0001");
        let route = RouteIdentity::from_bind(&identity, &None);
        assert_eq!(route.session_kind, SessionKind::Primary);
        assert_eq!(route.profile_disposition, ProfileDisposition::Durable);
    }

    #[test]
    fn absent_session_kind_is_not_attested() {
        let identity = bind_identity("/tmp/project", "session-0001");
        let accepted = AcceptedBindFacts::from_bind(
            &identity,
            Some(Principal::Direct),
            Some(&serde_json::json!({
                "agentProjectId": "pj-attested",
            })),
            None,
            &tool_route(),
        );
        assert!(accepted.agent_project_id_attested);
        assert!(!accepted.session_kind_attested);
        assert_eq!(accepted.identity.session_kind, SessionKind::Primary);
        assert_eq!(
            accepted.identity.profile_disposition,
            ProfileDisposition::Durable
        );
    }

    #[test]
    fn distinct_projects_and_conversations_have_distinct_keys() {
        let same_conversation_a = bind_identity("/tmp/project-a", "conversation-shared");
        let same_conversation_b = bind_identity("/tmp/project-b", "conversation-shared");
        let project_a = RouteIdentity::from_accepted_bind(
            &same_conversation_a,
            &Some(Principal::Direct),
            Some(&facts("pj-a", "primary")),
        );
        let project_b = RouteIdentity::from_accepted_bind(
            &same_conversation_b,
            &Some(Principal::Direct),
            Some(&facts("pj-b", "primary")),
        );
        assert_ne!(
            project_a.resolve_profile().logical_profile_key,
            project_b.resolve_profile().logical_profile_key,
            "different projects must not share a durable profile key"
        );

        let same_project_a = bind_identity("/tmp/project", "conversation-a");
        let same_project_b = bind_identity("/tmp/project", "conversation-b");
        let conversation_a = RouteIdentity::from_accepted_bind(
            &same_project_a,
            &Some(Principal::Direct),
            Some(&facts("pj-shared", "subagent")),
        );
        let conversation_b = RouteIdentity::from_accepted_bind(
            &same_project_b,
            &Some(Principal::Direct),
            Some(&facts("pj-shared", "subagent")),
        );
        assert_ne!(
            conversation_a.resolve_profile().logical_profile_key,
            conversation_b.resolve_profile().logical_profile_key,
            "different subagent conversations must not share a disposable key"
        );
    }
}
