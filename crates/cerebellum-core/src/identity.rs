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
        match identity.profile_disposition {
            ProfileDisposition::Durable => Self {
                profile_disposition: ProfileDisposition::Durable,
                profile_name: Some("default".to_string()),
                logical_profile_key,
            },
            ProfileDisposition::Disposable => Self {
                profile_disposition: ProfileDisposition::Disposable,
                profile_name: Some("default".to_string()),
                logical_profile_key,
            },
            ProfileDisposition::None => Self {
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
    /// The request being served under this identity, marked when a plane
    /// commits a dispatch for it. A route's stored identity carries a detached
    /// one; the tool handler gives each request's copy its own.
    pub witness: crate::dispatch_witness::DispatchWitness,
    /// The caller behind the request being served, when another module
    /// relayed it, so the audit records written for it can name that caller.
    /// A route's stored identity carries none; the tool handler sets it on
    /// each request's copy. Attribution only: no admission, grant or call-key
    /// decision reads it.
    pub origin: crate::journal::CallOriginRecord,
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
            witness: crate::dispatch_witness::DispatchWitness::detached(),
            origin: crate::journal::CallOriginRecord::Absent,
        }
    }

    /// Compute the logical profile key without opening profile storage.
    pub fn logical_profile_key(&self) -> Option<LogicalProfileKey> {
        match self.profile_disposition {
            ProfileDisposition::Durable => {
                Some((self.agent_project_id.clone(), "default".to_string()))
            }
            ProfileDisposition::Disposable => {
                Some((self.agent_project_id.clone(), self.conversation_key.clone()))
            }
            ProfileDisposition::None => None,
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
    /// True only when the project id is daemon-vouched: either the bind's
    /// admission facts carried `agentProjectId` (stamped by the daemon's
    /// configured carrier, never by the caller), or an authorized scope stamp
    /// admitted for this route named it as `agent_id` (see [`Self::flow_id`]).
    /// The fallback that derives a project id from the caller's project root
    /// never counts.
    pub agent_project_id_attested: bool,
    /// Permits durable browser profiles and reading or offering standing browser
    /// and persistent application grants for the attested agent.
    pub acts_as_agent: bool,
    /// True only when daemon facts or an eligible scope identify the session kind; the
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
    /// The session scope the daemon stamped on this route's bind, if it was
    /// opened under one. The daemon's word, fixed for the route's life: a
    /// change that revokes authority closes the route instead. Never read from
    /// a request body. `None` for a route opened without a scope, which is
    /// served exactly as routes were before scopes existed.
    pub scope: Option<subc_protocol::scope::ScopeStamp>,
    /// Execution mode stamped by the daemon, never chosen by tool arguments.
    pub call_mode: subc_protocol::call_mode::CallMode,
    /// The flow's id, fixed at bind time and retained only for an admitted carrier.
    ///
    /// A **flow** is an unattended workflow that the Basal module runs on an
    /// agent's behalf, with no person available to answer a consent question.
    /// Its **owner** is the agent it acts for, named by `agent_id` in the scope stamp.
    /// A **scope stamp** is session identity the daemon attaches to a route's bind;
    /// the session owner writes it, not the caller. It is **authorized** when its
    /// stamp owner is `reserved:prefrontal-core` and the daemon reports that owner
    /// as a configured scope authority (`owner_authorized`). The **carrier** is
    /// the module that opened the route; for a flow it must be `reserved:basal`.
    pub flow_id: Option<String>,
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
            acts_as_agent: admitted_agent_project_id(admission_facts).is_some(),
            session_kind_attested: admitted_session_kind(admission_facts).is_some(),
            control_operations: control_operations_from_facts(admission_facts),
            // A bind carrying a scope under a retired name is refused before it
            // is retained (see `admission_facts_refusal`). Should any caller
            // build facts from such a bind without that check, the scope is
            // taken as explicitly empty rather than absent: absent means the
            // permissive default, and a scope the carrier meant to restrict
            // must never widen into it.
            effective_capability_scope: if misplaced_capability_scope_key(admission_facts).is_some()
            {
                Some(Vec::new())
            } else {
                effective_capability_scope_from_facts(admission_facts)
            },
            consumer_capabilities: consumer_capabilities.unwrap_or_default().to_vec(),
            surface: RouteSurface::from_target(target),
            scope: None,
            call_mode: subc_protocol::call_mode::CallMode::Classic,
            flow_id: None,
        }
    }

    /// Attach the scope stamp the daemon put on the bind (`None` for a route
    /// opened without a scope).
    pub fn with_scope(mut self, scope: Option<subc_protocol::scope::ScopeStamp>) -> Self {
        if let Some(stamp) = scope
            .as_ref()
            .filter(|stamp| flow_carrier_admitted(stamp, &self.principal))
        {
            self.flow_id = stamp.attributes.flow_id.clone();
            // On a flow route, bind admission facts identify the carrier (Basal),
            // so discard them. Only the scope stamp's `agent_id` names the owner.
            self.identity.agent_project_id.clear();
            self.identity.profile_disposition = ProfileDisposition::None;
            self.agent_project_id_attested = false;
            self.session_kind_attested = false;
            self.acts_as_agent = false;
            self.control_operations.clear();
        }
        if let Some(stamp) = scope
            .as_ref()
            .filter(|stamp| scope_admission_eligible(stamp, &self.principal))
        {
            if let Some(agent) = stamp
                .attributes
                .agent_id
                .as_ref()
                .filter(|_| self.flow_id.is_none() || stamp.attributes.delegates)
            {
                self.identity.agent_project_id = agent.clone();
                // A run's ephemeral lifetime does not change the head browser's
                // storage identity. Its bind still names the head conversation.
                if stamp.attributes.run_id.is_none() {
                    self.identity.session_kind = session_kind_from_scope(stamp.kind);
                }
                self.identity.profile_disposition = if !stamp.attributes.delegates
                    && self.identity.session_kind == SessionKind::Primary
                {
                    ProfileDisposition::None
                } else {
                    ProfileDisposition::for_session_kind(self.identity.session_kind)
                };
                self.agent_project_id_attested = true;
                self.session_kind_attested = true;
                self.acts_as_agent = stamp.attributes.delegates;
                self.control_operations = match if stamp.attributes.run_id.is_some() {
                    match self.identity.session_kind {
                        SessionKind::Primary => subc_protocol::scope::ScopeKind::Head,
                        SessionKind::Subagent => subc_protocol::scope::ScopeKind::Worker,
                        SessionKind::Ephemeral => subc_protocol::scope::ScopeKind::Ephemeral,
                    }
                } else {
                    stamp.kind
                } {
                    subc_protocol::scope::ScopeKind::Head
                    | subc_protocol::scope::ScopeKind::Worker => {
                        ["browser.launch", "browser.status", "browser.close"]
                            .map(String::from)
                            .to_vec()
                    }
                    subc_protocol::scope::ScopeKind::Ephemeral => Vec::new(),
                };
            }
        }
        self.scope = scope;
        self
    }

    /// Why these admission facts must refuse the bind outright, if they must.
    ///
    /// The route is not bound at all when this returns a refusal, so nothing on
    /// it is served.
    pub fn admission_facts_refusal(
        admission_facts: Option<&Value>,
    ) -> Option<AdmissionFactsRefusal> {
        misplaced_capability_scope_key(admission_facts)
            .map(|key| AdmissionFactsRefusal::CapabilityScopeMisspelled { key })
    }

    /// Refuse a bind when its eligible scope stamp and daemon admission facts
    /// name different agents or session kinds, rather than choosing one claim.
    pub fn scope_facts_refusal(
        principal: &Option<Principal>,
        scope: Option<&subc_protocol::scope::ScopeStamp>,
        facts: Option<&Value>,
    ) -> Option<AdmissionFactsRefusal> {
        let stamp = scope.filter(|stamp| scope_admission_eligible(stamp, principal))?;
        let agent = stamp.attributes.agent_id.as_deref()?;
        if admitted_agent_project_id(facts).is_some_and(|fact| fact != agent) {
            return Some(AdmissionFactsRefusal::ScopeFactsConflict {
                field: "agentProjectId",
            });
        }
        if stamp.attributes.run_id.is_none()
            && admitted_session_kind(facts)
                .is_some_and(|kind| kind != session_kind_from_scope(stamp.kind))
        {
            return Some(AdmissionFactsRefusal::ScopeFactsConflict {
                field: "sessionKind",
            });
        }
        None
    }

    /// Used by reverse-lane cards until those flows move to Cingulate.
    /// Whether the consumer declared it can relay a question to a human.
    ///
    /// True means asking is worth attempting, never that an answer will arrive.
    pub fn declares_elicitation(&self) -> bool {
        self.flow_id.is_none()
            && self.call_mode == subc_protocol::call_mode::CallMode::Classic
            && self
                .consumer_capabilities
                .iter()
                .any(|family| family == ELICITATION_CAPABILITY)
    }

    /// Consumer declarations retained from the daemon's accepted route bind.
    /// An absent or empty list declares no reverse requests or result readers.
    pub fn consumer_capabilities(&self) -> Option<&[String]> {
        (!self.consumer_capabilities.is_empty()).then_some(self.consumer_capabilities.as_slice())
    }

    /// Whether daemon-attested bind facts admit this control operation. Caller
    /// request fields cannot substitute for missing identity or authority facts.
    pub fn allows_control_operation(&self, operation: &str) -> bool {
        self.control_operation_refusal(operation).is_none()
    }

    /// A missing scoped identity must be repaired by the scope owner, not by
    /// adding caller-controlled request fields or enabling a legacy carrier.
    pub fn control_refusal_remedy(&self, refusal: ControlOperationRefusal) -> &'static str {
        if self.scope.is_some() && !self.agent_project_id_attested {
            "this scoped route has no attested agent; ask prefrontal-core to open a non-flow scope with agent_id under its authorized owner, or use a route with daemon admission facts"
        } else {
            refusal.remedy()
        }
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

    /// Whether this route's opener may make calls in a conversation's name.
    ///
    /// Read from the daemon-stamped principal alone: the conversation key and
    /// admission facts on the bind say which conversation a call would act in,
    /// never whether this caller may act in one.
    pub fn admits_session_calls(&self) -> bool {
        self.flow_id.is_some() || crate::principal::admits_session_calls(&self.principal)
    }

    /// These facts as an operator's call outside any conversation sees them.
    ///
    /// Every standing permission is keyed on the conversation or the agent
    /// project, so the view carries neither: an empty conversation key (which
    /// no grant is ever recorded under), no project id, the ephemeral session
    /// kind (which resolves no browser profile), no attested facts, no browser
    /// controls and an explicitly empty capability scope. An operator whose
    /// route happens to name a live conversation therefore still sees none of
    /// that conversation's grants. The principal and surface are kept, but no
    /// agent session remains under which an operator could raise a permission card.
    pub fn outside_session_scope(&self) -> Self {
        Self {
            identity: RouteIdentity {
                conversation_key: String::new(),
                agent_project_id: String::new(),
                session_kind: SessionKind::Ephemeral,
                profile_disposition: ProfileDisposition::None,
                project_root: self.identity.project_root.clone(),
                witness: self.identity.witness.clone(),
                origin: self.identity.origin.clone(),
            },
            principal: self.principal.clone(),
            agent_project_id_attested: false,
            acts_as_agent: false,
            session_kind_attested: false,
            control_operations: Vec::new(),
            effective_capability_scope: Some(Vec::new()),
            consumer_capabilities: self.consumer_capabilities.clone(),
            surface: self.surface,
            call_mode: self.call_mode.clone(),
            // A scope is session identity, like the conversation above, so an
            // operator's view outside any session carries none.
            scope: None,
            flow_id: None,
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

fn scope_admission_eligible(
    stamp: &subc_protocol::scope::ScopeStamp,
    principal: &Option<Principal>,
) -> bool {
    let core = Principal::Reserved {
        module_id: "prefrontal-core".to_string(),
    };
    flow_carrier_admitted(stamp, principal)
        || (stamp.owner_authorized
            && stamp.owner == core
            && principal.as_ref() == Some(&core)
            && stamp.attributes.flow_id.is_none())
}

/// Check that `flow_id` is present, `owner_authorized` is true, the stamp owner
/// is `reserved:prefrontal-core`, and the route principal is `reserved:basal`.
/// This is the only way a module outside the first-party list may bind a route.
/// For flow vocabulary, see [`AcceptedBindFacts::flow_id`].
pub fn flow_carrier_admitted(
    stamp: &subc_protocol::scope::ScopeStamp,
    principal: &Option<Principal>,
) -> bool {
    stamp.attributes.flow_id.is_some()
        && stamp.owner_authorized
        && stamp.owner
            == Principal::Reserved {
                module_id: "prefrontal-core".into(),
            }
        && principal.as_ref()
            == Some(&Principal::Reserved {
                module_id: "basal".into(),
            })
}

/// Map daemon scope kinds explicitly to the older session-kind vocabulary.
fn session_kind_from_scope(kind: subc_protocol::scope::ScopeKind) -> SessionKind {
    match kind {
        subc_protocol::scope::ScopeKind::Head => SessionKind::Primary,
        subc_protocol::scope::ScopeKind::Worker => SessionKind::Subagent,
        subc_protocol::scope::ScopeKind::Ephemeral => SessionKind::Ephemeral,
    }
}

/// Why a bind's admission facts are refused before the route is bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionFactsRefusal {
    /// A capability scope was stamped under a name or location this module no
    /// longer reads. `key` is where it was found, as a dotted path from the
    /// root of the facts (for example `accepted.effectiveCapabilityScope`).
    CapabilityScopeMisspelled { key: String },
    /// The scope stamp and daemon admission facts disagree about this identity field.
    ScopeFactsConflict { field: &'static str },
}

impl AdmissionFactsRefusal {
    /// The wire reason code.
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::CapabilityScopeMisspelled { .. } => "admission_fact_misspelled",
            Self::ScopeFactsConflict { .. } => "scope_admission_conflict",
        }
    }

    /// A human-readable account of the refusal and what to do about it.
    pub fn message(&self) -> String {
        match self {
            Self::ScopeFactsConflict { field } => format!("scope stamp and admission facts disagree about {field}; reopen the route with consistent daemon-stamped identity"),
            Self::CapabilityScopeMisspelled { key } => format!(
                "the admission facts carry a capability scope at '{key}', which is not read; \
                 the scope is read only from the root key 'effectiveCapabilityScope'. The bind \
                 is refused rather than admitted without the restriction the scope was meant \
                 to impose; restamp the scope under that key"
            ),
        }
    }

    /// Structured facts about the refusal, for the error body's `detail`.
    pub fn detail(&self) -> Value {
        match self {
            Self::ScopeFactsConflict { field } => serde_json::json!({"field": field}),
            Self::CapabilityScopeMisspelled { key } => serde_json::json!({
                "key": key,
                "expected_key": "effectiveCapabilityScope",
            }),
        }
    }
}

/// The reverse-request family that carries a question to a human, as spelled on
/// the wire.
pub const ELICITATION_CAPABILITY: &str = "elicitation";

/// Read one admission fact by its single exact name, at the root of the facts
/// object and nowhere else.
///
/// The admission carrier stamps each fact at the root in camelCase, and these
/// facts decide which durable browser profile a route opens and which browser
/// controls it may call. Every additional place a fact could be read from (a
/// nested object, another spelling, a similarly named key from a different
/// schema) is another way to pick up a value the carrier never stamped for this
/// purpose, so there is exactly one. Every other key is an unknown fact and is
/// ignored rather than refused: providers ignore facts they do not recognise,
/// so a carrier can add facts for other consumers without breaking this one.
/// The one exception is a capability scope in a place it used to be read from,
/// which refuses the bind instead; `misplaced_capability_scope_key` says why.
fn fact<'a>(facts: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    facts?.as_object()?.get(name)
}

/// Root names under which a capability scope used to be read and no longer is.
const RETIRED_CAPABILITY_SCOPE_NAMES: [&str; 3] = [
    "effective_capability_scope",
    "capabilityScope",
    "capability_scope",
];

/// Nested objects under which any spelling of the capability scope used to be
/// read and no longer is.
const RETIRED_FACT_CONTAINERS: [&str; 4] = ["accepted", "bind", "bind_identity", "identity"];

/// Where a capability scope sits that this module used to read and no longer
/// does, as a dotted path from the root of the facts.
///
/// Unlike every other fact, the scope RESTRICTS: when it is absent the route
/// receives the permissive first-party default. Ignoring a scope written in a
/// retired place would therefore silently widen the route to everything,
/// whereas ignoring a retired spelling of a granting fact only refuses. So a
/// retired scope location is refused rather than treated as an unknown fact.
/// Any other unknown key stays ignored.
fn misplaced_capability_scope_key(facts: Option<&Value>) -> Option<String> {
    let root = facts?.as_object()?;
    if let Some(name) = RETIRED_CAPABILITY_SCOPE_NAMES
        .iter()
        .find(|name| root.contains_key(**name))
    {
        return Some((*name).to_string());
    }
    RETIRED_FACT_CONTAINERS.iter().find_map(|container| {
        let nested = root.get(*container)?.as_object()?;
        std::iter::once("effectiveCapabilityScope")
            .chain(RETIRED_CAPABILITY_SCOPE_NAMES)
            .find(|name| nested.contains_key(*name))
            .map(|name| format!("{container}.{name}"))
    })
}

fn admitted_agent_project_id(facts: Option<&Value>) -> Option<&str> {
    fact(facts, "agentProjectId")
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
    fact(facts, "sessionKind")
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
    fact(facts, "browserControlOperations")
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
    let value = fact(facts, "effectiveCapabilityScope")?;
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

    #[test]
    fn scope_admission_ephemeral_kind_is_not_worker() {
        let core = Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let stamp = subc_protocol::scope::ScopeStamp::new(
            core.clone(),
            "ephemeral",
            1,
            subc_protocol::scope::ScopeKind::Ephemeral,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("pj-agent".into()))
                .with_delegates(true),
        )
        .with_owner_authorized(true);
        let accepted = AcceptedBindFacts::from_bind(
            &bind_identity("/caller/project", "conversation"),
            Some(core),
            None,
            None,
            &tool_route(),
        )
        .with_scope(Some(stamp));
        assert_eq!(accepted.identity.session_kind, SessionKind::Ephemeral);
        assert_eq!(
            accepted.identity.profile_disposition,
            ProfileDisposition::None
        );
        assert!(accepted.control_operations.is_empty());
    }

    #[test]
    fn scope_admission_flow_stamp_attests_nothing() {
        let core = Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let stamp = subc_protocol::scope::ScopeStamp::new(
            core.clone(),
            "flow-head",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("pj-agent".into()))
                .with_delegates(true)
                .with_flow_id(Some("flow".into())),
        )
        .with_owner_authorized(true);
        let accepted = AcceptedBindFacts::from_bind(
            &bind_identity("/caller/project", "conversation"),
            Some(core),
            None,
            None,
            &tool_route(),
        )
        .with_scope(Some(stamp));
        assert!(!accepted.agent_project_id_attested);
        assert!(!accepted.session_kind_attested);
        assert!(!accepted.acts_as_agent);
        assert!(accepted.control_operations.is_empty());
        assert_eq!(accepted.effective_capability_scope, None);
    }

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

    /// Admit a bind carrying `facts` and report the control refusal for
    /// `browser.launch`, alongside the accepted facts themselves.
    fn launch_refusal(facts: serde_json::Value) -> (AcceptedBindFacts, Option<&'static str>) {
        let accepted = AcceptedBindFacts::from_bind(
            &bind_identity("/caller/project", "conversation-1"),
            Some(Principal::Direct),
            Some(&facts),
            None,
            &tool_route(),
        );
        let refusal = accepted
            .control_operation_refusal("browser.launch")
            .map(ControlOperationRefusal::reason_code);
        (accepted, refusal)
    }

    /// A project id anywhere but the root `agentProjectId` key is not admitted.
    ///
    /// The durable profile a route opens is keyed on this fact, so a value read
    /// from a nested object or under another spelling, possibly a different
    /// schema's `projectId`, would select a profile the carrier never named.
    /// Each misplaced id must leave the bind exactly as if the fact were absent:
    /// unattested, refused by name, and falling back to the unattested project
    /// root that durable storage refuses.
    #[test]
    fn a_project_id_outside_the_root_camel_case_key_is_not_admitted() {
        let (absent, absent_refusal) = launch_refusal(serde_json::json!({
            "sessionKind": "primary",
            "browserControlOperations": ["browser.launch"],
        }));
        assert!(!absent.agent_project_id_attested);
        assert_eq!(absent_refusal, Some("agent_project_id_unattested"));

        for (shape, facts) in [
            (
                "nested under accepted",
                serde_json::json!({
                    "sessionKind": "primary",
                    "browserControlOperations": ["browser.launch"],
                    "accepted": {"agentProjectId": "pj-misplaced"},
                }),
            ),
            (
                "nested under bind",
                serde_json::json!({
                    "sessionKind": "primary",
                    "browserControlOperations": ["browser.launch"],
                    "bind": {"agentProjectId": "pj-misplaced"},
                }),
            ),
            (
                "nested under bind_identity",
                serde_json::json!({
                    "sessionKind": "primary",
                    "browserControlOperations": ["browser.launch"],
                    "bind_identity": {"agentProjectId": "pj-misplaced"},
                }),
            ),
            (
                "nested under identity",
                serde_json::json!({
                    "sessionKind": "primary",
                    "browserControlOperations": ["browser.launch"],
                    "identity": {"agentProjectId": "pj-misplaced"},
                }),
            ),
            (
                "spelled agent_project_id",
                serde_json::json!({
                    "sessionKind": "primary",
                    "browserControlOperations": ["browser.launch"],
                    "agent_project_id": "pj-misplaced",
                }),
            ),
            (
                "spelled projectId",
                serde_json::json!({
                    "sessionKind": "primary",
                    "browserControlOperations": ["browser.launch"],
                    "projectId": "pj-misplaced",
                }),
            ),
            (
                "spelled project_id",
                serde_json::json!({
                    "sessionKind": "primary",
                    "browserControlOperations": ["browser.launch"],
                    "project_id": "pj-misplaced",
                }),
            ),
        ] {
            let (accepted, refusal) = launch_refusal(facts);
            assert!(!accepted.agent_project_id_attested, "{shape}");
            assert_eq!(refusal, absent_refusal, "{shape}");
            assert_eq!(
                accepted.identity, absent.identity,
                "{shape}: the misplaced id must not reach the route identity"
            );
        }
    }

    /// A session kind spelled `session_kind` is not admitted, and neither is
    /// a control-operation list nested under another object: each refuses as
    /// if its fact were absent.
    #[test]
    fn a_session_kind_or_operation_list_outside_its_root_key_is_not_admitted() {
        let (absent_kind, absent_kind_refusal) = launch_refusal(serde_json::json!({
            "agentProjectId": "pj-accepted",
            "browserControlOperations": ["browser.launch"],
        }));
        assert_eq!(absent_kind_refusal, Some("session_kind_unattested"));
        let (snake_kind, snake_kind_refusal) = launch_refusal(serde_json::json!({
            "agentProjectId": "pj-accepted",
            "session_kind": "subagent",
            "browserControlOperations": ["browser.launch"],
        }));
        assert!(!snake_kind.session_kind_attested);
        assert_eq!(snake_kind_refusal, absent_kind_refusal);
        assert_eq!(snake_kind.identity, absent_kind.identity);

        let (absent_operations, absent_operations_refusal) = launch_refusal(serde_json::json!({
            "agentProjectId": "pj-accepted",
            "sessionKind": "primary",
        }));
        assert_eq!(absent_operations_refusal, Some("operation_not_granted"));
        for container in ["accepted", "bind", "bind_identity", "identity"] {
            let (nested, nested_refusal) = launch_refusal(serde_json::json!({
                "agentProjectId": "pj-accepted",
                "sessionKind": "primary",
                container: {"browserControlOperations": ["browser.launch"]},
            }));
            assert!(nested.control_operations.is_empty(), "{container}");
            assert_eq!(nested_refusal, absent_operations_refusal, "{container}");
            assert_eq!(
                nested.control_operations,
                absent_operations.control_operations
            );
        }
    }

    /// A fact this module does not know is ignored, never refused, so a
    /// carrier can stamp facts for other consumers beside the ones read here.
    #[test]
    fn an_unknown_top_level_fact_beside_the_three_root_keys_admits_normally() {
        let (accepted, refusal) = launch_refusal(serde_json::json!({
            "agentProjectId": "pj-accepted",
            "sessionKind": "primary",
            "browserControlOperations": ["browser.launch"],
            "ck.project-trust/v1": {"projectId": "pj-other-schema", "trusted": true},
        }));
        assert_eq!(refusal, None);
        assert!(accepted.agent_project_id_attested);
        assert!(accepted.session_kind_attested);
        assert_eq!(accepted.identity.agent_project_id, "pj-accepted");
        assert_eq!(accepted.identity.session_kind, SessionKind::Primary);
    }

    /// A capability scope under a retired name or inside a retired container
    /// refuses the bind by name, and the facts built from such a bind never
    /// carry the permissive absent scope.
    ///
    /// The scope restricts, so ignoring it as an unknown fact would admit the
    /// route with every capability. Keys that are not retired scope locations,
    /// including another schema's object and a misplaced granting fact, are
    /// still ignored.
    #[test]
    fn a_capability_scope_in_a_retired_place_refuses_rather_than_widening() {
        let bind = bind_identity("/tmp/project", "conversation-1");
        let base = serde_json::json!({
            "agentProjectId": "pj-accepted",
            "sessionKind": "primary",
            "browserControlOperations": ["browser.launch"],
        });
        let mut cases = Vec::new();
        for name in RETIRED_CAPABILITY_SCOPE_NAMES {
            let mut facts = base.clone();
            facts[name] = serde_json::json!(["other.capability"]);
            cases.push((name.to_string(), facts));
        }
        for container in RETIRED_FACT_CONTAINERS {
            for name in [
                "effectiveCapabilityScope",
                "effective_capability_scope",
                "capabilityScope",
                "capability_scope",
            ] {
                let mut facts = base.clone();
                facts[container] = serde_json::json!({ name: ["other.capability"] });
                cases.push((format!("{container}.{name}"), facts));
            }
        }
        assert_eq!(cases.len(), 19);

        for (key, facts) in cases {
            assert_eq!(
                AcceptedBindFacts::admission_facts_refusal(Some(&facts)),
                Some(AdmissionFactsRefusal::CapabilityScopeMisspelled { key: key.clone() }),
                "{key}"
            );
            let accepted = AcceptedBindFacts::from_bind(
                &bind,
                Some(Principal::Direct),
                Some(&facts),
                None,
                &tool_route(),
            );
            assert_eq!(
                accepted.effective_capability_scope,
                Some(Vec::new()),
                "{key}: a retired scope must not read as the absent, permissive one"
            );
            assert!(!accepted.allows_capability("browser.status"), "{key}");
        }

        for (shape, facts) in [
            ("no scope", base.clone()),
            (
                "scope under its read name",
                serde_json::json!({"effectiveCapabilityScope": ["browser.status"]}),
            ),
            (
                "another schema's object",
                serde_json::json!({"ck.project-trust/v1": {"capabilityScope": ["x"]}}),
            ),
            (
                "a misplaced granting fact",
                serde_json::json!({"accepted": {"agentProjectId": "pj-misplaced"}}),
            ),
        ] {
            assert_eq!(
                AcceptedBindFacts::admission_facts_refusal(Some(&facts)),
                None,
                "{shape}"
            );
        }
        assert_eq!(AcceptedBindFacts::admission_facts_refusal(None), None);
    }

    #[test]
    fn explicit_scope_is_enforced_without_request_body_input() {
        let bind = bind_identity("/tmp/project", "conversation-1");
        let accepted = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            Some(&serde_json::json!({
                "effectiveCapabilityScope": ["other.capability"]
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

    /// An operator's call outside any conversation keeps nothing that a
    /// standing permission or a durable profile is keyed on, even when its
    /// route named a conversation and carried fully attested facts.
    #[test]
    fn outside_session_scope_carries_no_session_identity() {
        let accepted = AcceptedBindFacts::from_bind(
            &bind_identity("/tmp/project", "conversation-live"),
            Some(Principal::Direct),
            Some(&serde_json::json!({
                "agentProjectId": "pj-live",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
                "browserControlOperations": ["browser.launch"],
            })),
            Some(&[ELICITATION_CAPABILITY.to_string()]),
            &RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
        );
        let operator = accepted.outside_session_scope();
        assert_eq!(operator.identity.conversation_key, "");
        assert_eq!(operator.identity.agent_project_id, "");
        assert_eq!(operator.identity.session_kind, SessionKind::Ephemeral);
        assert_eq!(operator.identity.logical_profile_key(), None);
        assert!(!operator.agent_project_id_attested);
        assert!(!operator.session_kind_attested);
        assert!(!operator.allows_control_operation("browser.launch"));
        assert!(!operator.allows_capability("browser.status"));
        // Kept: who opened the route, which surface it reaches, and whether
        // it can relay the operator's question to a person.
        assert_eq!(operator.principal, Some(Principal::Direct));
        assert_eq!(operator.surface, RouteSurface::Management);
        assert!(operator.declares_elicitation());
    }

    #[test]
    fn only_a_prefrontal_core_bind_admits_session_calls() {
        let bind = |principal| {
            AcceptedBindFacts::from_bind(
                &bind_identity("/tmp/project", "conversation-live"),
                principal,
                Some(&facts("pj-live", "primary")),
                None,
                &tool_route(),
            )
        };
        assert!(bind(Some(Principal::Reserved {
            module_id: "prefrontal-core".to_string()
        }))
        .admits_session_calls());
        assert!(!bind(Some(Principal::Direct)).admits_session_calls());
        assert!(!bind(Some(Principal::Reserved {
            module_id: "aft".to_string()
        }))
        .admits_session_calls());
    }
}
