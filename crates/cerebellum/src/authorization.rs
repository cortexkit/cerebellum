//! Action-grant selection and immutable authorization decisions for the browser
//! authorization contract.
//!
//! This module owns the semantic part of authorization. Browser and connector
//! integrations retain the returned decision; they must not query ambient grant
//! state again after dispatch commitment.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::agent_grants::{AgentGrants, BrowserTarget, GrantDemand, GrantHolder, GrantUse};
use crate::browser_standing_grants::StandingBrowserGrants;
use crate::classification::{
    canonical_grant_origin, canonical_origin, NonTypeClassificationFingerprint,
    NonTypeClassificationRecord,
};

/// The start of the grant id of every decision made under a standing browser
/// row rather than a conversation grant. The rest of the id is the row's key,
/// which commit uses to check the row is still in force.
pub const STANDING_GRANT_ID_PREFIX: &str = "standing:";

/// The agent a browser request is served for, when its identity was attested
/// by the daemon, so that standing browser rows of that agent may be consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingCaller {
    /// The attested `agentProjectId`.
    pub holder: GrantHolder,
}

tokio::task_local! {
    /// Set around one browser request by the code that knows whether its
    /// route's agent identity is attested. Authorization reads it rather than
    /// taking it as an argument because the browser plane builds its requests
    /// from a route identity that does not carry the attestation. A request
    /// served outside such a scope, or on a task spawned from it, sees no
    /// caller and is authorized by conversation grants alone.
    static STANDING_CALLER: Option<StandingCaller>;
    static FLOW: bool;
}

/// Run `future` with `caller` as the agent whose standing browser rows may
/// authorize it. `None` hides any caller an enclosing scope set.
pub async fn with_standing_caller<F: std::future::Future>(
    caller: Option<StandingCaller>,
    future: F,
) -> F::Output {
    STANDING_CALLER.scope(caller, future).await
}

/// A flow (see `AcceptedBindFacts::flow_id`) uses its owner's persistent
/// (standing) browser grants, never grants given for one conversation with a person.
pub(crate) async fn with_flow<F: std::future::Future>(flow: bool, future: F) -> F::Output {
    FLOW.scope(flow, future).await
}

fn current_standing_caller() -> Option<StandingCaller> {
    STANDING_CALLER.try_with(Clone::clone).ok().flatten()
}

pub const OBSERVE: u8 = 1;
pub const COMPOSE: u8 = 2;
pub const PUBLIC_WEB_BASELINE: &str = "public_web_baseline";

/// Public browsing has no human approval to revoke. Sensitive or lasting
/// actions still go through the ordinary site-grant and disclosure checks.
pub fn public_web_baseline_covers(
    origin: &str,
    required: Severity,
    hazards: &BTreeSet<HazardClass>,
) -> bool {
    required.tier <= COMPOSE
        && !required.credential
        && !required.financial
        && hazards.is_empty()
        && crate::browser_standing_grants::origin_is_public(origin)
}
pub const MUTATE_REVERSIBLE: u8 = 3;
pub const MUTATE_DURABLE: u8 = 4;
pub const ACTUATE: u8 = 5;
pub const MAX_ORIGINS: usize = 256;
/// The highest ceiling `browser.open_grant` mints. Actuation is never granted
/// to the browser, so a declared tier above this cannot be covered by asking.
pub const MAX_GRANTABLE_TIER: u8 = MUTATE_DURABLE;

/// Target facts a person must be told before a grant can cover the action.
///
/// This vocabulary is closed so the mint and dispatch cannot each invent a
/// spelling that the other side never understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HazardClass {
    CredentialFormSubmit,
    FinancialFormSubmit,
    UnverifiedFormContents,
}

impl HazardClass {
    pub const ALL: [Self; 3] = [
        Self::CredentialFormSubmit,
        Self::FinancialFormSubmit,
        Self::UnverifiedFormContents,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialFormSubmit => "credential_form_submit",
            Self::FinancialFormSubmit => "financial_form_submit",
            Self::UnverifiedFormContents => "unverified_form_contents",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|hazard| hazard.as_str() == value)
    }
}

impl fmt::Display for HazardClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Names for the closed `ck-action-severity/v1` tier vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SeverityTier {
    Observe = OBSERVE,
    Compose = COMPOSE,
    MutateReversible = MUTATE_REVERSIBLE,
    MutateDurable = MUTATE_DURABLE,
    Actuate = ACTUATE,
}

impl SeverityTier {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for SeverityTier {
    type Error = AuthorizationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            OBSERVE => Ok(Self::Observe),
            COMPOSE => Ok(Self::Compose),
            MUTATE_REVERSIBLE => Ok(Self::MutateReversible),
            MUTATE_DURABLE => Ok(Self::MutateDurable),
            ACTUATE => Ok(Self::Actuate),
            _ => Err(AuthorizationError::InvalidSeverityTier),
        }
    }
}

/// A severity declaration or computed requirement.  Flags are independent of
/// the tier and are combined by logical OR when effective severity is formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Severity {
    pub tier: u8,
    pub credential: bool,
    pub financial: bool,
}

pub type ActionSeverity = Severity;
pub type Grant = ActionGrant;

impl Severity {
    pub const fn new(tier: u8, credential: bool, financial: bool) -> Self {
        Self {
            tier,
            credential,
            financial,
        }
    }

    pub const fn from_tier(tier: SeverityTier) -> Self {
        Self::new(tier as u8, false, false)
    }

    pub fn validate(self) -> Result<(), AuthorizationError> {
        SeverityTier::try_from(self.tier).map(|_| ())
    }

    pub fn covers(self, required: Self) -> bool {
        self.tier >= required.tier
            && (!required.credential || self.credential)
            && (!required.financial || self.financial)
    }

    pub fn maximum(self, other: Self) -> Self {
        Self {
            tier: self.tier.max(other.tier),
            credential: self.credential || other.credential,
            financial: self.financial || other.financial,
        }
    }
}

/// An action that cannot be protected by a separate execution fence; its grant
/// is evaluated by the authorization policy defined in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Navigate,
    Snapshot,
    Screenshot,
    Click,
    ClickPoint,
    Type,
}

pub type CapabilityAction = Action;

impl Action {
    pub const fn floor(self) -> Severity {
        match self {
            Self::Navigate | Self::Snapshot | Self::Screenshot => {
                Severity::new(OBSERVE, false, false)
            }
            Self::Click | Self::ClickPoint | Self::Type => Severity::new(COMPOSE, false, false),
        }
    }
}

/// A grant scoped to one conversation. Each grant has an identifier, revision,
/// severity requirement, authorized origins, and the target hazards disclosed to
/// the person who issued it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionGrant {
    agent_grant: Option<GrantUse>,
    pub id: String,
    pub revision: u64,
    pub conversation_key: String,
    pub severity: Severity,
    pub authorized_origins: Vec<String>,
    pub disclosed_hazards: BTreeSet<HazardClass>,
}

impl ActionGrant {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        conversation_key: impl Into<String>,
        severity: Severity,
        authorized_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            agent_grant: None,
            id: id.into(),
            revision,
            conversation_key: conversation_key.into(),
            severity,
            authorized_origins: authorized_origins.into_iter().map(Into::into).collect(),
            // Empty is the safe compatibility default for direct test grants: it
            // covers targets with no classified hazards and never silently grants
            // consent for a form hazard nobody disclosed.
            disclosed_hazards: BTreeSet::new(),
        }
    }

    pub fn with_disclosed_hazards(
        mut self,
        hazards: impl IntoIterator<Item = HazardClass>,
    ) -> Self {
        self.disclosed_hazards = hazards.into_iter().collect();
        self
    }

    pub fn for_conversation(
        id: impl Into<String>,
        revision: u64,
        conversation_key: impl Into<String>,
        severity: Severity,
        authorized_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(id, revision, conversation_key, severity, authorized_origins)
    }

    pub fn grant_id(&self) -> &str {
        &self.id
    }

    pub fn validate(&self) -> Result<(), AuthorizationError> {
        if self.id.is_empty() || self.conversation_key.is_empty() || self.revision == 0 {
            return Err(AuthorizationError::InvalidGrant);
        }
        self.severity.validate()?;
        if self.authorized_origins.len() > MAX_ORIGINS {
            return Err(AuthorizationError::OriginListOutOfBounds);
        }
        let mut seen = HashSet::new();
        for origin in &self.authorized_origins {
            // The grant-specific form, not `canonical_origin`: that one also
            // accepts the opaque `null`, and a grant naming it would match
            // every about:blank, data: and sandboxed page alike. An invalid
            // grant is refused on install and skipped during selection.
            if canonical_grant_origin(origin).as_deref() != Some(origin) {
                return Err(AuthorizationError::InvalidOrigin);
            }
            if !seen.insert(origin) {
                return Err(AuthorizationError::DuplicateOrigin);
            }
        }
        Ok(())
    }
}

/// A request to construct one immutable authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest<'a> {
    pub conversation_key: &'a str,
    pub action: Action,
    pub requested_severity: Severity,
    pub invocation_id: &'a str,
    pub bind_identity: &'a str,
    pub signed_in_profile: &'a str,
    pub classification: Option<&'a NonTypeClassificationRecord>,
}

impl<'a> AuthorizationRequest<'a> {
    pub fn navigate(
        conversation_key: &'a str,
        requested_severity: Severity,
        invocation_id: &'a str,
        bind_identity: &'a str,
    ) -> Self {
        Self {
            conversation_key,
            action: Action::Navigate,
            requested_severity,
            invocation_id,
            bind_identity,
            signed_in_profile: "default",
            classification: None,
        }
    }

    pub fn snapshot(
        conversation_key: &'a str,
        invocation_id: &'a str,
        bind_identity: &'a str,
    ) -> Self {
        Self {
            conversation_key,
            action: Action::Snapshot,
            requested_severity: Action::Snapshot.floor(),
            invocation_id,
            bind_identity,
            signed_in_profile: "default",
            classification: None,
        }
    }

    pub fn screenshot(
        conversation_key: &'a str,
        invocation_id: &'a str,
        bind_identity: &'a str,
    ) -> Self {
        Self {
            conversation_key,
            action: Action::Screenshot,
            requested_severity: Action::Screenshot.floor(),
            invocation_id,
            bind_identity,
            signed_in_profile: "default",
            classification: None,
        }
    }

    pub fn click(
        conversation_key: &'a str,
        requested_severity: Severity,
        invocation_id: &'a str,
        bind_identity: &'a str,
        classification: &'a NonTypeClassificationRecord,
    ) -> Self {
        Self {
            conversation_key,
            action: Action::Click,
            requested_severity,
            invocation_id,
            bind_identity,
            signed_in_profile: "default",
            classification: Some(classification),
        }
    }

    pub fn click_unverified(
        conversation_key: &'a str,
        requested_severity: Severity,
        invocation_id: &'a str,
        bind_identity: &'a str,
    ) -> Self {
        Self {
            conversation_key,
            action: Action::Click,
            requested_severity,
            invocation_id,
            bind_identity,
            signed_in_profile: "default",
            classification: None,
        }
    }

    pub fn click_point(
        conversation_key: &'a str,
        requested_severity: Severity,
        invocation_id: &'a str,
        bind_identity: &'a str,
        classification: &'a NonTypeClassificationRecord,
    ) -> Self {
        Self {
            conversation_key,
            action: Action::ClickPoint,
            requested_severity,
            invocation_id,
            bind_identity,
            signed_in_profile: "default",
            classification: Some(classification),
        }
    }

    pub fn click_point_unverified(
        conversation_key: &'a str,
        requested_severity: Severity,
        invocation_id: &'a str,
        bind_identity: &'a str,
    ) -> Self {
        Self {
            conversation_key,
            action: Action::ClickPoint,
            requested_severity,
            invocation_id,
            bind_identity,
            signed_in_profile: "default",
            classification: None,
        }
    }
}

/// The process-local decision object retained across all transition checks.
/// Its fields are private so callers cannot replace the selected grant or its
/// origin scope after commitment.  The accessors return copies or borrowed
/// values and there is deliberately no reauthorization method on this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    agent_grant: Option<GrantUse>,
    decision_id: String,
    grant_id: String,
    grant_revision: u64,
    invocation_id: String,
    bind_identity: String,
    effective_severity: Severity,
    selected_grant_severity: Severity,
    grant_conversation_key: String,
    authorized_origins: Vec<String>,
    disclosed_hazards: BTreeSet<HazardClass>,
    classification_fingerprint: Option<NonTypeClassificationFingerprint>,
    action: Action,
    baseline: bool,
    signed_in_profile: String,
}

pub type ImmutableAuthorizationDecision = AuthorizationDecision;

impl AuthorizationDecision {
    pub fn is_public_web_baseline(&self) -> bool {
        self.baseline
    }

    pub fn authorization_decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn decision_id(&self) -> &str {
        self.authorization_decision_id()
    }

    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn grant_revision(&self) -> u64 {
        self.grant_revision
    }

    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub fn bind_identity(&self) -> &str {
        &self.bind_identity
    }

    pub fn effective_severity(&self) -> Severity {
        self.effective_severity
    }

    pub fn authorized_origins(&self) -> &[String] {
        &self.authorized_origins
    }

    pub fn disclosed_hazards(&self) -> &BTreeSet<HazardClass> {
        &self.disclosed_hazards
    }

    pub fn classification_fingerprint(&self) -> Option<NonTypeClassificationFingerprint> {
        self.classification_fingerprint
    }

    pub fn action(&self) -> Action {
        self.action
    }
}

/// A successful dispatch commitment carrying the exact decision accepted by
/// the grant store at the commit point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCommitment {
    token: String,
    decision: AuthorizationDecision,
}

impl AuthorizationCommitment {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn decision(&self) -> &AuthorizationDecision {
        &self.decision
    }

    pub fn authorization_decision_id(&self) -> &str {
        self.decision.authorization_decision_id()
    }
}

/// The mutable grant view is used only before commitment.  Once a commitment
/// has been returned, later replacement/revocation cannot alter the copied
/// decision inside that commitment.
#[derive(Debug, Clone, Default)]
pub struct GrantStore {
    agent_grants: Option<Arc<AgentGrants>>,
    current: BTreeMap<String, ActionGrant>,
    invalid: bool,
    /// Standing per-agent browser rows, consulted when no conversation grant
    /// covers an action and the request runs for an attested agent (see
    /// [`with_standing_caller`]).
    standing: Option<Arc<StandingBrowserGrants>>,
    signed_in: Option<Arc<crate::browser_signed_in::SignedInDomains>>,
}

pub type AuthorizationStore = GrantStore;

impl GrantStore {
    pub fn with_agent_grants(mut self, grants: Arc<AgentGrants>) -> Self {
        self.agent_grants = Some(grants);
        self
    }
    pub fn with_public_web_baseline(
        mut self,
        signed_in: Arc<crate::browser_signed_in::SignedInDomains>,
    ) -> Self {
        self.signed_in = Some(signed_in);
        self
    }

    pub fn signed_in_domains(&self) -> Option<&Arc<crate::browser_signed_in::SignedInDomains>> {
        self.signed_in.as_ref()
    }
    pub fn new(grants: impl IntoIterator<Item = ActionGrant>) -> Self {
        let mut store = Self::default();
        for grant in grants {
            if store.insert_initial(grant).is_err() {
                store.invalid = true;
            }
        }
        store
    }

    pub fn try_new(
        grants: impl IntoIterator<Item = ActionGrant>,
    ) -> Result<Self, AuthorizationError> {
        let mut store = Self::default();
        for grant in grants {
            store.insert_initial(grant)?;
        }
        Ok(store)
    }

    /// Consult `standing` for actions no conversation grant covers.
    pub fn with_standing_grants(mut self, standing: Arc<StandingBrowserGrants>) -> Self {
        self.standing = Some(standing);
        self
    }

    /// The standing browser rows this store consults, if any.
    pub fn standing_grants(&self) -> Option<&Arc<StandingBrowserGrants>> {
        self.standing.as_ref()
    }

    /// A grant standing in for the live standing row that covers this action,
    /// when the request runs for an attested agent that holds one.
    ///
    /// The grant names only the attempted origin, so the decision's origin
    /// scope is that one origin: a redirect or a later read elsewhere is
    /// authorized again on its own, exactly as under a conversation grant.
    fn standing_grant(
        &self,
        request: &AuthorizationRequest<'_>,
        required: Severity,
        attempted_origin: &str,
        required_hazards: &BTreeSet<HazardClass>,
        public_document: bool,
    ) -> Option<ActionGrant> {
        let caller = current_standing_caller()?;
        // The request names the agent it acts for; a scope set for another
        // agent must never lend that agent's rows to this request.
        if caller.holder.agent_id().is_empty() || caller.holder.agent_id() != request.bind_identity
        {
            return None;
        }
        let origin = canonical_grant_origin(attempted_origin)?;
        if let Some(grants) = &self.agent_grants {
            let used = grants.authorize_filtered(
                &caller.holder,
                GrantDemand::Browser {
                    target: BrowserTarget::AgentProfile,
                    origin: origin.clone(),
                    severity: required,
                    hazards: required_hazards.clone(),
                },
                |row| public_document || row.subject != crate::agent_grants::GrantSubject::AllSites,
            )?;
            let row = used.row();
            let mut grant = ActionGrant::new(
                format!("{STANDING_GRANT_ID_PREFIX}{}", row.id),
                row.granted_at_ms.max(1),
                request.conversation_key,
                required,
                [origin],
            )
            .with_disclosed_hazards(required_hazards.iter().copied());
            crate::grant_enforcement::track(&used);
            grant.agent_grant = Some(used);
            return Some(grant);
        }
        let standing = self.standing.as_ref()?;
        let GrantHolder::Head { agent_id } = &caller.holder else {
            return None;
        };
        let row = standing.covering_document_row(
            agent_id,
            &origin,
            required,
            required_hazards,
            standing.now_ms(),
            public_document,
        )?;
        Some(
            ActionGrant::new(
                format!("{STANDING_GRANT_ID_PREFIX}{}", row.key()),
                row.granted_at_ms.max(1),
                request.conversation_key,
                row.severity(),
                [origin],
            )
            .with_disclosed_hazards(row.hazards.iter().copied()),
        )
    }

    fn baseline_grant(
        &self,
        request: &AuthorizationRequest<'_>,
        required: Severity,
        attempted_origin: &str,
        required_hazards: &BTreeSet<HazardClass>,
        public_document: bool,
    ) -> Option<ActionGrant> {
        if let Some(signed_in) = &self.signed_in {
            if public_document
                && public_web_baseline_covers(attempted_origin, required, required_hazards)
                && (request.action != Action::Type
                    || !signed_in.is_signed_in(
                        request.bind_identity,
                        request.signed_in_profile,
                        attempted_origin,
                    ))
            {
                return Some(ActionGrant::new(
                    PUBLIC_WEB_BASELINE,
                    1,
                    request.conversation_key,
                    Severity::new(COMPOSE, false, false),
                    [attempted_origin],
                ));
            }
        }
        None
    }

    /// Prefer a person's covering grant, falling back to public risk policy.
    /// Only a person's approval of the top page permits reading embedded local
    /// services; policy-only public reads must omit those frames.
    fn select_conversation_or_standing(
        &self,
        request: &AuthorizationRequest<'_>,
        required: Severity,
        attempted_origin: &str,
        required_hazards: &BTreeSet<HazardClass>,
        public_document: bool,
    ) -> Result<ActionGrant, AuthorizationError> {
        if self.agent_grants.is_some() {
            return self
                .standing_grant(
                    request,
                    required,
                    attempted_origin,
                    required_hazards,
                    public_document,
                )
                .or_else(|| {
                    self.baseline_grant(
                        request,
                        required,
                        attempted_origin,
                        required_hazards,
                        public_document,
                    )
                })
                .ok_or_else(|| AuthorizationError::NoGrantForAction {
                    attempted_origin: attempted_origin.into(),
                    required,
                });
        }
        match self.select_covering_grant_for_hazards(
            request.conversation_key,
            required,
            attempted_origin,
            required_hazards,
        ) {
            Ok(grant) => Ok(grant),
            Err(
                refusal @ (AuthorizationError::InvalidGrant
                | AuthorizationError::InvalidSeverityTier),
            ) => Err(refusal),
            Err(refusal) => self
                .standing_grant(
                    request,
                    required,
                    attempted_origin,
                    required_hazards,
                    public_document,
                )
                .or_else(|| {
                    self.baseline_grant(
                        request,
                        required,
                        attempted_origin,
                        required_hazards,
                        public_document,
                    )
                })
                .ok_or(refusal),
        }
    }

    fn insert_initial(&mut self, grant: ActionGrant) -> Result<(), AuthorizationError> {
        if grant.id == PUBLIC_WEB_BASELINE {
            return Err(AuthorizationError::InvalidGrant);
        }
        grant.validate()?;
        if self.current.insert(grant.id.clone(), grant).is_some() {
            return Err(AuthorizationError::DuplicateGrantIdentity);
        }
        Ok(())
    }

    pub fn replace(&mut self, grant: ActionGrant) -> Result<(), AuthorizationError> {
        if grant.id == PUBLIC_WEB_BASELINE {
            return Err(AuthorizationError::InvalidGrant);
        }
        self.ensure_valid()?;
        grant.validate()?;
        if let Some(previous) = self.current.get(&grant.id) {
            if grant.revision <= previous.revision {
                return Err(AuthorizationError::GrantRevisionNotAdvanced);
            }
        }
        self.current.insert(grant.id.clone(), grant);
        Ok(())
    }

    pub fn revoke(&mut self, grant_id: &str) -> Result<(), AuthorizationError> {
        self.ensure_valid()?;
        self.current.remove(grant_id);
        Ok(())
    }

    pub fn current_grants(&self) -> impl Iterator<Item = &ActionGrant> {
        self.current.values()
    }

    pub fn select_covering_grant(
        &self,
        conversation_key: &str,
        required: Severity,
        attempted_origin: &str,
    ) -> Result<ActionGrant, AuthorizationError> {
        self.select_covering_grant_for_hazards(
            conversation_key,
            required,
            attempted_origin,
            &BTreeSet::new(),
        )
    }

    fn select_covering_grant_for_hazards(
        &self,
        conversation_key: &str,
        required: Severity,
        attempted_origin: &str,
        required_hazards: &BTreeSet<HazardClass>,
    ) -> Result<ActionGrant, AuthorizationError> {
        self.ensure_valid()?;
        required.validate()?;
        let mut conversation_grants = self
            .current
            .values()
            .filter(|grant| {
                !FLOW.try_with(|flow| *flow).unwrap_or(false)
                    && grant.validate().is_ok()
                    && grant.conversation_key == conversation_key
            })
            .collect::<Vec<_>>();
        conversation_grants.sort_by(compare_grants);
        let candidates = conversation_grants
            .iter()
            .copied()
            .filter(|grant| grant.severity.covers(required))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            // An empty severity scope still names a target hazard when one is
            // known. This is the actionable fact the caller needs in order to
            // re-ask a person, and disclosing it mints a grant whose ceiling
            // is high enough for any classified target.
            if let Some(missing) = required_hazards.iter().next().copied() {
                return Err(AuthorizationError::HazardNotDisclosed {
                    missing,
                    attempted_origin: canonical_origin(attempted_origin)
                        .unwrap_or_else(|| attempted_origin.to_string()),
                    required,
                    required_hazards: required_hazards.clone(),
                });
            }
            // Both refusals name the attempted origin and the required
            // severity, so the one grant a caller opens from them covers this
            // action. When the existing grants are wrong on origin as well as
            // on severity, the severity refusal is the one reported: a grant
            // opened for the attempted origin at the required severity fixes
            // both at once, whereas reporting the origin first would send the
            // caller to open a grant that is still too low.
            let attempted_origin =
                canonical_origin(attempted_origin).unwrap_or_else(|| attempted_origin.to_string());
            if conversation_grants.is_empty() {
                return Err(AuthorizationError::NoGrantForAction {
                    attempted_origin,
                    required,
                });
            }
            let mut granted_ceilings = Vec::new();
            for grant in &conversation_grants {
                if !granted_ceilings.contains(&grant.severity) {
                    granted_ceilings.push(grant.severity);
                }
            }
            return Err(AuthorizationError::GrantSeverityInsufficient {
                attempted_origin,
                required,
                granted_ceilings,
            });
        }

        let Some(canonical_attempted) = canonical_origin(attempted_origin) else {
            return Err(AuthorizationError::OriginScope {
                attempted_origin: attempted_origin.to_string(),
                granted_origins: granted_origins(&candidates),
                required,
                required_hazards: required_hazards.clone(),
            });
        };
        let scoped = candidates
            .iter()
            .copied()
            .filter(|grant| grant_authorizes_origin(grant, &canonical_attempted))
            .collect::<Vec<_>>();
        if scoped.is_empty() {
            return Err(AuthorizationError::OriginScope {
                attempted_origin: canonical_attempted,
                granted_origins: granted_origins(&candidates),
                required,
                required_hazards: required_hazards.clone(),
            });
        }
        if let Some(grant) = scoped
            .iter()
            .find(|grant| required_hazards.is_subset(&grant.disclosed_hazards))
        {
            return Ok((**grant).clone());
        }

        let missing = required_hazards.iter().copied().find(|hazard| {
            scoped
                .iter()
                .all(|grant| !grant.disclosed_hazards.contains(hazard))
        });
        if let Some(missing) = missing.or_else(|| {
            required_hazards
                .difference(&scoped[0].disclosed_hazards)
                .next()
                .copied()
        }) {
            return Err(AuthorizationError::HazardNotDisclosed {
                missing,
                attempted_origin: canonical_attempted,
                required,
                required_hazards: required_hazards.clone(),
            });
        }
        // Not reachable: `scoped` is non-empty and no grant in it discloses
        // every required hazard, so the required set is non-empty and the
        // first scoped grant lacks at least one of them, which the fallback
        // above returns. Kept as a refusal rather than a panic so a future
        // change to the selection above fails closed.
        Err(AuthorizationError::NoGrant)
    }

    /// Build a decision and perform no browser or connector work.
    pub fn authorize(
        &self,
        request: AuthorizationRequest<'_>,
        attempted_origin: &str,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.authorize_document(request, attempted_origin, true)
    }

    /// A connected private peer rules out implicit public-web access and grants
    /// for all sites, but not a person's explicit grant for that site.
    pub(crate) fn authorize_document(
        &self,
        request: AuthorizationRequest<'_>,
        attempted_origin: &str,
        public_document: bool,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.authorize_document_input(request, attempted_origin, public_document, None)
    }

    pub(crate) fn authorize_document_input(
        &self,
        mut request: AuthorizationRequest<'_>,
        attempted_origin: &str,
        public_document: bool,
        key: Option<crate::browser::keys::Key>,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.ensure_valid()?;
        let (computed, fingerprint) =
            computed_required_severity(request.action, request.classification)?;
        let (computed, required_hazards, destinations) = if let Some(key) = key {
            let record = request
                .classification
                .ok_or(AuthorizationError::SeverityUnclassifiable)?;
            let policy = key.policy(record)?;
            request.requested_severity = policy.severity;
            (policy.severity, policy.hazards, policy.destinations)
        } else {
            let hazards = target_hazards(request.action, request.classification)?;
            let destination = request
                .classification
                .and_then(|record| record.activation_destination_origin.as_deref());
            (computed, hazards, [destination, None])
        };
        let floor = if computed.tier == OBSERVE {
            computed
        } else {
            request.action.floor()
        };
        request.requested_severity.validate()?;
        if request.requested_severity.tier < floor.tier {
            return Err(AuthorizationError::SeverityBelowFloor { required: computed });
        }
        let effective = request.requested_severity.maximum(computed);
        let grant = self.select_conversation_or_standing(
            &request,
            effective,
            attempted_origin,
            &required_hazards,
            public_document,
        )?;
        for destination in destinations.into_iter().flatten() {
            self.select_conversation_or_standing(
                &request,
                effective,
                destination,
                &required_hazards,
                destination != attempted_origin || public_document,
            )?;
        }
        let baseline = self.signed_in.is_some() && grant.id == PUBLIC_WEB_BASELINE;
        let mut decision = make_decision(&grant, request, effective, fingerprint)?;
        decision.baseline = baseline;
        Ok(decision)
    }

    /// Commit is the pre-input guard.  It succeeds only if the exact selected
    /// grant identity and revision still describe the current grant.
    pub fn commit(
        &self,
        decision: &AuthorizationDecision,
    ) -> Result<AuthorizationCommitment, AuthorizationCommitError> {
        self.ensure_valid()
            .map_err(|_| AuthorizationCommitError::InvalidGrantState)?;
        if decision.baseline {
            if decision.action == Action::Type
                && self.signed_in.as_ref().is_none_or(|signed_in| {
                    signed_in.is_signed_in(
                        &decision.bind_identity,
                        &decision.signed_in_profile,
                        &decision.authorized_origins[0],
                    )
                })
            {
                return Err(AuthorizationCommitError::GrantRevoked);
            }
            return Ok(AuthorizationCommitment {
                token: format!("commit-{}", decision.decision_id),
                decision: decision.clone(),
            });
        }
        if let Some(key) = decision.grant_id.strip_prefix(STANDING_GRANT_ID_PREFIX) {
            if self.agent_grants.is_some() {
                if !decision.agent_grant.as_ref().is_some_and(GrantUse::is_live) {
                    return Err(AuthorizationCommitError::GrantRevoked);
                }
                return Ok(AuthorizationCommitment {
                    token: format!("commit-{}", decision.decision_id),
                    decision: decision.clone(),
                });
            }
            // A standing decision commits only while its row is still in
            // force: revoked or expired since authorization admits nothing.
            let live = self.standing.as_ref().is_some_and(|standing| {
                standing.row_is_live(&decision.bind_identity, key, standing.now_ms())
            });
            if !live {
                return Err(AuthorizationCommitError::GrantRevoked);
            }
            return Ok(AuthorizationCommitment {
                token: format!("commit-{}", decision.decision_id),
                decision: decision.clone(),
            });
        }
        let Some(current) = self.current.get(&decision.grant_id) else {
            return Err(AuthorizationCommitError::GrantRevoked);
        };
        if current.revision != decision.grant_revision
            || current.conversation_key != decision.grant_conversation_key
            || current.severity != decision.selected_grant_severity
            || current.authorized_origins != decision.authorized_origins
            || current.disclosed_hazards != decision.disclosed_hazards
        {
            return Err(AuthorizationCommitError::GrantReplaced);
        }
        Ok(AuthorizationCommitment {
            token: format!("commit-{}", decision.decision_id),
            decision: decision.clone(),
        })
    }

    fn ensure_valid(&self) -> Result<(), AuthorizationError> {
        if self.invalid {
            Err(AuthorizationError::InvalidGrant)
        } else {
            Ok(())
        }
    }
}

pub fn authorize(
    grants: &[ActionGrant],
    request: AuthorizationRequest<'_>,
    attempted_origin: &str,
) -> Result<AuthorizationDecision, AuthorizationError> {
    let store = GrantStore::try_new(grants.iter().cloned())?;
    store.authorize(request, attempted_origin)
}

/// Compute the exact static floor or the single non-type classification-derived
/// requirement.  The record itself is checked again so a caller cannot alter a
/// derived flag or tier between classification and authorization.
pub fn computed_required_severity(
    action: Action,
    classification: Option<&NonTypeClassificationRecord>,
) -> Result<(Severity, Option<NonTypeClassificationFingerprint>), AuthorizationError> {
    match action {
        Action::Navigate | Action::Snapshot | Action::Screenshot => Ok((action.floor(), None)),
        Action::Click | Action::ClickPoint | Action::Type if classification.is_none() => {
            Ok((Severity::new(MUTATE_DURABLE, true, true), None))
        }
        Action::Click | Action::ClickPoint | Action::Type => {
            let record = classification.ok_or(AuthorizationError::SeverityUnclassifiable)?;
            record
                .validate()
                .map_err(|_| AuthorizationError::SeverityUnclassifiable)?;
            Ok((
                Severity::new(record.required_tier, record.credential, record.financial),
                Some(
                    record
                        .try_fingerprint()
                        .map_err(|_| AuthorizationError::SeverityUnclassifiable)?,
                ),
            ))
        }
    }
}

/// Derive the exact disclosure requirements from the same closed record used
/// for severity. A form submit can independently carry credential and financial
/// fields; an unavailable record is not equivalent to either flag being false.
pub fn target_hazards(
    action: Action,
    classification: Option<&NonTypeClassificationRecord>,
) -> Result<BTreeSet<HazardClass>, AuthorizationError> {
    match (action, classification) {
        (Action::Navigate, _) => Ok(BTreeSet::new()),
        // Page captures cannot activate a control, so no form-submit hazard can
        // arise from either structured or pixel observations.
        (Action::Snapshot | Action::Screenshot, _) => Ok(BTreeSet::new()),
        // click_point shares this arm with click deliberately. A coordinate
        // click hit-tests to a control and can activate the same submit button
        // a ref click would, so disclosing one and not the other would let a
        // caller reach a credential-bearing form through the geometry path
        // using a grant that never named the hazard. `computed_required_severity`
        // already derives severity identically for both; this keeps disclosure
        // in step with it.
        (Action::Click | Action::ClickPoint | Action::Type, None) => {
            Ok(BTreeSet::from([HazardClass::UnverifiedFormContents]))
        }
        (Action::Click | Action::ClickPoint | Action::Type, Some(record)) => {
            record
                .validate()
                .map_err(|_| AuthorizationError::SeverityUnclassifiable)?;
            let mut hazards = BTreeSet::new();
            if record.activation_invokes_form_submit && record.credential {
                hazards.insert(HazardClass::CredentialFormSubmit);
            }
            if record.activation_invokes_form_submit && record.financial {
                hazards.insert(HazardClass::FinancialFormSubmit);
            }
            Ok(hazards)
        }
    }
}

pub fn effective_severity(
    action: Action,
    requested: Severity,
    classification: Option<&NonTypeClassificationRecord>,
) -> Result<Severity, AuthorizationError> {
    requested.validate()?;
    let (computed, _) = computed_required_severity(action, classification)?;
    let floor = if computed.tier == OBSERVE {
        computed
    } else {
        action.floor()
    };
    if requested.tier < floor.tier {
        return Err(AuthorizationError::SeverityBelowFloor { required: computed });
    }
    Ok(requested.maximum(computed))
}

fn make_decision(
    grant: &ActionGrant,
    request: AuthorizationRequest<'_>,
    effective: Severity,
    fingerprint: Option<NonTypeClassificationFingerprint>,
) -> Result<AuthorizationDecision, AuthorizationError> {
    if request.invocation_id.is_empty() || request.bind_identity.is_empty() {
        return Err(AuthorizationError::InvalidInvocationAssociation);
    }
    let decision_number = NEXT_DECISION_ID.fetch_add(1, AtomicOrdering::Relaxed);
    let decision_id = format!("ad-{decision_number:016x}");
    Ok(AuthorizationDecision {
        agent_grant: grant.agent_grant.clone(),
        decision_id,
        grant_id: grant.id.clone(),
        grant_revision: grant.revision,
        invocation_id: request.invocation_id.to_string(),
        bind_identity: request.bind_identity.to_string(),
        effective_severity: effective,
        selected_grant_severity: grant.severity,
        grant_conversation_key: grant.conversation_key.clone(),
        authorized_origins: grant.authorized_origins.clone(),
        disclosed_hazards: grant.disclosed_hazards.clone(),
        classification_fingerprint: fingerprint,
        action: request.action,
        baseline: false,
        signed_in_profile: request.signed_in_profile.to_string(),
    })
}

/// The one place origin membership is decided.
///
/// Both selection paths call this rather than each carrying a copy of the
/// comparison. Two copies of a scope rule drift independently, and a reader
/// who finds one and fixes it has no way to know the other exists -- which is
/// how the origin came to be checked after selection instead of during it.
fn grant_authorizes_origin(grant: &ActionGrant, canonical_attempted: &str) -> bool {
    grant
        .authorized_origins
        .iter()
        .any(|origin| origin == canonical_attempted)
}

fn granted_origins(candidates: &[&ActionGrant]) -> Vec<String> {
    let mut seen = HashSet::new();
    candidates
        .iter()
        .flat_map(|grant| grant.authorized_origins.iter())
        .filter(|origin| seen.insert(origin.as_str()))
        .cloned()
        .collect()
}

fn compare_grants(left: &&ActionGrant, right: &&ActionGrant) -> Ordering {
    left.id
        .cmp(&right.id)
        .then_with(|| left.revision.cmp(&right.revision))
        .then_with(|| left.conversation_key.cmp(&right.conversation_key))
        .then_with(|| left.severity.tier.cmp(&right.severity.tier))
        .then_with(|| left.severity.credential.cmp(&right.severity.credential))
        .then_with(|| left.severity.financial.cmp(&right.severity.financial))
        .then_with(|| left.authorized_origins.cmp(&right.authorized_origins))
        .then_with(|| left.disclosed_hazards.cmp(&right.disclosed_hazards))
}

static NEXT_DECISION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDeniedDetail {
    NoGrant,
    OriginScope {
        attempted_origin: String,
        granted_origins: Vec<String>,
    },
}

impl AuthorizationDeniedDetail {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NoGrant => "no_grant",
            Self::OriginScope { .. } => "origin_scope",
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Self::NoGrant => json!({ "reason": "no_grant" }),
            Self::OriginScope {
                attempted_origin,
                granted_origins,
            } => json!({
                "reason": "origin_scope",
                "attempted_origin": attempted_origin,
                "granted_origins": granted_origins,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidSeverityTier,
    /// The requested tier is under the action's floor. `required` is the
    /// severity this target computes to (never below the floor), so a caller
    /// learns what to ask for without probing tier by tier.
    SeverityBelowFloor {
        required: Severity,
    },
    /// No grant is available, without facts about what one must cover. Used
    /// where the refusal is about a grant that vanished or changed between
    /// selection and commit rather than about the action's requirements.
    NoGrant,
    /// This conversation holds no valid grant at all. Names the attempted
    /// origin and the severity a grant must cover, so the caller can open the
    /// one grant that makes the retry succeed.
    NoGrantForAction {
        attempted_origin: String,
        required: Severity,
    },
    /// This conversation holds grants, but none has a severity ceiling that
    /// covers `required`. Kept apart from `NoGrantForAction` because opening
    /// another grant at the default ceiling would be refused the same way;
    /// the caller has to ask for this severity specifically.
    GrantSeverityInsufficient {
        attempted_origin: String,
        required: Severity,
        granted_ceilings: Vec<Severity>,
    },
    /// Grants reach the severity, but none names the attempted origin.
    /// `required` and `required_hazards` are what a grant for that origin must
    /// cover, so the refusal can name the one grant that admits the retry.
    OriginScope {
        attempted_origin: String,
        granted_origins: Vec<String>,
        required: Severity,
        required_hazards: BTreeSet<HazardClass>,
    },
    /// The target carries a hazard no usable grant disclosed. `missing` is the
    /// first such hazard; the other fields describe the whole grant that would
    /// admit this action, because disclosing only `missing` can leave another
    /// required hazard or the origin still uncovered.
    HazardNotDisclosed {
        missing: HazardClass,
        attempted_origin: String,
        required: Severity,
        required_hazards: BTreeSet<HazardClass>,
    },
    SeverityUnclassifiable,
    InvalidGrant,
    DuplicateGrantIdentity,
    GrantRevisionNotAdvanced,
    OriginListOutOfBounds,
    InvalidOrigin,
    DuplicateOrigin,
    InvalidInvocationAssociation,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthorizationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationCommitError {
    GrantRevoked,
    GrantReplaced,
    InvalidGrantState,
}

impl fmt::Display for AuthorizationCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthorizationCommitError {}

#[cfg(test)]
mod tests {

    /// Both planes number the fleet severity tiers identically.
    ///
    /// The browser plane declares these constants and the computer plane's
    /// severity table carries tier numbers of its own, and both say they speak
    /// `ck-action-severity/v1`. Nothing else holds the two together, so a
    /// renumbering on either side would leave each plane internally consistent
    /// and mean different things by the same number.
    ///
    /// That failure is silent in the worst way: severity is what a decision
    /// plane reads to judge how consequential an action is, so a mismatch does
    /// not produce an error, it produces a wrong judgement. A browser action
    /// recorded as tier 4 would be read against the computer plane's meaning of
    /// 4, and any policy keyed on the number would admit or refuse the wrong
    /// thing.
    ///
    /// Asserted against the loaded taxonomy rather than the computer plane's
    /// own constants, because the taxonomy is the data a consumer reads.
    #[test]
    fn the_two_planes_agree_on_what_each_severity_tier_means() {
        use cerebellum_computer::platform::severity::{
            load_severity_taxonomy, FLEET_SEVERITY_SCHEMA_ID,
        };

        // The same schema is claimed on both sides, which is what makes the
        // numbers comparable at all.
        assert_eq!(FLEET_SEVERITY_SCHEMA_ID, "ck-action-severity/v1");

        let taxonomy = load_severity_taxonomy().expect("the computer plane's table loads");

        // Every tier the computer plane can produce is one this plane names.
        for (inputs, record) in taxonomy.table() {
            let tier = SeverityTier::try_from(record.tier).unwrap_or_else(|_| {
                panic!(
                    "{inputs:?} resolves to tier {}, which the browser plane does not name",
                    record.tier
                )
            });
            assert_eq!(tier.as_u8(), record.tier);
        }

        // And the numbering itself, stated as literals rather than derived from
        // the constants under test: deriving them would pass however they were
        // renumbered.
        assert_eq!(SeverityTier::Observe.as_u8(), 1);
        assert_eq!(SeverityTier::Compose.as_u8(), 2);
        assert_eq!(SeverityTier::MutateReversible.as_u8(), 3);
        assert_eq!(SeverityTier::MutateDurable.as_u8(), 4);
        assert_eq!(SeverityTier::Actuate.as_u8(), 5);
    }
    use super::*;
    use crate::classification::{
        classify_click, ElementClassificationInput, NodeIdentityInput, NonTypeClassificationInput,
        TargetKind,
    };

    fn grant(id: &str, revision: u64, origins: &[&str]) -> ActionGrant {
        ActionGrant::new(
            id,
            revision,
            "conversation",
            Severity::new(COMPOSE, false, false),
            origins.iter().copied(),
        )
    }

    #[test]
    fn deterministic_selection_is_independent_of_candidate_order() {
        let required = Severity::new(COMPOSE, false, false);
        let a = grant("grant-b", 1, &["https://common.test"]);
        let b = grant("grant-a", 1, &["https://common.test"]);
        let first_store = GrantStore::new([a.clone(), b.clone()]);
        let second_store = GrantStore::new([b, a]);
        let first = first_store
            .select_covering_grant("conversation", required, "https://common.test")
            .unwrap();
        let second = second_store
            .select_covering_grant("conversation", required, "https://common.test")
            .unwrap();
        assert_eq!(first.id, "grant-a");
        assert_eq!(first, second);
    }

    #[test]
    fn a_point_click_discloses_the_same_hazards_as_a_ref_click() {
        // A coordinate click resolves to a control and can activate the same
        // submit button a ref click reaches. Disclosure has to follow, or the
        // geometry path becomes a way to touch a credential-bearing form
        // holding a grant that never named the hazard.
        let target = ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame", 1),
            TargetKind::Button,
        )
        // The button submits the form that owns the password field.
        .form_owner(NodeIdentityInput::new("target", "frame", 3))
        .associated_control(
            crate::classification::AssociatedFormControlInput::new(NodeIdentityInput::new(
                "target", "frame", 2,
            ))
            .with_password(true),
        );
        let record = classify_click(&NonTypeClassificationInput::new(
            1,
            target,
            "https://example.test",
        ))
        .unwrap();

        let by_ref = target_hazards(Action::Click, Some(&record)).unwrap();
        let by_point = target_hazards(Action::ClickPoint, Some(&record)).unwrap();

        assert!(
            by_ref.contains(&HazardClass::CredentialFormSubmit),
            "the fixture no longer classifies as credential-bearing, so this \
             test cannot detect a disclosure gap: {by_ref:?}"
        );
        assert_eq!(
            by_ref, by_point,
            "a point click disclosed different hazards than a ref click on the \
             same classified target"
        );

        // The same parity where nothing could be classified: unknown is its own
        // hazard on both paths, never an empty set.
        assert_eq!(
            target_hazards(Action::ClickPoint, None).unwrap(),
            BTreeSet::from([HazardClass::UnverifiedFormContents])
        );
    }

    #[test]
    fn submit_and_financial_classification_raise_effective_severity() {
        let target = ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame", 1),
            TargetKind::Button,
        )
        // The button submits the form that owns the card-number field.
        .form_owner(NodeIdentityInput::new("target", "frame", 3))
        .associated_control(
            crate::classification::AssociatedFormControlInput::new(NodeIdentityInput::new(
                "target", "frame", 2,
            ))
            .with_tokens(["cc-number"]),
        );
        let record = classify_click(&NonTypeClassificationInput::new(
            1,
            target,
            "https://example.test",
        ))
        .unwrap();
        let severity = effective_severity(
            Action::Click,
            Severity::new(COMPOSE, false, false),
            Some(&record),
        )
        .unwrap();
        assert_eq!(severity, Severity::new(MUTATE_DURABLE, false, true));
    }

    #[test]
    fn revocation_before_commit_fails_but_later_revocation_does_not_rewrite_decision() {
        let mut store = GrantStore::new([grant("grant-a", 1, &["https://allowed.test"])]);
        let decision = store
            .authorize(
                AuthorizationRequest::navigate(
                    "conversation",
                    Severity::new(OBSERVE, false, false),
                    "invocation-1",
                    "bind-1",
                ),
                "https://allowed.test",
            )
            .unwrap();
        store.revoke("grant-a").unwrap();
        assert_eq!(
            store.commit(&decision),
            Err(AuthorizationCommitError::GrantRevoked)
        );

        let mut store = GrantStore::new([grant("grant-a", 1, &["https://allowed.test"])]);
        let decision = store
            .authorize(
                AuthorizationRequest::navigate(
                    "conversation",
                    Severity::new(OBSERVE, false, false),
                    "invocation-1",
                    "bind-1",
                ),
                "https://allowed.test",
            )
            .unwrap();
        let commitment = store.commit(&decision).unwrap();
        store.revoke("grant-a").unwrap();
        assert_eq!(commitment.decision(), &decision);
    }
}
