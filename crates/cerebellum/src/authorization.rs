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

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::classification::{
    canonical_grant_origin, canonical_origin, NonTypeClassificationFingerprint,
    NonTypeClassificationRecord,
};

pub const OBSERVE: u8 = 1;
pub const COMPOSE: u8 = 2;
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
}

pub type CapabilityAction = Action;

impl Action {
    pub const fn floor(self) -> Severity {
        match self {
            Self::Navigate | Self::Snapshot | Self::Screenshot => {
                Severity::new(OBSERVE, false, false)
            }
            Self::Click | Self::ClickPoint => Severity::new(COMPOSE, false, false),
        }
    }
}

/// A grant scoped to one conversation. Each grant has an identifier, revision,
/// severity requirement, authorized origins, and the target hazards disclosed to
/// the person who issued it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionGrant {
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
}

pub type ImmutableAuthorizationDecision = AuthorizationDecision;

impl AuthorizationDecision {
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

    pub fn evaluate_origin_scope(
        &self,
        attempted_origin: &str,
    ) -> Result<(), AuthorizationDeniedDetail> {
        evaluate_origin_scope(self, attempted_origin)
    }
}

/// A successful dispatch commitment.  Integrations pass this value to the
/// connector; it carries the exact decision selected before commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCommitment {
    token: String,
    decision: AuthorizationDecision,
}

/// A borrowed pre-commit guard that lets a caller construct a decision first
/// and commit that same decision through the grant store later.
pub struct AuthorizationCommitGuard<'a> {
    store: &'a GrantStore,
    decision: &'a AuthorizationDecision,
}

impl<'a> AuthorizationCommitGuard<'a> {
    pub fn new(store: &'a GrantStore, decision: &'a AuthorizationDecision) -> Self {
        Self { store, decision }
    }

    pub fn commit(&self) -> Result<AuthorizationCommitment, AuthorizationCommitError> {
        self.store.commit(self.decision)
    }
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

    pub fn evaluate_origin_scope(
        &self,
        attempted_origin: &str,
    ) -> Result<(), AuthorizationDeniedDetail> {
        self.decision.evaluate_origin_scope(attempted_origin)
    }
}

/// The mutable grant view is used only before commitment.  Once a commitment
/// has been returned, later replacement/revocation cannot alter the copied
/// decision inside that commitment.
#[derive(Debug, Clone, Default)]
pub struct GrantStore {
    current: BTreeMap<String, ActionGrant>,
    invalid: bool,
}

pub type AuthorizationStore = GrantStore;

impl GrantStore {
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

    fn insert_initial(&mut self, grant: ActionGrant) -> Result<(), AuthorizationError> {
        grant.validate()?;
        if self.current.insert(grant.id.clone(), grant).is_some() {
            return Err(AuthorizationError::DuplicateGrantIdentity);
        }
        Ok(())
    }

    pub fn replace(&mut self, grant: ActionGrant) -> Result<(), AuthorizationError> {
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
            .filter(|grant| grant.validate().is_ok() && grant.conversation_key == conversation_key)
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
        self.ensure_valid()?;
        let (computed, fingerprint) =
            computed_required_severity(request.action, request.classification)?;
        let required_hazards = target_hazards(request.action, request.classification)?;
        let floor = request.action.floor();
        request.requested_severity.validate()?;
        if request.requested_severity.tier < floor.tier {
            return Err(AuthorizationError::SeverityBelowFloor { required: computed });
        }
        let effective = request.requested_severity.maximum(computed);
        let grant = self.select_covering_grant_for_hazards(
            request.conversation_key,
            effective,
            attempted_origin,
            &required_hazards,
        )?;
        make_decision(&grant, request, effective, fingerprint)
    }

    /// Commit is the pre-input guard.  It succeeds only if the exact selected
    /// grant identity and revision still describe the current grant.
    pub fn commit(
        &self,
        decision: &AuthorizationDecision,
    ) -> Result<AuthorizationCommitment, AuthorizationCommitError> {
        self.ensure_valid()
            .map_err(|_| AuthorizationCommitError::InvalidGrantState)?;
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

    pub fn commit_decision(
        &self,
        decision: &AuthorizationDecision,
    ) -> Result<AuthorizationCommitment, AuthorizationCommitError> {
        self.commit(decision)
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

/// Select one covering grant using a total order independent of provider map
/// iteration or arrival order.  Grant identity is the primary stable key;
/// revision and the remaining immutable grant material complete the order.
pub fn select_covering_grant<'a>(
    candidates: &'a [ActionGrant],
    required: Severity,
    attempted_origin: &str,
) -> Result<Option<&'a ActionGrant>, AuthorizationError> {
    select_deterministic_covering_grant(candidates, required, attempted_origin)
}

pub fn select_deterministic_covering_grant<'a>(
    candidates: &'a [ActionGrant],
    required: Severity,
    attempted_origin: &str,
) -> Result<Option<&'a ActionGrant>, AuthorizationError> {
    required.validate()?;
    let Some(canonical_attempted) = canonical_origin(attempted_origin) else {
        return Ok(None);
    };
    let mut covering = candidates
        .iter()
        .filter(|grant| {
            grant.validate().is_ok()
                && grant.severity.covers(required)
                && grant_authorizes_origin(grant, &canonical_attempted)
        })
        .collect::<Vec<_>>();
    covering.sort_by(compare_grants);
    Ok(covering.into_iter().next())
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
        Action::Click | Action::ClickPoint if classification.is_none() => {
            Ok((Severity::new(MUTATE_DURABLE, true, true), None))
        }
        Action::Click | Action::ClickPoint => {
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
        (Action::Click | Action::ClickPoint, None) => {
            Ok(BTreeSet::from([HazardClass::UnverifiedFormContents]))
        }
        (Action::Click | Action::ClickPoint, Some(record)) => {
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
    let floor = action.floor();
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

pub fn evaluate_origin_scope(
    decision: &AuthorizationDecision,
    attempted_origin: &str,
) -> Result<(), AuthorizationDeniedDetail> {
    let Some(canonical_attempted) = canonical_origin(attempted_origin) else {
        return Err(AuthorizationDeniedDetail::OriginScope {
            attempted_origin: attempted_origin.to_string(),
            granted_origins: decision.authorized_origins.clone(),
        });
    };
    if decision
        .authorized_origins
        .iter()
        .any(|origin| origin == &canonical_attempted)
    {
        Ok(())
    } else {
        Err(AuthorizationDeniedDetail::OriginScope {
            attempted_origin: canonical_attempted,
            granted_origins: decision.authorized_origins.clone(),
        })
    }
}

/// Retains the unique authorization decision associated with each invocation so
/// connector transitions can verify which decision authorized them.  A missing
/// or ambiguous association fails closed.
#[derive(Debug, Clone, Default)]
pub struct DecisionBindings {
    by_invocation: BTreeMap<String, Vec<AuthorizationDecision>>,
}

impl DecisionBindings {
    pub fn bind(&mut self, commitment: &AuthorizationCommitment) {
        self.by_invocation
            .entry(commitment.decision.invocation_id.clone())
            .or_default()
            .push(commitment.decision.clone());
    }

    pub fn clear_invocation(&mut self, invocation_id: &str) {
        self.by_invocation.remove(invocation_id);
    }

    pub fn select_unique(
        &self,
        invocation_id: &str,
    ) -> Result<&AuthorizationDecision, AuthorizationDeniedDetail> {
        match self.by_invocation.get(invocation_id).map(Vec::as_slice) {
            Some([decision]) => Ok(decision),
            Some(_) | None => Err(AuthorizationDeniedDetail::NoGrant),
        }
    }

    pub fn select_for_transition(
        &self,
        invocation_id: &str,
        attempted_origin: &str,
    ) -> Result<&AuthorizationDecision, AuthorizationDeniedDetail> {
        let decision = self.select_unique(invocation_id)?;
        evaluate_origin_scope(decision, attempted_origin)?;
        Ok(decision)
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
        let first_candidates = [a.clone(), b.clone()];
        let second_candidates = [b, a];
        let first =
            select_deterministic_covering_grant(&first_candidates, required, "https://common.test")
                .unwrap()
                .unwrap();
        let second = select_deterministic_covering_grant(
            &second_candidates,
            required,
            "https://common.test",
        )
        .unwrap()
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
        assert!(commitment
            .evaluate_origin_scope("https://allowed.test")
            .is_ok());
        assert!(commitment
            .evaluate_origin_scope("https://other.test")
            .is_err());
    }

    #[test]
    fn origin_scope_denial_preserves_recorded_origin_order() {
        let store = GrantStore::new([grant(
            "grant-a",
            1,
            &["https://one.test", "https://two.test"],
        )]);
        let decision = store
            .authorize(
                AuthorizationRequest::navigate(
                    "conversation",
                    Severity::new(OBSERVE, false, false),
                    "invocation-1",
                    "bind-1",
                ),
                "https://one.test",
            )
            .unwrap();
        assert_eq!(
            decision.evaluate_origin_scope("https://three.test"),
            Err(AuthorizationDeniedDetail::OriginScope {
                attempted_origin: "https://three.test".to_string(),
                granted_origins: vec![
                    "https://one.test".to_string(),
                    "https://two.test".to_string()
                ],
            })
        );
    }
}
