//! Action-grant selection and immutable authorization decisions for the browser
//! authorization contract.
//!
//! This module owns the semantic part of authorization. Browser and connector
//! integrations retain the returned decision; they must not query ambient grant
//! state again after dispatch commitment.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::classification::{
    canonical_origin, NonTypeClassificationFingerprint, NonTypeClassificationRecord,
};

pub const OBSERVE: u8 = 1;
pub const COMPOSE: u8 = 2;
pub const MUTATE_REVERSIBLE: u8 = 3;
pub const MUTATE_DURABLE: u8 = 4;
pub const ACTUATE: u8 = 5;
pub const MAX_ORIGINS: usize = 256;

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
    Click,
    ClickPoint,
}

pub type CapabilityAction = Action;

impl Action {
    pub const fn floor(self) -> Severity {
        match self {
            Self::Navigate => Severity::new(OBSERVE, false, false),
            Self::Click | Self::ClickPoint => Severity::new(COMPOSE, false, false),
        }
    }
}

/// A grant scoped to one conversation. Each grant has an identifier, revision,
/// severity requirement, and list of authorized origins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionGrant {
    pub id: String,
    pub revision: u64,
    pub conversation_key: String,
    pub severity: Severity,
    pub authorized_origins: Vec<String>,
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
        }
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
            if canonical_origin(origin).as_deref() != Some(origin) {
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
    ) -> Result<ActionGrant, AuthorizationError> {
        self.ensure_valid()?;
        required.validate()?;
        let candidates = self
            .current
            .values()
            .filter(|grant| {
                grant.conversation_key == conversation_key && grant.severity.covers(required)
            })
            .cloned()
            .collect::<Vec<_>>();
        select_deterministic_covering_grant(&candidates, required)?
            .cloned()
            .ok_or(AuthorizationError::NoGrant)
    }

    /// Build a decision and perform no browser or connector work.
    pub fn authorize(
        &self,
        request: AuthorizationRequest<'_>,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.ensure_valid()?;
        let (computed, fingerprint) =
            computed_required_severity(request.action, request.classification)?;
        let floor = request.action.floor();
        request.requested_severity.validate()?;
        if request.requested_severity.tier < floor.tier {
            return Err(AuthorizationError::SeverityBelowFloor);
        }
        let effective = request.requested_severity.maximum(computed);
        let grant = self.select_covering_grant(request.conversation_key, effective)?;
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
) -> Result<AuthorizationDecision, AuthorizationError> {
    let store = GrantStore::try_new(grants.iter().cloned())?;
    store.authorize(request)
}

/// Select one covering grant using a total order independent of provider map
/// iteration or arrival order.  Grant identity is the primary stable key;
/// revision and the remaining immutable grant material complete the order.
pub fn select_covering_grant(
    candidates: &[ActionGrant],
    required: Severity,
) -> Result<Option<&ActionGrant>, AuthorizationError> {
    select_deterministic_covering_grant(candidates, required)
}

pub fn select_deterministic_covering_grant(
    candidates: &[ActionGrant],
    required: Severity,
) -> Result<Option<&ActionGrant>, AuthorizationError> {
    required.validate()?;
    let mut covering = candidates
        .iter()
        .filter(|grant| grant.validate().is_ok() && grant.severity.covers(required))
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
        Action::Navigate => Ok((Action::Navigate.floor(), None)),
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

pub fn effective_severity(
    action: Action,
    requested: Severity,
    classification: Option<&NonTypeClassificationRecord>,
) -> Result<Severity, AuthorizationError> {
    requested.validate()?;
    let (computed, _) = computed_required_severity(action, classification)?;
    let floor = action.floor();
    if requested.tier < floor.tier {
        return Err(AuthorizationError::SeverityBelowFloor);
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
        classification_fingerprint: fingerprint,
        action: request.action,
    })
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
    SeverityBelowFloor,
    NoGrant,
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
        let a = grant("grant-b", 1, &["https://b.test"]);
        let b = grant("grant-a", 1, &["https://a.test"]);
        let first_candidates = [a.clone(), b.clone()];
        let second_candidates = [b, a];
        let first = select_deterministic_covering_grant(&first_candidates, required)
            .unwrap()
            .unwrap();
        let second = select_deterministic_covering_grant(&second_candidates, required)
            .unwrap()
            .unwrap();
        assert_eq!(first.id, "grant-a");
        assert_eq!(first, second);
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
            .authorize(AuthorizationRequest::navigate(
                "conversation",
                Severity::new(OBSERVE, false, false),
                "invocation-1",
                "bind-1",
            ))
            .unwrap();
        store.revoke("grant-a").unwrap();
        assert_eq!(
            store.commit(&decision),
            Err(AuthorizationCommitError::GrantRevoked)
        );

        let mut store = GrantStore::new([grant("grant-a", 1, &["https://allowed.test"])]);
        let decision = store
            .authorize(AuthorizationRequest::navigate(
                "conversation",
                Severity::new(OBSERVE, false, false),
                "invocation-1",
                "bind-1",
            ))
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
            .authorize(AuthorizationRequest::navigate(
                "conversation",
                Severity::new(OBSERVE, false, false),
                "invocation-1",
                "bind-1",
            ))
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
