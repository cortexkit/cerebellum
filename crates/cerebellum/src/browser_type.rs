//! Ordered `browser.type` verification and evidence-gate primitives.
//!
//! The real browser adapter is deliberately behind [`BrowserTypeDriver`].  Keeping
//! the ordering here makes the input boundary auditable and gives CDP and the
//! deterministic mutation fixtures one implementation to exercise.  In
//! particular, the classification used for authorization is never replaced by
//! the observation taken immediately before insertion.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The capability whose registration is protected by this slice's evidence.
pub const BROWSER_TYPE_TOOL: &str = "browser.type";

/// SHA-256 of the immutable eligibility artifact, populated from the checked-in
/// artifact and repeated in the capability manifest and source lock.
pub const BROWSER_EVIDENCE_ELIGIBILITY_SHA256: &str =
    "b2dc267d5b4753339686b8546a701959f6b1535cdbbc6cf262018ee73333f40e";

const ELIGIBILITY_ARTIFACT: &[u8] =
    include_bytes!("../resources/browser_evidence_eligibility-v1.json");
const IMPLEMENTATION_SOURCE_LOCK: &[u8] =
    include_bytes!("../resources/implementation-source-lock.json");

/// The fields that decide whether a type target can receive text.
///
/// This value is produced once for an observation and is reused by geometry,
/// dispatch, and final revalidation.  Do not duplicate these checks at a call
/// site: a duplicated predicate can allow focus or input after a mutation that
/// should have invalidated the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityPredicates {
    pub writable_text_control: bool,
    pub editable_region: bool,
    pub disabled: bool,
    pub readonly: bool,
    pub inert: bool,
}

impl EligibilityPredicates {
    /// Return whether the observed node is an eligible text target.
    pub fn allows_type(&self) -> bool {
        (self.writable_text_control || self.editable_region)
            && !self.disabled
            && !self.readonly
            && !self.inert
    }
}

/// A form-associated descendant that contributes to target classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormDescendantClassification {
    pub node_identity: String,
    pub form_owner: Option<String>,
    pub disabled: bool,
    pub autocomplete_tokens: Vec<String>,
    pub password: bool,
}

impl FormDescendantClassification {
    fn credential(&self) -> bool {
        self.password
            || self.autocomplete_tokens.iter().any(|token| {
                matches!(
                    token.as_str(),
                    "current-password" | "new-password" | "one-time-code"
                )
            })
    }

    fn financial(&self) -> bool {
        self.autocomplete_tokens.iter().any(|token| {
            matches!(
                token.as_str(),
                "cc-name"
                    | "cc-given-name"
                    | "cc-additional-name"
                    | "cc-family-name"
                    | "cc-number"
                    | "cc-exp"
                    | "cc-exp-month"
                    | "cc-exp-year"
                    | "cc-csc"
                    | "cc-type"
            )
        })
    }
}

/// Geometry observed for a structured type target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeGeometry {
    pub rendered_box: bool,
    pub area: f64,
    /// The CDP/layout observation revision.  It is part of the complete
    /// fingerprint so a geometry mutation cannot be silently adopted.
    pub revision: u64,
}

impl Default for TypeGeometry {
    fn default() -> Self {
        Self {
            rendered_box: true,
            area: 1.0,
            revision: 0,
        }
    }
}

/// The captured node state retained by a snapshot and presented by a browser
/// adapter to the ordered type executor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeTarget {
    pub node_identity: String,
    pub document_epoch: u64,
    pub form_owner: Option<String>,
    pub autocomplete_tokens: Vec<String>,
    pub password: bool,
    pub writable_text_control: bool,
    pub editable_region: bool,
    pub disabled: bool,
    pub readonly: bool,
    pub inert: bool,
    pub form_descendants: Vec<FormDescendantClassification>,
    pub geometry: TypeGeometry,
}

impl TypeTarget {
    /// Derive the single eligibility predicate set used at all browser.type
    /// boundaries.
    pub fn eligibility_predicates(&self) -> EligibilityPredicates {
        EligibilityPredicates {
            writable_text_control: self.writable_text_control,
            editable_region: self.editable_region,
            disabled: self.disabled,
            readonly: self.readonly,
            inert: self.inert,
        }
    }

    /// Geometry eligibility includes the shared type predicate and a rendered,
    /// positive-area box.  The shared predicate itself is not reimplemented.
    pub fn geometry_eligible(&self) -> bool {
        browser_type_eligibility(self)
            && self.geometry.rendered_box
            && self.geometry.area.is_finite()
            && self.geometry.area > 0.0
    }

    /// Build the one classification record used for credential checks,
    /// authorization, and both snapshot verifications.
    pub fn classification(&self) -> ClassificationRecord {
        let descendant_credential = self
            .form_descendants
            .iter()
            .filter(|node| node.form_owner == self.form_owner)
            .any(FormDescendantClassification::credential);
        let descendant_financial = self
            .form_descendants
            .iter()
            .filter(|node| node.form_owner == self.form_owner)
            .any(FormDescendantClassification::financial);
        let credential = self.password
            || self.autocomplete_tokens.iter().any(|token| {
                matches!(
                    token.as_str(),
                    "current-password" | "new-password" | "one-time-code"
                )
            })
            || descendant_credential;
        let financial = self.autocomplete_tokens.iter().any(|token| {
            matches!(
                token.as_str(),
                "cc-name"
                    | "cc-given-name"
                    | "cc-additional-name"
                    | "cc-family-name"
                    | "cc-number"
                    | "cc-exp"
                    | "cc-exp-month"
                    | "cc-exp-year"
                    | "cc-csc"
                    | "cc-type"
            )
        }) || descendant_financial;

        ClassificationRecord {
            node_identity: self.node_identity.clone(),
            document_epoch: self.document_epoch,
            form_owner: self.form_owner.clone(),
            autocomplete_tokens: self.autocomplete_tokens.clone(),
            password: self.password,
            writable_text_control: self.writable_text_control,
            editable_region: self.editable_region,
            disabled: self.disabled,
            readonly: self.readonly,
            inert: self.inert,
            form_descendants: self.form_descendants.clone(),
            geometry_rendered_box: self.geometry.rendered_box,
            geometry_area_bits: self.geometry.area.to_bits(),
            geometry_revision: self.geometry.revision,
            required_tier: 2,
            credential,
            financial,
            destination_origin: None,
        }
    }
}

/// The complete classification record.  Every field is serialized into the
/// fingerprint; adding a classification input requires updating this record and
/// the immutable eligibility artifact together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationRecord {
    pub node_identity: String,
    pub document_epoch: u64,
    pub form_owner: Option<String>,
    pub autocomplete_tokens: Vec<String>,
    pub password: bool,
    pub writable_text_control: bool,
    pub editable_region: bool,
    pub disabled: bool,
    pub readonly: bool,
    pub inert: bool,
    pub form_descendants: Vec<FormDescendantClassification>,
    pub geometry_rendered_box: bool,
    pub geometry_area_bits: u64,
    pub geometry_revision: u64,
    pub required_tier: u8,
    pub credential: bool,
    pub financial: bool,
    pub destination_origin: Option<String>,
}

impl ClassificationRecord {
    /// Return the stable SHA-256 fingerprint of this complete record.
    pub fn fingerprint(&self) -> ClassificationFingerprint {
        let bytes = serde_json::to_vec(self).expect("classification record is serializable");
        let mut digest = [0; 32];
        digest.copy_from_slice(Sha256::digest(bytes).as_slice());
        ClassificationFingerprint(digest)
    }

    pub fn eligibility_predicates(&self) -> EligibilityPredicates {
        EligibilityPredicates {
            writable_text_control: self.writable_text_control,
            editable_region: self.editable_region,
            disabled: self.disabled,
            readonly: self.readonly,
            inert: self.inert,
        }
    }
}

/// Opaque, comparable representation of the complete classification record.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClassificationFingerprint([u8; 32]);

impl ClassificationFingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClassificationFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClassificationFingerprint")
            .field(&hex(&self.0))
            .finish()
    }
}

/// A browser.type request after closed-schema validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserTypeRequest {
    pub ref_name: String,
    pub snapshot_id: String,
    pub text: String,
    pub replace: bool,
}

impl BrowserTypeRequest {
    pub fn new(
        ref_name: impl Into<String>,
        snapshot_id: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            ref_name: ref_name.into(),
            snapshot_id: snapshot_id.into(),
            text: text.into(),
            replace: false,
        }
    }
}

/// The stale reasons used by both verification points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleReason {
    DocumentEpochChanged,
    ResolvedNodeChanged,
}

/// Closed result model for the focused type path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserTypeResult {
    Ok,
    InvalidRequest { field: String, reason_code: String },
    StaleSnapshot { reason: StaleReason },
    AuthorizationDenied,
    InternalError { reason_code: String },
}

impl BrowserTypeResult {
    pub fn to_value(&self) -> Value {
        match self {
            Self::Ok => json!({ "outcome": "ok" }),
            Self::InvalidRequest { field, reason_code } => json!({
                "outcome": "invalid_request",
                "detail": { "field": field, "reason_code": reason_code }
            }),
            Self::StaleSnapshot { reason } => json!({
                "outcome": "stale_snapshot",
                "detail": { "reason_code": match reason {
                    StaleReason::DocumentEpochChanged => "document_epoch_changed",
                    StaleReason::ResolvedNodeChanged => "resolved_node_changed",
                }}
            }),
            Self::AuthorizationDenied => json!({
                "outcome": "authorization_denied",
                "detail": { "reason": "no_grant" }
            }),
            Self::InternalError { reason_code } => json!({
                "outcome": "internal_error",
                "detail": { "reason_code": reason_code }
            }),
        }
    }
}

/// A journal terminal transition emitted by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEvent {
    Reserved,
    FinalizeRejected(BrowserTypeResult),
    CommitDispatched,
    FinalizeDispatched(BrowserTypeResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalError {
    pub reason: String,
}

impl JournalError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// The journal interface consumed by `browser.type`. It intentionally contains
/// no sequence or token construction; those remain values owned by the journal.
pub trait BrowserTypeJournal {
    fn reserve(&mut self) -> Result<(), JournalError>;
    fn finalize_rejected(&mut self, result: &BrowserTypeResult) -> Result<(), JournalError>;
    fn commit_dispatched(&mut self) -> Result<(), JournalError>;
    fn finalize_dispatched(&mut self, result: &BrowserTypeResult) -> Result<(), JournalError>;
}

/// Authorization is called exactly once, after the initial classification and
/// never during the final fingerprint verification.
pub trait BrowserTypeAuthorizer {
    fn authorize(&mut self, classification: &ClassificationRecord) -> bool;
}

#[derive(Debug, Default)]
pub struct RecordingAuthorizer {
    pub allow: bool,
    pub calls: usize,
    pub classifications: Vec<ClassificationFingerprint>,
}

impl RecordingAuthorizer {
    pub fn allowing() -> Self {
        Self {
            allow: true,
            ..Self::default()
        }
    }
}

impl BrowserTypeAuthorizer for RecordingAuthorizer {
    fn authorize(&mut self, classification: &ClassificationRecord) -> bool {
        self.calls += 1;
        self.classifications.push(classification.fingerprint());
        self.allow
    }
}

/// The narrow browser seam required by the ordered type path.
pub trait BrowserTypeDriver {
    fn observe_type_target(&mut self) -> Result<TypeTarget, TypeDriverError>;
    fn focus_type_target(&mut self, node_identity: &str) -> Result<(), TypeDriverError>;
    fn select_type_target_contents(&mut self, node_identity: &str) -> Result<(), TypeDriverError>;
    fn insert_type_text(&mut self, node_identity: &str, text: &str) -> Result<(), TypeDriverError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDriverError {
    pub reason: String,
}

impl TypeDriverError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Execute browser.type in the fixed order: reserve, initial verification,
/// authorization, commit, focus, optional selection, final verification, input,
/// and dispatched finalization.
pub struct BrowserTypeExecutor;

impl BrowserTypeExecutor {
    pub fn execute<D, J, A>(
        driver: &mut D,
        journal: &mut J,
        authorizer: &mut A,
        snapshot: &TypeTarget,
        request: &BrowserTypeRequest,
    ) -> BrowserTypeResult
    where
        D: BrowserTypeDriver,
        J: BrowserTypeJournal,
        A: BrowserTypeAuthorizer,
    {
        if request.ref_name.is_empty() || request.snapshot_id.is_empty() {
            return BrowserTypeResult::InvalidRequest {
                field: if request.ref_name.is_empty() {
                    "ref"
                } else {
                    "snapshot_id"
                }
                .to_string(),
                reason_code: "missing_field".to_string(),
            };
        }
        if request.text.len() > 8192 {
            return BrowserTypeResult::InvalidRequest {
                field: "text".to_string(),
                reason_code: "out_of_range".to_string(),
            };
        }

        if journal.reserve().is_err() {
            return BrowserTypeResult::InternalError {
                reason_code: "journal_reservation_failed".to_string(),
            };
        }

        let initial = match driver.observe_type_target() {
            Ok(target) => target,
            Err(_) => {
                return finalize_rejected(
                    journal,
                    BrowserTypeResult::InternalError {
                        reason_code: "cdp_failure".to_string(),
                    },
                )
            }
        };
        if let Err(reason) = verify_type_target(snapshot, &initial) {
            return finalize_rejected(journal, BrowserTypeResult::StaleSnapshot { reason });
        }
        if !browser_type_dispatch_eligible(&initial) || !browser_type_geometry_eligible(&initial) {
            return finalize_rejected(
                journal,
                BrowserTypeResult::InvalidRequest {
                    field: "ref".to_string(),
                    reason_code: "target_not_interactive".to_string(),
                },
            );
        }

        let initial_classification = initial.classification();
        if initial_classification.credential || initial_classification.financial {
            return finalize_rejected(
                journal,
                BrowserTypeResult::InvalidRequest {
                    field: "text".to_string(),
                    reason_code: "credential_input_unsupported".to_string(),
                },
            );
        }
        if !authorizer.authorize(&initial_classification) {
            return finalize_rejected(journal, BrowserTypeResult::AuthorizationDenied);
        }
        if journal.commit_dispatched().is_err() {
            return finalize_rejected(
                journal,
                BrowserTypeResult::InternalError {
                    reason_code: "internal_failure".to_string(),
                },
            );
        }

        if driver.focus_type_target(&initial.node_identity).is_err() {
            return finalize_dispatched(
                journal,
                BrowserTypeResult::InternalError {
                    reason_code: "cdp_failure".to_string(),
                },
            );
        }
        if request.replace
            && driver
                .select_type_target_contents(&initial.node_identity)
                .is_err()
        {
            return finalize_dispatched(
                journal,
                BrowserTypeResult::InternalError {
                    reason_code: "cdp_failure".to_string(),
                },
            );
        }

        // This is intentionally a verification, not a new classification for
        // authorization.  The original record remains authoritative; a changed
        // record is stale and is never adopted.
        let final_observation = match driver.observe_type_target() {
            Ok(target) => target,
            Err(_) => {
                return finalize_dispatched(
                    journal,
                    BrowserTypeResult::InternalError {
                        reason_code: "cdp_failure".to_string(),
                    },
                )
            }
        };
        if let Err(reason) = verify_type_target(snapshot, &final_observation) {
            return finalize_dispatched(journal, BrowserTypeResult::StaleSnapshot { reason });
        }
        if !browser_type_revalidation_eligible(&final_observation)
            || !browser_type_geometry_eligible(&final_observation)
        {
            return finalize_dispatched(
                journal,
                BrowserTypeResult::StaleSnapshot {
                    reason: StaleReason::ResolvedNodeChanged,
                },
            );
        }

        if driver
            .insert_type_text(&initial.node_identity, &request.text)
            .is_err()
        {
            return finalize_dispatched(
                journal,
                BrowserTypeResult::InternalError {
                    reason_code: "cdp_failure".to_string(),
                },
            );
        }
        finalize_dispatched(journal, BrowserTypeResult::Ok)
    }
}

/// Verify epoch before fingerprint so a document change always maps to the
/// document-specific stale reason.
pub fn verify_type_target(expected: &TypeTarget, observed: &TypeTarget) -> Result<(), StaleReason> {
    if observed.document_epoch != expected.document_epoch {
        return Err(StaleReason::DocumentEpochChanged);
    }
    if observed.node_identity != expected.node_identity
        || observed.classification().fingerprint() != expected.classification().fingerprint()
    {
        return Err(StaleReason::ResolvedNodeChanged);
    }
    Ok(())
}

/// Shared eligibility entry point used by geometry, dispatch, and final
/// revalidation.  All three callers intentionally pass the live observation.
pub fn browser_type_eligibility(target: &TypeTarget) -> bool {
    target.eligibility_predicates().allows_type()
}

pub fn browser_type_geometry_eligible(target: &TypeTarget) -> bool {
    target.geometry_eligible()
}

/// Dispatch eligibility is deliberately the same predicate set as geometry;
/// the geometry wrapper only adds the rendered positive-area requirement.
pub fn browser_type_dispatch_eligible(target: &TypeTarget) -> bool {
    browser_type_eligibility(target)
}

/// The final live observation is checked through the same eligibility function,
/// never through a second set of booleans.
pub fn browser_type_revalidation_eligible(target: &TypeTarget) -> bool {
    browser_type_eligibility(target)
}

fn finalize_rejected<J: BrowserTypeJournal>(
    journal: &mut J,
    result: BrowserTypeResult,
) -> BrowserTypeResult {
    if journal.finalize_rejected(&result).is_err() {
        BrowserTypeResult::InternalError {
            reason_code: "journal_reservation_failed".to_string(),
        }
    } else {
        result
    }
}

fn finalize_dispatched<J: BrowserTypeJournal>(
    journal: &mut J,
    result: BrowserTypeResult,
) -> BrowserTypeResult {
    if journal.finalize_dispatched(&result).is_err() {
        BrowserTypeResult::InternalError {
            reason_code: "internal_failure".to_string(),
        }
    } else {
        result
    }
}

/// Evidence inputs accepted by the registration gate.  A dependency bundle,
/// ambient flag, or implementation-defined boolean is never an approval source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceEligibilityInput {
    pub manifest_digest: Option<String>,
    pub source_lock_digest: Option<String>,
    pub computed_artifact_digest: Option<String>,
    pub dependency_bundle_digest: Option<String>,
    pub ambient_approval: bool,
    pub implementation_defined_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceEligibilityError {
    AmbientApprovalNotAccepted,
    ImplementationDefinedApprovalNotAccepted,
    MissingManifestDigest,
    MissingSourceLockDigest,
    MissingComputedArtifactDigest,
    ManifestDigestMismatch,
    SourceLockDigestMismatch,
    ComputedArtifactDigestMismatch,
    ArtifactDigestMismatch,
}

impl fmt::Display for EvidenceEligibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EvidenceEligibilityError {}

/// Return the digest computed from the checked-in immutable artifact.
pub fn computed_eligibility_artifact_digest() -> String {
    hex(&Sha256::digest(ELIGIBILITY_ARTIFACT))
}

pub fn implementation_source_lock_digest() -> Option<String> {
    serde_json::from_slice::<Value>(IMPLEMENTATION_SOURCE_LOCK)
        .ok()
        .and_then(|value| {
            value
                .get("browser_evidence_eligibility_sha256")?
                .as_str()
                .map(str::to_owned)
        })
}

/// Validate the only accepted evidence path: manifest value, implementation
/// source lock, and the digest computed from the immutable artifact all agree.
pub fn validate_evidence_eligibility(
    input: &EvidenceEligibilityInput,
) -> Result<(), EvidenceEligibilityError> {
    if input.ambient_approval {
        return Err(EvidenceEligibilityError::AmbientApprovalNotAccepted);
    }
    if input.implementation_defined_approval {
        return Err(EvidenceEligibilityError::ImplementationDefinedApprovalNotAccepted);
    }
    let Some(manifest) = input.manifest_digest.as_deref() else {
        return Err(EvidenceEligibilityError::MissingManifestDigest);
    };
    let Some(source_lock) = input.source_lock_digest.as_deref() else {
        return Err(EvidenceEligibilityError::MissingSourceLockDigest);
    };
    let Some(computed) = input.computed_artifact_digest.as_deref() else {
        return Err(EvidenceEligibilityError::MissingComputedArtifactDigest);
    };
    if manifest != BROWSER_EVIDENCE_ELIGIBILITY_SHA256 {
        return Err(EvidenceEligibilityError::ManifestDigestMismatch);
    }
    if source_lock != BROWSER_EVIDENCE_ELIGIBILITY_SHA256
        || implementation_source_lock_digest().as_deref()
            != Some(BROWSER_EVIDENCE_ELIGIBILITY_SHA256)
    {
        return Err(EvidenceEligibilityError::SourceLockDigestMismatch);
    }
    if computed != BROWSER_EVIDENCE_ELIGIBILITY_SHA256 {
        return Err(EvidenceEligibilityError::ComputedArtifactDigestMismatch);
    }
    if computed_eligibility_artifact_digest() != BROWSER_EVIDENCE_ELIGIBILITY_SHA256 {
        return Err(EvidenceEligibilityError::ArtifactDigestMismatch);
    }
    Ok(())
}

/// A convenience gate for manifest registration tests.  It does not accept a
/// dependency-bundle or ambient shortcut because those values do not prove the
/// immutable eligibility artifact was evaluated.
pub fn browser_type_registration_eligible(input: &EvidenceEligibilityInput) -> bool {
    validate_evidence_eligibility(input).is_ok()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

/// A deterministic driver used by acceptance fixtures.  Mutation handlers run
/// before their corresponding CDP acknowledgement is returned.
#[derive(Debug, Clone)]
pub struct DeterministicTypeFixture {
    pub target: TypeTarget,
    pub focus_mutation: Option<FixtureMutation>,
    pub replacement_selection_mutation: Option<FixtureMutation>,
    pub events: Vec<FixtureEvent>,
}

impl DeterministicTypeFixture {
    pub fn new(target: TypeTarget) -> Self {
        Self {
            target,
            focus_mutation: None,
            replacement_selection_mutation: None,
            events: Vec::new(),
        }
    }

    pub fn with_focus_mutation(mut self, mutation: FixtureMutation) -> Self {
        self.focus_mutation = Some(mutation);
        self
    }

    pub fn with_replacement_selection_mutation(mut self, mutation: FixtureMutation) -> Self {
        self.replacement_selection_mutation = Some(mutation);
        self
    }

    pub fn inserted(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, FixtureEvent::TextInserted { .. }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FixtureMutation {
    FormOwnership(Option<String>),
    Autocomplete(Vec<String>),
    Password(bool),
    Editability {
        writable_text_control: bool,
        editable_region: bool,
    },
    Disabled(bool),
    Readonly(bool),
    Inert(bool),
    FormDescendants(Vec<FormDescendantClassification>),
    Epoch(u64),
    Geometry {
        rendered_box: bool,
        area: f64,
    },
    NodeIdentity(String),
}

impl FixtureMutation {
    fn apply(&self, target: &mut TypeTarget) {
        match self {
            Self::FormOwnership(value) => target.form_owner = value.clone(),
            Self::Autocomplete(value) => target.autocomplete_tokens = value.clone(),
            Self::Password(value) => target.password = *value,
            Self::Editability {
                writable_text_control,
                editable_region,
            } => {
                target.writable_text_control = *writable_text_control;
                target.editable_region = *editable_region;
            }
            Self::Disabled(value) => target.disabled = *value,
            Self::Readonly(value) => target.readonly = *value,
            Self::Inert(value) => target.inert = *value,
            Self::FormDescendants(value) => target.form_descendants = value.clone(),
            Self::Epoch(value) => target.document_epoch = *value,
            Self::Geometry { rendered_box, area } => {
                target.geometry.rendered_box = *rendered_box;
                target.geometry.area = *area;
                target.geometry.revision += 1;
            }
            Self::NodeIdentity(value) => target.node_identity = value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FixtureEvent {
    Observed,
    FocusAcknowledged,
    ReplacementSelectionAcknowledged,
    TextInserted { node_identity: String, text: String },
}

impl BrowserTypeDriver for DeterministicTypeFixture {
    fn observe_type_target(&mut self) -> Result<TypeTarget, TypeDriverError> {
        self.events.push(FixtureEvent::Observed);
        Ok(self.target.clone())
    }

    fn focus_type_target(&mut self, _node_identity: &str) -> Result<(), TypeDriverError> {
        if let Some(mutation) = self.focus_mutation.take() {
            mutation.apply(&mut self.target);
        }
        self.events.push(FixtureEvent::FocusAcknowledged);
        Ok(())
    }

    fn select_type_target_contents(&mut self, _node_identity: &str) -> Result<(), TypeDriverError> {
        if let Some(mutation) = self.replacement_selection_mutation.take() {
            mutation.apply(&mut self.target);
        }
        self.events
            .push(FixtureEvent::ReplacementSelectionAcknowledged);
        Ok(())
    }

    fn insert_type_text(&mut self, node_identity: &str, text: &str) -> Result<(), TypeDriverError> {
        self.events.push(FixtureEvent::TextInserted {
            node_identity: node_identity.to_string(),
            text: text.to_string(),
        });
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RecordingJournal {
    pub events: Vec<JournalEvent>,
    pub fail_reserve: bool,
    pub fail_finalize_rejected: bool,
    pub fail_commit: bool,
    pub fail_finalize_dispatched: bool,
}

impl BrowserTypeJournal for RecordingJournal {
    fn reserve(&mut self) -> Result<(), JournalError> {
        if self.fail_reserve {
            return Err(JournalError::new("reserve"));
        }
        self.events.push(JournalEvent::Reserved);
        Ok(())
    }

    fn finalize_rejected(&mut self, result: &BrowserTypeResult) -> Result<(), JournalError> {
        if self.fail_finalize_rejected {
            return Err(JournalError::new("finalize_rejected"));
        }
        self.events
            .push(JournalEvent::FinalizeRejected(result.clone()));
        Ok(())
    }

    fn commit_dispatched(&mut self) -> Result<(), JournalError> {
        if self.fail_commit {
            return Err(JournalError::new("commit_dispatched"));
        }
        self.events.push(JournalEvent::CommitDispatched);
        Ok(())
    }

    fn finalize_dispatched(&mut self, result: &BrowserTypeResult) -> Result<(), JournalError> {
        if self.fail_finalize_dispatched {
            return Err(JournalError::new("finalize_dispatched"));
        }
        self.events
            .push(JournalEvent::FinalizeDispatched(result.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> TypeTarget {
        TypeTarget {
            node_identity: "backend-17".to_string(),
            document_epoch: 4,
            form_owner: Some("form-1".to_string()),
            autocomplete_tokens: vec!["name".to_string()],
            password: false,
            writable_text_control: true,
            editable_region: false,
            disabled: false,
            readonly: false,
            inert: false,
            form_descendants: vec![FormDescendantClassification {
                node_identity: "descendant-1".to_string(),
                form_owner: Some("form-1".to_string()),
                disabled: false,
                autocomplete_tokens: vec!["name".to_string()],
                password: false,
            }],
            geometry: TypeGeometry::default(),
        }
    }

    /// A target whose own autocomplete token marks it credential-bearing.
    fn credential_target(token: &str) -> TypeTarget {
        let mut target = target();
        target.autocomplete_tokens = vec![token.to_string()];
        target
    }

    /// A target marked credential-bearing by the password attribute alone,
    /// carrying no autocomplete hint at all.
    fn password_target() -> TypeTarget {
        let mut target = target();
        target.autocomplete_tokens = Vec::new();
        target.password = true;
        target
    }

    fn request(replace: bool) -> BrowserTypeRequest {
        BrowserTypeRequest {
            ref_name: "e1".to_string(),
            snapshot_id: "0123456789abcdef0123456789abcdef".to_string(),
            text: "hello".to_string(),
            replace,
        }
    }

    fn execute(
        fixture: &mut DeterministicTypeFixture,
        journal: &mut RecordingJournal,
        authorizer: &mut RecordingAuthorizer,
        snapshot: &TypeTarget,
        request: &BrowserTypeRequest,
    ) -> BrowserTypeResult {
        BrowserTypeExecutor::execute(fixture, journal, authorizer, snapshot, request)
    }

    #[test]
    fn success_focus_then_replace_then_final_verify_then_insert() {
        let snapshot = target();
        let mut fixture = DeterministicTypeFixture::new(snapshot.clone());
        let mut journal = RecordingJournal::default();
        let mut authorizer = RecordingAuthorizer::allowing();
        assert_eq!(
            execute(
                &mut fixture,
                &mut journal,
                &mut authorizer,
                &snapshot,
                &request(true)
            ),
            BrowserTypeResult::Ok
        );
        assert_eq!(authorizer.calls, 1);
        assert!(fixture.inserted());
        assert_eq!(journal.events.len(), 3);
        assert!(matches!(
            journal.events[2],
            JournalEvent::FinalizeDispatched(BrowserTypeResult::Ok)
        ));
    }

    #[test]
    fn epoch_changed_before_focus_is_rejected_before_commit() {
        let snapshot = target();
        let mut current = snapshot.clone();
        current.document_epoch = 5;
        let mut fixture = DeterministicTypeFixture::new(current);
        let mut journal = RecordingJournal::default();
        let mut authorizer = RecordingAuthorizer::allowing();
        let result = execute(
            &mut fixture,
            &mut journal,
            &mut authorizer,
            &snapshot,
            &request(false),
        );
        assert_eq!(
            result,
            BrowserTypeResult::StaleSnapshot {
                reason: StaleReason::DocumentEpochChanged
            }
        );
        assert!(!fixture.inserted());
        assert_eq!(authorizer.calls, 0);
        assert!(matches!(
            journal.events[1],
            JournalEvent::FinalizeRejected(_)
        ));
    }

    #[test]
    fn epoch_changed_after_focus_finalizes_dispatched_without_input() {
        let snapshot = target();
        let mut fixture = DeterministicTypeFixture::new(snapshot.clone())
            .with_focus_mutation(FixtureMutation::Epoch(5));
        let mut journal = RecordingJournal::default();
        let mut authorizer = RecordingAuthorizer::allowing();
        let result = execute(
            &mut fixture,
            &mut journal,
            &mut authorizer,
            &snapshot,
            &request(false),
        );
        assert_eq!(
            result,
            BrowserTypeResult::StaleSnapshot {
                reason: StaleReason::DocumentEpochChanged
            }
        );
        assert!(!fixture.inserted());
        assert_eq!(authorizer.calls, 1);
        assert!(matches!(
            journal.events[2],
            JournalEvent::FinalizeDispatched(BrowserTypeResult::StaleSnapshot { .. })
        ));
    }

    #[test]
    fn fingerprint_mutations_after_focus_are_stale_and_not_authorized_again() {
        let mutations = [
            FixtureMutation::FormOwnership(Some("form-2".to_string())),
            FixtureMutation::Autocomplete(vec!["current-password".to_string()]),
            FixtureMutation::Password(true),
            FixtureMutation::Editability {
                writable_text_control: false,
                editable_region: false,
            },
            FixtureMutation::Disabled(true),
            FixtureMutation::Readonly(true),
            FixtureMutation::Inert(true),
            FixtureMutation::FormDescendants(vec![FormDescendantClassification {
                node_identity: "descendant-2".to_string(),
                form_owner: Some("form-1".to_string()),
                disabled: false,
                autocomplete_tokens: vec!["cc-number".to_string()],
                password: false,
            }]),
        ];
        for mutation in mutations {
            let snapshot = target();
            let mut fixture =
                DeterministicTypeFixture::new(snapshot.clone()).with_focus_mutation(mutation);
            let mut journal = RecordingJournal::default();
            let mut authorizer = RecordingAuthorizer::allowing();
            let result = execute(
                &mut fixture,
                &mut journal,
                &mut authorizer,
                &snapshot,
                &request(false),
            );
            assert_eq!(
                result,
                BrowserTypeResult::StaleSnapshot {
                    reason: StaleReason::ResolvedNodeChanged
                }
            );
            assert!(!fixture.inserted());
            assert_eq!(authorizer.calls, 1);
            assert!(matches!(
                journal.events.last(),
                Some(JournalEvent::FinalizeDispatched(
                    BrowserTypeResult::StaleSnapshot { .. }
                ))
            ));
        }
    }

    #[test]
    fn replacement_handler_mutation_has_same_second_verification_boundary() {
        let snapshot = target();
        let mutation = FixtureMutation::FormDescendants(vec![FormDescendantClassification {
            node_identity: "descendant-3".to_string(),
            form_owner: Some("form-1".to_string()),
            disabled: false,
            autocomplete_tokens: vec!["new-password".to_string()],
            password: false,
        }]);
        let mut fixture = DeterministicTypeFixture::new(snapshot.clone())
            .with_replacement_selection_mutation(mutation);
        let mut journal = RecordingJournal::default();
        let mut authorizer = RecordingAuthorizer::allowing();
        let result = execute(
            &mut fixture,
            &mut journal,
            &mut authorizer,
            &snapshot,
            &request(true),
        );
        assert_eq!(
            result,
            BrowserTypeResult::StaleSnapshot {
                reason: StaleReason::ResolvedNodeChanged
            }
        );
        assert!(!fixture.inserted());
        assert_eq!(authorizer.calls, 1);
        assert!(fixture
            .events
            .iter()
            .any(|event| matches!(event, FixtureEvent::ReplacementSelectionAcknowledged)));
    }

    #[test]
    fn shared_predicate_rejects_every_ineligible_type_target() {
        for mutation in [
            FixtureMutation::Editability {
                writable_text_control: false,
                editable_region: false,
            },
            FixtureMutation::Disabled(true),
            FixtureMutation::Readonly(true),
            FixtureMutation::Inert(true),
        ] {
            let mut observed = target();
            mutation.apply(&mut observed);
            assert!(!browser_type_eligibility(&observed));
            assert!(!browser_type_geometry_eligible(&observed));
        }
    }

    #[test]
    fn evidence_gate_requires_manifest_lock_and_computed_artifact() {
        let digest = computed_eligibility_artifact_digest();
        assert_eq!(digest, BROWSER_EVIDENCE_ELIGIBILITY_SHA256);
        let input = EvidenceEligibilityInput {
            manifest_digest: Some(digest.clone()),
            source_lock_digest: Some(digest.clone()),
            computed_artifact_digest: Some(digest),
            ..EvidenceEligibilityInput::default()
        };
        assert!(browser_type_registration_eligible(&input));
        assert!(!browser_type_registration_eligible(
            &EvidenceEligibilityInput {
                dependency_bundle_digest: Some(BROWSER_EVIDENCE_ELIGIBILITY_SHA256.to_string()),
                ..EvidenceEligibilityInput::default()
            }
        ));
        assert!(!browser_type_registration_eligible(
            &EvidenceEligibilityInput {
                ambient_approval: true,
                ..input.clone()
            }
        ));
        assert!(!browser_type_registration_eligible(
            &EvidenceEligibilityInput {
                implementation_defined_approval: true,
                ..input
            }
        ));
    }

    /// The credential and financial refusal is the single most important safety
    /// property of this module: a refused target must never receive a keystroke,
    /// and the refusal must happen BEFORE authorization is consulted, so that no
    /// grant can ever authorize typing into a credential field.
    ///
    /// Without these cases the whole suite passes with the refusal branch
    /// removed, because every other fixture targets an ordinary text control.
    #[test]
    fn credential_and_financial_targets_are_refused_before_authorization() {
        let cases: Vec<(&str, TypeTarget)> = vec![
            ("password attribute", password_target()),
            ("current-password", credential_target("current-password")),
            ("new-password", credential_target("new-password")),
            ("one-time-code", credential_target("one-time-code")),
            ("cc-number", credential_target("cc-number")),
            ("cc-csc", credential_target("cc-csc")),
            ("cc-exp", credential_target("cc-exp")),
        ];

        for (label, snapshot) in cases {
            let mut fixture = DeterministicTypeFixture::new(snapshot.clone());
            let mut journal = RecordingJournal::default();
            let mut authorizer = RecordingAuthorizer::allowing();

            let result = execute(
                &mut fixture,
                &mut journal,
                &mut authorizer,
                &snapshot,
                &request(true),
            );

            assert_eq!(
                result,
                BrowserTypeResult::InvalidRequest {
                    field: "text".to_string(),
                    reason_code: "credential_input_unsupported".to_string(),
                },
                "{label} was not refused"
            );
            // The authorizer is never consulted, so an over-broad grant cannot
            // turn this refusal into an allow.
            assert_eq!(authorizer.calls, 0, "{label} consulted the authorizer");
            // No keystroke reaches the field.
            assert!(!fixture.inserted(), "{label} inserted text");
        }
    }

    /// The refusal must be driven by classification, not by the request shape:
    /// the same request against an ordinary text control is accepted.  Without
    /// this pair, a constant-reject implementation would satisfy the refusal
    /// test above and never be caught.
    #[test]
    fn an_ordinary_text_control_with_the_same_request_is_not_refused() {
        let snapshot = target();
        let mut fixture = DeterministicTypeFixture::new(snapshot.clone());
        let mut journal = RecordingJournal::default();
        let mut authorizer = RecordingAuthorizer::allowing();

        let result = execute(
            &mut fixture,
            &mut journal,
            &mut authorizer,
            &snapshot,
            &request(true),
        );

        assert_eq!(result, BrowserTypeResult::Ok);
        assert_eq!(authorizer.calls, 1);
        assert!(fixture.inserted());
    }
}
