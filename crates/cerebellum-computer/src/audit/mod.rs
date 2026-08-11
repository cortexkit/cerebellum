//! Computer-plane audit binding.
//!
//! This module owns the computer vocabulary which is deliberately kept outside
//! `cerebellum-core`.  Core receives only the deterministic bytes produced by
//! [`ComputerJournalCodec`], while this adapter is responsible for mapping the
//! closed computer action, containment, and observation domains to the neutral
//! severity inputs.

use crate::grounding::ContainmentRung;
use crate::platform::ActionKind;
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::codec::{
    CompletionInput, DispatchedInput, EncodedJournalState, JournalCodecError, PlaneJournalCodec,
    ProvisionalInput, RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
};
use cerebellum_core::journal::{
    ActionObligationId, EffectClass, IsolationClass, JournalIdentity, ObservabilityClass,
    RecoveryAction, RecoveryClassification, SeverityInputs, SeverityRecord, TerminalKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// The complete computer capability set frozen by the C1 vocabulary artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerCapability {
    Click,
    Type,
    Keys,
    Scroll,
    Move,
    Drag,
    Screenshot,
    Wait,
}

impl ComputerCapability {
    pub const ALL: [Self; 8] = [
        Self::Click,
        Self::Type,
        Self::Keys,
        Self::Scroll,
        Self::Move,
        Self::Drag,
        Self::Screenshot,
        Self::Wait,
    ];

    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::Click => "computer.click",
            Self::Type => "computer.type",
            Self::Keys => "computer.keys",
            Self::Scroll => "computer.scroll",
            Self::Move => "computer.move",
            Self::Drag => "computer.drag",
            Self::Screenshot => "computer.screenshot",
            Self::Wait => "computer.wait",
        }
    }

    pub const fn action_kind(self) -> ActionKind {
        match self {
            Self::Drag => ActionKind::MutateDurable,
            Self::Screenshot | Self::Wait => ActionKind::Observe,
            Self::Click | Self::Type | Self::Keys | Self::Scroll | Self::Move => {
                ActionKind::Compose
            }
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "computer.click" => Some(Self::Click),
            "computer.type" => Some(Self::Type),
            "computer.keys" => Some(Self::Keys),
            "computer.scroll" => Some(Self::Scroll),
            "computer.move" => Some(Self::Move),
            "computer.drag" => Some(Self::Drag),
            "computer.screenshot" => Some(Self::Screenshot),
            "computer.wait" => Some(Self::Wait),
            _ => None,
        }
    }
}

/// The closed observation state used by the computer adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    HumanObserved,
    HumanUnobserved,
}

impl ObservationState {
    pub const ALL: [Self; 2] = [Self::HumanObserved, Self::HumanUnobserved];

    pub const fn observability_class(self) -> ObservabilityClass {
        match self {
            Self::HumanObserved => ObservabilityClass::HumanObserved,
            Self::HumanUnobserved => ObservabilityClass::HumanUnobserved,
        }
    }
}

/// Convert the C1 containment evidence, never the nominal dispatch mode.
pub const fn containment_isolation_class(rung: ContainmentRung) -> IsolationClass {
    match rung {
        ContainmentRung::SemanticElement => IsolationClass::ResourceScoped,
        ContainmentRung::PidStructural => IsolationClass::OwnerScoped,
        ContainmentRung::GlobalNone => IsolationClass::Uncontained,
    }
}

/// The exhaustive action-kind mapping used by the computer adapter.
pub const fn action_effect_class(kind: ActionKind) -> EffectClass {
    match kind {
        ActionKind::Observe => EffectClass::Read,
        ActionKind::Compose | ActionKind::MutateDurable => EffectClass::Mutate,
    }
}

/// Map a frozen capability id to its normalized effect class.
pub const fn capability_effect_class(capability: ComputerCapability) -> EffectClass {
    action_effect_class(capability.action_kind())
}

/// Build the exact neutral severity input for one computer action.
pub const fn severity_inputs(
    capability: ComputerCapability,
    containment: ContainmentRung,
    observation: ObservationState,
) -> SeverityInputs {
    SeverityInputs {
        effect_class: capability_effect_class(capability),
        isolation_class: containment_isolation_class(containment),
        observability_class: observation.observability_class(),
    }
}

/// A material descriptor is intentionally closed.  It is the only computer
/// object that crosses the core codec boundary during reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerPlaneDescriptor {
    pub capability: ComputerCapability,
    pub containment_rung: ContainmentRung,
    pub observation: ObservationState,
}

impl ComputerPlaneDescriptor {
    pub fn new(
        capability: ComputerCapability,
        containment_rung: ContainmentRung,
        observation: ObservationState,
    ) -> Self {
        Self {
            capability,
            containment_rung,
            observation,
        }
    }

    pub fn severity_inputs(&self) -> SeverityInputs {
        severity_inputs(self.capability, self.containment_rung, self.observation)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DescriptorError> {
        serde_json::to_vec(self).map_err(|_| DescriptorError::Refused)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DescriptorError> {
        serde_json::from_slice(bytes).map_err(|_| DescriptorError::Refused)
    }
}

/// The four-operation descriptor codec required by the C2 seam.
#[derive(Debug, Clone, Copy, Default)]
pub struct ComputerDescriptorCodec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    Refused,
}

impl ComputerDescriptorCodec {
    pub const CODEC_ID: &'static str = "ck-computer-descriptor/v1";

    pub fn encode(&self, descriptor: &ComputerPlaneDescriptor) -> Result<Vec<u8>, DescriptorError> {
        descriptor.encode()
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<ComputerPlaneDescriptor, DescriptorError> {
        ComputerPlaneDescriptor::decode(bytes)
    }

    pub fn encoded_len(&self, descriptor: &ComputerPlaneDescriptor) -> u64 {
        // All three values are closed enum labels, so the exact JSON length can
        // be computed without allocating or serializing a descriptor.
        let capability = match descriptor.capability {
            ComputerCapability::Click => "click",
            ComputerCapability::Type => "type",
            ComputerCapability::Keys => "keys",
            ComputerCapability::Scroll => "scroll",
            ComputerCapability::Move => "move",
            ComputerCapability::Drag => "drag",
            ComputerCapability::Screenshot => "screenshot",
            ComputerCapability::Wait => "wait",
        };
        let containment = match descriptor.containment_rung {
            ContainmentRung::SemanticElement => "semantic_element",
            ContainmentRung::PidStructural => "pid_structural",
            ContainmentRung::GlobalNone => "global_none",
        };
        let observation = match descriptor.observation {
            ObservationState::HumanObserved => "human_observed",
            ObservationState::HumanUnobserved => "human_unobserved",
        };
        (r#"{"capability":"","containment_rung":"","observation":""}"#.len()
            + capability.len()
            + containment.len()
            + observation.len()) as u64
    }

    pub const fn codec_id(&self) -> &'static str {
        Self::CODEC_ID
    }
}

/// A deterministic JSON codec for the opaque material stored by core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerJournalCodec {
    pub codec_version: String,
}

impl Default for ComputerJournalCodec {
    fn default() -> Self {
        Self {
            codec_version: "ck-computer-journal/v1".to_string(),
        }
    }
}

impl ComputerJournalCodec {
    pub fn new(codec_version: impl Into<String>) -> Result<Self, JournalCodecError> {
        let codec_version = codec_version.into();
        if codec_version.trim().is_empty() {
            return Err(JournalCodecError::VersionUnavailable);
        }
        Ok(Self { codec_version })
    }

    fn encoded(&self, value: Value) -> Result<EncodedJournalState, JournalCodecError> {
        let durable_bytes = serde_json::to_vec(&value).map_err(|_| JournalCodecError::Failed)?;
        if durable_bytes.is_empty() {
            return Err(JournalCodecError::Failed);
        }
        Ok(EncodedJournalState {
            accounted_serialized_size: durable_bytes.len() as u64,
            durable_bytes,
            codec_version: self.codec_version.clone(),
        })
    }

    fn identity(value: &JournalIdentity) -> Value {
        json!({
            "agent_project_id": value.agent_project_id,
            "conversation_key": value.conversation_key,
            "principal": value.principal,
            "session_kind": value.session_kind,
        })
    }

    fn severity(value: Option<SeverityInputs>) -> Value {
        value.map_or(Value::Null, |inputs| json!(inputs))
    }

    pub fn decode_entry(bytes: &[u8]) -> Result<Value, DescriptorError> {
        serde_json::from_slice(bytes).map_err(|_| DescriptorError::Refused)
    }
}

impl PlaneJournalCodec for ComputerJournalCodec {
    fn encode_provisional(
        &self,
        input: &ProvisionalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        self.encoded(json!({
            "codec_version": self.codec_version,
            "identity": Self::identity(&input.identity),
            "invocation_descriptor": input.invocation_descriptor,
            "phase": "provisional",
            "sequence": input.action_obligation_id,
        }))
    }

    fn encode_dispatched(
        &self,
        input: &DispatchedInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        self.encoded(json!({
            "codec_version": self.codec_version,
            "dispatch_material": input.dispatch_material,
            "governing_observation": input.governing_observation,
            "grant_decision": input.grant_decision,
            "identity": Self::identity(&input.identity),
            "invocation_descriptor": input.invocation_descriptor,
            "phase": "dispatched",
            "sequence": input.action_obligation_id,
            "severity_inputs": Self::severity(input.severity_inputs),
        }))
    }

    fn encode_rejection(
        &self,
        input: &RejectionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        self.encoded(json!({
            "codec_version": self.codec_version,
            "identity": Self::identity(&input.identity),
            "invocation_descriptor": input.invocation_descriptor,
            "phase": "rejected",
            "rejection_material": input.rejection_material,
            "sequence": input.action_obligation_id,
        }))
    }

    fn encode_completion(
        &self,
        input: &CompletionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        self.encoded(json!({
            "attachments": input.attachments,
            "codec_version": self.codec_version,
            "completed_result": input.completed_result,
            "dispatch_material": input.dispatch_material,
            "final_context": input.final_context,
            "identity": Self::identity(&input.identity),
            "phase": "finalized",
            "sequence": input.action_obligation_id,
            "severity_inputs": Self::severity(input.severity_inputs),
        }))
    }

    fn encode_reduced_terminal(
        &self,
        input: &ReducedTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        self.encoded(json!({
            "codec_version": self.codec_version,
            "identity": Self::identity(&input.identity),
            "phase": "reduced_terminal",
            "reason": input.reason.as_str(),
            "sequence": input.action_obligation_id,
            "severity_inputs": Self::severity(input.severity_inputs),
        }))
    }

    fn encode_recovery_terminal(
        &self,
        input: &RecoveryTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        self.encoded(json!({
            "attachments": input.attachments,
            "classification": recovery_classification_name(input.classification),
            "codec_version": self.codec_version,
            "dispatch_material": input.dispatch_material,
            "identity": Self::identity(&input.identity),
            "invocation_descriptor": input.invocation_descriptor,
            "phase": "recovery_terminal",
            "sequence": input.action_obligation_id,
            "severity_inputs": Self::severity(input.severity_inputs),
        }))
    }
}

fn recovery_classification_name(value: RecoveryClassification) -> &'static str {
    match value {
        RecoveryClassification::UnmarkedOrphan => "unmarked_orphan",
        RecoveryClassification::FailedRejection => "failed_rejection",
        RecoveryClassification::FailedCommitment => "failed_commitment",
        RecoveryClassification::ProvisionalDispatched => "provisional_dispatched",
    }
}

/// Exact computer terminal names exposed by the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerTerminalKind {
    FinalizedCommitted,
    RejectedCommitted,
    RecoveryDispatchFinalized,
    RecoveryRejectionCommitted,
    RecoveryCancelled,
}

impl From<TerminalKind> for ComputerTerminalKind {
    fn from(value: TerminalKind) -> Self {
        match value {
            TerminalKind::FinalizedCommitted => Self::FinalizedCommitted,
            TerminalKind::RejectedCommitted => Self::RejectedCommitted,
            TerminalKind::RecoveryDispatchFinalized => Self::RecoveryDispatchFinalized,
            TerminalKind::RecoveryRejectionCommitted => Self::RecoveryRejectionCommitted,
            TerminalKind::RecoveryCancelled => Self::RecoveryCancelled,
        }
    }
}

impl ComputerTerminalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FinalizedCommitted => "finalized_committed",
            Self::RejectedCommitted => "rejected_committed",
            Self::RecoveryDispatchFinalized => "recovery_dispatch_finalized",
            Self::RecoveryRejectionCommitted => "recovery_rejection_committed",
            Self::RecoveryCancelled => "recovery_cancelled",
        }
    }
}

/// The complete consent-gated background failure taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundFailureCause {
    SemanticTargetUnavailable,
    PidScopeUnavailable,
    FrontingConsentRequired,
    GlobalInputConsentRequired,
}

/// The role is part of the descriptor and is used to reconstruct pairs without
/// assuming that two journal sequences were adjacent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptRole {
    Background,
    Reauthorized,
}

/// Consent provenance is closed and its digest is derived from the six
/// preceding fields, not accepted as caller-authored free text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentProvenance {
    pub grant_id: String,
    pub authority_id: String,
    pub decision_id: String,
    pub authorized_scope: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub provenance_sha256: String,
}

impl ConsentProvenance {
    pub fn new(
        grant_id: impl Into<String>,
        authority_id: impl Into<String>,
        decision_id: impl Into<String>,
        authorized_scope: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, EscalationError> {
        let value = Self {
            grant_id: grant_id.into(),
            authority_id: authority_id.into(),
            decision_id: decision_id.into(),
            authorized_scope: authorized_scope.into(),
            issued_at,
            expires_at,
            provenance_sha256: String::new(),
        };
        value.validate_fields()?;
        let provenance_sha256 = value.computed_digest();
        Ok(Self {
            provenance_sha256,
            ..value
        })
    }

    fn validate_fields(&self) -> Result<(), EscalationError> {
        if self.grant_id.is_empty()
            || self.authority_id.is_empty()
            || self.decision_id.is_empty()
            || self.authorized_scope.is_empty()
            || self.expires_at <= self.issued_at
        {
            return Err(EscalationError::InvalidProvenance);
        }
        Ok(())
    }

    fn canonical_preimage(&self) -> Vec<u8> {
        // The field order is the RFC 8785 canonical object order used by the
        // release contract; serde_json emits these primitive values exactly.
        serde_json::to_vec(&json!({
            "authorized_scope": self.authorized_scope,
            "authority_id": self.authority_id,
            "decision_id": self.decision_id,
            "expires_at": self.expires_at,
            "grant_id": self.grant_id,
            "issued_at": self.issued_at,
        }))
        .expect("provenance fields are serializable")
    }

    pub fn computed_digest(&self) -> String {
        hex_digest(&Sha256::digest(self.canonical_preimage()))
    }

    pub fn verify(&self) -> Result<(), EscalationError> {
        self.validate_fields()?;
        if self.provenance_sha256 != self.computed_digest() {
            return Err(EscalationError::InvalidProvenance);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundEscalationDescriptor {
    pub escalation_id: String,
    pub attempt_role: AttemptRole,
    pub achieved_containment_rung: ContainmentRung,
    pub background_failure_cause: BackgroundFailureCause,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthorizedEscalationDescriptor {
    pub escalation_id: String,
    pub attempt_role: AttemptRole,
    pub consent_provenance: ConsentProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EscalationDescriptor {
    Background(BackgroundEscalationDescriptor),
    Reauthorized(ReauthorizedEscalationDescriptor),
}

impl EscalationDescriptor {
    pub fn escalation_id(&self) -> &str {
        match self {
            Self::Background(value) => &value.escalation_id,
            Self::Reauthorized(value) => &value.escalation_id,
        }
    }

    pub fn attempt_role(&self) -> AttemptRole {
        match self {
            Self::Background(value) => value.attempt_role,
            Self::Reauthorized(value) => value.attempt_role,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, EscalationError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| EscalationError::InvalidDescriptor)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EscalationError> {
        let descriptor: Self =
            serde_json::from_slice(bytes).map_err(|_| EscalationError::InvalidDescriptor)?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn validate(&self) -> Result<(), EscalationError> {
        if self.escalation_id().is_empty() {
            return Err(EscalationError::InvalidDescriptor);
        }
        match self {
            Self::Background(value) if value.attempt_role != AttemptRole::Background => {
                Err(EscalationError::InvalidDescriptor)
            }
            Self::Reauthorized(value) => {
                if value.attempt_role != AttemptRole::Reauthorized {
                    return Err(EscalationError::InvalidDescriptor);
                }
                value.consent_provenance.verify()
            }
            Self::Background(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationError {
    InvalidDescriptor,
    InvalidProvenance,
    MismatchedPair,
}

/// A typed pair view.  Pair reconstruction is by id and role, never sequence
/// adjacency, so unrelated actions cannot accidentally form an escalation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationPair {
    pub background: BackgroundEscalationDescriptor,
    pub reauthorized: Option<ReauthorizedEscalationDescriptor>,
}

impl EscalationPair {
    pub fn refused(background: BackgroundEscalationDescriptor) -> Result<Self, EscalationError> {
        let pair = Self {
            background,
            reauthorized: None,
        };
        pair.validate()?;
        Ok(pair)
    }

    pub fn consented(
        background: BackgroundEscalationDescriptor,
        reauthorized: ReauthorizedEscalationDescriptor,
    ) -> Result<Self, EscalationError> {
        let pair = Self {
            background,
            reauthorized: Some(reauthorized),
        };
        pair.validate()?;
        Ok(pair)
    }

    pub fn validate(&self) -> Result<(), EscalationError> {
        let background = EscalationDescriptor::Background(self.background.clone());
        background.validate()?;
        if let Some(reauthorized) = &self.reauthorized {
            let successor = EscalationDescriptor::Reauthorized(reauthorized.clone());
            successor.validate()?;
            if self.background.escalation_id != reauthorized.escalation_id {
                return Err(EscalationError::MismatchedPair);
            }
        }
        Ok(())
    }
}

/// Typed dispatch material prevents callers from bypassing the adapter mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCaptureDispatch {
    pub capability: ComputerCapability,
    pub containment_rung: ContainmentRung,
    pub observation: ObservationState,
    pub descriptor: ComputerPlaneDescriptor,
}

impl TypedCaptureDispatch {
    pub fn new(
        capability: ComputerCapability,
        containment_rung: ContainmentRung,
        observation: ObservationState,
    ) -> Self {
        Self {
            capability,
            containment_rung,
            observation,
            descriptor: ComputerPlaneDescriptor::new(capability, containment_rung, observation),
        }
    }

    pub fn severity_inputs(&self) -> SeverityInputs {
        self.descriptor.severity_inputs()
    }

    pub fn dispatch_material(&self, bytes: Vec<u8>) -> TypedDispatchMaterial {
        TypedDispatchMaterial {
            bytes,
            severity_inputs: self.severity_inputs(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedDispatchMaterial {
    pub bytes: Vec<u8>,
    pub severity_inputs: SeverityInputs,
}

/// Adapter-owned gate used when building capability advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCapabilityGate {
    pub journal_available: bool,
    pub severity_available: bool,
    pub custody_available: bool,
    pub clock_available: bool,
    pub grant_authority_available: bool,
    pub redactor_available: bool,
}

impl AuditCapabilityGate {
    pub const fn ready(self) -> bool {
        self.journal_available
            && self.severity_available
            && self.custody_available
            && self.clock_available
            && self.grant_authority_available
            && self.redactor_available
    }

    pub const fn advertised(self, capability: ComputerCapability) -> bool {
        match capability {
            // Wait has no capture or redaction obligation, but it still needs a
            // durable journal obligation under the C2 fail-closed rule.
            ComputerCapability::Wait => self.journal_available && self.severity_available,
            ComputerCapability::Screenshot => self.ready(),
            ComputerCapability::Click
            | ComputerCapability::Type
            | ComputerCapability::Keys
            | ComputerCapability::Scroll
            | ComputerCapability::Move
            | ComputerCapability::Drag => self.journal_available && self.severity_available,
        }
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::capture_custody::{CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority};
    use cerebellum_core::journal::{
        InMemoryJournalStorage, JournalConfig, UnavailablePolicy, ValidatedSeverityTaxonomy,
    };

    fn taxonomy() -> ValidatedSeverityTaxonomy {
        crate::platform::severity::load_severity_taxonomy().expect("the pinned table loads")
    }

    fn custody() -> CaptureCustody {
        CaptureCustody::new(
            CustodyBounds {
                maximum_verification_duration_ms: 100,
                maximum_pin_lifetime_ms: 50,
                maximum_concurrently_pinned_artifacts: 4,
                maximum_total_pinned_artifact_bytes: 10_000,
                maximum_custody_attachment_bytes: 2_000,
            },
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
        .expect("custody constructs")
    }

    fn audit_with<R: Redactor>(
        redactor: R,
    ) -> ComputerAudit<R, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
        ComputerAudit::new(
            redactor,
            taxonomy(),
            JournalConfig {
                journal_retention_bytes: 200_000,
                journal_max_entry_bytes: 40_000,
            },
            InMemoryJournalStorage::new(),
            custody(),
        )
        .expect("the audit constructs")
    }

    /// Without a redaction policy, capture is withheld and waiting is not.
    ///
    /// The two capabilities depend on different things, and reporting one answer
    /// for both would either withhold a capability that works or offer one whose
    /// obligations cannot be met. Waiting records a duration; capturing produces
    /// material that has to be redactable before it is retained.
    #[test]
    fn a_missing_redaction_policy_withholds_capture_but_not_waiting() {
        let audit = audit_with(UnavailablePolicy);
        let gate = audit.capability_gate();

        assert!(!gate.redactor_available);
        assert!(
            !gate.advertised(ComputerCapability::Screenshot),
            "capture was offered with no redaction policy bound"
        );
        assert!(
            gate.advertised(ComputerCapability::Wait),
            "waiting was withheld for a policy it does not need"
        );
    }

    /// The gate reports what the audit holds rather than what a caller says.
    ///
    /// Every field is read from a part the audit owns. A caller supplying them
    /// would be restating what the audit already knows, and the restatement can
    /// drift from it while both continue to look correct.
    #[test]
    fn the_gate_is_read_from_the_parts_the_audit_holds() {
        let audit = audit_with(UnavailablePolicy);
        let gate = audit.capability_gate();

        assert!(gate.journal_available);
        assert!(gate.severity_available, "a severity table is bound");
        assert!(gate.custody_available);
        assert!(gate.clock_available);
        assert!(gate.grant_authority_available);
    }

    /// A journal with no severity table withholds every capability.
    ///
    /// Severity is what a decision plane reads to judge an action. Offering a
    /// capability whose actions cannot be scored promises a judgement nobody can
    /// make, so this is the one condition that withholds even waiting.
    #[test]
    fn no_severity_table_withholds_everything() {
        let audit = ComputerAudit::new(
            UnavailablePolicy,
            UnavailablePolicy,
            JournalConfig {
                journal_retention_bytes: 200_000,
                journal_max_entry_bytes: 40_000,
            },
            InMemoryJournalStorage::new(),
            custody(),
        )
        .expect("the audit constructs");

        let gate = audit.capability_gate();
        for capability in ComputerCapability::ALL {
            assert!(
                !gate.advertised(capability),
                "{} was offered with no severity table",
                capability.capability_id()
            );
        }
    }

    /// Custody losing its storage withholds capture and leaves waiting alone.
    #[test]
    fn unavailable_custody_withholds_capture_only() {
        let mut audit = audit_with(UnavailablePolicy);
        audit.custody_mut().set_available(false);

        let gate = audit.capability_gate();
        assert!(!gate.custody_available);
        assert!(!gate.advertised(ComputerCapability::Screenshot));
        assert!(gate.advertised(ComputerCapability::Wait));
    }
}

/// Neutral recovery mapping is exhaustive and does not silently default.
pub const fn recovery_surface(
    classification: RecoveryClassification,
) -> (RecoveryAction, ComputerTerminalKind) {
    match classification {
        RecoveryClassification::UnmarkedOrphan | RecoveryClassification::FailedCommitment => (
            RecoveryAction::Cancelled,
            ComputerTerminalKind::RecoveryCancelled,
        ),
        RecoveryClassification::FailedRejection => (
            RecoveryAction::RejectionCommitted,
            ComputerTerminalKind::RecoveryRejectionCommitted,
        ),
        RecoveryClassification::ProvisionalDispatched => (
            RecoveryAction::DispatchFinalized,
            ComputerTerminalKind::RecoveryDispatchFinalized,
        ),
    }
}

/// A small typed record useful to consumers that need to retain the core id
/// alongside the plane descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerAuditRecord {
    pub action_obligation_id: ActionObligationId,
    pub descriptor: ComputerPlaneDescriptor,
    pub severity: Option<SeverityRecord>,
    pub terminal_kind: Option<ComputerTerminalKind>,
}

/// A helper for constructing the neutral identity without allowing the plane to
/// invent an additional identity field.
pub fn journal_identity(
    principal: impl Into<String>,
    conversation_key: impl Into<String>,
    agent_project_id: impl Into<String>,
    session_kind: SessionKind,
) -> JournalIdentity {
    JournalIdentity {
        principal: principal.into(),
        conversation_key: conversation_key.into(),
        agent_project_id: agent_project_id.into(),
        session_kind,
    }
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("descriptor_refused")
    }
}

impl std::error::Error for DescriptorError {}

/// Canonical capability map used by conformance tests and release tooling.
pub fn capability_map() -> BTreeMap<&'static str, ActionKind> {
    ComputerCapability::ALL
        .into_iter()
        .map(|capability| (capability.capability_id(), capability.action_kind()))
        .collect()
}

// Short aliases keep the vocabulary readable at call sites without creating a
// second type or a second mapping table.
pub use action_effect_class as map_action_kind_to_effect_class;
pub use capability_effect_class as map_capability_to_effect_class;
pub use containment_isolation_class as map_containment_to_isolation_class;

use crate::capture_custody::{
    CaptureCustody, CapturePinRefusalCause, CapturePrepareRefusalCause, CaptureRefusedCause,
    CaptureScope, CustodyError, PixelArtifact, CAPTURE_ATTACHMENT_SLOT,
};
use cerebellum_core::journal::redaction::Redactor;
use cerebellum_core::journal::severity::SeverityTaxonomy;
use cerebellum_core::journal::storage::JournalStorage;
use cerebellum_core::journal::{
    BindingError, Committed, CompletedResult, DispatchCommitmentToken, DispatchMaterial,
    FinalContextAssociation, JournalConfig, JournalError, RejectionMaterial, ReservationHandle,
};

/// Errors raised while opening or driving the typed computer journal binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputerAuditError {
    BindingUnavailable,
    Journal(JournalError),
    Custody(CustodyError),
}

impl From<JournalError> for ComputerAuditError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<CustodyError> for ComputerAuditError {
    fn from(value: CustodyError) -> Self {
        Self::Custody(value)
    }
}

/// The computer adapter binds the neutral lifecycle and custody protocol. The
/// storage types remain generic so production bindings can replace both
/// in-memory stores without changing the typed surface.
pub struct ComputerAudit<R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    journal: cerebellum_core::journal::JournalBinding<ComputerJournalCodec, R, T, S>,
    custody: CaptureCustody,
    reservations: BTreeMap<ActionObligationId, ReservationMetadata>,
}

#[derive(Debug, Clone)]
struct ReservationMetadata {
    handle: ReservationHandle,
    identity: JournalIdentity,
    active: bool,
}

impl<R, T, S> ComputerAudit<R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    pub fn new(
        redactor: R,
        severity_taxonomy: T,
        config: JournalConfig,
        journal_storage: S,
        custody: CaptureCustody,
    ) -> Result<Self, BindingError> {
        let journal = cerebellum_core::journal::JournalBinding::new(
            ComputerJournalCodec::default(),
            Some(redactor),
            Some(severity_taxonomy),
            config,
            journal_storage,
        )?;
        Ok(Self {
            journal,
            custody,
            reservations: BTreeMap::new(),
        })
    }

    pub fn journal(
        &self,
    ) -> &cerebellum_core::journal::JournalBinding<ComputerJournalCodec, R, T, S> {
        &self.journal
    }

    pub fn journal_mut(
        &mut self,
    ) -> &mut cerebellum_core::journal::JournalBinding<ComputerJournalCodec, R, T, S> {
        &mut self.journal
    }

    /// What this audit can support, read from the parts it holds.
    ///
    /// Derived rather than supplied, because a caller that fills these in is
    /// stating a second time what the audit already knows, and the two can
    /// disagree while both look correct: the gate would then advertise a
    /// capability whose journal cannot record it, or withhold one that works.
    ///
    /// The grant authority travels with custody rather than being separately
    /// optional, so its availability is custody's.
    pub fn capability_gate(&self) -> AuditCapabilityGate {
        AuditCapabilityGate {
            journal_available: true,
            // Asked by RESOLVING rather than by checking that something is
            // bound. A policy that reports itself unavailable still answers the
            // question "is a taxonomy present" with a version string, so
            // presence would read as availability for a table that scores
            // nothing. The tables are total by construction, so any input is a
            // sufficient probe.
            severity_available: self
                .journal
                .resolve_severity(SeverityInputs {
                    effect_class: EffectClass::Read,
                    isolation_class: IsolationClass::ResourceScoped,
                    observability_class: ObservabilityClass::HumanUnobserved,
                })
                .is_some(),
            custody_available: self.custody.is_available(),
            clock_available: self.custody.clock_is_available(),
            grant_authority_available: self.custody.is_available(),
            redactor_available: self.journal.redactor_available(),
        }
    }

    pub fn custody(&self) -> &CaptureCustody {
        &self.custody
    }

    pub fn custody_mut(&mut self) -> &mut CaptureCustody {
        &mut self.custody
    }

    pub fn reserve(
        &mut self,
        identity: JournalIdentity,
        descriptor: ComputerPlaneDescriptor,
    ) -> Result<ReservationHandle, ComputerAuditError> {
        let bytes = descriptor
            .encode()
            .map_err(|_| ComputerAuditError::Journal(JournalError::CodecFailed))?;
        let handle = self.journal.reserve(identity.clone(), bytes)?;
        self.reservations.insert(
            handle.action_obligation_id(),
            ReservationMetadata {
                handle,
                identity,
                active: true,
            },
        );
        Ok(handle)
    }

    pub fn commit_dispatched(
        &mut self,
        handle: ReservationHandle,
        dispatch: &TypedDispatchMaterial,
        grant_decision: Vec<u8>,
        governing_observation: Option<Vec<u8>>,
    ) -> Result<DispatchCommitmentToken, ComputerAuditError> {
        Ok(self.journal.commit_dispatched(
            handle,
            DispatchMaterial {
                dispatch_material: dispatch.bytes.clone(),
                severity_inputs: Some(dispatch.severity_inputs),
                grant_decision,
                governing_observation,
            },
        )?)
    }

    pub fn finalize_dispatched(
        &mut self,
        token: DispatchCommitmentToken,
        completed_result: Vec<u8>,
        final_context: Vec<u8>,
    ) -> Result<Committed, ComputerAuditError> {
        let result = self.journal.finalize_dispatched(
            token,
            CompletedResult { completed_result },
            FinalContextAssociation { final_context },
        )?;
        if let Some(record) = self.reservations.get_mut(&token.action_obligation_id()) {
            record.active = false;
        }
        self.consume_terminal_transitions();
        Ok(result)
    }

    pub fn finalize_rejected(
        &mut self,
        handle: ReservationHandle,
        rejection_material: Vec<u8>,
    ) -> Result<Committed, ComputerAuditError> {
        let result = self
            .journal
            .finalize_rejected(handle, RejectionMaterial { rejection_material })?;
        if let Some(record) = self.reservations.get_mut(&handle.action_obligation_id()) {
            record.active = false;
        }
        self.consume_terminal_transitions();
        Ok(result)
    }

    pub fn finalize_redacted_failure(
        &mut self,
        handle: ReservationHandle,
    ) -> Result<Committed, ComputerAuditError> {
        let result = self.journal.finalize_reduced(
            handle,
            cerebellum_core::journal::JournalReason::RedactionUnavailable,
        )?;
        if let Some(record) = self.reservations.get_mut(&handle.action_obligation_id()) {
            record.active = false;
        }
        self.consume_terminal_transitions();
        Ok(result)
    }

    /// Establish a reservation-bound preparation token. The handle is the only
    /// caller input that identifies the obligation; custody never accepts a
    /// separately supplied obligation id from the capture backend.
    pub fn prepare_capture(
        &mut self,
        handle: ReservationHandle,
        scope: CaptureScope,
        grant_id: Option<String>,
        now: u64,
    ) -> Result<
        crate::capture_custody::CaptureAdmissionToken,
        crate::capture_custody::CapturePrepareRefused,
    > {
        let Some(record) = self.reservations.get(&handle.action_obligation_id()) else {
            return Err(crate::capture_custody::CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::ObligationNotDurable,
            });
        };
        let durable = self
            .journal
            .read_obligation_audit(handle.action_obligation_id())
            .is_ok();
        self.custody.prepare_capture(
            handle.action_obligation_id(),
            &record.identity,
            durable,
            record.active,
            scope,
            grant_id,
            now,
        )
    }

    /// The pending artifact is not returned until its attachment is committed.
    /// If the journal CAS fails, the staged artifact is logically destroyed and
    /// only a retryable deletion record remains.
    pub fn admit_capture(
        &mut self,
        token: crate::capture_custody::CaptureAdmissionToken,
        artifact: PixelArtifact,
        now: u64,
    ) -> Result<String, crate::capture_custody::CaptureRefused> {
        let Some(metadata) = self
            .reservations
            .get(&token.action_obligation_id())
            .cloned()
        else {
            return Err(crate::capture_custody::CaptureRefused {
                cause: CaptureRefusedCause::ObligationNotActive,
            });
        };
        self.admit_capture_for_handle(metadata.handle, token, artifact, now)
    }

    pub fn admit_capture_for_handle(
        &mut self,
        handle: ReservationHandle,
        token: crate::capture_custody::CaptureAdmissionToken,
        artifact: PixelArtifact,
        now: u64,
    ) -> Result<String, crate::capture_custody::CaptureRefused> {
        let Some(record) = self
            .reservations
            .get(&handle.action_obligation_id())
            .cloned()
        else {
            return Err(crate::capture_custody::CaptureRefused {
                cause: CaptureRefusedCause::ObligationNotActive,
            });
        };
        let staged =
            self.custody
                .stage_admission(token, &record.identity, record.active, artifact, now)?;
        let attachment =
            match CaptureCustody::attachment_bytes(&staged.artifact_id, &staged.descriptor, None) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let _ = self.custody.abort_admission(&staged);
                    return Err(crate::capture_custody::CaptureRefused {
                        cause: CaptureRefusedCause::JournalAttachmentFailed,
                    });
                }
            };
        if !self.custody.attachment_within_bound(&attachment) {
            let _ = self.custody.abort_admission(&staged);
            return Err(crate::capture_custody::CaptureRefused {
                cause: CaptureRefusedCause::JournalAttachmentFailed,
            });
        }
        let revision = match self.journal.attach_obligation_material(
            handle,
            CAPTURE_ATTACHMENT_SLOT,
            0,
            attachment,
        ) {
            Ok(revision) => revision,
            Err(_) => {
                let _ = self.custody.abort_admission(&staged);
                return Err(crate::capture_custody::CaptureRefused {
                    cause: CaptureRefusedCause::JournalAttachmentFailed,
                });
            }
        };
        self.custody
            .commit_admission(&staged, revision)
            .map_err(|_| crate::capture_custody::CaptureRefused {
                cause: CaptureRefusedCause::CustodyUnavailable,
            })
    }

    pub fn pin_capture(
        &mut self,
        artifact_id: &str,
        grant_id: Option<String>,
        expires_at: u64,
        now: u64,
    ) -> Result<String, crate::capture_custody::CapturePinRefused> {
        let Some(obligation_id) = self.custody.artifact_obligation_id(artifact_id) else {
            return Err(crate::capture_custody::CapturePinRefused {
                cause: CapturePinRefusalCause::ArtifactUnavailable,
            });
        };
        let Some(metadata) = self.reservations.get(&obligation_id).cloned() else {
            return Err(crate::capture_custody::CapturePinRefused {
                cause: CapturePinRefusalCause::ArtifactUnavailable,
            });
        };
        self.pin_capture_for_handle(metadata.handle, artifact_id, grant_id, expires_at, now)
    }

    pub fn pin_capture_for_handle(
        &mut self,
        handle: ReservationHandle,
        artifact_id: &str,
        grant_id: Option<String>,
        expires_at: u64,
        now: u64,
    ) -> Result<String, crate::capture_custody::CapturePinRefused> {
        let pending = self
            .custody
            .prepare_pin(artifact_id, grant_id, expires_at, now)?;
        let Some(descriptor) = self.custody.capture_descriptor(artifact_id) else {
            let _ = self.custody.abort_pin(&pending);
            return Err(crate::capture_custody::CapturePinRefused {
                cause: CapturePinRefusalCause::ArtifactUnavailable,
            });
        };
        let attachment = match CaptureCustody::attachment_bytes(
            artifact_id,
            &descriptor,
            Some(&pending.retention_pin_id),
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = self.custody.abort_pin(&pending);
                return Err(crate::capture_custody::CapturePinRefused {
                    cause: CapturePinRefusalCause::JournalAttachmentFailed,
                });
            }
        };
        if !self.custody.attachment_within_bound(&attachment) {
            let _ = self.custody.abort_pin(&pending);
            return Err(crate::capture_custody::CapturePinRefused {
                cause: CapturePinRefusalCause::JournalAttachmentFailed,
            });
        }
        let revision = match self.journal.attach_obligation_material(
            handle,
            CAPTURE_ATTACHMENT_SLOT,
            1,
            attachment,
        ) {
            Ok(revision) => revision,
            Err(_) => {
                let _ = self.custody.abort_pin(&pending);
                return Err(crate::capture_custody::CapturePinRefused {
                    cause: CapturePinRefusalCause::JournalAttachmentFailed,
                });
            }
        };
        self.custody.commit_pin(&pending, revision).map_err(|_| {
            crate::capture_custody::CapturePinRefused {
                cause: CapturePinRefusalCause::CustodyUnavailable,
            }
        })
    }

    pub fn release_capture(
        &mut self,
        pin_id: &str,
    ) -> crate::capture_custody::CaptureReleaseResult {
        self.custody.release_capture(pin_id)
    }

    pub fn sweep_expired_captures(
        &mut self,
        now: u64,
    ) -> crate::capture_custody::CustodySweepResult {
        self.custody.sweep_expired_captures(now)
    }

    pub fn read_obligation_audit(
        &self,
        action_obligation_id: ActionObligationId,
    ) -> Result<cerebellum_core::journal::ObligationAuditRecord, JournalError> {
        self.journal.read_obligation_audit(action_obligation_id)
    }

    pub fn recover_active(&mut self) -> Vec<cerebellum_core::journal::CoreRecoveryOutcome> {
        let outcomes = self.journal.recover_active();
        self.consume_terminal_transitions();
        outcomes
    }

    pub fn terminal_transitions(
        &self,
        after_cursor: u64,
    ) -> Result<Vec<cerebellum_core::journal::TerminalTransition>, JournalError> {
        self.journal.terminal_transitions(after_cursor)
    }

    pub fn consume_terminal_transitions(&mut self) -> usize {
        let cursor = self.custody.terminal_cursor();
        let Ok(transitions) = self.journal.terminal_transitions(cursor) else {
            return 0;
        };
        let mut consumed = 0;
        for transition in transitions {
            self.custody.apply_terminal_transition(
                transition.cursor,
                transition.action_obligation_id,
                transition.kind,
            );
            if let Some(record) = self.reservations.get_mut(&transition.action_obligation_id) {
                record.active = false;
            }
            consumed += 1;
        }
        consumed
    }

    /// Restore pending custody and terminal-feed state before exposing reads.
    pub fn startup_reconcile(&mut self, now: u64) -> Result<(), ComputerAuditError> {
        self.custody.begin_process_epoch();
        let ids = self.custody.obligation_ids();
        let mut attachments = Vec::new();
        for id in ids {
            if let Ok(record) = self.journal.read_obligation_audit(id) {
                attachments.extend(record.attachment_slots);
            }
        }
        self.custody.reconcile_attachments(attachments)?;
        self.consume_terminal_transitions();
        self.custody.close_elapsed_windows(now);
        self.custody.sweep_expired_captures(now);
        Ok(())
    }

    pub fn journal_purge(&mut self) -> cerebellum_core::journal::PurgeReport {
        self.journal.purge()
    }
}

use crate::capture_custody::{
    redact_accessibility_snapshot, AccessibilityRedactionError, AccessibilityRedactionOutcome,
    AccessibilityRedactionPath, AccessibilitySchema, AccessibilitySnapshot,
};
use cerebellum_core::journal::RedactionUnavailable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessibilityDispatchError {
    Redaction(AccessibilityRedactionError),
    Journal(JournalError),
}

/// Route a structured accessibility capture through the one redactor bound to
/// this journal.  A non-selected success becomes a terminal rejection without
/// attaching snapshot bytes; a selected success returns only after its opaque
/// envelope is attached durably.  Any redaction failure records the reduced
/// `redaction_unavailable` terminal instead of silently dropping the attempt.
impl<R, T, S> ComputerAudit<R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    #[allow(clippy::too_many_arguments)]
    pub fn redact_accessibility(
        &mut self,
        handle: ReservationHandle,
        snapshot: AccessibilitySnapshot,
        schema: &AccessibilitySchema,
        redactor_id: impl Into<String>,
        max_field_bytes: usize,
        max_descriptor_bytes: usize,
        path: AccessibilityRedactionPath,
    ) -> Result<AccessibilityRedactionOutcome, AccessibilityDispatchError> {
        let bound = JournalBoundRedactor {
            journal: &self.journal,
        };
        let outcome = redact_accessibility_snapshot(
            snapshot,
            schema,
            &bound,
            redactor_id,
            max_field_bytes,
            max_descriptor_bytes,
            path,
        );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                self.journal
                    .finalize_reduced(
                        handle,
                        cerebellum_core::journal::JournalReason::RedactionUnavailable,
                    )
                    .map_err(AccessibilityDispatchError::Journal)?;
                self.consume_terminal_transitions();
                return Err(AccessibilityDispatchError::Redaction(error));
            }
        };
        match &outcome {
            AccessibilityRedactionOutcome::SuccessNotSelected => {
                self.journal
                    .finalize_rejected(
                        handle,
                        RejectionMaterial {
                            rejection_material: b"success_not_selected".to_vec(),
                        },
                    )
                    .map_err(AccessibilityDispatchError::Journal)?;
                self.consume_terminal_transitions();
            }
            AccessibilityRedactionOutcome::PendingSuccess {
                descriptor_bytes, ..
            } => {
                self.journal
                    .attach_obligation_material(
                        handle,
                        "computer.accessibility",
                        0,
                        descriptor_bytes.clone(),
                    )
                    .map_err(AccessibilityDispatchError::Journal)?;
            }
        }
        Ok(outcome)
    }
}

struct JournalBoundRedactor<'a, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    journal: &'a cerebellum_core::journal::JournalBinding<ComputerJournalCodec, R, T, S>,
}

impl<R, T, S> Redactor for JournalBoundRedactor<'_, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    fn available(&self) -> bool {
        self.journal.redactor_available()
    }

    fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable> {
        self.journal.redact(input, max_bytes)
    }
}
