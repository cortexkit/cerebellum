//! Computer-plane audit binding.
//!
//! This module owns the computer vocabulary which is deliberately kept outside
//! `cerebellum-core`.  Core receives only the deterministic bytes produced by
//! [`ComputerJournalCodec`], while this adapter is responsible for mapping the
//! closed computer action, containment, and observation domains to the neutral
//! severity inputs.

pub mod redaction;
mod token;

pub use token::{
    audit_reservation_cleanup_failures, lock_audit, ActuationAudit, AuditToken, SharedAudit,
};

use crate::dispatch::{AbortDecision, DispatchError};
use crate::grounding::ContainmentRung;
use crate::platform::{AccessibilityElementName, ActionKind, ProcessGrant};
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::codec::{
    CompletionInput, DispatchedInput, EncodedJournalState, JournalCodecError, PlaneJournalCodec,
    ProvisionalInput, RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
};
use cerebellum_core::journal::{
    ActionObligationId, EffectClass, IsolationClass, JournalIdentity, LifecycleState,
    ObservabilityClass, RecoveryClassification, SeverityInputs, SeverityRecord, TerminalKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// Every computer capability the journal can name.
///
/// Two groups. [`ComputerCapability::ALL`] is the set the frozen vocabulary
/// artifact carries now. [`ComputerCapability::RETIRED`] are capabilities an
/// earlier vocabulary served and the current one does not: they are never
/// parsed from a capability id and never dispatched, and they stay variants
/// only so the journal can still read them. A journal entry names its
/// capability by this enum's serialized name, and startup reconciliation
/// decodes every entry it settles, so removing a variant would make any
/// journal written while that capability was served unreadable, and the
/// module would refuse to start on that machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerCapability {
    ReadState,
    PressElement,
    PressPoint,
    WriteText,
    Type,
    Keys,
    TakeoverMove,
    TakeoverClick,
    TakeoverDrag,
    TakeoverScroll,
    Wait,
    ListApps,
    OpenApp,
    /// Retired; readable from the journal only.
    Click,
    /// Retired; readable from the journal only.
    Scroll,
    /// Retired; readable from the journal only.
    Move,
    /// Retired; readable from the journal only.
    Drag,
    /// Retired; readable from the journal only.
    Screenshot,
}

impl ComputerCapability {
    /// The capabilities the current vocabulary carries, in artifact order.
    pub const ALL: [Self; 13] = [
        Self::ReadState,
        Self::PressElement,
        Self::PressPoint,
        Self::WriteText,
        Self::Type,
        Self::Keys,
        Self::TakeoverMove,
        Self::TakeoverClick,
        Self::TakeoverDrag,
        Self::TakeoverScroll,
        Self::Wait,
        Self::ListApps,
        Self::OpenApp,
    ];

    /// Capabilities an earlier vocabulary served, kept only so journal
    /// entries that name them still decode.
    pub const RETIRED: [Self; 5] = [
        Self::Click,
        Self::Scroll,
        Self::Move,
        Self::Drag,
        Self::Screenshot,
    ];

    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::ReadState => "computer.read_state",
            Self::PressElement => "computer.press_element",
            Self::PressPoint => "computer.press_point",
            Self::WriteText => "computer.write_text",
            Self::Type => "computer.type",
            Self::Keys => "computer.keys",
            Self::TakeoverMove => "computer.takeover_move",
            Self::TakeoverClick => "computer.takeover_click",
            Self::TakeoverDrag => "computer.takeover_drag",
            Self::TakeoverScroll => "computer.takeover_scroll",
            Self::Wait => "computer.wait",
            Self::ListApps => "computer.list_apps",
            Self::OpenApp => "computer.open_app",
            Self::Click => "computer.click",
            Self::Scroll => "computer.scroll",
            Self::Move => "computer.move",
            Self::Drag => "computer.drag",
            Self::Screenshot => "computer.screenshot",
        }
    }

    pub const fn is_retired(self) -> bool {
        matches!(
            self,
            Self::Click | Self::Scroll | Self::Move | Self::Drag | Self::Screenshot
        )
    }

    /// The consent lease kind an action of this capability is admitted under,
    /// and the effect class its journal entry is scored with.
    ///
    /// The rows added with the accessibility-first actions take the kind of
    /// the row they replace: reading is an observation like the screenshot it
    /// replaces, pressing and writing compose like the click and typing they
    /// replace, and each pointer row keeps the kind of the pointer row it
    /// re-homes, so a drag stays the one durable-change pointer action.
    pub const fn action_kind(self) -> ActionKind {
        match self {
            Self::Drag | Self::TakeoverDrag => ActionKind::MutateDurable,
            Self::Screenshot | Self::Wait | Self::ReadState | Self::ListApps => ActionKind::Observe,
            Self::OpenApp
            | Self::Click
            | Self::Type
            | Self::Keys
            | Self::Scroll
            | Self::Move
            | Self::PressElement
            | Self::PressPoint
            | Self::WriteText
            | Self::TakeoverMove
            | Self::TakeoverClick
            | Self::TakeoverScroll => ActionKind::Compose,
        }
    }

    /// The capability a current capability id names.
    ///
    /// A retired id parses to nothing: it is not a capability anyone can ask
    /// for any more, only a name old journal entries carry.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.capability_id() == value)
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

    pub const fn codec_id(&self) -> &'static str {
        Self::CODEC_ID
    }
}

/// A deterministic JSON codec for the opaque material stored by core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerJournalCodec {
    pub codec_version: String,
}

/// The version of the computer journal's entries, as the codec writes it and
/// startup reconciliation reads it back.
///
/// Version 4 adds message indices and position/gap ordering to identities.
/// Entries without positioned ordering still use version 3 (which added
/// origin attribution). All earlier entry versions remain readable.
pub const COMPUTER_JOURNAL_CODEC_VERSION: &str = "ck-computer-journal/v4";
const ORIGIN_COMPUTER_JOURNAL_CODEC_VERSION: &str = "ck-computer-journal/v3";

/// The computer journal's entry format. Its floor is raised before entries are
/// written, and staging refuses a build whose readers stop short of it.
pub const COMPUTER_ENTRY_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new(
        "computer-journal-entry",
        cerebellum_core::format_floor::tag_version(COMPUTER_JOURNAL_CODEC_VERSION),
    );

impl Default for ComputerJournalCodec {
    fn default() -> Self {
        Self {
            codec_version: COMPUTER_JOURNAL_CODEC_VERSION.to_string(),
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

    fn encoded(&self, mut value: Value) -> Result<EncodedJournalState, JournalCodecError> {
        let mut codec_version = self.codec_version.clone();
        if self.writes_current_family() {
            codec_version = if value["identity"]["message_index"].is_u64() {
                COMPUTER_JOURNAL_CODEC_VERSION
            } else {
                ORIGIN_COMPUTER_JOURNAL_CODEC_VERSION
            }
            .to_string();
            value["codec_version"] = json!(codec_version);
            if let Some(status) = AccessibilityReadScope::current() {
                value["manual_accessibility"] = json!(status);
            }
        }
        let durable_bytes = serde_json::to_vec(&value).map_err(|_| JournalCodecError::Failed)?;
        if durable_bytes.is_empty() {
            return Err(JournalCodecError::Failed);
        }
        Ok(EncodedJournalState {
            accounted_serialized_size: durable_bytes.len() as u64,
            durable_bytes,
            codec_version,
        })
    }

    fn writes_current_family(&self) -> bool {
        matches!(
            self.codec_version.as_str(),
            COMPUTER_JOURNAL_CODEC_VERSION | ORIGIN_COMPUTER_JOURNAL_CODEC_VERSION
        )
    }

    fn identity(value: &JournalIdentity) -> Value {
        let mut identity = json!({
            "agent_project_id": value.agent_project_id,
            "conversation_key": value.conversation_key,
            "principal": value.principal,
            "session_kind": value.session_kind,
        });
        // Written only when the request named an origin, so an entry for a
        // call nobody relayed reads exactly as it did before the member existed.
        if !value.origin.is_absent() {
            identity["origin"] = json!(value.origin);
        }
        if let Some(order) = value
            .computer_order
            .and_then(cerebellum_core::journal::ComputerOrderRecord::positioned)
        {
            if let Some(index) = order.message_index {
                identity["message_index"] = json!(index);
            }
            identity["ordering"] = json!(order.ordering);
        }
        identity
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
        let mut entry = json!({
            "attachments": input.attachments,
            "codec_version": self.codec_version,
            "completed_result": input.completed_result,
            "dispatch_material": input.dispatch_material,
            "final_context": input.final_context,
            "identity": Self::identity(&input.identity),
            "phase": "finalized",
            "sequence": input.action_obligation_id,
            "severity_inputs": Self::severity(input.severity_inputs),
        });
        // Read summaries stay directly queryable without decoding opaque result
        // bytes. Copy only counts, Booleans and typed image facts, never tree text.
        if self.writes_current_family() {
            if let Ok(summary) = serde_json::from_slice::<Value>(&input.completed_result) {
                if summary["element_count"].is_u64()
                    && summary["unreadable_subtrees"].is_u64()
                    && summary["image_returned"].is_boolean()
                {
                    for key in ["element_count", "unreadable_subtrees", "image_returned"] {
                        entry[key] = summary[key].clone();
                    }
                    if let Ok(decision) = serde_json::from_value::<
                        crate::app_state::image::ImageDecision,
                    >(summary["image_decision"].clone())
                    {
                        entry["image_decision"] = json!(decision);
                    }
                    if let Ok(fronting) = serde_json::from_value::<
                        crate::app_state::image::ImageFronting,
                    >(summary["image_fronting"].clone())
                    {
                        entry["longest_fronted_interval_ms"] =
                            json!(fronting.longest_fronted_interval_ms);
                        entry["image_fronting"] = json!(fronting);
                    }
                }
            }
        }
        self.encoded(entry)
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
        let descriptor = ComputerPlaneDescriptor::decode(&input.invocation_descriptor)
            .map_err(|_| JournalCodecError::DescriptorRefused)?;
        let (_, terminal_kind) = recovery_surface(
            recovery_entry_class(descriptor.capability),
            input.classification,
        );
        self.encoded(json!({
            "attachments": input.attachments,
            "classification": recovery_classification_name(input.classification),
            "codec_version": self.codec_version,
            "dispatch_material": input.dispatch_material,
            "identity": Self::identity(&input.identity),
            "invocation_descriptor": input.invocation_descriptor,
            "phase": "recovery_terminal",
            "sequence": input.action_obligation_id,
            "settled": terminal_kind.is_settled(),
            "settler": "startup_reconciliation",
            "severity_inputs": Self::severity(input.severity_inputs),
            "terminal_kind": terminal_kind.as_str(),
        }))
    }

    /// Ordinary calls retain the origin-era format and its existing floor.
    /// Only a record actually encoded with ordering metadata raises version 4.
    /// Arbitrary fixture codecs are not formats a module reader decodes.
    fn entry_format(&self) -> Option<cerebellum_core::format_floor::DurableFormat> {
        self.writes_current_family()
            .then_some(cerebellum_core::format_floor::DurableFormat::new(
                COMPUTER_ENTRY_FORMAT.name,
                3,
            ))
    }

    fn entry_format_for(
        &self,
        codec_version: &str,
    ) -> Option<cerebellum_core::format_floor::DurableFormat> {
        if !self.writes_current_family() {
            return None;
        }
        let version = match codec_version {
            "ck-computer-journal/v1" => 1,
            "ck-computer-journal/v2" => 2,
            ORIGIN_COMPUTER_JOURNAL_CODEC_VERSION => 3,
            COMPUTER_JOURNAL_CODEC_VERSION => 4,
            _ => return None,
        };
        Some(cerebellum_core::format_floor::DurableFormat::new(
            COMPUTER_ENTRY_FORMAT.name,
            version,
        ))
    }
}

fn recovery_classification_name(value: RecoveryClassification) -> &'static str {
    match value {
        RecoveryClassification::UnmarkedOrphan => "unmarked_orphan",
        RecoveryClassification::FailedRejection => "failed_rejection",
        RecoveryClassification::FailedCommitment => "failed_commitment",
        RecoveryClassification::ProvisionalDispatched => "indeterminate",
    }
}

/// Exact computer terminal names exposed by the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerTerminalKind {
    FinalizedCommitted,
    RejectedCommitted,
    RecoveryDispatchFinalized,
    DispatchOutcomeUnknown,
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
            Self::DispatchOutcomeUnknown => "dispatch_outcome_unknown",
            Self::RecoveryRejectionCommitted => "recovery_rejection_committed",
            Self::RecoveryCancelled => "recovery_cancelled",
        }
    }

    /// Whether the terminal says the effect's outcome is known.
    pub const fn is_settled(self) -> bool {
        match self {
            Self::FinalizedCommitted
            | Self::RejectedCommitted
            | Self::RecoveryDispatchFinalized
            | Self::RecoveryRejectionCommitted
            | Self::RecoveryCancelled => true,
            Self::DispatchOutcomeUnknown => false,
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

/// The accessibility names known for the exact element an intent may actuate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActuationElementIdentity {
    pub matched_by: AccessibilityElementName,
    pub alternate_name: Option<AccessibilityElementName>,
}

/// Durable material written before an actuation can reach a platform driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActuationIntent {
    pub element: Option<ActuationElementIdentity>,
    pub action: String,
    pub grant_identity: ProcessGrant,
}

/// What is known after an actuation intent has been journaled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ActuationOutcome {
    /// The caller interrupted a live action. Unlike
    /// `ComputerRecoveryAction::Cancelled`, this is an observed action outcome,
    /// not a startup recovery lifecycle classification.
    Cancelled {
        posts_returned: u64,
        held_state: crate::platform::process_event::HeldStateDisposition,
    },
    HandlerReturned {
        /// Subtrees omitted from the accessibility tree used for the actuation.
        unreadable_subtrees: u64,
    },
    Refused {
        refusal: DispatchError,
        /// The whole stop decision, when the refusal came from an
        /// observed-mode abort.
        ///
        /// The refusal that reaches the caller keeps only the reason and which
        /// source seized, because that is all a caller can act on. The numbers
        /// an operator needs after the fact -- how long detection took, which
        /// action in the sequence stopped, how many queued posts were thrown
        /// away -- have nowhere else to live, so they live here.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abort: Option<AbortDecision>,
    },
    NoAction {
        refusal: DispatchError,
    },
}

fn add_route_defaults(bytes: Vec<u8>) -> Vec<u8> {
    let Ok(Value::Object(mut outcome)) = serde_json::from_slice::<Value>(&bytes) else {
        return bytes;
    };
    let Value::Object(defaults) =
        serde_json::to_value(crate::platform::input_route::InputRouteEvidence::default())
            .expect("route evidence is serializable")
    else {
        unreachable!()
    };
    for (name, value) in defaults {
        outcome.entry(name).or_insert(value);
    }
    serde_json::to_vec(&outcome).expect("JSON object is serializable")
}

/// Aggregate transport facts are flattened alongside the existing outcome.
/// Old entries have no route facts and decode with zero counts, not invented
/// evidence of a historical transport.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecordedActuationOutcome {
    #[serde(flatten)]
    pub outcome: ActuationOutcome,
    #[serde(flatten, default)]
    pub routes: crate::platform::input_route::InputRouteEvidence,
    /// How the keystrokes' action used the front of the screen, when the
    /// worker that dispatched them said so through a [`FrontingRecordScope`].
    /// Absent from older entries and from actions that do not front.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fronting: Option<FrontingRecord>,
}

/// The only serialization boundary for a result containing fronting evidence.
/// Its private representation binds the outcome and evidence: a failed-front
/// result cannot carry a confirmed front, including in nested audit refusals.
#[derive(Serialize)]
#[serde(transparent)]
pub struct FinalFrontingResult(Value);

impl FinalFrontingResult {
    pub fn new(mut body: Value) -> Self {
        if body["outcome"] == "fronting_failed" || body["refusal"]["reason"] == "fronting_failed" {
            if let Some(fronting) = body.get_mut("fronting").and_then(Value::as_object_mut) {
                fronting.insert("fronted".into(), Value::Bool(false));
            }
        }
        Self(body)
    }

    pub fn into_value(self) -> Value {
        self.0
    }
}

impl Serialize for RecordedActuationOutcome {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_json::to_value(&self.outcome).map_err(serde::ser::Error::custom)?;
        let routes = serde_json::to_value(&self.routes).map_err(serde::ser::Error::custom)?;
        value
            .as_object_mut()
            .expect("actuation outcome is an object")
            .extend(routes.as_object().expect("routes are an object").clone());
        if let Some(fronting) = self.fronting {
            value["fronting"] =
                serde_json::to_value(fronting).map_err(serde::ser::Error::custom)?;
        }
        FinalFrontingResult::new(value).serialize(serializer)
    }
}

/// The setting an action ran under, as a journal row records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontingRecordMode {
    Foreground,
    Background,
}

/// Why an action tried to bring its application to the front.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontingRecordPurpose {
    ForegroundMode,
    NeedsFront,
    BringToFront,
    None,
}

/// What became of the application that was in front before the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontingRecordRestore {
    NotNeeded,
    LeftInFront,
    Restored,
    SkippedPerson,
    Failed,
}

/// The text-free journal form of an action reply's `fronting` object, plus
/// how many preview frames were drawn for the action.
///
/// It is written into rows whose result is open JSON (the state read's
/// result, the element press rows and [`RecordedActuationOutcome`]), so it
/// needs no codec or entry-format change: a reader that does not know the
/// `fronting` member skips it. For the same reason it accepts members it does
/// not know, and every optional member is left out when it has nothing to
/// say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontingRecord {
    pub mode: FrontingRecordMode,
    pub fronted: bool,
    pub purpose: FrontingRecordPurpose,
    pub restore: FrontingRecordRestore,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_fronted_reason: Option<crate::dispatch::NotFrontedReason>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub person_input_during_fronting: bool,
    /// Preview frames written for the action. Only the count is journaled,
    /// never the pixels.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub preview_frames: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

thread_local! {
    static FRONTING_RECORD: std::cell::RefCell<Option<FrontingRecordSource>> =
        const { std::cell::RefCell::new(None) };
}

type FrontingRecordSource = Box<dyn Fn() -> Option<FrontingRecord>>;

/// Tells the actuation rows finalized on this thread how the action used the
/// front of the screen. A synthetic worker installs one around its dispatch,
/// because the dispatcher, not the worker, finalizes the row; the source is
/// asked at the moment the row is finalized, so a front and restore that the
/// dispatch itself ran are already decided. Construct and drop on the same
/// blocking thread as the dispatch.
pub struct FrontingRecordScope {
    previous: Option<FrontingRecordSource>,
}

impl FrontingRecordScope {
    pub fn new(source: impl Fn() -> Option<FrontingRecord> + 'static) -> Self {
        let previous = FRONTING_RECORD.with(|slot| slot.replace(Some(Box::new(source))));
        Self { previous }
    }

    /// What the innermost scope on this thread says now, if any.
    pub fn current() -> Option<FrontingRecord> {
        FRONTING_RECORD.with(|slot| slot.borrow().as_ref().and_then(|source| source()))
    }
}

impl Drop for FrontingRecordScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        FRONTING_RECORD.with(|slot| {
            slot.replace(previous);
        });
    }
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
            // Listing and opening applications return metadata only, never
            // pixels, so like wait they need the journal and no image custody.
            ComputerCapability::ListApps | ComputerCapability::OpenApp => {
                self.journal_available && self.severity_available
            }
            // Reading state can return an image, which passes through capture
            // custody and redaction exactly as a screenshot did.
            ComputerCapability::ReadState => self.ready(),
            ComputerCapability::PressElement
            | ComputerCapability::PressPoint
            | ComputerCapability::WriteText
            | ComputerCapability::Type
            | ComputerCapability::Keys
            | ComputerCapability::TakeoverMove
            | ComputerCapability::TakeoverClick
            | ComputerCapability::TakeoverDrag
            | ComputerCapability::TakeoverScroll => {
                self.journal_available && self.severity_available
            }
            // Never advertised, whatever the audit can do: these exist only
            // so old journal entries decode.
            ComputerCapability::Click
            | ComputerCapability::Scroll
            | ComputerCapability::Move
            | ComputerCapability::Drag
            | ComputerCapability::Screenshot => false,
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

    #[test]
    fn late_fronting_cleanup_uses_the_existing_journal_reader_and_format() {
        use cerebellum_core::journal::storage::JournalStorage;
        let storage = InMemoryJournalStorage::new();
        let mut audit = ComputerAudit::new(
            UnavailablePolicy,
            taxonomy(),
            JournalConfig {
                journal_retention_bytes: 200_000,
                journal_max_entry_bytes: 40_000,
            },
            storage.clone(),
            custody(),
        )
        .unwrap();
        let mut identity =
            journal_identity("principal", "conversation", "project", SessionKind::Primary);
        identity.witness = cerebellum_core::dispatch_witness::DispatchWitness::armed();
        audit.record_fronting_cleanup(
            identity,
            ComputerCapability::Keys,
            serde_json::json!({"cleanup":"restore", "restore":"restored", "activation_latency_ms":800}),
        ).unwrap();
        let state = storage.load().unwrap();
        let bytes = serde_json::to_vec(&state).unwrap();
        // Open completion JSON uses the existing durable-state reader and
        // schema; cleanup must not introduce a row kind or journal version.
        let read: cerebellum_core::journal::DurableState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(read, state);
        let state_json: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(state_json["entries"]["1"]["kind"], "finalized_committed");
        let exported = audit.journal().export();
        let row = ComputerJournalCodec::decode_entry(exported.trim().as_bytes()).unwrap();
        assert_eq!(row["phase"], "finalized");
        let result_bytes: Vec<u8> =
            serde_json::from_value(row["completed_result"].clone()).unwrap();
        let result: Value = serde_json::from_slice(&result_bytes).unwrap();
        assert_eq!(result["cleanup"], "restore");
        assert_eq!(result["activation_latency_ms"], 800);
        assert_eq!(audit.recover_active().len(), 0);
    }

    /// A late watch record with a restore word the reader has never seen
    /// (`skipped_coverage`) is opaque completion material: a module started
    /// over that journal opens it, recovers nothing, and reads the row back.
    /// The journal reader here is the one the released build carries, so a
    /// plain-swap rollback reads the new word the same way.
    #[test]
    fn a_journal_with_a_new_cleanup_restore_word_opens_and_reads_normally() {
        let storage = InMemoryJournalStorage::new();
        let open = || {
            ComputerAudit::new(
                UnavailablePolicy,
                taxonomy(),
                JournalConfig {
                    journal_retention_bytes: 200_000,
                    journal_max_entry_bytes: 40_000,
                },
                storage.clone(),
                custody(),
            )
            .unwrap()
        };
        let mut audit = open();
        let mut identity =
            journal_identity("principal", "conversation", "project", SessionKind::Primary);
        identity.witness = cerebellum_core::dispatch_witness::DispatchWitness::armed();
        audit
            .record_fronting_cleanup(
                identity,
                ComputerCapability::Keys,
                serde_json::json!({"cleanup":"restore", "restore":"skipped_coverage",
                    "person_input_during_fronting":false}),
            )
            .unwrap();
        drop(audit);
        // A restart over the same journal.
        let mut reopened = open();
        assert_eq!(reopened.recover_active().len(), 0);
        let exported = reopened.journal().export();
        let row = ComputerJournalCodec::decode_entry(exported.trim().as_bytes()).unwrap();
        let result_bytes: Vec<u8> =
            serde_json::from_value(row["completed_result"].clone()).unwrap();
        let result: Value = serde_json::from_slice(&result_bytes).unwrap();
        assert_eq!(result["restore"], "skipped_coverage");
    }

    #[test]
    fn failed_front_cannot_serialize_as_confirmed_in_reply_or_audit() {
        for body in [
            serde_json::json!({"outcome":"fronting_failed", "fronting":{"fronted":true}}),
            serde_json::json!({"outcome":"refused", "refusal":{"reason":"fronting_failed"}, "fronting":{"fronted":true}}),
        ] {
            let encoded = serde_json::to_value(FinalFrontingResult::new(body)).unwrap();
            assert_eq!(encoded["fronting"]["fronted"], false);
        }
        let recorded = RecordedActuationOutcome {
            outcome: ActuationOutcome::Refused {
                refusal: DispatchError::FrontingFailed,
                abort: None,
            },
            routes: Default::default(),
            fronting: Some(FrontingRecord {
                mode: FrontingRecordMode::Background,
                fronted: true,
                purpose: FrontingRecordPurpose::NeedsFront,
                restore: FrontingRecordRestore::Failed,
                not_fronted_reason: None,
                person_input_during_fronting: false,
                preview_frames: 0,
            }),
        };
        assert_eq!(
            serde_json::to_value(recorded).unwrap()["fronting"]["fronted"],
            false
        );
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
            !gate.advertised(ComputerCapability::ReadState),
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

    /// With a policy that excludes application text, capture is offerable.
    ///
    /// The exclusion policy is always able to answer, so binding it satisfies
    /// the redaction obligation without any classifier existing. A policy that
    /// truncated instead would satisfy this same gate while making a prefix of
    /// whatever it was given durable, which is why the gate alone is not
    /// evidence that application text is protected.
    #[test]
    fn a_policy_that_excludes_application_text_lets_capture_be_offered() {
        let audit = audit_with(crate::audit::redaction::ExcludeApplicationText);
        let gate = audit.capability_gate();

        assert!(gate.redactor_available);
        assert!(
            gate.advertised(ComputerCapability::ReadState),
            "capture is still withheld with a redaction policy bound"
        );
        assert!(gate.advertised(ComputerCapability::Wait));
    }

    /// Custody losing its storage withholds capture and leaves waiting alone.
    #[test]
    fn unavailable_custody_withholds_capture_only() {
        let mut audit = audit_with(UnavailablePolicy);
        audit.custody_mut().set_available(false);

        let gate = audit.capability_gate();
        assert!(!gate.custody_available);
        assert!(!gate.advertised(ComputerCapability::ReadState));
        assert!(gate.advertised(ComputerCapability::Wait));
    }

    /// Finalized actions retain their journal record but not their local metadata.
    #[test]
    fn finalized_actions_release_reservation_metadata() {
        let mut audit = audit_with(UnavailablePolicy);
        let baseline = audit.reservations.len();

        for action in 0..3 {
            let handle = audit
                .reserve(
                    journal_identity(
                        "principal",
                        format!("conversation-{action}"),
                        "project",
                        SessionKind::Primary,
                    ),
                    ComputerPlaneDescriptor::new(
                        ComputerCapability::Wait,
                        ContainmentRung::SemanticElement,
                        ObservationState::HumanObserved,
                    ),
                )
                .expect("the reservation succeeds");
            assert_eq!(audit.reservations.len(), baseline + 1);

            audit
                .finalize_rejected(handle, b"refused".to_vec())
                .expect("the action finalizes");
            assert_eq!(audit.reservations.len(), baseline);
        }
    }

    /// The terminal feed closes custody even after finalization releases metadata.
    #[test]
    fn terminal_feed_consumes_and_applies_custody_after_metadata_release() {
        let mut audit = audit_with(UnavailablePolicy);
        let handle = audit
            .reserve(
                journal_identity("principal", "conversation", "project", SessionKind::Primary),
                ComputerPlaneDescriptor::new(
                    ComputerCapability::ReadState,
                    ContainmentRung::SemanticElement,
                    ObservationState::HumanObserved,
                ),
            )
            .expect("the reservation succeeds");
        let token = audit
            .prepare_capture(handle, CaptureScope::PerWindow, None, 10)
            .expect("the active reservation prepares capture");
        let artifact_id = audit
            .admit_capture(
                token,
                PixelArtifact::per_window(vec![1, 2, 3], 10, "window", 42, 3, 1),
                10,
            )
            .expect("the capture is admitted");

        audit
            .journal_mut()
            .finalize_rejected(
                handle,
                RejectionMaterial {
                    rejection_material: b"refused".to_vec(),
                },
            )
            .expect("the journal emits a terminal transition");
        assert!(
            audit
                .reservations
                .remove(&handle.action_obligation_id())
                .is_some(),
            "the test must remove metadata before consuming the terminal feed"
        );

        assert_eq!(audit.consume_terminal_transitions(), 1);
        assert_eq!(audit.custody().read_artifact(&artifact_id), Ok(None));
    }
}

/// Recovery separates captures, whose dispatch proves the read happened, from
/// actuations, whose dispatch does not prove the platform effect occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputerRecoveryEntryClass {
    Capture,
    Actuation,
}

/// The plane-level action taken while reconciling an interrupted entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputerRecoveryAction {
    Cancelled,
    RejectionCommitted,
    DispatchFinalized,
    DispatchOutcomeUnknown,
}

/// Classify each capability by whether a recorded dispatch proves completion
/// or leaves the platform effect uncertain.
pub const fn recovery_entry_class(capability: ComputerCapability) -> ComputerRecoveryEntryClass {
    match capability {
        ComputerCapability::Screenshot
        | ComputerCapability::Wait
        | ComputerCapability::ReadState
        | ComputerCapability::ListApps
        | ComputerCapability::OpenApp => ComputerRecoveryEntryClass::Capture,
        ComputerCapability::Click
        | ComputerCapability::Type
        | ComputerCapability::Keys
        | ComputerCapability::Scroll
        | ComputerCapability::Move
        | ComputerCapability::Drag
        | ComputerCapability::PressElement
        | ComputerCapability::PressPoint
        | ComputerCapability::WriteText
        | ComputerCapability::TakeoverMove
        | ComputerCapability::TakeoverClick
        | ComputerCapability::TakeoverDrag
        | ComputerCapability::TakeoverScroll => ComputerRecoveryEntryClass::Actuation,
    }
}

/// Plane recovery mapping, exhaustive across both entry class and classification.
pub const fn recovery_surface(
    entry_class: ComputerRecoveryEntryClass,
    classification: RecoveryClassification,
) -> (ComputerRecoveryAction, ComputerTerminalKind) {
    match (entry_class, classification) {
        (
            ComputerRecoveryEntryClass::Capture,
            RecoveryClassification::UnmarkedOrphan | RecoveryClassification::FailedCommitment,
        )
        | (
            ComputerRecoveryEntryClass::Actuation,
            RecoveryClassification::UnmarkedOrphan | RecoveryClassification::FailedCommitment,
        ) => (
            ComputerRecoveryAction::Cancelled,
            ComputerTerminalKind::RecoveryCancelled,
        ),
        (ComputerRecoveryEntryClass::Capture, RecoveryClassification::FailedRejection)
        | (ComputerRecoveryEntryClass::Actuation, RecoveryClassification::FailedRejection) => (
            ComputerRecoveryAction::RejectionCommitted,
            ComputerTerminalKind::RecoveryRejectionCommitted,
        ),
        (ComputerRecoveryEntryClass::Capture, RecoveryClassification::ProvisionalDispatched) => (
            ComputerRecoveryAction::DispatchFinalized,
            ComputerTerminalKind::RecoveryDispatchFinalized,
        ),
        (ComputerRecoveryEntryClass::Actuation, RecoveryClassification::ProvisionalDispatched) => (
            ComputerRecoveryAction::DispatchOutcomeUnknown,
            ComputerTerminalKind::DispatchOutcomeUnknown,
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
        witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
        principal: principal.into(),
        conversation_key: conversation_key.into(),
        agent_project_id: agent_project_id.into(),
        session_kind,
        origin: Default::default(),
        computer_order: None,
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
    /// The journal holds an entry a newer build wrote. Reconciliation stops
    /// before acting on anything: settling or sweeping records it cannot
    /// read could destroy captures the newer build still holds.
    NewerWriter(cerebellum_core::format_floor::NewerWriter),
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

/// What the durable journal says when local reservation metadata is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationMetadataAbsence {
    AlreadyTerminal,
    Unknown,
    Unavailable,
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

    /// Keep read-side application changes on the read's own obligation, including
    /// unsuccessful reads: opting into accessibility can succeed before reading fails.
    pub fn record_accessibility_read<U>(
        &mut self,
        identity: JournalIdentity,
        capability: ComputerCapability,
        grant: &ProcessGrant,
        read: impl FnOnce() -> U,
    ) -> Result<U, ComputerAuditError> {
        let descriptor = ComputerPlaneDescriptor::new(
            capability,
            ContainmentRung::SemanticElement,
            ObservationState::HumanUnobserved,
        );
        let handle = self.reserve(identity, descriptor.clone())?;
        let token = self.commit_actuation_intent(
            handle,
            &descriptor,
            &ActuationIntent {
                element: None,
                action: capability.capability_id().to_string(),
                grant_identity: grant.clone(),
            },
        )?;
        let result = read();
        self.finalize_dispatched(
            token,
            br#"{"outcome":"read_attempted"}"#.to_vec(),
            Vec::new(),
        )?;
        Ok(result)
    }

    /// Persist one complete actuation intent before the platform can receive it.
    ///
    /// THE JOURNAL RECORDS THE CALLER'S WORDS, NEVER THE SCREEN'S. `matched_by`
    /// is the caller's own intent expression and stays raw, always: a crash
    /// between intent and outcome must leave an entry naming what might have
    /// been pressed, and a withheld marker names nothing. A re-found element
    /// could not be re-identified against a marker either. `alternate_name` is
    /// enrichment the plane scraped off the screen, not intent the caller
    /// stated, so it goes through the bound redaction policy, always. That is
    /// one uniform rule per field -- no branch on key form, no condition on
    /// content -- and the property that falls out: an identifier-addressed
    /// actuation journals no application text at all, while a role+title-
    /// addressed one journals exactly the phrase the caller used to ask.
    ///
    /// When the policy cannot redact, the commit is refused. The intent must
    /// be durable before the platform can receive the action, so a refused
    /// commit is a refused action: no actuation that carries scraped screen
    /// text proceeds without a bound, working redactor. That is the intended
    /// direction -- an action that cannot be audited safely does not happen.
    pub fn commit_actuation_intent(
        &mut self,
        handle: ReservationHandle,
        descriptor: &ComputerPlaneDescriptor,
        intent: &ActuationIntent,
    ) -> Result<DispatchCommitmentToken, ComputerAuditError> {
        let journaled = self.journaled_intent(intent)?;
        let bytes = serde_json::to_vec(&journaled)
            .map_err(|_| ComputerAuditError::Journal(JournalError::CodecFailed))?;
        let grant_decision = serde_json::to_vec(&journaled.grant_identity)
            .map_err(|_| ComputerAuditError::Journal(JournalError::CodecFailed))?;
        self.commit_dispatched(
            handle,
            &TypedDispatchMaterial {
                bytes,
                severity_inputs: descriptor.severity_inputs(),
            },
            grant_decision,
            None,
        )
    }

    /// The intent as it may reach the journal: the caller's own key untouched,
    /// scraped enrichment passed through the bound redaction policy.
    fn journaled_intent(
        &self,
        intent: &ActuationIntent,
    ) -> Result<ActuationIntent, ComputerAuditError> {
        let element = match &intent.element {
            Some(element) => Some(ActuationElementIdentity {
                matched_by: element.matched_by.clone(),
                alternate_name: match &element.alternate_name {
                    Some(name) => Some(self.redact_scraped_element_name(name)?),
                    None => None,
                },
            }),
            None => None,
        };
        Ok(ActuationIntent {
            element,
            action: intent.action.clone(),
            grant_identity: intent.grant_identity.clone(),
        })
    }

    /// Pass one scraped element name through the journal's bound redaction
    /// policy. Every string the plane read off the screen is covered: an
    /// identifier as a whole, and a role and a title each.
    fn redact_scraped_element_name(
        &self,
        name: &AccessibilityElementName,
    ) -> Result<AccessibilityElementName, ComputerAuditError> {
        // A field cannot outgrow the journal entry that carries it, so the
        // entry bound doubles as the per-field bound.
        let max_bytes = self.journal.config().journal_max_entry_bytes as usize;
        let redact = |value: &str| {
            self.journal
                .redact(value, max_bytes)
                .map_err(|_| ComputerAuditError::Journal(JournalError::RedactionUnavailable))
        };
        Ok(match name {
            AccessibilityElementName::Identifier(identifier) => {
                AccessibilityElementName::Identifier(redact(identifier)?)
            }
            AccessibilityElementName::RoleAndTitle { role, title } => {
                AccessibilityElementName::RoleAndTitle {
                    role: redact(role)?,
                    title: redact(title)?,
                }
            }
        })
    }

    /// Persist the handler result or typed refusal before returning it upstream.
    pub fn finalize_actuation_outcome(
        &mut self,
        token: DispatchCommitmentToken,
        outcome: &ActuationOutcome,
    ) -> Result<Committed, ComputerAuditError> {
        self.finalize_actuation_outcome_with_routes(token, outcome, &Default::default())
    }

    pub fn finalize_actuation_outcome_with_routes(
        &mut self,
        token: DispatchCommitmentToken,
        outcome: &ActuationOutcome,
        routes: &crate::platform::input_route::InputRouteEvidence,
    ) -> Result<Committed, ComputerAuditError> {
        let bytes = serde_json::to_vec(&RecordedActuationOutcome {
            outcome: outcome.clone(),
            routes: routes.clone(),
            fronting: FrontingRecordScope::current(),
        })
        .map_err(|_| ComputerAuditError::Journal(JournalError::CodecFailed))?;
        self.finalize_dispatched(token, bytes, Vec::new())
    }

    /// Close a gate refusal while explicitly recording that no action was sent.
    pub fn finalize_actuation_no_action(
        &mut self,
        handle: ReservationHandle,
        refusal: &DispatchError,
    ) -> Result<Committed, ComputerAuditError> {
        let bytes = serde_json::to_vec(&ActuationOutcome::NoAction {
            refusal: refusal.clone(),
        })
        .map_err(|_| ComputerAuditError::Journal(JournalError::CodecFailed))?;
        self.finalize_rejected(handle, add_route_defaults(bytes))
    }

    pub fn finalize_dispatched(
        &mut self,
        token: DispatchCommitmentToken,
        completed_result: Vec<u8>,
        final_context: Vec<u8>,
    ) -> Result<Committed, ComputerAuditError> {
        let completed_result = add_route_defaults(completed_result);
        let result = self.journal.finalize_dispatched(
            token,
            CompletedResult { completed_result },
            FinalContextAssociation { final_context },
        )?;
        self.reservations.remove(&token.action_obligation_id());
        self.consume_terminal_transitions();
        Ok(result)
    }

    /// Record bounded focus cleanup in the existing computer completion row.
    /// Cleanup is not a retry of the original actuation; its result is open
    /// JSON, like other completion material, so older journal readers need
    /// no new schema version or minimum compatible reader version.
    pub fn record_fronting_cleanup(
        &mut self,
        identity: JournalIdentity,
        capability: ComputerCapability,
        result: Value,
    ) -> Result<Committed, ComputerAuditError> {
        let dispatch = TypedCaptureDispatch::new(
            capability,
            ContainmentRung::GlobalNone,
            ObservationState::HumanUnobserved,
        );
        let handle = self.reserve(identity, dispatch.descriptor.clone())?;
        let token = self.commit_dispatched(
            handle,
            &dispatch.dispatch_material(br#"{"cleanup":"restore"}"#.to_vec()),
            b"null".to_vec(),
            None,
        )?;
        self.finalize_dispatched(
            token,
            serde_json::to_vec(&result)
                .map_err(|_| ComputerAuditError::Journal(JournalError::CodecFailed))?,
            Vec::new(),
        )
    }

    pub fn finalize_rejected(
        &mut self,
        handle: ReservationHandle,
        rejection_material: Vec<u8>,
    ) -> Result<Committed, ComputerAuditError> {
        let result = self
            .journal
            .finalize_rejected(handle, RejectionMaterial { rejection_material })?;
        self.reservations.remove(&handle.action_obligation_id());
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
        self.reservations.remove(&handle.action_obligation_id());
        self.consume_terminal_transitions();
        Ok(result)
    }

    /// Consult the journal when the local metadata needed to drive capture is gone.
    fn reservation_metadata_absence(
        &self,
        action_obligation_id: ActionObligationId,
    ) -> ReservationMetadataAbsence {
        match self.journal.read_obligation_audit(action_obligation_id) {
            Ok(record)
                if matches!(
                    record.lifecycle,
                    LifecycleState::Finalized
                        | LifecycleState::Rejected
                        | LifecycleState::Cancelled
                ) =>
            {
                ReservationMetadataAbsence::AlreadyTerminal
            }
            Err(JournalError::ObligationUnknown) => ReservationMetadataAbsence::Unknown,
            Ok(_) | Err(_) => ReservationMetadataAbsence::Unavailable,
        }
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
                cause: match self.reservation_metadata_absence(handle.action_obligation_id()) {
                    ReservationMetadataAbsence::AlreadyTerminal => {
                        CapturePrepareRefusalCause::ObligationAlreadyTerminal
                    }
                    ReservationMetadataAbsence::Unknown => {
                        CapturePrepareRefusalCause::ObligationUnknown
                    }
                    ReservationMetadataAbsence::Unavailable => {
                        CapturePrepareRefusalCause::ObligationNotDurable
                    }
                },
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
        let obligation_id = match self.custody.artifact_obligation_id(artifact_id) {
            Ok(Some(obligation_id)) => obligation_id,
            Ok(None) => {
                return Err(crate::capture_custody::CapturePinRefused {
                    cause: CapturePinRefusalCause::ArtifactUnavailable,
                })
            }
            Err(crate::capture_custody::CustodyUnavailable) => {
                return Err(crate::capture_custody::CapturePinRefused {
                    cause: CapturePinRefusalCause::CustodyUnavailable,
                })
            }
        };
        let Some(metadata) = self.reservations.get(&obligation_id).cloned() else {
            return Err(crate::capture_custody::CapturePinRefused {
                cause: match self.reservation_metadata_absence(obligation_id) {
                    ReservationMetadataAbsence::AlreadyTerminal => {
                        CapturePinRefusalCause::ObligationAlreadyTerminal
                    }
                    ReservationMetadataAbsence::Unknown => {
                        CapturePinRefusalCause::ObligationUnknown
                    }
                    ReservationMetadataAbsence::Unavailable => {
                        CapturePinRefusalCause::ArtifactUnavailable
                    }
                },
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
        let descriptor = match self.custody.capture_descriptor(artifact_id) {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => {
                let _ = self.custody.abort_pin(&pending);
                return Err(crate::capture_custody::CapturePinRefused {
                    cause: CapturePinRefusalCause::ArtifactUnavailable,
                });
            }
            Err(crate::capture_custody::CustodyUnavailable) => {
                let _ = self.custody.abort_pin(&pending);
                return Err(crate::capture_custody::CapturePinRefused {
                    cause: CapturePinRefusalCause::CustodyUnavailable,
                });
            }
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

    pub fn read_computer_audit_record(
        &self,
        action_obligation_id: ActionObligationId,
    ) -> Result<ComputerAuditRecord, ComputerAuditError> {
        let record = self.journal.read_obligation_audit(action_obligation_id)?;
        let descriptor = ComputerPlaneDescriptor::decode(&record.descriptor_bytes)
            .map_err(|_| ComputerAuditError::Journal(JournalError::CodecFailed))?;
        let terminal_kind = record.terminal_kind.map(|terminal_kind| {
            if record.recovery_supplied_terminal
                && terminal_kind == TerminalKind::RecoveryDispatchFinalized
            {
                recovery_surface(
                    recovery_entry_class(descriptor.capability),
                    RecoveryClassification::ProvisionalDispatched,
                )
                .1
            } else {
                ComputerTerminalKind::from(terminal_kind)
            }
        });
        Ok(ComputerAuditRecord {
            action_obligation_id,
            descriptor,
            severity: record.severity,
            terminal_kind,
        })
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

    /// Restore journal, custody, and terminal-feed state before exposing reads.
    pub fn startup_reconcile(&mut self, now: u64) -> Result<(), ComputerAuditError> {
        self.refuse_newer_entries()?;
        self.custody.begin_process_epoch();
        self.recover_active();
        if self.journal.status().active_reservation_count != 0 {
            return Err(ComputerAuditError::Journal(
                JournalError::FinalizationPending,
            ));
        }
        let ids = self.custody.obligation_ids();
        let mut attachments = Vec::new();
        for id in ids {
            if let Ok(record) = self.journal.read_obligation_audit(id) {
                attachments.extend(record.attachment_slots);
            }
        }
        self.custody.reconcile_attachments(attachments)?;
        self.consume_terminal_transitions();
        let elapsed = self.custody.close_elapsed_windows(now);
        let expired = self.sweep_expired_captures(now);
        if elapsed.deletion_failure_count != 0 || expired.deletion_failure_count != 0 {
            return Err(ComputerAuditError::Custody(
                CustodyError::StorageUnavailable,
            ));
        }
        Ok(())
    }

    /// Refuse, by name, a journal holding an entry in a newer version of this
    /// codec's format, before reconciliation recovers or reads any of it.
    fn refuse_newer_entries(&self) -> Result<(), ComputerAuditError> {
        for sequence in 1..self.journal.next_sequence() {
            if let Ok(record) = self.journal.read_obligation_audit(sequence) {
                COMPUTER_ENTRY_FORMAT
                    .refuse_newer_tag(&record.codec_id, COMPUTER_JOURNAL_CODEC_VERSION)
                    .map_err(ComputerAuditError::NewerWriter)?;
            }
        }
        Ok(())
    }

    pub fn journal_purge(&mut self) -> cerebellum_core::journal::PurgeReport {
        self.journal.purge()
    }
}

/// Keeps enable evidence on the action's journal row, never in its wire result.
/// Construct and drop on the same blocking thread as the reads and journal writes.
pub struct AccessibilityReadScope {
    #[cfg(target_os = "macos")]
    _guard: cerebellum_macos::ManualAccessibilityScope,
}

impl AccessibilityReadScope {
    pub fn new(pid: u32, initial: Option<&'static str>) -> Self {
        #[cfg(target_os = "macos")]
        {
            use cerebellum_macos::ManualAccessibility as M;
            let initial = initial.and_then(|s| match s {
                "newly_enabled" => Some(M::NewlyEnabled),
                "already_enabled" => Some(M::AlreadyEnabled),
                "not_supported" => Some(M::NotSupported),
                "failed" => Some(M::Failed(-1)),
                _ => None,
            });
            Self {
                _guard: cerebellum_macos::ManualAccessibilityScope::new(pid, initial),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (pid, initial);
            Self {}
        }
    }

    pub fn current() -> Option<&'static str> {
        #[cfg(target_os = "macos")]
        {
            cerebellum_macos::ManualAccessibilityScope::current().map(|status| status.as_str())
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }
}
