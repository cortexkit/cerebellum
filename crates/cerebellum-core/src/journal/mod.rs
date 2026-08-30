//! Neutral journal lifecycle, accounting, recovery, and publication.
//!
//! The lifecycle owns durable state transitions and stores opaque adapter
//! material. Codecs, redactors, and severity tables remain policy bindings; the
//! types in this module do not interpret their bytes.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::identity::SessionKind;

pub mod codec;
pub mod late_events;
pub mod redaction;
pub mod refusal_ring;
pub mod recovery {
    pub use super::{CoreRecoveryOutcome, RecoveryAction, RecoveryClassification, TerminalKind};
}
pub mod reservation {
    pub use super::{
        Committed, CompletedResult, DispatchCommitmentToken, DispatchMaterial,
        FinalContextAssociation, RejectionMaterial, ReservationHandle,
    };
}
pub mod store {
    pub use super::{
        BindingError, DurableState, JournalBinding, JournalConfig, JournalError, JournalStatus,
        PurgeReport,
    };
    pub type JournalStore<C, R = (), T = (), S = super::InMemoryJournalStorage> =
        super::JournalBinding<C, R, T, S>;
}
pub mod severity;
pub mod storage;

pub use codec::{
    CompletionInput, DispatchedInput, EncodedJournalState, JournalCodecError, PlaneJournalCodec,
    ProvisionalInput, RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
};
pub use late_events::{
    DeliveryRoute, LateDelivery, LateEventCause, LateEventDescriptor, LateEventError,
    LateEventQueue, LateEventSequence,
};
pub use redaction::{redact_then_truncate, RedactionUnavailable, Redactor};
pub use refusal_ring::{
    CallerRefusalHistory, RefusalRecord, RefusalRing, RefusalRingConfig, RefusalRingError,
    RefusalRingState,
};
pub use severity::{
    taxonomy_digest, EffectClass, IsolationClass, ObservabilityClass, SeverityInputs,
    SeverityRecord, SeverityTaxonomy, TaxonomyError, ValidatedSeverityTaxonomy,
};
pub use storage::{
    journal_data_path, FilesystemJournalStorage, InMemoryJournalStorage, JournalStorage,
};

pub type ActionObligationId = u64;
pub type AttachmentRevision = u64;
pub type PublicationCursor = u64;

/// The neutral identity stamped before an obligation is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalIdentity {
    pub principal: String,
    pub conversation_key: String,
    pub agent_project_id: String,
    pub session_kind: SessionKind,
}

/// A positive capacity configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalConfig {
    pub journal_retention_bytes: u64,
    pub journal_max_entry_bytes: u64,
}

impl JournalConfig {
    pub fn validate(self) -> Result<(), BindingError> {
        if self.journal_retention_bytes == 0
            || self.journal_max_entry_bytes == 0
            || self.journal_max_entry_bytes > self.journal_retention_bytes
        {
            return Err(BindingError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Neutral journal reasons used by reduced records and audit reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalReason {
    ReservationFailed,
    EntryOversize,
    InterruptedAfterDispatch,
    RedactionUnavailable,
    InternalFailure,
}

impl JournalReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservationFailed => "journal_reservation_failed",
            Self::EntryOversize => "journal_entry_oversize",
            Self::InterruptedAfterDispatch => "interrupted_after_dispatch",
            Self::RedactionUnavailable => "redaction_unavailable",
            Self::InternalFailure => "internal_failure",
        }
    }
}

/// Lifecycle failures exposed without codec or storage implementation detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    ReservationFailed,
    CodecFailed,
    AttachmentFailed,
    FinalizationPending,
    StorageUnavailable,
    ObligationUnknown,
    InvalidHandle,
    EntryOversize,
    RedactionUnavailable,
}

impl JournalError {
    pub const fn reason(self) -> JournalReason {
        match self {
            Self::ReservationFailed => JournalReason::ReservationFailed,
            Self::CodecFailed => JournalReason::InternalFailure,
            Self::AttachmentFailed => JournalReason::InternalFailure,
            Self::FinalizationPending => JournalReason::InterruptedAfterDispatch,
            Self::StorageUnavailable => JournalReason::InternalFailure,
            Self::ObligationUnknown => JournalReason::InternalFailure,
            Self::InvalidHandle => JournalReason::InternalFailure,
            Self::EntryOversize => JournalReason::EntryOversize,
            Self::RedactionUnavailable => JournalReason::RedactionUnavailable,
        }
    }
}

/// Failure while opening a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    InvalidConfiguration,
    Storage(StorageError),
}

/// Owned diagnostic details retained from an operating-system I/O error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoDiagnostic {
    pub kind: io::ErrorKind,
    pub message: String,
}

/// Storage failures are separated by remedy so absence can never be confused
/// with damaged or temporarily inaccessible history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    Missing {
        path: PathBuf,
        source: IoDiagnostic,
    },
    Unreadable {
        path: PathBuf,
        source: IoDiagnostic,
    },
    Corrupt {
        path: PathBuf,
        source: String,
    },
    UnknownSchemaVersion {
        path: PathBuf,
        found: u64,
        supported: u64,
    },
    HomeDirectoryUnavailable {
        variable: String,
    },
    CreateDirectory {
        path: PathBuf,
        source: IoDiagnostic,
    },
    ProbeWrite {
        path: PathBuf,
        source: IoDiagnostic,
    },
    ProbeCleanup {
        path: PathBuf,
        source: IoDiagnostic,
    },
    Serialization {
        path: PathBuf,
        source: String,
    },
    TemporaryWrite {
        path: PathBuf,
        source: IoDiagnostic,
    },
    FileSync {
        path: PathBuf,
        source: IoDiagnostic,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
        source: IoDiagnostic,
    },
    DirectorySync {
        path: PathBuf,
        source: IoDiagnostic,
    },
    LockPoisoned {
        binding: String,
    },
}

/// A lifecycle state visible from the read-only audit surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Active,
    Dispatched,
    Finalized,
    Rejected,
    Cancelled,
}

/// Durable terminal transition kinds. The publication cursor is independent of
/// the obligation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalKind {
    FinalizedCommitted,
    RejectedCommitted,
    RecoveryDispatchFinalized,
    RecoveryRejectionCommitted,
    RecoveryCancelled,
}

/// Classification of one active record at recovery time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClassification {
    UnmarkedOrphan,
    FailedRejection,
    FailedCommitment,
    ProvisionalDispatched,
}

/// Recovery action performed by the neutral lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    Cancelled,
    RejectionCommitted,
    DispatchFinalized,
}

pub type CoreRecoveryClassification = RecoveryClassification;
pub type CoreRecoveryAction = RecoveryAction;

/// Recovery result returned without exposing adapter payload types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreRecoveryOutcome {
    pub action_obligation_id: u64,
    pub classification: RecoveryClassification,
    pub terminal_kind: TerminalKind,
    pub recovery_action: RecoveryAction,
    pub attachments: Vec<ObligationAttachment>,
}

/// Opaque attachment stored against one obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationAttachment {
    pub slot: String,
    pub revision: u64,
    pub opaque_bytes: Vec<u8>,
}

/// Descriptor and lifecycle facts returned by the read-only audit operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationAuditRecord {
    pub action_obligation_id: u64,
    pub lifecycle: LifecycleState,
    pub terminal_kind: Option<TerminalKind>,
    pub descriptor_bytes: Vec<u8>,
    pub codec_id: String,
    pub attachment_slots: Vec<ObligationAttachment>,
    pub severity_inputs: Option<SeverityInputs>,
    pub severity: Option<SeverityRecord>,
    pub reason: Option<JournalReason>,
    pub recovery_supplied_terminal: bool,
}

/// Durable position in the terminal publication feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalTransition {
    pub cursor: u64,
    pub action_obligation_id: u64,
    pub kind: TerminalKind,
}

/// The value returned by a successful reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationHandle {
    action_obligation_id: u64,
}

impl ReservationHandle {
    pub fn action_obligation_id(self) -> u64 {
        self.action_obligation_id
    }

    pub fn sequence(self) -> u64 {
        self.action_obligation_id
    }
}

/// The single-use token returned after dispatch commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchCommitmentToken {
    action_obligation_id: u64,
}

impl DispatchCommitmentToken {
    pub fn action_obligation_id(self) -> u64 {
        self.action_obligation_id
    }

    pub fn sequence(self) -> u64 {
        self.action_obligation_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed;

/// Opaque dispatch material and normalized policy inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchMaterial {
    #[serde(with = "crate::serde_base64::bytes")]
    pub dispatch_material: Vec<u8>,
    pub severity_inputs: Option<SeverityInputs>,
    #[serde(with = "crate::serde_base64::bytes")]
    pub grant_decision: Vec<u8>,
    #[serde(with = "crate::serde_base64::optional_bytes")]
    pub governing_observation: Option<Vec<u8>>,
}

/// Opaque completed result and final-context association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedResult {
    pub completed_result: Vec<u8>,
}

/// Opaque final-context association captured at completion time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalContextAssociation {
    pub final_context: Vec<u8>,
}

/// Opaque pre-dispatch rejection material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectionMaterial {
    #[serde(with = "crate::serde_base64::bytes")]
    pub rejection_material: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReservationMarker {
    Rejection(RejectionMaterial),
    DispatchCommitment,
    Reduced(JournalReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentState {
    revision: u64,
    #[serde(with = "crate::serde_base64::bytes")]
    opaque_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationRecord {
    identity: JournalIdentity,
    #[serde(with = "crate::serde_base64::bytes")]
    invocation_descriptor: Vec<u8>,
    provisional: EncodedJournalState,
    codec_id: String,
    charge: u64,
    state: LifecycleState,
    marker: Option<ReservationMarker>,
    dispatch: Option<DispatchMaterial>,
    attachments: BTreeMap<String, AttachmentState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalRecord {
    identity: JournalIdentity,
    #[serde(with = "crate::serde_base64::bytes")]
    invocation_descriptor: Vec<u8>,
    #[serde(with = "crate::serde_base64::bytes")]
    bytes: Vec<u8>,
    accounted_size: u64,
    codec_id: String,
    kind: TerminalKind,
    reason: Option<JournalReason>,
    severity_inputs: Option<SeverityInputs>,
    severity: Option<SeverityRecord>,
    attachments: BTreeMap<String, AttachmentState>,
    recovered: bool,
}

struct TerminalCommit {
    sequence: u64,
    record: ReservationRecord,
    encoded: EncodedJournalState,
    kind: TerminalKind,
    reason: Option<JournalReason>,
    recovered: bool,
}

/// Durable state shared by a storage binding.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableState {
    next_sequence: u64,
    next_cursor: u64,
    entries: BTreeMap<u64, TerminalRecord>,
    reservations: BTreeMap<u64, ReservationRecord>,
    transitions: Vec<TerminalTransition>,
    oversize_flag: bool,
    // Fault injection is a process-local test control, not audit history. Not
    // persisting it prevents an intentionally armed failure from surprising a
    // production process after restart.
    #[serde(skip, default)]
    faults: BTreeMap<String, usize>,
}

impl DurableState {
    fn fresh() -> Self {
        Self {
            next_sequence: 1,
            next_cursor: 1,
            ..Self::default()
        }
    }
}

/// Durable journal mechanics bound to one codec, policy set, and storage.
pub struct JournalBinding<C, R = (), T = (), S = InMemoryJournalStorage> {
    codec: C,
    redactor: Option<R>,
    severity_taxonomy: Option<T>,
    config: JournalConfig,
    storage: S,
    state: DurableState,
}

impl<C, R, T, S> JournalBinding<C, R, T, S>
where
    C: PlaneJournalCodec,
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    /// Open the binding over durable state. Policy bindings are optional and do
    /// not disable unrelated lifecycle operations when absent.
    pub fn new(
        codec: C,
        redactor: Option<R>,
        severity_taxonomy: Option<T>,
        config: JournalConfig,
        storage: S,
    ) -> Result<Self, BindingError> {
        config.validate()?;
        let mut state = storage.load().map_err(BindingError::Storage)?;
        if state.next_sequence == 0 {
            state = DurableState::fresh();
            storage.save(&state).map_err(BindingError::Storage)?;
        }
        Ok(Self {
            codec,
            redactor,
            severity_taxonomy,
            config,
            storage,
            state,
        })
    }

    pub fn config(&self) -> JournalConfig {
        self.config
    }

    pub fn redactor_available(&self) -> bool {
        self.redactor.as_ref().is_some_and(Redactor::available)
    }

    pub fn taxonomy_version(&self) -> Option<&str> {
        self.severity_taxonomy
            .as_ref()
            .map(SeverityTaxonomy::version)
    }

    pub fn taxonomy_digest(&self) -> Option<&str> {
        self.severity_taxonomy
            .as_ref()
            .map(SeverityTaxonomy::digest)
    }

    pub fn resolve_severity(&self, inputs: SeverityInputs) -> Option<SeverityRecord> {
        self.severity_taxonomy
            .as_ref()
            .and_then(|taxonomy| taxonomy.resolve(inputs))
    }

    pub fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable> {
        redact_then_truncate(self.redactor.as_ref(), input, max_bytes)
    }

    pub fn next_sequence(&self) -> u64 {
        self.state.next_sequence
    }

    pub fn retained_bytes(&self) -> u64 {
        retained_bytes(&self.state)
    }

    pub fn active_reserved_bytes(&self) -> u64 {
        self.state
            .reservations
            .values()
            .map(|record| record.charge)
            .sum()
    }

    pub fn active_pre_dispatch_count(&self) -> usize {
        self.state
            .reservations
            .values()
            .filter(|record| record.state == LifecycleState::Active)
            .count()
    }

    pub fn set_oversize_flag(&mut self) {
        self.state.oversize_flag = true;
        let candidate = self.state.clone();
        let _ = self.commit_state(candidate);
    }

    pub fn status(&self) -> JournalStatus {
        let mut sequences: Vec<u64> = self.state.entries.keys().copied().collect();
        sequences.extend(
            self.state
                .reservations
                .iter()
                .filter(|(_, record)| record.state == LifecycleState::Dispatched)
                .map(|(sequence, _)| *sequence),
        );
        sequences.sort_unstable();
        JournalStatus {
            entry_count: sequences.len(),
            oldest_retained_sequence: sequences.first().copied(),
            newest_retained_sequence: sequences.last().copied(),
            retained_bytes: retained_bytes(&self.state),
            active_reservation_count: self.state.reservations.len(),
            active_reserved_bytes: self
                .state
                .reservations
                .values()
                .map(|record| record.charge)
                .sum(),
            oversize_flag: self.state.oversize_flag,
        }
    }

    /// Allocate and persist the next sequence number without reserving or
    /// committing a journal entry for it.
    pub fn allocate_sequence(&mut self) -> Result<u64, JournalError> {
        let mut candidate = self.state.clone();
        if take_fault(&mut candidate, "advance_allocator") {
            return Err(JournalError::ReservationFailed);
        }
        let sequence = candidate.next_sequence;
        candidate.next_sequence = candidate.next_sequence.saturating_add(1);
        self.commit_state(candidate)?;
        Ok(sequence)
    }

    /// Reserve capacity through the codec's provisional representation.
    pub fn reserve(
        &mut self,
        identity: JournalIdentity,
        invocation_descriptor: Vec<u8>,
    ) -> Result<ReservationHandle, JournalError> {
        let mut candidate = self.state.clone();
        if take_fault(&mut candidate, "advance_allocator") {
            return Err(JournalError::ReservationFailed);
        }
        let action_obligation_id = candidate.next_sequence;
        candidate.next_sequence = candidate.next_sequence.saturating_add(1);
        let input = ProvisionalInput {
            action_obligation_id,
            identity: identity.clone(),
            invocation_descriptor: invocation_descriptor.clone(),
        };
        let provisional = match self.encode(|codec| codec.encode_provisional(&input)) {
            Ok(encoded) => encoded,
            Err(error) => {
                let _ = self.commit_state(candidate);
                return Err(error);
            }
        };
        let mut reservation = ReservationRecord {
            identity,
            invocation_descriptor,
            codec_id: provisional.codec_version.clone(),
            charge: 0,
            provisional,
            state: LifecycleState::Active,
            marker: None,
            dispatch: None,
            attachments: BTreeMap::new(),
        };
        let charge = refresh_reservation_charge(&mut reservation)?;
        if !make_room(&mut candidate, charge, self.config) {
            let _ = self.commit_state(candidate);
            return Err(JournalError::ReservationFailed);
        }
        candidate
            .reservations
            .insert(action_obligation_id, reservation);
        self.commit_state(candidate)?;
        Ok(ReservationHandle {
            action_obligation_id,
        })
    }

    /// Commit the dispatch representation before an external side effect.
    pub fn commit_dispatched(
        &mut self,
        handle: ReservationHandle,
        material: DispatchMaterial,
    ) -> Result<DispatchCommitmentToken, JournalError> {
        let sequence = handle.action_obligation_id;
        let record = self
            .state
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        if record.state == LifecycleState::Dispatched {
            return Ok(DispatchCommitmentToken {
                action_obligation_id: sequence,
            });
        }
        if record.state != LifecycleState::Active || record.marker.is_some() {
            return Err(JournalError::InvalidHandle);
        }
        let input = DispatchedInput {
            action_obligation_id: sequence,
            identity: record.identity.clone(),
            invocation_descriptor: record.invocation_descriptor.clone(),
            dispatch_material: material.dispatch_material.clone(),
            severity_inputs: material.severity_inputs,
            grant_decision: material.grant_decision.clone(),
            governing_observation: material.governing_observation.clone(),
        };
        let encoded = self.encode(|codec| codec.encode_dispatched(&input))?;
        let mut marked = self.state.clone();
        if take_fault(&mut marked, "establish_marker") {
            return Err(JournalError::ReservationFailed);
        }
        let mut marked_record = marked
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        marked_record.marker = Some(ReservationMarker::DispatchCommitment);
        let marked_charge = refresh_reservation_charge(&mut marked_record)?;
        if !make_room_delta(&mut marked, record.charge, marked_charge, self.config) {
            return Err(JournalError::ReservationFailed);
        }
        marked.reservations.insert(sequence, marked_record);
        self.commit_state(marked)?;

        let mut committed = self.state.clone();
        if take_fault(&mut committed, "commit_dispatch") {
            self.commit_state(committed)?;
            return Err(JournalError::ReservationFailed);
        }
        let mut dispatched_record = committed
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        let old_charge = dispatched_record.charge;
        dispatched_record.state = LifecycleState::Dispatched;
        dispatched_record.marker = None;
        dispatched_record.provisional = encoded;
        dispatched_record.dispatch = Some(material);
        let dispatched_charge = refresh_reservation_charge(&mut dispatched_record)?;
        if !make_room_delta(&mut committed, old_charge, dispatched_charge, self.config) {
            return Err(JournalError::ReservationFailed);
        }
        committed.reservations.insert(sequence, dispatched_record);
        self.commit_state(committed)?;
        Ok(DispatchCommitmentToken {
            action_obligation_id: sequence,
        })
    }

    /// Finalize a pre-dispatch rejection and publish its terminal transition.
    pub fn finalize_rejected(
        &mut self,
        handle: ReservationHandle,
        material: RejectionMaterial,
    ) -> Result<Committed, JournalError> {
        let sequence = handle.action_obligation_id;
        let record = self
            .state
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        if record.state != LifecycleState::Active || record.marker.is_some() {
            return Err(JournalError::InvalidHandle);
        }
        let input = RejectionInput {
            action_obligation_id: sequence,
            identity: record.identity.clone(),
            invocation_descriptor: record.invocation_descriptor.clone(),
            rejection_material: material.rejection_material.clone(),
        };
        let encoded = self.encode(|codec| codec.encode_rejection(&input))?;
        let mut marked = self.state.clone();
        if take_fault(&mut marked, "establish_marker") {
            return Err(JournalError::ReservationFailed);
        }
        let mut marked_record = marked
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        marked_record.marker = Some(ReservationMarker::Rejection(material));
        let marked_charge = refresh_reservation_charge(&mut marked_record)?;
        if !make_room_delta(&mut marked, record.charge, marked_charge, self.config) {
            return Err(JournalError::ReservationFailed);
        }
        marked.reservations.insert(sequence, marked_record);
        self.commit_state(marked)?;
        let mut committed = self.state.clone();
        if take_fault(&mut committed, "commit_rejection") {
            self.commit_state(committed)?;
            return Err(JournalError::ReservationFailed);
        }
        self.insert_terminal(
            &mut committed,
            TerminalCommit {
                sequence,
                record,
                encoded,
                kind: TerminalKind::RejectedCommitted,
                reason: None,
                recovered: false,
            },
        )?;
        self.commit_state(committed)?;
        Ok(Committed)
    }

    /// Publish a reduced terminal record without retaining adapter material.
    pub fn finalize_reduced(
        &mut self,
        handle: ReservationHandle,
        reason: JournalReason,
    ) -> Result<Committed, JournalError> {
        let sequence = handle.action_obligation_id;
        let record = self
            .state
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        if record.state != LifecycleState::Active || record.marker.is_some() {
            return Err(JournalError::InvalidHandle);
        }
        let input = ReducedTerminalInput {
            action_obligation_id: sequence,
            identity: record.identity.clone(),
            reason,
            severity_inputs: record
                .dispatch
                .as_ref()
                .and_then(|material| material.severity_inputs),
        };
        let encoded = self.encode(|codec| codec.encode_reduced_terminal(&input))?;
        let mut marked = self.state.clone();
        if take_fault(&mut marked, "establish_marker") {
            return Err(JournalError::ReservationFailed);
        }
        let mut marked_record = marked
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        marked_record.marker = Some(ReservationMarker::Reduced(reason));
        let marked_charge = refresh_reservation_charge(&mut marked_record)?;
        if !make_room_delta(&mut marked, record.charge, marked_charge, self.config) {
            return Err(JournalError::ReservationFailed);
        }
        marked.reservations.insert(sequence, marked_record);
        self.commit_state(marked)?;
        let mut committed = self.state.clone();
        if take_fault(&mut committed, "commit_rejection") {
            self.commit_state(committed)?;
            return Err(JournalError::ReservationFailed);
        }
        self.insert_terminal(
            &mut committed,
            TerminalCommit {
                sequence,
                record,
                encoded,
                kind: TerminalKind::RejectedCommitted,
                reason: Some(reason),
                recovered: false,
            },
        )?;
        self.commit_state(committed)?;
        Ok(Committed)
    }

    /// Finalize a committed dispatch. A failed write leaves the dispatched
    /// representation active for recovery.
    pub fn finalize_dispatched(
        &mut self,
        token: DispatchCommitmentToken,
        result: CompletedResult,
        final_context: FinalContextAssociation,
    ) -> Result<Committed, JournalError> {
        let sequence = token.action_obligation_id;
        let record = self
            .state
            .reservations
            .get(&sequence)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        if record.state != LifecycleState::Dispatched {
            return Err(JournalError::InvalidHandle);
        }
        let dispatch = record.dispatch.clone().ok_or(JournalError::InvalidHandle)?;
        let input = CompletionInput {
            action_obligation_id: sequence,
            identity: record.identity.clone(),
            dispatch_material: dispatch.dispatch_material,
            completed_result: result.completed_result,
            final_context: final_context.final_context,
            severity_inputs: dispatch.severity_inputs,
            attachments: record
                .attachments
                .values()
                .map(|attachment| attachment.opaque_bytes.clone())
                .collect(),
        };
        let encoded = self.encode(|codec| codec.encode_completion(&input))?;
        let mut committed = self.state.clone();
        if take_fault(&mut committed, "commit_finalization") {
            self.commit_state(committed)?;
            return Err(JournalError::FinalizationPending);
        }
        self.insert_terminal(
            &mut committed,
            TerminalCommit {
                sequence,
                record,
                encoded,
                kind: TerminalKind::FinalizedCommitted,
                reason: None,
                recovered: false,
            },
        )?;
        self.commit_state(committed)?;
        Ok(Committed)
    }

    /// Compare-and-set an opaque attachment revision.
    pub fn attach_obligation_material(
        &mut self,
        handle: ReservationHandle,
        slot: impl Into<String>,
        expected_revision: u64,
        opaque_bytes: Vec<u8>,
    ) -> Result<u64, JournalError> {
        if opaque_bytes.len() as u64 > self.config.journal_max_entry_bytes {
            return Err(JournalError::AttachmentFailed);
        }
        let slot = slot.into();
        let mut candidate = self.state.clone();
        let mut record = candidate
            .reservations
            .get(&handle.action_obligation_id)
            .cloned()
            .ok_or(JournalError::ObligationUnknown)?;
        let current = record
            .attachments
            .get(&slot)
            .map(|attachment| attachment.revision)
            .unwrap_or(0);
        if current != expected_revision {
            return Err(JournalError::AttachmentFailed);
        }
        let revision = expected_revision.saturating_add(1);
        let old_charge = record.charge;
        record.attachments.insert(
            slot,
            AttachmentState {
                revision,
                opaque_bytes,
            },
        );
        let new_charge =
            refresh_reservation_charge(&mut record).map_err(|_| JournalError::AttachmentFailed)?;
        if !make_room_delta(&mut candidate, old_charge, new_charge, self.config) {
            return Err(JournalError::AttachmentFailed);
        }
        candidate
            .reservations
            .insert(handle.action_obligation_id, record);
        self.commit_state(candidate)?;
        Ok(revision)
    }

    /// Recover every active reservation from durable opaque material.
    pub fn classify(&self, action_obligation_id: u64) -> Option<RecoveryClassification> {
        let record = self.state.reservations.get(&action_obligation_id)?;
        if record.state == LifecycleState::Dispatched {
            return Some(RecoveryClassification::ProvisionalDispatched);
        }
        match record.marker {
            None => Some(RecoveryClassification::UnmarkedOrphan),
            Some(ReservationMarker::Rejection(_)) | Some(ReservationMarker::Reduced(_)) => {
                Some(RecoveryClassification::FailedRejection)
            }
            Some(ReservationMarker::DispatchCommitment) => {
                Some(RecoveryClassification::FailedCommitment)
            }
        }
    }

    pub fn recover_one(&mut self, action_obligation_id: u64) -> Option<CoreRecoveryOutcome> {
        self.recover_active()
            .into_iter()
            .find(|outcome| outcome.action_obligation_id == action_obligation_id)
    }

    pub fn recover_active(&mut self) -> Vec<CoreRecoveryOutcome> {
        let sequences: Vec<u64> = self.state.reservations.keys().copied().collect();
        let mut outcomes = Vec::new();
        for sequence in sequences {
            let Some(record) = self.state.reservations.get(&sequence).cloned() else {
                continue;
            };
            let classification = if record.state == LifecycleState::Dispatched {
                RecoveryClassification::ProvisionalDispatched
            } else {
                match record.marker {
                    None => RecoveryClassification::UnmarkedOrphan,
                    Some(ReservationMarker::Rejection(_)) | Some(ReservationMarker::Reduced(_)) => {
                        RecoveryClassification::FailedRejection
                    }
                    Some(ReservationMarker::DispatchCommitment) => {
                        RecoveryClassification::FailedCommitment
                    }
                }
            };
            let outcome = match classification {
                RecoveryClassification::ProvisionalDispatched => {
                    self.recover_dispatched(sequence, record)
                }
                RecoveryClassification::FailedRejection => self.recover_rejection(sequence, record),
                RecoveryClassification::UnmarkedOrphan
                | RecoveryClassification::FailedCommitment => {
                    self.cancel_recovery(sequence, record, classification)
                }
            };
            if let Some(outcome) = outcome {
                outcomes.push(outcome);
            }
        }
        outcomes
    }

    pub fn read_obligation_audit(
        &self,
        action_obligation_id: u64,
    ) -> Result<ObligationAuditRecord, JournalError> {
        if let Some(entry) = self.state.entries.get(&action_obligation_id) {
            return Ok(self.audit_from_terminal(action_obligation_id, entry));
        }
        if let Some(record) = self.state.reservations.get(&action_obligation_id) {
            return Ok(ObligationAuditRecord {
                action_obligation_id,
                lifecycle: record.state,
                terminal_kind: None,
                descriptor_bytes: record.invocation_descriptor.clone(),
                codec_id: record.codec_id.clone(),
                attachment_slots: attachments_from(&record.attachments),
                severity_inputs: record
                    .dispatch
                    .as_ref()
                    .and_then(|material| material.severity_inputs),
                severity: record
                    .dispatch
                    .as_ref()
                    .and_then(|material| material.severity_inputs)
                    .and_then(|inputs| self.resolve_severity(inputs)),
                reason: None,
                recovery_supplied_terminal: false,
            });
        }
        Err(JournalError::ObligationUnknown)
    }

    pub fn read_obligation_record(
        &self,
        action_obligation_id: u64,
    ) -> Result<ObligationAuditRecord, JournalError> {
        self.read_obligation_audit(action_obligation_id)
    }

    pub fn terminal_transitions(
        &self,
        after_cursor: u64,
    ) -> Result<Vec<TerminalTransition>, JournalError> {
        Ok(self
            .state
            .transitions
            .iter()
            .filter(|transition| transition.cursor > after_cursor)
            .copied()
            .collect())
    }

    pub fn arm_fault(&mut self, point: impl Into<String>, count: usize) {
        self.state.faults.insert(point.into(), count);
        let candidate = self.state.clone();
        let _ = self.commit_state(candidate);
    }

    pub fn oversize_flag(&self) -> bool {
        self.state.oversize_flag
    }

    pub fn export_bytes(&self) -> Vec<u8> {
        let mut records: Vec<(u64, &[u8])> = self
            .state
            .entries
            .iter()
            .map(|(sequence, entry)| (*sequence, entry.bytes.as_slice()))
            .collect();
        records.extend(
            self.state
                .reservations
                .iter()
                .filter(|(_, record)| record.state == LifecycleState::Dispatched)
                .map(|(sequence, record)| (*sequence, record.provisional.durable_bytes.as_slice())),
        );
        records.sort_by_key(|(sequence, _)| *sequence);
        records
            .into_iter()
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect()
    }

    pub fn export(&self) -> String {
        String::from_utf8_lossy(&self.export_bytes()).into_owned()
    }

    pub fn purge(&mut self) -> PurgeReport {
        let mut candidate = self.state.clone();
        let report = PurgeReport {
            purged_entry_count: candidate.entries.len() as u64,
            purged_bytes: candidate
                .entries
                .values()
                .map(|entry| entry.accounted_size)
                .sum(),
        };
        candidate.entries.clear();
        candidate.oversize_flag = false;
        let _ = self.commit_state(candidate);
        report
    }

    pub fn retention_get(&self) -> JournalConfig {
        self.config
    }

    pub fn retention_set(&mut self, config: JournalConfig) -> Result<JournalConfig, JournalError> {
        config
            .validate()
            .map_err(|_| JournalError::StorageUnavailable)?;
        let mut candidate = self.state.clone();
        let active: u64 = candidate
            .reservations
            .values()
            .map(|record| record.charge)
            .sum();
        if active > config.journal_retention_bytes {
            return Err(JournalError::ReservationFailed);
        }
        while retained_bytes(&candidate) > config.journal_retention_bytes {
            let Some(sequence) = candidate.entries.keys().next().copied() else {
                return Err(JournalError::ReservationFailed);
            };
            candidate.entries.remove(&sequence);
        }
        candidate.oversize_flag = false;
        let previous = self.config;
        self.config = config;
        if let Err(error) = self.commit_state(candidate) {
            self.config = previous;
            return Err(error);
        }
        Ok(config)
    }

    fn recover_dispatched(
        &mut self,
        sequence: u64,
        record: ReservationRecord,
    ) -> Option<CoreRecoveryOutcome> {
        let dispatch = record.dispatch.clone()?;
        let input = RecoveryTerminalInput {
            action_obligation_id: sequence,
            identity: record.identity.clone(),
            dispatch_material: dispatch.dispatch_material,
            invocation_descriptor: record.invocation_descriptor.clone(),
            severity_inputs: dispatch.severity_inputs,
            attachments: record
                .attachments
                .values()
                .map(|attachment| attachment.opaque_bytes.clone())
                .collect(),
            classification: RecoveryClassification::ProvisionalDispatched,
        };
        let encoded = self
            .encode(|codec| codec.encode_recovery_terminal(&input))
            .ok()?;
        let mut candidate = self.state.clone();
        self.insert_terminal(
            &mut candidate,
            TerminalCommit {
                sequence,
                record: record.clone(),
                encoded,
                kind: TerminalKind::RecoveryDispatchFinalized,
                reason: Some(JournalReason::InterruptedAfterDispatch),
                recovered: true,
            },
        )
        .ok()?;
        self.commit_state(candidate).ok()?;
        Some(CoreRecoveryOutcome {
            action_obligation_id: sequence,
            classification: RecoveryClassification::ProvisionalDispatched,
            terminal_kind: TerminalKind::RecoveryDispatchFinalized,
            recovery_action: RecoveryAction::DispatchFinalized,
            attachments: attachments_from(&record.attachments),
        })
    }

    fn recover_rejection(
        &mut self,
        sequence: u64,
        record: ReservationRecord,
    ) -> Option<CoreRecoveryOutcome> {
        let marker = record.marker.clone()?;
        let (material, reason) = match marker {
            ReservationMarker::Rejection(material) => (material, None),
            ReservationMarker::Reduced(reason) => (
                RejectionMaterial {
                    rejection_material: Vec::new(),
                },
                Some(reason),
            ),
            ReservationMarker::DispatchCommitment => return None,
        };
        let encoded = if let Some(reason) = reason {
            let input = ReducedTerminalInput {
                action_obligation_id: sequence,
                identity: record.identity.clone(),
                reason,
                severity_inputs: None,
            };
            self.encode(|codec| codec.encode_reduced_terminal(&input))
                .ok()?
        } else {
            let input = RejectionInput {
                action_obligation_id: sequence,
                identity: record.identity.clone(),
                invocation_descriptor: record.invocation_descriptor.clone(),
                rejection_material: material.rejection_material,
            };
            self.encode(|codec| codec.encode_rejection(&input)).ok()?
        };
        let mut candidate = self.state.clone();
        self.insert_terminal(
            &mut candidate,
            TerminalCommit {
                sequence,
                record: record.clone(),
                encoded,
                kind: TerminalKind::RecoveryRejectionCommitted,
                reason,
                recovered: true,
            },
        )
        .ok()?;
        self.commit_state(candidate).ok()?;
        Some(CoreRecoveryOutcome {
            action_obligation_id: sequence,
            classification: RecoveryClassification::FailedRejection,
            terminal_kind: TerminalKind::RecoveryRejectionCommitted,
            recovery_action: RecoveryAction::RejectionCommitted,
            attachments: attachments_from(&record.attachments),
        })
    }

    fn cancel_recovery(
        &mut self,
        sequence: u64,
        record: ReservationRecord,
        classification: RecoveryClassification,
    ) -> Option<CoreRecoveryOutcome> {
        let mut candidate = self.state.clone();
        candidate.reservations.remove(&sequence)?;
        publish_transition(&mut candidate, sequence, TerminalKind::RecoveryCancelled);
        self.commit_state(candidate).ok()?;
        Some(CoreRecoveryOutcome {
            action_obligation_id: sequence,
            classification,
            terminal_kind: TerminalKind::RecoveryCancelled,
            recovery_action: RecoveryAction::Cancelled,
            attachments: attachments_from(&record.attachments),
        })
    }

    fn audit_from_terminal(&self, sequence: u64, entry: &TerminalRecord) -> ObligationAuditRecord {
        ObligationAuditRecord {
            action_obligation_id: sequence,
            lifecycle: match entry.kind {
                TerminalKind::RejectedCommitted | TerminalKind::RecoveryRejectionCommitted => {
                    LifecycleState::Rejected
                }
                TerminalKind::RecoveryCancelled => LifecycleState::Cancelled,
                _ => LifecycleState::Finalized,
            },
            terminal_kind: Some(entry.kind),
            descriptor_bytes: entry.invocation_descriptor.clone(),
            codec_id: entry.codec_id.clone(),
            attachment_slots: attachments_from(&entry.attachments),
            severity_inputs: entry.severity_inputs,
            severity: entry.severity,
            reason: entry.reason,
            recovery_supplied_terminal: entry.recovered,
        }
    }

    fn encode<F>(&self, operation: F) -> Result<EncodedJournalState, JournalError>
    where
        F: Fn(&C) -> Result<EncodedJournalState, JournalCodecError>,
    {
        let first = operation(&self.codec).map_err(map_codec_error)?;
        let second = operation(&self.codec).map_err(map_codec_error)?;
        if first != second {
            return Err(JournalError::CodecFailed);
        }
        if first.accounted_serialized_size > self.config.journal_max_entry_bytes {
            return Err(JournalError::EntryOversize);
        }
        if first.durable_bytes.is_empty()
            || first.accounted_serialized_size == 0
            || first.codec_version.is_empty()
        {
            return Err(JournalError::CodecFailed);
        }
        Ok(first)
    }

    fn insert_terminal(
        &self,
        candidate: &mut DurableState,
        commit: TerminalCommit,
    ) -> Result<(), JournalError> {
        let TerminalCommit {
            sequence,
            record,
            encoded,
            kind,
            reason,
            recovered,
        } = commit;
        let severity_inputs = record
            .dispatch
            .as_ref()
            .and_then(|material| material.severity_inputs);
        let severity = severity_inputs.and_then(|inputs| self.resolve_severity(inputs));
        let old_charge = record.charge;
        let mut terminal = TerminalRecord {
            identity: record.identity,
            invocation_descriptor: record.invocation_descriptor,
            bytes: encoded.durable_bytes,
            accounted_size: 0,
            codec_id: encoded.codec_version,
            kind,
            reason,
            severity_inputs,
            severity,
            attachments: record.attachments,
            recovered,
        };
        let terminal_charge = refresh_terminal_charge(&mut terminal)?;
        if !make_room_delta(candidate, old_charge, terminal_charge, self.config) {
            return Err(JournalError::ReservationFailed);
        }
        candidate.reservations.remove(&sequence);
        candidate.entries.insert(sequence, terminal);
        publish_transition(candidate, sequence, kind);
        Ok(())
    }

    fn commit_state(&mut self, candidate: DurableState) -> Result<(), JournalError> {
        self.storage
            .save(&candidate)
            .map_err(|_| JournalError::StorageUnavailable)?;
        self.state = candidate;
        Ok(())
    }
}

impl<C, S> JournalBinding<C, (), (), S>
where
    C: PlaneJournalCodec,
    S: JournalStorage,
{
    pub fn new_without_policies(
        codec: C,
        config: JournalConfig,
        storage: S,
    ) -> Result<Self, BindingError> {
        Self::new(codec, None, None, config, storage)
    }
}

fn map_codec_error(error: JournalCodecError) -> JournalError {
    match error {
        JournalCodecError::InvalidAccounting | JournalCodecError::VersionUnavailable => {
            JournalError::CodecFailed
        }
        JournalCodecError::DescriptorRefused => JournalError::CodecFailed,
        JournalCodecError::Failed => JournalError::CodecFailed,
    }
}

fn take_fault(state: &mut DurableState, point: &str) -> bool {
    match state.faults.get_mut(point) {
        Some(count) if *count > 0 => {
            *count -= 1;
            true
        }
        _ => false,
    }
}

fn refresh_reservation_charge(record: &mut ReservationRecord) -> Result<u64, JournalError> {
    // The charge itself is serialized, so setting it can change the number of
    // decimal digits in the record. Iterate to the stable serialized length.
    let codec_minimum = record.provisional.accounted_serialized_size;
    for _ in 0..4 {
        let serialized = serde_json::to_vec(record).map_err(|_| JournalError::CodecFailed)?;
        let serialized = u64::try_from(serialized.len()).map_err(|_| JournalError::CodecFailed)?;
        let charge = serialized.max(codec_minimum);
        if record.charge == charge {
            return Ok(charge);
        }
        record.charge = charge;
    }
    Err(JournalError::CodecFailed)
}

fn refresh_terminal_charge(record: &mut TerminalRecord) -> Result<u64, JournalError> {
    // Terminal accounting is the compact JSON representation persisted for this
    // entry, including its metadata and attachments rather than only payload bytes.
    for _ in 0..4 {
        let serialized = serde_json::to_vec(record).map_err(|_| JournalError::CodecFailed)?;
        let charge = u64::try_from(serialized.len()).map_err(|_| JournalError::CodecFailed)?;
        if record.accounted_size == charge {
            return Ok(charge);
        }
        record.accounted_size = charge;
    }
    Err(JournalError::CodecFailed)
}

fn retained_bytes(state: &DurableState) -> u64 {
    state
        .entries
        .values()
        .map(|entry| entry.accounted_size)
        .sum::<u64>()
        + state
            .reservations
            .values()
            .map(|record| record.charge)
            .sum::<u64>()
}

fn make_room(state: &mut DurableState, needed: u64, config: JournalConfig) -> bool {
    while retained_bytes(state).saturating_add(needed) > config.journal_retention_bytes {
        let Some(sequence) = state.entries.keys().next().copied() else {
            return false;
        };
        state.entries.remove(&sequence);
    }
    true
}

fn make_room_delta(
    state: &mut DurableState,
    old_charge: u64,
    new_charge: u64,
    config: JournalConfig,
) -> bool {
    let mut current = retained_bytes(state).saturating_sub(old_charge);
    while current.saturating_add(new_charge) > config.journal_retention_bytes {
        let Some(sequence) = state.entries.keys().next().copied() else {
            return false;
        };
        let Some(entry) = state.entries.remove(&sequence) else {
            return false;
        };
        current = current.saturating_sub(entry.accounted_size);
    }
    true
}

fn publish_transition(state: &mut DurableState, sequence: u64, kind: TerminalKind) {
    let cursor = state.next_cursor;
    state.next_cursor = state.next_cursor.saturating_add(1);
    state.transitions.push(TerminalTransition {
        cursor,
        action_obligation_id: sequence,
        kind,
    });
}

fn attachments_from(attachments: &BTreeMap<String, AttachmentState>) -> Vec<ObligationAttachment> {
    attachments
        .iter()
        .map(|(slot, attachment)| ObligationAttachment {
            slot: slot.clone(),
            revision: attachment.revision,
            opaque_bytes: attachment.opaque_bytes.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalStatus {
    pub entry_count: usize,
    pub oldest_retained_sequence: Option<u64>,
    pub newest_retained_sequence: Option<u64>,
    pub retained_bytes: u64,
    pub active_reservation_count: usize,
    pub active_reserved_bytes: u64,
    pub oversize_flag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    pub purged_entry_count: u64,
    pub purged_bytes: u64,
}

/// A policy object that is explicitly unavailable rather than a permissive
/// copy-through implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailablePolicy;

impl Redactor for UnavailablePolicy {
    fn available(&self) -> bool {
        false
    }

    fn redact(&self, _input: &str, _max_bytes: usize) -> Result<String, RedactionUnavailable> {
        Err(RedactionUnavailable)
    }
}

impl SeverityTaxonomy for UnavailablePolicy {
    fn version(&self) -> &str {
        "unavailable"
    }

    fn digest(&self) -> &str {
        "unavailable"
    }

    fn resolve(&self, _inputs: SeverityInputs) -> Option<SeverityRecord> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::codec::{
        CompletionInput, DispatchedInput, EncodedJournalState, ProvisionalInput,
        RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
    };

    #[derive(Debug, Clone, Copy)]
    struct FixtureCodec;

    impl PlaneJournalCodec for FixtureCodec {
        fn encode_provisional(
            &self,
            input: &ProvisionalInput,
        ) -> Result<EncodedJournalState, JournalCodecError> {
            Ok(encoded(format!("p:{}", input.action_obligation_id)))
        }

        fn encode_dispatched(
            &self,
            input: &DispatchedInput,
        ) -> Result<EncodedJournalState, JournalCodecError> {
            Ok(encoded(format!("d:{}", input.action_obligation_id)))
        }

        fn encode_rejection(
            &self,
            input: &RejectionInput,
        ) -> Result<EncodedJournalState, JournalCodecError> {
            Ok(encoded(format!("r:{}", input.action_obligation_id)))
        }

        fn encode_completion(
            &self,
            input: &CompletionInput,
        ) -> Result<EncodedJournalState, JournalCodecError> {
            Ok(encoded(format!("c:{}", input.action_obligation_id)))
        }

        fn encode_reduced_terminal(
            &self,
            input: &ReducedTerminalInput,
        ) -> Result<EncodedJournalState, JournalCodecError> {
            Ok(encoded(format!("x:{}", input.action_obligation_id)))
        }

        fn encode_recovery_terminal(
            &self,
            input: &RecoveryTerminalInput,
        ) -> Result<EncodedJournalState, JournalCodecError> {
            Ok(encoded(format!("y:{}", input.action_obligation_id)))
        }
    }

    fn encoded(text: String) -> EncodedJournalState {
        let durable_bytes = text.into_bytes();
        EncodedJournalState {
            accounted_serialized_size: durable_bytes.len() as u64,
            durable_bytes,
            codec_version: "fixture-v1".to_string(),
        }
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            principal: "p".to_string(),
            conversation_key: "c".to_string(),
            agent_project_id: "a".to_string(),
            session_kind: SessionKind::Primary,
        }
    }

    fn binding() -> JournalBinding<FixtureCodec, (), (), InMemoryJournalStorage> {
        JournalBinding::new_without_policies(
            FixtureCodec,
            JournalConfig {
                journal_retention_bytes: 1000,
                journal_max_entry_bytes: 100,
            },
            InMemoryJournalStorage::new(),
        )
        .unwrap()
    }

    #[test]
    fn codec_accounting_and_feed_are_durable() {
        let mut journal = binding();
        let handle = journal.reserve(identity(), vec![1]).unwrap();
        let token = journal
            .commit_dispatched(
                handle,
                DispatchMaterial {
                    dispatch_material: vec![2],
                    severity_inputs: None,
                    grant_decision: vec![],
                    governing_observation: None,
                },
            )
            .unwrap();
        journal
            .finalize_dispatched(
                token,
                CompletedResult {
                    completed_result: vec![3],
                },
                FinalContextAssociation {
                    final_context: vec![4],
                },
            )
            .unwrap();
        let transitions = journal.terminal_transitions(0).unwrap();
        assert_eq!(transitions[0].action_obligation_id, 1);
        assert_eq!(transitions[0].cursor, 1);
        assert_eq!(journal.export_bytes(), b"c:1");
    }

    #[test]
    fn attachments_use_compare_and_set_revisions() {
        let mut journal = binding();
        let handle = journal.reserve(identity(), vec![1]).unwrap();
        assert_eq!(
            journal.attach_obligation_material(handle, "slot", 0, vec![2]),
            Ok(1)
        );
        assert_eq!(
            journal.attach_obligation_material(handle, "slot", 0, vec![3]),
            Err(JournalError::AttachmentFailed)
        );
        assert_eq!(
            journal.attach_obligation_material(handle, "slot", 1, vec![3]),
            Ok(2)
        );
    }

    #[test]
    fn recovery_does_not_allocate_a_new_sequence() {
        let storage = InMemoryJournalStorage::new();
        let mut journal = JournalBinding::new_without_policies(
            FixtureCodec,
            JournalConfig {
                journal_retention_bytes: 1000,
                journal_max_entry_bytes: 100,
            },
            storage.clone(),
        )
        .unwrap();
        let handle = journal.reserve(identity(), vec![1]).unwrap();
        journal.arm_fault("commit_rejection", 1);
        journal
            .finalize_rejected(
                handle,
                RejectionMaterial {
                    rejection_material: vec![2],
                },
            )
            .unwrap_err();
        let next = journal.next_sequence();
        let outcomes = journal.recover_active();
        assert_eq!(outcomes[0].action_obligation_id, 1);
        assert_eq!(journal.next_sequence(), next);
        let reopened =
            JournalBinding::new_without_policies(FixtureCodec, journal.config(), storage).unwrap();
        assert_eq!(reopened.terminal_transitions(0).unwrap().len(), 1);
    }
}
