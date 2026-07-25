//! Opaque codec seams used by the journal lifecycle.
//!
//! The shared lifecycle stores bytes and bounded facts, while each execution
//! plane owns the meaning and serialization of those bytes. Keeping the seam
//! here deliberately small prevents the lifecycle from learning action or
//! wire vocabulary.

use super::{JournalIdentity, SeverityInputs};

/// Exact bytes and accounting returned by a plane-owned journal codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedJournalState {
    pub durable_bytes: Vec<u8>,
    pub accounted_serialized_size: u64,
    pub codec_version: String,
}

/// Opaque material supplied when an obligation is reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalInput {
    pub action_obligation_id: u64,
    pub identity: JournalIdentity,
    pub invocation_descriptor: Vec<u8>,
}

/// Opaque material supplied before an external side effect begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchedInput {
    pub action_obligation_id: u64,
    pub identity: JournalIdentity,
    pub invocation_descriptor: Vec<u8>,
    pub dispatch_material: Vec<u8>,
    pub severity_inputs: Option<SeverityInputs>,
    pub grant_decision: Vec<u8>,
    pub governing_observation: Option<Vec<u8>>,
}

/// Opaque material supplied for a pre-dispatch rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectionInput {
    pub action_obligation_id: u64,
    pub identity: JournalIdentity,
    pub invocation_descriptor: Vec<u8>,
    pub rejection_material: Vec<u8>,
}

/// Opaque completed result and final association material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionInput {
    pub action_obligation_id: u64,
    pub identity: JournalIdentity,
    pub dispatch_material: Vec<u8>,
    pub completed_result: Vec<u8>,
    pub final_context: Vec<u8>,
    pub severity_inputs: Option<SeverityInputs>,
    pub attachments: Vec<Vec<u8>>,
}

/// A reduced terminal state used when the complete plane payload cannot be
/// safely encoded. The lifecycle still records that the obligation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReducedTerminalInput {
    pub action_obligation_id: u64,
    pub identity: JournalIdentity,
    pub reason: super::JournalReason,
    pub severity_inputs: Option<SeverityInputs>,
}

/// Material replayed by recovery without asking the caller to rebuild it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryTerminalInput {
    pub action_obligation_id: u64,
    pub identity: JournalIdentity,
    pub dispatch_material: Vec<u8>,
    pub invocation_descriptor: Vec<u8>,
    pub severity_inputs: Option<SeverityInputs>,
    pub attachments: Vec<Vec<u8>>,
    pub classification: super::RecoveryClassification,
}

/// A codec failure. The lifecycle never exposes codec implementation details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalCodecError {
    Failed,
    DescriptorRefused,
    InvalidAccounting,
    VersionUnavailable,
}

/// Plane-owned serialization and accounting contract.
///
/// Implementations must be deterministic. Core calls the selected operation
/// twice before committing it and rejects different bytes, versions, or sizes.
pub trait PlaneJournalCodec {
    fn encode_provisional(
        &self,
        input: &ProvisionalInput,
    ) -> Result<EncodedJournalState, JournalCodecError>;

    fn encode_dispatched(
        &self,
        input: &DispatchedInput,
    ) -> Result<EncodedJournalState, JournalCodecError>;

    fn encode_rejection(
        &self,
        input: &RejectionInput,
    ) -> Result<EncodedJournalState, JournalCodecError>;

    fn encode_completion(
        &self,
        input: &CompletionInput,
    ) -> Result<EncodedJournalState, JournalCodecError>;

    fn encode_reduced_terminal(
        &self,
        input: &ReducedTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError>;

    fn encode_recovery_terminal(
        &self,
        input: &RecoveryTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError>;
}

impl<T: PlaneJournalCodec + ?Sized> PlaneJournalCodec for Box<T> {
    fn encode_provisional(
        &self,
        input: &ProvisionalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        (**self).encode_provisional(input)
    }

    fn encode_dispatched(
        &self,
        input: &DispatchedInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        (**self).encode_dispatched(input)
    }

    fn encode_rejection(
        &self,
        input: &RejectionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        (**self).encode_rejection(input)
    }

    fn encode_completion(
        &self,
        input: &CompletionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        (**self).encode_completion(input)
    }

    fn encode_reduced_terminal(
        &self,
        input: &ReducedTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        (**self).encode_reduced_terminal(input)
    }

    fn encode_recovery_terminal(
        &self,
        input: &RecoveryTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        (**self).encode_recovery_terminal(input)
    }
}
