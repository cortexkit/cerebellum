//! Compatibility binding between the frozen browser journal surface and the
//! neutral lifecycle in `cerebellum-core`.
//!
//! The adapter owns browser entry bytes and accounting. Core receives only the
//! already encoded bytes, so it cannot reinterpret or reserialize the frozen
//! export shape.

use cerebellum_core::journal::{
    CompletionInput, DispatchedInput, EncodedJournalState, JournalBinding, JournalCodecError,
    JournalConfig, JournalIdentity, JournalReason, JournalStorage, LateEventCause,
    LateEventError as CoreLateEventError, PlaneJournalCodec, ProvisionalInput, RecoveryAction,
    RecoveryClassification, RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
    UnavailablePolicy,
};

use super::late_events::LateEventError as BrowserLateEventError;
use super::recovery::{
    RecoveryAction as BrowserRecoveryAction,
    RecoveryClassification as BrowserRecoveryClassification,
};
use super::JournalEntry;

/// The browser-owned codec version used for compatibility bytes.
pub const BROWSER_CODEC_VERSION: &str = "ck-browser-journal/v1";

/// Codec that transports pre-encoded browser bytes without inspecting them.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserJournalCodec;

impl BrowserJournalCodec {
    fn encoded(bytes: &[u8]) -> Result<EncodedJournalState, JournalCodecError> {
        if bytes.is_empty() {
            return Err(JournalCodecError::DescriptorRefused);
        }
        Ok(EncodedJournalState {
            durable_bytes: bytes.to_vec(),
            accounted_serialized_size: bytes.len() as u64,
            codec_version: BROWSER_CODEC_VERSION.to_string(),
        })
    }

    /// Produce the exact frozen export bytes and accounted size for an entry.
    pub fn encode_entry(entry: &JournalEntry) -> EncodedJournalState {
        let bytes = entry.export_line().into_bytes();
        EncodedJournalState {
            accounted_serialized_size: bytes.len() as u64,
            durable_bytes: bytes,
            codec_version: BROWSER_CODEC_VERSION.to_string(),
        }
    }
}

impl PlaneJournalCodec for BrowserJournalCodec {
    fn encode_provisional(
        &self,
        input: &ProvisionalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encoded(&input.invocation_descriptor)
    }

    fn encode_dispatched(
        &self,
        input: &DispatchedInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encoded(&input.dispatch_material)
    }

    fn encode_rejection(
        &self,
        input: &RejectionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encoded(&input.rejection_material)
    }

    fn encode_completion(
        &self,
        input: &CompletionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encoded(&input.completed_result)
    }

    fn encode_reduced_terminal(
        &self,
        input: &ReducedTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encoded(input.reason.as_str().as_bytes())
    }

    fn encode_recovery_terminal(
        &self,
        input: &RecoveryTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encoded(&input.dispatch_material)
    }
}

/// A core binding with no implicit policy fallback.
pub type BrowserCoreJournal<S> =
    JournalBinding<BrowserJournalCodec, UnavailablePolicy, UnavailablePolicy, S>;

/// Open a browser-compatible neutral binding. The existing browser facade
/// remains responsible for constructing the opaque bytes and frozen fields.
pub fn open_browser_core_journal<S: JournalStorage>(
    config: JournalConfig,
    storage: S,
) -> Result<BrowserCoreJournal<S>, cerebellum_core::journal::BindingError> {
    JournalBinding::new(
        BrowserJournalCodec,
        Some(UnavailablePolicy),
        Some(UnavailablePolicy),
        config,
        storage,
    )
}

/// Convert an existing browser entry into the codec result used by core.
pub fn encode_browser_entry(entry: &JournalEntry) -> EncodedJournalState {
    BrowserJournalCodec::encode_entry(entry)
}

/// Map every neutral recovery classification to its frozen browser value.
pub fn map_recovery_classification(
    classification: RecoveryClassification,
) -> BrowserRecoveryClassification {
    match classification {
        RecoveryClassification::UnmarkedOrphan => BrowserRecoveryClassification::UnmarkedOrphan,
        RecoveryClassification::FailedRejection => BrowserRecoveryClassification::FailedRejection,
        RecoveryClassification::FailedCommitment => BrowserRecoveryClassification::FailedCommitment,
        RecoveryClassification::ProvisionalDispatched => {
            BrowserRecoveryClassification::ProvisionalDispatched
        }
    }
}

/// Map every neutral recovery action to its frozen browser value.
pub fn map_recovery_action(action: RecoveryAction) -> BrowserRecoveryAction {
    match action {
        RecoveryAction::Cancelled => BrowserRecoveryAction::Cancelled,
        RecoveryAction::RejectionCommitted => BrowserRecoveryAction::RejectionCommitted,
        RecoveryAction::DispatchFinalized => BrowserRecoveryAction::DispatchFinalized,
    }
}

/// Neutral causes that cannot be represented by the frozen browser surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableBrowserLateEventCause {
    BoundUnavailable,
    DescriptorRefused,
}

/// Preserve the browser surface's exactly four reachable late-event causes.
pub fn map_late_event_cause(
    error: CoreLateEventError,
) -> Result<BrowserLateEventError, UnreachableBrowserLateEventCause> {
    match error.cause {
        LateEventCause::QueueFull => Ok(BrowserLateEventError::QueueFull),
        LateEventCause::AllocatorFailed => Ok(BrowserLateEventError::AllocatorFailed),
        LateEventCause::CommitmentFailed => Ok(BrowserLateEventError::CommitmentFailed),
        LateEventCause::Backpressure => Ok(BrowserLateEventError::Backpressure),
        LateEventCause::BoundUnavailable => Err(UnreachableBrowserLateEventCause::BoundUnavailable),
        LateEventCause::DescriptorRefused => {
            Err(UnreachableBrowserLateEventCause::DescriptorRefused)
        }
    }
}

/// Keep the adapter's policy imports explicit: no policy error may disable
/// ordinary journal lifecycle operations.
pub fn reduced_reason(reason: JournalReason) -> &'static str {
    reason.as_str()
}

#[allow(dead_code)]
fn _identity_is_neutral(identity: JournalIdentity) -> JournalIdentity {
    identity
}
