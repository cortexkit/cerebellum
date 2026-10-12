//! Compatibility binding between the frozen browser journal surface and the
//! neutral lifecycle in `cerebellum-core`.
//!
//! The adapter owns browser entry bytes and accounting. Core receives only the
//! already encoded bytes, so it cannot reinterpret or reserialize the frozen
//! export shape.

use cerebellum_core::journal::{
    CompletionInput, DispatchedInput, EncodedJournalState, JournalBinding, JournalCodecError,
    JournalConfig, JournalReason, JournalStorage, LateEventCause,
    LateEventError as CoreLateEventError, PlaneJournalCodec, ProvisionalInput, RecoveryAction,
    RecoveryClassification, RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
    UnavailablePolicy,
};

use super::late_events::LateEventError as BrowserLateEventError;
use super::recovery::{
    RecoveryAction as BrowserRecoveryAction,
    RecoveryClassification as BrowserRecoveryClassification,
};
/// The browser-owned codec version used for compatibility bytes.
pub const BROWSER_CODEC_VERSION: &str = super::FORMAT_VERSION;

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
            codec_version: if serde_json::from_slice::<serde_json::Value>(bytes)
                .ok()
                .is_some_and(|entry| entry["format_version"] == super::BASELINE_FORMAT_VERSION)
            {
                super::BASELINE_FORMAT_VERSION
            } else {
                BROWSER_CODEC_VERSION
            }
            .to_string(),
        })
    }
}

impl PlaneJournalCodec for BrowserJournalCodec {
    fn encode_provisional(
        &self,
        input: &ProvisionalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        if input.invocation_descriptor.len() == 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&input.invocation_descriptor);
            let accounted = u64::from_le_bytes(bytes);
            if accounted == 0 {
                return Err(JournalCodecError::InvalidAccounting);
            }
            return Ok(EncodedJournalState {
                durable_bytes: vec![0],
                accounted_serialized_size: accounted,
                codec_version: BROWSER_CODEC_VERSION.to_string(),
            });
        }
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

    /// Browser entries are carried as opaque bytes and exported as written;
    /// nothing in this module decodes them again, so no build can fail on a
    /// newer one and none is floored.
    fn entry_format(&self) -> Option<cerebellum_core::format_floor::DurableFormat> {
        None
    }

    fn entry_format_for(
        &self,
        codec_version: &str,
    ) -> Option<cerebellum_core::format_floor::DurableFormat> {
        // Only public_web_baseline entries need the v8 decision vocabulary.
        // Keeping ordinary entries at v7 lets older binaries serve them without
        // rewriting the journal or advancing its format floor.
        (codec_version == super::BASELINE_FORMAT_VERSION).then_some(super::BASELINE_ENTRY_FORMAT)
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
