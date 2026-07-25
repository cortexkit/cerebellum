//! Converts durable recovery results from the core journal into the
//! browser-facing recovery classifications and API.

use super::store::JournalStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClassification {
    UnmarkedOrphan,
    FailedRejection,
    FailedCommitment,
    ProvisionalDispatched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    Cancelled,
    RejectionCommitted,
    DispatchFinalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryOutcome {
    pub sequence: u64,
    pub classification: RecoveryClassification,
    pub action: RecoveryAction,
}

fn classification(
    value: cerebellum_core::journal::RecoveryClassification,
) -> RecoveryClassification {
    match value {
        cerebellum_core::journal::RecoveryClassification::UnmarkedOrphan => {
            RecoveryClassification::UnmarkedOrphan
        }
        cerebellum_core::journal::RecoveryClassification::FailedRejection => {
            RecoveryClassification::FailedRejection
        }
        cerebellum_core::journal::RecoveryClassification::FailedCommitment => {
            RecoveryClassification::FailedCommitment
        }
        cerebellum_core::journal::RecoveryClassification::ProvisionalDispatched => {
            RecoveryClassification::ProvisionalDispatched
        }
    }
}

fn action(value: cerebellum_core::journal::RecoveryAction) -> RecoveryAction {
    match value {
        cerebellum_core::journal::RecoveryAction::Cancelled => RecoveryAction::Cancelled,
        cerebellum_core::journal::RecoveryAction::RejectionCommitted => {
            RecoveryAction::RejectionCommitted
        }
        cerebellum_core::journal::RecoveryAction::DispatchFinalized => {
            RecoveryAction::DispatchFinalized
        }
    }
}

impl JournalStore {
    pub fn classify(&self, sequence: u64) -> Option<RecoveryClassification> {
        self.core.classify(sequence).map(classification)
    }

    pub fn recover_one(&mut self, sequence: u64) -> Option<RecoveryOutcome> {
        self.core
            .recover_one(sequence)
            .map(|outcome| RecoveryOutcome {
                sequence: outcome.action_obligation_id,
                classification: classification(outcome.classification),
                action: action(outcome.recovery_action),
            })
    }

    pub fn recover_all(&mut self) -> Vec<RecoveryOutcome> {
        self.core
            .recover_active()
            .into_iter()
            .map(|outcome| RecoveryOutcome {
                sequence: outcome.action_obligation_id,
                classification: classification(outcome.classification),
                action: action(outcome.recovery_action),
            })
            .collect()
    }
}
