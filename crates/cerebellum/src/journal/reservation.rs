//! Converts the core journal's lifecycle values and encoded data into the
//! vocabulary and codec types used by the browser-facing API.

use cerebellum_core::journal as core_journal;

use super::store::JournalStore;
use super::{
    Action, Capability, GoverningObservation, GrantDecision, JournalEntry, JournalError,
    JournalIdentity, JournalReasonCode, Locator, Outcome, Phase, Severity, FORMAT_VERSION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationHandle {
    pub(crate) core: core_journal::ReservationHandle,
}

impl ReservationHandle {
    pub(crate) fn from_core(core: core_journal::ReservationHandle) -> Self {
        Self { core }
    }

    pub fn sequence(&self) -> u64 {
        self.core.sequence()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchCommitmentToken {
    pub(crate) core: core_journal::DispatchCommitmentToken,
}

impl DispatchCommitmentToken {
    pub fn sequence(&self) -> u64 {
        self.core.sequence()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed;

#[derive(Debug, Clone, PartialEq)]
pub struct RejectionMaterial {
    pub intent_redacted: Option<String>,
    pub requested_severity: Option<Severity>,
    pub effective_severity: Option<Severity>,
    pub grant_decision: GrantDecision,
    pub governing_observation: GoverningObservation,
    pub action: Option<Action>,
    pub locator: Option<Locator>,
    pub snapshot_ids: Vec<String>,
    pub outcome: Outcome,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DispatchMaterial {
    pub intent_redacted: Option<String>,
    pub requested_severity: Option<Severity>,
    pub effective_severity: Option<Severity>,
    pub grant_decision: GrantDecision,
    /// Absent for an observation, which performs no action.
    ///
    /// The record's own `action` field has always been optional; this was the
    /// layer that could not express the absence, so every dispatch had to name
    /// an action whether or not one happened. That was tolerable while only
    /// actuating capabilities were journaled and became a lie the moment reads
    /// were.
    pub action: Option<Action>,
    pub locator: Option<Locator>,
    pub snapshot_ids: Vec<String>,
    pub governing_observation: GoverningObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalContextAssociation {
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompletedResult {
    pub outcome: Outcome,
    pub detail: serde_json::Value,
}

struct EntryMaterial {
    action: Option<Action>,
    locator: Option<Locator>,
    grant_decision: GrantDecision,
    governing_observation: GoverningObservation,
    intent_redacted: Option<String>,
    requested_severity: Option<Severity>,
    effective_severity: Option<Severity>,
    snapshot_ids: Vec<String>,
    outcome: Outcome,
    detail: serde_json::Value,
}

fn identity_entry(
    sequence: u64,
    identity: &JournalIdentity,
    capability: Capability,
    phase: Phase,
    material: EntryMaterial,
) -> JournalEntry {
    JournalEntry {
        format_version: FORMAT_VERSION.to_string(),
        sequence,
        phase,
        identity: identity.clone(),
        capability: Some(capability),
        intent_redacted: material.intent_redacted,
        requested_severity: material.requested_severity,
        effective_severity: material.effective_severity,
        grant_decision: material.grant_decision,
        governing_observation: material.governing_observation,
        action: material.action,
        locator: material.locator,
        snapshot_ids: material.snapshot_ids,
        outcome: Some(material.outcome),
        payload: None,
        detail: Some(material.detail),
    }
}

fn rejection_entry(
    sequence: u64,
    identity: &JournalIdentity,
    capability: Capability,
    material: &RejectionMaterial,
) -> JournalEntry {
    identity_entry(
        sequence,
        identity,
        capability,
        Phase::RejectedPreDispatch,
        EntryMaterial {
            action: material.action.clone(),
            locator: material.locator.clone(),
            grant_decision: material.grant_decision.clone(),
            governing_observation: material.governing_observation.clone(),
            intent_redacted: material.intent_redacted.clone(),
            requested_severity: material.requested_severity,
            effective_severity: material.effective_severity,
            snapshot_ids: material.snapshot_ids.clone(),
            outcome: material.outcome,
            detail: material.detail.clone(),
        },
    )
}

fn provisional_entry(
    sequence: u64,
    identity: &JournalIdentity,
    capability: Capability,
    material: &DispatchMaterial,
) -> JournalEntry {
    identity_entry(
        sequence,
        identity,
        capability,
        Phase::Dispatched,
        EntryMaterial {
            action: material.action.clone(),
            locator: material.locator.clone(),
            grant_decision: material.grant_decision.clone(),
            governing_observation: material.governing_observation.clone(),
            intent_redacted: material.intent_redacted.clone(),
            requested_severity: material.requested_severity,
            effective_severity: material.effective_severity,
            snapshot_ids: material.snapshot_ids.clone(),
            outcome: Outcome::InternalError,
            detail: serde_json::json!({
                "reason_code": JournalReasonCode::InterruptedAfterDispatch.as_str()
            }),
        },
    )
}

fn reduced_entry(
    sequence: u64,
    identity: &JournalIdentity,
    capability: Capability,
    reason: JournalReasonCode,
) -> JournalEntry {
    identity_entry(
        sequence,
        identity,
        capability,
        Phase::RejectedPreDispatch,
        EntryMaterial {
            action: None,
            locator: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            snapshot_ids: vec![],
            outcome: Outcome::InternalError,
            detail: serde_json::json!({ "reason_code": reason.as_str() }),
        },
    )
}

impl JournalStore {
    pub fn reserve(
        &mut self,
        identity: JournalIdentity,
        capability: Capability,
    ) -> Result<ReservationHandle, JournalError> {
        let handle = self.reserve_core(&identity, self.max_entry_bytes().to_le_bytes().to_vec())?;
        self.metadata
            .insert(handle.sequence(), (identity, capability));
        Ok(handle)
    }

    pub fn finalize_rejected(
        &mut self,
        handle: ReservationHandle,
        material: &RejectionMaterial,
    ) -> Result<Committed, JournalError> {
        let (identity, capability) = self
            .metadata
            .get(&handle.sequence())
            .cloned()
            .ok_or_else(JournalError::internal_failure)?;
        let entry = rejection_entry(handle.sequence(), &identity, capability, material);
        self.sync_faults_for_transition();
        self.core
            .finalize_rejected(
                handle.core,
                core_journal::RejectionMaterial {
                    rejection_material: entry.export_line().into_bytes(),
                },
            )
            .map(|_| Committed)
            .map_err(JournalStore::map_error)
    }

    pub fn commit_dispatched(
        &mut self,
        handle: ReservationHandle,
        material: &DispatchMaterial,
    ) -> Result<DispatchCommitmentToken, JournalError> {
        let (identity, capability) = self
            .metadata
            .get(&handle.sequence())
            .cloned()
            .ok_or_else(JournalError::internal_failure)?;
        let entry = provisional_entry(handle.sequence(), &identity, capability, material);
        self.sync_faults_for_transition();
        let token = self
            .core
            .commit_dispatched(
                handle.core,
                core_journal::DispatchMaterial {
                    dispatch_material: entry.export_line().into_bytes(),
                    severity_inputs: None,
                    grant_decision: Vec::new(),
                    governing_observation: None,
                },
            )
            .map_err(JournalStore::map_error)?;
        self.provisional.insert(handle.sequence(), entry);
        Ok(DispatchCommitmentToken { core: token })
    }

    pub fn finalize_dispatched(
        &mut self,
        token: DispatchCommitmentToken,
        final_context: &FinalContextAssociation,
        result: &CompletedResult,
    ) -> Result<Committed, JournalError> {
        let sequence = token.sequence();
        let mut entry = self
            .provisional
            .get(&sequence)
            .cloned()
            .ok_or_else(JournalError::internal_failure)?;
        entry.outcome = Some(result.outcome);
        entry.detail = Some(result.detail.clone());
        entry.identity.profile_uuid = final_context.profile_uuid.clone();
        entry.identity.profile_name = final_context.profile_name.clone();
        self.sync_faults_for_transition();
        self.core
            .finalize_dispatched(
                token.core,
                core_journal::CompletedResult {
                    completed_result: entry.export_line().into_bytes(),
                },
                core_journal::FinalContextAssociation {
                    final_context: Vec::new(),
                },
            )
            .map(|_| Committed)
            .map_err(JournalStore::map_error)
    }

    pub(crate) fn select_reduced(
        &mut self,
        handle: ReservationHandle,
        entry_reason: JournalReasonCode,
        visible_reason: JournalReasonCode,
    ) -> Result<JournalReasonCode, JournalError> {
        let (identity, capability) = self
            .metadata
            .get(&handle.sequence())
            .cloned()
            .ok_or_else(JournalError::internal_failure)?;
        let entry = reduced_entry(handle.sequence(), &identity, capability, entry_reason);
        if entry_reason == JournalReasonCode::JournalEntryOversize {
            self.set_oversize_flag();
        }
        self.sync_faults_for_transition();
        self.core
            .finalize_rejected(
                handle.core,
                core_journal::RejectionMaterial {
                    rejection_material: entry.export_line().into_bytes(),
                },
            )
            .map(|_| visible_reason)
            .map_err(JournalStore::map_error)
    }
}
