//! Short-lock access to the computer audit from blocking workers.
//!
//! A worker that runs platform work must not hold the audit lock while that
//! work runs: one application whose accessibility server hangs would then
//! stall journaling, and with it every action, on every other application.
//! The [`AuditToken`] carries a call's reserve, commit and finalize steps and
//! takes the shared lock only for the moment each step writes the journal.
//!
//! The commit step is also where an actuation asks the call's
//! [`MutationGate`]: an intent is committed only while the call has not been
//! stopped, so a worker that resumes after its call's terminal decision
//! records that nothing was sent instead of sending it.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use cerebellum_core::journal::redaction::Redactor;
use cerebellum_core::journal::severity::SeverityTaxonomy;
use cerebellum_core::journal::storage::JournalStorage;
use cerebellum_core::journal::{
    ActionObligationId, DispatchCommitmentToken, JournalIdentity, ReservationHandle,
};

use super::{
    ActuationIntent, ActuationOutcome, ComputerAudit, ComputerAuditError, ComputerCapability,
    ComputerPlaneDescriptor,
};
use crate::dispatch::{DispatchError, MutationGate, OpenGate};
use crate::platform::input_route::InputRouteEvidence;
use crate::platform::ProcessGrant;

/// The audit steps the dispatcher needs for one actuation.
///
/// Implemented by [`AuditToken`], which production workers use, and by
/// [`ComputerAudit`] itself for single-threaded callers that own the audit
/// outright and have no terminal decision to respect.
pub trait ActuationAudit {
    fn reserve_actuation(
        &mut self,
        identity: JournalIdentity,
        descriptor: ComputerPlaneDescriptor,
    ) -> Result<ReservationHandle, ComputerAuditError>;

    /// Ask the call's dispatch gate (see `MutationGate`) to start the
    /// mutation the next commit announces. False once the call has been
    /// stopped by its terminal decision; the dispatcher then commits nothing.
    fn begin_mutation(&self) -> bool;

    /// Whether the call has been stopped; checked between the posts of one
    /// sequence so no later ordinary post starts after a stop.
    fn mutation_stopped(&self) -> bool;

    fn commit_intent(
        &mut self,
        handle: ReservationHandle,
        descriptor: &ComputerPlaneDescriptor,
        intent: &ActuationIntent,
    ) -> Result<DispatchCommitmentToken, ComputerAuditError>;

    fn finalize_outcome(
        &mut self,
        token: DispatchCommitmentToken,
        outcome: &ActuationOutcome,
        routes: &InputRouteEvidence,
    ) -> Result<(), ComputerAuditError>;

    fn finalize_no_action(
        &mut self,
        handle: ReservationHandle,
        refusal: &DispatchError,
    ) -> Result<(), ComputerAuditError>;
}

impl<R, T, S> ActuationAudit for ComputerAudit<R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    fn reserve_actuation(
        &mut self,
        identity: JournalIdentity,
        descriptor: ComputerPlaneDescriptor,
    ) -> Result<ReservationHandle, ComputerAuditError> {
        self.reserve(identity, descriptor)
    }

    fn begin_mutation(&self) -> bool {
        OpenGate.begin_mutation()
    }

    fn mutation_stopped(&self) -> bool {
        OpenGate.stopped()
    }

    fn commit_intent(
        &mut self,
        handle: ReservationHandle,
        descriptor: &ComputerPlaneDescriptor,
        intent: &ActuationIntent,
    ) -> Result<DispatchCommitmentToken, ComputerAuditError> {
        self.commit_actuation_intent(handle, descriptor, intent)
    }

    fn finalize_outcome(
        &mut self,
        token: DispatchCommitmentToken,
        outcome: &ActuationOutcome,
        routes: &InputRouteEvidence,
    ) -> Result<(), ComputerAuditError> {
        self.finalize_actuation_outcome_with_routes(token, outcome, routes)
            .map(|_| ())
    }

    fn finalize_no_action(
        &mut self,
        handle: ReservationHandle,
        refusal: &DispatchError,
    ) -> Result<(), ComputerAuditError> {
        self.finalize_actuation_no_action(handle, refusal)
            .map(|_| ())
    }
}

/// A shared audit as the plane holds it.
pub type SharedAudit<R, T, S> = Arc<Mutex<ComputerAudit<R, T, S>>>;

/// Lock a shared audit for one short journal step.
///
/// A panic in another holder leaves the journal binding in whatever state its
/// own write left it; the binding validates every transition, so continuing
/// is safer than refusing every later action on every application.
pub fn lock_audit<R, T, S>(audit: &SharedAudit<R, T, S>) -> MutexGuard<'_, ComputerAudit<R, T, S>>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    audit
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One call's handle on the shared audit: reserve, commit and finalize, each
/// under its own short lock, with the commit gated by the call's
/// [`MutationGate`].
///
/// A step that finalizes an obligation this token already finalized is a
/// no-op, so a worker's cleanup path cannot turn a recorded outcome into a
/// journal error.
pub struct AuditToken<R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    audit: SharedAudit<R, T, S>,
    gate: Arc<dyn MutationGate>,
    reserved_ahead: Option<(ReservationHandle, ComputerPlaneDescriptor)>,
    finalized: BTreeSet<ActionObligationId>,
}

impl<R, T, S> AuditToken<R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    pub fn new(audit: SharedAudit<R, T, S>, gate: Arc<dyn MutationGate>) -> Self {
        Self {
            audit,
            gate,
            reserved_ahead: None,
            finalized: BTreeSet::new(),
        }
    }

    pub fn gate(&self) -> &Arc<dyn MutationGate> {
        &self.gate
    }

    /// Run one journal step under the shared lock. The closure must not do
    /// platform work: the lock is shared by every application's actions.
    pub fn with_audit<X>(&self, step: impl FnOnce(&mut ComputerAudit<R, T, S>) -> X) -> X {
        step(&mut lock_audit(&self.audit))
    }

    /// Reserve the actuation's journal entry before the blocking worker
    /// starts, so the entry exists whatever the worker later does. The
    /// dispatcher's own reservation then uses it rather than reserving again.
    pub fn reserve_ahead(
        &mut self,
        identity: JournalIdentity,
        descriptor: ComputerPlaneDescriptor,
    ) -> Result<(), ComputerAuditError> {
        let handle = self.with_audit(|audit| audit.reserve(identity, descriptor.clone()))?;
        self.reserved_ahead = Some((handle, descriptor));
        Ok(())
    }

    /// The reservation made ahead that no dispatch consumed, if any. A worker
    /// that ends before dispatching closes it with
    /// [`AuditToken::release_unused`].
    pub fn has_unused_reservation(&self) -> bool {
        self.reserved_ahead.is_some()
    }

    /// Close an unused reservation made ahead as an action that never ran.
    pub fn release_unused(&mut self, refusal: &DispatchError) -> Result<(), ComputerAuditError> {
        match self.reserved_ahead.take() {
            Some((handle, _)) => self.finalize_no_action(handle, refusal),
            None => Ok(()),
        }
    }

    /// Record a read that may change application state (an accessibility
    /// opt-in) on its own entry. The read itself runs without the shared
    /// audit lock; only the reserve, commit and finalize steps take it.
    pub fn record_accessibility_read<U>(
        &mut self,
        identity: JournalIdentity,
        capability: ComputerCapability,
        grant: &ProcessGrant,
        read: impl FnOnce() -> U,
    ) -> Result<U, ComputerAuditError> {
        let descriptor = ComputerPlaneDescriptor::new(
            capability,
            crate::grounding::ContainmentRung::SemanticElement,
            super::ObservationState::HumanUnobserved,
        );
        let token = self.with_audit(|audit| {
            let handle = audit.reserve(identity, descriptor.clone())?;
            audit.commit_actuation_intent(
                handle,
                &descriptor,
                &ActuationIntent {
                    element: None,
                    action: capability.capability_id().to_string(),
                    grant_identity: grant.clone(),
                },
            )
        })?;
        let result = read();
        self.finalize_dispatched(
            token,
            br#"{"outcome":"read_attempted"}"#.to_vec(),
            Vec::new(),
        )?;
        Ok(result)
    }

    /// Record a refusal decided before anything was sent, on its own entry.
    pub fn reject(
        &mut self,
        identity: JournalIdentity,
        descriptor: ComputerPlaneDescriptor,
        rejection_material: Vec<u8>,
    ) -> Result<(), ComputerAuditError> {
        let handle = self.with_audit(|audit| audit.reserve(identity, descriptor))?;
        self.finalize_rejected(handle, rejection_material)
    }

    pub fn finalize_dispatched(
        &mut self,
        token: DispatchCommitmentToken,
        completed_result: Vec<u8>,
        final_context: Vec<u8>,
    ) -> Result<(), ComputerAuditError> {
        let id = token.action_obligation_id();
        if self.finalized.contains(&id) {
            return Ok(());
        }
        self.with_audit(|audit| audit.finalize_dispatched(token, completed_result, final_context))?;
        self.finalized.insert(id);
        Ok(())
    }

    pub fn finalize_rejected(
        &mut self,
        handle: ReservationHandle,
        rejection_material: Vec<u8>,
    ) -> Result<(), ComputerAuditError> {
        let id = handle.action_obligation_id();
        if self.finalized.contains(&id) {
            return Ok(());
        }
        self.with_audit(|audit| audit.finalize_rejected(handle, rejection_material))?;
        self.finalized.insert(id);
        Ok(())
    }
}

impl<R, T, S> ActuationAudit for AuditToken<R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    fn reserve_actuation(
        &mut self,
        identity: JournalIdentity,
        descriptor: ComputerPlaneDescriptor,
    ) -> Result<ReservationHandle, ComputerAuditError> {
        match self.reserved_ahead.take() {
            Some((handle, reserved)) if reserved == descriptor => Ok(handle),
            ahead => {
                // A reservation made ahead for another descriptor would leave
                // an entry nothing finalizes; close it before reserving anew.
                if let Some((handle, _)) = ahead {
                    self.finalize_no_action(handle, &DispatchError::InvalidRequest)?;
                }
                self.with_audit(|audit| audit.reserve(identity, descriptor))
            }
        }
    }

    fn begin_mutation(&self) -> bool {
        self.gate.begin_mutation()
    }

    fn mutation_stopped(&self) -> bool {
        self.gate.stopped()
    }

    fn commit_intent(
        &mut self,
        handle: ReservationHandle,
        descriptor: &ComputerPlaneDescriptor,
        intent: &ActuationIntent,
    ) -> Result<DispatchCommitmentToken, ComputerAuditError> {
        self.with_audit(|audit| audit.commit_actuation_intent(handle, descriptor, intent))
    }

    fn finalize_outcome(
        &mut self,
        token: DispatchCommitmentToken,
        outcome: &ActuationOutcome,
        routes: &InputRouteEvidence,
    ) -> Result<(), ComputerAuditError> {
        let id = token.action_obligation_id();
        if self.finalized.contains(&id) {
            return Ok(());
        }
        self.with_audit(|audit| {
            audit.finalize_actuation_outcome_with_routes(token, outcome, routes)
        })?;
        self.finalized.insert(id);
        Ok(())
    }

    fn finalize_no_action(
        &mut self,
        handle: ReservationHandle,
        refusal: &DispatchError,
    ) -> Result<(), ComputerAuditError> {
        let id = handle.action_obligation_id();
        if self.finalized.contains(&id) {
            return Ok(());
        }
        self.with_audit(|audit| audit.finalize_actuation_no_action(handle, refusal))?;
        self.finalized.insert(id);
        Ok(())
    }
}
