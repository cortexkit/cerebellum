//! The invocation-bound frozen journal pin (Spec B2A, slice S10).
//!
//! This is the in-process journal pin consumed one-way by Spec B1 and Spec B2B.
//! It wraps the slice S7 [`JournalStore`] (the durable allocator, reservation,
//! transition-marker, and recovery substrate) and adds the invocation-binding,
//! strict bind-fact / current-open validation, non-mutating transition
//! preflight, and the B2B association seam that the S7 substrate deliberately
//! leaves to this slice.
//!
//! # Invocation binding
//!
//! Every reservation handle and dispatch-commitment token is opaque (its field
//! is private and never caller-constructed, persisted, exported, or returned
//! across invocations) and is bound to the [`InvocationToken`] that created it.
//! A transition call names the caller's invocation token; the pin verifies the
//! handle's owning invocation matches before any journal mutation. Invalid,
//! malformed, stale, mismatched, and cross-invocation calls are rejected by a
//! read-only preflight that never touches the store, so they create no marker
//! and no journal mutation.
//!
//! # Preflight ordering
//!
//! Strict bind-fact and current-open association validation precede `reserve`
//! and fail with `internal_failure` without allocating a sequence. Each
//! transition call runs a non-mutating preflight (invocation ownership and
//! invocation-side state) before S7 establishes any transition-attempt marker.
//! Once a post-preflight call returns `journal_reservation_failed`, the
//! invocation side is permanently locked out of that reservation: retry and
//! cancellation belong exclusively to S7 writer recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::journal::reservation::{
    Committed, CompletedResult, DispatchCommitmentToken, DispatchMaterial, FinalContextAssociation,
    RejectionMaterial, ReservationHandle,
};
use crate::journal::store::JournalStore;
use crate::journal::{Capability, JournalError, JournalIdentity, JournalReasonCode, SessionKind};

/// An opaque, process-local invocation token.
///
/// Minted by the pin's invocation seam and never caller-supplied, persisted,
/// exported, or returned across invocations. It identifies the invocation that
/// owns a reservation handle or commitment token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InvocationToken(u64);

/// An opaque, invocation-bound reservation handle.
///
/// Wraps the allocated sequence but is never caller-constructed or reused
/// across invocations. The sequence accessor is exposed for the in-process
/// conformance seam only; production callers treat the handle as opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinReservationHandle {
    sequence: u64,
}

impl PinReservationHandle {
    /// The allocated sequence (conformance-seam correlation only).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// An opaque, invocation-bound dispatch-commitment token.
///
/// Returned by a successful `commit_dispatched` and required by
/// `finalize_dispatched`. Never caller-constructed or reused across
/// invocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinCommitmentToken {
    sequence: u64,
}

impl PinCommitmentToken {
    /// The committed sequence (conformance-seam correlation only).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Provenance of a bind fact.
///
/// The strict bind-fact contract consumes daemon-attested source facts BEFORE
/// any compatibility constructor, fallback, defaulting parser, or local
/// derivation can erase their provenance. A value that arrived through a
/// compatibility path is ineligible for a B2A-enabled route even when its
/// normalized shape is otherwise valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactProvenance {
    /// An original daemon-attested source fact.
    DaemonAttested,
    /// A value produced by a compatibility constructor, fallback, defaulting
    /// parser, or local derivation. Ineligible for B2A-enabled routes.
    CompatibilityDerived,
}

/// Daemon-stamped bind facts presented for strict validation before `reserve`.
///
/// These are the immutable identity facts the invocation seam validated under
/// the strict bind-fact contract. The pin never substitutes `project_root` for
/// an absent `agent_project_id`, defaults an absent session kind to `primary`,
/// derives profile disposition locally, widens absent capability scope, or
/// synthesizes a principal projection from caller material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedBindFacts {
    /// The canonical principal projection (never a raw identity string and
    /// never the forbidden `not mcp:*` rule).
    pub principal: String,
    pub conversation_key: String,
    pub agent_project_id: String,
    pub session_kind: SessionKind,
    /// Whether these facts arrived daemon-attested or via a compatibility path.
    pub provenance: FactProvenance,
}

/// The B2B-published current-open fact tuple for one live session.
///
/// `profile_uuid` and `profile_name` are both null when `valid` is true and the
/// association positively reports no context open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentOpenFacts {
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
    pub association_epoch: u64,
    pub valid: bool,
}

/// One atomic read of the B2B current-open publication channel.
///
/// Carries the current-open fact tuple and the session's current association
/// epoch published on the same channel at read time. The tuple is stale when
/// `valid` is false or when its `association_epoch` does not match
/// `current_association_epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentOpenPublication {
    pub facts: CurrentOpenFacts,
    pub current_association_epoch: u64,
}

/// The invocation-side lifecycle state of one reserved sequence.
///
/// This is pin-level state layered over the S7 reservation record; it tracks
/// what the invocation side may still do, independently of the durable marker
/// state that S7 recovery owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinState {
    /// Reserved; no invocation-side transition has been attempted yet.
    Active,
    /// A post-preflight transition call returned `journal_reservation_failed`;
    /// the invocation side is permanently locked out and S7 writer recovery
    /// exclusively owns retry or cancellation.
    Locked,
    /// A rejection was finalized: a no-commit completion decision. No dispatch
    /// commitment may follow.
    NoCommitComplete,
    /// Dispatch was committed; `finalize_dispatched` may follow.
    Dispatched,
    /// The dispatched result was finalized (terminal).
    Finalized,
}

/// An opaque prepared-open reference associated with a reservation.
///
/// Conveys only that a no-commit completion path requires an abort attempt; it
/// exposes no profile path, registry record, grant, or preparation mechanics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOpenRef(pub String);

/// The observed B2B-defined outcome of a required abort attempt.
///
/// B2A records only that the call reached an outcome before invocation
/// completion; it does not interpret the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortOutcome {
    Completed,
    Failed,
}

/// A conformance violation observed on the association seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeamViolation {
    /// A launch was observed for a reservation with no matching durable
    /// dispatch commitment, or before the invocation owned it.
    LaunchWithoutCommitment { sequence: u64 },
    /// A conflicting abort-outcome recording was attempted for a reservation
    /// that already recorded a different outcome.
    ConflictingAbortOutcome { sequence: u64 },
    /// A conflicting prepared-open reference was associated with a reservation
    /// that already carried a different reference.
    ConflictingPreparedOpen { sequence: u64 },
    /// A conflicting final-context association was recorded for a commitment
    /// that already carried a different one.
    ConflictingFinalContext { sequence: u64 },
}

/// The B2B journal-association conformance seam.
///
/// Records the associations among invocation tokens, reservation handles,
/// commitment tokens, reservation-time current-open associations, token-bound
/// final-context associations, prepared-open references, and required
/// abort-attempt outcome signals. It proves that no journal object crosses
/// invocations, every launch follows a matching durable commitment, and exactly
/// one logical abort attempt is observed for each associated no-commit
/// invocation. It does not duplicate B2B preparation, abort, restoration, or
/// launch mechanics.
#[derive(Debug, Default)]
pub struct AssociationSeam {
    reservation_invocation: BTreeMap<u64, InvocationToken>,
    reservation_association: BTreeMap<u64, CurrentOpenFacts>,
    commitment_invocation: BTreeMap<u64, InvocationToken>,
    final_context: BTreeMap<u64, FinalContextAssociation>,
    prepared_open: BTreeMap<u64, PreparedOpenRef>,
    abort_outcomes: BTreeMap<u64, AbortOutcome>,
    launched: BTreeSet<u64>,
    violations: Vec<SeamViolation>,
}

impl AssociationSeam {
    fn record_reservation(
        &mut self,
        sequence: u64,
        token: InvocationToken,
        assoc: CurrentOpenFacts,
    ) {
        self.reservation_invocation.insert(sequence, token);
        self.reservation_association.insert(sequence, assoc);
    }

    fn record_commitment(&mut self, sequence: u64, token: InvocationToken) {
        self.commitment_invocation.insert(sequence, token);
    }

    /// Record the immutable token-bound final-context association.
    ///
    /// Byte-identical recording is idempotent; a conflicting association is
    /// rejected and recorded as a violation.
    fn record_final_context(&mut self, sequence: u64, assoc: FinalContextAssociation) {
        match self.final_context.get(&sequence) {
            Some(existing) if existing == &assoc => {}
            Some(_) => self
                .violations
                .push(SeamViolation::ConflictingFinalContext { sequence }),
            None => {
                self.final_context.insert(sequence, assoc);
            }
        }
    }

    /// Associate an opaque prepared-open reference with a reservation.
    ///
    /// Repeating the same association is idempotent; a different reference is
    /// rejected and recorded as a violation.
    pub fn associate_prepared_open(
        &mut self,
        sequence: u64,
        reference: PreparedOpenRef,
    ) -> Result<(), SeamViolation> {
        match self.prepared_open.get(&sequence) {
            Some(existing) if existing == &reference => Ok(()),
            Some(_) => {
                let violation = SeamViolation::ConflictingPreparedOpen { sequence };
                self.violations.push(violation.clone());
                Err(violation)
            }
            None => {
                self.prepared_open.insert(sequence, reference);
                Ok(())
            }
        }
    }

    /// Record the observed outcome of the required abort attempt for a
    /// reservation that completed without a dispatch commitment.
    ///
    /// Exactly one logical abort attempt is recorded per associated no-commit
    /// invocation: byte-identical recording is idempotent, a conflicting
    /// outcome is rejected and recorded as a violation.
    pub fn record_abort_outcome(
        &mut self,
        sequence: u64,
        outcome: AbortOutcome,
    ) -> Result<(), SeamViolation> {
        match self.abort_outcomes.get(&sequence) {
            Some(existing) if *existing == outcome => Ok(()),
            Some(_) => {
                let violation = SeamViolation::ConflictingAbortOutcome { sequence };
                self.violations.push(violation.clone());
                Err(violation)
            }
            None => {
                self.abort_outcomes.insert(sequence, outcome);
                Ok(())
            }
        }
    }

    /// Record that a browser-side launch was observed for a reservation.
    ///
    /// A launch is permitted only after a matching durable dispatch commitment;
    /// observing one without a commitment is a violation.
    fn observe_launch(&mut self, sequence: u64) -> Result<(), SeamViolation> {
        if !self.commitment_invocation.contains_key(&sequence) {
            let violation = SeamViolation::LaunchWithoutCommitment { sequence };
            self.violations.push(violation.clone());
            return Err(violation);
        }
        self.launched.insert(sequence);
        Ok(())
    }

    /// The invocation that owns the reservation, if any.
    pub fn reservation_invocation(&self, sequence: u64) -> Option<InvocationToken> {
        self.reservation_invocation.get(&sequence).copied()
    }

    /// The reservation-time current-open association bound to a reservation.
    pub fn reservation_association(&self, sequence: u64) -> Option<&CurrentOpenFacts> {
        self.reservation_association.get(&sequence)
    }

    /// Whether a durable dispatch commitment exists for the reservation under
    /// the given invocation.
    pub fn has_commitment(&self, sequence: u64, token: InvocationToken) -> bool {
        self.commitment_invocation.get(&sequence) == Some(&token)
    }

    /// The immutable final-context association recorded for a commitment.
    pub fn final_context(&self, sequence: u64) -> Option<&FinalContextAssociation> {
        self.final_context.get(&sequence)
    }

    /// Whether a prepared-open reference is associated with the reservation.
    pub fn has_prepared_open(&self, sequence: u64) -> bool {
        self.prepared_open.contains_key(&sequence)
    }

    /// The number of logical abort-attempt outcomes recorded for a reservation
    /// (always 0 or 1: byte-identical recording is idempotent).
    pub fn abort_attempt_count(&self, sequence: u64) -> usize {
        usize::from(self.abort_outcomes.contains_key(&sequence))
    }

    /// Whether a launch was observed for the reservation.
    pub fn is_launched(&self, sequence: u64) -> bool {
        self.launched.contains(&sequence)
    }

    /// All conformance violations observed so far.
    pub fn violations(&self) -> &[SeamViolation] {
        &self.violations
    }
}

/// The invocation-bound journal pin over the S7 [`JournalStore`].
#[derive(Debug)]
pub struct JournalPin {
    store: JournalStore,
    next_invocation: u64,
    /// Sequence -> owning invocation. Permanent: retained after finalization so
    /// stale and cross-invocation use can still be detected and rejected.
    owners: BTreeMap<u64, InvocationToken>,
    /// Sequence -> invocation-side lifecycle state.
    states: BTreeMap<u64, PinState>,
    seam: AssociationSeam,
}

impl JournalPin {
    /// Build a pin over an already-opened S7 store.
    pub fn new(store: JournalStore) -> Self {
        Self {
            store,
            next_invocation: 1,
            owners: BTreeMap::new(),
            states: BTreeMap::new(),
            seam: AssociationSeam::default(),
        }
    }

    /// The underlying S7 store (read-only; for export and status surfaces).
    pub fn store(&self) -> &JournalStore {
        &self.store
    }

    /// The underlying S7 store (mutable; for the administration surface and
    /// recovery).
    pub fn store_mut(&mut self) -> &mut JournalStore {
        &mut self.store
    }

    /// The association conformance seam.
    pub fn seam(&self) -> &AssociationSeam {
        &self.seam
    }

    /// The association conformance seam (mutable).
    pub fn seam_mut(&mut self) -> &mut AssociationSeam {
        &mut self.seam
    }

    /// The point-in-time journal export snapshot (delegates to S7).
    pub fn export(&self) -> String {
        self.store.export()
    }

    /// Mint a fresh opaque invocation token for a new invocation.
    pub fn mint_invocation(&mut self) -> InvocationToken {
        let id = self.next_invocation;
        self.next_invocation = self.next_invocation.saturating_add(1);
        InvocationToken(id)
    }

    /// Reserve durable journal capacity for one parsed unfenceable invocation.
    ///
    /// Strict bind-fact validation and the atomic B2B current-open association
    /// read both precede allocation; their failure returns `internal_failure`
    /// without allocating a sequence or invoking the S7 reserve. Allocation or
    /// establishment failure returns only `journal_reservation_failed`.
    pub fn reserve(
        &mut self,
        token: InvocationToken,
        capability: Capability,
        bind_facts: &StampedBindFacts,
        publication: &CurrentOpenPublication,
    ) -> Result<PinReservationHandle, JournalError> {
        // Strict bind-fact validation BEFORE allocation.
        validate_bind_facts(bind_facts)?;
        // Current-open association validation BEFORE allocation.
        let assoc = validate_current_open(publication)?;
        // Build the reservation-bound identity from the validated facts only;
        // profile facts come from the validated current-open association.
        let identity = JournalIdentity {
            principal: bind_facts.principal.clone(),
            conversation_key: bind_facts.conversation_key.clone(),
            agent_project_id: bind_facts.agent_project_id.clone(),
            session_kind: bind_facts.session_kind,
            profile_uuid: assoc.profile_uuid.clone(),
            profile_name: assoc.profile_name.clone(),
        };
        // S7 reserve: durably advances the allocator and establishes the
        // reservation. Failure is journal_reservation_failed.
        let handle = self.store.reserve(identity, capability)?;
        let sequence = handle.sequence();
        self.owners.insert(sequence, token);
        self.states.insert(sequence, PinState::Active);
        self.seam.record_reservation(sequence, token, assoc);
        Ok(PinReservationHandle { sequence })
    }

    /// Finalize a reservation as one exportable `rejected_pre_dispatch` entry.
    ///
    /// Runs the non-mutating preflight before S7 establishes any marker. A
    /// successful rejection is a no-commit completion decision. A post-preflight
    /// `journal_reservation_failed` permanently locks the invocation side out of
    /// the reservation.
    pub fn finalize_rejected(
        &mut self,
        token: InvocationToken,
        handle: PinReservationHandle,
        material: &RejectionMaterial,
    ) -> Result<Committed, JournalError> {
        let sequence = handle.sequence;
        // Allowed from Active (first attempt) or NoCommitComplete (byte-identical
        // idempotent retry of an already-committed rejection).
        self.preflight(
            token,
            sequence,
            &[PinState::Active, PinState::NoCommitComplete],
        )?;
        let was_active = self.states.get(&sequence) == Some(&PinState::Active);
        match self
            .store
            .finalize_rejected(ReservationHandle(sequence), material)
        {
            Ok(committed) => {
                self.states.insert(sequence, PinState::NoCommitComplete);
                Ok(committed)
            }
            Err(e) if e.reason_code == JournalReasonCode::JournalReservationFailed => {
                if was_active {
                    self.states.insert(sequence, PinState::Locked);
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Commit a reservation as an exportable, active provisional `dispatched`
    /// entry and return the matching invocation-bound commitment token.
    ///
    /// No browser-side dispatch is permitted before this succeeds. A
    /// post-preflight `journal_reservation_failed` permanently locks the
    /// invocation side out of the reservation.
    pub fn commit_dispatched(
        &mut self,
        token: InvocationToken,
        handle: PinReservationHandle,
        material: &DispatchMaterial,
    ) -> Result<PinCommitmentToken, JournalError> {
        let sequence = handle.sequence;
        // Allowed from Active (first) or Dispatched (byte-identical idempotent
        // retry of an already-committed dispatch).
        self.preflight(token, sequence, &[PinState::Active, PinState::Dispatched])?;
        let was_active = self.states.get(&sequence) == Some(&PinState::Active);
        match self
            .store
            .commit_dispatched(ReservationHandle(sequence), material)
        {
            Ok(_s7_token) => {
                self.states.insert(sequence, PinState::Dispatched);
                self.seam.record_commitment(sequence, token);
                Ok(PinCommitmentToken { sequence })
            }
            Err(e) if e.reason_code == JournalReasonCode::JournalReservationFailed => {
                if was_active {
                    self.states.insert(sequence, PinState::Locked);
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Finalize a dispatch commitment with the completed B1 result.
    ///
    /// Requires the matching commitment token: the reservation must be owned by
    /// this invocation and in the Dispatched state, which only a successful
    /// `commit_dispatched` under the same token reaches. Journal profile facts
    /// are set from the immutable token-bound final-context association. Failure
    /// leaves the provisional entry authoritative and the state Dispatched so a
    /// corrected retry remains possible for this invocation.
    pub fn finalize_dispatched(
        &mut self,
        token: InvocationToken,
        commitment: PinCommitmentToken,
        final_context: &FinalContextAssociation,
        result: &CompletedResult,
    ) -> Result<Committed, JournalError> {
        let sequence = commitment.sequence;
        // Allowed from Dispatched (first) or Finalized (byte-identical
        // idempotent retry of an already-finalized result).
        self.preflight(
            token,
            sequence,
            &[PinState::Dispatched, PinState::Finalized],
        )?;
        match self.store.finalize_dispatched(
            DispatchCommitmentToken(sequence),
            final_context,
            result,
        ) {
            Ok(committed) => {
                self.states.insert(sequence, PinState::Finalized);
                self.seam
                    .record_final_context(sequence, final_context.clone());
                Ok(committed)
            }
            Err(e) => Err(e),
        }
    }

    // ------------------------------------------------------------------
    // B2B association seam operations (invocation-checked)
    // ------------------------------------------------------------------

    /// Associate an opaque prepared-open reference with an active reservation.
    ///
    /// The reference must be associated by the owning invocation. Repeating the
    /// same association is idempotent; a different reference fails closed.
    pub fn associate_prepared_open(
        &mut self,
        token: InvocationToken,
        handle: PinReservationHandle,
        reference: PreparedOpenRef,
    ) -> Result<(), SeamViolation> {
        let sequence = handle.sequence;
        if self.owners.get(&sequence) != Some(&token) {
            let violation = SeamViolation::ConflictingPreparedOpen { sequence };
            self.seam_mut().violations.push(violation.clone());
            return Err(violation);
        }
        self.seam.associate_prepared_open(sequence, reference)
    }

    /// Record the observed outcome of the required abort attempt for a
    /// reservation that completed without a dispatch commitment.
    ///
    /// Permitted only for the owning invocation and only on a no-commit
    /// completion path (a finalized rejection or a locked failed-transition
    /// reservation). Exactly one logical abort attempt is recorded.
    pub fn record_abort_outcome(
        &mut self,
        token: InvocationToken,
        handle: PinReservationHandle,
        outcome: AbortOutcome,
    ) -> Result<(), SeamViolation> {
        let sequence = handle.sequence;
        let owned = self.owners.get(&sequence) == Some(&token);
        let no_commit = matches!(
            self.states.get(&sequence),
            Some(PinState::NoCommitComplete) | Some(PinState::Locked)
        );
        if !owned || !no_commit {
            let violation = SeamViolation::ConflictingAbortOutcome { sequence };
            self.seam_mut().violations.push(violation.clone());
            return Err(violation);
        }
        self.seam.record_abort_outcome(sequence, outcome)
    }

    /// Observe a browser-side launch for a reservation.
    ///
    /// A launch is permitted only after a matching durable dispatch commitment
    /// owned by this invocation; observing one earlier is a violation and proves
    /// the matching-commitment launch ordering.
    pub fn observe_launch(
        &mut self,
        token: InvocationToken,
        handle: PinReservationHandle,
    ) -> Result<(), SeamViolation> {
        let sequence = handle.sequence;
        let committed_here = self.seam.has_commitment(sequence, token);
        let dispatched = self.states.get(&sequence) == Some(&PinState::Dispatched);
        if !committed_here || !dispatched {
            let violation = SeamViolation::LaunchWithoutCommitment { sequence };
            self.seam_mut().violations.push(violation.clone());
            return Err(violation);
        }
        self.seam.observe_launch(sequence)
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /// Non-mutating transition-call preflight.
    ///
    /// Verifies invocation ownership and invocation-side state WITHOUT touching
    /// the journal store. A rejected call therefore creates no marker and no
    /// journal mutation; a corrected valid call remains possible for the
    /// rightful still-active invocation until a no-commit completion decision.
    fn preflight(
        &self,
        token: InvocationToken,
        sequence: u64,
        allowed: &[PinState],
    ) -> Result<(), JournalError> {
        // Cross-invocation / invalid / stale: the reservation must be owned by
        // this invocation.
        if self.owners.get(&sequence) != Some(&token) {
            return Err(JournalError::internal_failure());
        }
        let state = self
            .states
            .get(&sequence)
            .copied()
            .unwrap_or(PinState::Active);
        if !allowed.contains(&state) {
            return Err(JournalError::internal_failure());
        }
        Ok(())
    }
}

/// Strict bind-fact validation under `strict_bind_fact_contract`.
///
/// Consumes daemon-attested source facts before any compatibility constructor
/// can erase their provenance. Failure returns `internal_failure` (never
/// `journal_reservation_failed`, since no reservation is attempted, and never
/// `invalid_request`, since the request schema is not at fault).
fn validate_bind_facts(facts: &StampedBindFacts) -> Result<(), JournalError> {
    // Provenance: a compatibility-derived value is ineligible even when its
    // normalized shape is otherwise valid.
    if facts.provenance != FactProvenance::DaemonAttested {
        return Err(JournalError::internal_failure());
    }
    // Required facts must be present: no project_root fallback for an absent
    // agent_project_id and no defaulting of required identity facts.
    if facts.principal.is_empty()
        || facts.conversation_key.is_empty()
        || facts.agent_project_id.is_empty()
    {
        return Err(JournalError::internal_failure());
    }
    // The principal is a canonical projection, never the forbidden rule string.
    if facts.principal == "not mcp:*" {
        return Err(JournalError::internal_failure());
    }
    Ok(())
}

/// Current-open association validation under `pre_reservation_identity_association`.
///
/// The association is stale when `valid` is false or when the tuple's
/// `association_epoch` does not match the session's current association epoch
/// published on the same channel. A mixed null/present profile pair is
/// malformed. Returns the validated association object on success.
fn validate_current_open(
    publication: &CurrentOpenPublication,
) -> Result<CurrentOpenFacts, JournalError> {
    if !publication.facts.valid {
        return Err(JournalError::internal_failure());
    }
    if publication.facts.association_epoch != publication.current_association_epoch {
        return Err(JournalError::internal_failure());
    }
    match (
        &publication.facts.profile_uuid,
        &publication.facts.profile_name,
    ) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => return Err(JournalError::internal_failure()),
    }
    Ok(publication.facts.clone())
}
