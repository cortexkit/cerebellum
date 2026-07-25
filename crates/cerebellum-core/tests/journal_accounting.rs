use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::codec::{
    CompletionInput, DispatchedInput, EncodedJournalState, PlaneJournalCodec, ProvisionalInput,
    RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
};
use cerebellum_core::journal::store::JournalStore;
use cerebellum_core::journal::{
    CompletedResult, DispatchMaterial, FinalContextAssociation, InMemoryJournalStorage,
    JournalConfig, JournalError, JournalIdentity, RejectionMaterial,
};

#[derive(Debug, Clone, Copy)]
struct AccountingCodec;

impl AccountingCodec {
    fn encoded(prefix: &str, action_obligation_id: u64) -> EncodedJournalState {
        let durable_bytes = format!("{prefix}:{action_obligation_id}").into_bytes();
        EncodedJournalState {
            accounted_serialized_size: durable_bytes.len() as u64,
            durable_bytes,
            codec_version: "accounting-test-v1".to_string(),
        }
    }
}

impl PlaneJournalCodec for AccountingCodec {
    fn encode_provisional(
        &self,
        input: &ProvisionalInput,
    ) -> Result<EncodedJournalState, cerebellum_core::journal::JournalCodecError> {
        Ok(Self::encoded("p", input.action_obligation_id))
    }

    fn encode_dispatched(
        &self,
        input: &DispatchedInput,
    ) -> Result<EncodedJournalState, cerebellum_core::journal::JournalCodecError> {
        Ok(Self::encoded("dispatch", input.action_obligation_id))
    }

    fn encode_rejection(
        &self,
        input: &RejectionInput,
    ) -> Result<EncodedJournalState, cerebellum_core::journal::JournalCodecError> {
        Ok(Self::encoded("reject", input.action_obligation_id))
    }

    fn encode_completion(
        &self,
        input: &CompletionInput,
    ) -> Result<EncodedJournalState, cerebellum_core::journal::JournalCodecError> {
        Ok(Self::encoded("done", input.action_obligation_id))
    }

    fn encode_reduced_terminal(
        &self,
        input: &ReducedTerminalInput,
    ) -> Result<EncodedJournalState, cerebellum_core::journal::JournalCodecError> {
        Ok(Self::encoded("reduced", input.action_obligation_id))
    }

    fn encode_recovery_terminal(
        &self,
        input: &RecoveryTerminalInput,
    ) -> Result<EncodedJournalState, cerebellum_core::journal::JournalCodecError> {
        Ok(Self::encoded("recovered", input.action_obligation_id))
    }
}

fn identity() -> JournalIdentity {
    JournalIdentity {
        principal: "principal-1".to_string(),
        conversation_key: "conversation-1".to_string(),
        agent_project_id: "project-1".to_string(),
        session_kind: SessionKind::Primary,
    }
}

fn store(retention_bytes: u64) -> JournalStore<AccountingCodec> {
    JournalStore::new(
        AccountingCodec,
        None,
        None,
        JournalConfig {
            journal_retention_bytes: retention_bytes,
            journal_max_entry_bytes: retention_bytes,
        },
        InMemoryJournalStorage::new(),
    )
    .unwrap()
}

#[test]
fn active_reservation_has_exact_provisional_charge() {
    let mut journal = store(100);
    let handle = journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();

    // The provisional fixture is `p:1`, so its three serialized bytes are
    // charged while the obligation is still active.
    assert_eq!(journal.active_reserved_bytes(), 3);
    assert_eq!(journal.retained_bytes(), 3);
    assert_eq!(journal.status().active_reserved_bytes, 3);
    assert_eq!(journal.status().retained_bytes, 3);
    assert_eq!(handle.action_obligation_id(), 1);
}

#[test]
fn retention_counts_active_reservation_bytes_absolutely() {
    let mut journal = store(5);
    journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();

    // Retention must include in-flight reservations, leaving only two of the
    // five configured bytes unavailable for another three-byte reservation.
    assert_eq!(journal.active_reserved_bytes(), 3);
    assert_eq!(journal.retained_bytes(), 3);
    assert_eq!(
        journal.reserve(identity(), b"invoke-2".to_vec()),
        Err(JournalError::ReservationFailed)
    );
}

#[test]
fn dispatch_and_finalization_keep_exact_active_and_retained_bytes() {
    let mut journal = store(100);
    let handle = journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();
    assert_eq!(journal.active_reserved_bytes(), 3);
    assert_eq!(journal.retained_bytes(), 3);

    let token = journal
        .commit_dispatched(
            handle,
            DispatchMaterial {
                dispatch_material: b"dispatch-material".to_vec(),
                severity_inputs: None,
                grant_decision: b"allowed".to_vec(),
                governing_observation: None,
            },
        )
        .unwrap();
    // The dispatched fixture is `dispatch:1`, exactly ten bytes, replacing
    // rather than adding to the provisional reservation charge.
    assert_eq!(journal.active_reserved_bytes(), 10);
    assert_eq!(journal.retained_bytes(), 10);

    journal
        .finalize_dispatched(
            token,
            CompletedResult {
                completed_result: b"result".to_vec(),
            },
            FinalContextAssociation {
                final_context: b"context".to_vec(),
            },
        )
        .unwrap();
    // Finalization releases active capacity and retains the `done:1` terminal,
    // whose exact serialized size is six bytes.
    assert_eq!(journal.active_reserved_bytes(), 0);
    assert_eq!(journal.retained_bytes(), 6);
    assert_eq!(journal.status().entry_count, 1);
}

#[test]
fn rejected_terminal_retains_exact_encoded_size() {
    let mut journal = store(100);
    let handle = journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();
    assert_eq!(journal.active_reserved_bytes(), 3);

    journal
        .finalize_rejected(
            handle,
            RejectionMaterial {
                rejection_material: b"denied".to_vec(),
            },
        )
        .unwrap();

    // A rejected terminal is retained as the `reject:1` fixture, exactly eight
    // bytes, after its active reservation is released.
    assert_eq!(journal.active_reserved_bytes(), 0);
    assert_eq!(journal.retained_bytes(), 8);
    assert_eq!(journal.purge().purged_bytes, 8);
}
