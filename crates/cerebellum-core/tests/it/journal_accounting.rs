use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::codec::{
    CompletionInput, DispatchedInput, EncodedJournalState, PlaneJournalCodec, ProvisionalInput,
    RecoveryTerminalInput, ReducedTerminalInput, RejectionInput,
};
use cerebellum_core::journal::store::JournalStore;
use cerebellum_core::journal::{
    CompletedResult, DispatchMaterial, FilesystemJournalStorage, FinalContextAssociation,
    InMemoryJournalStorage, JournalConfig, JournalError, JournalIdentity, RejectionMaterial,
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

    fn entry_format(&self) -> Option<cerebellum_core::format_floor::DurableFormat> {
        None
    }
}

fn identity() -> JournalIdentity {
    JournalIdentity {
        witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
        principal: "principal-1".to_string(),
        conversation_key: "conversation-1".to_string(),
        agent_project_id: "project-1".to_string(),
        session_kind: SessionKind::Primary,
        origin: Default::default(),
        computer_order: None,
    }
}

fn config(retention_bytes: u64) -> JournalConfig {
    JournalConfig {
        journal_retention_bytes: retention_bytes,
        journal_max_entry_bytes: retention_bytes,
    }
}

fn store(retention_bytes: u64) -> JournalStore<AccountingCodec> {
    JournalStore::new(
        AccountingCodec,
        None,
        None,
        config(retention_bytes),
        InMemoryJournalStorage::new(),
    )
    .unwrap()
}

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(test_name: &str) -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cerebellum-accounting-{test_name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary accounting directory");
        Self(path)
    }

    fn journal_path(&self) -> PathBuf {
        self.0.join("journal.json")
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn filesystem_store(
    retention_bytes: u64,
    path: &Path,
) -> JournalStore<AccountingCodec, (), (), FilesystemJournalStorage> {
    JournalStore::new(
        AccountingCodec,
        None,
        None,
        config(retention_bytes),
        FilesystemJournalStorage::new(path),
    )
    .unwrap()
}

fn compact_record_size(path: &Path, collection: &str, sequence: u64) -> u64 {
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("read journal file"))
            .expect("parse journal file");
    serde_json::to_vec(&stored["state"][collection][sequence.to_string()])
        .expect("serialize stored record")
        .len() as u64
}

fn compact_transition_bytes(path: &Path) -> u64 {
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("read journal file"))
            .expect("parse journal file");
    stored["state"]["transitions"]
        .as_array()
        .expect("stored terminal transitions")
        .iter()
        .map(|transition| {
            serde_json::to_vec(transition)
                .expect("serialize stored transition")
                .len() as u64
        })
        .sum()
}

#[test]
fn active_reservation_charge_matches_the_full_serialized_record() {
    let directory = TemporaryDirectory::new("active");
    let path = directory.journal_path();
    let mut journal = filesystem_store(10_000, &path);
    let handle = journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();

    let actual = compact_record_size(&path, "reservations", 1);
    assert_eq!(journal.active_reserved_bytes(), actual);
    assert_eq!(journal.retained_bytes(), actual);
    assert_eq!(journal.status().active_reserved_bytes, actual);
    assert_eq!(journal.status().retained_bytes, actual);
    assert_eq!(handle.action_obligation_id(), 1);
}

#[test]
fn retention_counts_active_reservation_records_absolutely() {
    let mut probe = store(10_000);
    probe.reserve(identity(), b"invoke-1".to_vec()).unwrap();
    let one_record = probe.active_reserved_bytes();

    let mut journal = store(one_record * 2 - 1);
    journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();
    assert_eq!(journal.active_reserved_bytes(), one_record);
    assert_eq!(journal.retained_bytes(), one_record);
    assert_eq!(
        journal.reserve(identity(), b"invoke-2".to_vec()),
        Err(JournalError::ReservationFailed)
    );
}

#[test]
fn dispatch_and_finalization_reaccount_each_full_record() {
    let directory = TemporaryDirectory::new("lifecycle");
    let path = directory.journal_path();
    let mut journal = filesystem_store(10_000, &path);
    let handle = journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();
    assert_eq!(
        journal.active_reserved_bytes(),
        compact_record_size(&path, "reservations", 1)
    );

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
    assert_eq!(
        journal.active_reserved_bytes(),
        compact_record_size(&path, "reservations", 1)
    );
    assert_eq!(journal.retained_bytes(), journal.active_reserved_bytes());

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
    assert_eq!(journal.active_reserved_bytes(), 0);
    assert_eq!(
        journal.retained_bytes(),
        compact_record_size(&path, "entries", 1) + compact_transition_bytes(&path)
    );
    assert_eq!(journal.status().entry_count, 1);
}

#[test]
fn terminal_accounting_matches_serialized_record_not_payload() {
    let directory = TemporaryDirectory::new("terminal");
    let path = directory.journal_path();
    let mut journal = filesystem_store(10_000, &path);
    let handle = journal.reserve(identity(), b"invoke-1".to_vec()).unwrap();

    journal
        .finalize_rejected(
            handle,
            RejectionMaterial {
                rejection_material: b"denied".to_vec(),
            },
        )
        .unwrap();

    let entry_bytes = compact_record_size(&path, "entries", 1);
    let transition_bytes = compact_transition_bytes(&path);
    assert_eq!(journal.active_reserved_bytes(), 0);
    assert_eq!(journal.retained_bytes(), entry_bytes + transition_bytes);
    // Purge removes the entry, not its separately retained transitions.
    assert_eq!(journal.purge().purged_bytes, entry_bytes);
    let purged: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read purged journal file"))
            .expect("parse purged journal file");
    assert!(purged["state"]["entries"].as_object().unwrap().is_empty());
    assert_eq!(compact_transition_bytes(&path), transition_bytes);
    assert_eq!(journal.retained_bytes(), transition_bytes);
}
