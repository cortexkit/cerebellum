use super::*;
use crate::browser_launch::{
    AttestedLaunchRequest, LaunchJournalPort, PreSpawnIdentityVerification,
    WindowsLaunchJournalInput,
};
#[cfg(feature = "windows-browser-release")]
use crate::browser_launch::{
    ExecutableIdentityChain, ExecutableIdentityCheckpoints, ExecutableIdentityClaim,
    ExecutableIdentityRecord, OrphanProfileCustodyFailure,
};
#[cfg(feature = "windows-browser-release")]
use cerebellum_core::journal::StorageError;
use cerebellum_core::journal::{DurableState, InMemoryJournalStorage, JournalConfig};
use std::cell::Cell;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

fn config() -> JournalConfig {
    JournalConfig {
        journal_retention_bytes: 1024 * 1024,
        journal_max_entry_bytes: 64 * 1024,
    }
}

fn open(
    storage: InMemoryJournalStorage,
) -> Result<DurableLaunchJournal<InMemoryJournalStorage>, BindingError> {
    DurableLaunchJournal::open(config(), storage)
}

fn request(holder: SupervisorGeneration) -> AttestedLaunchRequest {
    let legacy: AuthorizedLaunchIntent = serde_json::from_str(include_str!(
        "../../../tests/fixtures/launch-intent-v4.json"
    ))
    .unwrap();
    let executable = PathBuf::from(r"C:\Program Files\Échantillon\chrome.exe");
    AttestedLaunchRequest {
        launch_attempt_id: legacy.launch_attempt_id,
        holder_id: legacy.holder_id,
        route: legacy.route,
        profile: legacy.profile,
        executable,
        arguments: vec![OsString::from("--example=quoted \"日本語\"")],
        environment: vec![(OsString::from("SystemRoot"), OsString::from(r"C:\Windows"))],
        verified_executable_identity: legacy.verified_executable_identity,
        pre_spawn_identity_verification: PreSpawnIdentityVerification::Established,
        windows_journal: Some(WindowsLaunchJournalInput {
            supervisor: holder,
            canonical_profile_path: PathBuf::from(r"\\?\C:\試験 Profile"),
            command_line:
                r#""C:\Program Files\Échantillon\chrome.exe" "--example=quoted \"日本語\"""#
                    .encode_utf16()
                    .collect(),
        }),
    }
}

fn current_and_replaced() -> (SupervisorGeneration, SupervisorGeneration) {
    let current = crate::profile_custody::current_supervisor_generation().unwrap();
    let replaced = SupervisorGeneration::from_windows_filetime(current.pid, current.start_time + 1);
    (current, replaced)
}

#[cfg(feature = "windows-browser-release")]
fn barred(intent: AuthorizedLaunchIntent, root: SupervisorGeneration) -> LaunchAttestationRecord {
    let (identifier, hash) = match &intent.verified_executable_identity {
        crate::browser_launch::VerifiedExecutableIdentity::CodeSignedFile {
            signing_identifier,
            slice_code_hashes,
        } => (
            signing_identifier.clone(),
            slice_code_hashes.first().unwrap().clone(),
        ),
        _ => panic!("expected fixture's synthetic signed identity"),
    };
    let claim = ExecutableIdentityClaim::CodeSigned {
        signing_identifier: identifier,
        unique_code_hash: hash,
    };
    LaunchAttestationRecord {
        generation: LaunchGenerationRecord {
            intent,
            process_generation: BrowserProcessGeneration::from_windows_filetime(
                root.pid,
                root.start_time,
            ),
        },
        observed_executable_identity: claim.clone(),
        executable_identity_chain: ExecutableIdentityChain::NoWalkPerformed {
            attestation: ExecutableIdentityRecord { claim, path: None },
        },
        executable_identity_checkpoints: ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
    }
}

#[test]
fn windows_launch_vector_round_trips_quoted_non_ascii_and_unpaired_units() {
    let (holder, _) = current_and_replaced();
    let mut request = request(holder);
    request
        .arguments
        .push(OsString::from_wide(&[0xd800, b'X'.into()]));
    request.environment[0].1 = OsString::from_wide(&[0xdc00, b'Y'.into()]);
    let input = request.windows_journal.as_mut().unwrap();
    input.command_line.extend([b' '.into(), 0xd800]);
    let path_units = [0x005c, 0x005c, 0x003f, 0x005c, 0x6f22, 0xd800];
    input.canonical_profile_path = PathBuf::from(OsString::from_wide(&path_units));
    let intent = request.durable_intent();
    let bytes = serde_json::to_vec(&intent).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["launch_vector"]["encoding"], "utf16le");
    assert!(value["launch_vector"]["lpCommandLine"].is_string());
    assert!(value["profile"]["canonical_profile_path"].is_string());
    let reopened: AuthorizedLaunchIntent = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reopened, intent);
    let units = |bytes: &[u8]| -> Vec<u16> {
        let (pairs, remainder) = bytes.as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs.iter().copied().map(u16::from_le_bytes).collect()
    };
    assert_eq!(
        units(&reopened.launch_vector.executable),
        request
            .executable
            .as_os_str()
            .encode_wide()
            .collect::<Vec<_>>()
    );
    assert_eq!(
        units(&reopened.launch_vector.arguments[1]),
        [0xd800, b'X'.into()]
    );
    assert_eq!(
        units(&reopened.launch_vector.environment[0].1),
        [0xdc00, b'Y'.into()]
    );
    assert_eq!(
        units(reopened.launch_vector.lp_command_line.as_deref().unwrap()),
        request.windows_journal.unwrap().command_line
    );
    assert_eq!(units(&reopened.profile.canonical_profile_path), path_units);
}

#[cfg(not(feature = "windows-browser-release"))]
#[test]
fn windows_browser_unbound_startup_opens_neither_launch_store() {
    assert!(!crate::browser_build_admits());
    let journal = InMemoryJournalStorage::new();
    let (holder, _) = current_and_replaced();
    let handle = open(journal.clone())
        .unwrap()
        .record_intent(&request(holder).durable_intent())
        .unwrap();
    let before = journal.load().unwrap();
    let registry = Cell::new(b"test-owned registry bytes".as_slice());
    let result = open_windows_startup(
        || {
            journal.save(&DurableState::default()).unwrap();
            open(journal.clone())
        },
        || {
            registry.set(b"opened");
            Ok(())
        },
        |(), _| panic!("an unbound build must not release anything"),
    )
    .unwrap();
    assert!(result.is_none());
    assert_eq!(registry.get(), b"test-owned registry bytes");
    assert_eq!(
        serde_json::to_vec(&journal.load().unwrap()).unwrap(),
        serde_json::to_vec(&before).unwrap()
    );
    assert!(open(journal)
        .unwrap()
        .core
        .classify(handle.sequence())
        .is_some());
}

#[cfg(feature = "windows-browser-release")]
fn run(
    storage: &InMemoryJournalStorage,
    release: impl FnMut(&mut (), &AuthorizedLaunchIntent) -> Result<(), OrphanProfileCustodyFailure>,
) -> WindowsStartup<InMemoryJournalStorage> {
    open_windows_startup(|| open(storage.clone()), || Ok(()), release)
        .unwrap()
        .unwrap()
}

#[cfg(feature = "windows-browser-release")]
fn basis_for(storage: &InMemoryJournalStorage, sequence: u64) -> Option<Basis> {
    let audit = open(storage.clone())
        .unwrap()
        .read_attempt(sequence)
        .unwrap();
    attachment(&audit, RECOVERY_CLEAR_SLOT).map(|bytes| {
        serde_json::from_slice::<RecoveryClear>(bytes)
            .unwrap()
            .basis
    })
}

#[cfg(feature = "windows-browser-release")]
#[test]
fn windows_startup_keeps_current_codec_records_until_their_basis_is_proven() {
    let (live, gone) = current_and_replaced();
    for (holder, root, expected) in [
        (live, None, None),
        (live, Some(gone), None),
        (gone, Some(live), None),
        (gone, None, Some(Basis::NeverResumedHolderGone)),
        (gone, Some(gone), Some(Basis::GenerationsGone)),
    ] {
        let storage = InMemoryJournalStorage::new();
        let intent = request(holder).durable_intent();
        let mut first = open(storage.clone()).unwrap();
        let mut handle = first.record_intent(&intent).unwrap();
        if let Some(root) = root {
            let record = barred(intent.clone(), root);
            first
                .record_generation(&mut handle, &record.generation)
                .unwrap();
            first.commit_attestation(&mut handle, &record).unwrap();
        }
        let sequence = handle.sequence();
        let audit = first.read_attempt(sequence).unwrap();
        assert_eq!(audit.codec_id, super::LAUNCH_CODEC_VERSION);
        drop(first);
        let released = Cell::new(false);
        let recovered = run(&storage, |(), observed| {
            assert_eq!(observed, &intent);
            assert_eq!(
                basis_for(&storage, sequence),
                expected,
                "basis must precede release"
            );
            assert!(!released.replace(true));
            Ok(())
        });
        assert_eq!(released.get(), expected.is_some());
        assert_eq!(
            recovered.journal.core.classify(sequence).is_some(),
            expected.is_none()
        );
        assert_eq!(
            recovered.pending,
            if expected.is_none() {
                vec![intent]
            } else {
                vec![]
            }
        );
        assert_eq!(basis_for(&storage, sequence), expected);
        if expected == Some(Basis::NeverResumedHolderGone) {
            use cerebellum_core::journal::{LifecycleState, TerminalKind};
            let cancelled = recovered.journal.read_attempt(sequence).unwrap();
            assert_eq!(cancelled.descriptor_bytes, audit.descriptor_bytes);
            assert_eq!(cancelled.lifecycle, LifecycleState::Cancelled);
            assert_eq!(
                cancelled.terminal_kind,
                Some(TerminalKind::RecoveryCancelled)
            );
            assert!(cancelled.recovery_supplied_terminal);
        }
    }
}

#[cfg(feature = "windows-browser-release")]
#[test]
fn windows_startup_keeps_partial_and_unreadable_attachments_locked() {
    let (_, gone) = current_and_replaced();
    for unreadable in [false, true] {
        let storage = InMemoryJournalStorage::new();
        let intent = request(gone).durable_intent();
        let mut first = open(storage.clone()).unwrap();
        let mut handle = first.record_intent(&intent).unwrap();
        if unreadable {
            first
                .core
                .attach_obligation_material(
                    handle.reservation,
                    ATTESTATION_SLOT,
                    0,
                    b"bad json".to_vec(),
                )
                .unwrap();
        } else {
            first
                .record_generation(&mut handle, &barred(intent.clone(), gone).generation)
                .unwrap();
        }
        let sequence = handle.sequence();
        drop(first);
        let recovered = run(&storage, |(), _| {
            panic!("partial evidence must not release custody")
        });
        assert_eq!(recovered.pending, [intent]);
        assert!(recovered.journal.core.classify(sequence).is_some());
        assert_eq!(basis_for(&storage, sequence), None);
    }
}

#[cfg(feature = "windows-browser-release")]
#[derive(Clone)]
struct Unreadable;

#[cfg(feature = "windows-browser-release")]
impl JournalStorage for Unreadable {
    fn load(&self) -> Result<DurableState, StorageError> {
        Err(StorageError::LockPoisoned {
            binding: "unreadable fixture".into(),
        })
    }

    fn save(&self, _: &DurableState) -> Result<(), StorageError> {
        panic!("must not overwrite an unreadable journal")
    }
    fn raise_format(
        &self,
        _: cerebellum_core::format_floor::DurableFormat,
    ) -> Result<(), StorageError> {
        panic!("must not raise floor on failed read")
    }
}

#[cfg(feature = "windows-browser-release")]
#[test]
fn windows_no_intent_basis_needs_absence_in_a_complete_read_and_a_dead_holder() {
    let (live, gone) = current_and_replaced();
    let storage = InMemoryJournalStorage::new();
    let intent = request(gone).durable_intent();
    let holder_id = HolderId::from_recorded(&intent.holder_id);
    assert_eq!(
        no_intent_basis(|| open(storage.clone()), &holder_id, live),
        Ok(None)
    );
    assert_eq!(
        no_intent_basis(|| open(storage.clone()), &holder_id, gone),
        Ok(Some(Basis::NoIntentHolderGone))
    );
    let handle = open(storage.clone())
        .unwrap()
        .record_intent(&intent)
        .unwrap();
    assert_eq!(
        no_intent_basis(|| open(storage.clone()), &holder_id, gone),
        Ok(None)
    );
    assert!(open(storage)
        .unwrap()
        .core
        .classify(handle.sequence())
        .is_some());
    let unreadable = || DurableLaunchJournal::open(config(), Unreadable);
    assert_eq!(
        no_intent_basis(unreadable, &holder_id, gone),
        Err(Failure::JournalOpen)
    );
    assert!(matches!(
        open_windows_startup(
            unreadable,
            || -> Result<(), _> { panic!("must not open custody after an unreadable journal") },
            |(), _| unreachable!()
        ),
        Err(Failure::JournalOpen)
    ));
}

#[cfg(feature = "windows-browser-release")]
#[test]
fn windows_startup_refuses_newer_writer_without_consuming_intent() {
    let (_, gone) = current_and_replaced();
    let storage = InMemoryJournalStorage::new();
    let mut intent = request(gone).durable_intent();
    intent.format_version = "ck-browser-launch-attestation/v999".into();
    let sequence = open(storage.clone())
        .unwrap()
        .record_intent(&intent)
        .unwrap()
        .sequence();
    let result = open_windows_startup(
        || open(storage.clone()),
        || -> Result<(), _> { panic!("must not open custody after a newer writer") },
        |(), _| unreachable!(),
    );
    assert!(
        matches!(result, Err(Failure::NewerWriter { sequence: found, .. }) if found == sequence)
    );
    assert!(open(storage).unwrap().core.classify(sequence).is_some());
}
