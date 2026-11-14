//! Browser compatibility storage adapter.
//!
//! Lifecycle state, allocation, capacity accounting, and durable transitions are
//! owned by `cerebellum-core`. This module retains only the frozen browser
//! configuration and error/status shapes needed by the compatibility surface.

use std::collections::BTreeMap;

use cerebellum_core::journal::{
    journal_data_path, DurableState, FilesystemJournalStorage, InMemoryJournalStorage,
    JournalBinding, JournalConfig as CoreJournalConfig, JournalError as CoreError,
    JournalIdentity as CoreIdentity, JournalStorage, StorageError,
};

use super::reservation::ReservationHandle;
use super::{
    Capability, GoverningObservation, GrantDecision, HandoffJournalOutcome, HandoffPayload,
    JournalConfig, JournalEntry, JournalError, JournalIdentity, JournalPayload,
    LoginCapturePayload, LoginFillPayload, LoginImportPayload, Outcome, Phase, SessionKind,
    FORMAT_VERSION,
};

/// Test-only fault schedule retained by the browser compatibility surface.
#[derive(Debug, Default)]
pub struct FaultInjector {
    failures: BTreeMap<String, usize>,
}

impl FaultInjector {
    pub fn arm(&mut self, point: impl Into<String>, count: usize) {
        self.failures.insert(point.into(), count);
    }

    fn drain_into_core(&mut self, core: &mut BrowserCoreStore) {
        let failures = std::mem::take(&mut self.failures);
        for (point, count) in failures {
            let mapped = if point == "commit_policy_event" {
                "commit_rejection"
            } else {
                point.as_str()
            };
            core.arm_fault(mapped, count);
        }
    }
}

#[derive(Clone, Debug)]
pub enum BrowserJournalStorage {
    Filesystem(FilesystemJournalStorage),
    Memory(InMemoryJournalStorage),
}

impl JournalStorage for BrowserJournalStorage {
    fn load(&self) -> Result<DurableState, StorageError> {
        match self {
            Self::Filesystem(storage) => storage.load(),
            Self::Memory(storage) => storage.load(),
        }
    }

    fn save(&self, state: &DurableState) -> Result<(), StorageError> {
        match self {
            Self::Filesystem(storage) => storage.save(state),
            Self::Memory(storage) => storage.save(state),
        }
    }

    fn raise_format(
        &self,
        format: cerebellum_core::format_floor::DurableFormat,
    ) -> Result<(), StorageError> {
        match self {
            Self::Filesystem(storage) => storage.raise_format(format),
            Self::Memory(storage) => storage.raise_format(format),
        }
    }
}

pub type BrowserCoreStore = JournalBinding<
    super::core_adapter::BrowserJournalCodec,
    cerebellum_core::journal::UnavailablePolicy,
    cerebellum_core::journal::UnavailablePolicy,
    BrowserJournalStorage,
>;

/// The browser-facing store translates the compatibility API into the shared
/// core journal lifecycle while retaining browser configuration, fault injection,
/// and compatibility metadata.
pub struct JournalStore {
    pub(crate) core: BrowserCoreStore,
    pub faults: FaultInjector,
    pub(crate) metadata: BTreeMap<u64, (JournalIdentity, super::Capability)>,
    pub(crate) provisional: BTreeMap<u64, JournalEntry>,
    config: JournalConfig,
}

impl JournalStore {
    pub fn new(config: JournalConfig) -> Result<Self, JournalError> {
        let core_config = CoreJournalConfig {
            journal_retention_bytes: config.journal_retention_bytes,
            journal_max_entry_bytes: config.journal_max_entry_bytes,
        };
        let path =
            journal_data_path("browser.json").map_err(|_| JournalError::internal_failure())?;
        let storage = FilesystemJournalStorage::prepare(path)
            .map(BrowserJournalStorage::Filesystem)
            .map_err(|_| JournalError::internal_failure())?;
        Self::open(config, core_config, storage)
    }

    /// Open an isolated fixture binding without touching production journal data.
    pub fn new_in_memory(config: JournalConfig) -> Result<Self, JournalError> {
        let core_config = CoreJournalConfig {
            journal_retention_bytes: config.journal_retention_bytes,
            journal_max_entry_bytes: config.journal_max_entry_bytes,
        };
        Self::open(
            config,
            core_config,
            BrowserJournalStorage::Memory(InMemoryJournalStorage::new()),
        )
    }

    fn open(
        config: JournalConfig,
        core_config: CoreJournalConfig,
        storage: BrowserJournalStorage,
    ) -> Result<Self, JournalError> {
        let core = super::core_adapter::open_browser_core_journal(core_config, storage)
            .map_err(|_| JournalError::internal_failure())?;
        Ok(Self {
            core,
            faults: FaultInjector::default(),
            metadata: BTreeMap::new(),
            provisional: BTreeMap::new(),
            config,
        })
    }

    pub(crate) fn sync_faults(&mut self) {
        self.faults.drain_into_core(&mut self.core);
    }

    pub(crate) fn sync_faults_for_transition(&mut self) {
        self.sync_faults();
    }

    pub fn config(&self) -> JournalConfig {
        self.config
    }

    pub fn max_entry_bytes(&self) -> u64 {
        self.config.journal_max_entry_bytes
    }

    pub fn retention_bytes(&self) -> u64 {
        self.config.journal_retention_bytes
    }

    pub fn oversize_flag(&self) -> bool {
        self.core.oversize_flag()
    }

    pub fn next_sequence(&self) -> u64 {
        self.core.next_sequence()
    }

    pub fn allocate_sequence(&mut self) -> Result<u64, JournalError> {
        self.sync_faults();
        self.core.allocate_sequence().map_err(Self::map_error)
    }

    pub fn retained_bytes(&self) -> u64 {
        self.core.retained_bytes()
    }

    pub fn active_reserved_bytes(&self) -> u64 {
        self.core.active_reserved_bytes()
    }

    /// Dispatches committed and never closed out. See the core method for why
    /// this cannot be read off the export or the byte accounting.
    pub fn unfinalized_dispatch_count(&self) -> usize {
        self.core.unfinalized_dispatch_count()
    }

    pub fn active_pre_dispatch_count(&self) -> u64 {
        self.core.active_pre_dispatch_count() as u64
    }

    pub(crate) fn browser_identity(identity: &JournalIdentity) -> CoreIdentity {
        CoreIdentity {
            witness: identity.witness.clone(),
            principal: identity.principal.clone(),
            conversation_key: identity.conversation_key.clone(),
            agent_project_id: identity.agent_project_id.clone(),
            session_kind: match identity.session_kind {
                SessionKind::Primary => cerebellum_core::identity::SessionKind::Primary,
                SessionKind::Subagent => cerebellum_core::identity::SessionKind::Subagent,
                SessionKind::Ephemeral => cerebellum_core::identity::SessionKind::Ephemeral,
            },
            origin: identity.origin.clone(),
            computer_order: None,
        }
    }

    pub(crate) fn map_error(error: CoreError) -> JournalError {
        match error {
            CoreError::ReservationFailed => JournalError::reservation_failed(),
            CoreError::EntryOversize => JournalError::internal_failure(),
            CoreError::FinalizationPending => JournalError::internal_failure(),
            CoreError::CodecFailed
            | CoreError::AttachmentFailed
            | CoreError::StorageUnavailable
            | CoreError::ObligationUnknown
            | CoreError::InvalidHandle
            | CoreError::RedactionUnavailable => JournalError::internal_failure(),
        }
    }

    pub(crate) fn reserve_core(
        &mut self,
        identity: &JournalIdentity,
        capability_descriptor: Vec<u8>,
    ) -> Result<ReservationHandle, JournalError> {
        self.sync_faults();
        let handle = self
            .core
            .reserve(Self::browser_identity(identity), capability_descriptor)
            .map_err(Self::map_error)?;
        Ok(ReservationHandle::from_core(handle))
    }

    pub fn export(&self) -> String {
        self.core.export()
    }

    pub fn export_bytes(&self) -> Vec<u8> {
        self.core.export_bytes()
    }

    pub fn purge(&mut self) -> PurgeReport {
        self.sync_faults();
        let report = self.core.purge();
        PurgeReport {
            purged_entry_count: report.purged_entry_count,
            purged_bytes: report.purged_bytes,
        }
    }

    pub fn status(&self) -> JournalStatus {
        let status = self.core.status();
        JournalStatus {
            entry_count: status.entry_count as u64,
            oldest_retained_sequence: status.oldest_retained_sequence,
            newest_retained_sequence: status.newest_retained_sequence,
            retained_bytes: status.retained_bytes,
            active_reservation_count: self.active_pre_dispatch_count(),
            active_reserved_bytes: status.active_reserved_bytes,
            oversize_flag: status.oversize_flag,
        }
    }

    pub(crate) fn retention_set_core(&mut self, config: JournalConfig) -> Result<(), JournalError> {
        self.sync_faults();
        self.core
            .retention_set(CoreJournalConfig {
                journal_retention_bytes: config.journal_retention_bytes,
                journal_max_entry_bytes: config.journal_max_entry_bytes,
            })
            .map_err(Self::map_error)?;
        self.config = config;
        Ok(())
    }

    pub fn commit_handoff(
        &mut self,
        identity: JournalIdentity,
        origin: String,
        outcome: HandoffJournalOutcome,
        cookie_names_added: Option<u64>,
    ) -> Result<(), JournalError> {
        let handle = self.reserve_policy_event(&identity)?;
        let entry = JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: handle.sequence(),
            phase: Phase::Dispatched,
            identity,
            capability: Some(Capability::Present),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: Vec::new(),
            outcome: Some(Outcome::Success),
            payload: Some(JournalPayload::Handoff(HandoffPayload {
                origin,
                outcome,
                cookie_names_added,
            })),
            detail: None,
        };
        self.commit_reserved_policy(handle, entry.export_line().into_bytes())
    }

    /// The generic detail field is readable by older journal readers, so this
    /// count-only management event does not introduce a new durable format.
    pub(crate) fn commit_would_ask(
        &mut self,
        identity: JournalIdentity,
        agent_id: &str,
        flow_id: &str,
        counts: serde_json::Value,
    ) -> Result<(), JournalError> {
        let handle = self.reserve_policy_event(&identity)?;
        let entry = JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: handle.sequence(),
            phase: Phase::Dispatched,
            identity,
            capability: None,
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: Vec::new(),
            outcome: None,
            payload: None,
            detail: Some(
                serde_json::json!({"event":"grants.would_ask","caller":{"agent_id":agent_id,"flow_id":flow_id},"counts":counts}),
            ),
        };
        self.commit_reserved_policy(handle, entry.export_line().into_bytes())
    }

    /// User-target metadata is confined to this origin-only policy event. The
    /// detail slot is readable by existing journal readers without changing own
    /// browser entries or retaining extension/CDP payloads.
    pub(crate) fn commit_user_browser(
        &mut self,
        identity: JournalIdentity,
        action: &str,
        origin: Option<&str>,
        outcome: &str,
        input_dispatched: Option<bool>,
    ) -> Result<(), JournalError> {
        let handle = self.reserve_policy_event(&identity)?;
        let entry = JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: handle.sequence(),
            phase: Phase::PolicyEvent,
            identity: identity.clone(),
            capability: None,
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: Vec::new(),
            outcome: None,
            payload: None,
            detail: Some(
                serde_json::json!({"browser":"user","action":action,"origin":origin,"outcome":outcome,"input_dispatched":input_dispatched}),
            ),
        };
        self.commit_reserved_policy(handle, entry.export_line().into_bytes())?;
        if outcome == "dispatch_committed" {
            identity.witness.mark_committed();
        }
        Ok(())
    }

    pub fn commit_login_import(
        &mut self,
        identity: JournalIdentity,
        origin: String,
        outcome: String,
        browser: Option<String>,
        rows: u64,
    ) -> Result<(), JournalError> {
        let handle = self.reserve_policy_event(&identity)?;
        let entry = JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: handle.sequence(),
            phase: Phase::Dispatched,
            identity,
            capability: Some(Capability::ImportLogin),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: Vec::new(),
            outcome: Some(Outcome::Success),
            payload: Some(JournalPayload::LoginImport(LoginImportPayload {
                origin,
                outcome,
                browser,
                rows,
            })),
            detail: None,
        };
        self.commit_reserved_policy(handle, entry.export_line().into_bytes())
    }

    pub fn commit_login_capture(
        &mut self,
        identity: JournalIdentity,
        payload: LoginCapturePayload,
    ) -> Result<(), JournalError> {
        let handle = self.reserve_policy_event(&identity)?;
        let entry = JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: handle.sequence(),
            phase: Phase::Dispatched,
            identity,
            capability: Some(Capability::CaptureLogin),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: Vec::new(),
            outcome: Some(Outcome::Success),
            payload: Some(JournalPayload::LoginCapture(payload)),
            detail: None,
        };
        self.commit_reserved_policy(handle, entry.export_line().into_bytes())
    }

    pub fn commit_login_fill(
        &mut self,
        identity: JournalIdentity,
        payload: LoginFillPayload,
    ) -> Result<(), JournalError> {
        let handle = self.reserve_policy_event(&identity)?;
        let entry = JournalEntry {
            format_version: super::FILL_LOGIN_FORMAT_VERSION.to_string(),
            sequence: handle.sequence(),
            phase: Phase::Dispatched,
            identity,
            capability: Some(Capability::FillLogin),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: Vec::new(),
            outcome: Some(Outcome::Success),
            payload: Some(JournalPayload::LoginFill(payload)),
            detail: None,
        };
        self.commit_reserved_policy(handle, entry.export_line().into_bytes())
    }

    pub fn commit_policy_event(&mut self, mut entry: JournalEntry) -> Result<(), JournalError> {
        let identity = entry.identity.clone();
        let handle = self.reserve_policy_event(&identity)?;
        entry.sequence = handle.sequence();
        self.commit_reserved_policy(handle, entry.export_line().into_bytes())
    }

    pub(crate) fn reserve_policy_event(
        &mut self,
        identity: &JournalIdentity,
    ) -> Result<ReservationHandle, JournalError> {
        self.reserve_core(identity, self.max_entry_bytes().to_le_bytes().to_vec())
    }

    /// Settle exactly one failed policy commit. Recovery cancels a reservation
    /// if no entry was stored, or publishes the entry saved before the failure.
    pub(crate) fn recover_policy_event(&mut self, sequence: u64) -> bool {
        #[cfg(test)]
        if let Some(remaining) = self.faults.failures.get_mut("recover_policy_event") {
            if *remaining > 0 {
                *remaining -= 1;
                return false;
            }
        }
        self.sync_faults();
        self.core.recover_record(sequence).is_some()
    }

    pub(crate) fn commit_reserved_policy(
        &mut self,
        handle: ReservationHandle,
        bytes: Vec<u8>,
    ) -> Result<(), JournalError> {
        self.sync_faults();
        self.core
            .finalize_rejected(
                handle.core,
                cerebellum_core::journal::RejectionMaterial {
                    rejection_material: bytes,
                },
            )
            .map(|_| ())
            .map_err(Self::map_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalStatus {
    pub entry_count: u64,
    pub oldest_retained_sequence: Option<u64>,
    pub newest_retained_sequence: Option<u64>,
    pub retained_bytes: u64,
    pub active_reservation_count: u64,
    pub active_reserved_bytes: u64,
    pub oversize_flag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    pub purged_entry_count: u64,
    pub purged_bytes: u64,
}

impl From<&JournalEntry> for Vec<u8> {
    fn from(entry: &JournalEntry) -> Self {
        entry.export_line().into_bytes()
    }
}

#[cfg(test)]
mod fill_format_tests {
    use super::*;
    use cerebellum_core::format_floor::{read_floors, FormatFloor};

    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "direct:fixture".into(),
            conversation_key: "fill-fixture".into(),
            agent_project_id: "project".into(),
            session_kind: SessionKind::Primary,
            profile_uuid: None,
            profile_name: None,
            origin: Default::default(),
        }
    }

    #[test]
    fn fill_v9_is_lazy_and_keeps_ordinary_entry_bytes_unchanged() {
        let scratch = Scratch(std::env::temp_dir().join(format!(
            "cerebellum-fill-floor-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        )));
        std::fs::create_dir_all(&scratch.0).unwrap();
        let floor = scratch.0.join("format-floor.json");
        let storage = FilesystemJournalStorage::new(scratch.0.join("browser.json"))
            .with_format_floor(FormatFloor::at(&floor));
        let mut journal = JournalStore::open(
            JournalConfig {
                journal_retention_bytes: 1_000_000,
                journal_max_entry_bytes: 100_000,
            },
            CoreJournalConfig {
                journal_retention_bytes: 1_000_000,
                journal_max_entry_bytes: 100_000,
            },
            BrowserJournalStorage::Filesystem(storage),
        )
        .unwrap();
        assert_eq!(
            read_floors(&floor).unwrap().get("browser-journal-entry"),
            None
        );
        journal
            .commit_login_capture(
                identity(),
                LoginCapturePayload {
                    origin: "https://x.test".into(),
                    holder: "reserved:insula".into(),
                    credential_id: "cookie:x.test:work".into(),
                    bytes: 0,
                    outcome: "expired".into(),
                    deletion_succeeded: None,
                },
            )
            .unwrap();
        let before = journal.export();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(before.trim()).unwrap()["format_version"],
            "ck-browser-journal/v7"
        );
        assert_eq!(
            read_floors(&floor).unwrap().get("browser-journal-entry"),
            None
        );
        let payload = LoginFillPayload {
            origin: Some("https://x.test".into()),
            outcome: "ok".into(),
            filled: vec![
                super::super::LoginFillField::Username,
                super::super::LoginFillField::Password,
                super::super::LoginFillField::Otp,
            ],
        };
        journal
            .commit_login_fill(identity(), payload.clone())
            .unwrap();
        let after = journal.export();
        assert!(after.starts_with(&before));
        assert_eq!(
            read_floors(&floor).unwrap().get("browser-journal-entry"),
            Some(&9)
        );
        let line = after.lines().last().unwrap();
        let entry: JournalEntry = serde_json::from_str(line).unwrap();
        assert_eq!(entry.format_version, "ck-browser-journal/v9");
        assert_eq!(entry.capability, Some(Capability::FillLogin));
        assert_eq!(entry.payload, Some(JournalPayload::LoginFill(payload)));
        assert!(entry.action.is_none());
        assert_eq!(entry.export_line().trim(), line);
        assert_eq!(
            super::super::EXPORT_FORMAT_VERSION,
            "ck-browser-journal-export/v9"
        );
    }
}
