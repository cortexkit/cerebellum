//! Browser compatibility storage adapter.
//!
//! Lifecycle state, allocation, capacity accounting, and durable transitions are
//! owned by `cerebellum-core`. This module retains only the frozen browser
//! configuration and error/status shapes needed by the compatibility surface.

use std::collections::BTreeMap;

use cerebellum_core::journal::{
    InMemoryJournalStorage, JournalBinding, JournalConfig as CoreJournalConfig,
    JournalError as CoreError, JournalIdentity as CoreIdentity,
};

use super::reservation::ReservationHandle;
use super::{JournalConfig, JournalEntry, JournalError, JournalIdentity, SessionKind};

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

pub type BrowserCoreStore = JournalBinding<
    super::core_adapter::BrowserJournalCodec,
    cerebellum_core::journal::UnavailablePolicy,
    cerebellum_core::journal::UnavailablePolicy,
    InMemoryJournalStorage,
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
        let core = super::core_adapter::open_browser_core_journal(
            core_config,
            InMemoryJournalStorage::new(),
        )
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

    pub(crate) fn set_oversize_flag(&mut self) {
        self.core.set_oversize_flag();
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

    pub fn active_pre_dispatch_count(&self) -> u64 {
        self.core.active_pre_dispatch_count() as u64
    }

    pub(crate) fn browser_identity(identity: &JournalIdentity) -> CoreIdentity {
        CoreIdentity {
            principal: identity.principal.clone(),
            conversation_key: identity.conversation_key.clone(),
            agent_project_id: identity.agent_project_id.clone(),
            session_kind: match identity.session_kind {
                SessionKind::Primary => cerebellum_core::identity::SessionKind::Primary,
                SessionKind::Subagent => cerebellum_core::identity::SessionKind::Subagent,
                SessionKind::Ephemeral => cerebellum_core::identity::SessionKind::Ephemeral,
            },
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
