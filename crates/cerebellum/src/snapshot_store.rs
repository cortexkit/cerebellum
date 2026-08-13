//! Browser-plane snapshot and reference retention.
//!
//! This store retains the exact bounded caller-visible observation together
//! with the private identity projection needed for a later action.  Retaining
//! the two together prevents a click from silently falling back to a newer
//! document or to an unredacted accessible name.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::coordinate::ScreenshotSnapshot;
use crate::journal::redaction::utf8_safe_truncate;

pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_REFS: usize = 4_096;
pub const MAX_REF: usize = 4_096;
pub const MAX_ROLE_BYTES: usize = 128;
pub const MAX_NAME_BYTES: usize = 4_096;
pub const MAX_VALUE_BYTES: usize = 4_096;
pub const MAX_AX_RECORD_BYTES: usize = 1_048_576;
pub const AX_SCHEMA: &str = "ck-browser-snapshot-ax-jsonl/v1";
pub const DOM_SCHEMA: &str = "ck-browser-snapshot-dom-text/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    Ax,
    DomFull,
    Screenshot,
}

impl SnapshotKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ax => "ax",
            Self::DomFull => "dom_full",
            Self::Screenshot => "screenshot",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRef {
    #[serde(rename = "ref")]
    pub reference: String,
    pub role: String,
    pub name: String,
    pub nth: u64,
}

impl SnapshotRef {
    pub fn new(
        reference: impl Into<String>,
        role: impl Into<String>,
        name: impl Into<String>,
        nth: u64,
    ) -> Result<Self, SnapshotError> {
        let item = Self {
            reference: reference.into(),
            role: role.into(),
            name: name.into(),
            nth,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn validate(&self) -> Result<(), SnapshotError> {
        if !valid_ref(&self.reference) {
            return Err(SnapshotError::InvalidRef);
        }
        if self.role.len() > MAX_ROLE_BYTES
            || self.name.len() > MAX_NAME_BYTES
            || self.nth > MAX_SAFE_INTEGER
        {
            return Err(SnapshotError::BoundExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendNodeIdentity {
    pub target_id: String,
    pub frame_id: String,
    pub backend_node_id: u64,
}

impl BackendNodeIdentity {
    pub fn new(
        target_id: impl Into<String>,
        frame_id: impl Into<String>,
        backend_node_id: u64,
    ) -> Result<Self, SnapshotError> {
        let value = Self {
            target_id: target_id.into(),
            frame_id: frame_id.into(),
            backend_node_id,
        };
        if value.target_id.is_empty()
            || value.target_id.len() > 4096
            || value.frame_id.is_empty()
            || value.frame_id.len() > 4096
            || !(1..=MAX_SAFE_INTEGER).contains(&value.backend_node_id)
        {
            return Err(SnapshotError::IdentityOutOfBounds);
        }
        Ok(value)
    }

    pub fn digest(&self) -> String {
        let value = serde_json::json!({"target_id":self.target_id,"frame_id":self.frame_id,"backend_node_id":self.backend_node_id});
        let bytes = serde_json::to_vec(&value).expect("identity is serializable");
        hex(&Sha256::digest(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefRecord {
    pub captured: SnapshotRef,
    pub frame_path: Vec<String>,
    pub backend_identity: Option<BackendNodeIdentity>,
    pub raw_role: Option<String>,
    pub raw_name: Option<String>,
    /// Form facts captured from the same document epoch as this reference.
    /// Absence is an unknown classification, not an assertion that no hazard exists.
    pub classification: Option<Box<crate::classification::NonTypeClassificationRecord>>,
}

impl RefRecord {
    pub fn fallback_key(&self) -> FallbackKey {
        FallbackKey {
            frame_path: self.frame_path.clone(),
            role: self.captured.role.clone(),
            name: self.captured.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FallbackKey {
    pub frame_path: Vec<String>,
    pub role: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefCandidate {
    pub identity: Option<BackendNodeIdentity>,
    pub frame_path: Vec<String>,
    pub role: String,
    pub name: String,
    pub traversal_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefResolution {
    Resolved(Box<RefRecord>),
    NotFound,
    Ambiguous { candidate_count: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxRecord {
    pub depth: i64,
    pub role: String,
    pub name: String,
    pub value: Option<String>,
    pub reference: Option<String>,
}

impl AxRecord {
    pub fn canonical_line(&self) -> Result<String, SnapshotError> {
        if self.depth < 0
            || self.role.len() > MAX_ROLE_BYTES
            || self.name.len() > MAX_NAME_BYTES
            || self
                .value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_VALUE_BYTES)
        {
            return Err(SnapshotError::BoundExceeded);
        }
        let value = serde_json::json!({"depth":self.depth,"role":self.role,"name":self.name,"value":self.value,"ref":self.reference});
        let line = serde_json::to_string(&value).map_err(|_| SnapshotError::Serialization)?;
        if line.len() > MAX_AX_RECORD_BYTES {
            return Err(SnapshotError::BoundExceeded);
        }
        Ok(format!("{line}\n"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSnapshot {
    pub snapshot_id: String,
    pub kind: SnapshotKind,
    pub document_epoch: u64,
    pub source_origin: String,
    pub content_schema: &'static str,
    pub content: String,
    pub truncated: bool,
    pub refs_truncated: bool,
    pub refs: Vec<RefRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StoredSnapshot {
    Text(TextSnapshot),
    Screenshot(ScreenshotSnapshot),
}

impl StoredSnapshot {
    pub fn id(&self) -> &str {
        match self {
            Self::Text(value) => &value.snapshot_id,
            Self::Screenshot(value) => &value.snapshot_id,
        }
    }
    pub fn kind(&self) -> SnapshotKind {
        match self {
            Self::Text(value) => value.kind,
            Self::Screenshot(_) => SnapshotKind::Screenshot,
        }
    }
    pub fn epoch(&self) -> u64 {
        match self {
            Self::Text(value) => value.document_epoch,
            Self::Screenshot(value) => value.document_epoch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidId,
    InvalidRef,
    IdentityOutOfBounds,
    BoundExceeded,
    WrongKind,
    NotFound,
    Evicted,
    EpochOverflow,
    EpochMismatch,
    Ambiguous { candidate_count: usize },
    Serialization,
    RetentionFull,
    Teardown,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SnapshotError {}

#[derive(Debug)]
struct StoredRecord {
    snapshot: StoredSnapshot,
    refs: HashMap<String, RefRecord>,
    pinned: usize,
    invalidated: bool,
    insertion: u64,
}

pub type SnapshotStore = BrowserSnapshotStore;
pub type Snapshot = StoredSnapshot;

#[derive(Debug)]
pub struct BrowserSnapshotStore {
    retention_limit: usize,
    records: BTreeMap<String, StoredRecord>,
    insertion: u64,
    teardown: bool,
}

impl BrowserSnapshotStore {
    pub fn new(retention_limit: usize) -> Result<Self, SnapshotError> {
        if retention_limit == 0 {
            return Err(SnapshotError::RetentionFull);
        }
        Ok(Self {
            retention_limit,
            records: BTreeMap::new(),
            insertion: 0,
            teardown: false,
        })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn contains(&self, id: &str) -> bool {
        self.records.contains_key(id)
    }

    pub fn retain_text(&mut self, snapshot: TextSnapshot) -> Result<(), SnapshotError> {
        if self.teardown {
            return Err(SnapshotError::Teardown);
        }
        if !valid_snapshot_id(&snapshot.snapshot_id) {
            return Err(SnapshotError::InvalidId);
        }
        if snapshot.refs.len() > MAX_REFS {
            return Err(SnapshotError::BoundExceeded);
        }
        for record in &snapshot.refs {
            record.captured.validate()?;
        }
        self.reserve_slot(&snapshot.snapshot_id)?;
        let refs = snapshot
            .refs
            .iter()
            .cloned()
            .map(|item| (item.captured.reference.clone(), item))
            .collect();
        self.insertion = self.insertion.saturating_add(1);
        self.records.insert(
            snapshot.snapshot_id.clone(),
            StoredRecord {
                snapshot: StoredSnapshot::Text(snapshot),
                refs,
                pinned: 0,
                invalidated: false,
                insertion: self.insertion,
            },
        );
        Ok(())
    }

    pub fn retain_screenshot(&mut self, snapshot: ScreenshotSnapshot) -> Result<(), SnapshotError> {
        if self.teardown {
            return Err(SnapshotError::Teardown);
        }
        if !valid_snapshot_id(&snapshot.snapshot_id) {
            return Err(SnapshotError::InvalidId);
        }
        self.reserve_slot(&snapshot.snapshot_id)?;
        self.insertion = self.insertion.saturating_add(1);
        self.records.insert(
            snapshot.snapshot_id.clone(),
            StoredRecord {
                snapshot: StoredSnapshot::Screenshot(snapshot),
                refs: HashMap::new(),
                pinned: 0,
                invalidated: false,
                insertion: self.insertion,
            },
        );
        Ok(())
    }

    fn reserve_slot(&mut self, id: &str) -> Result<(), SnapshotError> {
        if self.records.contains_key(id) {
            return Ok(());
        }
        if self.records.len() < self.retention_limit {
            return Ok(());
        }
        let candidate = self
            .records
            .values()
            .filter(|record| record.pinned == 0)
            .min_by_key(|record| record.insertion)
            .map(|record| record.snapshot.id().to_string());
        match candidate {
            Some(candidate) => {
                self.records.remove(&candidate);
                Ok(())
            }
            None => Err(SnapshotError::RetentionFull),
        }
    }

    pub fn get(&self, id: &str) -> Option<&StoredSnapshot> {
        self.records
            .get(id)
            .filter(|record| !record.invalidated)
            .map(|record| &record.snapshot)
    }
    pub fn get_any(&self, id: &str) -> Option<&StoredSnapshot> {
        self.records.get(id).map(|record| &record.snapshot)
    }

    pub fn pin_text(&mut self, id: &str, epoch: u64) -> Result<TextSnapshot, SnapshotError> {
        let record = self.records.get_mut(id).ok_or(SnapshotError::Evicted)?;
        if record.invalidated {
            return Err(SnapshotError::Evicted);
        }
        let snapshot = match &record.snapshot {
            StoredSnapshot::Text(snapshot) if snapshot.document_epoch == epoch => snapshot.clone(),
            StoredSnapshot::Text(_) => return Err(SnapshotError::EpochMismatch),
            StoredSnapshot::Screenshot(_) => return Err(SnapshotError::WrongKind),
        };
        record.pinned = record.pinned.saturating_add(1);
        Ok(snapshot)
    }

    pub fn pin(
        &mut self,
        id: &str,
        kind: SnapshotKind,
        epoch: u64,
    ) -> Result<StoredSnapshot, SnapshotError> {
        if self.teardown {
            return Err(SnapshotError::Teardown);
        }
        let record = self.records.get_mut(id).ok_or(SnapshotError::Evicted)?;
        if record.invalidated {
            return Err(SnapshotError::Evicted);
        }
        if record.snapshot.kind() != kind {
            return Err(SnapshotError::WrongKind);
        }
        if record.snapshot.epoch() != epoch {
            return Err(SnapshotError::EpochMismatch);
        }
        record.pinned = record.pinned.saturating_add(1);
        Ok(record.snapshot.clone())
    }

    pub fn unpin(&mut self, id: &str) {
        let remove = self
            .records
            .get_mut(id)
            .map(|record| {
                record.pinned = record.pinned.saturating_sub(1);
                record.pinned == 0 && record.invalidated
            })
            .unwrap_or(false);
        if remove {
            self.records.remove(id);
        }
    }

    pub fn pin_count(&self, id: &str) -> usize {
        self.records
            .get(id)
            .map(|record| record.pinned)
            .unwrap_or(0)
    }

    pub fn resolve_ref(
        &self,
        snapshot_id: &str,
        reference: &str,
        epoch: u64,
        current: &[RefCandidate],
    ) -> Result<RefResolution, SnapshotError> {
        if !valid_ref(reference) {
            return Err(SnapshotError::InvalidRef);
        }
        let record = self
            .records
            .get(snapshot_id)
            .ok_or(SnapshotError::Evicted)?;
        if record.invalidated {
            return Err(SnapshotError::Evicted);
        }
        match &record.snapshot {
            StoredSnapshot::Text(snapshot) if snapshot.document_epoch == epoch => (),
            StoredSnapshot::Text(_) => return Err(SnapshotError::EpochMismatch),
            _ => return Err(SnapshotError::WrongKind),
        };
        let captured = record.refs.get(reference).ok_or(SnapshotError::NotFound)?;
        if let Some(identity) = &captured.backend_identity {
            let matches = current
                .iter()
                .filter(|candidate| candidate.identity.as_ref() == Some(identity))
                .collect::<Vec<_>>();
            if matches.len() == 1 {
                return Ok(RefResolution::Resolved(Box::new(captured.clone())));
            }
            if matches.len() > 1 {
                return Ok(RefResolution::Ambiguous {
                    candidate_count: matches.len(),
                });
            }
        }
        // When the current backend node no longer matches the captured node, use
        // its deterministic redacted fallback key to find a safe matching candidate.
        let key = captured.fallback_key();
        let mut candidates = current
            .iter()
            .filter(|candidate| {
                FallbackKey {
                    frame_path: candidate.frame_path.clone(),
                    role: candidate.role.clone(),
                    name: candidate.name.clone(),
                } == key
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Ok(RefResolution::NotFound);
        }
        candidates.sort_by_key(|candidate| candidate.traversal_index);
        if candidates
            .windows(2)
            .any(|pair| pair[0].traversal_index == pair[1].traversal_index)
        {
            return Ok(RefResolution::Ambiguous {
                candidate_count: candidates.len(),
            });
        }
        let selected = candidates.get(captured.captured.nth as usize);
        Ok(selected
            .map(|_| RefResolution::Resolved(Box::new(captured.clone())))
            .unwrap_or(RefResolution::NotFound))
    }

    pub fn invalidate_before(&mut self, epoch: u64) {
        let ids = self
            .records
            .iter_mut()
            .filter_map(|(id, record)| {
                if record.snapshot.epoch() < epoch {
                    record.invalidated = true;
                    (record.pinned == 0).then_some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for id in ids {
            self.records.remove(&id);
        }
    }

    pub fn begin_teardown(&mut self) {
        self.teardown = true;
    }
    pub fn teardown_ready(&self) -> bool {
        self.records.values().all(|record| record.pinned == 0)
    }
    pub fn complete_teardown(&mut self) -> Result<(), SnapshotError> {
        if !self.teardown_ready() {
            return Err(SnapshotError::Teardown);
        }
        self.records.clear();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentTransition {
    TopLevelDocumentReplaced,
    FrameDocumentReplaced,
    FrameInserted,
    FrameRemoved,
    FrameTreeReplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameDocumentChange {
    Fragment,
    PushState,
    ReplaceState,
    DomMutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochObservation {
    pub frame_id: String,
    pub document_id: String,
    pub represented: bool,
}

#[derive(Debug, Default)]
pub struct DocumentEpochTracker {
    epoch: DocumentEpoch,
    documents: BTreeMap<String, String>,
}
impl DocumentEpochTracker {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.value()
    }
    pub fn observe(&mut self, observation: EpochObservation) -> Result<u64, SnapshotError> {
        if observation.frame_id.is_empty() || observation.document_id.is_empty() {
            return Err(SnapshotError::IdentityOutOfBounds);
        }
        let previous = self.documents.get(&observation.frame_id).cloned();
        if !observation.represented {
            if previous.is_some() {
                self.documents.remove(&observation.frame_id);
                return self.epoch.replace(DocumentTransition::FrameRemoved);
            }
            return Ok(self.epoch.value());
        }
        if previous.as_deref() == Some(observation.document_id.as_str()) {
            return Ok(self.epoch.value());
        }
        self.documents
            .insert(observation.frame_id, observation.document_id);
        self.epoch
            .replace(DocumentTransition::FrameDocumentReplaced)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentEpoch {
    value: u64,
}

impl Default for DocumentEpoch {
    fn default() -> Self {
        Self::new()
    }
}
impl DocumentEpoch {
    pub const fn new() -> Self {
        Self { value: 0 }
    }
    pub const fn value(self) -> u64 {
        self.value
    }
    pub fn replace(&mut self, _transition: DocumentTransition) -> Result<u64, SnapshotError> {
        if self.value >= MAX_SAFE_INTEGER {
            return Err(SnapshotError::EpochOverflow);
        }
        self.value += 1;
        Ok(self.value)
    }
    pub const fn same_document(self, _change: SameDocumentChange) -> u64 {
        self.value
    }
}

pub fn valid_snapshot_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
pub fn valid_ref(value: &str) -> bool {
    let Some(number) = value.strip_prefix('e') else {
        return false;
    };
    number
        .parse::<u64>()
        .ok()
        .is_some_and(|number| (1..=MAX_REFS as u64).contains(&number))
}
pub fn new_snapshot_id(seed: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(seed.as_ref());
    hex(&digest[..16])
}

pub fn encode_ax_jsonl(
    records: &[AxRecord],
    max_bytes: usize,
) -> Result<(String, bool), SnapshotError> {
    let mut output = String::new();
    let mut truncated = false;
    for record in records {
        let line = record.canonical_line()?;
        if output.len().saturating_add(line.len()) > max_bytes {
            truncated = true;
            break;
        }
        output.push_str(&line);
    }
    Ok((output, truncated))
}

pub fn encode_dom_text(content: &str, max_bytes: usize) -> (String, bool) {
    let output = utf8_safe_truncate(content, max_bytes);
    (output.clone(), output.len() != content.len())
}

/// Bound an accessibility field to its byte budget.
///
/// Truncation only.  It is deliberately not named for redaction: the journal's
/// redaction contract refuses when no policy is bound, precisely so that
/// shortening a value is never mistaken for removing sensitive material from it.
/// A caller that needs redacted output wants `journal::redaction`, which fails
/// closed instead of returning a prefix of the secret.
pub fn truncate_ax_field(value: &str, max_bytes: usize) -> String {
    utf8_safe_truncate(value, max_bytes)
}

pub fn ax_record_from_value(value: &Value) -> Result<AxRecord, SnapshotError> {
    let object = value.as_object().ok_or(SnapshotError::Serialization)?;
    let depth = object
        .get("depth")
        .and_then(Value::as_i64)
        .ok_or(SnapshotError::Serialization)?;
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .ok_or(SnapshotError::Serialization)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or(SnapshotError::Serialization)?;
    let item = AxRecord {
        depth,
        role: truncate_ax_field(role, MAX_ROLE_BYTES),
        name: truncate_ax_field(name, MAX_NAME_BYTES),
        value: object
            .get("value")
            .and_then(Value::as_str)
            .map(|value| truncate_ax_field(value, MAX_VALUE_BYTES)),
        reference: object
            .get("ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    };
    item.canonical_line()?;
    Ok(item)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: &str) -> String {
        new_snapshot_id(seed)
    }

    #[test]
    fn ax_truncation_keeps_complete_records_and_refs_are_bounded() {
        let records = vec![
            AxRecord {
                depth: 0,
                role: "root".into(),
                name: "hello".into(),
                value: None,
                reference: Some("e1".into()),
            },
            AxRecord {
                depth: 1,
                role: "button".into(),
                name: "world".into(),
                value: None,
                reference: Some("e2".into()),
            },
        ];
        let one = records[0].canonical_line().unwrap();
        let (content, truncated) = encode_ax_jsonl(&records, one.len() + 1).unwrap();
        assert_eq!(content, one);
        assert!(truncated);
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn backend_identity_falls_back_deterministically_and_duplicate_order_is_ambiguous() {
        let snapshot_id = id("snapshot");
        let reference = SnapshotRef::new("e1", "button", "Save", 0).unwrap();
        let mut store = BrowserSnapshotStore::new(2).unwrap();
        store
            .retain_text(TextSnapshot {
                snapshot_id: snapshot_id.clone(),
                kind: SnapshotKind::Ax,
                document_epoch: 0,
                source_origin: "https://example.test".into(),
                content_schema: AX_SCHEMA,
                content: String::new(),
                truncated: false,
                refs_truncated: false,
                refs: vec![RefRecord {
                    captured: reference,
                    frame_path: vec![],
                    backend_identity: None,
                    raw_role: None,
                    raw_name: None,
                    classification: None,
                }],
            })
            .unwrap();
        let candidates = vec![
            RefCandidate {
                identity: None,
                frame_path: vec![],
                role: "button".into(),
                name: "Save".into(),
                traversal_index: 0,
            },
            RefCandidate {
                identity: None,
                frame_path: vec![],
                role: "button".into(),
                name: "Save".into(),
                traversal_index: 1,
            },
        ];
        assert_eq!(
            store
                .resolve_ref(&snapshot_id, "e1", 0, &candidates)
                .unwrap(),
            RefResolution::Resolved(Box::new(store.records[&snapshot_id].refs["e1"].clone(),))
        );
        let mut ambiguous = candidates.clone();
        ambiguous[1].traversal_index = 0;
        assert_eq!(
            store
                .resolve_ref(&snapshot_id, "e1", 0, &ambiguous)
                .unwrap(),
            RefResolution::Ambiguous { candidate_count: 2 }
        );
    }

    #[test]
    fn epoch_only_changes_for_document_replacement_and_overflow_is_safe() {
        let mut epoch = DocumentEpoch::new();
        assert_eq!(epoch.same_document(SameDocumentChange::PushState), 0);
        assert_eq!(epoch.replace(DocumentTransition::FrameInserted).unwrap(), 1);
        epoch.value = MAX_SAFE_INTEGER;
        assert_eq!(
            epoch.replace(DocumentTransition::TopLevelDocumentReplaced),
            Err(SnapshotError::EpochOverflow)
        );
    }
}
