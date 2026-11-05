//! Browser-plane snapshot and reference retention.
//!
//! This store retains the exact bounded caller-visible observation together
//! with the private identity projection needed for a later action.  Retaining
//! the two together prevents a click from silently falling back to a newer
//! document or to an unredacted accessible name.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::browser::state_text::{one_line, short_url, NodeFacts};
use crate::coordinate::ScreenshotSnapshot;
use crate::journal::redaction::utf8_safe_truncate;

pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_REFS: usize = 4_096;
pub const MAX_REF: usize = 4_096;
pub const MAX_ROLE_BYTES: usize = 128;
pub const MAX_NAME_BYTES: usize = 4_096;
pub const MAX_VALUE_BYTES: usize = 4_096;
/// The `ax` snapshot's page text: one accessibility node per line, as
/// [`render_ax_text`] renders it.
pub const AX_SCHEMA: &str = "ck-browser-snapshot-ax-text/v1";
pub const DOM_SCHEMA: &str = "ck-browser-snapshot-dom-text/v1";
/// The default snapshot's page text: one element per line, as
/// `crate::browser::state_text` renders it.
pub const STATE_TEXT_SCHEMA: &str = "ck-browser-state-text/v1";

/// The longest source URL a snapshot reply repeats. The retained snapshot
/// keeps the whole URL for its action checks; only the reply's copy is cut.
pub const MAX_SOURCE_ORIGIN_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    Actionable,
    Ax,
    DomFull,
    Screenshot,
}

impl SnapshotKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Actionable => "actionable",
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

/// Browser-reported identity of one frame document. Session changes invalidate
/// refs even when Chrome retains a frame id across a renderer replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameDocument {
    pub navigation_revision: u64,
    pub frame_id: String,
    pub parent_id: Option<String>,
    pub session_id: String,
    pub loader_id: String,
    pub url: String,
    pub origin: String,
}

impl FrameDocument {
    /// URL and event revision can change on pushState or a fragment navigation.
    /// The loader, session and origin fence the document an input can reach.
    pub fn same_document(&self, other: &Self) -> bool {
        self.frame_id == other.frame_id
            && self.parent_id == other.parent_id
            && self.session_id == other.session_id
            && self.loader_id == other.loader_id
            && self.origin == other.origin
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefRecord {
    pub frame_document: Option<FrameDocument>,
    pub captured: SnapshotRef,
    pub frame_path: Vec<String>,
    pub backend_identity: Option<BackendNodeIdentity>,
    pub raw_role: Option<String>,
    pub raw_name: Option<String>,
    /// Form facts captured from the same document epoch as this reference.
    /// An error is an unknown classification with its named cause, not an
    /// assertion that no hazard exists.
    pub classification: Result<
        Box<crate::classification::NonTypeClassificationRecord>,
        crate::classification::ClassificationUnavailable,
    >,
}

impl RefRecord {
    pub(crate) fn redact(&mut self, redact: &dyn Fn(&mut String)) {
        redact(&mut self.captured.name);
        redact(&mut self.captured.role);
        for text in [&mut self.raw_name, &mut self.raw_role]
            .into_iter()
            .flatten()
        {
            redact(text);
        }
        if let Some(frame) = &mut self.frame_document {
            redact(&mut frame.url);
        }
        if let Ok(classification) = &mut self.classification {
            for token in &mut classification.target_autocomplete_tokens {
                redact(token);
            }
            for control in &mut classification.associated_form_controls {
                for token in &mut control.autocomplete_tokens {
                    redact(token);
                }
            }
        }
    }

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
    /// Refuse a record outside the snapshot's bounds: a negative depth, or a
    /// role, name or value longer than its byte limit.
    pub fn check_bounds(&self) -> Result<(), SnapshotError> {
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
        Ok(())
    }
}

/// Which committed document the browser's main frame showed, as the browser
/// itself reports it.
///
/// The module's own document epoch only moves on navigations it starts or
/// watches. A page can also replace itself (a timer, a script assigning
/// `location`, a late redirect), and only the browser knows that happened.
/// Reads compare two of these taken around a capture, and an action compares
/// the one recorded with its snapshot to the one current at dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedDocument {
    /// The committed main-frame URL.
    pub url: String,
    /// The browser's actual security origin, including opaque origins.
    pub security_origin: String,
    /// The browser's unique id for the current history entry
    /// (`Page.getNavigationHistory`). Every committed navigation that adds
    /// or replaces an entry changes it, including a same-document one such as
    /// a fragment change or `history.pushState`.
    pub entry_id: i64,
    /// The id of every history entry, in order, with `current_index` naming
    /// the current one. A navigation away and a history traversal back can
    /// land on the original entry id again, but the entry it created remains
    /// in this list, so the round trip still shows.
    pub history: Vec<i64>,
    pub current_index: usize,
    /// The main frame's document loader (`Page.getFrameTree`). It changes when
    /// a new document commits, including a reload, and stays the same across
    /// same-document navigations, which keep the elements a ref names.
    pub loader_id: String,
}

impl CommittedDocument {
    /// A document whose history holds only its own entry.
    pub fn new(url: impl Into<String>, entry_id: i64, loader_id: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            security_origin: "null".into(),
            entry_id,
            history: vec![entry_id],
            current_index: 0,
            loader_id: loader_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSnapshot {
    pub snapshot_id: String,
    pub kind: SnapshotKind,
    pub document_epoch: u64,
    pub source_origin: String,
    /// The browser-reported document this snapshot was read from. `None` for
    /// an observation handed in without one, which no action will trust.
    pub source_document: Option<CommittedDocument>,
    pub content_schema: &'static str,
    pub content: String,
    pub truncated: bool,
    pub refs_truncated: bool,
    pub refs: Vec<RefRecord>,
}

impl TextSnapshot {
    /// Sanitize before the store or reply encoder clones any captured text.
    pub(crate) fn redact(&mut self, redact: &dyn Fn(&mut String)) {
        redact(&mut self.content);
        redact(&mut self.source_origin);
        if let Some(document) = &mut self.source_document {
            redact(&mut document.url);
        }
        for reference in &mut self.refs {
            reference.redact(redact);
        }
    }
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
    number.parse::<u64>().ok().is_some_and(|number| number > 0)
}
pub fn new_snapshot_id(seed: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(seed.as_ref());
    hex(&digest[..16])
}

/// The `ax` snapshot's page text, cut to its byte bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxText {
    /// One accessibility node per line, as [`render_ax_text`] describes.
    pub text: String,
    /// The ref of every line in `text`. These, and only these, stay usable
    /// for an action on this snapshot.
    pub printed_refs: BTreeSet<String>,
    /// Bytes and lines the byte bound removed; zero when nothing was cut.
    pub cut_bytes: usize,
    pub cut_lines: usize,
}

/// Render the accessibility tree as plain text, one node per line, in the
/// default snapshot's line style (see `crate::browser::state_text`):
///
/// ```text
/// <ref> <role> <name>[, Value: <value>]
/// ```
///
/// Each line is indented two spaces per printed ancestor. A node without a
/// ref prints without one, and the role is Chrome's own accessibility role.
/// Unlike the default snapshot nothing is folded into an outline: every node
/// prints except the ones that repeat text already shown (see below).
///
/// A value prints under the default snapshot's rules: a link shows where it
/// points, a numeric control (slider, progress bar, ...) its level, and a text
/// field its contents only when `facts` show its DOM node is neither a
/// credential nor a payment field. Below a text field only controls print,
/// because Chrome's inner editor there names its text with the field's value.
///
/// The text is cut at a whole line so that it fits `max_bytes`, and the
/// lines after the first one that does not fit are dropped with it.
pub fn render_ax_text(
    records: &[AxRecord],
    facts: &HashMap<String, NodeFacts>,
    max_bytes: usize,
) -> Result<AxText, SnapshotError> {
    struct Seen<'a> {
        record: &'a AxRecord,
        /// Inside a text field, outside any control within it: the node's
        /// text may be the field's value.
        in_field: bool,
    }
    let mut lines: Vec<(String, Option<&str>)> = Vec::new();
    let mut ancestors: Vec<Seen<'_>> = Vec::new();
    // Depths of the ancestors that printed, which set a line's indent.
    let mut printed: Vec<i64> = Vec::new();
    for record in records {
        record.check_bounds()?;
        while ancestors
            .last()
            .is_some_and(|parent| parent.record.depth >= record.depth)
        {
            ancestors.pop();
        }
        while printed.last().is_some_and(|depth| *depth >= record.depth) {
            printed.pop();
        }
        let parent = ancestors.last();
        // Inline boxes are layout fragments of text already named by their parent.
        // Repeating them can exhaust the byte budget before any controls are shown.
        let folded = record.role == "InlineTextBox"
            || (record.role == "StaticText"
                && record.value.is_none()
                && parent.is_some_and(|parent| {
                    !record.name.is_empty() && parent.record.name == record.name
                }));
        let withheld = parent.is_some_and(|parent| parent.in_field) && !is_actionable(&record.role);
        ancestors.push(Seen {
            record,
            in_field: is_text_field(&record.role) || withheld,
        });
        if folded || withheld {
            continue;
        }
        let mut line = "  ".repeat(printed.len());
        if let Some(reference) = &record.reference {
            line.push_str(reference);
            line.push(' ');
        }
        line.push_str(&one_line(&record.role));
        let name = one_line(&record.name);
        if !name.is_empty() {
            line.push(' ');
            line.push_str(&name);
        }
        if let Some(value) = ax_shown_value(record, facts).filter(|value| !value.is_empty()) {
            line.push_str(", Value: ");
            line.push_str(&value);
        }
        if let Some(reference) = &record.reference {
            crate::browser::state_text::append_classification_notice(&mut line, reference, facts);
        }
        line.push('\n');
        lines.push((line, record.reference.as_deref()));
        printed.push(record.depth);
    }
    let mut rendered = AxText {
        text: String::new(),
        printed_refs: BTreeSet::new(),
        cut_bytes: 0,
        cut_lines: 0,
    };
    let mut lines = lines.into_iter();
    for (line, reference) in lines.by_ref() {
        if rendered.text.len().saturating_add(line.len()) > max_bytes {
            rendered.cut_bytes = line.len();
            rendered.cut_lines = 1;
            break;
        }
        rendered.text.push_str(&line);
        rendered.printed_refs.extend(reference.map(str::to_string));
    }
    for (line, _) in lines {
        rendered.cut_bytes += line.len();
        rendered.cut_lines += 1;
    }
    Ok(rendered)
}

/// The value an `ax` line shows, by the default snapshot's value rules
/// (`Tree::shown_value` in `crate::browser::state_text`).
fn ax_shown_value(record: &AxRecord, facts: &HashMap<String, NodeFacts>) -> Option<String> {
    let facts = record
        .reference
        .as_deref()
        .and_then(|reference| facts.get(reference));
    let value = record.value.as_deref();
    if record.role == "link" {
        facts
            .and_then(|facts| facts.url.as_deref())
            .and_then(short_url)
    } else if is_text_field(&record.role) {
        // What a person typed prints only when the field's DOM node is known
        // to be neither a credential nor a payment field. No facts, or no
        // verdict in them, withholds it.
        value
            .filter(|_| facts.and_then(|facts| facts.credential) == Some(false))
            .map(one_line)
    } else if is_value_control(&record.role) {
        value.map(one_line)
    } else {
        None
    }
}

// The three role sets below copy the default snapshot's private ones in
// `crate::browser::state_text` (`is_text_field`, `is_value_control`,
// `is_actionable`), so both views withhold the same values. The test
// `ax_value_rules_match_the_default_snapshot` renders the same nodes through
// both and fails if the copies drift apart.

fn is_text_field(role: &str) -> bool {
    matches!(role, "textbox" | "searchbox" | "combobox")
}

fn is_value_control(role: &str) -> bool {
    matches!(
        role,
        "slider" | "spinbutton" | "progressbar" | "meter" | "scrollbar"
    )
}

fn is_actionable(role: &str) -> bool {
    matches!(
        role,
        "link"
            | "button"
            | "textbox"
            | "searchbox"
            | "combobox"
            | "listbox"
            | "option"
            | "checkbox"
            | "radio"
            | "slider"
            | "spinbutton"
            | "switch"
            | "tab"
            | "menuitem"
            | "menuitemcheckbox"
            | "menuitemradio"
            | "treeitem"
            | "PopUpButton"
            | "ToggleButton"
            | "MenuListOption"
            | "ListBoxOption"
    )
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
    item.check_bounds()?;
    Ok(item)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bound a text snapshot's page text to `max_bytes` and build its reply.
///
/// The page text goes in `state_text`; there is no separate ref table, the
/// refs are the ids the text itself prints. So the retained snapshot keeps
/// exactly the refs its text names, and an action can use a ref only if the
/// caller was shown it:
///
/// - the default view arrives already rendered within the bound with its refs
///   narrowed to the printed ones (`prior_cut` carries what that render cut);
/// - the AX view likewise arrives cut at a whole line by [`render_ax_text`],
///   with its refs narrowed to the ones its printed lines name;
/// - the raw DOM view arrives already laid out within the bound (see
///   `browser::dom_layout`) with its refs narrowed to the ones its comments
///   name; anything still over the bound is cut at a character boundary.
///
/// The reply's copy of the source URL is cut at [`MAX_SOURCE_ORIGIN_BYTES`];
/// the retained snapshot keeps all of it for its action checks.
pub fn bounded_text_reply(
    snapshot: &mut TextSnapshot,
    max_bytes: usize,
    prior_cut: (usize, usize),
    context: Value,
) -> Value {
    let (mut cut_bytes, mut cut_lines) = prior_cut;
    if snapshot.content.len() > max_bytes {
        let mut end = max_bytes;
        while !snapshot.content.is_char_boundary(end) {
            end -= 1;
        }
        if snapshot.kind != SnapshotKind::DomFull {
            end = snapshot.content[..end].rfind('\n').map_or(0, |i| i + 1);
        }
        let removed = &snapshot.content[end..];
        cut_bytes += removed.len();
        cut_lines += removed.lines().count();
        snapshot.content.truncate(end);
        snapshot.truncated = true;
    }
    let source = utf8_safe_truncate(&snapshot.source_origin, MAX_SOURCE_ORIGIN_BYTES);
    serde_json::json!({
        "outcome":"ok", "mode":snapshot.kind.as_str(),
        "snapshot_id":snapshot.snapshot_id, "document_epoch":snapshot.document_epoch,
        "source_origin":source, "content_schema":snapshot.content_schema,
        "truncated":snapshot.truncated, "refs_truncated":snapshot.refs_truncated,
        (crate::browser::state_text::STATE_TEXT_FIELD):snapshot.content,
        "omitted":{"state_text_bytes":cut_bytes, "state_text_lines":cut_lines,
            "source_origin":source.len() != snapshot.source_origin.len()},
        "context":context
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: &str) -> String {
        new_snapshot_id(seed)
    }

    fn ax(depth: i64, role: &str, name: &str, reference: Option<&str>) -> AxRecord {
        AxRecord {
            depth,
            role: role.into(),
            name: name.into(),
            value: None,
            reference: reference.map(str::to_string),
        }
    }

    fn valued(record: AxRecord, value: &str) -> AxRecord {
        AxRecord {
            value: Some(value.into()),
            ..record
        }
    }

    fn credential(verdict: Option<bool>) -> NodeFacts {
        NodeFacts {
            credential: verdict,
            ..NodeFacts::default()
        }
    }

    #[test]
    fn ax_inline_fragments_cannot_exhaust_the_control_budget() {
        let mut records = vec![
            ax(0, "RootWebArea", "Local form", None),
            ax(1, "StaticText", "Skip to content", None),
        ];
        for _ in 0..100 {
            for letter in "Skip to content".chars() {
                records.push(ax(2, "InlineTextBox", &letter.to_string(), None));
            }
        }
        records.push(ax(1, "checkbox", "Request authorization", Some("e2")));
        let rendered = render_ax_text(&records, &HashMap::new(), 12000).unwrap();
        assert_eq!(rendered.cut_lines, 0);
        assert_eq!(
            rendered.text,
            "RootWebArea Local form\n  StaticText Skip to content\n  e2 checkbox Request authorization\n"
        );
    }

    #[test]
    fn ax_repeated_static_text_folds_but_distinct_text_and_controls_remain() {
        let records = [
            ax(0, "RootWebArea", "Form", None),
            ax(1, "button", "Save", None),
            ax(2, "StaticText", "Save", None),
            ax(3, "InlineTextBox", "S", None),
            ax(2, "StaticText", "Details", None),
            ax(1, "checkbox", "Save", None),
        ];
        let rendered = render_ax_text(&records, &HashMap::new(), 12000).unwrap();
        assert_eq!(
            rendered.text,
            "RootWebArea Form\n  button Save\n    StaticText Details\n  checkbox Save\n"
        );
    }

    /// The whole `ax` line grammar on one small page: refs, indentation by
    /// printed ancestor (an unrecorded ignored node leaves no gap), folded
    /// text, names on one line, and each value rule.
    #[test]
    fn ax_text_golden_for_a_small_sign_in_page() {
        let records = vec![
            ax(0, "RootWebArea", "Sign in", Some("e1")),
            ax(1, "heading", "Welcome back", Some("e2")),
            ax(2, "StaticText", "Welcome back", None),
            valued(ax(1, "textbox", "Email", Some("e3")), "ada@example.test"),
            ax(2, "generic", "", Some("e4")),
            ax(3, "StaticText", "ada@example.test", None),
            valued(ax(1, "textbox", "Password", Some("e5")), "hunter2"),
            valued(
                ax(1, "textbox", "Card number", Some("e6")),
                "4111111111111111",
            ),
            valued(
                ax(1, "link", "Help", Some("e7")),
                "https://example.test/help",
            ),
            valued(ax(1, "slider", "Volume", Some("e8")), "40"),
            valued(ax(1, "button", "Continue", Some("e9")), "pressed"),
            ax(2, "StaticText", "Continue", None),
            ax(3, "InlineTextBox", "Continue", None),
            ax(1, "list", "Steps", Some("e10")),
            ax(3, "listitem", "First", Some("e11")),
            ax(1, "StaticText", "Line one\n  line two", None),
        ];
        let facts = HashMap::from([
            ("e3".to_string(), credential(Some(false))),
            ("e5".to_string(), credential(Some(true))),
            (
                "e7".to_string(),
                NodeFacts {
                    url: Some("https://example.test/help?session=1".into()),
                    ..credential(Some(false))
                },
            ),
        ]);
        let rendered = render_ax_text(&records, &facts, usize::MAX).unwrap();
        assert_eq!(
            rendered.text,
            "e1 RootWebArea Sign in
  e2 heading Welcome back
  e3 textbox Email, Value: ada@example.test
  e5 textbox Password
  e6 textbox Card number
  e7 link Help, Value: example.test/help
  e8 slider Volume, Value: 40
  e9 button Continue
  e10 list Steps
    e11 listitem First
  StaticText Line one line two
"
        );
        let printed: Vec<&str> = rendered.printed_refs.iter().map(String::as_str).collect();
        assert_eq!(
            printed,
            ["e1", "e10", "e11", "e2", "e3", "e5", "e6", "e7", "e8", "e9"]
        );
        assert_eq!((rendered.cut_bytes, rendered.cut_lines), (0, 0));
    }

    /// A credential or payment field's value never prints: not on the
    /// field's own line, and not through the text Chrome's inner editor holds
    /// below it, whatever the field's DOM verdict says or when there is none.
    #[test]
    fn ax_text_never_prints_a_credential_fields_value() {
        const SECRET: &str = "hunter2-4111111111111111";
        for role in ["textbox", "searchbox", "combobox"] {
            for verdict in [Some(true), None, Some(false)] {
                let records = vec![
                    ax(0, "RootWebArea", "Pay", Some("e1")),
                    valued(ax(1, role, "Card", Some("e2")), SECRET),
                    ax(2, "generic", "", Some("e3")),
                    ax(3, "StaticText", SECRET, Some("e4")),
                    ax(4, "InlineTextBox", SECRET, None),
                    ax(3, "paragraph", SECRET, None),
                    ax(3, "link", "Card help", Some("e5")),
                ];
                let facts = HashMap::from([("e2".to_string(), credential(verdict))]);
                let rendered = render_ax_text(&records, &facts, usize::MAX).unwrap();
                let field_line = rendered.text.lines().nth(1).unwrap();
                assert_eq!(
                    rendered
                        .text
                        .lines()
                        .filter(|line| line.contains(SECRET))
                        .count(),
                    usize::from(verdict == Some(false)),
                    "{role} {verdict:?}: {}",
                    rendered.text
                );
                if verdict != Some(false) {
                    assert_eq!(field_line, format!("  e2 {role} Card"));
                }
                // A control inside the field stays reachable; the editor's
                // text and its ref do not.
                assert!(rendered.text.contains("\n    e5 link Card help\n"));
                assert!(!rendered.printed_refs.contains("e3"));
                assert!(!rendered.printed_refs.contains("e4"));
            }
        }
    }

    /// The `ax` view copies the default snapshot's private role sets; this
    /// renders the same nodes through both and fails when they disagree on a
    /// value shown or on an element printed inside a text field.
    #[test]
    fn ax_value_rules_match_the_default_snapshot() {
        use crate::browser::state_text::{render, Filters, RenderInput, Zoom};
        let roles = [
            "textbox",
            "searchbox",
            "combobox",
            "slider",
            "spinbutton",
            "progressbar",
            "meter",
            "scrollbar",
            "link",
            "button",
            "listbox",
            "option",
            "checkbox",
            "radio",
            "switch",
            "tab",
            "menuitem",
            "menuitemcheckbox",
            "menuitemradio",
            "treeitem",
            "PopUpButton",
            "ToggleButton",
            "MenuListOption",
            "ListBoxOption",
            "heading",
            "paragraph",
            "image",
            "listitem",
            "cell",
            "StaticText",
        ];
        // The default snapshot's printed value, or `None`, and whether its
        // line for `inner` appears, as zooming into the page prints them.
        let outline = |records: &[AxRecord], facts: &HashMap<String, NodeFacts>| {
            render(&RenderInput {
                records,
                facts,
                page_url: "https://example.test/",
                snapshot_id: "0123456789abcdef0123456789abcdef",
                zoom: Some(Zoom {
                    requested: "e1",
                    target: Some("e1"),
                }),
                filters: &Filters::default(),
                max_bytes: usize::MAX,
            })
            .text
        };
        let value_of = |text: &str, reference: &str| {
            text.lines()
                .find(|line| line.split_whitespace().next() == Some(reference))
                .map(|line| {
                    line.split_once(", Value: ")
                        .map(|(_, value)| value.to_string())
                })
        };
        for role in roles {
            for verdict in [None, Some(true), Some(false)] {
                let records = vec![
                    ax(0, "RootWebArea", "Page", Some("e1")),
                    valued(ax(1, role, "Field", Some("e2")), "v42"),
                ];
                let facts = HashMap::from([(
                    "e2".to_string(),
                    NodeFacts {
                        url: Some("https://example.test/target".into()),
                        ..credential(verdict)
                    },
                )]);
                let ours = render_ax_text(&records, &facts, usize::MAX).unwrap().text;
                assert_eq!(
                    value_of(&ours, "e2"),
                    value_of(&outline(&records, &facts), "e2"),
                    "{role} {verdict:?}"
                );
            }
            for field in ["textbox", "searchbox", "combobox"] {
                let records = vec![
                    ax(0, "RootWebArea", "Page", Some("e1")),
                    ax(1, field, "Field", Some("e2")),
                    ax(2, "generic", "Editor", Some("e3")),
                    ax(3, role, "Inner", Some("e4")),
                ];
                let ours = render_ax_text(&records, &HashMap::new(), usize::MAX)
                    .unwrap()
                    .text;
                assert_eq!(
                    value_of(&ours, "e4").is_some(),
                    value_of(&outline(&records, &HashMap::new()), "e4").is_some(),
                    "{role} inside {field}"
                );
            }
        }
    }

    /// The text is cut at a whole line, and only the refs of lines that
    /// printed are reported: a ref on a cut line is never usable.
    #[test]
    fn ax_cut_keeps_whole_lines_and_only_their_refs() {
        let records = vec![
            ax(0, "RootWebArea", "hello", Some("e1")),
            ax(1, "button", "world", Some("e2")),
            ax(1, "button", "again", Some("e3")),
        ];
        let first = "e1 RootWebArea hello\n";
        let rendered = render_ax_text(&records, &HashMap::new(), first.len() + 1).unwrap();
        assert_eq!(rendered.text, first);
        assert_eq!(rendered.printed_refs, BTreeSet::from(["e1".to_string()]));
        assert_eq!(rendered.cut_lines, 2);
        assert_eq!(
            rendered.cut_bytes,
            "  e2 button world\n  e3 button again\n".len()
        );
        let none = render_ax_text(&records, &HashMap::new(), 0).unwrap();
        assert!(none.text.is_empty() && none.printed_refs.is_empty());
        assert_eq!(none.cut_lines, 3);
    }

    #[test]
    fn ax_text_refuses_an_out_of_bounds_record() {
        let records = [ax(-1, "button", "Save", Some("e1"))];
        assert_eq!(
            render_ax_text(&records, &HashMap::new(), usize::MAX),
            Err(SnapshotError::BoundExceeded)
        );
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
                source_document: None,
                content_schema: AX_SCHEMA,
                content: String::new(),
                truncated: false,
                refs_truncated: false,
                refs: vec![RefRecord {
                    frame_document: None,
                    captured: reference,
                    frame_path: vec![],
                    backend_identity: None,
                    raw_role: None,
                    raw_name: None,
                    classification: Err(
                        crate::classification::ClassificationUnavailable::NotCaptured,
                    ),
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
