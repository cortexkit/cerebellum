use std::collections::{BTreeMap, HashMap};

use crate::snapshot_store::{
    AxRecord, BackendNodeIdentity, BrowserSnapshotStore, CommittedDocument, RefRecord,
};

use super::state_text::NodeFacts;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ElementKey {
    epoch: u64,
    target: String,
    frame: String,
    backend: u64,
    loader: String,
    session: String,
    origin: String,
}

fn key(record: &RefRecord, epoch: u64, document: Option<&CommittedDocument>) -> Option<ElementKey> {
    let BackendNodeIdentity {
        target_id,
        frame_id,
        backend_node_id,
    } = record.backend_identity.as_ref()?;
    Some(ElementKey {
        epoch,
        target: target_id.clone(),
        frame: frame_id.clone(),
        backend: *backend_node_id,
        loader: record
            .frame_document
            .as_ref()
            .map(|f| f.loader_id.clone())
            .or_else(|| document.map(|d| d.loader_id.clone()))
            .unwrap_or_default(),
        origin: record
            .frame_document
            .as_ref()
            .map(|f| f.origin.clone())
            .or_else(|| document.map(|d| super::origin_from_url(&d.url)))
            .unwrap_or_default(),
        session: record
            .frame_document
            .as_ref()
            .map(|f| f.session_id.clone())
            .unwrap_or_default(),
    })
}

#[derive(Debug, Default)]
pub(super) struct StableRefs {
    next: u64,
    shown_sequence: u64,
    names: HashMap<ElementKey, CachedName>,
    name_recency: BTreeMap<(u64, u64), ElementKey>,
    shown: HashMap<String, ShownRef>,
}

const MAX_STABLE_IDENTITIES: usize = 20_000;

#[derive(Debug)]
struct CachedName {
    reference: String,
    last_shown: u64,
    number: u64,
}

#[derive(Debug)]
pub(super) struct ShownRef {
    pub record: RefRecord,
    pub snapshot_id: String,
    pub(super) epoch: u64,
    pub(super) document: Option<CommittedDocument>,
}

impl StableRefs {
    pub fn next_document(&self) -> Self {
        Self {
            next: self.next,
            ..Self::default()
        }
    }

    fn cache_name(&mut self, identity: ElementKey, reference: String, last_shown: u64) {
        if let Some(previous) = self.names.remove(&identity) {
            self.name_recency
                .remove(&(previous.last_shown, previous.number));
        }
        let number = reference[1..]
            .parse()
            .expect("allocated browser ref number");
        self.name_recency
            .insert((last_shown, number), identity.clone());
        self.names.insert(
            identity,
            CachedName {
                reference,
                last_shown,
                number,
            },
        );
        while self.names.len() > MAX_STABLE_IDENTITIES {
            let (_, oldest) = self
                .name_recency
                .pop_first()
                .expect("cached name has a recency entry");
            self.names.remove(&oldest);
        }
    }
    /// Capture order is only a temporary join key. Browser identity owns the
    /// public name, so inserting a sibling cannot move an existing reference.
    pub fn assign(
        &mut self,
        records: &mut [AxRecord],
        refs: &mut [RefRecord],
        facts: &mut HashMap<String, NodeFacts>,
        epoch: u64,
        document: Option<&CommittedDocument>,
    ) {
        let mut rename = HashMap::new();
        // Repeated AX records for one DOM node share a ref even if the global
        // cache evicts its name before this capture finishes.
        let mut captured_names = HashMap::new();
        for record in refs {
            let identity = key(record, epoch, document);
            let name = identity
                .as_ref()
                .and_then(|k| {
                    captured_names
                        .get(k)
                        .cloned()
                        .or_else(|| self.names.get(k).map(|cached| cached.reference.clone()))
                })
                .unwrap_or_else(|| {
                    self.next = self
                        .next
                        .checked_add(1)
                        .expect("browser reference counter exhausted");
                    let name = format!("e{}", self.next);
                    if let Some(identity) = identity.clone() {
                        // Prefer names the caller has actually seen over nodes
                        // captured from the page but omitted from snapshot text.
                        self.cache_name(identity, name.clone(), 0);
                    }
                    name
                });
            if let Some(identity) = identity {
                captured_names.insert(identity, name.clone());
            }
            rename.insert(record.captured.reference.clone(), name.clone());
            record.captured.reference = name;
        }
        for record in records {
            if let Some(reference) = &mut record.reference {
                if let Some(name) = rename.get(reference) {
                    *reference = name.clone();
                } else {
                    record.reference = None;
                }
            }
        }
        *facts = std::mem::take(facts)
            .into_iter()
            .filter_map(|(old, facts)| Some((rename.get(&old)?.clone(), facts)))
            .collect();
    }

    /// Only refs actually printed can be used later. Keep their provenance
    /// independently of the latest view, which may be filtered to another item.
    pub fn remember(
        &mut self,
        refs: &[RefRecord],
        snapshot_id: &str,
        epoch: u64,
        document: Option<&CommittedDocument>,
    ) {
        for record in refs {
            if let Some(identity) = key(record, epoch, document) {
                self.shown_sequence = self
                    .shown_sequence
                    .checked_add(1)
                    .expect("browser shown-ref counter exhausted");
                self.cache_name(
                    identity,
                    record.captured.reference.clone(),
                    self.shown_sequence,
                );
            }
            self.shown.insert(
                record.captured.reference.clone(),
                ShownRef {
                    record: record.clone(),
                    snapshot_id: snapshot_id.into(),
                    epoch,
                    document: document.cloned(),
                },
            );
        }
    }

    /// Retained snapshots are the provenance for usable refs. Eviction also
    /// releases their ledger entries, so a long-lived page cannot grow this
    /// ledger by repeatedly showing new nodes in successive snapshots.
    pub fn prune_shown(&mut self, snapshots: &BrowserSnapshotStore) {
        self.shown
            .retain(|_, shown| snapshots.get(&shown.snapshot_id).is_some());
    }

    pub fn shown(&self, reference: &str) -> Option<&ShownRef> {
        self.shown.get(reference)
    }

    pub fn resolves(
        &self,
        reference: &str,
        fresh: &RefRecord,
        epoch: u64,
        document: Option<&CommittedDocument>,
    ) -> bool {
        self.shown.get(reference).is_some_and(|old| {
            let identity = key(&old.record, old.epoch, old.document.as_ref());
            identity.is_some() && identity == key(fresh, epoch, document)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classification::ClassificationUnavailable;
    use crate::snapshot_store::{FrameDocument, SnapshotRef};

    fn record(backend: u64, loader: &str) -> RefRecord {
        RefRecord {
            captured: SnapshotRef::new("e1", "button", "Access", 0).unwrap(),
            frame_path: vec!["child".into()],
            backend_identity: Some(BackendNodeIdentity::new("target", "child", backend).unwrap()),
            frame_document: Some(FrameDocument {
                navigation_revision: 1,
                frame_id: "child".into(),
                parent_id: Some("main".into()),
                session_id: "session".into(),
                loader_id: loader.into(),
                url: "https://frame.example/".into(),
                origin: "https://frame.example".into(),
            }),
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        }
    }

    #[test]
    fn stable_refs_frame_loader_and_backend_identity_own_names() {
        let mut registry = StableRefs::default();
        let mut initial = vec![record(10, "first")];
        registry.assign(&mut [], &mut initial, &mut HashMap::new(), 0, None);
        registry.remember(&initial, "snapshot", 0, None);
        let old = initial[0].captured.reference.clone();
        let mut inserted = vec![record(11, "first"), record(10, "first")];
        inserted[1].captured.reference = "e2".into();
        registry.assign(&mut [], &mut inserted, &mut HashMap::new(), 0, None);
        assert_eq!(inserted[1].captured.reference, old);
        assert_ne!(inserted[0].captured.reference, old);
        let mut reloaded = vec![record(10, "second")];
        registry.assign(&mut [], &mut reloaded, &mut HashMap::new(), 0, None);
        assert_ne!(reloaded[0].captured.reference, old);
        assert!(!registry.resolves(&old, &reloaded[0], 0, None));
        assert!(registry.resolves(&old, &inserted[1], 0, None));
        let mut replaced_target = vec![record(10, "first")];
        replaced_target[0]
            .backend_identity
            .as_mut()
            .unwrap()
            .target_id = "another-target".into();
        registry.assign(&mut [], &mut replaced_target, &mut HashMap::new(), 0, None);
        assert_ne!(replaced_target[0].captured.reference, old);
    }

    #[test]
    fn stable_refs_shown_ledger_is_bounded_by_retained_snapshots() {
        use crate::snapshot_store::{
            new_snapshot_id, SnapshotKind, TextSnapshot, STATE_TEXT_SCHEMA,
        };
        let mut registry = StableRefs::default();
        let mut snapshots = BrowserSnapshotStore::new(2).unwrap();
        for backend in 1u64..=4 {
            let mut refs = vec![record(backend, "loader")];
            registry.assign(&mut [], &mut refs, &mut HashMap::new(), 0, None);
            let id = new_snapshot_id(backend.to_le_bytes());
            snapshots
                .retain_text(TextSnapshot {
                    snapshot_id: id.clone(),
                    kind: SnapshotKind::Actionable,
                    document_epoch: 0,
                    source_origin: "https://frame.example".into(),
                    source_document: None,
                    content_schema: STATE_TEXT_SCHEMA,
                    content: format!("{} button Access\n", refs[0].captured.reference),
                    truncated: false,
                    refs_truncated: false,
                    refs: refs.clone(),
                })
                .unwrap();
            registry.remember(&refs, &id, 0, None);
            registry.prune_shown(&snapshots);
            assert_eq!(
                registry.shown.len(),
                usize::try_from(backend.min(2)).unwrap()
            );
        }
        assert!(registry.shown("e1").is_none());
        assert!(registry.shown("e2").is_none());
        assert!(registry.shown("e3").is_some());
        assert!(registry.shown("e4").is_some());
        snapshots.invalidate_before(1);
        registry.prune_shown(&snapshots);
        assert!(registry.shown.is_empty());
    }

    #[test]
    fn stable_refs_name_cache_is_bounded_by_least_recently_shown_identity() {
        let mut registry = StableRefs::default();
        for backend in 1..=MAX_STABLE_IDENTITIES as u64 {
            let mut refs = vec![record(backend, "loader")];
            registry.assign(&mut [], &mut refs, &mut HashMap::new(), 0, None);
            registry.remember(&refs, "snapshot", 0, None);
        }
        assert_eq!(registry.names.len(), MAX_STABLE_IDENTITIES);
        assert_eq!(registry.name_recency.len(), MAX_STABLE_IDENTITIES);
        let mut first = vec![record(1, "loader")];
        registry.assign(&mut [], &mut first, &mut HashMap::new(), 0, None);
        registry.remember(&first, "snapshot", 0, None);
        assert_eq!(first[0].captured.reference, "e1");
        // Observing a node without printing it must not refresh its shown age.
        let mut second = vec![record(2, "loader")];
        registry.assign(&mut [], &mut second, &mut HashMap::new(), 0, None);
        let mut added = vec![
            record(MAX_STABLE_IDENTITIES as u64 + 1, "loader"),
            record(MAX_STABLE_IDENTITIES as u64 + 1, "loader"),
        ];
        added[1].captured.reference = "e2".into();
        registry.assign(&mut [], &mut added, &mut HashMap::new(), 0, None);
        assert_eq!(added[0].captured.reference, added[1].captured.reference);
        assert_eq!(registry.names.len(), MAX_STABLE_IDENTITIES);
        registry.remember(&added, "snapshot", 0, None);
        assert_eq!(registry.names.len(), MAX_STABLE_IDENTITIES);
        assert_eq!(registry.name_recency.len(), MAX_STABLE_IDENTITIES);
        assert!(registry
            .names
            .contains_key(&key(&first[0], 0, None).unwrap()));
        assert!(!registry
            .names
            .contains_key(&key(&second[0], 0, None).unwrap()));
        registry.assign(&mut [], &mut second, &mut HashMap::new(), 0, None);
        assert_eq!(
            second[0].captured.reference,
            format!("e{}", MAX_STABLE_IDENTITIES + 2)
        );
        assert_ne!(second[0].captured.reference, "e2");
        assert_ne!(second[0].captured.reference, added[0].captured.reference);
        registry.remember(&second, "snapshot", 0, None);
        assert_eq!(registry.names.len(), MAX_STABLE_IDENTITIES);
        assert_eq!(registry.name_recency.len(), MAX_STABLE_IDENTITIES);
    }

    #[test]
    fn stable_refs_numbers_can_outlive_the_per_capture_ref_budget() {
        let mut registry = StableRefs {
            next: crate::snapshot_store::MAX_REFS as u64,
            ..StableRefs::default()
        };
        let mut records = vec![record(10, "loader")];
        registry.assign(&mut [], &mut records, &mut HashMap::new(), 0, None);
        assert!(crate::snapshot_store::valid_ref(
            &records[0].captured.reference
        ));
        assert_eq!(
            records[0].captured.reference,
            format!("e{}", crate::snapshot_store::MAX_REFS + 1)
        );
    }
}
