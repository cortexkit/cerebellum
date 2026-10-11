use std::collections::HashMap;

use crate::snapshot_store::{AxRecord, BackendNodeIdentity, CommittedDocument, RefRecord};

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
    names: HashMap<ElementKey, String>,
    shown: HashMap<String, ShownRef>,
}

#[derive(Debug)]
pub(super) struct ShownRef {
    pub record: RefRecord,
    pub snapshot_id: String,
    epoch: u64,
    document: Option<CommittedDocument>,
}

impl StableRefs {
    pub fn next_document(&self) -> Self {
        Self {
            next: self.next,
            ..Self::default()
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
        for record in refs {
            let identity = key(record, epoch, document);
            let name = identity
                .as_ref()
                .and_then(|k| self.names.get(k))
                .cloned()
                .unwrap_or_else(|| {
                    self.next = self
                        .next
                        .checked_add(1)
                        .expect("browser reference counter exhausted");
                    let name = format!("e{}", self.next);
                    if let Some(identity) = identity {
                        self.names.insert(identity, name.clone());
                    }
                    name
                });
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
