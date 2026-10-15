use super::*;
#[cfg(test)]
use std::cell::Cell;
use std::ops::Index;

#[cfg(test)]
thread_local! { static NODE_READS: Cell<usize> = const { Cell::new(0) }; }
#[derive(Default)]
struct Work;
impl Work {
    #[inline(always)]
    fn step(&self) {
        #[cfg(test)]
        NODE_READS.with(|reads| reads.set(reads.get() + 1));
    }
}

/// Count actual node reads in tests so scaling guards observe scans, not timing.
pub(super) struct CountedNodes<'a> {
    nodes: &'a [RawDomNode],
    work: &'a Work,
}
impl<'a> CountedNodes<'a> {
    fn new(nodes: &'a [RawDomNode], work: &'a Work) -> Self {
        Self { nodes, work }
    }
    pub(super) fn get(&self, index: usize) -> Option<&RawDomNode> {
        self.work.step();
        self.nodes.get(index)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &'a RawDomNode> + '_ {
        self.nodes.iter().inspect(|_| self.work.step())
    }
}
impl Index<usize> for CountedNodes<'_> {
    type Output = RawDomNode;
    fn index(&self, index: usize) -> &Self::Output {
        self.work.step();
        &self.nodes[index]
    }
}

pub(super) struct DomIndexes {
    pub(super) form_owners: Vec<Option<usize>>,
    pub(super) label_controls: HashMap<usize, usize>,
    pub(super) controls_by_form: HashMap<usize, Vec<usize>>,
    pub(super) base_href: Option<String>,
}
struct PreparedDocument {
    nodes: Vec<RawDomNode>,
    by_node: HashMap<u64, usize>,
    by_backend: HashMap<u64, usize>,
    indexes: DomIndexes,
}

/// A flattened DOM can contain several frame documents. Prepare each scope once
/// and never let a form id, label target or base element cross that boundary.
pub(super) struct DomClassificationBatch {
    roots_by_backend: HashMap<u64, u64>,
    documents: HashMap<u64, Result<PreparedDocument, ClassificationUnavailable>>,
    work: Work,
}
impl DomClassificationBatch {
    pub(super) fn new(nodes: &[RawDomNode]) -> Self {
        let work = Work;
        let counted = CountedNodes::new(nodes, &work);
        let by_id = counted
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id, index))
            .collect::<HashMap<_, _>>();
        let parents = counted
            .iter()
            .map(|node| node.parent_id.and_then(|id| by_id.get(&id).copied()))
            .collect::<Vec<_>>();
        let mut roots = vec![None; nodes.len()];
        let mut marks = vec![0; nodes.len()];
        for start in 0..nodes.len() {
            let mut path = Vec::new();
            let mut current = start;
            let root = loop {
                work.step();
                if let Some(root) = roots[current] {
                    break root;
                }
                if counted[current].local_name == "#document" {
                    let root = counted[current].node_id;
                    roots[current] = Some(root);
                    break root;
                }
                if marks[current] == start + 1 {
                    break 0;
                }
                marks[current] = start + 1;
                path.push(current);
                match parents[current] {
                    Some(parent) => current = parent,
                    None => break counted[current].node_id,
                }
            };
            for index in path {
                roots[index] = Some(root);
            }
        }
        let mut roots_by_backend = HashMap::new();
        let mut scopes: HashMap<u64, Vec<RawDomNode>> = HashMap::new();
        for (index, node) in counted.iter().enumerate() {
            let root = roots[index].expect("every document root was resolved");
            roots_by_backend.entry(node.backend_node_id).or_insert(root);
            scopes.entry(root).or_default().push(node.clone());
        }
        let documents = scopes
            .into_iter()
            .map(|(root, nodes)| (root, PreparedDocument::new(nodes, &work)))
            .collect();
        Self {
            roots_by_backend,
            documents,
            work,
        }
    }

    pub(super) fn classify(
        &self,
        identity: &BackendNodeIdentity,
        epoch: u64,
        origin: &str,
    ) -> Result<NonTypeClassificationRecord, ClassificationUnavailable> {
        self.work.step();
        let missing = || ClassificationUnavailable::TargetNotInDocument {
            backend_node_id: identity.backend_node_id,
        };
        let root = self
            .roots_by_backend
            .get(&identity.backend_node_id)
            .ok_or_else(missing)?;
        let document = self
            .documents
            .get(root)
            .expect("each root has a prepared scope")
            .as_ref()
            .map_err(Clone::clone)?;
        let target = *document
            .by_backend
            .get(&identity.backend_node_id)
            .ok_or_else(missing)?;
        let context = DomClassificationContext {
            nodes: CountedNodes::new(&document.nodes, &self.work),
            indexes: &document.indexes,
            by_node_id: &document.by_node,
            by_backend_id: &document.by_backend,
            target_id: &identity.target_id,
            frame_id: &identity.frame_id,
            current_origin: origin,
        };
        classify_indexed(&context, target, epoch, identity)
    }
}

pub(super) fn classify_refs(
    refs: &mut [RefRecord],
    nodes: &[RawDomNode],
    epoch: u64,
    origin: &str,
) {
    let batch = DomClassificationBatch::new(nodes);
    for reference in refs {
        if let Some(identity) = &reference.backend_identity {
            reference.classification = batch.classify(identity, epoch, origin).map(Box::new);
        }
    }
}

#[cfg(test)]
pub(super) fn test_refs(nodes: &[RawDomNode], target: &str, frame: &str) -> Vec<RefRecord> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| RefRecord {
            captured: SnapshotRef::new(format!("e{}", index + 1), "generic", "", 0).unwrap(),
            frame_document: None,
            frame_path: vec![frame.into()],
            backend_identity: Some(
                BackendNodeIdentity::new(target, frame, node.backend_node_id).unwrap(),
            ),
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        })
        .collect()
}

impl PreparedDocument {
    fn new(nodes: Vec<RawDomNode>, work: &Work) -> Result<Self, ClassificationUnavailable> {
        let counted = CountedNodes::new(&nodes, work);
        let mut by_node = HashMap::new();
        let mut by_backend = HashMap::new();
        let mut forms = HashMap::new();
        let mut labelable = HashMap::new();
        let mut base_href = None;
        for (index, node) in counted.iter().enumerate() {
            if by_node.insert(node.node_id, index).is_some() {
                return Err(ClassificationUnavailable::DuplicateNodeId {
                    node_id: node.node_id,
                });
            }
            if by_backend.insert(node.backend_node_id, index).is_some() {
                return Err(ClassificationUnavailable::DuplicateBackendNodeId {
                    backend_node_id: node.backend_node_id,
                });
            }
            if let Some(id) = node.attributes.get("id") {
                if node.local_name == "form" {
                    forms.entry(id.clone()).or_insert(index);
                }
                if is_labelable(&node.local_name) {
                    labelable.entry(id.clone()).or_insert(index);
                }
            }
            if base_href.is_none() && node.local_name == "base" {
                base_href = node.attributes.get("href").cloned();
            }
        }
        let parents = counted
            .iter()
            .map(|node| node.parent_id.and_then(|id| by_node.get(&id).copied()))
            .collect::<Vec<_>>();
        // Cache the nearest DOM form independently of explicit form attributes:
        // assigning a control to a form does not make it a form ancestor.
        let mut nearest = vec![None; nodes.len()];
        let mut marks = vec![0; nodes.len()];
        for start in 0..nodes.len() {
            let mut current = Some(start);
            let mut path = Vec::new();
            let owner = loop {
                work.step();
                let Some(index) = current else {
                    break None;
                };
                if let Some(owner) = nearest[index] {
                    break owner;
                }
                if counted[index].local_name == "form" {
                    nearest[index] = Some(Some(index));
                    break Some(index);
                }
                if marks[index] == start + 1 {
                    break None;
                }
                marks[index] = start + 1;
                path.push(index);
                current = parents[index];
            };
            for index in path {
                nearest[index] = Some(owner);
            }
        }
        let form_owners = counted
            .iter()
            .enumerate()
            .map(|(index, node)| {
                if let Some(form) = node.attributes.get("form") {
                    forms.get(form).copied()
                } else {
                    parents[index].and_then(|parent| nearest[parent].flatten())
                }
            })
            .collect::<Vec<_>>();
        let mut label_controls = HashMap::new();
        let mut controls_by_form: HashMap<usize, Vec<usize>> = HashMap::new();
        for (index, node) in counted.iter().enumerate() {
            if node.local_name == "label" {
                if let Some(id) = node.attributes.get("for") {
                    if let Some(&control) = labelable.get(id) {
                        label_controls.insert(index, control);
                    }
                }
            }
            if is_form_control(&node.local_name) {
                if let Some(owner) = form_owners[index] {
                    controls_by_form.entry(owner).or_default().push(index);
                }
            }
            if !is_labelable(&node.local_name) {
                continue;
            }
            let mut parent = parents[index];
            let mut visited = HashSet::new();
            while let Some(ancestor) = parent {
                work.step();
                if !visited.insert(ancestor) {
                    break;
                }
                let ancestor_node = &counted[ancestor];
                if ancestor_node.local_name == "label"
                    && !ancestor_node.attributes.contains_key("for")
                {
                    label_controls.entry(ancestor).or_insert(index);
                }
                parent = parents[ancestor];
            }
        }
        Ok(Self {
            nodes,
            by_node,
            by_backend,
            indexes: DomIndexes {
                form_owners,
                label_controls,
                controls_by_form,
                base_href,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settings_nodes(links: usize) -> Vec<RawDomNode> {
        let mut raw = vec![
            json!({"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"}),
            json!({"nodeId":2,"backendNodeId":2,"parentId":1,"nodeType":1,"localName":"nav","attributes":[]}),
        ];
        for n in 0..links {
            let id = n as u64 * 2 + 3;
            raw.push(json!({"nodeId":id,"backendNodeId":id,"parentId":2,"nodeType":1,"localName":"a","attributes":["href",format!("#setting-{n}")]}));
            raw.push(json!({"nodeId":id+1,"backendNodeId":id+1,"parentId":id,"nodeType":3,"localName":"#text"}));
        }
        parse_flattened_dom_nodes(json!({"nodes":raw}).as_object().unwrap()).unwrap()
    }

    #[test]
    fn settings_classification_node_work_scales_linearly() {
        let classify = |links| {
            let nodes = settings_nodes(links);
            let mut refs = test_refs(&nodes, "target", "frame");
            NODE_READS.with(|reads| reads.set(0));
            classify_refs(&mut refs, &nodes, 1, "https://example.com");
            let work = NODE_READS.with(Cell::get);
            for (node, reference) in nodes.iter().zip(refs) {
                let result = reference.classification;
                if node.local_name == "#document" {
                    assert!(result.is_err());
                } else {
                    let record = result.unwrap();
                    assert_eq!(
                        record.node_identity,
                        NodeIdentityInput::new("target", "frame", node.backend_node_id)
                            .identity()
                            .unwrap()
                    );
                    if node.local_name == "a" || node.local_name == "#text" {
                        assert_eq!(
                            record.activation_target_identity,
                            NodeIdentityInput::new(
                                "target",
                                "frame",
                                if node.local_name == "a" {
                                    node.backend_node_id
                                } else {
                                    node.backend_node_id - 1
                                }
                            )
                            .identity()
                            .unwrap()
                        );
                    }
                }
            }
            work
        };
        let small = classify(200);
        let large = classify(400);
        assert!(small > 0);
        assert!(
            large * 10 < small * 23,
            "node reads grew from {small} to {large} for twice as many links"
        );
        println!("classification node reads: 200 links={small}, 400 links={large}");
    }
}
