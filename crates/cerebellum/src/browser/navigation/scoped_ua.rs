use super::*;

pub(super) type NativeUaRoots = HashMap<u64, Result<Vec<Value>, ClassificationUnavailable>>;

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn snapshot_ua_roots<C: NavigationClock>(
        &mut self,
        descriptions: &[Result<Value, ClassificationUnavailable>],
        session: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<NativeUaRoots, ClassificationUnavailable> {
        let roots = descriptions
            .iter()
            .filter_map(|v| v.as_ref().ok())
            .flat_map(|host| {
                host["shadowRoots"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|root| root["shadowRootType"] == "user-agent")
                    .map(move |root| (host["backendNodeId"].as_u64().unwrap_or(0), root.clone()))
            })
            .collect::<Vec<_>>();
        let replies = self.scoped_reads("DOM.describeNode", roots.iter().map(|(_,root)| serde_json::json!({"backendNodeId":root["backendNodeId"],"depth":-1,"pierce":true})).collect(), session, deadline, clock).map_err(|_| ClassificationUnavailable::DomReadFailed)?;
        let mut out = HashMap::<u64, Result<Vec<Value>, ClassificationUnavailable>>::new();
        for ((host, expected), reply) in roots.into_iter().zip(replies) {
            let values = (|| {
                let reply = reply?;
                let root = reply
                    .get("node")
                    .ok_or(ClassificationUnavailable::DomReadFailed)?;
                if host == 0
                    || root["backendNodeId"] != expected["backendNodeId"]
                    || root["shadowRootType"] != "user-agent"
                    || root["childNodeCount"] != expected["childNodeCount"]
                    || !super::scoped_dom::same_native_facts(root, &expected)
                {
                    return Err(ClassificationUnavailable::DomReadFailed);
                }
                let mut values = Vec::new();
                flatten_native_subtree(root, host, &mut values, &mut HashSet::new())?;
                Ok(values)
            })();
            if let Ok(existing) = out.entry(host).or_insert_with(|| Ok(Vec::new())) {
                match values {
                    Ok(values) => existing.extend(values),
                    Err(reason) => {
                        out.insert(host, Err(reason));
                    }
                }
            }
        }
        Ok(out)
    }
}

fn flatten_native_subtree(
    node: &Value,
    parent: u64,
    values: &mut Vec<Value>,
    seen: &mut HashSet<u64>,
) -> Result<(), ClassificationUnavailable> {
    let backend = node["backendNodeId"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or(ClassificationUnavailable::DomReadFailed)?;
    if !seen.insert(backend)
        || seen.len() > 16384
        || node.get("templateContent").is_some()
        || node.get("contentDocument").is_some()
    {
        return Err(ClassificationUnavailable::DomReadFailed);
    }
    let children = node.get("children").and_then(Value::as_array);
    let count = children.map_or(0, Vec::len) as u64;
    if node
        .get("childNodeCount")
        .and_then(Value::as_u64)
        .is_some_and(|expected| expected != count)
    {
        return Err(ClassificationUnavailable::DomReadFailed);
    }
    for key in ["shadowRoots", "children", "pseudoElements"] {
        for child in node
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            flatten_native_subtree(child, backend, values, seen)?;
        }
    }
    let mut node = node.clone();
    node["parentId"] = Value::from(parent);
    values.push(node);
    Ok(())
}

/// JavaScript cannot inspect input editors' browser-owned roots. Supply their
/// complete native graphs, rather than ignoring the roots or rejecting every
/// ordinary input. Closed page-authored shadow roots and pseudo-elements still
/// refuse complete contexts when their identities are absent from the graph.
pub(super) fn supplement_ua_context(
    metadata: &mut Value,
    values: &mut Vec<Value>,
    roots: &NativeUaRoots,
) -> Result<(), ClassificationUnavailable> {
    if metadata["complete"] != true {
        return Ok(());
    }
    let hosts = values
        .iter()
        .filter_map(|v| v["backendNodeId"].as_u64())
        .collect::<Vec<_>>();
    let mut by_backend = values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| Some((v["backendNodeId"].as_u64()?, i)))
        .collect::<HashMap<_, _>>();
    let mut next_key = metadata["keys"]
        .as_array()
        .ok_or(ClassificationUnavailable::DomReadFailed)?
        .iter()
        .filter_map(Value::as_u64)
        .max()
        .unwrap_or(0)
        + 1;
    let mut added = Vec::new();
    for host in hosts {
        let Some(root) = roots.get(&host) else {
            continue;
        };
        for value in root.as_ref().map_err(Clone::clone)? {
            let backend = value["backendNodeId"]
                .as_u64()
                .ok_or(ClassificationUnavailable::DomReadFailed)?;
            if by_backend.contains_key(&backend) {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
            by_backend.insert(backend, values.len());
            added.push(value.clone());
            values.push(value.clone());
            metadata["keys"]
                .as_array_mut()
                .ok_or(ClassificationUnavailable::DomReadFailed)?
                .push(Value::from(next_key));
            next_key += 1;
            metadata["slots"]
                .as_array_mut()
                .ok_or(ClassificationUnavailable::DomReadFailed)?
                .push(Value::Null);
            metadata["childCounts"]
                .as_array_mut()
                .ok_or(ClassificationUnavailable::DomReadFailed)?
                .push(
                    value
                        .get("childNodeCount")
                        .cloned()
                        .unwrap_or(Value::from(0)),
                );
        }
    }
    for node in added {
        let parent = node["parentId"]
            .as_u64()
            .and_then(|id| by_backend.get(&id))
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        metadata["parents"]
            .as_array_mut()
            .ok_or(ClassificationUnavailable::DomReadFailed)?
            .push(Value::from(*parent));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn editor() -> Value {
        json!({"nodeId":0,"backendNodeId":4,"nodeType":11,"nodeName":"#document-fragment","localName":"","nodeValue":"","shadowRootType":"user-agent","childNodeCount":1,
            "children":[{"nodeId":0,"backendNodeId":5,"nodeType":1,"nodeName":"DIV","localName":"div","nodeValue":"","attributes":[],"childNodeCount":0}]})
    }

    #[test]
    fn native_editor_requires_every_child_and_unique_backend_identity() {
        let mut values = Vec::new();
        flatten_native_subtree(&editor(), 3, &mut values, &mut HashSet::new()).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["parentId"], 4);
        assert_eq!(values[1]["parentId"], 3);
        let mut missing = editor();
        missing["children"] = json!([]);
        assert_eq!(
            flatten_native_subtree(&missing, 3, &mut Vec::new(), &mut HashSet::new()),
            Err(ClassificationUnavailable::DomReadFailed)
        );
        let mut duplicate = editor();
        duplicate["children"][0]["backendNodeId"] = json!(4);
        assert_eq!(
            flatten_native_subtree(&duplicate, 3, &mut Vec::new(), &mut HashSet::new()),
            Err(ClassificationUnavailable::DomReadFailed)
        );
    }

    #[test]
    fn complete_native_editor_retains_password_facts_and_closed_roots_still_refuse() {
        let nodes = vec![
            json!({"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","nodeValue":"","childNodeCount":1}),
            json!({"nodeId":2,"backendNodeId":2,"nodeType":1,"nodeName":"FORM","localName":"form","nodeValue":"","attributes":["id","login"],"childNodeCount":1}),
            json!({"nodeId":3,"backendNodeId":3,"nodeType":1,"nodeName":"INPUT","localName":"input","nodeValue":"","attributes":["type","password"],"childNodeCount":0,"shadowRoots":[editor()]}),
        ];
        let metadata = json!({"complete":true,"bound":288,"parents":[null,0,1],"keys":[1,2,3],"slots":[null,null,null],"childCounts":[1,1,0]});
        assert!(
            super::super::scoped_dom::materialize_context(&metadata, nodes.clone(), false).is_err(),
            "an unobserved root cannot simply be ignored"
        );
        let mut extra = Vec::new();
        flatten_native_subtree(&editor(), 3, &mut extra, &mut HashSet::new()).unwrap();
        let roots = HashMap::from([(3, Ok(extra))]);
        let mut values = nodes.clone();
        let mut complete = metadata.clone();
        supplement_ua_context(&mut complete, &mut values, &roots).unwrap();
        let dom = super::super::scoped_dom::materialize_context(&complete, values, false).unwrap();
        let parsed = parse_flattened_dom_nodes(&dom).unwrap();
        let identity = BackendNodeIdentity::new("target", "frame", 3).unwrap();
        let record =
            build_non_type_classification(&parsed, &identity, 7, "https://example.com").unwrap();
        assert!(record.target_password && record.credential);
        assert_eq!(record.associated_form_controls.len(), 1);
        let mut closed = nodes;
        closed[2]["shadowRoots"][0]["shadowRootType"] = json!("closed");
        assert!(super::super::scoped_dom::materialize_context(&metadata, closed, false).is_err());
        let failed_roots = HashMap::from([(3, Err(ClassificationUnavailable::DomReadFailed))]);
        let mut local = json!({"complete":false});
        assert!(
            supplement_ua_context(&mut local, &mut Vec::new(), &failed_roots).is_ok(),
            "a failed editor read must not poison an unrelated partial context"
        );
    }
}
