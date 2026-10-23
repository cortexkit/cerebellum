use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

/// Resolve non-element refs through the captured DOM, without asking Chrome to
/// run an element-only selector on a text node. Skip wrappers that add no text
/// so a field key includes its sibling value rather than just the key's span.
pub(crate) fn enclosing_element(
    dom: &Map<String, Value>,
    backend: u64,
) -> Result<(u64, Option<&'static str>), ()> {
    let nodes = dom.get("nodes").and_then(Value::as_array).ok_or(())?;
    let by_id: HashMap<_, _> = nodes
        .iter()
        .filter_map(|node| Some((node["nodeId"].as_u64()?, node)))
        .collect();
    let node = nodes
        .iter()
        .find(|node| node["backendNodeId"].as_u64() == Some(backend))
        .ok_or(())?;
    let kind = node["nodeType"].as_u64().ok_or(())?;
    if kind == 1 {
        return Ok((backend, None));
    }
    let mut text_sizes = HashMap::<u64, usize>::new();
    for text in nodes.iter().filter(|node| node["nodeType"] == 3) {
        let size = text["nodeValue"]
            .as_str()
            .unwrap_or_default()
            .chars()
            .count();
        let mut current = Some(text);
        let mut seen = HashSet::new();
        while let Some(node) = current {
            let id = node["nodeId"].as_u64().ok_or(())?;
            if !seen.insert(id) {
                return Err(());
            }
            *text_sizes.entry(id).or_default() += size;
            current = node["parentId"]
                .as_u64()
                .and_then(|id| by_id.get(&id).copied());
        }
    }
    let own_size = text_sizes
        .get(&node["nodeId"].as_u64().ok_or(())?)
        .copied()
        .unwrap_or_default();
    let mut current = node;
    let mut nearest = None;
    let mut seen = HashSet::new();
    while let Some(parent) = current["parentId"].as_u64().and_then(|id| by_id.get(&id)) {
        let id = parent["nodeId"].as_u64().ok_or(())?;
        if !seen.insert(id) {
            return Err(());
        }
        if parent["nodeType"] == 1 {
            let backend = parent["backendNodeId"].as_u64().ok_or(())?;
            nearest.get_or_insert(backend);
            if text_sizes.get(&id).copied().unwrap_or_default() > own_size {
                nearest = Some(backend);
                break;
            }
        }
        current = parent;
    }
    // A document has no enclosing element, but its own markup is still readable.
    let target = nearest.or((kind == 9).then_some(backend)).ok_or(())?;
    Ok((target, Some(if kind == 3 { "text" } else { "non-element" })))
}

pub(crate) fn enclosing_notice(reference: &str, kind: &str) -> String {
    format!("{reference} is a {kind} node; showing its enclosing element\n")
}

#[cfg(test)]
pub(crate) fn key_value_fixture() -> Map<String, Value> {
    serde_json::json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document"},
        {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"nodeName":"BODY","attributes":[]},
        {"nodeId":3,"parentId":2,"backendNodeId":3,"nodeType":1,"nodeName":"DIV","attributes":[]},
        {"nodeId":4,"parentId":3,"backendNodeId":4,"nodeType":1,"nodeName":"SPAN","attributes":[]},
        {"nodeId":5,"parentId":4,"backendNodeId":5,"nodeType":3,"nodeName":"#text","nodeValue":"event"},
        {"nodeId":6,"parentId":3,"backendNodeId":6,"nodeType":1,"nodeName":"SPAN","attributes":["role","button","tabindex","0","onclick","this.dataset.clicked='yes'"]},
        {"nodeId":7,"parentId":6,"backendNodeId":7,"nodeType":3,"nodeName":"#text","nodeValue":"request"},
        {"nodeId":8,"parentId":4,"backendNodeId":8,"nodeType":8,"nodeName":"#comment","nodeValue":"metadata"}
    ]}).as_object().unwrap().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_element_zoom_skips_wrappers_with_no_additional_text() {
        let dom = key_value_fixture();
        assert_eq!(enclosing_element(&dom, 5), Ok((3, Some("text"))));
        assert_eq!(enclosing_element(&dom, 8), Ok((4, Some("non-element"))));
        assert_eq!(enclosing_element(&dom, 6), Ok((6, None)));
        assert!(enclosing_element(&dom, 99).is_err());
    }
}
