use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

/// Resolve non-element refs through the captured DOM, without asking Chrome to
/// run an element-only selector on a text node. Skip wrappers that add no text
/// so a field key includes its sibling value rather than just the key's span.
///
/// Text is measured in letters and digits only. A JSON viewer renders a key as
/// its own span holding `'event':`, so the span adds quotes and a colon to the
/// key's text but no content; counting every character would stop the climb
/// at that span and show the key without its value.
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
            .filter(|character| character.is_alphanumeric())
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

    /// A JSON viewer's expanded event: each property is a line wrapper
    /// holding the key as its own click-to-filter span (`'event':`, three
    /// text nodes, so the accessibility text is just `event`) and the value
    /// in a sibling span.
    fn json_viewer_chip_fixture() -> Map<String, Value> {
        let chip = "inline-block py-0.5 rounded hover:bg-blue-500/30 hover:cursor-pointer transition-colors duration-400 text-nowrap";
        serde_json::json!({"nodes":[
            {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document"},
            {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"nodeName":"BODY","attributes":[]},
            {"nodeId":3,"parentId":2,"backendNodeId":3,"nodeType":1,"nodeName":"DIV","attributes":[]},
            {"nodeId":4,"parentId":3,"backendNodeId":4,"nodeType":1,"nodeName":"DIV","attributes":[]},
            {"nodeId":5,"parentId":4,"backendNodeId":5,"nodeType":1,"nodeName":"SPAN","attributes":["class",chip]},
            {"nodeId":6,"parentId":5,"backendNodeId":6,"nodeType":3,"nodeName":"#text","nodeValue":"'"},
            {"nodeId":7,"parentId":5,"backendNodeId":7,"nodeType":3,"nodeName":"#text","nodeValue":"event"},
            {"nodeId":8,"parentId":5,"backendNodeId":8,"nodeType":3,"nodeName":"#text","nodeValue":"':"},
            {"nodeId":9,"parentId":4,"backendNodeId":9,"nodeType":1,"nodeName":"SPAN","attributes":[]},
            {"nodeId":10,"parentId":9,"backendNodeId":10,"nodeType":3,"nodeName":"#text","nodeValue":"'boat_pool_retire'"},
            {"nodeId":11,"parentId":3,"backendNodeId":11,"nodeType":1,"nodeName":"DIV","attributes":[]},
            {"nodeId":12,"parentId":11,"backendNodeId":12,"nodeType":1,"nodeName":"SPAN","attributes":["class",chip]},
            {"nodeId":13,"parentId":12,"backendNodeId":13,"nodeType":3,"nodeName":"#text","nodeValue":"'eventType':"},
            {"nodeId":14,"parentId":11,"backendNodeId":14,"nodeType":1,"nodeName":"SPAN","attributes":[]},
            {"nodeId":15,"parentId":14,"backendNodeId":15,"nodeType":3,"nodeName":"#text","nodeValue":"'cron'"}
        ]}).as_object().unwrap().clone()
    }

    #[test]
    fn a_text_zoom_on_a_json_viewer_key_climbs_past_its_punctuated_chip_to_the_line() {
        let dom = json_viewer_chip_fixture();
        // The key's chip holds `'event':`, which adds only punctuation to
        // `event`, so the zoom shows the property line with its value.
        assert_eq!(enclosing_element(&dom, 7), Ok((4, Some("text"))));
        // A quote holds no content of its own, so its chip already adds some.
        assert_eq!(enclosing_element(&dom, 6), Ok((5, Some("text"))));
        // A key whose text node carries its own quotes climbs the same way.
        assert_eq!(enclosing_element(&dom, 13), Ok((11, Some("text"))));
    }

    #[test]
    fn non_element_zoom_skips_wrappers_with_no_additional_text() {
        let dom = key_value_fixture();
        assert_eq!(enclosing_element(&dom, 5), Ok((3, Some("text"))));
        assert_eq!(enclosing_element(&dom, 8), Ok((4, Some("non-element"))));
        assert_eq!(enclosing_element(&dom, 6), Ok((6, None)));
        assert!(enclosing_element(&dom, 99).is_err());
    }
}
