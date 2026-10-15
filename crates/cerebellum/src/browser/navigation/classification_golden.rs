use super::*;

#[test]
fn settings_classification_matches_preindexed_fixture_bytes() {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/loopback_flattened_document.json")).unwrap();
    let mut document = fixture["result"].clone();
    let nodes = document["nodes"].as_array_mut().unwrap();
    let body = nodes
        .iter()
        .find(|node| node["localName"] == "body")
        .unwrap()["nodeId"]
        .as_u64()
        .unwrap();
    nodes.push(serde_json::json!({"nodeId":999999,"backendNodeId":1999999,"parentId":body,"nodeType":1,"localName":"nav","attributes":[]}));
    for n in 0..600 {
        let id = 1000000 + n * 2;
        let backend = 2000000 + n * 2;
        nodes.push(serde_json::json!({"nodeId":id,"backendNodeId":backend,"parentId":999999,"nodeType":1,"localName":"a","attributes":["href",format!("#setting-{n}")]}));
        nodes.push(serde_json::json!({"nodeId":id+1,"backendNodeId":backend+1,"parentId":id,"nodeType":3,"localName":"#text"}));
    }
    let nodes = parse_flattened_dom_nodes(document.as_object().unwrap()).unwrap();
    let mut refs = classification_index::test_refs(&nodes, "fixture-target", "fixture-frame");
    classify_refs(&mut refs, &nodes, 7, "http://127.0.0.1:54881");
    let classified = nodes
        .iter()
        .zip(refs)
        .map(|(node, reference)| {
            let result = match reference.classification {
                Ok(record) => serde_json::to_value(record).unwrap(),
                Err(reason) => serde_json::json!({"error":format!("{reason:?}")}),
            };
            (node.backend_node_id, result)
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&classified).unwrap();
    let digest = crate::manifest::sha256_hex(&bytes);
    // Freeze complete pre-indexing results for a recorded DOM plus settings
    // navigation: identities, form hazards and unavailable reasons must all
    // remain byte-identical, not merely produce the same rendered labels.
    assert_eq!(classified.len(), 1226);
    assert_eq!(bytes.len(), 765897);
    assert_eq!(
        digest,
        "32c59bb56922bf0023570ab9803d6597fb6792e618e4ee70609a4c86f248ce99"
    );
    println!(
        "{} classification results, {} bytes, sha256={digest}",
        classified.len(),
        bytes.len()
    );
}
