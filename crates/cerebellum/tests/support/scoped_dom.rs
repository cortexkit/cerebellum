//! Scripted protocol peer for scoped snapshot contexts. This emulates remote
//! node handles and DOM.describeNode; it does not execute the runtime helper.
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Default)]
pub struct ScopedDom {
    pub target: u64,
    nodes: Vec<Value>,
    complete: bool,
    pub mutate_form_on_describe: Option<u64>,
    pub collected: HashMap<u64, Value>,
    metadata: Option<Value>,
    pub close_shadow_on_target: Option<u64>,
    pub closed_host: Option<u64>,
}

impl ScopedDom {
    pub fn described_backend(&self, index: usize) -> u64 {
        self.nodes[index]["backendNodeId"].as_u64().unwrap()
    }
    fn answer_batch(&mut self, params: &Value, dom: &Value) -> Option<Value> {
        let mut nodes = Vec::<Value>::new();
        let mut facts = Vec::<Value>::new();
        let mut child_counts = Vec::<Value>::new();
        let mut contexts = Vec::<Value>::new();
        let mut assignments = Vec::new();
        let mut complete: Option<usize> = None;
        for argument in params["arguments"].as_array()?.iter().skip(1) {
            let backend: u64 = argument["objectId"]
                .as_str()?
                .strip_prefix("scoped-target-")?
                .parse()
                .ok()?;
            if let Some(index) = complete {
                let members = contexts[index]["members"].as_array()?;
                if members
                    .iter()
                    .any(|m| nodes[m.as_u64().unwrap() as usize]["backendNodeId"] == backend)
                {
                    assignments.push(json!(index));
                    continue;
                }
            }
            let answer = self.answer(&json!({"method":"Runtime.callFunctionOn","params":{"objectId":argument["objectId"],"arguments":[{"value":256},{"value":false}]}}), dom)?;
            if answer.get("exceptionDetails").is_some() {
                assignments.push(Value::Null);
                continue;
            }
            let properties = self.answer(
                &json!({"method":"Runtime.getProperties","params":{"objectId":"scoped-context"}}),
                dom,
            )?;
            let meta: Value =
                serde_json::from_str(properties["result"][0]["value"]["value"].as_str()?).ok()?;
            let mut members = Vec::new();
            let mut invalid = false;
            for (i, node) in self.nodes.iter().enumerate() {
                let index = match nodes
                    .iter()
                    .position(|n| n["backendNodeId"] == node["backendNodeId"])
                {
                    Some(index) => index,
                    None => {
                        nodes.push(node.clone());
                        facts.push(meta["facts"][i].clone());
                        child_counts.push(Value::Null);
                        nodes.len() - 1
                    }
                };
                invalid |= facts[index] != meta["facts"][i];
                if meta["complete"] == true {
                    child_counts[index] = meta["childCounts"][i].clone();
                }
                members.push(index);
            }
            if meta["complete"] == true {
                complete = Some(contexts.len());
            }
            assignments.push(json!(contexts.len()));
            contexts.push(json!({"members":members,"complete":meta["complete"],"bound":meta.get("bound").cloned().unwrap_or(json!(256)),"invalid":invalid}));
        }
        let parents = nodes
            .iter()
            .map(|node| {
                nodes
                    .iter()
                    .position(|n| n["nodeId"] == node["parentId"] && !node["parentId"].is_null())
            })
            .collect::<Vec<_>>();
        let slots = nodes
            .iter()
            .map(|node| {
                nodes.iter().position(|n| {
                    n["backendNodeId"] == node["assignedSlot"]["backendNodeId"]
                        && !node["assignedSlot"].is_null()
                })
            })
            .collect::<Vec<_>>();
        self.metadata = Some(
            json!({"contexts":contexts,"assignments":assignments,"parents":parents,"slots":slots,"facts":facts,"childCounts":child_counts}),
        );
        self.nodes = nodes;
        Some(json!({"result":{"objectId":"scoped-context"}}))
    }

    pub fn handles(request: &Value) -> bool {
        let params = &request["params"];
        match request["method"].as_str().unwrap_or("") {
            "Page.createIsolatedWorld" => params["worldName"] == "ck-snapshot-classification",
            "DOM.resolveNode" | "Runtime.releaseObjectGroup" => {
                params["objectGroup"] == "ck-snapshot-classification"
            }
            "Runtime.callFunctionOn" => {
                params["objectId"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("scoped-target-"))
                    || params["functionDeclaration"]
                        .as_str()
                        .is_some_and(|f| f.contains("const collect ="))
            }
            "Runtime.getProperties" => params["objectId"] == "scoped-context",
            "DOM.describeNode" => params["objectId"]
                .as_str()
                .is_some_and(|id| id.starts_with("scoped-node-")),
            _ => false,
        }
    }

    pub fn answer(&mut self, request: &Value, dom: &Value) -> Option<Value> {
        if !Self::handles(request) {
            return None;
        }
        let params = &request["params"];
        match request["method"].as_str()? {
            "Page.createIsolatedWorld" if params["worldName"] == "ck-snapshot-classification" => {
                Some(json!({"executionContextId":7}))
            }
            "DOM.resolveNode" if params["objectGroup"] == "ck-snapshot-classification" => {
                self.target = params["backendNodeId"].as_u64().unwrap();
                Some(json!({"object":{"objectId":format!("scoped-target-{}", self.target)}}))
            }
            "Runtime.callFunctionOn"
                if params["functionDeclaration"]
                    .as_str()
                    .is_some_and(|f| f.contains("const collect =")) =>
            {
                self.answer_batch(params, dom)
            }
            "Runtime.callFunctionOn"
                if params["objectId"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("scoped-target-")) =>
            {
                self.target = params["objectId"]
                    .as_str()?
                    .strip_prefix("scoped-target-")?
                    .parse()
                    .ok()?;
                self.metadata = None;
                if let Some(context) = self.collected.get(&self.target) {
                    if let Some(error) = context["error"].as_str() {
                        return Some(json!({"exceptionDetails":{"text":error}}));
                    }
                    self.nodes = context["backends"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|backend| {
                            dom["nodes"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .find(|node| node["backendNodeId"] == *backend)
                                .unwrap()
                                .clone()
                        })
                        .collect();
                    self.metadata = Some(context["metadata"].clone());
                    return Some(json!({"result":{"objectId":"scoped-context"}}));
                }
                let mut all = dom["nodes"].as_array().cloned().unwrap_or_default();
                let pierced = all
                    .iter()
                    .flat_map(|node| {
                        ["shadowRoots", "pseudoElements"]
                            .into_iter()
                            .flat_map(move |key| {
                                node[key].as_array().into_iter().flatten().map(move |root| {
                                    (root["nodeId"].clone(), node["nodeId"].clone())
                                })
                            })
                    })
                    .collect::<Vec<_>>();
                for node in &mut all {
                    if let Some((_, parent)) = pierced.iter().find(|(id, _)| *id == node["nodeId"])
                    {
                        node["parentId"] = parent.clone();
                    }
                }
                self.nodes = Vec::new();
                let mut current = all.iter().find(|n| n["backendNodeId"] == self.target);
                let mut global = false;
                while let Some(node) = current {
                    if self.nodes.contains(node) {
                        break;
                    }
                    self.nodes.push(node.clone());
                    global |=
                        matches!(node["localName"].as_str(), Some("input" | "form" | "label"));
                    global |= node["attributes"].as_array().is_some_and(|attrs| {
                        attrs
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .any(|a| a[0] == "form" || a[0] == "href" || a[0] == "formaction")
                    });
                    current = all
                        .iter()
                        .find(|n| n["nodeId"] == node["parentId"] && !node["parentId"].is_null());
                }
                if params["arguments"][1]["value"] == true {
                    global = false;
                    if self.nodes.first().is_some_and(|node| node["nodeType"] != 1) {
                        // Include the small local key/value container's text,
                        // as the DOM-full helper does for text-node zooms.
                        self.nodes = all.clone();
                    }
                }
                if global {
                    self.nodes = all;
                }
                self.nodes
                    .retain(|node| matches!(node["nodeType"].as_u64(), Some(1 | 3 | 9 | 11)));
                self.complete = global;
                let controls = self
                    .nodes
                    .iter()
                    .filter(|n| {
                        matches!(
                            n["localName"].as_str(),
                            Some("input" | "button" | "select" | "textarea" | "output")
                        )
                    })
                    .count();
                let bound = if global {
                    (256 + controls * 32).min(16384)
                } else {
                    256
                };
                if self.nodes.len() > bound {
                    return Some(json!({"exceptionDetails":{"text":"context bound"}}));
                }
                Some(json!({"result":{"objectId":"scoped-context"}}))
            }
            "Runtime.getProperties" if params["objectId"] == "scoped-context" => {
                let parents = self
                    .nodes
                    .iter()
                    .map(|node| {
                        self.nodes.iter().position(|n| {
                            n["nodeId"] == node["parentId"] && !node["parentId"].is_null()
                        })
                    })
                    .collect::<Vec<_>>();
                let metadata = self.metadata.clone().unwrap_or_else(|| json!({"parents":parents,"complete":self.complete,"bound":if self.complete { (256 + 32 * self.nodes.iter().filter(|n| matches!(n["localName"].as_str(), Some("input" | "button" | "select" | "textarea" | "output"))).count()).min(16384) } else { 256 },"childCounts":self.nodes.iter().map(|n| n["childNodeCount"].clone()).collect::<Vec<_>>(),"keys":self.nodes.iter().map(|node| node["backendNodeId"].clone()).collect::<Vec<_>>(),"slots":self.nodes.iter().map(|node| node["assignedSlot"]["backendNodeId"].clone()).collect::<Vec<_>>(),"facts":self.nodes}));
                let mut properties = vec![
                    json!({"name":"0","value":{"value":serde_json::to_string(&metadata).unwrap()}}),
                    json!({"name":"state","value":{"objectId":"scoped-state"}}),
                ];
                properties.extend(self.nodes.iter().enumerate().map(|(i, _)| json!({"name":(i+1).to_string(),"value":{"objectId":format!("scoped-node-{i}")}})));
                Some(json!({"result":properties}))
            }
            "DOM.describeNode"
                if params["objectId"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("scoped-node-")) =>
            {
                let index = params["objectId"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("scoped-node-")
                    .parse::<usize>()
                    .unwrap();
                let mut node = self.nodes[index].clone();
                if self.mutate_form_on_describe == Some(self.described_backend(index)) {
                    node["attributes"]
                        .as_array_mut()
                        .unwrap()
                        .extend([json!("form"), json!("login")]);
                }
                if self.close_shadow_on_target == Some(self.target)
                    && self.closed_host == node["backendNodeId"].as_u64()
                    && self.closed_host.is_some()
                {
                    node["shadowRoots"] = json!([{"nodeId":987654321,"backendNodeId":987654321,"nodeType":11,"nodeName":"#document-fragment","shadowRootType":"closed"}]);
                }
                Some(json!({"node":node}))
            }
            "Runtime.releaseObjectGroup"
                if params["objectGroup"] == "ck-snapshot-classification" =>
            {
                Some(json!({}))
            }
            _ => None,
        }
    }
}
