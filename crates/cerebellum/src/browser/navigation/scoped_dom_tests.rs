use super::large_page_tests::driver_with_dom;
use super::tests::{ax_node, FakeClock};
use super::*;
use serde_json::json;
use std::io::Write;
use std::process::{Command, Stdio};

// This is a DOM model, not a second implementation of scope discovery. Node
// executes the exact production collector supplied in the JSON input. Its
// returned handles/metadata then drive the normal Rust CDP read protocol.
const DOM_MODEL: &str = r#"
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const collect = vm.runInNewContext('(' + input.function + ')');
const outputs = [];
for (const fixture of input.fixtures) {
  let childReads = 0;
  class Node {
    constructor(raw) {
      this.raw = raw; this.children = []; this.parentNode = null;
      this.host = null; this.shadowRoot = null; this.assignedSlot = null;
    }
    get nodeType() { return this.raw.nodeType; }
    get nodeName() { return this.raw.nodeName || this.raw.localName; }
    get localName() { return this.raw.localName || ''; }
    get nodeValue() { return this.raw.nodeValue || ''; }
    get attributes() {
      const values = this.raw.attributes || [], out = [];
      for (let n = 0; n < values.length; n += 2) out.push({name: values[n], value: values[n + 1]});
      return out;
    }
    hasAttribute(name) { return this.attributes.some(attr => attr.name === name); }
    getAttribute(name) { return this.attributes.find(attr => attr.name === name)?.value ?? null; }
    get firstChild() { ++childReads; return this.children[0] || null; }
    get nextSibling() {
      if (!this.parentNode) return null;
      return this.parentNode.children[this.parentNode.children.indexOf(this) + 1] || null;
    }
    get ownerDocument() {
      if (this.nodeType === 9) return null;
      let node = this;
      while (node && node.nodeType !== 9) node = node.parentNode || node.host;
      return node;
    }
    get isConnected() { return this.nodeType === 9 || !!this.ownerDocument; }
  }
  const nodes = fixture.dom.nodes.map(raw => new Node(raw));
  const byId = new Map(nodes.map(node => [node.raw.nodeId, node]));
  const byBackend = new Map(nodes.map(node => [node.raw.backendNodeId, node]));
  for (const node of nodes) {
    if (node.nodeType === 9) continue; // A frame Document is not a light-DOM child.
    const parent = byId.get(node.raw.parentId);
    if (parent) { node.parentNode = parent; parent.children.push(node); }
  }
  for (const host of nodes) {
    for (const raw of host.raw.shadowRoots || []) {
      const root = byId.get(raw.nodeId);
      if (!root) continue;
      if (root.parentNode) root.parentNode.children = root.parentNode.children.filter(node => node !== root);
      root.parentNode = null; root.host = host;
      if (raw.shadowRootType !== 'closed' && raw.shadowRootType !== 'user-agent') host.shadowRoot = root;
    }
    host.assignedSlot = byBackend.get(host.raw.assignedSlot?.backendNodeId) || null;
  }
  let state = {keys: new WeakMap(), next: 1};
  const contexts = {};
  for (const backend of fixture.targets) {
    try {
      for (const change of fixture.mutations || []) {
        if (change.before !== backend) continue;
        const node = byBackend.get(change.backend);
        if (change.attributes) node.raw.attributes = change.attributes;
        if (change.closedShadow) {
          const root = new Node({nodeId: 987654321, backendNodeId: 987654321, nodeType: 11, nodeName: '#document-fragment'});
          root.host = node; // Deliberately not exposed as Element.shadowRoot.
          node.closedRoot = root;
          node.raw.shadowRoots = [{nodeId: 987654321, backendNodeId: 987654321, shadowRootType: 'closed'}];
        }
      }
      const out = collect.call(byBackend.get(backend), 256, false, state);
      if (!out) throw new Error('disconnected');
      state = out.state;
      contexts[backend] = {metadata: JSON.parse(out[0]), backends: out.slice(1).map(node => node.raw.backendNodeId)};
    } catch (error) { contexts[backend] = {error: error.message, childReads}; }
  }
  outputs.push(contexts);
}
process.stdout.write(JSON.stringify(outputs));
"#;

fn collected_contexts(fixtures: &[(&Value, &[u64])]) -> Vec<HashMap<u64, Value>> {
    run_collector(json!(fixtures
        .iter()
        .map(|(dom, targets)| json!({"dom":dom,"targets":targets}))
        .collect::<Vec<_>>()))
}

fn run_collector(fixtures: Value) -> Vec<HashMap<u64, Value>> {
    let input = json!({"function":include_str!("scoped_dom.js"),"fixtures":fixtures});
    let mut child = Command::new("node")
        .args(["-e", DOM_MODEL])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(
            "scoped collector parity tests require Node.js: install `node` on the test host's PATH",
        );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "collector execution failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn node(id: u64, parent: Option<u64>, tag: &str, attributes: &[&str]) -> Value {
    let kind = match tag {
        "#document" => 9,
        "#document-fragment" => 11,
        "#text" => 3,
        _ => 1,
    };
    let mut node = json!({"nodeId":id,"backendNodeId":id,"nodeType":kind,"nodeName":tag,"localName":tag,"attributes":attributes});
    if let Some(parent) = parent {
        node["parentId"] = json!(parent);
    }
    node
}

struct Fixture {
    name: &'static str,
    dom: Value,
    targets: Vec<u64>,
    frame: &'static str,
    bounded_refusal: bool,
}

fn fixture(name: &'static str, mut nodes: Vec<Value>, targets: Vec<u64>) -> Fixture {
    let shadow_ids = nodes
        .iter()
        .flat_map(|node| {
            node["shadowRoots"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|root| root["nodeId"].as_u64())
        })
        .collect::<HashSet<_>>();
    let mut child_counts = HashMap::<u64, u64>::new();
    for child in &nodes {
        if child["nodeType"] == 9 || shadow_ids.contains(&child["nodeId"].as_u64().unwrap()) {
            continue;
        }
        if let Some(parent) = child["parentId"].as_u64() {
            *child_counts.entry(parent).or_default() += 1;
        }
    }
    for node in &mut nodes {
        node["childNodeCount"] = json!(child_counts
            .get(&node["nodeId"].as_u64().unwrap())
            .copied()
            .unwrap_or_default());
    }
    Fixture {
        name,
        dom: json!({"nodes":nodes}),
        targets,
        frame: "frame-main",
        bounded_refusal: false,
    }
}

fn observation_for(
    fixture: &Fixture,
    contexts: HashMap<u64, Value>,
    cached: bool,
) -> (
    CdpNavigationDriver<super::large_page_tests::ThreadPipe>,
    BrowserSnapshotObservation,
) {
    let ids = fixture
        .targets
        .iter()
        .map(|id| format!("target-{id}"))
        .collect::<Vec<_>>();
    let mut root = ax_node(
        "root",
        "RootWebArea",
        "Page",
        &ids.iter().map(String::as_str).collect::<Vec<_>>(),
        999_999,
        Some(fixture.frame),
    );
    root["ignored"] = json!(true);
    let mut ax = vec![root];
    ax.extend(
        fixture
            .targets
            .iter()
            .zip(ids)
            .map(|(backend, id)| ax_node(&id, "generic", "Target", &[], *backend, None)),
    );
    let mut driver = driver_with_dom(ax, fixture.dom.clone());
    driver.pipe.scoped.collected = contexts;
    driver.cache_snapshot_contexts = cached;
    let observation = driver
        .snapshot_with_clock(
            "route-own",
            SnapshotKind::Ax,
            120_000,
            None,
            None,
            &[],
            &mut FakeClock::new(),
        )
        .unwrap();
    (driver, observation)
}

fn classify_scoped(
    driver: &mut CdpNavigationDriver<super::large_page_tests::ThreadPipe>,
    observation: &mut BrowserSnapshotObservation,
) {
    driver.pipe.requests.clear();
    let attachment = driver.attachment.clone().unwrap();
    let mut clock = FakeClock::new();
    let deadline = clock.now() + Duration::from_secs(120);
    driver.scoped_snapshot_dom(
        observation,
        &attachment,
        Some((7, "https://example.com/page")),
        &mut SnapshotTimings::default(),
        deadline,
        &mut clock,
    );
    assert!(
        driver
            .pipe
            .requests
            .iter()
            .filter(|request| request["method"] == "Runtime.callFunctionOn")
            .all(|request| request["params"]["functionDeclaration"]
                .as_str()
                .is_some_and(|function| function.contains(include_str!("scoped_dom.js")))),
        "the responder must be driven by the same collector Node executed"
    );
}

fn representative_fixtures() -> Vec<Fixture> {
    let base = || {
        vec![
            node(1, None, "#document", &[]),
            node(2, Some(1), "body", &[]),
        ]
    };
    let mut fixtures = Vec::new();
    let mut nodes = base();
    nodes.push(node(
        3,
        Some(2),
        "input",
        &["type", "password", "autocomplete", "current-password"],
    ));
    fixtures.push(fixture("password", nodes, vec![3]));

    let mut nodes = base();
    nodes.extend([
        node(3, Some(2), "form", &["id", "payment"]),
        node(4, Some(3), "input", &["autocomplete", "cc-number"]),
        node(5, Some(3), "input", &["autocomplete", "cc-exp"]),
        node(6, Some(3), "input", &["autocomplete", "cc-csc"]),
        node(7, Some(3), "button", &["type", "submit"]),
    ]);
    fixtures.push(fixture(
        "card-number-expiry-csc-and-submit",
        nodes,
        vec![4, 5, 6, 7],
    ));

    let mut nodes = base();
    nodes.extend([
        node(3, Some(2), "form", &["id", "login"]),
        node(
            4,
            Some(3),
            "input",
            &["name", "user", "autocomplete", "username"],
        ),
        node(5, Some(3), "input", &["type", "password"]),
    ]);
    fixtures.push(fixture("username-before-password", nodes, vec![4, 5]));

    let mut nodes = base();
    nodes.push(node(
        3,
        Some(2),
        "input",
        &["type", "search", "role", "searchbox"],
    ));
    fixtures.push(fixture("search-box", nodes, vec![3]));

    let mut nodes = base();
    nodes.extend([
        node(3, Some(2), "form", &["id", "login"]),
        node(4, Some(3), "input", &["type", "password"]),
        node(
            5,
            Some(2),
            "input",
            &["form", "login", "autocomplete", "username"],
        ),
    ]);
    fixtures.push(fixture("external-form-owned-field", nodes, vec![5, 4]));

    let mut nodes = base();
    let mut host = node(4, Some(3), "div", &[]);
    host["shadowRoots"] = json!([{"nodeId":5,"backendNodeId":5,"shadowRootType":"open"}]);
    nodes.extend([
        node(3, Some(2), "form", &["id", "login"]),
        host,
        node(5, Some(4), "#document-fragment", &[]),
        node(6, Some(5), "input", &["type", "password"]),
    ]);
    fixtures.push(fixture("open-shadow-root-field", nodes, vec![6]));

    let mut nodes = base();
    nodes.extend([
        node(3, Some(2), "form", &["id", "login"]),
        node(4, Some(3), "input", &["autocomplete", "username"]),
        node(5, Some(2), "iframe", &[]),
        node(6, Some(5), "#document", &[]),
        node(7, Some(6), "form", &["id", "login"]),
        node(8, Some(7), "input", &["type", "password"]),
        node(9, Some(7), "input", &["autocomplete", "cc-csc"]),
    ]);
    let mut frame = fixture(
        "same-origin-frame-with-duplicate-form-id",
        nodes,
        vec![8, 9],
    );
    frame.frame = "frame-child";
    fixtures.push(frame);

    let nodes = vec![
        node(1, None, "#document", &[]),
        node(2, Some(1), "head", &[]),
        node(
            3,
            Some(2),
            "base",
            &["href", "https://landing.example.net/base/"],
        ),
        node(4, Some(1), "body", &[]),
        node(5, Some(4), "a", &["href", "relative/path"]),
        node(6, Some(4), "button", &["type", "button"]),
    ];
    fixtures.push(fixture("relative-link-under-base", nodes, vec![5, 6]));

    let mut nodes = base();
    nodes.extend([
        node(
            3,
            Some(2),
            "form",
            &["action", "https://example.com/default"],
        ),
        node(4, Some(3), "input", &["autocomplete", "cc-number"]),
        node(
            5,
            Some(3),
            "button",
            &[
                "type",
                "submit",
                "formaction",
                "https://billing.example.net/pay",
            ],
        ),
    ]);
    fixtures.push(fixture("button-formaction", nodes, vec![5]));

    let mut nodes = base();
    nodes.extend([
        node(3, Some(2), "button", &["type", "button"]),
        node(4, Some(2), "span", &["role", "button"]),
    ]);
    fixtures.push(fixture("plain-non-form-controls", nodes, vec![3, 4]));

    // An ordinary ref comes first so this also exercises the fresh complete
    // upgrade rather than satisfying a form from a partial cached ancestor.
    let mut nodes = base();
    nodes.extend([
        node(3, Some(2), "button", &["type", "button"]),
        node(4, Some(2), "form", &["id", "f"]),
        node(5, Some(4), "input", &["type", "password"]),
    ]);
    fixtures.push(fixture("ordinary-then-complete-context", nodes, vec![3, 5]));

    let mut nodes = base();
    nodes.push(node(3, Some(2), "input", &["type", "password"]));
    nodes.extend((4..304).map(|id| node(id, Some(2), "div", &[])));
    let mut overflow = fixture("global-facts-beyond-256-node-bound", nodes, vec![3]);
    overflow.bounded_refusal = true;
    fixtures.push(overflow);
    fixtures
}

/// Requires Node.js (`node` on PATH). A missing runtime fails the test; it is
/// never treated as a skipped or successful parity check.
#[test]
fn scoped_collector_matches_whole_document_records_including_login_ordinals() {
    let fixtures = representative_fixtures();
    let contexts = collected_contexts(
        &fixtures
            .iter()
            .map(|fixture| (&fixture.dom, fixture.targets.as_slice()))
            .collect::<Vec<_>>(),
    );
    let mut pairs = 0;
    for (fixture, contexts) in fixtures.iter().zip(contexts) {
        let flattened = parse_flattened_dom_nodes(fixture.dom.as_object().unwrap()).unwrap();
        let old = DomClassificationBatch::new(&flattened);
        let (mut driver, mut observation) = observation_for(fixture, contexts, true);
        let same_refs = observation.refs.clone();
        classify_scoped(&mut driver, &mut observation);
        assert_eq!(same_refs.len(), fixture.targets.len());
        for (reference, actual) in same_refs.iter().zip(&observation.refs) {
            let identity = reference.backend_identity.as_ref().unwrap();
            assert_eq!(actual.backend_identity.as_ref(), Some(identity));
            let expected = old.classify(identity, 7, "https://example.com").unwrap();
            if fixture.name == "username-before-password" {
                let facts = expected.login_field.as_ref().unwrap();
                let expected_order = if identity.backend_node_id == 4 {
                    (3, 0)
                } else {
                    (4, 1)
                };
                assert_eq!(
                    (
                        facts.document_order,
                        facts.form_start_order,
                        facts.preceding_text_inputs
                    ),
                    (Some(expected_order.0), Some(2), expected_order.1),
                    "the fixture must exercise real global ordinals and preceding-input counts"
                );
            }
            if fixture.bounded_refusal {
                assert_eq!(
                    actual.classification,
                    Err(ClassificationUnavailable::DomReadFailed),
                    "{}",
                    fixture.name
                );
                assert!(fixture.dom["nodes"].as_array().unwrap().len() > 256);
                continue;
            }
            let actual = actual.classification.as_ref().unwrap_or_else(|reason| {
                panic!(
                    "{} / backend {}: {reason:?}",
                    fixture.name, identity.backend_node_id
                )
            });
            assert_eq!(
                actual.as_ref(),
                &expected,
                "{} / backend {}: authorization record",
                fixture.name,
                identity.backend_node_id
            );
            // Neither record serialization nor its PartialEq includes these
            // ephemeral hints. Compare them explicitly, including ordinals.
            assert_eq!(
                actual.login_field, expected.login_field,
                "{} / backend {}: complete login-field facts",
                fixture.name, identity.backend_node_id
            );
            pairs += 1;
        }
    }
    println!(
        "collector parity: {} fixtures, {pairs} exact record pairs and one named bounded refusal",
        fixtures.len()
    );
}

fn described_backends(
    driver: &CdpNavigationDriver<super::large_page_tests::ThreadPipe>,
) -> HashMap<u64, usize> {
    let mut descriptions = HashMap::new();
    // Each context's getProperties reply numbers handles in its collector
    // order. Resolve that order from the already-executed collector fixture.
    let mut target = 0;
    for request in &driver.pipe.requests {
        if request["method"] == "DOM.resolveNode" {
            target = request["params"]["backendNodeId"].as_u64().unwrap();
        }
        if request["method"] == "DOM.describeNode" {
            let index = request["params"]["objectId"]
                .as_str()
                .unwrap()
                .strip_prefix("scoped-node-")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let backend = if driver.cache_snapshot_contexts {
                driver.pipe.scoped.described_backend(index)
            } else {
                driver.pipe.scoped.collected[&target]["backends"][index]
                    .as_u64()
                    .unwrap()
            };
            *descriptions.entry(backend).or_insert(0) += 1;
        }
    }
    descriptions
}

#[test]
fn cached_ancestor_facts_are_rechecked_without_a_second_description() {
    let fixture = fixture(
        "cached-host-attribute-churn",
        vec![
            node(1, None, "#document", &[]),
            node(2, Some(1), "body", &[]),
            node(3, Some(2), "div", &[]),
            node(4, Some(3), "button", &["type", "button"]),
            node(5, Some(3), "button", &["type", "button"]),
        ],
        vec![4, 5],
    );
    let contexts = run_collector(json!([{"dom":fixture.dom,"targets":fixture.targets,"mutations":[{"before":5,"backend":3,"attributes":["role","button","disabled",""]}]}])).remove(0);
    let (mut driver, mut observation) = observation_for(&fixture, contexts, true);
    classify_scoped(&mut driver, &mut observation);
    assert!(observation.refs[0].classification.is_ok());
    assert_eq!(
        observation.refs[1].classification,
        Err(ClassificationUnavailable::DomReadFailed)
    );
    assert!(described_backends(&driver)
        .values()
        .all(|count| *count == 1));
}

#[test]
fn closed_shadow_is_seen_by_the_shared_fresh_native_read() {
    let fixture = fixture(
        "closed-shadow-upgrade",
        vec![
            node(1, None, "#document", &[]),
            node(2, Some(1), "body", &[]),
            node(3, Some(2), "div", &[]),
            node(4, Some(3), "button", &["type", "button"]),
            node(5, Some(2), "form", &["id", "login"]),
            node(6, Some(5), "input", &["type", "password"]),
        ],
        vec![4, 6],
    );
    let contexts = run_collector(json!([{"dom":fixture.dom,"targets":fixture.targets,"mutations":[{"before":6,"backend":3,"closedShadow":true}]}])).remove(0);
    let (mut driver, mut observation) = observation_for(&fixture, contexts, true);
    driver.pipe.scoped.close_shadow_on_target = Some(6);
    driver.pipe.scoped.closed_host = Some(3);
    classify_scoped(&mut driver, &mut observation);
    assert!(observation.refs[0].classification.is_ok());
    assert_eq!(
        observation.refs[1].classification,
        Err(ClassificationUnavailable::DomReadFailed),
        "a partial cached host cannot prove complete shadow facts"
    );
    assert_eq!(
        described_backends(&driver)[&3],
        1,
        "the shared native read observes closed roots for the complete context"
    );
}

fn shared_chains(refs: u64) -> Fixture {
    // A target, its comment-thread container, and 23 common ancestors: 25
    // nodes per chain, with 18 threads sharing the common path.
    let mut nodes = vec![node(1, None, "#document", &[])];
    nodes.extend((2..=23).map(|id| node(id, Some(id - 1), "div", &[])));
    nodes.extend((24..42).map(|id| node(id, Some(23), "div", &[])));
    let targets = (42..42 + refs).collect::<Vec<_>>();
    nodes.extend(targets.iter().enumerate().map(|(index, id)| {
        node(
            *id,
            Some(24 + index as u64 % 18),
            "button",
            &["type", "button"],
        )
    }));
    fixture("shared-depth-25-chains", nodes, targets)
}

fn complete_context(refs: u64) -> Fixture {
    let mut nodes = vec![
        node(1, None, "#document", &[]),
        node(2, Some(1), "body", &[]),
    ];
    let targets = (3..refs + 3).collect::<Vec<_>>();
    nodes.extend(
        targets
            .iter()
            .map(|id| node(*id, Some(2), "input", &["type", "text"])),
    );
    let next = refs + 3;
    if nodes.len() < 256 {
        nodes.extend((next..257).map(|id| node(id, Some(2), "div", &[])));
    }
    fixture("bounded-complete-context", nodes, targets)
}

#[test]
fn scoped_classification_round_trips_before_and_after_snapshot_cache() {
    let mut overflow = complete_context(100);
    let nodes = overflow.dom["nodes"].as_array_mut().unwrap();
    nodes.extend((257..16600).map(|id| node(id, Some(2), "div", &[])));
    let fixtures = [
        shared_chains(100),
        shared_chains(2900),
        complete_context(100),
        overflow,
    ];
    let contexts = collected_contexts(
        &fixtures
            .iter()
            .map(|fixture| (&fixture.dom, fixture.targets.as_slice()))
            .collect::<Vec<_>>(),
    );
    for (index, (fixture, contexts)) in fixtures.iter().zip(contexts).enumerate() {
        for cached in [false, true] {
            let (mut driver, mut observation) = observation_for(fixture, contexts.clone(), cached);
            classify_scoped(&mut driver, &mut observation);
            let trips = driver.pipe.requests.len();
            let descriptions = driver
                .pipe
                .requests
                .iter()
                .filter(|request| request["method"] == "DOM.describeNode")
                .count();
            let classified = observation
                .refs
                .iter()
                .filter(|reference| reference.classification.is_ok())
                .count();
            let expected = match (index, cached) {
                (0, false) => 2803,
                (0, true) => 246,
                (1, false) => 81203,
                (1, true) => 5846,
                (2, false) => 25903,
                (2, true) => 361,
                (3, false) => 203,
                (3, true) => 105,
                _ => unreachable!(),
            };
            assert_eq!(
                trips,
                expected,
                "{} / N={} / cached={cached}",
                fixture.name,
                fixture.targets.len()
            );
            if cached && index < 2 {
                assert!(described_backends(&driver)
                    .values()
                    .all(|count| *count == 1));
            }
            assert_eq!(
                classified,
                if index == 3 { 0 } else { fixture.targets.len() }
            );
            println!("classification CDP: case={} N={} cached={cached} trips={trips} describes={descriptions} classified={classified} refused={}", fixture.name, fixture.targets.len(), fixture.targets.len() - classified);
        }
    }
}

#[test]
fn live_chrome_regression_scoped_reads_have_a_finishable_shared_deadline() {
    let fixture = shared_chains(100);
    let contexts = collected_contexts(&[(&fixture.dom, &fixture.targets)]).remove(0);
    let (mut driver, mut observation) = observation_for(&fixture, contexts, true);
    driver.pipe.poll_before_reply = true;
    driver.pipe.requests.clear();
    let attachment = driver.attachment.clone().unwrap();
    let mut clock = FakeClock::new();
    let deadline = clock.now() + Duration::from_millis(500);
    driver.scoped_snapshot_dom(
        &mut observation,
        &attachment,
        Some((7, "https://example.com/page")),
        &mut SnapshotTimings::default(),
        deadline,
        &mut clock,
    );
    assert_eq!(
        observation
            .refs
            .iter()
            .filter(|r| r.classification.is_ok())
            .count(),
        100,
        "a five-millisecond polling turn must not exhaust each ref's multistep context read"
    );
    assert_eq!(
        driver
            .pipe
            .requests
            .iter()
            .filter(|r| r["method"] == "Runtime.callFunctionOn")
            .count(),
        1
    );
    assert_eq!(driver.transport.pending_len(), 0);
}

#[test]
fn live_chrome_regression_complete_form_bound_scales_with_controls() {
    let mut nodes = vec![
        node(1, None, "#document", &[]),
        node(2, Some(1), "form", &["id", "ordinary"]),
    ];
    let targets = (3..83).collect::<Vec<_>>();
    nodes.extend(
        targets
            .iter()
            .map(|id| node(*id, Some(2), "input", &["type", "text"])),
    );
    nodes.extend((83..600).map(|id| node(id, Some(2), "div", &[])));
    let fixture = fixture("ordinary-large-form", nodes, targets);
    let contexts = collected_contexts(&[(&fixture.dom, &fixture.targets)]).remove(0);
    assert_eq!(
        contexts[&3]["metadata"]["complete"], true,
        "ordinary fields need an exact complete context beyond 256 layout nodes"
    );
    let (mut driver, mut observation) = observation_for(&fixture, contexts, true);
    classify_scoped(&mut driver, &mut observation);
    let nodes = parse_flattened_dom_nodes(fixture.dom.as_object().unwrap()).unwrap();
    let old = DomClassificationBatch::new(&nodes);
    for reference in observation.refs {
        let actual = reference.classification.unwrap();
        let expected = old
            .classify(
                reference.backend_identity.as_ref().unwrap(),
                7,
                "https://example.com",
            )
            .unwrap();
        assert_eq!(*actual, expected);
        assert_eq!(actual.login_field, expected.login_field);
        assert_eq!(actual.associated_form_controls.len(), 80);
    }
}

#[test]
fn oversized_complete_context_is_walked_only_once_per_snapshot() {
    let mut nodes = vec![
        node(1, None, "#document", &[]),
        node(2, Some(1), "form", &[]),
    ];
    nodes.extend([
        node(3, Some(2), "input", &["type", "password"]),
        node(4, Some(2), "input", &["type", "text"]),
    ]);
    nodes.extend((5..1000).map(|id| node(id, Some(2), "div", &[])));
    let fixture = fixture("oversized-form", nodes, vec![3, 4]);
    let contexts = collected_contexts(&[(&fixture.dom, &fixture.targets)]).remove(0);
    assert_eq!(contexts[&3]["error"], "context bound");
    assert_eq!(contexts[&4]["error"], "context bound");
    assert!(contexts[&3]["childReads"].as_u64().unwrap() > 0);
    assert_eq!(
        contexts[&3]["childReads"], contexts[&4]["childReads"],
        "repeated global failures must not keep the renderer walking the same document"
    );
}
