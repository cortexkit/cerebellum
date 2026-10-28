import test from "node:test";
import assert from "node:assert/strict";
import { mapFrames } from "../frames.mjs";
import { setup } from "./harness.mjs";

const root = { id: "cdp-main", loaderId: "main-loader", url: "https://page.example/" };
const child = { id: "cdp-child", parentId: root.id, loaderId: "child-loader", url: "https://page.example/child" };
const tree = () => ({ frame: root, childFrames: [{ frame: child }] });
const navigation = () => [
  { frameId: 0, parentFrameId: -1, documentId: "main-doc", url: root.url },
  { frameId: 17, parentFrameId: 0, documentId: "child-doc", url: child.url },
];

test("same-origin mapping joins the parent chain rather than numeric and CDP ids", () => {
  const mappings = mapFrames(tree(), navigation());
  assert.deepEqual(mappings[1], { frame_id: child.id, parent_id: root.id, loader_id: child.loaderId, url: child.url, session_id: "root", web_navigation_frame_id: 17, document_id: "child-doc" });
});

test("cross-origin mapping retains the verified child target owner", () => {
  const cross = { ...child, url: "https://other.example/field" };
  const frames = navigation();
  frames[1].url = cross.url;
  assert.equal(mapFrames({ frame: root, childFrames: [{ frame: cross }] }, frames, new Map([[child.id, "target-not-frame-id"]]))[1].session_id, "target-not-frame-id");
});

test("ambiguous siblings leave the top level and normal child readable", () => {
  const frames = [...navigation(), { ...navigation()[1], frameId: 18, documentId: "duplicate-doc" }, { frameId: 19, parentFrameId: 0, documentId: "normal-doc", url: "https://page.example/normal" }];
  const mappings = mapFrames({ frame: root, childFrames: [{ frame: child }, { frame: { ...child, id: "duplicate-child" } }, { frame: { ...child, id: "normal-child", url: frames[3].url } }] }, frames);
  assert.deepEqual(mappings.map(frame => [frame.frame_id, frame.unreadable_reason ?? "readable"]), [[root.id, "readable"], [child.id, "ambiguous"], ["duplicate-child", "ambiguous"], ["normal-child", "readable"]]);
  assert.equal(mappings[3].web_navigation_frame_id, 19);
  assert.equal(mappings[1].web_navigation_frame_id, undefined);
  assert.equal(mappings[2].web_navigation_frame_id, undefined);
});

test("documentId disambiguates only when Chrome exposes it on both sides", () => {
  const frames = [...navigation(), { ...navigation()[1], frameId: 18, documentId: "duplicate-doc" }];
  const duplicate = { ...child, id: "another-child", documentId: "duplicate-doc" };
  const mappings = mapFrames({ frame: root, childFrames: [{ frame: { ...child, documentId: "child-doc" } }, { frame: duplicate }] }, frames);
  assert.equal(mappings[1].web_navigation_frame_id, 17);
  assert.equal(mappings[2].web_navigation_frame_id, 18);
});

test("a navigated-away child is omitted as stale even at the same URL", () => {
  const frames = navigation();
  frames[1].documentId = "replacement-document";
  const mappings = mapFrames({ frame: root, childFrames: [{ frame: { ...child, documentId: "child-doc" } }] }, frames);
  assert.equal(mappings[0].unreadable_reason, undefined);
  assert.equal(mappings[1].unreadable_reason, "stale");
});

async function framed(cross = true) {
  const f = await setup();
  const crossChild = { ...child, url: cross ? "https://other.example/field" : child.url };
  const frames = navigation();
  frames[1].url = crossChild.url;
  f.chrome.webNavigation.getAllFrames = async () => frames;
  const base = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    if (method === "Target.setAutoAttach" && !target.sessionId && cross) {
      f.chrome.debugger.onEvent.emit(target, "Target.attachedToTarget", { sessionId: "ephemeral-child-session", targetInfo: { type: "iframe", targetId: child.id, parentFrameId: root.id, url: crossChild.url } });
    }
    await base(target, method, params);
    // Real Chrome reports the OOPIF only in its own session, not as a stub
    // in the parent's tree. webNavigation still lists both documents.
    if (method === "Page.getFrameTree") return { frameTree: target.sessionId ? { frame: crossChild } : cross ? { frame: root } : { frame: root, childFrames: [{ frame: crossChild }] } };
    if (method === "Accessibility.getFullAXTree" && target.sessionId) return { nodes: [{ nodeId: "child-input", role: { value: "textbox" }, name: { value: "Iframe input" }, backendDOMNodeId: 42, frameId: child.id }] };
    return { nodes: [] };
  };
  const discover = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  return { ...f, frames, scope: discover.frame_mappings[1] };
}

test("OOPIF commands resolve fresh flattened sessions and detach with their tab", async () => {
  const f = await framed();
  const { frame_id, loader_id, session_id } = f.scope;
  assert.equal(session_id, child.id);
  const reply = await f.run(f.cdp([{ method: "Accessibility.getFullAXTree", params: { frameId: frame_id }, frame_id, loader_id, session_id }]));
  assert.equal(reply.results[0].result.nodes[0].name.value, "Iframe input");
  const dispatched = f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Accessibility.getFullAXTree");
  assert.deepEqual(dispatched.map(call => call[1]), [{ tabId: 2, sessionId: "ephemeral-child-session" }]);
  assert.equal(f.chrome.calls.filter(call => call[0] === "attach").length, f.chrome.calls.filter(call => call[0] === "detach").length);
  assert.equal(f.chrome.debugger.onEvent.listeners.size, 0);
});

test("nested OOPIFs join reachable parents after pending child auto-attach", async () => {
  const f = await setup();
  const nested = { id: "nested-frame", parentId: child.id, loaderId: "nested-loader", url: "https://nested.example/" };
  f.chrome.webNavigation.getAllFrames = async () => [...navigation(), { frameId: 18, parentFrameId: 17, documentId: "nested-doc", url: nested.url }];
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    await send(target, method, params);
    if (method === "Target.setAutoAttach" && !target.sessionId) {
      f.chrome.debugger.onEvent.emit(target, "Target.attachedToTarget", { sessionId: "child-session", targetInfo: { type: "iframe", targetId: child.id } });
    } else if (method === "Target.setAutoAttach" && target.sessionId === "child-session") {
      await new Promise(resolve => setImmediate(resolve));
      f.chrome.debugger.onEvent.emit(target, "Target.attachedToTarget", { sessionId: "nested-session", targetInfo: { type: "iframe", targetId: nested.id } });
    }
    if (method === "Page.getFrameTree") return { frameTree: { frame: target.sessionId === "nested-session" ? nested : target.sessionId ? child : root } };
    return {};
  };
  const reply = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  assert.deepEqual(reply.frame_mappings.map(frame => [frame.frame_id, frame.session_id]), [[root.id, "root"], [child.id, child.id], [nested.id, nested.id]]);
  assert.equal(reply.results[0].result.frameTree.childFrames[0].childFrames[0].frame.id, nested.id);
});

test("an OOPIF stub is replaced rather than duplicated by its session tree", async () => {
  const f = await framed();
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    const reply = await send(target, method, params);
    if (method === "Page.getFrameTree" && !target.sessionId) reply.frameTree.childFrames = [{ frame: { ...child, loaderId: "", url: "" } }];
    return reply;
  };
  const reply = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  assert.equal(reply.results[0].result.frameTree.childFrames.length, 1);
  assert.equal(reply.frame_mappings[1].loader_id, child.loaderId);
  assert.equal(reply.frame_mappings[1].session_id, child.id);
  assert.equal(reply.frame_mappings[1].unreadable_reason, undefined);
});

test("same-origin child commands stay on the root target", async () => {
  const f = await framed(false);
  const { frame_id, loader_id, session_id } = f.scope;
  await f.run(f.cdp([{ method: "DOM.enable", params: {}, frame_id, loader_id, session_id }]));
  assert.deepEqual(f.chrome.calls.find(call => call[0] === "cdp" && call[2] === "DOM.enable")[1], { tabId: 2 });
});

for (const cross of [false, true]) {
  const owner = cross ? "OOPIF" : "same-process";
  test(`${owner} child classification reads and button mouse pairs use the verified owner`, async () => {
    const f = await framed(cross);
    // The fake models document-id targeting only for the root. Frame-id
    // targeting still exercises the child's sentinel and verified CDP scope.
    f.frames[0].documentId = "document-2";
    delete f.frames[1].documentId;
    assert.equal(await f.epochs.install(2), true);
    assert.ok(f.chrome.sentinels.has("2:17"));
    const { frame_id, loader_id, session_id } = f.scope;
    const scope = { frame_id, loader_id, session_id };
    const send = f.chrome.debugger.sendCommand;
    const button = { nodeId: 42, backendNodeId: 42, nodeType: 1, nodeName: "BUTTON", localName: "button", attributes: ["type", "button"] };
    f.chrome.debugger.sendCommand = async (target, method, params) => {
      const result = await send(target, method, params);
      return method === "DOM.getFlattenedDocument" ? { nodes: [button] } : result;
    };
    const read = await f.run(f.cdp([
      { method: "DOM.enable", params: {}, ...scope },
      { method: "DOM.getFlattenedDocument", params: { depth: -1, pierce: true }, ...scope },
    ]));
    assert.equal(read.observer_available, true);
    assert.deepEqual(read.results[1].result.nodes, [button]);
    const mouse = type => ({ method: "Input.dispatchMouseEvent", params: { type, x: 10, y: 20, button: "left" }, ...scope });
    const clicked = await f.run({ ...f.cdp([mouse("mousePressed"), mouse("mouseReleased")]), interaction_epoch: read.interaction_epoch });
    assert.equal(clicked.results.length, 2);
    assert.equal(clicked.results.some(entry => entry.error), false);
    const target = cross ? { tabId: 2, sessionId: "ephemeral-child-session" } : { tabId: 2 };
    const dom = f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "DOM.getFlattenedDocument");
    assert.deepEqual(dom.map(call => call[1]), [target]);
    assert.deepEqual(dom[0][3], { depth: -1, pierce: true });
    const clicks = f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Input.dispatchMouseEvent");
    assert.deepEqual(clicks.map(call => call[1]), [target, target]);
  });

  test(`${owner} child DOM capture preserves credential facts for the Rust input guard`, async () => {
    const f = await framed(cross);
    const { frame_id, loader_id, session_id } = f.scope;
    const scope = { frame_id, loader_id, session_id };
    const password = { nodeId: 43, backendNodeId: 43, nodeType: 1, nodeName: "INPUT", localName: "input", attributes: ["type", "password", "autocomplete", "current-password"] };
    const send = f.chrome.debugger.sendCommand;
    f.chrome.debugger.sendCommand = async (target, method, params) => {
      const result = await send(target, method, params);
      return method === "DOM.getFlattenedDocument" ? { nodes: [password] } : result;
    };
    const read = await f.run(f.cdp([
      { method: "DOM.enable", params: {}, ...scope },
      { method: "DOM.getFlattenedDocument", params: { depth: -1, pierce: true }, ...scope },
    ]));
    assert.deepEqual(read.results[1].result.nodes[0].attributes, password.attributes);
    assert.equal(f.chrome.calls.some(call => call[0] === "cdp" && call[2].startsWith("Input.")), false);
  });
}

test("a stale loader cannot dispatch through a newly attached child session", async () => {
  const f = await framed();
  const { frame_id, session_id } = f.scope;
  await assert.rejects(f.run(f.cdp([{ method: "DOM.enable", params: {}, frame_id, loader_id: "old-loader", session_id }])), { reason: "frame_stale" });
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "DOM.enable").length, 0);
});

test("a stray navigation entry does not hide any tree document", async () => {
  const f = await framed(false);
  f.frames.push({ frameId: 99, parentFrameId: 0, documentId: "stray-doc", url: "about:blank" });
  const reply = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  assert.deepEqual(reply.frame_mappings.map(frame => [frame.frame_id, frame.unreadable_reason]), [[root.id, undefined], [child.id, undefined]]);
});

test("an unaccounted child session is ignored without hiding the tab", async () => {
  const f = await framed();
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    if (method === "Target.setAutoAttach" && !target.sessionId) f.chrome.debugger.onEvent.emit(target, "Target.attachedToTarget", { sessionId: "stray-session", targetInfo: { type: "iframe", targetId: "stray-target" } });
    if (method === "Page.getFrameTree" && target.sessionId === "stray-session") return { frameTree: { frame: { id: "stray-frame", loaderId: "stray-loader", url: "about:blank" } } };
    return send(target, method, params);
  };
  const reply = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  assert.deepEqual(reply.frame_mappings.map(frame => frame.frame_id), [root.id, child.id]);
  assert(reply.frame_mappings.every(frame => !frame.unreadable_reason));
});

test("root reads survive an unverified navigation mapping", async () => {
  const f = await framed(false);
  f.frames[0].url = "https://page.example/navigating";
  await f.run(f.cdp([{ method: "Accessibility.getFullAXTree", params: { frameId: root.id }, frame_id: root.id, loader_id: root.loaderId, session_id: "root" }]));
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Accessibility.getFullAXTree").length, 1);
});

test("clicking an omitted ambiguous child still refuses frame_ambiguous", async () => {
  const f = await framed(false);
  f.frames.push({ ...f.frames[1], frameId: 18, documentId: "duplicate" });
  const epoch = f.epochs.record(2).epoch;
  f.agent.baselines.set(2, { epoch, continuity: f.epochs.record(2).continuity });
  const { frame_id, loader_id, session_id } = f.scope;
  await assert.rejects(f.run({ ...f.cdp([{ method: "Input.dispatchMouseEvent", params: { type: "mousePressed", x: 10, y: 10, button: "left" }, frame_id, loader_id, session_id }]), interaction_epoch: epoch }), { reason: "frame_ambiguous" });
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Input.dispatchMouseEvent").length, 0);
});

test("a changing navigation tree is retried once and a stable retry stays readable", async () => {
  const f = await framed(false);
  let calls = 0;
  f.chrome.webNavigation.getAllFrames = async () => [{ ...f.frames[0] }, { ...f.frames[1], documentId: ++calls === 1 ? "before" : "after" }];
  const before = f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Page.getFrameTree").length;
  const reply = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Page.getFrameTree").length - before, 4);
  assert.equal(reply.frame_mappings[1].document_id, "after");
  assert.equal(reply.frame_mappings[1].unreadable_reason, undefined);
});

test("a child changing during both navigation reads is omitted after one retry", async () => {
  const f = await framed(false);
  let calls = 0;
  f.chrome.webNavigation.getAllFrames = async () => [{ ...f.frames[0] }, { ...f.frames[1], documentId: `moving-${++calls}` }];
  const before = f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Page.getFrameTree").length;
  const reply = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Page.getFrameTree").length - before, 4);
  assert.equal(reply.frame_mappings[0].unreadable_reason, undefined);
  assert.equal(reply.frame_mappings[1].unreadable_reason, "stale");
});

test("a CDP tree changing twice degrades only its moving child", async () => {
  const f = await framed(false);
  const send = f.chrome.debugger.sendCommand;
  let trees = 0;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    const reply = await send(target, method, params);
    if (method === "Page.getFrameTree") reply.frameTree.childFrames[0].frame.loaderId = `moving-${++trees}`;
    return reply;
  };
  const reply = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  assert.equal(trees, 4);
  assert.equal(reply.frame_mappings[0].unreadable_reason, undefined);
  assert.equal(reply.frame_mappings[1].unreadable_reason, "stale");
});

test("missing webNavigation coverage never blocks a top-document read", async () => {
  const f = await framed(false);
  f.chrome.webNavigation.getAllFrames = async () => { throw new Error("navigation unavailable"); };
  await f.run(f.cdp([{ method: "Accessibility.getFullAXTree", params: { frameId: root.id }, frame_id: root.id, loader_id: root.loaderId, session_id: "root" }]));
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Accessibility.getFullAXTree").length, 1);
});

test("an empty loader preserves top reads but never authorizes frame input", async () => {
  const f = await framed(false);
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    const reply = await send(target, method, params);
    if (method === "Page.getFrameTree") reply.frameTree.frame = { ...reply.frameTree.frame, loaderId: "" };
    return reply;
  };
  const scope = { frame_id: root.id, loader_id: "", session_id: "root" };
  await f.run(f.cdp([{ method: "Accessibility.getFullAXTree", params: { frameId: root.id }, ...scope }]));
  const epoch = f.epochs.record(2).epoch;
  f.agent.baselines.set(2, { epoch, continuity: f.epochs.record(2).continuity });
  await assert.rejects(f.run({ ...f.cdp([{ method: "Input.dispatchMouseEvent", params: { type: "mousePressed", x: 10, y: 10, button: "left" }, ...scope }]), interaction_epoch: epoch }), { reason: "frame_stale" });
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Accessibility.getFullAXTree").length, 1);
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Input.dispatchMouseEvent").length, 0);
});
