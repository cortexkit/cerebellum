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

test("duplicate sibling URL mapping refuses frame_ambiguous instead of picking a candidate", () => {
  const frames = [...navigation(), { ...navigation()[1], frameId: 18, documentId: "duplicate-doc" }];
  assert.throws(() => mapFrames({ frame: root, childFrames: [{ frame: child }, { frame: { ...child, id: "duplicate-child" } }] }, frames), { reason: "frame_ambiguous" });
});

test("documentId disambiguates only when Chrome exposes it on both sides", () => {
  const frames = [...navigation(), { ...navigation()[1], frameId: 18, documentId: "duplicate-doc" }];
  const duplicate = { ...child, id: "another-child", documentId: "duplicate-doc" };
  const mappings = mapFrames({ frame: root, childFrames: [{ frame: { ...child, documentId: "child-doc" } }, { frame: duplicate }] }, frames);
  assert.equal(mappings[1].web_navigation_frame_id, 17);
  assert.equal(mappings[2].web_navigation_frame_id, 18);
});

test("a navigated-away child refuses frame_stale even at the same URL", () => {
  const frames = navigation();
  frames[1].documentId = "replacement-document";
  assert.throws(() => mapFrames({ frame: root, childFrames: [{ frame: { ...child, documentId: "child-doc" } }] }, frames), { reason: "frame_stale" });
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
      f.chrome.debugger.onEvent.emit(target, "Target.attachedToTarget", { sessionId: "ephemeral-child-session", targetInfo: { type: "iframe", targetId: "stable-target-not-frame-id" } });
    }
    await base(target, method, params);
    if (method === "Page.getFrameTree") return { frameTree: target.sessionId ? { frame: crossChild } : { frame: root, childFrames: [{ frame: crossChild }] } };
    return { nodes: [] };
  };
  const discover = await f.run(f.cdp([{ method: "Page.getFrameTree", params: {} }]));
  return { ...f, frames, scope: discover.frame_mappings[1] };
}

test("OOPIF commands resolve fresh flattened sessions and detach with their tab", async () => {
  const f = await framed();
  const { frame_id, loader_id, session_id } = f.scope;
  assert.equal(session_id, "stable-target-not-frame-id");
  await f.run(f.cdp([{ method: "Accessibility.getFullAXTree", params: { frameId: frame_id }, frame_id, loader_id, session_id }]));
  const dispatched = f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Accessibility.getFullAXTree");
  assert.deepEqual(dispatched.map(call => call[1]), [{ tabId: 2, sessionId: "ephemeral-child-session" }]);
  assert.equal(f.chrome.calls.filter(call => call[0] === "attach").length, f.chrome.calls.filter(call => call[0] === "detach").length);
  assert.equal(f.chrome.debugger.onEvent.listeners.size, 0);
});

test("same-origin child commands stay on the root target", async () => {
  const f = await framed(false);
  const { frame_id, loader_id, session_id } = f.scope;
  await f.run(f.cdp([{ method: "DOM.enable", params: {}, frame_id, loader_id, session_id }]));
  assert.deepEqual(f.chrome.calls.find(call => call[0] === "cdp" && call[2] === "DOM.enable")[1], { tabId: 2 });
});

test("a stale loader cannot dispatch through a newly attached child session", async () => {
  const f = await framed();
  const { frame_id, session_id } = f.scope;
  await assert.rejects(f.run(f.cdp([{ method: "DOM.enable", params: {}, frame_id, loader_id: "old-loader", session_id }])), { reason: "frame_stale" });
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "DOM.enable").length, 0);
});
