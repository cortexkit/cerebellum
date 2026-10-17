import test from "node:test";
import assert from "node:assert/strict";
import { FrameGeometry, transformPoint } from "../frame-geometry.mjs";
import { classifyCommand } from "../commands.mjs";

const geometry = { quad: [100, 50, 500, 50, 500, 250, 100, 250], width: 200, height: 100 };
test("frame geometry converts local input to root hit coordinates and back", () => {
  const global = transformPoint({ x: 20, y: 30 }, geometry);
  assert.deepEqual(global, { x: 140, y: 110 });
  assert.deepEqual(transformPoint(global, geometry, true), { x: 20, y: 30 });
  assert.throws(() => transformPoint({ x: 99, y: 60 }, geometry, true), { reason: "point_outside_frame" });
});

test("frame geometry refuses perspective and degenerate quads rather than guessing", () => {
  for (const quad of [[100, 50, 500, 50, 490, 250, 100, 250], Array(8).fill(0)]) {
    assert.throws(() => transformPoint({ x: 20, y: 30 }, { ...geometry, quad }), { reason: "frame_geometry_unavailable" });
  }
});

test("frame geometry does not widen the caller runtime or target vocabulary", () => {
  for (const method of ["DOM.getBoxModel", "Page.createIsolatedWorld", "Target.setAutoAttach", "Runtime.evaluate"]) {
    assert.throws(() => classifyCommand({ method, params: {} }), { reason: "unsupported_cdp_method" });
  }
});

function fixture(overlay = false, scroll = 0) {
  const root = { frame_id: "root", session_id: "root" };
  const child = { frame_id: "child", parent_id: "root", session_id: "target-child" };
  const calls = [];
  const frames = { state: { tabId: 2 }, sessions: new Map([["target-child", { tabId: 2, sessionId: "fresh-session" }]]),
    async send(target, method, params) {
      calls.push({ target, method, params });
      if (method === "Page.getLayoutMetrics") return { cssVisualViewport: { offsetX: 0, offsetY: 0, pageX: 0, pageY: target.sessionId ? scroll * 2 : scroll, clientWidth: 800, clientHeight: 600 } };
      if (method === "DOM.getFrameOwner") return { backendNodeId: 6 };
      if (method === "DOM.getBoxModel") return { model: { content: geometry.quad } };
      if (method === "Page.createIsolatedWorld") return { executionContextId: 12 };
      if (method === "DOM.resolveNode") return { object: { objectId: "same-attachment-object" } };
      if (method === "Runtime.callFunctionOn") return { result: { value: { width: 200, height: 100 } } };
      if (method === "DOM.getNodeForLocation") return target.sessionId ? { frameId: "child", backendNodeId: 9 } : { frameId: "root", backendNodeId: overlay ? 77 : 6 };
      throw new Error(`unexpected geometry method: ${method}`);
    } };
  return { helper: new FrameGeometry(frames, [root, child]), child, calls };
}

test("OOPIF ref hit tests root occlusion before descending into the child renderer", async () => {
  const f = fixture();
  const hit = await f.helper.hit({ x: 20, y: 30 }, f.child, {});
  assert.equal(hit.frameId, "child");
  assert.deepEqual(hit.frame_point, { x: 20, y: 30 });
  const hits = f.calls.filter(call => call.method === "DOM.getNodeForLocation");
  assert.deepEqual(hits.map(call => [call.target.sessionId ?? "root", call.params.x, call.params.y]), [["root", 140, 110], ["fresh-session", 20, 30]]);
});

test("an overlay in the root renderer cannot be bypassed by a child ref", async () => {
  const f = fixture(true);
  const hit = await f.helper.hit({ x: 20, y: 30 }, f.child, {});
  assert.equal(hit.backendNodeId, 77);
  assert.equal(hit.frameId, "root");
  assert.equal(f.calls.filter(call => call.method === "DOM.getNodeForLocation").length, 1);
});

test("screenshot hit tests return child-local coordinates for subsequent input", async () => {
  const f = fixture();
  const hit = await f.helper.hit({ x: 140, y: 110 }, null, {});
  assert.equal(hit.frameId, "child");
  assert.deepEqual(hit.frame_point, { x: 20, y: 30 });
});

test("root and child hit tests use their own document scroll offsets", async () => {
  const f = fixture(false, 30);
  const hit = await f.helper.hit({ x: 20, y: 30 }, f.child, {});
  assert.deepEqual(hit.frame_point, { x: 20, y: 30 });
  const hits = f.calls.filter(call => call.method === "DOM.getNodeForLocation");
  assert.deepEqual(hits.map(call => [call.params.x, call.params.y]), [[140, 140], [20, 90]]);
});

test("point and ref hit tests preserve an omitted child's ambiguity refusal", async () => {
  for (const scoped of [false, true]) {
    const f = fixture();
    f.child.unreadable_reason = "ambiguous";
    await assert.rejects(f.helper.hit(scoped ? { x: 20, y: 30 } : { x: 140, y: 110 }, scoped ? f.child : null, {}), { reason: "frame_ambiguous" });
    assert(!f.calls.some(call => call.target.sessionId));
  }
});
