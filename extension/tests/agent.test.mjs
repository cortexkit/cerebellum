import assert from "node:assert/strict";
import { test } from "node:test";
import { deferred } from "./fake-chrome.mjs";

const route = { channel: 2, epoch: 1 };
const read = { method: "Page.getFrameTree", params: {} };
const press = { method: "Input.dispatchMouseEvent", params: { type: "mousePressed", x: 10, y: 20, button: "left" } };
const release = { method: "Input.dispatchMouseEvent", params: { type: "mouseReleased", x: 10, y: 20, button: "left" } };
import { setup } from "./harness.mjs";

const inputs = chrome => chrome.calls.filter(call => call[0] === "cdp" && call[2].startsWith("Input."));

test("group membership is rechecked before attachment", async () => {
  const f = await setup();
  f.chrome.calls.length = 0;
  f.chrome.tabData.get(2).groupId = -1;
  await assert.rejects(f.run(f.cdp([read])), { reason: "tab_not_in_agent_group" });
  assert.equal(f.chrome.calls.some(call => call[0] === "attach"), false);
  assert.equal(f.chrome.calls.some(call => call[0] === "cdp"), false);
});

test("outside tabs are invisible and raw tab ids cannot be driven", async () => {
  const f = await setup();
  const status = await f.run({ version: 1, action: "status" });
  assert.deepEqual(status, { tabs: [{ tab: f.record.handle, claimed: true, handed: true, interaction_epoch: 0 }], connection_epoch: 50 });
  await assert.rejects(f.run({ ...f.cdp([read]), tab: "1" }), { reason: "unknown_tab" });
  assert.equal(f.chrome.calls.some(call => call[0] === "get" && call[1] === 1), false);
});

test("claims and status remain route bound", async () => {
  const f = await setup();
  const other = { channel: 9, epoch: 4 };
  assert.deepEqual((await f.run({ version: 1, action: "status" }, other)).tabs, []);
  await assert.rejects(f.run({ version: 1, action: "claim_tab", tab: f.record.handle }, other), { reason: "tab_claimed_by_other_route" });
  await assert.rejects(f.run(f.cdp([read]), other), { reason: "tab_not_claimed" });
});

test("group withdrawal before each input and before content returns dispatches no later input", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    const result = await send(...args);
    if (args[1] === press.method) f.chrome.tabData.get(2).groupId = -1;
    return result;
  };
  await assert.rejects(f.run(f.input(epoch)));
  assert.equal(inputs(f.chrome).length, 1);
  assert.ok(f.chrome.calls.some(call => call[0] === "detach"));
  assert.equal(f.agent.baselines.has(2), false);
});

test("withdrawal during a read returns no page content", async () => {
  const f = await setup();
  f.chrome.debugger.sendCommand = async () => { f.chrome.tabData.get(2).groupId = -1; return { secret: "not returned" }; };
  await assert.rejects(f.fresh());
  assert.ok(f.chrome.calls.some(call => call[0] === "detach"));
});

test("detached human input refuses until a fresh read and refused input does not rebase", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  f.chrome.observations.get("2:0").sequence += 1;
  await assert.rejects(f.run(f.input(epoch)), { reason: "interaction_epoch_changed" });
  assert.equal(inputs(f.chrome).length, 0);
  await assert.rejects(f.run(f.input(epoch)), { reason: "interaction_epoch_changed" });
  const fresh = await f.fresh();
  await f.run(f.input(fresh.interaction_epoch));
  assert.equal(inputs(f.chrome).length, 2);
});

test("human input while paused before the first input dispatches nothing", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const arm = f.epochs.arm.bind(f.epochs);
  f.epochs.arm = async (...args) => { await arm(...args); f.chrome.observations.get("2:0").sequence += 1; };
  await assert.rejects(f.run(f.input(epoch)), { reason: "interaction_epoch_changed" });
  assert.equal(inputs(f.chrome).length, 0);
  assert.equal(f.chrome.calls.filter(call => call[0] === "sentinel" && call[2].operation === "disarm").length, 1);
});

test("activation between press and release stops the release and reports prior input", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => { const result = await send(...args); f.epochs.bump(2); return result; };
  const state = await f.agent.prepare(route, f.input(epoch), 50);
  await assert.rejects(f.agent.execute(state), { reason: "interaction_epoch_changed" });
  assert.equal(state.input, true);
  await f.agent.finish(state);
  assert.equal(inputs(f.chrome).length, 1);
});

test("human input between two typing steps stops further typing", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => { const result = await send(...args); f.chrome.observations.get("2:0").sequence += 1; return result; };
  const type = { method: "Input.insertText", params: { text: "x" } };
  await assert.rejects(f.run({ ...f.cdp([type, type]), interaction_epoch: epoch }), { reason: "interaction_epoch_changed" });
  assert.equal(inputs(f.chrome).length, 1);
});

test("restart clears baselines even when interaction epoch happens to match", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  await f.agent.disconnect();
  f.agent.connect(51);
  const tab = await f.tabs.join(2, "handed");
  await f.run({ version: 1, action: "claim_tab", tab: tab.handle });
  await assert.rejects(f.run({ ...f.input(epoch), tab: tab.handle }), { reason: "fresh_read_required" });
  assert.equal(inputs(f.chrome).length, 0);
});

test("missing frame coverage cannot establish an input baseline", async () => {
  const f = await setup();
  f.chrome.webNavigation.getAllFrames = async () => [{ frameId: 0 }, { frameId: 5 }];
  await f.fresh();
  assert.equal(f.agent.baselines.has(2), false);
  await assert.rejects(f.run(f.input(f.epochs.record(2).epoch)), { reason: "fresh_read_required" });
});

test("all focus target and arbitrary runtime escape hatches refuse before attach", async () => {
  const f = await setup();
  f.chrome.calls.length = 0;
  for (const method of ["Browser.close", "Browser.setDownloadBehavior", "Target.createTarget", "Target.attachToTarget", "Target.activateTarget", "Page.bringToFront", "Runtime.evaluate", "Runtime.callFunctionOn"]) {
    await assert.rejects(f.run(f.cdp([{ method, params: {} }])), { reason: "unsupported_cdp_method" });
  }
  assert.equal(f.chrome.calls.some(call => call[0] === "attach"), false);
});

test("CDP errors stop at the first error and the debugger always detaches", async () => {
  const f = await setup();
  f.chrome.debugger.sendCommand = async () => { throw Object.assign(new Error("private Chrome error"), { code: -32123 }); };
  const result = await f.run(f.cdp([read, read]));
  assert.deepEqual(result.results, [{ error: { code: -32123, message: "Chrome debugger command failed" } }]);
  assert.ok(f.chrome.calls.some(call => call[0] === "detach"));
});

test("Chrome's CDP error code and fixed message are relayed without its data", async () => {
  const f = await setup();
  // chrome.debugger.sendCommand rejects with the CDP error object serialized as the message.
  const cdp = JSON.stringify({ code: -32000, message: "DOM agent hasn't been enabled", data: "extra detail" });
  f.chrome.debugger.sendCommand = async () => { throw new Error(cdp); };
  const result = await f.run(f.cdp([read, read]));
  assert.deepEqual(result.results, [{ error: { code: -32000, message: "DOM agent hasn't been enabled" } }]);
  for (const message of ["x".repeat(201), "line one\nline two"]) {
    f.chrome.debugger.sendCommand = async () => { throw new Error(JSON.stringify({ code: -32000, message })); };
    const replaced = await f.run(f.cdp([read]));
    assert.deepEqual(replaced.results, [{ error: { code: -32000, message: "Chrome debugger command failed" } }]);
  }
});

test("result references resolve within one attachment without arbitrary JavaScript", async () => {
  const f = await setup();
  let calls = 0;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    assert.equal(method, "DOM.resolveNode");
    if (calls++ === 0) return { node: { backendNodeId: 42 } };
    assert.equal(params.backendNodeId, 42);
    return { object: { objectId: "opaque-object" } };
  };
  const result = await f.run(f.cdp([
    { method: "DOM.resolveNode", params: { backendNodeId: 1 } },
    { method: "DOM.resolveNode", params: { backendNodeId: { $result: 0, path: ["node", "backendNodeId"] } } },
  ]));
  assert.equal(result.results.length, 2);
});

test("a cancelled in-flight command has no follow-up input", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const pause = deferred();
  f.chrome.debugger.sendCommand = () => pause.promise;
  const state = await f.agent.prepare(route, f.input(epoch), 50);
  const running = f.agent.execute(state);
  await new Promise(resolve => setImmediate(resolve));
  await f.agent.cancel(state);
  pause.resolve({});
  await assert.rejects(running, { reason: "cancelled" });
  await f.agent.finish(state);
  assert.equal(state.input, true);
  assert.equal(f.chrome.calls.filter(call => call[0] === "detach").length, 2);
});

test("close leaves every tab alive and returns handed tabs", async () => {
  const f = await setup();
  const opened = await f.run({ version: 1, action: "open_tab" });
  await f.run({ version: 1, action: "close" });
  assert.equal(f.chrome.tabData.has(1), true);
  assert.equal(f.chrome.tabData.has(2), true);
  assert.equal(f.chrome.tabData.get(2).groupId, -1);
  assert.equal([...f.chrome.tabData.values()].find(tab => tab.id >= 10).groupId, 7);
  await assert.rejects(f.tabs.resolve(opened.tab), { reason: "unknown_tab" });
});


test("human input during a snapshot refuses rather than refreshing its baseline", async () => {
  const f = await setup();
  const original = await f.fresh();
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    const result = await send(...args);
    f.chrome.observations.get("2:0").sequence += 1;
    return result;
  };
  await assert.rejects(f.fresh(), { reason: "interaction_epoch_changed" });
  assert.equal(f.agent.baselines.get(2).epoch, original.interaction_epoch);
});

test("agent document changes lose continuity without pretending to be human input", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  f.chrome.observations.get("2:0").documentId = "new-document";
  await assert.rejects(f.run(f.input(epoch)), { reason: "interaction_continuity_lost" });
  assert.equal(f.epochs.record(2).epoch, epoch);
  assert.equal(inputs(f.chrome).length, 0);
  await f.fresh();
  await f.run(f.input(epoch));
  assert.equal(inputs(f.chrome).length, 2);
});

test("cancelled background creation never leaks a new route claim", async () => {
  const f = await setup();
  const pause = deferred();
  const create = f.chrome.tabs.create;
  f.chrome.tabs.create = async options => { await pause.promise; return create(options); };
  const state = await f.agent.prepare(route, { version: 1, action: "open_tab" }, 50);
  const running = f.agent.execute(state);
  await new Promise(resolve => setImmediate(resolve));
  await f.agent.cancel(state);
  pause.resolve();
  await assert.rejects(running, { reason: "cancelled" });
  await f.agent.finish(state);
  assert.deepEqual([...f.agent.claims.keys()], [2]);
});
