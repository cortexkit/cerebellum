import assert from "node:assert/strict";
import { test } from "node:test";
import { deferred } from "./fake-chrome.mjs";

const route = { channel: 2, epoch: 1 };
const read = { method: "Page.getLayoutMetrics", params: {} };
const press = { method: "Input.dispatchMouseEvent", params: { type: "mousePressed", x: 10, y: 20, button: "left" } };
const release = { method: "Input.dispatchMouseEvent", params: { type: "mouseReleased", x: 10, y: 20, button: "left" } };
import { setup } from "./harness.mjs";
import { BrowserEvents } from "../events.mjs";

const inputs = chrome => chrome.calls.filter(call => call[0] === "cdp" && call[2].startsWith("Input."));

test("CDP press and release inside the action window leave the interaction epoch unchanged", async () => {
  const f = await setup();
  new BrowserEvents(f.chrome, f.tabs, f.epochs, f.agent).listen();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    const result = await send(...args);
    if (args[1] === "Emulation.setFocusEmulationEnabled") {
      f.chrome.tabs.onActivated.emit({ tabId: 2, windowId: 3 });
      f.chrome.windows.onFocusChanged.emit(3);
      f.chrome.input(2, { type: "focus" });
    }
    if (args[1] === "Input.dispatchMouseEvent") {
      const types = args[2].type === "mousePressed" ? ["pointerdown", "mousedown"] : ["pointerup", "mouseup", "click"];
      for (const type of types) f.chrome.input(2, { type, clientX: 10, clientY: 20, button: 0 });
    }
    return result;
  };
  const plan = f.input(epoch);
  plan.commands.unshift({ method: "Emulation.setFocusEmulationEnabled", params: { enabled: true } });
  const result = await f.run(plan);
  assert.equal(result.interaction_epoch, epoch);
  assert.equal(await f.epochs.sample(2), epoch);
  assert.deepEqual(inputs(f.chrome).map(call => call[3]), [press.params, release.params]);
});

test("clicks before attach and at detach count even when their observations arrive later", async () => {
  const f = await setup();
  let now = 5;
  f.chrome.now = () => now;
  const epoch = (await f.fresh()).interaction_epoch;
  now = 10;
  f.chrome.input(2, { type: "click" });
  now = 20;
  const state = await f.agent.prepare(route, f.cdp([read]), 50);
  f.chrome.input(2, { type: "click" });
  now = 25;
  f.chrome.input(2, { type: "click" });
  now = 30;
  await f.agent.finish(state);
  // No grace period: a click at the closed window's endpoint belongs to the
  // person. Sampling now also sees the unsampled pre-attach and attached clicks.
  f.chrome.input(2, { type: "click" });
  assert.equal(await f.epochs.sample(2), epoch + 2);
  now = 31;
  f.chrome.input(2, { type: "keydown" });
  f.chrome.input(2, { type: "wheel" });
  assert.equal(await f.epochs.sample(2), epoch + 4);
});

test("membership refusal before a press dispatches no input or cleanup release", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const state = await f.agent.prepare(route, f.input(epoch), 50);
  f.chrome.tabData.get(2).groupId = -1;
  await assert.rejects(f.agent.execute(state), { reason: "tab_not_in_agent_group" });
  await f.agent.finish(state);
  assert.equal(inputs(f.chrome).length, 0);
  assert.equal(state.input, false);
});

test("a failed cleanup release still detaches and reports unconfirmed input", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    if (args[2].type === "mouseReleased") throw new Error("release failed");
    const result = await send(...args);
    if (args[2].type === "mousePressed") f.epochs.bump(2);
    return result;
  };
  await assert.rejects(f.run(f.input(epoch)), { reason: "input_release_unconfirmed", detail: { remedy: "read again", input_dispatched: true } });
  assert.equal(f.agent.active.size, 0);
  assert.equal(f.chrome.calls.filter(call => call[0] === "detach").length, 2);
});

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
  const status = await f.run({ version: 2, action: "status" });
  assert.deepEqual(status, { tabs: [{ tab: f.record.handle, claimed: true, handed: true, interaction_epoch: 0 }], connection_epoch: 50 });
  await assert.rejects(f.run({ ...f.cdp([read]), tab: "1" }), { reason: "unknown_tab" });
  assert.equal(f.chrome.calls.some(call => call[0] === "get" && call[1] === 1), false);
});

test("claims and status remain route bound", async () => {
  const f = await setup();
  const other = { channel: 9, epoch: 4 };
  assert.deepEqual((await f.run({ version: 2, action: "status" }, other)).tabs, []);
  await assert.rejects(f.run({ version: 2, action: "claim_tab", tab: f.record.handle }, other), { reason: "tab_claimed_by_other_route" });
  await assert.rejects(f.run(f.cdp([read]), other), { reason: "tab_not_claimed" });
});

test("group withdrawal after a press sends only its matching cleanup release", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    const result = await send(...args);
    if (args[1] === press.method) f.chrome.tabData.get(2).groupId = -1;
    return result;
  };
  await assert.rejects(f.run(f.input(epoch)));
  assert.deepEqual(inputs(f.chrome).map(call => call[3]), [press.params, release.params]);
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
  f.chrome.input(2, { type: "click" });
  await assert.rejects(f.run(f.input(epoch)), { reason: "interaction_epoch_changed" });
  assert.equal(inputs(f.chrome).length, 0);
  await assert.rejects(f.run(f.input(epoch)), { reason: "interaction_epoch_changed" });
  const fresh = await f.fresh();
  await f.run(f.input(fresh.interaction_epoch));
  assert.equal(inputs(f.chrome).length, 2);
});

test("a person's click before attach refuses before the press and sends no input", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const attach = f.chrome.debugger.attach;
  f.chrome.debugger.attach = async (...args) => { f.chrome.input(2, { type: "click" }); await attach(...args); };
  await assert.rejects(f.run(f.input(epoch)), { reason: "interaction_epoch_changed" });
  assert.equal(inputs(f.chrome).length, 0);
});

test("epoch refusal after a press sends only its matching cleanup release", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => { const result = await send(...args); if (args[2].type === "mousePressed") f.epochs.bump(2); return result; };
  const plan = f.input(epoch);
  plan.commands.push({ method: "Input.insertText", params: { text: "must not run" } });
  const state = await f.agent.prepare(route, plan, 50);
  await assert.rejects(f.agent.execute(state), { reason: "interaction_epoch_changed" });
  assert.equal(state.input, true);
  await f.agent.finish(state);
  assert.deepEqual(inputs(f.chrome).map(call => call[3]), [press.params, release.params]);
});

test("trusted input within the attachment does not interrupt a typing plan", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => { const result = await send(...args); f.chrome.input(2, { type: "input" }); return result; };
  const type = { method: "Input.insertText", params: { text: "x" } };
  const result = await f.run({ ...f.cdp([type, type]), interaction_epoch: epoch });
  assert.equal(result.interaction_epoch, epoch);
  assert.equal(inputs(f.chrome).length, 2);
});

test("restart clears baselines even when interaction epoch happens to match", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  await f.agent.disconnect();
  f.agent.connect(51);
  const tab = await f.tabs.join(2, "handed");
  await f.run({ version: 2, action: "claim_tab", tab: tab.handle });
  await assert.rejects(f.run({ ...f.input(epoch), tab: tab.handle }), { reason: "fresh_read_required" });
  assert.equal(inputs(f.chrome).length, 0);
});

test("disconnect keeps handed tabs grouped and unclaimed for reconnect", async () => {
  const f = await setup();
  const handle = f.record.handle;
  const state = await f.agent.prepare(route, f.cdp([read]), 50);
  assert.equal(state.attached, true);
  const detaches = () => f.chrome.calls.filter(call => call[0] === "detach").length;
  const before = detaches();
  await f.agent.disconnect();
  assert.equal(state.attached, false);
  assert.ok(detaches() > before);
  assert.equal(f.agent.claims.size, 0);
  assert.equal(f.tabs.tabs.get(2)?.handle, handle);
  assert.equal(f.tabs.tabs.get(2)?.kind, "handed");
  assert.equal(f.chrome.tabData.get(2).groupId, f.tabs.group.id);
  f.agent.connect(51);
  const status = await f.run({ version: 2, action: "status" });
  assert.deepEqual(status.tabs, [{ tab: handle, claimed: false, handed: true, interaction_epoch: 0 }]);
  const claimed = await f.run({ version: 2, action: "claim_tab", tab: handle });
  assert.equal(claimed.tab, handle);
  assert.equal((await f.run({ version: 2, action: "status" })).tabs[0].claimed, true);
  await f.tabs.toggle(2);
  assert.equal(f.chrome.tabData.get(2).groupId, -1);
  assert.equal(f.tabs.tabs.has(2), false);
  assert.equal(f.agent.claims.has(2), false);
});

test("missing frame coverage cannot establish an input baseline", async () => {
  const f = await setup();
  f.chrome.webNavigation.getAllFrames = async () => [{ frameId: 0 }, { frameId: 5 }];
  const inject = f.chrome.scripting.executeScript;
  f.chrome.scripting.executeScript = options => options.target.frameIds?.includes(5) ? Promise.reject(new Error("The frame was removed.")) : inject(options);
  await f.fresh();
  assert.equal(f.agent.baselines.has(2), false);
  await assert.rejects(f.run(f.input(f.epochs.record(2).epoch)), { reason: "observer_unavailable" });
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

test("a cancelled in-flight press has only a matching cleanup release", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const pause = deferred();
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = (...args) => args[2].type === "mousePressed" ? pause.promise : send(...args);
  const state = await f.agent.prepare(route, f.input(epoch), 50);
  const running = f.agent.execute(state);
  await new Promise(resolve => setImmediate(resolve));
  await f.agent.cancel(state);
  pause.resolve({});
  await assert.rejects(running, { reason: "cancelled" });
  await f.agent.finish(state);
  assert.equal(state.input, true);
  assert.deepEqual(inputs(f.chrome).map(call => call[3]), [release.params]);
  assert.equal(f.chrome.calls.filter(call => call[0] === "detach").length, 2);
});

test("close leaves every tab alive and returns handed tabs", async () => {
  const f = await setup();
  const opened = await f.run({ version: 2, action: "open_tab" });
  await f.run({ version: 2, action: "close" });
  assert.equal(f.chrome.tabData.has(1), true);
  assert.equal(f.chrome.tabData.has(2), true);
  assert.equal(f.chrome.tabData.get(2).groupId, -1);
  assert.equal([...f.chrome.tabData.values()].find(tab => tab.id >= 10).groupId, 7);
  await assert.rejects(f.tabs.resolve(opened.tab), { reason: "unknown_tab" });
});


test("trusted input during an attached snapshot does not invalidate its baseline", async () => {
  const f = await setup();
  const original = await f.fresh();
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    const result = await send(...args);
    f.chrome.input(2, { type: "click" });
    return result;
  };
  assert.equal((await f.fresh()).interaction_epoch, original.interaction_epoch);
  assert.equal(f.agent.baselines.get(2).epoch, original.interaction_epoch);
});

test("agent document changes lose continuity without pretending to be human input", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  f.chrome.observations.delete("2:0");
  f.chrome.sentinels.delete("2:0");
  f.chrome.tabData.get(2).documentId = "new-document";
  await f.epochs.committed(2, 0, "new-document");
  await assert.rejects(f.run(f.input(epoch)), { reason: "observer_unavailable" });
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
  const state = await f.agent.prepare(route, { version: 2, action: "open_tab" }, 50);
  const running = f.agent.execute(state);
  await new Promise(resolve => setImmediate(resolve));
  await f.agent.cancel(state);
  pause.resolve();
  await assert.rejects(running, { reason: "cancelled" });
  await f.agent.finish(state);
  assert.deepEqual([...f.agent.claims.keys()], [2]);
});
