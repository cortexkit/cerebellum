import assert from "node:assert/strict";
import { test } from "node:test";
import { BrowserEvents } from "../events.mjs";
import { deferred } from "./fake-chrome.mjs";
import { setup, turn, read } from "./harness.mjs";

const inputCalls = f => f.chrome.calls.filter(call => call[0] === "cdp" && call[2].startsWith("Input."));

test("child commit after mouse release invalidates tab coverage without disabling the root receiver", async t => {
  const lines = [];
  t.mock.method(console, "info", line => lines.push(line));
  globalThis.__ckProbeReadDiagnostics = true;
  t.after(() => { delete globalThis.__ckProbeReadDiagnostics; });
  const f = await setup();
  const fresh = await f.fresh();
  const root = f.chrome.sentinels.get("2:0");
  const send = f.chrome.debugger.sendCommand;
  let committed = false;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    const result = await send(target, method, params);
    if (method === "Input.dispatchMouseEvent" && params.type === "mouseReleased" && !committed) {
      committed = true;
      await f.epochs.committed(2, 7);
    }
    return result;
  };
  await assert.rejects(f.run(f.input(fresh.interaction_epoch)), error => error.reason === "observer_unavailable" && error.detail.input_dispatched === true);
  assert.equal(inputCalls(f).length, 2);
  assert.equal(f.chrome.sentinels.get("2:0"), root);
  assert.equal(root.send("sample").enabled, true);
  assert.equal(f.epochs.record(2).coverageLost, true);
  assert.ok(lines.some(line => line.includes('"event":"observer_commit"') && line.includes('"frameId":7') && line.includes('"invalidated":true')));
  await assert.rejects(f.run(f.input(fresh.interaction_epoch)), { reason: "observer_unavailable" });
  assert.equal(inputCalls(f).length, 2);
  const recovered = await f.fresh();
  assert.equal(recovered.observer_available, true);
  await f.run(f.input(recovered.interaction_epoch));
  assert.equal(inputCalls(f).length, 4);
});

test("blank-tab install failure recovers on HTTP commit before fresh read and click", async () => {
  const f = await setup();
  new BrowserEvents(f.chrome, f.tabs, f.epochs, f.agent).listen();
  const inject = f.chrome.scripting.executeScript;
  f.chrome.scripting.executeScript = options => {
    if (f.chrome.tabData.get(options.target.tabId)?.url === "about:blank") throw new Error("Cannot access contents of the page. Extension manifest must request permission to access this host.");
    assert.equal(options.injectImmediately, true);
    return inject(options);
  };
  const opened = await f.run({ version: 2, action: "open_tab" });
  const record = await f.tabs.resolve(opened.tab);
  assert.equal(f.epochs.record(record.tabId).available, false);
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (target, method, params) => {
    if (method === "Page.navigate") {
      f.chrome.webNavigation.onBeforeNavigate.emit({ tabId: target.tabId, frameId: 0, url: params.url });
      Object.assign(f.chrome.tabData.get(target.tabId), { url: params.url, documentId: "committed-http" });
      f.chrome.observations.delete(`${target.tabId}:0`);
      f.chrome.sentinels.delete(`${target.tabId}:0`);
      f.chrome.webNavigation.onCommitted.emit({ tabId: target.tabId, frameId: 0, documentId: "committed-http" });
    }
    return send(target, method, params);
  };
  await f.run({ version: 2, action: "cdp", tab: opened.tab, commands: [{ method: "Page.navigate", params: { url: "http://127.0.0.1:12345/" } }] });
  await turn();
  const capture = () => f.run({ version: 2, action: "cdp", tab: opened.tab, commands: [read] });
  const first = await capture();
  const second = await capture();
  assert.equal(first.observer_available, true);
  assert.equal(second.observer_available, true);
  await f.epochs.committed(record.tabId, 0, "committed-http");
  await f.run({ ...f.input(second.interaction_epoch), tab: opened.tab, observer_continuity: second.observer_continuity });
  assert.equal(inputCalls(f).length, 2);
  assert.equal(f.chrome.tabData.get(record.tabId).active, false);
  assert.ok(f.chrome.calls.some(call => call[0] === "inject" && call[1].target.documentIds?.[0] === "committed-http"));
  const navigations = f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Page.navigate").length;
  f.chrome.tabData.get(record.tabId).url = "about:blank";
  await assert.rejects(f.run({ version: 2, action: "cdp", tab: opened.tab, commands: [{ method: "Page.navigate", params: { url: "http://127.0.0.1:12345/" } }] }), { reason: "observer_unavailable" });
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp" && call[2] === "Page.navigate").length, navigations);
});

test("fresh read repairs no_receiver once but metadata repair cannot rebase an old input baseline", async () => {
  const f = await setup();
  const initial = await f.fresh();
  const stalePlan = f.input(initial.interaction_epoch);
  const continuity = f.agent.baselines.get(2).continuity;
  f.chrome.observations.delete("2:0");
  f.chrome.sentinels.delete("2:0");
  const metadata = await f.run(f.cdp([{ method: "Page.getLayoutMetrics", params: {} }]));
  assert.equal(metadata.observer_available, true);
  assert.ok(metadata.observer_continuity > continuity);
  assert.equal(f.agent.baselines.get(2).continuity, continuity);
  await assert.rejects(f.run(f.input(initial.interaction_epoch)), { reason: "observer_unavailable" });
  assert.equal(inputCalls(f).length, 0);
  const fresh = await f.fresh();
  assert.equal(fresh.observer_available, true);
  await assert.rejects(f.run(stalePlan), { reason: "observer_unavailable" });
  assert.equal(inputCalls(f).length, 0);
  await f.run(f.input(fresh.interaction_epoch));
  assert.equal(inputCalls(f).length, 2);
});

test("unconfirmable observer retries are bounded and refuse honestly without input", async () => {
  const f = await setup();
  f.chrome.observations.delete("2:0");
  f.chrome.sentinels.delete("2:0");
  f.chrome.tabData.get(2).documentId = "unconfirmable-document";
  f.chrome.calls.length = 0;
  f.chrome.scripting.executeScript = async options => { f.chrome.calls.push(["inject", options]); return []; };
  for (let count = 0; count < 3; count++) {
    const capture = await f.fresh();
    assert.equal(capture.observer_available, false);
  }
  assert.equal(f.chrome.calls.filter(call => call[0] === "inject").length, 2);
  await assert.rejects(f.run(f.input(f.epochs.record(2).epoch)), { reason: "observer_unavailable" });
  assert.equal(inputCalls(f).length, 0);
});

test("probe logs real injection errors with URL and document-value redaction", async t => {
  const lines = [];
  t.mock.method(console, "info", line => lines.push(line));
  globalThis.__ckProbeReadDiagnostics = true;
  t.after(() => { delete globalThis.__ckProbeReadDiagnostics; });
  const f = await setup();
  const message = "Cannot access contents of the page. Extension manifest must request permission to access this host.";
  f.chrome.scripting.executeScript = async () => { throw new Error(message); };
  await f.epochs.install(2, 0, "new-document");
  const row = lines.filter(line => line.startsWith("Agent probe read: ")).map(line => JSON.parse(line.slice("Agent probe read: ".length))).find(row => row.event === "observer_install_failed");
  assert.equal(row.reason, "host_permission_missing");
  assert.equal(row.errorMessage, message);
  f.chrome.scripting.executeScript = async () => { throw "Injection failed on https://private.invalid/SECRET for 12345678-1234-1234-1234-123456789abc value 'SECRET'"; };
  await f.epochs.install(2, 0, "another-document");
  const other = lines.filter(line => line.startsWith("Agent probe read: ")).map(line => JSON.parse(line.slice("Agent probe read: ".length))).find(row => row.errorMessage?.startsWith("Injection failed"));
  assert.equal(other.reason, "other_error");
  assert.equal(other.errorMessage, "Injection failed on <url> for <document> value <quoted>");
  assert.ok(lines.every(line => !line.includes("SECRET") && !line.includes("private.invalid") && !line.includes("12345678-1234")));
});


test("commit during a sample cannot confirm the replaced document", async () => {
  const f = await setup();
  const old = await f.fresh();
  const send = f.chrome.tabs.sendMessage;
  let replace = true;
  f.chrome.tabs.sendMessage = async (...args) => {
    const observation = await send(...args);
    if (replace) {
      replace = false;
      f.chrome.tabData.get(2).documentId = "next-document";
      f.chrome.observations.delete("2:0");
      f.chrome.sentinels.delete("2:0");
      await f.epochs.committed(2, 0, "next-document");
    }
    return observation;
  };
  const metadata = await f.run(f.cdp([{ method: "Page.getLayoutMetrics", params: {} }]));
  assert.equal(metadata.observer_available, false);
  await assert.rejects(f.run(f.input(old.interaction_epoch)), { reason: "observer_unavailable" });
  assert.equal(inputCalls(f).length, 0);
  const fresh = await f.fresh();
  assert.equal(fresh.observer_available, true);
  await f.run(f.input(fresh.interaction_epoch));
  assert.equal(inputCalls(f).length, 2);
});


test("blank navigation exception rejects handed tabs and rechecks group and route after await", async () => {
  for (const race of ["handed", "opener", "withdraw", "owner", "activated", "person_navigation"]) {
    const f = await setup();
    new BrowserEvents(f.chrome, f.tabs, f.epochs, f.agent).listen();
    const opened = race === "handed" ? { tab: f.record.handle } : await f.run({ version: 2, action: "open_tab", ...(race === "opener" ? { opener_tab: f.record.handle } : {}) });
    const tab = await f.tabs.resolve(opened.tab);
    const send = f.chrome.debugger.sendCommand;
    f.chrome.debugger.sendCommand = async (target, method, params) => {
      const result = await send(target, method, params);
      if (method === "Page.getFrameTree") {
        if (race === "withdraw") f.chrome.tabData.get(tab.tabId).groupId = -1;
        if (race === "owner") f.agent.claims.set(tab.tabId, "99:1");
        if (race === "activated") f.chrome.tabs.onActivated.emit({ tabId: tab.tabId, windowId: 3 });
        if (race === "person_navigation") f.chrome.webNavigation.onBeforeNavigate.emit({ tabId: tab.tabId, frameId: 0, url: "https://personal.invalid/" });
      }
      return result;
    };
    const plan = { version: 2, action: "cdp", tab: opened.tab, commands: [{ method: "Page.navigate", params: { url: "http://127.0.0.1:12345/" } }] };
    await assert.rejects(f.run(plan), { reason: race === "withdraw" ? "tab_not_in_agent_group" : race === "owner" ? "tab_not_claimed" : "observer_unavailable" });
    if (race === "owner") await assert.rejects(f.run(plan, { channel: 99, epoch: 1 }), { reason: "observer_unavailable" });
    assert.equal(f.chrome.calls.some(call => call[0] === "cdp" && call[2] === "Page.navigate"), false);
    assert.equal(inputCalls(f).length, 0);
  }
});


test("late observer installation is disabled after the tab is withdrawn", async () => {
  const f = await setup();
  f.chrome.observations.delete("2:0");
  f.chrome.sentinels.delete("2:0");
  const gate = deferred();
  const inject = f.chrome.scripting.executeScript;
  f.chrome.scripting.executeScript = async options => { await gate.promise; return inject(options); };
  const pending = f.epochs.install(2, 0, "document-2", true);
  await turn();
  f.chrome.tabData.get(2).groupId = -1;
  f.tabs.withdraw(2);
  gate.resolve();
  assert.equal(await pending, false);
  assert.equal(f.chrome.sentinels.get("2:0").listeners, 0);
  assert.equal(f.epochs.records.has(2), false);
  assert.equal(inputCalls(f).length, 0);
});
