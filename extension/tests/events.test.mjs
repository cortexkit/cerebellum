import assert from "node:assert/strict";
import { test } from "node:test";
import { BrowserEvents } from "../events.mjs";
import { setup, turn } from "./harness.mjs";
import { start } from "../service-worker.mjs";
import { fakeChrome } from "./fake-chrome.mjs";

function listen(f) {
  const events = new BrowserEvents(f.chrome, f.tabs, f.epochs, f.agent);
  events.remember({ id: 1, windowId: 3, active: true });
  events.listen();
  return events;
}

test("explicit popup open creates a background grouped tab without changing focus", async () => {
  const f = await setup();
  const events = listen(f);
  const create = f.chrome.tabs.create;
  f.chrome.tabs.create = async options => {
    const tab = await create(options);
    tab.openerTabId = options.openerTabId;
    f.chrome.tabs.onCreated.emit(tab);
    return tab;
  };
  const reply = await f.run({ version: 2, action: "open_tab", url: "http://localhost/popup", opener_tab: f.record.handle });
  const tab = await f.tabs.resolve(reply.tab);
  await turn();
  const createCall = f.chrome.calls.find(call => call[0] === "create");
  assert.deepEqual(createCall[1], { url: "http://localhost/popup", active: false, openerTabId: 2, windowId: 3 });
  assert.equal(f.chrome.tabData.get(tab.tabId).groupId, f.tabs.group.id);
  assert.equal(f.chrome.calls.some(call => call[0] === "restoreTab" || call[0] === "restoreWindow"), false);
  assert.equal(events.focusedWindow, 3);
  assert.equal(events.popupSources.size, 0);
});

test("script popup joins opener group and restores remembered ids with a disclosed activation", async () => {
  const f = await setup();
  const events = listen(f);
  f.chrome.allowPopupRecovery = true;
  f.chrome.tabData.set(30, { id: 30, groupId: -1, windowId: 99, active: true });
  f.chrome.tabs.onCreated.emit({ id: 30, openerTabId: 2, windowId: 99, active: true });
  f.chrome.tabs.onActivated.emit({ tabId: 30, windowId: 99 });
  f.chrome.webNavigation.onCreatedNavigationTarget.emit({ tabId: 30, sourceTabId: 2 });
  await turn();
  await Promise.all(events.popupTasks.values());
  assert.equal(f.chrome.tabData.get(30).groupId, 7);
  assert.equal(f.agent.claims.get(30), f.agent.claims.get(2));
  assert.deepEqual(f.chrome.calls.find(call => call[0] === "restoreTab"), ["restoreTab", 1, { active: true }]);
  assert.deepEqual(f.chrome.calls.find(call => call[0] === "restoreWindow"), ["restoreWindow", 3, { focused: true }]);
  assert.equal((await f.fresh()).popup_activated_briefly, true);
  assert.equal((await f.fresh()).popup_activated_briefly, undefined);
  assert.equal(f.chrome.calls.some(call => call[0] === "get" && call[1] === 1), false);
});

test("popup activation before creation retains the preceding focus ids", async () => {
  const f = await setup();
  const events = listen(f);
  f.chrome.allowPopupRecovery = true;
  f.chrome.tabData.set(31, { id: 31, groupId: -1, windowId: 100, active: true });
  f.chrome.tabs.onActivated.emit({ tabId: 31, windowId: 100 });
  f.chrome.windows.onFocusChanged.emit(100);
  f.chrome.tabs.onCreated.emit({ id: 31, openerTabId: 2, windowId: 100, active: true });
  await turn();
  await Promise.all(events.popupTasks.values());
  assert.deepEqual(f.chrome.calls.find(call => call[0] === "restoreTab"), ["restoreTab", 1, { active: true }]);
  assert.deepEqual(f.chrome.calls.find(call => call[0] === "restoreWindow"), ["restoreWindow", 3, { focused: true }]);
});

test("popup from an outside opener is not listed read grouped or driven", async () => {
  const f = await setup();
  listen(f);
  f.chrome.calls.length = 0;
  f.chrome.tabs.onCreated.emit({ id: 40, openerTabId: 1, active: true, windowId: 3 });
  f.chrome.webNavigation.onCreatedNavigationTarget.emit({ tabId: 40, sourceTabId: 1 });
  await turn();
  assert.equal(f.chrome.calls.length, 0);
  assert.equal(f.tabs.tabs.has(40), false);
});

test("focus never counts as interaction but unattributed navigation still invalidates", async () => {
  const f = await setup();
  listen(f);
  f.chrome.tabs.onActivated.emit({ tabId: 2, windowId: 3 });
  f.chrome.windows.onFocusChanged.emit(3);
  assert.equal(f.epochs.record(2).epoch, 0);
  f.chrome.webNavigation.onBeforeNavigate.emit({ tabId: 2, frameId: 0 });
  assert.equal(f.epochs.record(2).epoch, 1);
  await f.fresh();
  const epoch = f.epochs.record(2).epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    if (args[1] === "Page.navigate") {
      f.chrome.webNavigation.onBeforeNavigate.emit({ tabId: 2, frameId: 0 });
      f.chrome.webNavigation.onCommitted.emit({ tabId: 2, frameId: 0 });
    }
    return send(...args);
  };
  await f.run(f.cdp([{ method: "Page.navigate", params: { url: "http://localhost/" } }]));
  assert.equal(f.epochs.record(2).epoch, epoch);
});

test("manual group removal cancels pending actions and removes sentinel coverage", async () => {
  const f = await setup();
  listen(f);
  f.chrome.tabData.get(2).groupId = -1;
  f.chrome.tabs.onUpdated.emit(2, { groupId: -1 });
  await turn();
  assert.equal(f.tabs.tabs.has(2), false);
  assert.equal(f.agent.claims.has(2), false);
  assert.ok(f.chrome.calls.some(call => call[0] === "sentinel" && call[2].operation === "disable"));
});

test("toolbar and context menu hand over and take back only the named tab", async () => {
  const chrome = fakeChrome();
  const worker = start(chrome);
  await turn();
  chrome.action.onClicked.emit(chrome.tabData.get(2));
  await turn();
  assert.equal(chrome.tabData.get(2).groupId, worker.tabs.group.id);
  assert.equal(worker.tabs.tabs.has(1), false);
  chrome.contextMenus.onClicked.emit({ menuItemId: "agent-handover" }, chrome.tabData.get(2));
  await turn();
  assert.equal(chrome.tabData.get(2).groupId, -1);
  assert.equal(worker.tabs.tabs.has(2), false);
  worker.bridge.drop();
  await worker.bridge.disconnecting;
});

test("worker restart recovers only its recorded group and rotates handles", async () => {
  const f = await setup();
  const { AgentTabs } = await import("../tabs.mjs");
  const restarted = new AgentTabs(f.chrome);
  await restarted.ready;
  const tabs = await restarted.list();
  assert.equal(tabs.length, 1);
  assert.notEqual(tabs[0].tab, f.record.handle);
  assert.equal(restarted.tabs.has(1), false);
  assert.ok(f.chrome.calls.some(call => call[0] === "query" && call[1].groupId === 7));
});

test("handover failures are visible on the toolbar and log the refusal reason", async t => {
  const chrome = fakeChrome();
  const worker = start(chrome);
  await turn();
  const errors = [];
  t.mock.method(console, "error", message => errors.push(message));
  worker.tabs.toggle = async () => { throw new Error("agent_group_other_window"); };
  for (const source of ["toolbar", "menu"]) {
    chrome.calls.length = 0;
    if (source === "toolbar") chrome.action.onClicked.emit(chrome.tabData.get(2));
    else chrome.contextMenus.onClicked.emit({ menuItemId: "agent-handover" }, chrome.tabData.get(2));
    await turn();
    assert.deepEqual(chrome.calls.find(call => call[0] === "badge"), ["badge", { tabId: 2, text: "!" }]);
    assert.deepEqual(chrome.calls.find(call => call[0] === "title"), ["title", { tabId: 2, title: "Agent handover failed: agent_group_other_window" }]);
  }
  assert.deepEqual(errors, ["Agent handover failed: agent_group_other_window", "Agent handover failed: agent_group_other_window"]);
  worker.bridge.drop();
  await worker.bridge.disconnecting;
});

test("a tab in a person-made Agent group moves into our group without adopting its neighbors", async () => {
  const chrome = fakeChrome();
  chrome.groups.set(99, { id: 99, title: "Agent", windowId: 3 });
  for (const tab of chrome.tabData.values()) tab.groupId = 99;
  const worker = start(chrome);
  await turn();
  chrome.action.onClicked.emit(chrome.tabData.get(2));
  await turn();
  assert.notEqual(worker.tabs.group.id, 99);
  assert.equal(chrome.tabData.get(2).groupId, worker.tabs.group.id);
  assert.equal(chrome.tabData.get(1).groupId, 99);
  assert.equal(worker.tabs.tabs.has(1), false);
  assert.equal(worker.tabs.tabs.get(2).kind, "handed");
  assert.ok(chrome.calls.some(call => call[0] === "badge" && call[1].text === ""));
  worker.bridge.drop();
  await worker.bridge.disconnecting;
});

test("dragging into the recorded group hands over a background tab and moving out withdraws it", async () => {
  const f = await setup();
  listen(f);
  f.chrome.tabData.set(3, { id: 3, windowId: 3, groupId: f.tabs.group.id, active: false });
  f.chrome.tabs.onUpdated.emit(3, { groupId: f.tabs.group.id });
  await turn();
  const record = f.tabs.tabs.get(3);
  assert.equal(record.kind, "handed");
  assert.ok(f.chrome.calls.some(call => call[0] === "inject" && call[1].target.tabId === 3));
  assert.ok((await f.tabs.list()).some(tab => tab.tab === record.handle));
  assert.equal(f.chrome.tabData.get(3).active, false);
  f.chrome.tabs.onUpdated.emit(3, { title: "ignored" });
  await turn();
  assert.equal(f.tabs.tabs.get(3).handle, record.handle);
  f.chrome.tabData.get(3).groupId = -1;
  f.chrome.tabs.onUpdated.emit(3, { groupId: -1 });
  await turn();
  assert.equal(f.tabs.tabs.has(3), false);
  assert.equal(f.chrome.calls.some(call => ["restoreTab", "restoreWindow"].includes(call[0])), false);
});

test("a delayed group event cannot adopt an outside tab or a namesake group", async () => {
  const f = await setup();
  listen(f);
  f.chrome.tabs.onUpdated.emit(1, { groupId: f.tabs.group.id });
  await turn();
  assert.equal(f.tabs.tabs.has(1), false);
  f.chrome.groups.set(99, { id: 99, title: "Agent", windowId: 3 });
  f.chrome.tabData.get(1).groupId = 99;
  f.chrome.tabs.onUpdated.emit(1, { groupId: 99 });
  await turn();
  assert.equal(f.tabs.tabs.has(1), false);
});
