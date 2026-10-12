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
  const reply = await f.run({ version: 1, action: "open_tab", url: "http://localhost/popup", opener_tab: f.record.handle });
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
