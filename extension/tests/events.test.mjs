import assert from "node:assert/strict";
import { test } from "node:test";
import { BrowserEvents } from "../events.mjs";
import { setup, turn } from "./harness.mjs";
import { start } from "../service-worker.mjs";
import { deferred, fakeChrome } from "./fake-chrome.mjs";

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

test("status adopts a grouped active tab without a groupId event and logs only membership metadata", async t => {
  const f = await setup();
  const logs = [];
  t.mock.method(console, "info", line => logs.push(line));
  f.chrome.tabData.get(1).url = "https://private.invalid/do-not-log";
  f.chrome.tabData.get(1).title = "PRIVATE_TITLE";
  f.chrome.calls.length = 0;
  await f.chrome.tabs.group({ groupId: f.tabs.group.id, tabIds: [1] });
  assert.equal(f.tabs.tabs.has(1), false, "group API must not invent an onUpdated groupId delta");
  const status = await f.run({ version: 2, action: "status" });
  const record = f.tabs.tabs.get(1);
  assert.equal(record.kind, "handed");
  assert.ok(status.tabs.some(tab => tab.tab === record.handle && tab.handed && !tab.claimed));
  assert.equal(f.chrome.calls.filter(call => call[0] === "inject" && call[1].target.tabId === 1).length, 1);
  assert.ok(logs.some(line => line.includes("source=status tab=1 group=7 decision=adopted_handed")));
  assert.ok(logs.every(line => !line.includes("private.invalid") && !line.includes("PRIVATE_TITLE")));
  assert.ok(f.chrome.calls.filter(call => call[0] === "query").every(call => call[1].groupId === 7 && call[1].windowId === 3));
  const again = await f.run({ version: 2, action: "status" });
  assert.ok(again.tabs.some(tab => tab.tab === record.handle));
  assert.equal(f.chrome.tabData.get(1).active, true);
  assert.equal(f.chrome.tabData.get(2).active, false);
  assert.equal(f.chrome.calls.some(call => ["restoreTab", "restoreWindow"].includes(call[0])), false);
});

test("a full-tab update adopts a background group member when changeInfo has no groupId", async () => {
  const f = await setup();
  listen(f);
  f.chrome.tabData.set(3, { id: 3, windowId: 3, groupId: -1, active: false });
  await f.chrome.tabs.group({ groupId: f.tabs.group.id, tabIds: [3] });
  f.chrome.tabs.onUpdated.emit(3, { status: "complete" }, { ...f.chrome.tabData.get(3) });
  await turn();
  assert.equal(f.tabs.tabs.get(3).kind, "handed");
  assert.ok(f.chrome.calls.some(call => call[0] === "inject" && call[1].target.tabId === 3));
  f.chrome.tabData.get(3).groupId = -1;
  f.chrome.tabs.onUpdated.emit(3, { status: "complete" }, { ...f.chrome.tabData.get(3) });
  await turn();
  assert.equal(f.tabs.tabs.has(3), false);
  assert.equal(f.chrome.tabData.get(3).active, false);
});

test("move and group-property hints reconcile only the recorded group without reclassifying owned tabs", async () => {
  const f = await setup();
  listen(f);
  const original = f.tabs.tabs.get(2);
  f.chrome.calls.length = 0;
  f.chrome.tabs.onMoved.emit(1, { windowId: 3, fromIndex: 0, toIndex: 1 });
  f.chrome.tabGroups.onUpdated.emit({ id: 7, windowId: 3, collapsed: true });
  await turn();
  assert.deepEqual([...f.tabs.tabs.keys()], [2]);
  assert.equal(f.tabs.tabs.get(2), original);
  assert.equal(f.chrome.calls.some(call => call[0] === "get" && call[1] === 1), false);
  f.chrome.tabData.set(3, { id: 3, windowId: 3, groupId: -1, active: false });
  await f.chrome.tabs.group({ groupId: 7, tabIds: [3] });
  f.chrome.tabs.onMoved.emit(3, { windowId: 3, fromIndex: 2, toIndex: 1 });
  await turn();
  assert.equal(f.tabs.tabs.get(3).kind, "handed");
  assert.ok(f.chrome.calls.filter(call => call[0] === "query").every(call => call[1].groupId === 7));
});

test("status reconciliation cannot adopt a tab while our own join is pending", async () => {
  const f = await setup();
  f.chrome.tabData.set(3, { id: 3, windowId: 3, groupId: -1, active: false });
  const gate = deferred();
  const group = f.chrome.tabs.group;
  f.chrome.tabs.group = async options => { const id = await group(options); await gate.promise; return id; };
  const joining = f.tabs.join(3, "opened");
  await turn();
  await f.tabs.list();
  assert.equal(f.tabs.tabs.has(3), false);
  gate.resolve();
  const record = await joining;
  assert.equal(record.kind, "opened");
  assert.equal(f.tabs.tabs.get(3), record);
});

test("status cannot re-adopt a handed tab while take-back waits for ungroup", async () => {
  const f = await setup();
  const gate = deferred();
  const ungroup = f.chrome.tabs.ungroup;
  f.chrome.tabs.ungroup = async id => { await gate.promise; return ungroup(id); };
  const takingBack = f.tabs.toggle(2);
  await turn();
  assert.equal((await f.tabs.list()).length, 0);
  gate.resolve();
  await takingBack;
  assert.equal(f.tabs.tabs.has(2), false);
  assert.equal(f.chrome.tabData.get(2).groupId, -1);
});

test("concurrent update hints and status install a new member observer once", async () => {
  const f = await setup();
  listen(f);
  f.chrome.tabData.set(3, { id: 3, windowId: 3, groupId: 7, active: false });
  f.chrome.tabs.onUpdated.emit(3, { status: "complete" }, { ...f.chrome.tabData.get(3) });
  f.chrome.tabs.onMoved.emit(3, { windowId: 3, fromIndex: 2, toIndex: 1 });
  const status = await f.run({ version: 2, action: "status" });
  await turn();
  assert.equal(f.chrome.calls.filter(call => call[0] === "inject" && call[1].target.tabId === 3).length, 1);
  const record = f.tabs.tabs.get(3);
  assert.ok(status.tabs.some(tab => tab.tab === record.handle && tab.handed));
});

test("a restored worker discovers later group members even without membership events", async () => {
  const f = await setup();
  const { AgentTabs } = await import("../tabs.mjs");
  const adopted = [];
  const restarted = new AgentTabs(f.chrome, () => {}, async id => { adopted.push(id); });
  await restarted.ready;
  f.chrome.tabData.set(3, { id: 3, windowId: 3, groupId: -1, active: false });
  await f.chrome.tabs.group({ groupId: 7, tabIds: [3] });
  const status = await restarted.list();
  assert.equal(restarted.tabs.get(3).kind, "handed");
  assert.ok(status.some(tab => tab.tab === restarted.tabs.get(3).handle));
  assert.deepEqual(adopted, [3]);
});

test("recorded groupId update then move then status exposes the handed handle to its route", async () => {
  const f = await setup();
  listen(f);
  const order = [];
  f.chrome.tabs.onUpdated.addListener(id => { if (id === 1) order.push("onUpdated"); });
  f.chrome.tabs.onMoved.addListener(id => { if (id === 1) order.push("onMoved"); });
  await f.chrome.tabs.group({ groupId: 7, tabIds: [1] });
  f.chrome.tabs.onUpdated.emit(1, { groupId: 7 }, { ...f.chrome.tabData.get(1) });
  f.chrome.tabs.onMoved.emit(1, { fromIndex: 0, toIndex: 1, windowId: 3 });
  order.push("status");
  const status = await f.run({ version: 2, action: "status" });
  assert.deepEqual(order, ["onUpdated", "onMoved", "status"]);
  const record = f.tabs.tabs.get(1);
  assert.equal(record.kind, "handed");
  assert.equal(f.agent.claims.has(1), false);
  assert.deepEqual(status.tabs.find(tab => tab.tab === record.handle), {
    tab: record.handle, claimed: false, handed: true, interaction_epoch: 0,
  });
  assert.notEqual(record.handle, "1");
  assert.equal(f.chrome.calls.filter(call => call[0] === "inject" && call[1].target.tabId === 1).length, 1);
  assert.equal(f.chrome.tabData.get(1).groupId, 7);
  assert.equal(f.chrome.tabData.get(1).windowId, 3);
  const claimed = await f.run({ version: 2, action: "claim_tab", tab: record.handle });
  assert.equal(claimed.tab, record.handle);
  const own = await f.run({ version: 2, action: "status" });
  assert.equal(own.tabs.find(tab => tab.tab === record.handle).claimed, true);
  const other = await f.run({ version: 2, action: "status" }, { channel: 9, epoch: 1 });
  assert.equal(other.tabs.some(tab => tab.tab === record.handle), false);
  assert.equal(f.chrome.tabData.get(1).active, true);
});
