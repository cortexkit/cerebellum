import assert from "node:assert/strict";
import { test } from "node:test";
import { AgentTabs } from "../tabs.mjs";
import { InteractionEpochs } from "../epochs.mjs";
import { Agent } from "../agent.mjs";
import { start } from "../service-worker.mjs";
import { fakeChrome } from "./fake-chrome.mjs";
import { route, setup, turn } from "./harness.mjs";

// An extension reload starts a new worker with storage.session cleared, while
// the tabs and the Agent group stay in Chrome.
async function reload(chrome) {
  chrome.clearSession();
  let agent;
  const tabs = new AgentTabs(chrome, id => agent?.withdraw(id), id => epochs.install(id));
  await tabs.ready;
  const epochs = new InteractionEpochs(chrome, tabs, () => chrome.now());
  agent = new Agent(chrome, tabs, epochs);
  agent.connect(51);
  const status = async () => {
    const state = await agent.prepare(route, { version: 2, action: "status" }, 51);
    try { return (await agent.execute(state)).tabs; } finally { await agent.finish(state); }
  };
  return { tabs, agent, status };
}

const groupChanges = chrome => chrome.calls.filter(call => ["group", "ungroup", "groupUpdate"].includes(call[0]));

test("after a reload the recorded Agent group's tabs are listed again, unclaimed", async () => {
  const f = await setup();
  // A second member, as a tab the person opened from the first one and Chrome grouped.
  f.chrome.tabData.set(30, { id: 30, windowId: 3, groupId: 7, active: false });
  await f.tabs.adoptMember(30);
  const before = new Set([...f.tabs.tabs.values()].map(record => record.handle));
  const reloaded = await reload(f.chrome);
  const tabs = await reloaded.status();
  assert.equal(tabs.length, 2);
  assert.deepEqual(tabs.map(tab => [tab.claimed, tab.handed]), [[false, true], [false, true]]);
  assert.ok(tabs.every(tab => !before.has(tab.tab)), "handles are rotated");
  assert.deepEqual([...reloaded.tabs.tabs.keys()].sort(), [2, 30]);
});

test("a toolbar click after a reload takes the tab back instead of splitting the group", async () => {
  const f = await setup();
  f.chrome.tabData.set(30, { id: 30, windowId: 3, groupId: 7, active: false });
  await f.tabs.adoptMember(30);
  f.chrome.clearSession();
  f.chrome.calls.length = 0;
  const worker = start(f.chrome);
  await worker.tabs.ready;
  f.chrome.action.onClicked.emit(f.chrome.tabData.get(2));
  await turn();
  await turn();
  assert.equal(f.chrome.tabData.get(2).groupId, -1);
  assert.equal(f.chrome.tabData.get(30).groupId, 7);
  assert.equal(worker.tabs.group.id, 7);
  assert.deepEqual([...worker.tabs.tabs.keys()], [30]);
  assert.deepEqual(groupChanges(f.chrome), [["ungroup", 2]]);
  worker.bridge.drop();
  await worker.bridge.disconnecting;
});

test("a tab taken back before a reload stays taken back", async () => {
  const f = await setup();
  await f.tabs.join(1, "handed");
  assert.deepEqual(f.chrome.localStore.agentGroupRecord.members, [2, 1]);
  assert.equal(await f.tabs.toggle(1), false);
  assert.deepEqual(f.chrome.localStore.agentGroupRecord.members, [2]);
  const reloaded = await reload(f.chrome);
  assert.equal((await reloaded.status()).length, 1);
  assert.deepEqual([...reloaded.tabs.tabs.keys()], [2]);
});

test("a group the person titled Agent is not adopted without a matching record", async () => {
  for (const record of [undefined, { id: 9, windowId: 3, members: [2] }, { id: 9, windowId: 4, members: [1] }]) {
    const chrome = fakeChrome();
    chrome.groups.set(9, { id: 9, windowId: 3, title: "Agent", color: "blue" });
    chrome.tabData.get(1).groupId = 9;
    if (record) chrome.localStore.agentGroupRecord = record;
    const reloaded = await reload(chrome);
    assert.equal(reloaded.tabs.group, null);
    assert.deepEqual(await reloaded.status(), []);
    assert.equal(chrome.localStore.agentGroupRecord, undefined, "a record that does not match is deleted");
    assert.deepEqual(groupChanges(chrome), [], "the person's group is left alone");
    assert.equal(chrome.tabData.get(1).groupId, 9);
  }
  // The recorded id, window and member, but the person retitled or recoloured it.
  for (const change of [{ title: "Work" }, { color: "red" }]) {
    const f = await setup();
    Object.assign(f.chrome.groups.get(7), change);
    const reloaded = await reload(f.chrome);
    assert.equal(reloaded.tabs.group, null);
    assert.equal(f.chrome.localStore.agentGroupRecord, undefined);
  }
});

test("after a browser start the stored group record adopts nothing", async () => {
  // onStartup arrives before the worker has read the record.
  const early = await setup();
  early.chrome.clearSession();
  early.chrome.calls.length = 0;
  const first = start(early.chrome);
  early.chrome.runtime.onStartup.emit();
  await first.tabs.ready;
  await turn();
  assert.equal(first.tabs.group, null);
  assert.equal(first.tabs.tabs.size, 0);
  assert.equal(early.chrome.localStore.agentGroupRecord, undefined);
  assert.deepEqual(groupChanges(early.chrome), []);
  first.bridge.drop();
  await first.bridge.disconnecting;

  // onStartup arrives after the worker has already re-adopted the group.
  const late = await setup();
  late.chrome.clearSession();
  late.chrome.calls.length = 0;
  const second = start(late.chrome);
  await second.tabs.ready;
  assert.equal(second.tabs.tabs.size, 1);
  late.chrome.runtime.onStartup.emit();
  await turn();
  await turn();
  assert.equal(second.tabs.group, null);
  assert.equal(second.tabs.tabs.size, 0);
  assert.equal(late.chrome.localStore.agentGroupRecord, undefined);
  assert.deepEqual(groupChanges(late.chrome), [], "the group itself is never changed");
  assert.equal(late.chrome.tabData.get(2).groupId, 7);
  second.bridge.drop();
  await second.bridge.disconnecting;
});
