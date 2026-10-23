import assert from "node:assert/strict";
import { test } from "node:test";
import { DEADLINES } from "../errors.mjs";
import { BrowserEvents } from "../events.mjs";
import { deferred } from "./fake-chrome.mjs";
import { setup, route, read, turn } from "./harness.mjs";

const busy = "Another debugger is already attached to the tab with id: 2.";
const calls = (f, name) => f.chrome.calls.filter(call => call[0] === name);

function debuggerHolder(f, initial) {
  let holder = initial;
  f.chrome.debugger.attach = async (target, version) => {
    f.chrome.calls.push(["attach", target, version]);
    if (holder) throw new Error(busy);
    holder = "ours";
  };
  f.chrome.debugger.detach = async target => {
    f.chrome.calls.push(["detach", target]);
    if (holder !== "ours") throw new Error("Debugger is not attached to the tab with id: 2.");
    holder = null;
  };
  return () => holder;
}

test("a stale own attach is detached and retried once", async () => {
  const f = await setup();
  const holder = debuggerHolder(f, "ours");
  await f.fresh();
  assert.equal(calls(f, "attach").length, 2);
  assert.equal(calls(f, "detach").length, 2);
  assert.equal(holder(), null);
  assert.equal(f.agent.active.size, 0);
});

test("another holder is never retried when the own-session detach probe rejects", async () => {
  const f = await setup();
  const holder = debuggerHolder(f, "other");
  await assert.rejects(f.fresh(), {
    reason: "debugger_busy",
    detail: {
      remedy: "Chrome rejected the debugger attach: DevTools or another extension is debugging this tab. Close it, then read again.",
      attach_failure: "rejection", attach_reason: "another_debugger",
    },
  });
  assert.equal(calls(f, "attach").length, 1);
  assert.equal(calls(f, "detach").length, 1);
  assert.equal(calls(f, "cdp").length, 0);
  assert.equal(holder(), "other");
});

test("an attached active plan is never detached by a competing prepare", async () => {
  const f = await setup();
  const holder = debuggerHolder(f, null);
  const state = await f.agent.prepare(route, f.cdp([read]), 50);
  try {
    await assert.rejects(f.agent.prepare(route, f.cdp([read]), 50), error => {
      assert.equal(error.reason, "debugger_busy");
      assert.equal(error.detail.attach_reason, "active_plan");
      assert.equal(error.detail.attach_failure, "rejection");
      assert.match(error.detail.remedy, /our plans.*Wait for that plan/);
      return true;
    });
    assert.equal(calls(f, "detach").length, 0);
    assert.equal(state.attached, true);
    assert.equal(holder(), "ours");
  } finally { await f.agent.finish(state); }
});

test("a busy rejection after the stale-own retry is not retried again", async () => {
  const f = await setup();
  f.chrome.debugger.attach = async target => {
    f.chrome.calls.push(["attach", target]);
    throw new Error(busy.toUpperCase());
  };
  await assert.rejects(f.fresh(), error => error.detail.attach_reason === "another_debugger");
  assert.equal(calls(f, "attach").length, 2);
  assert.equal(calls(f, "detach").length, 1);
});

test("a missing tab attach rejection tells the caller to read status and claim again", async () => {
  for (const message of ["No tab with given id 2", "NO TAB WITH ID: 2."]) {
    const f = await setup();
    f.chrome.debugger.attach = async () => { throw new Error(message); };
    await assert.rejects(f.fresh(), {
      reason: "debugger_busy",
      detail: {
        remedy: "Chrome rejected the debugger attach because the tab no longer exists. Read status and claim the tab again.",
        attach_failure: "rejection", attach_reason: "tab_gone",
      },
    });
    assert.equal(calls(f, "detach").length, 0);
  }
});

test("restricted page attach rejections say the page cannot be automated", async () => {
  for (const message of ["Cannot access a chrome:// URL", "Cannot access a chrome-extension:// URL of different extension", "The extensions gallery cannot be scripted.", "Cannot access a Chrome Web Store page."]) {
    const f = await setup();
    f.chrome.debugger.attach = async () => { throw new Error(message.toUpperCase()); };
    await assert.rejects(f.fresh(), {
      reason: "debugger_busy",
      detail: {
        remedy: "Chrome rejected the debugger attach because this page cannot be automated. Use a regular web page instead.",
        attach_failure: "rejection", attach_reason: "restricted_page",
      },
    });
    assert.equal(calls(f, "detach").length, 0);
  }
});

test("an unknown attach rejection quotes only a bounded Chrome message", async () => {
  const f = await setup();
  f.chrome.debugger.attach = async () => { throw new Error(`Unexpected Chrome failure\n${"x".repeat(400)}`); };
  await assert.rejects(f.fresh(), error => {
    assert.equal(error.reason, "debugger_busy");
    assert.equal(error.detail.attach_failure, "rejection");
    assert.equal(error.detail.attach_reason, "unknown");
    assert.equal(error.detail.chrome_message.length, 200);
    assert.equal(error.detail.chrome_message.includes("\n"), false);
    assert.equal(error.detail.remedy, `Chrome rejected the debugger attach: ${JSON.stringify(error.detail.chrome_message)}. Read again.`);
    return true;
  });
  assert.equal(calls(f, "detach").length, 0);
});

test("a generic restricted-target rejection is not mistaken for a known forbidden page", async () => {
  const f = await setup();
  f.chrome.debugger.attach = async () => { throw new Error("Cannot attach to this target."); };
  await assert.rejects(f.fresh(), error => {
    assert.equal(error.detail.attach_reason, "unknown");
    assert.equal(error.detail.chrome_message, "Cannot attach to this target.");
    assert.match(error.detail.remedy, /Chrome rejected.*"Cannot attach to this target\."\. Read again\.$/);
    return true;
  });
});

test("the five second attach deadline reports no Chrome answer and cleans up a late attach", async t => {
  const f = await setup();
  const gate = deferred();
  f.chrome.debugger.attach = async () => gate.promise;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const result = f.fresh();
  const rejected = assert.rejects(result, {
    reason: "attach_deadline", detached: false,
    detail: {
      remedy: "Chrome did not answer the debugger attach within 5 seconds (the attach deadline). Read again.",
      attach_failure: "deadline", attach_reason: "timeout",
    },
  });
  await turn();
  t.mock.timers.tick(DEADLINES.attach);
  await rejected;
  assert.equal(calls(f, "detach").length, 0);
  gate.resolve();
  await turn();
  assert.equal(calls(f, "detach").length, 1);
  assert.equal(f.agent.active.size, 0);
});

test("a pending attach refuses before calling Chrome with a cleanup remedy, not DevTools", async () => {
  const f = await setup();
  const gate = deferred();
  f.agent.pendingAttaches.add(gate.promise);
  await assert.rejects(f.fresh(), { reason: "debugger_busy", detail: { remedy: "wait for debugger cleanup, then read again" } });
  assert.equal(calls(f, "attach").length, 0);
});

test("an attach that rejects after its deadline does not retain an active plan", async t => {
  const f = await setup();
  const gate = deferred();
  f.chrome.debugger.attach = async () => gate.promise;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const rejected = assert.rejects(f.fresh(), { reason: "attach_deadline" });
  await turn();
  t.mock.timers.tick(DEADLINES.attach);
  await rejected;
  gate.reject(new Error("Chrome answered late"));
  await turn();
  assert.equal(f.agent.active.size, 0);
  assert.equal(f.agent.pendingAttaches.size, 0);
});

test("a stale-session probe that finishes after the deadline cannot retry attach", async t => {
  const f = await setup();
  const gate = deferred();
  f.chrome.debugger.attach = async target => {
    f.chrome.calls.push(["attach", target]);
    throw new Error(busy);
  };
  f.chrome.debugger.detach = async () => gate.promise;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const rejected = assert.rejects(f.fresh(), { reason: "attach_deadline", detached: false });
  await turn();
  t.mock.timers.tick(DEADLINES.attach);
  await rejected;
  gate.resolve();
  await turn();
  assert.equal(calls(f, "attach").length, 1);
  assert.equal(f.agent.active.size, 0);
});

test("releasing a claim cancels and detaches its active plan before reminting a handle", async () => {
  const f = await setup();
  f.record.kind = "opened";
  const handle = f.record.handle;
  const state = await f.agent.prepare(route, f.cdp([read]), 50);
  await f.run({ version: 2, action: "close" });
  assert.equal(state.cancelled, true);
  assert.equal(state.attached, false);
  assert.equal(calls(f, "detach").length, 1);
  assert.notEqual(f.record.handle, handle);
  assert.equal(f.agent.claims.has(2), false);
  await f.agent.finish(state);
});

test("a failed post-attach cleanup stays active and is never reported detached", async () => {
  const f = await setup();
  f.chrome.debugger.attach = async () => { f.agent.claims.delete(2); };
  f.chrome.debugger.detach = async () => { throw new Error("Chrome detach failed"); };
  await assert.rejects(f.fresh(), { reason: "tab_not_claimed", detached: false });
  const [state] = f.agent.active;
  assert.equal(state.attached, true);
  f.chrome.debugger.detach = async () => {};
  await f.agent.disconnect();
  assert.equal(state.attached, false);
  assert.equal(f.agent.active.size, 0);
});

test("tab replacement revokes the old handle and detaches its active plan", async () => {
  const f = await setup();
  new BrowserEvents(f.chrome, f.tabs, f.epochs, f.agent).listen();
  const state = await f.agent.prepare(route, f.cdp([read]), 50);
  const oldHandle = f.record.handle;
  f.chrome.tabData.set(20, { ...f.chrome.tabData.get(2), id: 20 });
  f.chrome.tabData.delete(2);
  f.chrome.tabs.onReplaced.emit(20, 2);
  await turn();
  assert.equal(state.cancelled, true);
  assert.equal(state.attached, false);
  assert.equal(f.agent.claims.has(2), false);
  await assert.rejects(f.tabs.resolve(oldHandle), { reason: "unknown_tab" });
  const replacement = (await f.tabs.list()).find(tab => f.tabs.tabs.get(20)?.handle === tab.tab);
  assert.ok(replacement);
  assert.notEqual(replacement.tab, oldHandle);
  assert.equal(f.epochs.record(20).epoch, 0);
  await f.agent.finish(state);
});
