import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyCommand } from "../commands.mjs";
import { route, setup, turn } from "./harness.mjs";

const wait = ms => ({ method: "Extension.wait", params: { ms } });
const metrics = { method: "Page.getLayoutMetrics", params: {} };
const sent = f => f.chrome.calls.filter(call => call[0] === "cdp");

test("wait has its own classification and refuses malformed or oversized delays before attach", async () => {
  const f = await setup();
  f.chrome.calls.length = 0;
  for (const ms of [0, 1, 2000]) assert.equal(classifyCommand(wait(ms)), "wait");
  for (const params of [{}, { ms: -1 }, { ms: 0.5 }, { ms: 2001 }, { ms: Infinity }, { ms: NaN }, { ms: "2000" }, { ms: 1, extra: true }]) {
    await assert.rejects(f.run(f.cdp([{ method: "Extension.wait", params }])), { reason: "invalid_command" });
  }
  assert.equal(f.chrome.calls.some(call => call[0] === "attach"), false);
});

test("wait keeps the debugger attached for its bounded duration and sends nothing to the page", async t => {
  const f = await setup();
  const state = await f.agent.prepare(route, f.cdp([wait(2000), metrics]), 50);
  f.chrome.calls.length = 0;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let done = false;
  const running = f.agent.execute(state).then(result => { done = true; return result; });
  await turn();
  assert.equal(typeof state.cancelWait, "function");
  t.mock.timers.tick(1999);
  await turn();
  assert.equal(done, false);
  assert.equal(state.attached, true);
  assert.deepEqual(sent(f), []);
  t.mock.timers.tick(1);
  const reply = await running;
  assert.deepEqual(reply.results[0], { result: {} });
  assert.deepEqual(sent(f).map(call => call[2]), ["Page.getLayoutMetrics"]);
  assert.equal(state.input, false);
  assert.equal(state.cancelWait, undefined);
  await f.agent.finish(state);
  assert.equal(state.attached, false);
});

test("the execution timer defensively clamps to two seconds", async t => {
  const f = await setup();
  const state = await f.agent.prepare(route, f.cdp([wait(2000)]), 50);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let done = false;
  const running = f.agent.wait(state, 10000).then(() => { done = true; });
  t.mock.timers.tick(1999);
  await turn();
  assert.equal(done, false);
  t.mock.timers.tick(1);
  await running;
  assert.equal(done, true);
  await f.agent.finish(state);
});

for (const stop of ["cancel", "detach", "disconnect", "connect"]) {
  test(`${stop} wakes a mid-wait plan immediately without advancing the timer`, async t => {
    const f = await setup();
    const state = await f.agent.prepare(route, f.cdp([wait(2000), metrics]), 50);
    f.chrome.calls.length = 0;
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let ended = false;
    const rejected = assert.rejects(f.agent.execute(state), { reason: "cancelled" }).then(() => { ended = true; });
    await turn();
    assert.equal(typeof state.cancelWait, "function");
    if (stop === "connect") f.agent.connect(51);
    else if (stop === "disconnect") await f.agent.disconnect();
    else await f.agent[stop](state);
    await turn();
    assert.equal(ended, true, "cancellation must not wait for the draw timer");
    await rejected;
    assert.deepEqual(sent(f), []);
    assert.equal(state.cancelWait, undefined);
    await f.agent.finish(state);
  });
}

test("wait checks the claim again before a later command can run", async t => {
  const f = await setup();
  const state = await f.agent.prepare(route, f.cdp([wait(2000), metrics]), 50);
  f.chrome.calls.length = 0;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const rejected = assert.rejects(f.agent.execute(state), { reason: "tab_not_claimed" });
  await turn();
  f.agent.claims.delete(2);
  t.mock.timers.tick(2000);
  await rejected;
  assert.deepEqual(sent(f), []);
  await f.agent.finish(state);
});

test("wait checks liveness again after its timer", async t => {
  const f = await setup();
  const state = await f.agent.prepare(route, f.cdp([wait(0), metrics]), 50);
  f.chrome.calls.length = 0;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const rejected = assert.rejects(f.agent.execute(state), { reason: "cancelled" });
  await turn();
  state.cancelled = true;
  t.mock.timers.tick(0);
  await rejected;
  assert.deepEqual(sent(f), []);
  await f.agent.finish(state);
});
