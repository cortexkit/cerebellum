import assert from "node:assert/strict";
import { test } from "node:test";
import { setup } from "./harness.mjs";

// The plans cerebellum sends for browser_use scroll on the person's browser.
// A page scroll asks the root element (backend node 1 here) to show a
// viewport-sized rectangle 600 px further down; a ref scroll brings that
// element into view in its own frame (tested with the frame fixtures in
// frames.test.mjs). Neither runs page JavaScript or dispatches input events:
// DOM.scrollIntoViewIfNeeded is already an admitted, input-guarded method.
// Focus emulation and a local draw wait let background feeds render before
// the final layout read, without activating the tab.
const metrics = { method: "Page.getLayoutMetrics", params: {} };
const pageScroll = { method: "DOM.scrollIntoViewIfNeeded", params: { backendNodeId: 1, rect: { x: 0, y: 600, width: 800, height: 600 } } };
const scrollPlan = [
  { method: "Emulation.setFocusEmulationEnabled", params: { enabled: true } },
  pageScroll,
  { method: "Extension.wait", params: { ms: 2000 } },
  metrics,
];

const sentScrolls = chrome => chrome.calls.filter(call => call[0] === "cdp" && call[2] === "DOM.scrollIntoViewIfNeeded");

test("a page scroll reaches Chrome unchanged and leaves the interaction epoch where the read left it", async () => {
  const f = await setup();
  const epoch = (await f.fresh()).interaction_epoch;
  const send = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    const result = await send(...args);
    // What the page sees while our scroll runs: scroll events the observer
    // ignores, and even a trusted wheel event, all inside the action window.
    if (args[1] === "DOM.scrollIntoViewIfNeeded") {
      f.chrome.input(2, { type: "scroll" });
      f.chrome.input(2, { type: "wheel" });
    }
    return result;
  };
  const result = await f.run({ ...f.cdp(scrollPlan), interaction_epoch: epoch });
  assert.equal(result.interaction_epoch, epoch);
  assert.equal(result.results.length, 4);
  assert.deepEqual(sentScrolls(f.chrome).map(call => [call[1], call[3]]), [[{ tabId: 2 }, pageScroll.params]]);
  assert.equal(await f.epochs.sample(2), epoch);
  // The agent's next scroll and its next read both go ahead under the same epoch.
  await f.run({ ...f.cdp(scrollPlan), interaction_epoch: epoch });
  assert.equal((await f.fresh()).interaction_epoch, epoch);
  // The person's own wheel after the scroll's detach still counts, so a
  // further scroll refuses until the agent reads again.
  f.chrome.input(2, { type: "wheel" });
  await assert.rejects(f.run({ ...f.cdp(scrollPlan), interaction_epoch: epoch }), { reason: "interaction_epoch_changed" });
  assert.equal(sentScrolls(f.chrome).length, 2);
});

test("a scroll needs a read of the tab first", async () => {
  const f = await setup();
  await assert.rejects(f.run({ ...f.cdp(scrollPlan), interaction_epoch: 0 }), { reason: "fresh_read_required" });
  assert.equal(sentScrolls(f.chrome).length, 0);
});

test("a scroll on a tab this route has not claimed refuses before attaching", async () => {
  const f = await setup();
  await f.fresh();
  const unclaimed = await f.tabs.join(1, "handed");
  f.chrome.calls.length = 0;
  await assert.rejects(f.run({ ...f.cdp(scrollPlan), tab: unclaimed.handle, interaction_epoch: 0 }), { reason: "tab_not_claimed" });
  const other = { channel: 9, epoch: 4 };
  await assert.rejects(f.run({ ...f.cdp(scrollPlan), interaction_epoch: 0 }, other), { reason: "tab_not_claimed" });
  assert.equal(f.chrome.calls.some(call => call[0] === "attach"), false);
  assert.equal(sentScrolls(f.chrome).length, 0);
});
