import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { setup, turn } from "./harness.mjs";
import { BrowserEvents } from "../events.mjs";
import { OBSERVED_INPUT_EVENTS } from "../epochs.mjs";

// These model one agent `type` into a field whose page reacts to focus. The
// agent's first plan focuses the field; its debugger then detaches, and the
// page's own reaction lands between that plan and the agent's next one. Each
// reaction must surface distinctly: a counted one with its own cause code, an
// uncounted child-frame navigation as lost observation, so a refusal on a real
// page says which signal stopped the type.
const focusEmulation = { method: "Emulation.setFocusEmulationEnabled", params: { enabled: true } };
const focus = { method: "DOM.focus", params: { backendNodeId: 4 } };
const insert = { method: "Input.insertText", params: { text: "x" } };
const metadata = { method: "Page.getLayoutMetrics", params: {} };

async function focusedField() {
  const f = await setup();
  new BrowserEvents(f.chrome, f.tabs, f.epochs, f.agent).listen();
  const epoch = (await f.fresh()).interaction_epoch;
  // The agent's own focus step, in its own debugger attachment.
  await f.run({ ...f.cdp([focusEmulation, focus]), interaction_epoch: epoch });
  return { f, epoch };
}

test("a page's execCommand insertText on focus names an input event as the cause", async () => {
  const { f, epoch } = await focusedField();
  // document.execCommand("insertText") fires trusted beforeinput and input.
  f.chrome.input(2, { type: "beforeinput" });
  f.chrome.input(2, { type: "input" });
  const read = await f.run(f.cdp([metadata]));
  assert.equal(read.interaction_epoch, epoch + 2);
  assert.equal(read.interaction_cause, "input.input.main");
  await assert.rejects(f.run({ ...f.cdp([insert]), interaction_epoch: epoch }), { reason: "interaction_epoch_changed" });
});

test("a page's child-frame navigation on focus is not a person's input", async () => {
  const { f, epoch } = await focusedField();
  f.chrome.webNavigation.onBeforeNavigate.emit({ tabId: 2, frameId: 7, url: "https://embedded.example/" });
  const read = await f.run(f.cdp([metadata]));
  assert.equal(read.interaction_epoch, epoch);
  assert.equal(read.interaction_cause, undefined);
  // The child's new document still invalidates the saved read when it
  // commits, as missing observation rather than a person's change.
  f.chrome.webNavigation.onCommitted.emit({ tabId: 2, frameId: 7, documentId: "child-next" });
  await turn();
  await assert.rejects(f.run({ ...f.cdp([insert]), interaction_epoch: epoch }), { reason: "observer_unavailable" });
});

test("a main-frame navigation the agent did not start still counts, named as a navigation", async () => {
  const { f, epoch } = await focusedField();
  f.chrome.webNavigation.onBeforeNavigate.emit({ tabId: 2, frameId: 0, url: "https://example.com/elsewhere" });
  const read = await f.run(f.cdp([metadata]));
  assert.equal(read.interaction_epoch, epoch + 1);
  assert.equal(read.interaction_cause, "navigation.main");
});

test("a person's key press between the agent's plans still counts", async () => {
  const { f, epoch } = await focusedField();
  f.chrome.input(2, { type: "keydown" });
  const read = await f.run(f.cdp([metadata]));
  assert.equal(read.interaction_epoch, epoch + 1);
  assert.equal(read.interaction_cause, "input.keydown.main");
  await assert.rejects(f.run({ ...f.cdp([insert]), interaction_epoch: epoch }), { reason: "interaction_epoch_changed" });
  assert.equal(f.chrome.calls.some(call => call[0] === "cdp" && call[2] === "Input.insertText"), false);
});

test("a person's key press inside a child frame names the child frame", async () => {
  const { f, epoch } = await focusedField();
  await f.chrome.scripting.executeScript({ target: { tabId: 2, frameIds: [7] }, files: ["sentinel.js"] });
  f.chrome.input(2, { type: "keydown" }, 7);
  await turn();
  const read = await f.run(f.cdp([metadata]));
  assert.equal(read.interaction_epoch, epoch + 1);
  assert.equal(read.interaction_cause, "input.keydown.subframe");
});

test("cause codes name exactly the event types the sentinel observes", async () => {
  const source = await readFile(new URL("../sentinel.js", import.meta.url), "utf8");
  const declared = source.match(/const types = (\[[^\]]*\]);/);
  assert.ok(declared, "sentinel.js declares its observed event types");
  assert.deepEqual(JSON.parse(declared[1]), OBSERVED_INPUT_EVENTS);
});
