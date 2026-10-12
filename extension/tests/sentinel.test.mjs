import assert from "node:assert/strict";
import { test } from "node:test";
import { setup } from "./harness.mjs";
import { sentinel } from "./sentinel-fixture.mjs";

test("sentinel counts detached trusted input but reads no page content", () => {
  const s = sentinel();
  s.event({ type: "keydown", isTrusted: true, key: "x", code: "KeyX", get target() { throw new Error("must not read target"); } });
  assert.equal(s.send("sample").sequence, 1);
  s.event({ type: "keydown", isTrusted: false });
  assert.equal(s.send("sample").sequence, 1);
});

test("sentinel timestamps every trusted click without a post-action grace period", () => {
  const s = sentinel();
  s.advance(10);
  s.event({ type: "click", isTrusted: true });
  s.advance(1);
  s.event({ type: "click", isTrusted: true });
  assert.deepEqual(s.send("sample").interactions, [{ sequence: 1, at: 10 }, { sequence: 2, at: 11 }]);
});

test("sentinel never records focus or tab visibility as interaction", () => {
  const s = sentinel();
  for (const type of ["focus", "blur", "focusin", "focusout", "visibilitychange"]) s.event({ type, isTrusted: true });
  assert.equal(s.send("sample").sequence, 0);
});

test("sentinel withdrawal removes all page input observers", () => {
  const s = sentinel();
  assert.ok(s.listeners > 0);
  assert.equal(s.send("disable").enabled, false);
  assert.equal(s.listeners, 0);
  s.event({ type: "keydown", isTrusted: true });
  assert.equal(s.send("sample"), undefined);
});


test("trusted pointer and mouse movement do not change the tab interaction epoch", async () => {
  const f = await setup();
  const s = f.chrome.sentinels.get("2:0");
  const epoch = await f.epochs.sample(2);
  s.event({ type: "pointermove", isTrusted: true, clientX: 10, clientY: 20 });
  s.event({ type: "mousemove", isTrusted: true, clientX: 10, clientY: 20 });
  assert.equal(await f.epochs.sample(2), epoch);
});

test("a trusted click still changes the tab interaction epoch", async () => {
  const f = await setup();
  const s = f.chrome.sentinels.get("2:0");
  const epoch = await f.epochs.sample(2);
  s.event({ type: "click", isTrusted: true, clientX: 10, clientY: 20, button: 0 });
  assert.equal(await f.epochs.sample(2), epoch + 1);
});

test("missing interaction history refuses instead of hiding unknown input", async () => {
  const f = await setup();
  const epoch = await f.epochs.sample(2);
  for (let i = 0; i < 257; i++) f.chrome.input(2, { type: "click" });
  assert.equal(f.chrome.sentinels.get("2:0").send("sample").interactions.length, 256);
  await assert.rejects(f.epochs.sample(2), { reason: "interaction_continuity_lost" });
  assert.equal(f.epochs.record(2).epoch, epoch);
});
