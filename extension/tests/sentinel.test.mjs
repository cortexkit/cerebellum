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
  assert.deepEqual(s.send("sample").interactions, [{ sequence: 1, at: 10, kind: "click" }, { sequence: 2, at: 11, kind: "click" }]);
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

test("sentinel tears down after sendMessage throws synchronously", () => {
  const s = sentinel();
  let sends = 0;
  s.runtime.sendMessage = () => { sends++; throw new Error("Extension context invalidated."); };
  assert.doesNotThrow(() => s.event({ type: "keydown", isTrusted: true }));
  assert.equal(sends, 1);
  assert.equal(s.listeners, 0);
  assert.equal(s.messageListeners, 0);
  assert.equal(s.marker, undefined);
  assert.equal(s.send("sample"), undefined);
  assert.doesNotThrow(() => s.event({ type: "click", isTrusted: true }));
  assert.equal(sends, 1);
});

test("sentinel tears down when its runtime id disappears", () => {
  const s = sentinel();
  delete s.runtime.id;
  const before = s.messages.length;
  assert.doesNotThrow(() => s.event({ type: "click", isTrusted: true }));
  assert.equal(s.listeners, 0);
  assert.equal(s.messageListeners, 0);
  assert.equal(s.marker, undefined);
  assert.equal(s.messages.length, before);
});

test("a new sentinel replaces an orphan in the same world and observes input", () => {
  const s = sentinel();
  const listenerCount = s.listeners;
  const orphan = s.runtime;
  delete orphan.id;
  orphan.sendMessage = () => { throw new Error("Extension context invalidated."); };
  assert.doesNotThrow(() => s.install({ reload: true }));
  assert.equal(orphan.onMessage.listeners.size, 0);
  assert.equal(s.listeners, listenerCount);
  assert.equal(s.messageListeners, 1);
  const before = s.messages.length;
  s.event({ type: "keydown", isTrusted: true });
  s.event({ type: "click", isTrusted: true });
  assert.equal(s.messages.length, before + 2);
  assert.deepEqual(s.send("sample").interactions.map(({ kind }) => kind), ["keydown", "click"]);
  assert.equal(s.send("sample").sequence, 2);
});

test("a new isolated world observes input while an orphan remains in the old world", () => {
  const orphan = sentinel();
  delete orphan.runtime.id;
  const fresh = sentinel();
  assert.ok(orphan.listeners > 0);
  assert.equal(fresh.messages.length, 1);
  assert.doesNotThrow(() => orphan.event({ type: "keydown", isTrusted: true }));
  fresh.event({ type: "keydown", isTrusted: true });
  fresh.event({ type: "click", isTrusted: true });
  assert.equal(orphan.listeners, 0);
  assert.equal(orphan.messageListeners, 0);
  assert.equal(fresh.messageListeners, 1);
  assert.equal(fresh.messages.length, 3);
  assert.equal(fresh.send("sample").sequence, 2);
});

test("reinjection keeps a live sentinel without duplicating observers", () => {
  const s = sentinel();
  const marker = s.marker;
  const listenerCount = s.listeners;
  s.event({ type: "keydown", isTrusted: true });
  s.install();
  assert.equal(s.marker, marker);
  assert.equal(s.listeners, listenerCount);
  assert.equal(s.messageListeners, 1);
  const before = s.messages.length;
  s.event({ type: "click", isTrusted: true });
  assert.equal(s.messages.length, before + 1);
  assert.equal(s.send("sample").sequence, 2);
});

test("a legacy boolean sentinel marker does not block installation", () => {
  const s = sentinel();
  s.send("disable");
  s.marker = true;
  s.install({ reload: true });
  s.event({ type: "keydown", isTrusted: true });
  assert.equal(s.send("sample").sequence, 1);
  assert.equal(s.messageListeners, 1);
});

test("sentinel keeps observing after an asynchronous delivery rejection", async () => {
  const s = sentinel();
  s.runtime.sendMessage = () => Promise.reject(new Error("Receiving end does not exist."));
  s.event({ type: "click", isTrusted: true });
  await Promise.resolve();
  assert.equal(s.send("sample").sequence, 1);
  assert.equal(s.send("sample").enabled, true);
  assert.equal(s.messageListeners, 1);
});

test("sentinel teardown survives invalidated onMessage bindings", () => {
  const s = sentinel();
  s.runtime.onMessage.removeListener = () => { throw new Error("Extension context invalidated."); };
  delete s.runtime.id;
  assert.doesNotThrow(() => s.event({ type: "click", isTrusted: true }));
  assert.equal(s.listeners, 0);
  assert.equal(s.marker, undefined);
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
  await assert.rejects(f.epochs.sample(2), { reason: "observer_unavailable" });
  assert.equal(f.epochs.record(2).epoch, epoch);
});


test("observer installs when secure-context randomUUID is unavailable", () => {
  const observer = sentinel({ randomUUIDAvailable: false });
  const first = observer.send("sample");
  assert.equal(first.enabled, true);
  assert.equal(first.documentId, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
  assert.equal(observer.randomValuesCalls, 1);
  observer.event({ type: "click", isTrusted: true });
  const second = observer.send("sample");
  assert.equal(second.documentId, first.documentId);
  assert.equal(second.sequence, 1);
});
