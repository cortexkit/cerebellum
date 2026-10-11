import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { test } from "node:test";

const source = await readFile(new URL("../sentinel.js", import.meta.url), "utf8");
function sentinel() {
  const handlers = new Map();
  let receiver;
  let clock = 0;
  const messages = [];
  const context = {
    crypto: { randomUUID: () => "document-one" },
    performance: { now: () => clock },
    addEventListener(type, fn) { handlers.set(type, fn); },
    removeEventListener(type) { handlers.delete(type); },
    chrome: { runtime: { id: "extension-id", sendMessage(message) { messages.push(message); return Promise.resolve(); }, onMessage: { addListener(fn) { receiver = fn; }, removeListener() { receiver = null; } } } },
  };
  vm.runInNewContext(source, context);
  return {
    messages,
    event(event) { handlers.get(event.type)?.(event); },
    advance(ms) { clock += ms; },
    send(operation, events = []) {
      let result;
      receiver?.({ kind: "agent-sentinel", operation, events }, { id: "extension-id" }, value => { result = value; });
      return result;
    },
    get listeners() { return handlers.size; },
  };
}

test("sentinel counts detached trusted input but reads no page content", () => {
  const s = sentinel();
  s.event({ type: "keydown", isTrusted: true, key: "x", code: "KeyX", get target() { throw new Error("must not read target"); } });
  assert.equal(s.send("sample").sequence, 1);
  s.event({ type: "keydown", isTrusted: false });
  assert.equal(s.send("sample").sequence, 1);
});

test("sentinel attributes only a one-shot exact current input ticket", () => {
  const s = sentinel();
  s.send("arm", [{ type: "mousedown", clientX: 10, clientY: 20, button: 0 }]);
  s.event({ type: "mousedown", isTrusted: true, clientX: 10, clientY: 20, button: 0 });
  assert.equal(s.send("sample").sequence, 0);
  s.event({ type: "mousedown", isTrusted: true, clientX: 10, clientY: 20, button: 0 });
  assert.equal(s.send("sample").sequence, 1);
});

test("sentinel counts mismatched and expired tickets as human input", () => {
  const s = sentinel();
  s.send("arm", [{ type: "keydown", key: "a", code: "KeyA" }]);
  s.event({ type: "keydown", isTrusted: true, key: "b", code: "KeyB" });
  s.send("arm", [{ type: "keydown", key: "a", code: "KeyA" }]);
  s.advance(251);
  s.event({ type: "keydown", isTrusted: true, key: "a", code: "KeyA" });
  assert.equal(s.send("sample").sequence, 2);
});

test("sentinel withdrawal removes all page input observers", () => {
  const s = sentinel();
  assert.ok(s.listeners > 0);
  assert.equal(s.send("disable").enabled, false);
  assert.equal(s.listeners, 0);
  s.event({ type: "keydown", isTrusted: true });
  assert.equal(s.send("sample"), undefined);
});
