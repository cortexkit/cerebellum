import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(new URL("../sentinel.js", import.meta.url), "utf8");

export function sentinel({ now, documentId = "document-one", onInteraction = () => {}, randomUUIDAvailable = true } = {}) {
  const handlers = new Map();
  let receiver;
  let clock = 0;
  const messages = [];
  let randomValuesCalls = 0;
  const context = {
    crypto: { ...(randomUUIDAvailable ? { randomUUID: () => documentId } : {}), getRandomValues: bytes => { randomValuesCalls++; bytes.fill(0x5a); return bytes; } },
    performance: { timeOrigin: 0, now: now ?? (() => clock) },
    addEventListener(type, fn) { handlers.set(type, fn); },
    removeEventListener(type) { handlers.delete(type); },
    chrome: { runtime: { id: "extension-id", sendMessage(message) {
      const copy = structuredClone(message);
      messages.push(copy);
      onInteraction(copy);
      return Promise.resolve();
    }, onMessage: { addListener(fn) { receiver = fn; }, removeListener() { receiver = null; } } } },
  };
  vm.runInNewContext(source, context);
  return {
    messages,
    event(event) { handlers.get(event.type)?.(event); },
    advance(ms) { clock += ms; },
    send(operation) {
      let result;
      receiver?.({ kind: "agent-sentinel", operation }, { id: "extension-id" }, value => { result = structuredClone(value); });
      return result;
    },
    get listeners() { return handlers.size; },
    get randomValuesCalls() { return randomValuesCalls; },
  };
}
