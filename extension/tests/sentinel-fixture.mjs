import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(new URL("../sentinel.js", import.meta.url), "utf8");

export function sentinel({ now, documentId = "document-one", onInteraction = () => {}, randomUUIDAvailable = true } = {}) {
  const handlers = new Map();
  const runtimes = [];
  let clock = 0;
  const messages = [];
  let randomValuesCalls = 0;
  const runtime = () => {
    const listeners = new Set();
    const value = { id: "extension-id", sendMessage(message) {
      const copy = structuredClone(message);
      messages.push(copy);
      onInteraction(copy);
      return Promise.resolve();
    }, onMessage: { listeners, addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); } } };
    runtimes.push(value);
    return value;
  };
  const context = {
    crypto: { ...(randomUUIDAvailable ? { randomUUID: () => documentId } : {}), getRandomValues: bytes => { randomValuesCalls++; bytes.fill(0x5a); return bytes; } },
    performance: { timeOrigin: 0, now: now ?? (() => clock) },
    addEventListener(type, fn) {
      if (!handlers.has(type)) handlers.set(type, new Set());
      handlers.get(type).add(fn);
    },
    removeEventListener(type, fn) { handlers.get(type)?.delete(fn); },
    chrome: { runtime: runtime() },
  };
  vm.createContext(context);
  const install = ({ reload = false } = {}) => {
    if (reload) context.chrome.runtime = runtime();
    vm.runInContext(source, context);
  };
  install();
  return {
    messages,
    install,
    get runtime() { return context.chrome.runtime; },
    get marker() { return context.__ckAgentSentinel; },
    set marker(value) { context.__ckAgentSentinel = value; },
    event(event) { for (const fn of [...(handlers.get(event.type) ?? [])]) fn(event); },
    advance(ms) { clock += ms; },
    send(operation) {
      let result;
      for (const fn of context.chrome.runtime.onMessage.listeners) {
        fn({ kind: "agent-sentinel", operation }, { id: "extension-id" }, value => { result = structuredClone(value); });
      }
      return result;
    },
    get listeners() { return [...handlers.values()].reduce((count, listeners) => count + listeners.size, 0); },
    get messageListeners() { return runtimes.reduce((count, runtime) => count + runtime.onMessage.listeners.size, 0); },
    get randomValuesCalls() { return randomValuesCalls; },
  };
}
