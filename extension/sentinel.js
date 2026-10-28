// This isolated-world observer stays alive between debugger attachments. It never
// reads page text, field values or URLs; only trusted interaction times.
(() => {
  const previous = globalThis.__ckAgentSentinel;
  try {
    if (typeof previous?.isAlive === "function" && previous.isAlive()) return;
  } catch {}
  // Keep the original bindings so a new injection cannot make an orphan look live.
  const runtime = chrome.runtime;
  // randomUUID is secure-context-only; getRandomValues also works on HTTP.
  // Keep a cryptographically random identity even on an insecure document.
  const documentId = typeof crypto.randomUUID === "function" ? crypto.randomUUID()
    : Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
  let sequence = 0;
  let enabled = true;
  const interactions = [];
  const now = () => performance.timeOrigin + performance.now();
  const observation = () => ({ documentId, sequence, enabled, observedAt: now(), interactions: interactions.slice() });
  const teardown = () => {
    enabled = false;
    for (const type of types) removeEventListener(type, observe, true);
    // Invalidated bindings can throw even while removing a listener.
    try { runtime?.onMessage.removeListener(receive); } catch {}
    if (globalThis.__ckAgentSentinel === state) delete globalThis.__ckAgentSentinel;
  };
  const isAlive = () => {
    if (!enabled) return false;
    try { if (runtime?.id) return true; } catch {}
    teardown();
    return false;
  };
  const notify = () => {
    if (!isAlive()) return;
    try {
      runtime.sendMessage({ kind: "agent-interaction", ...observation() }).catch(() => {});
    } catch { teardown(); }
  };
  const observe = (event) => {
    if (!event.isTrusted || !isAlive()) return;
    sequence += 1;
    // Event time, rather than message delivery time, identifies input within a
    // debugger attachment. Keep bounded history so sampling can catch delayed
    // notifications without extending the action window past detach. The
    // event type (one of `types` below) lets a refusal name what moved the
    // interaction epoch; it says nothing about the page or its content.
    interactions.push({ sequence, at: now(), kind: event.type });
    if (interactions.length > 256) interactions.shift();
    notify();
  };
  const types = ["pointerdown", "pointerup", "mousedown", "mouseup", "click", "dblclick", "keydown", "keyup", "beforeinput", "input", "wheel", "touchstart", "touchend"];
  for (const type of types) addEventListener(type, observe, { capture: true, passive: true });
  const receive = (message, sender, reply) => {
    if (!isAlive() || sender.id !== runtime.id || !message || message.kind !== "agent-sentinel") return;
    if (message.operation === "disable") teardown();
    reply(observation());
  };
  const state = { isAlive };
  globalThis.__ckAgentSentinel = state;
  if (!isAlive()) return;
  try {
    runtime.onMessage.addListener(receive);
    notify();
  } catch { teardown(); }
})();
