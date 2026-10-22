// This isolated-world observer stays alive between debugger attachments. It never
// reads page text, field values or URLs; only trusted interaction times.
(() => {
  if (globalThis.__ckAgentSentinel) return;
  // randomUUID is secure-context-only; getRandomValues also works on HTTP.
  // Keep a cryptographically random identity even on an insecure document.
  const documentId = typeof crypto.randomUUID === "function" ? crypto.randomUUID()
    : Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
  let sequence = 0;
  let enabled = true;
  const interactions = [];
  const now = () => performance.timeOrigin + performance.now();
  const observation = () => ({ documentId, sequence, enabled, observedAt: now(), interactions: interactions.slice() });
  const notify = () => {
    chrome.runtime.sendMessage({ kind: "agent-interaction", ...observation() }).catch(() => {});
  };
  const observe = (event) => {
    if (!enabled || !event.isTrusted) return;
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
    if (sender.id !== chrome.runtime.id || !message || message.kind !== "agent-sentinel") return;
    if (message.operation === "disable") {
      enabled = false;
      for (const type of types) removeEventListener(type, observe, true);
      chrome.runtime.onMessage.removeListener(receive);
      delete globalThis.__ckAgentSentinel;
    }
    reply(observation());
  };
  chrome.runtime.onMessage.addListener(receive);
  globalThis.__ckAgentSentinel = true;
  notify();
})();
