// This isolated-world observer stays alive between debugger attachments. It never
// reads page text, field values or URLs; only trusted interaction times.
(() => {
  if (globalThis.__ckAgentSentinel) return;
  const documentId = crypto.randomUUID();
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
    // notifications without extending the action window past detach.
    interactions.push({ sequence, at: now() });
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
