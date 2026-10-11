// This isolated-world observer stays alive between debugger attachments. It never
// reads page text, field values or URLs; only trusted interaction fingerprints.
(() => {
  if (globalThis.__ckAgentSentinel) return;
  const documentId = crypto.randomUUID();
  let sequence = 0;
  let enabled = true;
  let ticket = null;
  const notify = () => {
    chrome.runtime.sendMessage({ kind: "agent-interaction", documentId, sequence }).catch(() => {});
  };
  const matches = (event, expected) => {
    if (event.type !== expected.type) return false;
    for (const key of ["clientX", "clientY", "button", "key", "code", "data", "inputType", "deltaX", "deltaY"]) {
      if (key in expected && event[key] !== expected[key]) return false;
    }
    return true;
  };
  const observe = (event) => {
    if (!enabled || !event.isTrusted) return;
    const now = performance.now();
    if (ticket && now <= ticket.expires && ticket.events.length && matches(event, ticket.events[0])) {
      ticket.events.shift();
      return;
    }
    ticket = null;
    sequence += 1;
    notify();
  };
  const types = ["pointerdown", "pointerup", "pointermove", "mousedown", "mouseup", "mousemove", "click", "dblclick", "keydown", "keyup", "beforeinput", "input", "wheel", "touchstart", "touchend"];
  for (const type of types) addEventListener(type, observe, { capture: true, passive: true });
  const receive = (message, sender, reply) => {
    if (sender.id !== chrome.runtime.id || !message || message.kind !== "agent-sentinel") return;
    if (message.operation === "disable") {
      enabled = false;
      ticket = null;
      for (const type of types) removeEventListener(type, observe, true);
      chrome.runtime.onMessage.removeListener(receive);
      delete globalThis.__ckAgentSentinel;
    } else if (message.operation === "arm" && enabled) {
      // A ticket is one-shot, short-lived and only covers the exact events of a
      // debugger input step. Anything else, including ambiguous input, is human.
      ticket = { events: message.events.slice(), expires: performance.now() + 250 };
    } else if (message.operation === "disarm") {
      ticket = null;
    }
    reply({ documentId, sequence, enabled });
  };
  chrome.runtime.onMessage.addListener(receive);
  globalThis.__ckAgentSentinel = true;
  notify();
})();
