import { bounded, Refusal } from "./errors.mjs";

// Only group members are instrumented. The observer has no debugger dependency,
// so human input while the per-action debugger is detached still invalidates refs.
export class InteractionEpochs {
  constructor(chrome, tabs) {
    this.chrome = chrome;
    this.tabs = tabs;
    this.records = new Map();
  }

  record(tabId) {
    if (!this.records.has(tabId)) this.records.set(tabId, { epoch: 0, continuity: 0, documents: new Map() });
    return this.records.get(tabId);
  }

  bump(tabId) {
    if (this.tabs.tabs.has(tabId)) this.record(tabId).epoch += 1;
  }

  forget(tabId) {
    this.records.delete(tabId);
  }

  async observe(message, sender) {
    if (!sender.tab || sender.id !== this.chrome.runtime.id) return;
    try { await this.tabs.eligible(sender.tab.id); } catch { return; }
    this.accept(sender.tab.id, sender.frameId, message);
  }

  accept(tabId, frameId, observation) {
    if (!observation || ("enabled" in observation && !observation.enabled) || typeof observation.documentId !== "string" || !Number.isSafeInteger(observation.sequence) || observation.sequence < 0) {
      throw new Refusal("interaction_continuity_lost");
    }
    const record = this.record(tabId);
    const previous = record.documents.get(frameId);
    if (!previous || previous.documentId !== observation.documentId) {
      record.continuity += 1;
      record.epoch += observation.sequence;
    } else if (observation.sequence > previous.sequence) {
      record.epoch += observation.sequence - previous.sequence;
    } else if (observation.sequence < previous.sequence) {
      return; // An older asynchronous notification cannot roll the counter back.
    }
    record.documents.set(frameId, { documentId: observation.documentId, sequence: observation.sequence });
  }

  async sample(tabId) {
    await this.tabs.eligible(tabId);
    const frames = await bounded(this.chrome.webNavigation.getAllFrames({ tabId }), "dispatch");
    if (!frames?.length) throw new Refusal("interaction_continuity_lost");
    const record = this.record(tabId);
    const live = new Set(frames.map(frame => frame.frameId));
    for (const id of record.documents.keys()) {
      if (!live.has(id)) { record.documents.delete(id); record.continuity += 1; }
    }
    for (const frame of frames) {
      await this.tabs.eligible(tabId);
      let observation;
      try {
        observation = await bounded(this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "sample" }, { frameId: frame.frameId }), "dispatch");
      } catch {
        // Missing frame coverage invalidates input; it is never inferred from a
        // previous successful snapshot or an observer in a different document.
        throw new Refusal("interaction_continuity_lost");
      }
      this.accept(tabId, frame.frameId, observation);
    }
    await this.tabs.eligible(tabId);
    return record.epoch;
  }

  async install(tabId, frameId) {
    await this.tabs.eligible(tabId);
    try {
      const target = frameId === undefined ? { tabId, allFrames: true } : { tabId, frameIds: [frameId] };
      await bounded(this.chrome.scripting.executeScript({ target, files: ["sentinel.js"], world: "ISOLATED" }), "dispatch");
    } catch {
      // Restricted pages, about:blank and frames without coverage remain readable
      // by CDP, but cannot establish an input baseline until observers are live.
      this.record(tabId).continuity += 1;
    }
  }

  async check(tabId, expected) {
    const actual = await this.sample(tabId);
    if (!Number.isSafeInteger(expected) || actual !== expected) throw new Refusal("interaction_epoch_changed");
  }

  async arm(tabId, frameId, events) {
    await this.tabs.eligible(tabId);
    await bounded(this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "arm", events }, { frameId }), "dispatch");
  }

  async disarm(tabId, frameId) {
    await this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "disarm" }, { frameId }).catch(() => {});
  }

  async disable(tabId) {
    this.forget(tabId);
    await this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "disable" }).catch(() => {});
  }
}
