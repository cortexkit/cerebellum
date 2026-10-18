import { bounded, Refusal } from "./errors.mjs";
import { diagnosticReason, probeReadDiagnostic } from "./read-diagnostics.mjs";

// Only group members are instrumented. The observer has no debugger dependency,
// so human input while the per-action debugger is detached still invalidates refs.
export class InteractionEpochs {
  constructor(chrome, tabs, now = () => performance.timeOrigin + performance.now()) {
    this.chrome = chrome;
    this.tabs = tabs;
    this.records = new Map();
    this.now = now;
  }

  record(tabId) {
    if (!this.records.has(tabId)) this.records.set(tabId, { epoch: 0, continuity: 0, documents: new Map(), actions: [] });
    return this.records.get(tabId);
  }

  bump(tabId) {
    if (this.tabs.tabs.has(tabId)) this.record(tabId).epoch += 1;
  }

  forget(tabId) {
    this.records.delete(tabId);
  }

  beginAction(tabId) {
    const action = { start: this.now(), end: null };
    this.record(tabId).actions.push(action);
    return action;
  }

  endAction(action) {
    if (action && action.end === null) action.end = this.now();
  }

  async observe(message, sender) {
    if (!sender.tab || sender.id !== this.chrome.runtime.id) return;
    try { await this.tabs.eligible(sender.tab.id); } catch { return; }
    this.accept(sender.tab.id, sender.frameId, message);
  }

  accept(tabId, frameId, observation) {
    if (!observation || ("enabled" in observation && !observation.enabled) || typeof observation.documentId !== "string" || !Number.isSafeInteger(observation.sequence) || observation.sequence < 0 || !Number.isFinite(observation.observedAt) || !Array.isArray(observation.interactions)) {
      throw new Refusal("interaction_continuity_lost");
    }
    const record = this.record(tabId);
    const previous = record.documents.get(frameId);
    const sameDocument = previous?.documentId === observation.documentId;
    if (sameDocument && observation.sequence < previous.sequence) {
      return; // An older asynchronous notification cannot roll the counter back.
    }
    let sequence = sameDocument ? previous.sequence : 0;
    let increments = 0;
    for (const event of observation.interactions) {
      if (!Number.isSafeInteger(event.sequence) || !Number.isFinite(event.at) || event.at > observation.observedAt) throw new Refusal("interaction_continuity_lost");
      if (event.sequence <= sequence) continue;
      if (event.sequence !== sequence + 1) throw new Refusal("interaction_continuity_lost");
      sequence = event.sequence;
      if (!record.actions.some(action => event.at >= action.start && (action.end === null || event.at < action.end))) increments += 1;
    }
    // A truncated history cannot prove which side of attach/detach the missing
    // input belongs to. Fail closed instead of discounting unknown events.
    if (sequence !== observation.sequence) throw new Refusal("interaction_continuity_lost");
    if (!sameDocument) record.continuity += 1;
    record.epoch += increments;
    record.documents.set(frameId, { documentId: observation.documentId, sequence, observedAt: Math.max(sameDocument ? previous.observedAt : 0, observation.observedAt) });
  }

  async sample(tabId, stage = "sample") {
    try { await this.tabs.eligible(tabId); }
    catch (error) {
      probeReadDiagnostic("sample_failed", { tabId, stage, step: "membership", reason: diagnosticReason(error) });
      throw error;
    }
    let frames;
    try { frames = await bounded(this.chrome.webNavigation.getAllFrames({ tabId }), "dispatch"); }
    catch (error) {
      probeReadDiagnostic("sample_failed", { tabId, stage, step: "frame_list", reason: diagnosticReason(error) });
      throw error;
    }
    if (!frames?.length) {
      probeReadDiagnostic("sample_failed", { tabId, stage, step: "frame_list", reason: "no_frames", frameCount: 0 });
      throw new Refusal("interaction_continuity_lost");
    }
    const record = this.record(tabId);
    const live = new Set(frames.map(frame => frame.frameId));
    for (const id of record.documents.keys()) {
      if (!live.has(id)) { record.documents.delete(id); record.continuity += 1; }
    }
    for (const frame of frames) {
      try { await this.tabs.eligible(tabId); }
      catch (error) {
        probeReadDiagnostic("sample_failed", { tabId, stage, step: "membership", frameId: frame.frameId, reason: diagnosticReason(error) });
        throw error;
      }
      let observation;
      try {
        observation = await bounded(this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "sample" }, { frameId: frame.frameId }), "dispatch");
      } catch (error) {
        // Missing frame coverage invalidates input; it is never inferred from a
        // previous successful snapshot or an observer in a different document.
        probeReadDiagnostic("sample_failed", { tabId, stage, step: "frame_message", frameId: frame.frameId, reason: diagnosticReason(error) });
        throw new Refusal("interaction_continuity_lost");
      }
      const previous = record.documents.get(frame.frameId);
      try { this.accept(tabId, frame.frameId, observation); }
      catch (error) {
        probeReadDiagnostic("sample_failed", { tabId, stage, step: "observation", frameId: frame.frameId,
          reason: diagnosticReason(error), enabled: observation?.enabled, sequence: observation?.sequence,
          previousSequence: previous?.sequence, historyLength: Array.isArray(observation?.interactions) ? observation.interactions.length : undefined,
          sameDocument: typeof observation?.documentId === "string" && observation.documentId === previous?.documentId });
        throw error;
      }
    }
    await this.tabs.eligible(tabId);
    // Once every live frame has been sampled beyond a closed window, later
    // sequence advances cannot contain its events; stale messages are ignored.
    const sampledThrough = Math.min(...[...record.documents.values()].map(document => document.observedAt));
    record.actions = record.actions.filter(action => action.end === null || action.end > sampledThrough);
    return record.epoch;
  }

  async install(tabId, frameId) {
    await this.tabs.eligible(tabId);
    try {
      const target = frameId === undefined ? { tabId, allFrames: true } : { tabId, frameIds: [frameId] };
      await bounded(this.chrome.scripting.executeScript({ target, files: ["sentinel.js"], world: "ISOLATED" }), "dispatch");
    } catch (error) {
      // Restricted pages, about:blank and frames without coverage remain readable
      // by CDP, but cannot establish an input baseline until observers are live.
      this.record(tabId).continuity += 1;
      probeReadDiagnostic("observer_install_failed", { tabId, frameId, step: "observer_install", reason: diagnosticReason(error), continuity: this.record(tabId).continuity });
    }
  }

  async check(tabId, expected) {
    const actual = await this.sample(tabId, "input_check");
    if (!Number.isSafeInteger(expected) || actual !== expected) throw new Refusal("interaction_epoch_changed");
  }

  async disable(tabId) {
    this.forget(tabId);
    await this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "disable" }).catch(() => {});
  }
}
