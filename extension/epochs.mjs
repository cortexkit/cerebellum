import { bounded, Refusal } from "./errors.mjs";
import { diagnosticErrorMessage, diagnosticReason, probeReadDiagnostic } from "./read-diagnostics.mjs";

export const observerUnavailable = () => new Refusal("observer_unavailable", "The interaction observer is unavailable; take a fresh read after the page commits. If it stays unavailable, restore extension access or reload the page.");
const markUnavailable = record => {
  if (!record.coverageLost) record.continuity += 1;
  record.coverageLost = true;
  record.available = false;
};

// Only group members are instrumented. The observer has no debugger dependency,
// so human input while the per-action debugger is detached still invalidates refs.
export class InteractionEpochs {
  constructor(chrome, tabs, now = () => performance.timeOrigin + performance.now()) {
    this.chrome = chrome;
    this.tabs = tabs;
    this.records = new Map();
    this.now = now;
    this.installing = new Map();
  }

  record(tabId) {
    if (!this.records.has(tabId)) this.records.set(tabId, { epoch: 0, continuity: 0, documents: new Map(), actions: [], available: false, coverageLost: false, installAttempts: new Map(), navigationGeneration: 0, confirmedDocuments: new Map() });
    return this.records.get(tabId);
  }

    bump(tabId) {
    if (!this.tabs.tabs.has(tabId)) return;
    const record = this.record(tabId);
    // markUnavailable changes continuity, which input compares with its saved
    // read. Missing coverage must not also increment the interaction counter.
    if (!record.coverageLost) record.epoch += 1;
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
    try { this.accept(sender.tab.id, sender.frameId, message); }
    catch (error) { markUnavailable(this.record(sender.tab.id)); throw error; }
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

    async sample(tabId, stage = "sample", recover = false) {
    await this.tabs.eligible(tabId);
    const record = this.record(tabId);
    if (!recover && record.coverageLost) throw observerUnavailable();
    const generation = record.navigationGeneration;
    let frames;
    try { frames = await bounded(this.chrome.webNavigation.getAllFrames({ tabId }), "dispatch"); }
    catch (error) {
      probeReadDiagnostic("sample_failed", { tabId, stage, step: "frame_list", reason: diagnosticReason(error) });
      markUnavailable(record);
      throw observerUnavailable();
    }
    if (!frames?.length || frames.length > 256 || frames.some(frame => !Number.isSafeInteger(frame.frameId) || frame.frameId < 0)) {
      markUnavailable(record);
      probeReadDiagnostic("sample_failed", { tabId, stage, step: "frame_list", reason: frames?.length ? "observer_unavailable" : "no_frames", frameCount: frames?.length ?? 0 });
      throw observerUnavailable();
    }
    const live = new Set(frames.map(frame => frame.frameId));
    for (const id of record.documents.keys()) {
      if (!live.has(id)) { record.documents.delete(id); record.continuity += 1; }
    }
    for (const frame of frames) {
      await this.tabs.eligible(tabId);
      const request = () => bounded(this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "sample" }, frame.documentId ? { documentId: frame.documentId } : { frameId: frame.frameId }), "dispatch");
      let observation;
      try { observation = await request(); }
      catch (error) {
        const reason = diagnosticReason(error);
        probeReadDiagnostic("sample_failed", { tabId, stage, step: "frame_message", frameId: frame.frameId, reason });
        markUnavailable(record);
        // A fresh read may repair a missing receiver once. Input checks never
        // reinstall: events since the saved read may have gone unobserved, so
        // only a new successful read may establish another input baseline.
        if (!recover || !["no_receiver", "port_closed"].includes(reason)) throw observerUnavailable();
        await this.install(tabId, frame.frameId, frame.documentId, true);
        try { observation = await request(); }
        catch (retryError) {
          probeReadDiagnostic("sample_failed", { tabId, stage, step: "frame_message", frameId: frame.frameId, reason: diagnosticReason(retryError) });
          throw observerUnavailable();
        }
      }
      const previous = record.documents.get(frame.frameId);
      try { this.accept(tabId, frame.frameId, observation); }
      catch (error) {
        markUnavailable(record);
        probeReadDiagnostic("sample_failed", { tabId, stage, step: "observation", frameId: frame.frameId,
          reason: diagnosticReason(error), enabled: observation?.enabled, sequence: observation?.sequence,
          previousSequence: previous?.sequence, historyLength: Array.isArray(observation?.interactions) ? observation.interactions.length : undefined,
          sameDocument: typeof observation?.documentId === "string" && observation.documentId === previous?.documentId });
        throw observerUnavailable();
      }
    }
    await this.tabs.eligible(tabId);
    if (generation !== record.navigationGeneration) {
      markUnavailable(record);
      throw observerUnavailable();
    }
    record.available = true;
    record.confirmedDocuments = new Map(frames.map(frame => [frame.frameId, frame.documentId]));
    if (recover) record.coverageLost = false;
    const sampledThrough = Math.min(...[...record.documents.values()].map(document => document.observedAt));
    record.actions = record.actions.filter(action => action.end === null || action.end > sampledThrough);
    return record.epoch;
  }

  async install(tabId, frameId, documentId, retry = false) {
    await this.tabs.eligible(tabId);
    const record = this.record(tabId);
    if (frameId === undefined) {
      let frames;
      try { frames = await bounded(this.chrome.webNavigation.getAllFrames({ tabId }), "dispatch"); }
      catch { markUnavailable(record); return false; }
      if (!frames?.length || frames.length > 256 || frames.some(frame => !Number.isSafeInteger(frame.frameId) || frame.frameId < 0)) { markUnavailable(record); return false; }
      const installed = await Promise.all(frames.map(frame => this.install(tabId, frame.frameId, frame.documentId)));
      return installed.every(Boolean);
    }
    const slot = frameId;
    const key = `${tabId}:${slot}:${documentId ?? ""}`;
    if (this.installing.has(key)) return this.installing.get(key);
    let attempts = record.installAttempts.get(slot);
    if (!attempts || attempts.documentId !== documentId) {
      attempts = { documentId, count: 0, installed: false };
      record.installAttempts.set(slot, attempts);
    }
    if (attempts.installed && !retry) return true;
    // One commit-time attempt and one read-time retry per document. A missing
    // receiver must never turn repeated reads into an unbounded injection loop.
    if (attempts.count >= 2) return false;
    attempts.count += 1;
    const task = (async () => {
      try {
        const target = documentId ? { tabId, documentIds: [documentId] } : { tabId, frameIds: [frameId] };
        await bounded(this.chrome.scripting.executeScript({ target, files: ["sentinel.js"], world: "ISOLATED", injectImmediately: true }), "dispatch");
        await this.tabs.eligible(tabId);
        if (this.records.get(tabId) !== record || record.installAttempts.get(slot) !== attempts) return false;
        attempts.installed = true;
        return true;
      } catch (error) {
        if (record.installAttempts.get(slot) === attempts) markUnavailable(record);
        // A late injection may finish after withdrawal's first disable. This
        // release-only cleanup targets that document and reads no page state.
        if (!this.tabs.tabs.has(tabId)) {
          await bounded(this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "disable" }, documentId ? { documentId } : { frameId }), "cancel").catch(() => {});
        }
        probeReadDiagnostic("observer_install_failed", { tabId, frameId, step: "observer_install", reason: diagnosticReason(error), errorMessage: diagnosticErrorMessage(error), continuity: record.continuity });
        return false;
      }
    })();
    this.installing.set(key, task);
    try { return await task; }
    finally { this.installing.delete(key); }
  }

  async committed(tabId, frameId, documentId) {
    await this.tabs.eligible(tabId);
    const record = this.record(tabId);
    if (documentId) {
      let frames;
      try { frames = await bounded(this.chrome.webNavigation.getAllFrames({ tabId }), "dispatch"); }
      catch { markUnavailable(record); return false; }
      const live = frames?.find(frame => frame.frameId === frameId);
      if (live?.documentId && live.documentId !== documentId) return false;
    }
    // A delayed commit event for the exact document already sampled must not
    // invalidate the successful read that confirmed its observer.
    if (documentId && record.available && !record.coverageLost && record.confirmedDocuments.get(frameId) === documentId) return this.install(tabId, frameId, documentId);
    record.navigationGeneration += 1;
    markUnavailable(record);
    if (!documentId) record.installAttempts.delete(frameId);
    return this.install(tabId, frameId, documentId);
  }

  async check(tabId, expected, continuity) {
    const actual = await this.sample(tabId, "input_check");
    if (Number.isSafeInteger(continuity) && this.record(tabId).continuity !== continuity) throw observerUnavailable();
    if (!Number.isSafeInteger(expected) || actual !== expected) throw new Refusal("interaction_epoch_changed");
  }

  async disable(tabId) {
    this.forget(tabId);
    await this.chrome.tabs.sendMessage(tabId, { kind: "agent-sentinel", operation: "disable" }).catch(() => {});
  }
}
