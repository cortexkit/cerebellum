import { bounded, Refusal } from "./errors.mjs";
import { diagnosticErrorMessage, diagnosticReason, probeReadDiagnostic } from "./read-diagnostics.mjs";

export const observerUnavailable = () => new Refusal("observer_unavailable", "The interaction observer is unavailable; take a fresh read after the page commits. If it stays unavailable, restore extension access or reload the page.");
const markUnavailable = record => {
  if (!record.coverageLost) record.continuity += 1;
  record.coverageLost = true;
  record.available = false;
};

// The trusted event types sentinel.js counts. Keep this list identical to its
// `types` (a test compares them): a cause code names only one of these.
export const OBSERVED_INPUT_EVENTS = ["pointerdown", "pointerup", "mousedown", "mouseup", "click", "dblclick", "keydown", "keyup", "beforeinput", "input", "wheel", "touchstart", "touchend"];
const frameKind = frameId => frameId === 0 ? "main" : "subframe";
// Why the interaction epoch last moved, as a short closed code returned with
// the document state: `input.<event>.<main|subframe>` or `navigation.main`.
// It names an event type and a frame kind, never page text or a URL.
const inputCause = (kind, frameId) => OBSERVED_INPUT_EVENTS.includes(kind) ? `input.${kind}.${frameKind(frameId)}` : undefined;

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
    if (!this.records.has(tabId)) this.records.set(tabId, { epoch: 0, continuity: 0, documents: new Map(), actions: [], available: false, coverageLost: false, installAttempts: new Map(), navigationGeneration: 0, confirmedDocuments: new Map(), cause: undefined });
    return this.records.get(tabId);
  }

  // A navigation the agent did not start. Only the main frame counts: a
  // person starts a main-frame navigation from the browser itself (address
  // bar, back, reload) with no page input to observe. A child frame navigates
  // by page script, by input inside a frame, or by the back button walking a
  // frame's history. Input inside any live frame is already counted there,
  // since every live frame runs the observer (a sample needs every frame to
  // answer), and the child's new document changes continuity when it
  // commits, which refuses saved input as observer_unavailable.
  bump(tabId, frameId = 0) {
    if (!this.tabs.tabs.has(tabId) || frameId !== 0) return;
    const record = this.record(tabId);
    // markUnavailable changes continuity, which input compares with its saved
    // read. Missing coverage must not also increment the interaction counter.
    if (!record.coverageLost) {
      record.epoch += 1;
      record.cause = "navigation.main";
    }
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
    let cause;
    for (const event of observation.interactions) {
      if (!Number.isSafeInteger(event.sequence) || !Number.isFinite(event.at) || event.at > observation.observedAt) throw new Refusal("interaction_continuity_lost");
      if (event.sequence <= sequence) continue;
      if (event.sequence !== sequence + 1) throw new Refusal("interaction_continuity_lost");
      sequence = event.sequence;
      if (!record.actions.some(action => event.at >= action.start && (action.end === null || event.at < action.end))) {
        increments += 1;
        cause = inputCause(event.kind, frameId);
      }
    }
    // A truncated history cannot prove which side of attach/detach the missing
    // input belongs to. Fail closed instead of discounting unknown events.
    if (sequence !== observation.sequence) throw new Refusal("interaction_continuity_lost");
    if (!sameDocument) record.continuity += 1;
    record.epoch += increments;
    if (increments) record.cause = cause;
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
    // Share a two-injection budget between permission-binding recovery and a
    // fresh read's missing-receiver repair; neither can create an endless loop.
    if (attempts.count >= 2) return false;
    const task = (async () => {
      while (attempts.count < 2) {
        // The site's agent grant and Chrome's extension host access are separate
        // permissions. An initial blank tab has no HTTP host to confirm; a blank
        // child may inherit its live parent's access. Never prompt here.
        let frame;
        let allowed = false;
        let documentKind = "other";
        try {
          const frames = await bounded(this.chrome.webNavigation.getAllFrames({ tabId }), "dispatch");
          frame = frames?.find(frame => frame.frameId === frameId);
          if (!frame || documentId && frame.documentId !== documentId) return false;
          let url = new URL(frame.url);
          documentKind = ["http:", "https:"].includes(url.protocol) ? "http" : url.href === "about:blank" ? "blank" : "other";
          let authority = frame;
          const seen = new Set();
          while (["about:blank", "about:srcdoc"].includes(url.href) && authority.parentFrameId >= 0 && !seen.has(authority.frameId)) {
            seen.add(authority.frameId);
            authority = frames.find(parent => parent.frameId === authority.parentFrameId);
            if (!authority) break;
            url = new URL(authority.url);
          }
          if (["http:", "https:"].includes(url.protocol)) allowed = await bounded(this.chrome.permissions.contains({ origins: [`${url.protocol}//${url.hostname}/*`] }), "dispatch");
        } catch { /* Unknown host access cannot authorize injection. */ }
        probeReadDiagnostic("observer_access", { tabId, frameId, documentKind, allowed, attempt: attempts.count });
        if (!allowed) { markUnavailable(record); return false; }
        await this.tabs.eligible(tabId);
        if (this.records.get(tabId) !== record || record.installAttempts.get(slot) !== attempts) return false;
        attempts.count += 1;
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
          if (diagnosticReason(error) !== "host_permission_missing" || attempts.count >= 2 || !this.tabs.tabs.has(tabId)) return false;
          // Chrome may acknowledge host access before its document binding is
          // ready. Reconfirm the same document/access before one bounded retry.
          await new Promise(resolve => setTimeout(resolve, 25));
        }
      }
      return false;
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
    if (documentId && record.available && !record.coverageLost && record.confirmedDocuments.get(frameId) === documentId) {
      probeReadDiagnostic("observer_commit", { tabId, frameId, invalidated: false, continuity: record.continuity });
      return this.install(tabId, frameId, documentId);
    }
    record.navigationGeneration += 1;
    markUnavailable(record);
    // Coverage is tab-wide: a new child document invalidates the saved read,
    // but only that child's receiver is installed. The parent is not disabled.
    probeReadDiagnostic("observer_commit", { tabId, frameId, invalidated: true, continuity: record.continuity });
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
