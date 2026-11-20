import { observerUnavailable } from "./epochs.mjs";
import { bounded, Refusal } from "./errors.mjs";
import { classifyCommand, resolveParams, verifyRuntime } from "./commands.mjs";
import { Frames } from "./frames.mjs";
import { FrameGeometry } from "./frame-geometry.mjs";
import { diagnosticReason, probeReadDiagnostic } from "./read-diagnostics.mjs";
import { attachFailureKind, attachRefusal } from "./attach-errors.mjs";

const routeKey = route => `${route.channel}:${route.epoch}`;
const closed = (value, fields) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every(key => fields.includes(key));

// chrome.debugger.sendCommand rejects with an Error whose message is Chrome's
// CDP error object serialized as JSON, for example
// {"code":-32000,"message":"DOM agent hasn't been enabled"}. Relay only that
// code and its fixed protocol message, so cerebellum can say which command
// failed and why. Chrome's optional `data` field is dropped, and any other
// rejection, or a message that is long or multi-line, keeps the generic text.
const MAX_CDP_ERROR_MESSAGE = 200;

// The release a press or key-down owes, keyed by the button or key it holds,
// or null for any other command.
function releaseOwed({ method, params }) {
  if (method === "Input.dispatchMouseEvent" && params?.type === "mousePressed") {
    return { key: `mouse:${params.button}`, release: { method, params: { ...params, type: "mouseReleased" } } };
  }
  if (method === "Input.dispatchKeyEvent" && (params?.type === "keyDown" || params?.type === "rawKeyDown")) {
    // A key-up types nothing, so it carries the key's identity only.
    const { text: _text, unmodifiedText: _unmodifiedText, autoRepeat: _autoRepeat, ...identity } = params;
    return { key: heldKey(params), release: { method, params: { ...identity, type: "keyUp" } } };
  }
  return null;
}

// The button or key whose release this command is, or null.
function releaseDischarged({ method, params }) {
  if (method === "Input.dispatchMouseEvent" && params?.type === "mouseReleased") return `mouse:${params.button}`;
  if (method === "Input.dispatchKeyEvent" && params?.type === "keyUp") return heldKey(params);
  return null;
}

const heldKey = params => `key:${params.code ?? params.key ?? params.windowsVirtualKeyCode}`;
export function debuggerError(error) {
  try {
    const cdp = JSON.parse(error?.message);
    if (Number.isSafeInteger(cdp?.code) && typeof cdp.message === "string" && cdp.message.length <= MAX_CDP_ERROR_MESSAGE && !/[\u0000-\u001f\u007f]/.test(cdp.message)) {
      return { code: cdp.code, message: cdp.message };
    }
  } catch { /* Not a CDP error object. */ }
  return { code: Number.isInteger(error?.code) ? error.code : -32000, message: "Chrome debugger command failed" };
}

export function validatePlan(plan) {
  if (!closed(plan, ["version", "action", "tab", "url", "opener_tab", "interaction_epoch", "observer_continuity", "commands"]) || plan.version !== 2) throw new Refusal("invalid_plan", "update cerebellum and the extension together");
  const fields = {
    status: ["version", "action"], close: ["version", "action"],
    open_tab: ["version", "action", "url", "opener_tab"], claim_tab: ["version", "action", "tab"],
    cdp: ["version", "action", "tab", "interaction_epoch", "observer_continuity", "commands"],
  }[plan.action];
  if (!fields || !closed(plan, fields)) throw new Refusal("invalid_plan", "use a supported extension action");
  if (["claim_tab", "cdp"].includes(plan.action) && typeof plan.tab !== "string") throw new Refusal("invalid_plan");
  if ("url" in plan && typeof plan.url !== "string" || "opener_tab" in plan && typeof plan.opener_tab !== "string") throw new Refusal("invalid_plan");
  if (plan.action === "cdp") {
    if (!Array.isArray(plan.commands) || !plan.commands.length || plan.commands.length > 256) throw new Refusal("invalid_plan");
    for (const command of plan.commands) {
      // Chrome can expose an empty loader before a document commits. Preserve
      // top-level reads; frame resolution still rejects such a scope for input.
      if (!closed(command, ["method", "params", "frame_id", "session_id", "loader_id"]) || ["frame_id", "session_id", "loader_id"].some(key => key in command && (typeof command[key] !== "string" || !command[key] && key !== "loader_id")) || ["frame_id", "session_id", "loader_id"].some(key => key in command) && !["frame_id", "session_id", "loader_id"].every(key => key in command)) throw new Refusal("invalid_plan", "provide the complete verified frame scope");
      classifyCommand(command);
    }
  }
  return plan;
}

export class Agent {
  constructor(chrome, tabs, epochs) {
    this.chrome = chrome;
    this.tabs = tabs;
    this.epochs = epochs;
    this.claims = new Map();
    this.baselines = new Map();
    this.blankNavigations = new Map();
    this.active = new Set();
    this.connectionEpoch = null;
    this.navigation = new Map();
    this.popupFlags = new Set();
    this.pendingAttaches = new Set();
  }

  connect(epoch) {
    this.connectionEpoch = epoch;
    for (const state of this.active) state.cancelWait?.();
    this.claims.clear();
    this.blankNavigations.clear();
    probeReadDiagnostic("baseline_cleared", { reason: "connected", baselineCount: this.baselines.size });
    this.baselines.clear();
  }

  async disconnect() {
    this.connectionEpoch = null;
    const active = [...this.active];
    for (const state of active) state.cancelled = true;
    await Promise.all(active.map(state => this.detach(state)));
    // A dropped native port ends claims, not handovers. Handed tabs stay in
    // the recorded Agent group with their handles, so a reconnect lists them
    // as unclaimed and an agent re-claims. Only the person gives tabs back
    // (drag-out, close, toolbar toggle), or a tab whose recorded group no
    // longer resolves is withdrawn on its next membership check.
    this.claims.clear();
    this.blankNavigations.clear();
    probeReadDiagnostic("baseline_cleared", { reason: "disconnected", baselineCount: this.baselines.size });
    this.baselines.clear();
  }

  withdraw(tabId) {
    this.blankNavigations.delete(tabId);
    this.claims.delete(tabId);
    probeReadDiagnostic("baseline_cleared", { tabId, reason: "withdrawn", baselinePresent: this.baselines.has(tabId) });
    this.baselines.delete(tabId);
    this.epochs.forget(tabId);
    for (const state of this.active) if (state.tabId === tabId) {
      state.cancelled = true;
      void this.detach(state).catch(() => {});
    }
    void this.epochs.disable(tabId);
  }

  async release(key) {
    // A close can release claims while another call on the route is attached.
    // Cancel and detach that work before rotating handles or returning tabs.
    const active = [...this.active].filter(state => state.route === key && state.tabId !== undefined);
    for (const state of active) state.cancelled = true;
    await Promise.all(active.map(state => this.detach(state)));
    for (const [tabId, owner] of this.claims) {
      if (owner !== key) continue;
      this.claims.delete(tabId);
      this.blankNavigations.delete(tabId);
      probeReadDiagnostic("baseline_cleared", { tabId, reason: "released", baselinePresent: this.baselines.has(tabId) });
      this.baselines.delete(tabId);
      const record = this.tabs.tabs.get(tabId);
      if (!record) continue;
      if (record.kind === "handed") {
        this.tabs.withdraw(tabId);
        // Only a still-eligible handed tab is ungrouped. An externally withdrawn
        // tab is already the person's tab and must not be driven during cleanup.
        const tab = await this.chrome.tabs.get(tabId).catch(() => null);
        if (tab?.groupId === this.tabs.group?.id) await this.chrome.tabs.ungroup(tabId);
      } else {
        record.handle = crypto.randomUUID();
      }
    }
    await this.tabs.save();
  }

  async goodbye(route) {
    const key = routeKey(route);
    for (const state of this.active) if (state.route === key) state.cancelled = true;
    await Promise.all([...this.active].filter(state => state.route === key).map(state => this.detach(state)));
    // A route close ends that route's claims, not the person's handovers.
    // Handed tabs stay in the recorded Agent group with their handles, so a
    // reconnecting route lists them as unclaimed and claims them again.
    // Agent-opened tabs stay grouped too, with rotated handles, matching
    // the explicit close action's release() behaviour.
    for (const [tabId, owner] of [...this.claims]) {
      if (owner !== key) continue;
      this.claims.delete(tabId);
      this.blankNavigations.delete(tabId);
      probeReadDiagnostic("baseline_cleared", { tabId, reason: "released", baselinePresent: this.baselines.has(tabId) });
      this.baselines.delete(tabId);
      const record = this.tabs.tabs.get(tabId);
      if (record && record.kind !== "handed") record.handle = crypto.randomUUID();
    }
    await this.tabs.save();
  }

  // The route whose CDP plan has dispatched input to tabId and is still
  // attached there while that route holds the claim, or null. Only such a
  // plan can have caused a pop-up from tabId; a tab opened while no agent
  // input is in flight is the person's own action.
  inputRoute(tabId) {
    for (const state of this.active) {
      if (state.tabId === tabId && state.input && state.attached && this.claims.get(tabId) === state.route) return state.route;
    }
    return null;
  }

  alive(state) {
    if (state.cancelled || this.connectionEpoch !== state.epoch) throw new Refusal("cancelled");
  }

  async guard(state) {
    this.alive(state);
    if (state.tabId !== undefined) {
      await this.tabs.eligible(state.tabId);
      if (this.claims.get(state.tabId) !== state.route) throw new Refusal("tab_not_claimed", "claim the tab before using it");
    }
    this.alive(state);
  }

  async prepare(route, command, epoch) {
    const plan = validatePlan(command);
    for (const item of plan.commands ?? []) await verifyRuntime(item);
    const state = { plan, route: routeKey(route), epoch, cancelled: false, input: false, attached: false };
    this.active.add(state);
    try {
      this.alive(state);
      if (plan.action === "cdp") {
        state.tabId = (await this.tabs.resolve(plan.tab)).tabId;
        await this.guard(state);
        if (this.pendingAttaches.size) throw new Refusal("debugger_busy", "wait for debugger cleanup, then read again");
        state.attachSettled = false;
        // Attach is not dispatch: no Page, Runtime or Input commands run here.
        // A late attach completion still detaches even after timeout/cancellation.
        probeReadDiagnostic("debugger_timing", { tabId: state.tabId, phase: "attach_start" });
        const pending = this.attach(state).then(async () => {
          probeReadDiagnostic("debugger_timing", { tabId: state.tabId, phase: "attach_done" });
          state.attached = true;
          state.actionWindow = this.epochs.beginAction(state.tabId);
          if (state.cancelled || this.connectionEpoch !== state.epoch) {
            await this.detach(state);
            if (!state.attached) this.active.delete(state);
          }
        }).finally(() => {
          state.attachSettled = true;
          this.pendingAttaches.delete(pending);
          if (state.cancelled && !state.attached) this.active.delete(state);
        });
        this.pendingAttaches.add(pending);
        try { await bounded(pending, "attach"); } catch (error) {
          state.cancelled = true;
          if (error instanceof Refusal && error.reason !== "attach_deadline") throw error;
          throw attachRefusal(error);
        }
        await this.guard(state);
      }
      return state;
    } catch (error) {
      state.cancelled = true;
      try { await this.detach(state); } catch { /* Cleanup is unconfirmed; retain the state for disconnect cleanup. */ }
      error.detached = state.attachSettled !== false && !state.attached;
      if (error.detached) this.active.delete(state);
      throw error;
    }
  }

  async attach(state) {
    const target = { tabId: state.tabId };
    try {
      await this.chrome.debugger.attach(target, "1.3");
      return;
    } catch (error) {
      if (attachFailureKind(error) !== "another_debugger") throw error;
      // detach only affects this extension's session, but it must never take
      // an attachment away from another live plan of ours on the same tab.
      if ([...this.active].some(other => other !== state && other.tabId === state.tabId && other.attached)) throw attachRefusal(error, "active_plan");
      try { await this.chrome.debugger.detach(target); }
      catch { throw attachRefusal(error, "another_debugger"); }
      // A successful detach proves the busy session belonged to this extension.
      // Membership and cancellation may have changed while Chrome answered.
      await this.guard(state);
      await this.chrome.debugger.attach(target, "1.3");
    }
  }

  async detach(state) {
    state.cancelWait?.();
    if (!state.attached) return;
    if (state.detaching) return state.detaching;
    state.detaching = Promise.resolve().then(async () => {
      try { await this.releaseHeld(state); } finally {
        // Keep the window open until Chrome actually detaches, even if the
        // caller's deadline expires before the detach promise settles.
        probeReadDiagnostic("debugger_timing", { tabId: state.tabId, phase: "detach_start" });
        const pending = this.chrome.debugger.detach({ tabId: state.tabId }).then(() => {
          probeReadDiagnostic("debugger_timing", { tabId: state.tabId, phase: "detach_done" });
          state.attached = false;
          state.frames?.close();
          this.epochs.endAction(state.actionWindow);
          if (state.cancelled) this.active.delete(state);
        });
        await bounded(pending, "cancel");
      }
    }).finally(() => { state.detaching = null; });
    return state.detaching;
  }

  // Release-only cleanup for presses and key-downs this plan dispatched on this
  // attachment whose release Chrome has not acknowledged. A refusal (the tab
  // left the Agent group, or the person used the page) must not leave a button
  // or key held. Only the matching release is sent, to the target its press
  // went to; the plan is never resumed and no other input is dispatched. A release Chrome did not
  // acknowledge, or one that can no longer be sent because the debugger is
  // gone, is reported as unconfirmed.
  async releaseHeld(state) {
    if (state.releasing) return state.releasing;
    if (!state.held?.size) return;
    state.releasing = (async () => {
      let unconfirmed = !state.attached;
      if (state.attached) {
        for (const [key, { target, method, params }] of [...state.held]) {
          try {
            await bounded(this.chrome.debugger.sendCommand(target, method, params), "reply");
            state.held.delete(key);
          } catch { unconfirmed = true; }
        }
      }
      if (unconfirmed) throw new Refusal("input_release_unconfirmed", "read again", { input_dispatched: true });
    })();
    return state.releasing;
  }

  async cancel(state) {
    state.cancelled = true;
    await this.detach(state);
  }

  async finish(state) {
    try { await this.detach(state); } finally {
      if (!state.attached) this.active.delete(state);
    }
  }

  async wait(state, milliseconds) {
    this.alive(state);
    let timer;
    try {
      await new Promise((resolve, reject) => {
        state.cancelWait = () => reject(new Refusal("cancelled"));
        // Keep the debugger attached while the renderer draws, without sending
        // a command to the page. Cleanup wakes the wait without a polling delay.
        timer = setTimeout(resolve, Math.max(0, Math.min(milliseconds, 2000)));
      });
    } finally {
      clearTimeout(timer);
      delete state.cancelWait;
    }
    await this.guard(state);
    return {};
  }

  async execute(state) {
    const p = state.plan;
    await this.guard(state);
    if (p.action === "status") {
      const visible = [];
      // list() has just checked each member's membership; checking it again
      // per tab would double the Chrome calls for nothing.
      for (const tab of await this.tabs.list()) {
        const owner = this.claims.get(tab.tabId);
        if (owner && owner !== state.route || !owner && tab.kind !== "handed") continue;
        visible.push({ tab: tab.tab, claimed: owner === state.route, handed: tab.kind === "handed", interaction_epoch: this.epochs.record(tab.tabId).epoch });
      }
      return { tabs: visible, connection_epoch: state.epoch };
    }
    if (p.action === "close") {
      await this.release(state.route);
      return { connection_epoch: state.epoch };
    }
    if (p.action === "open_tab") {
      if (p.opener_tab) {
        const opener = await this.tabs.resolve(p.opener_tab);
        if (this.claims.get(opener.tabId) !== state.route) throw new Refusal("tab_not_claimed");
      }
      const tab = await this.tabs.open(p);
      state.tabId = tab.tabId;
      this.alive(state);
      this.claims.set(tab.tabId, state.route);
      if (!p.opener_tab && (!p.url || p.url === "about:blank")) this.blankNavigations.set(tab.tabId, state.route);
      await this.guard(state);
      await this.epochs.install(tab.tabId);
      return { tab: tab.handle, interaction_epoch: this.epochs.record(tab.tabId).epoch, connection_epoch: state.epoch };
    }
    if (p.action === "claim_tab") {
      const tab = await this.tabs.resolve(p.tab);
      const owner = this.claims.get(tab.tabId);
      if (owner && owner !== state.route) throw new Refusal("tab_claimed_by_other_route");
      if (!owner && tab.kind !== "handed") throw new Refusal("tab_not_handed", "hand the tab over using the extension");
      this.alive(state);
      this.claims.set(tab.tabId, state.route);
      state.tabId = tab.tabId;
      await this.guard(state);
      await this.epochs.install(tab.tabId);
      return { tab: tab.handle, interaction_epoch: this.epochs.record(tab.tabId).epoch, connection_epoch: state.epoch };
    }
    return this.executeCommands(state);
  }

  async executeCommands(state) {
    try {
      return await this.runCommands(state);
    } catch (error) {
      if (error instanceof Refusal && state.input) error.detail.input_dispatched = true;
      throw error;
    } finally {
      await this.releaseHeld(state);
    }
  }

  async runCommands(state) {
    const results = [];
    let frameMappings;
    if (state.plan.commands.some(command => command.frame_id || ["Page.getFrameTree", "DOM.getNodeForLocation"].includes(command.method))) {
      state.frames = new Frames(this.chrome, state, () => this.guard(state));
      await state.frames.start();
    }
    let readObservation = null;
    let preSampleAttempted = false;
    let readFailure;
    const hasInput = state.plan.commands.some(command => classifyCommand(command) === "input");
    const hasRead = state.plan.commands.some(command => ["Accessibility.getFullAXTree", "DOM.getFlattenedDocument", "DOM.getOuterHTML", "Page.captureScreenshot"].includes(command.method));
    const metadataOnly = state.plan.commands.every(command => classifyCommand(command) === "read") && !hasRead;
    const baseline = this.baselines.get(state.tabId);
    probeReadDiagnostic("plan_baseline", { tabId: state.tabId, hasInput, hasRead, baselinePresent: !!baseline, baselineEpoch: baseline?.epoch, planEpoch: state.plan.interaction_epoch, commandCount: state.plan.commands.length });
    if (hasInput && (!baseline || !Number.isSafeInteger(state.plan.interaction_epoch) || baseline.epoch !== state.plan.interaction_epoch)) {
      const reason = !baseline ? "baseline_missing" : !Number.isSafeInteger(state.plan.interaction_epoch) ? "plan_epoch_missing" : "epoch_mismatch";
      probeReadDiagnostic("input_baseline_refused", { tabId: state.tabId, reason, baselinePresent: !!baseline, baselineEpoch: baseline?.epoch, planEpoch: state.plan.interaction_epoch, continuity: baseline?.continuity });
      if (this.epochs.record(state.tabId).coverageLost) throw observerUnavailable();
      throw new Refusal("fresh_read_required");
    }
    if (hasInput && (!Number.isSafeInteger(state.plan.observer_continuity) || state.plan.observer_continuity !== baseline.continuity || state.plan.observer_continuity !== this.epochs.record(state.tabId).continuity)) {
      probeReadDiagnostic("input_baseline_refused", { tabId: state.tabId, reason: "observer_unavailable", planContinuity: state.plan.observer_continuity, baselineContinuity: baseline.continuity, continuity: this.epochs.record(state.tabId).continuity });
      throw observerUnavailable();
    }
    for (const planned of state.plan.commands) {
      const command = { ...planned, params: resolveParams(planned.params, results) };
      await this.guard(state);
      const kind = classifyCommand(command);
      const scope = command.frame_id ? await state.frames.resolve(command, kind === "read" && !hasInput) : null;
      const target = scope?.target ?? { tabId: state.tabId };
      const frameId = scope?.frame.web_navigation_frame_id ?? 0;
      if (!hasInput && hasRead && kind === "read" && !preSampleAttempted) {
        preSampleAttempted = true;
        try {
          const epoch = await this.epochs.sample(state.tabId, "pre_read", true);
          readObservation = { epoch, continuity: this.epochs.record(state.tabId).continuity };
        } catch (error) {
          // A failed pre-read interaction sample cannot authorize later input.
          readFailure = diagnosticReason(error);
          probeReadDiagnostic("sample_failed", { tabId: state.tabId, stage: "pre_read", reason: readFailure });
        }
      }
      try {
        if (kind === "input") {
          await this.epochs.check(state.tabId, state.plan.interaction_epoch, state.plan.observer_continuity);
          if (this.epochs.record(state.tabId).continuity !== baseline.continuity) throw observerUnavailable();
        }
        await this.guard(state);
        if (kind === "input" && this.epochs.record(state.tabId).epoch !== state.plan.interaction_epoch) throw new Refusal("interaction_epoch_changed");
        if (kind === "input" && this.epochs.record(state.tabId).continuity !== baseline.continuity) throw observerUnavailable();
        if (kind === "navigate") {
          if (Number.isSafeInteger(state.plan.interaction_epoch)) await this.epochs.check(state.tabId, state.plan.interaction_epoch, state.plan.observer_continuity);
          else {
            // Only an openerless agent-created blank tab may navigate without observation:
            // HTTP host permissions alone do not guarantee script access there.
            const tree = await bounded(this.chrome.debugger.sendCommand(target, "Page.getFrameTree", {}), "reply");
            await this.guard(state);
            if (this.blankNavigations.get(state.tabId) !== state.route || this.tabs.tabs.get(state.tabId)?.kind !== "opened" || tree.frameTree?.frame?.url !== "about:blank") throw observerUnavailable();
          }
          await this.guard(state);
          if (Number.isSafeInteger(state.plan.interaction_epoch) && state.plan.observer_continuity !== this.epochs.record(state.tabId).continuity) throw observerUnavailable();
          this.blankNavigations.delete(state.tabId);
          this.navigation.set(state.tabId, { state, frameId, started: false, url: command.params.url, deadline: Date.now() + 30000 });
        }
        if (kind === "input") state.input = true;
        // A press or key-down owes its release from before it is sent until
        // Chrome acknowledges that release (see releaseHeld).
        const owed = releaseOwed(command);
        if (owed) (state.held ??= new Map()).set(owed.key, { target, ...owed.release });
        const discharged = releaseDischarged(command);
        let result;
        if (kind === "wait") {
          result = await this.wait(state, command.params.ms);
        } else if (command.method === "Page.getFrameTree" && !scope) {
          const observed = await state.frames.read();
          result = { frameTree: observed.tree };
          frameMappings = observed.mappings;
        } else if (command.method === "DOM.getNodeForLocation") {
          const { mappings } = await state.frames.read();
          result = await new FrameGeometry(state.frames, mappings).hit({ x: command.params.x, y: command.params.y }, scope?.frame, command.params);
        } else result = await bounded(this.chrome.debugger.sendCommand(target, command.method, command.params), "reply");
        if (discharged) state.held?.delete(discharged);
        if (scope) await state.frames.resolve(command, kind === "read" && !hasInput);
        results.push({ result });
      } catch (error) {
        if (error instanceof Refusal) throw error;
        results.push({ error: debuggerError(error) });
        break;
      }
      await this.guard(state);
    }
    await this.guard(state);
    // Membership is checked again after observation, immediately before content
    // leaves the adapter. A refused input never creates a new read baseline.
    let epoch;
    let covered = true;
    try { epoch = await this.epochs.sample(state.tabId, "post_plan", metadataOnly); } catch (error) {
      readFailure = diagnosticReason(error);
      probeReadDiagnostic("sample_failed", { tabId: state.tabId, stage: "post_plan", reason: readFailure });
      if (hasInput) throw error;
      covered = false;
      epoch = this.epochs.record(state.tabId).epoch;
    }
    await this.guard(state);
    if (!hasInput && hasRead && !results.some(entry => entry.error)) {
      if (covered && readObservation) {
        if (readObservation.continuity !== this.epochs.record(state.tabId).continuity) throw observerUnavailable();
        if (readObservation.epoch !== epoch) throw new Refusal("interaction_epoch_changed");
        this.baselines.set(state.tabId, readObservation);
        probeReadDiagnostic("baseline_set", { tabId: state.tabId, epoch: readObservation.epoch, continuity: readObservation.continuity });
      } else {
        this.baselines.delete(state.tabId);
        probeReadDiagnostic("baseline_deleted", { tabId: state.tabId, reason: readFailure, covered, readObserved: !!readObservation, epoch });
      }
    }
    if (hasInput && this.epochs.record(state.tabId).continuity !== baseline.continuity) throw observerUnavailable();
    if (hasInput && epoch !== state.plan.interaction_epoch) throw new Refusal("interaction_epoch_changed");
    await this.guard(state);
    const result = { tab: state.plan.tab, results, interaction_epoch: epoch, observer_available: covered, observer_continuity: this.epochs.record(state.tabId).continuity, connection_epoch: state.epoch };
    const cause = this.epochs.record(state.tabId).cause;
    if (cause) result.interaction_cause = cause;
    if (frameMappings) result.frame_mappings = frameMappings;
    if (this.popupFlags.delete(state.tabId)) result.popup_activated_briefly = true;
    return result;
  }
}
