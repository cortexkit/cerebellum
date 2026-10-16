import { bounded, Refusal } from "./errors.mjs";
import { classifyCommand, resolveParams, verifyRuntime } from "./commands.mjs";
import { Frames } from "./frames.mjs";
import { FrameGeometry } from "./frame-geometry.mjs";

const routeKey = route => `${route.channel}:${route.epoch}`;
const closed = (value, fields) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every(key => fields.includes(key));

// chrome.debugger.sendCommand rejects with an Error whose message is Chrome's
// CDP error object serialized as JSON, for example
// {"code":-32000,"message":"DOM agent hasn't been enabled"}. Relay only that
// code and its fixed protocol message, so cerebellum can say which command
// failed and why. Chrome's optional `data` field is dropped, and any other
// rejection, or a message that is long or multi-line, keeps the generic text.
const MAX_CDP_ERROR_MESSAGE = 200;
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
  if (!closed(plan, ["version", "action", "tab", "url", "opener_tab", "interaction_epoch", "commands"]) || plan.version !== 2) throw new Refusal("invalid_plan", "update cerebellum and the extension together");
  const fields = {
    status: ["version", "action"], close: ["version", "action"],
    open_tab: ["version", "action", "url", "opener_tab"], claim_tab: ["version", "action", "tab"],
    cdp: ["version", "action", "tab", "interaction_epoch", "commands"],
  }[plan.action];
  if (!fields || !closed(plan, fields)) throw new Refusal("invalid_plan", "use a supported extension action");
  if (["claim_tab", "cdp"].includes(plan.action) && typeof plan.tab !== "string") throw new Refusal("invalid_plan");
  if ("url" in plan && typeof plan.url !== "string" || "opener_tab" in plan && typeof plan.opener_tab !== "string") throw new Refusal("invalid_plan");
  if (plan.action === "cdp") {
    if (!Array.isArray(plan.commands) || !plan.commands.length || plan.commands.length > 256) throw new Refusal("invalid_plan");
    for (const command of plan.commands) {
      if (!closed(command, ["method", "params", "frame_id", "session_id", "loader_id"]) || ["frame_id", "session_id", "loader_id"].some(key => key in command && (typeof command[key] !== "string" || !command[key])) || ["frame_id", "session_id", "loader_id"].some(key => key in command) && !["frame_id", "session_id", "loader_id"].every(key => key in command)) throw new Refusal("invalid_plan", "provide the complete verified frame scope");
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
    this.active = new Set();
    this.connectionEpoch = null;
    this.navigation = new Map();
    this.popupFlags = new Set();
    this.pendingAttaches = new Set();
  }

  connect(epoch) {
    this.connectionEpoch = epoch;
    this.claims.clear();
    this.baselines.clear();
  }

  async disconnect() {
    this.connectionEpoch = null;
    const active = [...this.active];
    for (const state of active) state.cancelled = true;
    await Promise.all(active.map(state => this.detach(state)));
    for (const key of new Set(this.claims.values())) await this.release(key);
    this.baselines.clear();
  }

  withdraw(tabId) {
    this.claims.delete(tabId);
    this.baselines.delete(tabId);
    this.epochs.forget(tabId);
    for (const state of this.active) if (state.tabId === tabId) {
      state.cancelled = true;
      void this.detach(state).catch(() => {});
    }
    void this.epochs.disable(tabId);
  }

  async release(key) {
    for (const [tabId, owner] of this.claims) {
      if (owner !== key) continue;
      this.claims.delete(tabId);
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
    await this.release(key);
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
        const pending = this.chrome.debugger.attach({ tabId: state.tabId }, "1.3").then(async () => {
          state.attached = true;
          state.actionWindow = this.epochs.beginAction(state.tabId);
          if (state.cancelled || this.connectionEpoch !== state.epoch) await this.detach(state);
        }).finally(() => {
          state.attachSettled = true;
          this.pendingAttaches.delete(pending);
        });
        this.pendingAttaches.add(pending);
        try { await bounded(pending, "attach"); } catch (error) {
          state.cancelled = true;
          if (error instanceof Refusal) throw error;
          throw new Refusal("debugger_busy", "close DevTools or the other debugger, then read again");
        }
        await this.guard(state);
      }
      return state;
    } catch (error) {
      state.cancelled = true;
      await this.detach(state);
      error.detached = state.attachSettled !== false;
      this.active.delete(state);
      throw error;
    }
  }

  async detach(state) {
    if (!state.attached) return;
    if (state.detaching) return state.detaching;
    state.detaching = Promise.resolve().then(async () => {
      try { await this.releaseMouse(state); } finally {
        // Keep the window open until Chrome actually detaches, even if the
        // caller's deadline expires before the detach promise settles.
        const pending = this.chrome.debugger.detach({ tabId: state.tabId }).then(() => {
          state.attached = false;
          state.frames?.close();
          this.epochs.endAction(state.actionWindow);
        });
        await bounded(pending, "cancel");
      }
    }).finally(() => { state.detaching = null; });
    return state.detaching;
  }

  async releaseMouse(state) {
    if (state.releasing) return state.releasing;
    if (!state.heldMouse || !state.attached) return;
    const { target, params } = state.heldMouse;
    state.heldMouse = null;
    // This is release-only cleanup for a press we dispatched on this attachment.
    // A refusal may revoke membership or freshness, but must not leave that
    // button held. Never resume the plan or dispatch another press during cleanup.
    state.releasing = bounded(this.chrome.debugger.sendCommand(target, "Input.dispatchMouseEvent", params), "reply")
      .catch(() => { throw new Refusal("input_release_unconfirmed", "read again", { input_dispatched: true }); });
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

  async execute(state) {
    const p = state.plan;
    await this.guard(state);
    if (p.action === "status") {
      const visible = [];
      for (const tab of await this.tabs.list()) {
        const record = await this.tabs.resolve(tab.tab);
        const owner = this.claims.get(record.tabId);
        if (owner && owner !== state.route || !owner && record.kind !== "handed") continue;
        visible.push({ tab: tab.tab, claimed: owner === state.route, handed: record.kind === "handed", interaction_epoch: this.epochs.record(record.tabId).epoch });
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
      await this.releaseMouse(state);
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
    const hasInput = state.plan.commands.some(command => classifyCommand(command) === "input");
    const hasRead = state.plan.commands.some(command => ["Accessibility.getFullAXTree", "DOM.getFlattenedDocument", "DOM.getOuterHTML", "Page.captureScreenshot"].includes(command.method));
    const baseline = this.baselines.get(state.tabId);
    if (hasInput && (!baseline || !Number.isSafeInteger(state.plan.interaction_epoch) || baseline.epoch !== state.plan.interaction_epoch)) throw new Refusal("fresh_read_required");
    for (const planned of state.plan.commands) {
      const command = { ...planned, params: resolveParams(planned.params, results) };
      await this.guard(state);
      const kind = classifyCommand(command);
      const scope = command.frame_id ? await state.frames.resolve(command) : null;
      const target = scope?.target ?? { tabId: state.tabId };
      const frameId = scope?.frame.web_navigation_frame_id ?? 0;
      if (!hasInput && hasRead && kind === "read" && !readObservation) {
        try {
          const epoch = await this.epochs.sample(state.tabId);
          readObservation = { epoch, continuity: this.epochs.record(state.tabId).continuity };
        } catch { /* Readable pages without sentinel coverage cannot authorize later input. */ }
      }
      try {
        if (kind === "input") {
          await this.epochs.check(state.tabId, state.plan.interaction_epoch);
          if (this.epochs.record(state.tabId).continuity !== baseline.continuity) throw new Refusal("interaction_continuity_lost");
        }
        await this.guard(state);
        if (kind === "input" && this.epochs.record(state.tabId).epoch !== state.plan.interaction_epoch) throw new Refusal("interaction_epoch_changed");
        if (kind === "input" && this.epochs.record(state.tabId).continuity !== baseline.continuity) throw new Refusal("interaction_continuity_lost");
        if (kind === "navigate") this.navigation.set(state.tabId, { state, frameId, started: false, url: command.params.url, deadline: Date.now() + 30000 });
        if (kind === "input") state.input = true;
        if (command.method === "Input.dispatchMouseEvent") {
          if (command.params.type === "mousePressed") state.heldMouse = { target, params: { ...command.params, type: "mouseReleased" } };
          if (command.params.type === "mouseReleased") state.heldMouse = null;
        }
        let result;
        if (command.method === "Page.getFrameTree" && !scope) {
          const observed = await state.frames.read();
          result = { frameTree: observed.tree };
          frameMappings = observed.mappings;
        } else if (command.method === "DOM.getNodeForLocation") {
          const { mappings } = await state.frames.read();
          result = await new FrameGeometry(state.frames, mappings).hit({ x: command.params.x, y: command.params.y }, scope?.frame, command.params);
        } else result = await bounded(this.chrome.debugger.sendCommand(target, command.method, command.params), "reply");
        if (scope) await state.frames.resolve(command);
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
    try { epoch = await this.epochs.sample(state.tabId); } catch (error) {
      if (hasInput) throw error;
      covered = false;
      epoch = this.epochs.record(state.tabId).epoch;
    }
    await this.guard(state);
    if (!hasInput && hasRead && !results.some(entry => entry.error)) {
      if (covered && readObservation) {
        if (readObservation.epoch !== epoch) throw new Refusal("interaction_epoch_changed");
        if (readObservation.continuity !== this.epochs.record(state.tabId).continuity) throw new Refusal("interaction_continuity_lost");
        this.baselines.set(state.tabId, readObservation);
      } else this.baselines.delete(state.tabId);
    }
    if (hasInput && epoch !== state.plan.interaction_epoch) throw new Refusal("interaction_epoch_changed");
    if (hasInput && this.epochs.record(state.tabId).continuity !== baseline.continuity) throw new Refusal("interaction_continuity_lost");
    await this.guard(state);
    const result = { tab: state.plan.tab, results, interaction_epoch: epoch, connection_epoch: state.epoch };
    if (frameMappings) result.frame_mappings = frameMappings;
    if (this.popupFlags.delete(state.tabId)) result.popup_activated_briefly = true;
    return result;
  }
}
