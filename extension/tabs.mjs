import { Refusal } from "./errors.mjs";

const STORAGE_KEY = "agentGroup";
// chrome.storage.session is cleared when the extension is reloaded, updated
// or disabled, so a copy of the group record also lives in storage.local.
// It lets a reloaded extension recognise the Agent group it made before.
const LOCAL_KEY = "agentGroupRecord";
const GROUP_TITLE = "Agent";
const GROUP_COLOR = "blue";

export class AgentTabs {
  constructor(chrome, onWithdraw = () => {}, onAdopt = async () => {}) {
    this.chrome = chrome;
    this.onWithdraw = onWithdraw;
    this.onAdopt = onAdopt;
    this.group = null;
    this.tabs = new Map();
    this.extensionCreated = new Set();
    this.creations = new Set();
    this.joining = new Set();
    this.adopting = new Map();
    this.browserStarted = false;
    this.readopted = false;
    this.ready = this.restore();
  }

  async restore() {
    const saved = (await this.chrome.storage.session.get(STORAGE_KEY))[STORAGE_KEY];
    // Only a session store that was never written means a fresh extension
    // load; an explicit null means this load already has no group.
    if (saved === undefined) return this.readopt();
    if (!saved) return;
    try {
      const group = await this.chrome.tabGroups.get(saved.id);
      if (group.windowId !== saved.windowId) return;
      this.group = { id: group.id, windowId: group.windowId };
      // Query by the recorded group id, never enumerate the person's other tabs.
      for (const tab of await this.chrome.tabs.query({ groupId: group.id })) {
        this.tabs.set(tab.id, { handle: crypto.randomUUID(), kind: saved.kinds?.[tab.id] ?? "handed" });
      }
    } catch {
      this.group = null;
    }
  }

  // Re-adopt, after an extension reload, the Agent group this extension made
  // before. Group, window and tab ids are unique only within one browser run,
  // so the record is accepted only if the group still has the recorded id,
  // window, title and colour, and still holds at least one tab the record
  // names. A browser start discards the record (see startedBrowser), because
  // ids restart and a person's own group could then match it by chance.
  // Handover survives the reload, claims do not: every current member
  // becomes an unclaimed handed tab with a new handle, including a tab the
  // person dragged in while the extension was down. A record that does not
  // match is deleted; the group it named is the person's and is left alone.
  async readopt() {
    const record = (await this.chrome.storage.local.get(LOCAL_KEY))[LOCAL_KEY];
    if (!record) return;
    let members = [];
    try {
      const group = await this.chrome.tabGroups.get(record.id);
      if (group.windowId === record.windowId && group.title === GROUP_TITLE && group.color === GROUP_COLOR) {
        members = await this.chrome.tabs.query({ groupId: record.id, windowId: record.windowId });
      }
    } catch { members = []; }
    const recorded = new Set(Array.isArray(record.members) ? record.members : []);
    if (this.browserStarted || !members.some(tab => recorded.has(tab.id))) {
      this.adoptionDecision("none", "reload", this.browserStarted ? "browser_started" : "record_mismatch");
      await this.chrome.storage.local.remove(LOCAL_KEY);
      return;
    }
    this.group = { id: record.id, windowId: record.windowId };
    this.readopted = true;
    for (const tab of members) this.tabs.set(tab.id, { handle: crypto.randomUUID(), kind: "handed" });
    this.adoptionDecision("none", "reload", "readopted_group");
    await this.save();
  }

  // Called on chrome.runtime.onStartup. After a browser start the stored
  // record's ids may name a different group, so it is discarded, and a group
  // re-adopted from it in this worker before the event arrived is dropped
  // again without touching the group itself.
  async startedBrowser() {
    this.browserStarted = true;
    await this.ready;
    if (this.readopted) {
      this.readopted = false;
      for (const tabId of [...this.tabs.keys()]) this.withdraw(tabId);
      this.group = null;
      await this.save();
    }
    await this.chrome.storage.local.remove(LOCAL_KEY);
  }

  async save() {
    // Written on every membership change, so the stored record never names
    // a tab the person has taken back.
    const members = [...this.tabs.keys()];
    await Promise.all([
      this.chrome.storage.session.set({ [STORAGE_KEY]: this.group && {
        ...this.group,
        kinds: Object.fromEntries([...this.tabs].map(([id, tab]) => [id, tab.kind])),
      } }),
      this.group
        ? this.chrome.storage.local.set({ [LOCAL_KEY]: { ...this.group, members } })
        : this.chrome.storage.local.remove(LOCAL_KEY),
    ]);
  }

  async eligible(tabId) {
    await this.ready;
    if (!this.group || !this.tabs.has(tabId)) throw new Refusal("tab_not_in_agent_group", "hand the tab over using the extension");
    let tab;
    try { tab = await this.chrome.tabs.get(tabId); } catch { /* Treat a closed tab as withdrawn from the Agent group. */ }
    if (!tab || tab.groupId !== this.group.id || tab.windowId !== this.group.windowId) {
      this.withdraw(tabId);
      throw new Refusal("tab_not_in_agent_group", "hand the tab over using the extension");
    }
    return tab;
  }

  withdraw(tabId) {
    if (!this.tabs.delete(tabId)) return;
    this.onWithdraw(tabId);
    void this.save();
  }

  async join(tabId, kind) {
    this.joining.add(tabId);
    try { return await this.joinTab(tabId, kind); }
    finally { this.joining.delete(tabId); }
  }

  async joinTab(tabId, kind) {
    if (this.group) {
      try { await this.chrome.tabGroups.get(this.group.id); } catch { this.group = null; }
    }
    const joining = await this.chrome.tabs.get(tabId);
    if (this.group && joining.windowId !== this.group.windowId) throw new Refusal("agent_group_other_window", "move the tab to the Agent group's window before handing it over");
    if (!this.group) {
      const id = await this.chrome.tabs.group({ tabIds: [tabId] });
      const group = await this.chrome.tabGroups.update(id, { title: GROUP_TITLE, color: GROUP_COLOR });
      this.group = { id, windowId: group.windowId };
    } else {
      await this.chrome.tabs.group({ groupId: this.group.id, tabIds: [tabId] });
    }
    const record = { handle: crypto.randomUUID(), kind };
    this.tabs.set(tabId, record);
    await this.save();
    await this.eligible(tabId);
    return record;
  }

  adoptionDecision(tabId, source, decision) {
    // Log identities and fixed decisions only, never a tab's URL or title.
    console.info(`Agent group adoption: source=${source} tab=${tabId} group=${this.group?.id ?? "none"} decision=${decision}`);
  }

  async adoptMember(tabId, source = "tabs.onUpdated") {
    await this.ready;
    if (this.adopting.has(tabId)) return this.adopting.get(tabId);
    const task = this.adoptMemberNow(tabId, source);
    this.adopting.set(tabId, task);
    try { return await task; }
    finally { this.adopting.delete(tabId); }
  }

  async adoptMemberNow(tabId, source) {
    if (!this.group || this.tabs.has(tabId) || this.joining.has(tabId)) {
      this.adoptionDecision(tabId, source, !this.group ? "no_recorded_group" : this.joining.has(tabId) ? "owned_join_in_progress" : "already_recorded");
      return false;
    }
    let tab;
    try { tab = await this.chrome.tabs.get(tabId); }
    catch { this.adoptionDecision(tabId, source, "tab_unavailable"); return false; }
    // Only the recorded group's identity conveys handover, never its title.
    // A delayed group event must not re-adopt a tab the person already removed.
    if (!this.group || this.tabs.has(tabId) || this.joining.has(tabId)
      || tab.groupId !== this.group.id || tab.windowId !== this.group.windowId) {
      this.adoptionDecision(tabId, source, "membership_changed_or_recorded");
      return false;
    }
    this.tabs.set(tabId, { handle: crypto.randomUUID(), kind: "handed" });
    try {
      await this.save();
      await this.eligible(tabId);
      await this.onAdopt(tabId);
      await this.eligible(tabId);
      this.adoptionDecision(tabId, source, "adopted_handed");
      return true;
    } catch (error) {
      this.withdraw(tabId);
      this.adoptionDecision(tabId, source, error?.reason ?? "adoption_failed");
      throw error;
    }
  }

  async reconcile(source = "status") {
    await this.ready;
    const group = this.group;
    if (!group) return;
    // Membership changes need not emit tabs.onUpdated with changeInfo.groupId.
    // Query only the recorded group so status discovers a drag-in even when no
    // event arrives, without enumerating the person's other tabs or groups.
    let members;
    try { members = await this.chrome.tabs.query({ groupId: group.id, windowId: group.windowId }); }
    catch (error) {
      this.adoptionDecision("none", source, "group_query_failed");
      throw error;
    }
    if (this.group?.id !== group.id || this.group?.windowId !== group.windowId) return;
    const ids = new Set(members.map(tab => tab.id));
    for (const tabId of this.tabs.keys()) {
      if (!ids.has(tabId) && !this.joining.has(tabId)) {
        this.adoptionDecision(tabId, source, "withdrawn_from_group");
        this.withdraw(tabId);
      }
    }
    for (const tab of members) {
      if (!this.tabs.has(tab.id) || this.adopting.has(tab.id)) await this.adoptMember(tab.id, source);
    }
  }

  async open({ url = "about:blank", opener_tab } = {}) {
    await this.ready;
    if (url !== "about:blank") {
      let parsed;
      try { parsed = new URL(url); } catch { throw new Refusal("invalid_navigation"); }
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Refusal("invalid_navigation");
    }
    const options = { url, active: false };
    if (opener_tab) options.openerTabId = (await this.resolve(opener_tab)).tabId;
    if (this.group) options.windowId = this.group.windowId;
    let releaseCreation;
    const creating = new Promise(resolve => { releaseCreation = resolve; });
    this.creations.add(creating);
    let tab;
    try {
      tab = await this.chrome.tabs.create(options);
      this.extensionCreated.add(tab.id);
    } finally {
      releaseCreation();
      this.creations.delete(creating);
    }
    try {
      const record = await this.join(tab.id, "opened");
      return { tabId: tab.id, ...record };
    } catch (error) {
      // Even a failed open is left for the person to close; teardown never closes tabs.
      this.withdraw(tab.id);
      throw error;
    }
  }

  async adoptPopup(tabId) {
    await this.ready;
    if (!this.group) throw new Refusal("tab_not_in_agent_group");
    // Script popups may start in a new window. Moving only that popup into the
    // recorded group is the narrowly scoped popup-disposition exception.
    this.joining.add(tabId);
    try {
      await this.chrome.tabs.group({ groupId: this.group.id, tabIds: [tabId] });
      const record = { handle: crypto.randomUUID(), kind: "opened" };
      this.tabs.set(tabId, record);
      await this.save();
      await this.eligible(tabId);
      return record;
    } finally { this.joining.delete(tabId); }
  }

  async toggle(tabId) {
    await this.ready;
    if (this.tabs.has(tabId)) {
      this.joining.add(tabId);
      try {
        this.withdraw(tabId);
        await this.chrome.tabs.ungroup(tabId);
      } finally { this.joining.delete(tabId); }
      return false;
    }
    await this.join(tabId, "handed");
    return true;
  }

  async resolve(handle) {
    const pair = [...this.tabs].find(([, tab]) => tab.handle === handle);
    if (!pair) throw new Refusal("unknown_tab", "use status to get an eligible tab handle");
    await this.eligible(pair[0]);
    return { tabId: pair[0], ...pair[1] };
  }

  // Each eligible member, checked once here: its handle, its kind and, for
  // this extension's own use only, its Chrome tab id. The id never leaves the
  // extension; a later action that names a handle checks membership again.
  async list() {
    await this.ready;
    await this.reconcile();
    const result = [];
    for (const [tabId, record] of this.tabs) {
      try {
        await this.eligible(tabId);
        result.push({ tab: record.handle, kind: record.kind, tabId });
      } catch { /* Withdrawn tabs must not contribute even a handle. */ }
    }
    return result;
  }
}
