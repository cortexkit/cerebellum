import { Refusal } from "./errors.mjs";

const STORAGE_KEY = "agentGroup";

export class AgentTabs {
  constructor(chrome, onWithdraw = () => {}) {
    this.chrome = chrome;
    this.onWithdraw = onWithdraw;
    this.group = null;
    this.tabs = new Map();
    this.extensionCreated = new Set();
    this.creations = new Set();
    this.ready = this.restore();
  }

  async restore() {
    const saved = (await this.chrome.storage.session.get(STORAGE_KEY))[STORAGE_KEY];
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

  async save() {
    await this.chrome.storage.session.set({ [STORAGE_KEY]: this.group && {
      ...this.group,
      kinds: Object.fromEntries([...this.tabs].map(([id, tab]) => [id, tab.kind])),
    } });
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
    if (this.group) {
      try { await this.chrome.tabGroups.get(this.group.id); } catch { this.group = null; }
    }
    const joining = await this.chrome.tabs.get(tabId);
    if (this.group && joining.windowId !== this.group.windowId) throw new Refusal("agent_group_other_window", "move the tab to the Agent group's window before handing it over");
    if (!this.group) {
      const id = await this.chrome.tabs.group({ tabIds: [tabId] });
      const group = await this.chrome.tabGroups.update(id, { title: "Agent", color: "blue" });
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
    await this.chrome.tabs.group({ groupId: this.group.id, tabIds: [tabId] });
    const record = { handle: crypto.randomUUID(), kind: "opened" };
    this.tabs.set(tabId, record);
    await this.save();
    await this.eligible(tabId);
    return record;
  }

  async toggle(tabId) {
    await this.ready;
    if (this.tabs.has(tabId)) {
      this.withdraw(tabId);
      await this.chrome.tabs.ungroup(tabId);
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

  async list() {
    await this.ready;
    const result = [];
    for (const [tabId, record] of this.tabs) {
      try {
        await this.eligible(tabId);
        result.push({ tab: record.handle, kind: record.kind });
      } catch { /* Withdrawn tabs must not contribute even a handle. */ }
    }
    return result;
  }
}
