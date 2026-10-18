export class BrowserEvents {
  constructor(chrome, tabs, epochs, agent, handoverFailed = (_tabId, error) => console.error("Agent handover failed", error)) {
    this.chrome = chrome;
    this.tabs = tabs;
    this.epochs = epochs;
    this.agent = agent;
    this.handoverFailed = handoverFailed;
    this.activeTabs = new Map();
    this.focusedWindow = null;
    this.popupSources = new Map();
    this.popupTasks = new Map();
  }

  remember(tab) {
    if (tab?.active) {
      this.activeTabs.set(tab.windowId, tab.id);
      this.focusedWindow = tab.windowId;
    }
  }

  listen() {
    this.chrome.tabs.onUpdated.addListener((tabId, change) => {
      if (!("groupId" in change)) return;
      if (change.groupId !== this.tabs.group?.id) this.tabs.withdraw(tabId);
      else void this.tabs.adoptMember(tabId).then(async adopted => {
        if (adopted) await this.epochs.install(tabId);
      }).catch(error => this.handoverFailed(tabId, error));
    });
    this.chrome.tabs.onRemoved.addListener(tabId => {
      this.tabs.withdraw(tabId);
      for (const [windowId, active] of this.activeTabs) if (active === tabId) this.activeTabs.delete(windowId);
    });
    this.chrome.tabGroups.onRemoved.addListener(group => {
      if (group.id !== this.tabs.group?.id) return;
      for (const tabId of [...this.tabs.tabs.keys()]) this.tabs.withdraw(tabId);
      this.tabs.group = null;
      void this.tabs.save();
    });
    this.chrome.tabs.onActivated.addListener(info => {
      const popup = this.popupSources.get(info.tabId);
      if (popup) {
        popup.activated = true;
        this.agent.popupFlags.add(popup.openerTabId);
        return;
      }
      this.lastActivation = { tabId: info.tabId, windowId: info.windowId, previousTab: this.activeTabs.get(this.focusedWindow), previousWindow: this.focusedWindow };
      this.activeTabs.set(info.windowId, info.tabId);
    });
    this.chrome.windows.onFocusChanged.addListener(windowId => {
      if (windowId >= 0 && ![...this.popupSources.values()].some(popup => popup.windowId === windowId)) {
        this.lastFocus = { windowId, previousWindow: this.focusedWindow };
        this.focusedWindow = windowId;
      }
    });
    this.chrome.tabs.onCreated.addListener(tab => {
      if (!this.tabs.tabs.has(tab.openerTabId)) return;
      this.notePopup(tab.id, tab.openerTabId, tab.windowId, tab.active);
      void this.handleCreated(tab.id);
    });
    this.chrome.webNavigation.onCreatedNavigationTarget.addListener(info => {
      if (!this.tabs.tabs.has(info.sourceTabId)) return;
      this.notePopup(info.tabId, info.sourceTabId);
      void this.handleCreated(info.tabId);
    });
    this.chrome.webNavigation.onBeforeNavigate.addListener(info => {
      if (!this.tabs.tabs.has(info.tabId)) return;
      const navigation = this.agent.navigation.get(info.tabId);
      if (navigation && navigation.state.epoch === this.agent.connectionEpoch && navigation.deadline >= Date.now() && navigation.frameId === info.frameId && !navigation.started && (!info.url || info.url === navigation.url)) {
        navigation.started = true;
        return;
      }
      this.epochs.bump(info.tabId);
    });
    this.chrome.webNavigation.onCommitted.addListener(info => {
      if (!this.tabs.tabs.has(info.tabId)) return;
      const navigation = this.agent.navigation.get(info.tabId);
      if (navigation?.started && navigation.state.epoch === this.agent.connectionEpoch && navigation.deadline >= Date.now() && navigation.frameId === info.frameId) this.agent.navigation.delete(info.tabId);
      else this.epochs.bump(info.tabId);
      void this.epochs.install(info.tabId, info.frameId).catch(() => {});
    });
    this.chrome.webNavigation.onErrorOccurred.addListener(info => {
      if (this.agent.navigation.get(info.tabId)?.frameId === info.frameId) this.agent.navigation.delete(info.tabId);
    });
    this.chrome.runtime.onMessage.addListener((message, sender) => {
      if (message?.kind === "agent-interaction") void this.epochs.observe(message, sender).catch(() => {});
    });
    this.chrome.debugger.onDetach.addListener(source => {
      for (const state of this.agent.active) {
        if (state.tabId !== source.tabId) continue;
        state.attached = false;
        this.epochs.endAction(state.actionWindow);
        if (!state.detaching) state.cancelled = true;
      }
    });
  }

  notePopup(tabId, openerTabId, windowId, activated = false) {
    if (this.popupSources.has(tabId)) {
      const popup = this.popupSources.get(tabId);
      popup.activated ||= activated;
      popup.windowId ??= windowId;
      return;
    }
    const previous = this.lastActivation?.tabId === tabId ? this.lastActivation : null;
    const restoreWindow = previous?.previousWindow ?? (this.lastFocus?.windowId === windowId ? this.lastFocus.previousWindow : this.focusedWindow);
    this.popupSources.set(tabId, {
      openerTabId, windowId, activated: activated || !!previous,
      restoreWindow,
      restoreTab: previous?.previousTab ?? this.activeTabs.get(restoreWindow),
    });
  }

  async handleCreated(tabId) {
    await Promise.all([...this.tabs.creations]);
    if (this.tabs.extensionCreated.has(tabId)) { this.popupSources.delete(tabId); return; }
    await this.adoptPopup(tabId);
  }

  async adoptPopup(tabId) {
    if (this.popupTasks.has(tabId)) return this.popupTasks.get(tabId);
    const pending = this.doAdoptPopup(tabId).catch(() => {}).finally(() => {
      this.popupTasks.delete(tabId);
      this.popupSources.delete(tabId);
    });
    this.popupTasks.set(tabId, pending);
    return pending;
  }

  async doAdoptPopup(tabId) {
    const popup = this.popupSources.get(tabId);
    if (!popup || this.tabs.tabs.has(tabId)) return;
    // The opener, not a page-supplied URL, determines whether popup recovery is
    // allowed. Never group, activate, or restore anything for an outside opener.
    await this.tabs.eligible(popup.openerTabId);
    const owner = this.agent.claims.get(popup.openerTabId);
    await this.tabs.adoptPopup(tabId);
    if (owner) this.agent.claims.set(tabId, owner);
    await this.epochs.install(tabId);
    if (popup.activated) {
      this.agent.popupFlags.add(popup.openerTabId);
      // This is the only foregrounding path. It restores remembered ids after
      // a script popup; it does not read the person's tab or window contents.
      if (popup.restoreTab !== undefined && popup.restoreWindow !== null) {
        await this.chrome.tabs.update(popup.restoreTab, { active: true });
        await this.chrome.windows.update(popup.restoreWindow, { focused: true });
      }
    }
  }
}
