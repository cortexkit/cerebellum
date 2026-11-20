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
    this.chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
      const groupId = Number.isInteger(tab?.groupId) ? tab.groupId : change.groupId;
      if (!Number.isInteger(groupId)) return;
      if (groupId !== this.tabs.group?.id) {
        if (this.tabs.tabs.has(tabId)) this.tabs.adoptionDecision(tabId, "tabs.onUpdated", "withdrawn_from_group");
        this.tabs.withdraw(tabId);
      } else if (!this.tabs.tabs.has(tabId) || this.tabs.adopting.has(tabId)) {
        const source = "groupId" in change ? "tabs.onUpdated:groupId" : "tabs.onUpdated:tab";
        void this.tabs.adoptMember(tabId, source).catch(error => this.handoverFailed(tabId, error));
      }
    });
    // Position and group-property events are hints, not membership authority.
    // Re-read only our recorded group; status also reconciles if no hint arrives.
    this.chrome.tabs.onMoved.addListener(tabId => {
      void this.tabs.reconcile("tabs.onMoved").catch(error => this.handoverFailed(tabId, error));
    });
    this.chrome.tabGroups.onUpdated.addListener(group => {
      if (group.id === this.tabs.group?.id) void this.tabs.reconcile("tabGroups.onUpdated").catch(error => this.handoverFailed(undefined, error));
    });
    this.chrome.tabs.onRemoved.addListener(tabId => {
      this.tabs.withdraw(tabId);
      for (const [windowId, active] of this.activeTabs) if (active === tabId) this.activeTabs.delete(windowId);
    });
    this.chrome.tabs.onReplaced.addListener((_addedTabId, removedTabId) => {
      // Prerender activation can replace a tab without an onRemoved event.
      // Revoke the old identity and its plan before adopting eligible members.
      this.tabs.withdraw(removedTabId);
      for (const [windowId, active] of this.activeTabs) if (active === removedTabId) this.activeTabs.delete(windowId);
      void this.tabs.reconcile("tabs.onReplaced").catch(error => this.handoverFailed(removedTabId, error));
    });
    this.chrome.tabGroups.onRemoved.addListener(group => {
      if (group.id !== this.tabs.group?.id) return;
      for (const tabId of [...this.tabs.tabs.keys()]) this.tabs.withdraw(tabId);
      this.tabs.group = null;
      void this.tabs.save();
    });
    this.chrome.tabs.onActivated.addListener(info => {
      // Selection is not a person-input count, but an unobserved blank tab may
      // no longer use the narrow first-hop exception once someone selects it.
      this.agent.blankNavigations.delete(info.tabId);
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
      const owner = this.popupOwner(tab.id, tab.openerTabId);
      if (!owner) return;
      this.notePopup(tab.id, tab.openerTabId, owner, tab.windowId, tab.active);
      void this.handleCreated(tab.id);
    });
    this.chrome.webNavigation.onCreatedNavigationTarget.addListener(info => {
      if (!this.tabs.tabs.has(info.sourceTabId)) return;
      const owner = this.popupOwner(info.tabId, info.sourceTabId);
      if (!owner) return;
      this.notePopup(info.tabId, info.sourceTabId, owner);
      void this.handleCreated(info.tabId);
    });
    this.chrome.webNavigation.onBeforeNavigate.addListener(info => {
      if (!this.tabs.tabs.has(info.tabId)) return;
      const navigation = this.agent.navigation.get(info.tabId);
      if (navigation && navigation.state.epoch === this.agent.connectionEpoch && navigation.deadline >= Date.now() && navigation.frameId === info.frameId && !navigation.started && (!info.url || info.url === navigation.url)) {
        navigation.started = true;
        return;
      }
      if (info.frameId === 0 && info.url && info.url !== "about:blank") this.agent.blankNavigations.delete(info.tabId);
      this.epochs.bump(info.tabId, info.frameId);
    });
    this.chrome.webNavigation.onCommitted.addListener(info => {
      if (!this.tabs.tabs.has(info.tabId)) return;
      const navigation = this.agent.navigation.get(info.tabId);
      if (navigation?.started && navigation.state.epoch === this.agent.connectionEpoch && navigation.deadline >= Date.now() && navigation.frameId === info.frameId) this.agent.navigation.delete(info.tabId);
      // A commit invalidates document continuity, not proof of a person's input.
      // In particular, an unobserved initial blank commit must not mint a human epoch.
      void this.epochs.committed(info.tabId, info.frameId, info.documentId).catch(() => {});
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
    console.info("Agent group listeners registered: tabs.onUpdated, tabs.onMoved, tabGroups.onUpdated; status reconciliation enabled");
  }

  // Decide when Chrome first reports a tab opened from a group member whether
  // agent input caused it. Only then does the pop-up path run: it groups the
  // tab, gives it the opener's claim and restores focus. A tab the person
  // opens from a handed tab (a link click, middle click, "open in new tab")
  // gets none of that. If Chrome itself places it in the Agent group, it is
  // adopted there as an unclaimed handed tab like any other tab the person
  // drags in, and an agent must claim it with claim_tab.
  popupOwner(tabId, openerTabId) {
    if (this.popupSources.has(tabId)) return this.popupSources.get(tabId).owner;
    const owner = this.agent.inputRoute(openerTabId);
    if (!owner) this.tabs.adoptionDecision(tabId, "popup", "opened_without_agent_input");
    return owner;
  }

  notePopup(tabId, openerTabId, owner, windowId, activated = false) {
    if (this.popupSources.has(tabId)) {
      const popup = this.popupSources.get(tabId);
      popup.activated ||= activated;
      popup.windowId ??= windowId;
      return;
    }
    const previous = this.lastActivation?.tabId === tabId ? this.lastActivation : null;
    const restoreWindow = previous?.previousWindow ?? (this.lastFocus?.windowId === windowId ? this.lastFocus.previousWindow : this.focusedWindow);
    this.popupSources.set(tabId, {
      openerTabId, owner, windowId, activated: activated || !!previous,
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
    // The pop-up inherits the claim of the route whose input opened it, and
    // only while that route still holds the opener. A claim that changed
    // hands or ended since then is never copied.
    if (this.agent.claims.get(popup.openerTabId) !== popup.owner) {
      this.tabs.adoptionDecision(tabId, "popup", "opener_claim_changed");
      return;
    }
    await this.tabs.adoptPopup(tabId);
    // Grouping and the observer install wait on Chrome, and the opener's
    // route can end meanwhile, releasing its claims. A pop-up of a
    // route that has ended stays an unclaimed agent-opened tab, and nothing
    // is focused for it.
    const ownerStillHoldsOpener = () => this.agent.claims.get(popup.openerTabId) === popup.owner;
    if (!ownerStillHoldsOpener()) {
      this.tabs.adoptionDecision(tabId, "popup", "opener_claim_changed");
      return;
    }
    this.agent.claims.set(tabId, popup.owner);
    await this.epochs.install(tabId);
    if (!ownerStillHoldsOpener()) {
      if (this.agent.claims.get(tabId) === popup.owner) this.agent.claims.delete(tabId);
      this.tabs.adoptionDecision(tabId, "popup", "opener_claim_changed");
      return;
    }
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
