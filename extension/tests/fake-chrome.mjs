import { sentinel } from "./sentinel-fixture.mjs";

export class Event {
  listeners = new Set();
  addListener = fn => this.listeners.add(fn);
  removeListener = fn => this.listeners.delete(fn);
  emit(...args) { for (const fn of this.listeners) fn(...args); }
}

export function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

export function fakeChrome() {
  const calls = [];
  const tabData = new Map([[1, { id: 1, windowId: 3, groupId: -1, active: true }], [2, { id: 2, windowId: 3, groupId: -1, active: false }]]);
  const groups = new Map();
  const store = {};
  const observations = new Map();
  const sentinels = new Map();
  let nextDocument = 0;
  let nextTab = 10;
  const ports = [];
  const chrome = {
    calls, tabData, groups, observations, ports, sentinels,
    now: () => performance.timeOrigin + performance.now(),
    input(tabId, event, frameId = 0) { sentinels.get(`${tabId}:${frameId}`)?.event({ isTrusted: true, ...event }); },
    runtime: {
      id: "test-extension", onMessage: new Event(), onStartup: new Event(), onInstalled: new Event(),
      connectNative(name) {
        calls.push(["connectNative", name]);
        const port = { onMessage: new Event(), onDisconnect: new Event(), onPost: new Event(), sent: [], postMessage(frame) { this.sent.push(structuredClone(frame)); this.onPost.emit(frame); }, disconnect() { this.onDisconnect.emit(); } };
        ports.push(port);
        return port;
      },
    },
    storage: { session: { async get(key) { return { [key]: store[key] }; }, async set(value) { Object.assign(store, value); } } },
    tabs: {
      onUpdated: new Event(), onMoved: new Event(), onRemoved: new Event(), onActivated: new Event(), onCreated: new Event(),
      async get(id) { calls.push(["get", id]); if (!tabData.has(id)) throw new Error("closed"); return { ...tabData.get(id) }; },
      async query(query) {
        if (query.active === true && query.lastFocusedWindow === true) return [...tabData.values()].filter(tab => tab.active).map(({ id, windowId }) => ({ id, windowId }));
        if (!Number.isInteger(query.groupId)) throw new Error("outside enumeration forbidden");
        calls.push(["query", query]);
        return [...tabData.values()].filter(tab => tab.groupId === query.groupId && (query.windowId === undefined || tab.windowId === query.windowId)).map(tab => ({ ...tab }));
      },
      async create(options) {
        if (options.active !== false) throw new Error("activation forbidden");
        calls.push(["create", options]);
        const tab = { id: nextTab++, windowId: options.windowId ?? 3, groupId: -1, active: false, url: options.url };
        tabData.set(tab.id, tab);
        return { ...tab };
      },
      async group({ tabIds, groupId }) {
        const id = groupId ?? 7;
        if (!groups.has(id)) groups.set(id, { id, windowId: tabData.get(tabIds[0]).windowId });
        for (const tabId of tabIds) {
          tabData.get(tabId).groupId = id; tabData.get(tabId).windowId = groups.get(id).windowId;
        }
        calls.push(["group", tabIds, id]);
        return id;
      },
      async ungroup(tabId) { calls.push(["ungroup", tabId]); tabData.get(tabId).groupId = -1; },
      async sendMessage(tabId, message, options = { frameId: 0 }) {
        calls.push(["sentinel", tabId, message, options]);
        if (options.documentId && options.documentId !== (tabData.get(tabId)?.documentId ?? `document-${tabId}`)) throw new Error("Could not establish connection. Receiving end does not exist.");
        const key = `${tabId}:${options.frameId ?? 0}`;
        if (!observations.has(key)) throw new Error("Could not establish connection. Receiving end does not exist.");
        const observation = sentinels.get(key).send(message.operation);
       if (!observation) throw new Error("Could not establish connection. Receiving end does not exist.");
        observations.set(key, observation);
        return observation;
      },
      async update(id, options) {
        if (!chrome.allowPopupRecovery) throw new Error("focus update forbidden");
        calls.push(["restoreTab", id, options]);
        return {};
      },
      async remove() { throw new Error("tab closing forbidden"); },
    },
    tabGroups: {
      onRemoved: new Event(), onUpdated: new Event(),
      async get(id) { if (!groups.has(id)) throw new Error("missing group"); return { ...groups.get(id) }; },
      async update(id, value) { Object.assign(groups.get(id), value); calls.push(["groupUpdate", id, value]); return { ...groups.get(id) }; },
    },
    scripting: { async executeScript(options) {
      calls.push(["inject", options]);
      const frameId = options.target.frameIds?.[0] ?? 0;
      const key = `${options.target.tabId}:${frameId}`;
      const existing = sentinels.get(key)?.send("sample");
      if (existing?.enabled) { observations.set(key, existing); return []; }
      const observer = sentinel({ now: () => chrome.now(), documentId: `doc-${++nextDocument}`, onInteraction: message => {
        observations.set(key, message);
        chrome.runtime.onMessage.emit(message, { id: chrome.runtime.id, tab: { id: options.target.tabId }, frameId });
      } });
      sentinels.set(key, observer);
      observations.set(key, observer.send("sample"));
      return [];
    } },
    webNavigation: { onCreatedNavigationTarget: new Event(), onCommitted: new Event(), onBeforeNavigate: new Event(), onErrorOccurred: new Event(), async getAllFrames({ tabId }) { return [{ tabId, frameId: 0, documentId: tabData.get(tabId)?.documentId ?? `document-${tabId}` }]; } },
    debugger: {
      onEvent: new Event(), onDetach: new Event(),
      async attach(target, version) { calls.push(["attach", target, version]); },
      async detach(target) { calls.push(["detach", target]); },
      async sendCommand(target, method, params) { calls.push(["cdp", target, method, params]); return method === "Page.getFrameTree" ? { frameTree: { frame: { id: "root", loaderId: "loader", url: tabData.get(target.tabId)?.url ?? "about:blank" } } } : { method }; },
    },
    action: { onClicked: new Event(),
      async setBadgeText(options) { calls.push(["badge", options]); },
      async setTitle(options) { calls.push(["title", options]); },
    },
    contextMenus: { onClicked: new Event(), create(options) { calls.push(["menu", options]); }, async removeAll() {} },
    alarms: { onAlarm: new Event(), async create(name, options) { calls.push(["alarm", name, options]); } },
    windows: { onFocusChanged: new Event(), async update(id, options) {
      if (!chrome.allowPopupRecovery) throw new Error("window focus forbidden");
      calls.push(["restoreWindow", id, options]);
      return {};
    } },
  };
  return chrome;
}
