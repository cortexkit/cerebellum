import { AgentTabs } from "./tabs.mjs";
import { InteractionEpochs } from "./epochs.mjs";
import { Agent } from "./agent.mjs";
import { NativeBridge } from "./native.mjs";
import { BrowserEvents } from "./events.mjs";
import { bounded } from "./errors.mjs";

export function start(chrome) {
  const handoverFailed = async (tabId, error) => {
    const reason = String(error?.reason ?? error?.message ?? "handover_failed").slice(0, 120);
    console.error(`Agent handover failed: ${reason}`);
    // A toolbar click has no reply channel. Keep the failure visible on that
    // tab until another handover succeeds, rather than leaving a silent group.
    await Promise.allSettled([
      chrome.action.setBadgeText({ tabId, text: "!" }),
      chrome.action.setTitle({ tabId, title: `Agent handover failed: ${reason}` }),
    ]);
  };
  let agent;
  const tabs = new AgentTabs(chrome, tabId => agent?.withdraw(tabId), tabId => epochs.install(tabId));
  const epochs = new InteractionEpochs(chrome, tabs);
  agent = new Agent(chrome, tabs, epochs);
  const bridge = new NativeBridge(chrome, agent);
  const events = new BrowserEvents(chrome, tabs, epochs, agent, handoverFailed);
  events.listen();
  const toggle = async tab => {
    if (!tab?.id) return;
    events.remember(tab);
    const handed = await tabs.toggle(tab.id);
    if (handed) await epochs.install(tab.id);
    await chrome.action.setBadgeText({ tabId: tab.id, text: "" });
    await chrome.action.setTitle({ tabId: tab.id, title: "Hand tab to Agent / take it back" });
  };
  const handover = tab => { void toggle(tab).catch(error => handoverFailed(tab?.id, error)); };
  chrome.action.onClicked.addListener(handover);
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "agent-handover") handover(tab);
  });
  const menu = async () => {
    await chrome.contextMenus.removeAll();
    chrome.contextMenus.create({ id: "agent-handover", title: "Hand tab to Agent / take it back", contexts: ["all"] });
  };
  chrome.runtime.onInstalled.addListener(() => { void menu().catch(() => {}); });
  chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === "agent-reconnect") bridge.connect(); });
  chrome.runtime.onStartup.addListener(() => bridge.connect());
  void tabs.ready.then(async () => {
    // Remember ids so a script popup that steals focus can return the person to
    // their previous tab/window. No outside URL, title or page text is retained.
    const active = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    for (const tab of active) events.remember({ id: tab.id, windowId: tab.windowId, active: true });
    for (const tabId of tabs.tabs.keys()) {
      await tabs.eligible(tabId);
      // A forcibly stopped worker may leave its extension-owned attachment alive.
      // Detach only recorded group members, never enumerate debugger targets.
      await bounded(chrome.debugger.detach({ tabId }), "cancel").catch(() => {});
      await epochs.install(tabId);
    }
    bridge.connect();
  }).catch(() => bridge.connect());
  return { tabs, epochs, agent, bridge, events };
}

if (globalThis.chrome?.runtime?.id) start(globalThis.chrome);
