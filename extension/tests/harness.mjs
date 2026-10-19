import { AgentTabs } from "../tabs.mjs";
import { InteractionEpochs } from "../epochs.mjs";
import { Agent } from "../agent.mjs";
import { fakeChrome } from "./fake-chrome.mjs";

export const route = { channel: 2, epoch: 1 };
export const read = { method: "Accessibility.getFullAXTree", params: {} };
export const press = { method: "Input.dispatchMouseEvent", params: { type: "mousePressed", x: 10, y: 20, button: "left" } };
export const release = { method: "Input.dispatchMouseEvent", params: { type: "mouseReleased", x: 10, y: 20, button: "left" } };
export async function setup() {
  const chrome = fakeChrome();
  let agent;
  const tabs = new AgentTabs(chrome, id => agent?.withdraw(id), id => epochs.install(id));
  await tabs.ready;
  const epochs = new InteractionEpochs(chrome, tabs, () => chrome.now());
  agent = new Agent(chrome, tabs, epochs);
  agent.connect(50);
  const record = await tabs.join(2, "handed");
  await epochs.install(2);
  const claim = await agent.prepare(route, { version: 2, action: "claim_tab", tab: record.handle }, 50);
  await agent.execute(claim);
  await agent.finish(claim);
  const run = async (plan, owner = route) => {
    const state = await agent.prepare(owner, plan, agent.connectionEpoch);
    try { return await agent.execute(state); } finally { await agent.finish(state); }
  };
  const cdp = commands => ({ version: 2, action: "cdp", tab: record.handle, commands, ...(agent.baselines.has(2) ? { observer_continuity: agent.baselines.get(2).continuity } : {}) });
  const fresh = () => run(cdp([read]));
  const input = epoch => ({ ...cdp([press, release]), interaction_epoch: epoch });
  return { chrome, tabs, epochs, agent, record, run, cdp, fresh, input };
}

export const turn = () => new Promise(resolve => setImmediate(resolve));
