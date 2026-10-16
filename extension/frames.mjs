import { bounded, Refusal } from "./errors.mjs";

const frameUrl = frame => frame.url + (frame.urlFragment && !frame.url.includes("#") ? frame.urlFragment : "");

// Frame ids from CDP and webNavigation are unrelated. A URL alone is not an
// identity: sibling frames can load the same page, including after navigation.
export function mapFrames(tree, navigation, sessions = new Map()) {
  const mapped = [];
  const used = new Set();
  function visit(node, parent, depth = 0) {
    if (depth > 64 || mapped.length >= 256) throw new Refusal("frame_limit");
    const frame = node.frame;
    if (!frame || typeof frame.id !== "string" || typeof frame.loaderId !== "string" || typeof frame.url !== "string") throw new Refusal("frame_stale");
    const url = frameUrl(frame);
    const candidates = navigation.filter(item => !used.has(item.frameId)
      && item.parentFrameId === (parent?.web_navigation_frame_id ?? -1)
      && item.url === url
      && (!frame.documentId || !item.documentId || frame.documentId === item.documentId));
    if (candidates.length > 1) throw new Refusal("frame_ambiguous", "read again after the embedded frames change");
    if (candidates.length !== 1) throw new Refusal("frame_stale", "read again");
    const match = candidates[0];
    used.add(match.frameId);
    const entry = { frame_id: frame.id, loader_id: frame.loaderId, url,
      session_id: sessions.get(frame.id) ?? "root", web_navigation_frame_id: match.frameId,
      ...(parent ? { parent_id: parent.frame_id } : {}),
      ...(match.documentId ? { document_id: match.documentId } : {}) };
    mapped.push(entry);
    for (const child of node.childFrames ?? []) visit(child, entry, depth + 1);
  }
  visit(tree, null);
  if (used.size !== navigation.length) throw new Refusal("frame_stale", "read again");
  return mapped;
}

export class Frames {
  constructor(chrome, state, guard) {
    this.chrome = chrome;
    this.state = state;
    this.guard = guard;
    this.sessions = new Map();
    this.pending = new Set();
    this.failure = null;
    this.listener = (source, method, params) => {
      if (source.tabId !== state.tabId || source.sessionId && ![...this.sessions.values()].some(session => session.sessionId === source.sessionId)) return;
      if (method === "Target.detachedFromTarget") {
        for (const [id, session] of this.sessions) if (session.sessionId === params.sessionId) this.sessions.delete(id);
        return;
      }
      if (method !== "Target.attachedToTarget") return;
      // Auto-attach is scoped to the claimed tab's iframe descendants, never
      // arbitrary browser targets, workers or popup tabs.
      if (params.targetInfo.type !== "iframe") return;
      const session = { tabId: state.tabId, sessionId: params.sessionId };
      this.sessions.set(params.targetInfo.targetId, session);
      const pending = this.autoAttach(session).catch(error => { this.failure = error; }).finally(() => this.pending.delete(pending));
      this.pending.add(pending);
    };
    chrome.debugger.onEvent.addListener(this.listener);
  }

  async send(target, method, params = {}) {
    await this.guard();
    return bounded(this.chrome.debugger.sendCommand(target, method, params), "reply");
  }

  async autoAttach(target) {
    // Chrome 125+ exposes flattened child sessions to extensions. This exact
    // internal method is not part of the caller's CDP command vocabulary.
    await this.send(target, "Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true, filter: [{ type: "iframe", exclude: false }, { exclude: true }] });
  }

  async start() { await this.autoAttach({ tabId: this.state.tabId }); }
  close() { this.chrome.debugger.onEvent.removeListener(this.listener); }

  async read() {
    await this.guard();
    const before = await bounded(this.chrome.webNavigation.getAllFrames({ tabId: this.state.tabId }), "reply");
    const root = await this.send({ tabId: this.state.tabId }, "Page.getFrameTree");
    const trees = new Map();
    const queried = new Set();
    while (true) {
      while (this.pending.size) await Promise.all([...this.pending]);
      if (this.failure) throw this.failure;
      const next = [...this.sessions].find(([id]) => !queried.has(id));
      if (!next) break;
      if (queried.size >= 128) throw new Refusal("frame_limit");
      const [id, session] = next;
      queried.add(id);
      const tree = (await this.send(session, "Page.getFrameTree")).frameTree;
      if (!tree?.frame) throw new Refusal("frame_stale");
      trees.set(tree.frame.id, { tree, owner: id });
    }
    const owners = new Map();
    function expand(node, owner = "root", depth = 0) {
      if (!node?.frame || depth > 64) throw new Refusal("frame_stale");
      const replacement = trees.get(node.frame.id);
      if (replacement && owner !== replacement.owner) return expand({ ...replacement.tree, frame: { ...replacement.tree.frame, ...(node.frame.parentId ? { parentId: node.frame.parentId } : {}) } }, replacement.owner, depth + 1);
      owners.set(node.frame.id, owner);
      return { ...node, frame: { ...node.frame, url: frameUrl(node.frame) }, childFrames: (node.childFrames ?? []).map(child => expand(child, owner, depth + 1)) };
    }
    const tree = expand(root.frameTree);
    // An unattached-to-the-tree session is not evidence of ancestry. Do not
    // expose content from a target the claimed tab's tree cannot account for.
    if ([...trees.keys()].some(id => !owners.has(id))) throw new Refusal("frame_stale");
    const after = await bounded(this.chrome.webNavigation.getAllFrames({ tabId: this.state.tabId }), "reply");
    const signature = frames => JSON.stringify(frames?.map(({ frameId, parentFrameId, documentId, url }) => ({ frameId, parentFrameId, documentId, url })).sort((a, b) => a.frameId - b.frameId));
    if (signature(before) !== signature(after)) throw new Refusal("frame_stale", "read again");
    return { tree, mappings: mapFrames(tree, after ?? [], owners) };
  }

  async resolve(command) {
    const { mappings } = await this.read();
    const frame = mappings.find(frame => frame.frame_id === command.frame_id);
    if (!frame || frame.loader_id !== command.loader_id || frame.session_id !== command.session_id) throw new Refusal("frame_stale", "read again");
    return { frame, target: frame.session_id === "root" ? { tabId: this.state.tabId } : this.sessions.get(frame.session_id) };
  }
}
