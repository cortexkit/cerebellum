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
    // Record an ambiguous or stale mapping on its frame entry instead of
    // selecting a candidate. Sibling and top-level reads can then continue,
    // and the renderer can mark the unreadable frame at its iframe owner.
    const reason = parent?.unreadable_reason ?? (!frame.loaderId ? "stale" : candidates.length > 1 ? "ambiguous" : candidates.length === 0 ? "stale" : null);
    const match = reason ? null : candidates[0];
    if (match) used.add(match.frameId);
    const entry = { frame_id: frame.id, loader_id: frame.loaderId, url,
      session_id: sessions.get(frame.id) ?? "root",
      ...(match ? { web_navigation_frame_id: match.frameId } : { unreadable_reason: reason }),
      ...(parent ? { parent_id: parent.frame_id } : {}),
      ...(match?.documentId ? { document_id: match.documentId } : {}) };
    mapped.push(entry);
    for (const child of node.childFrames ?? []) visit(child, entry, depth + 1);
  }
  visit(tree, null);
  return mapped;
}

export class Frames {
  constructor(chrome, state, guard) {
    this.chrome = chrome;
    this.state = state;
    this.guard = guard;
    this.sessions = new Map();
    this.pending = new Set();
    this.failures = new Set();
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
      const pending = this.autoAttach(session).catch(() => { this.failures.add(params.targetInfo.targetId); }).finally(() => this.pending.delete(pending));
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

  async navigation() {
    try { return await bounded(this.chrome.webNavigation.getAllFrames({ tabId: this.state.tabId }), "reply"); }
    catch { await this.guard(); return []; }
  }

  async read(attempt = 0) {
    await this.guard();
    const before = await this.navigation();
    const root = await this.send({ tabId: this.state.tabId }, "Page.getFrameTree");
    const trees = new Map();
    const queried = new Set();
    while (true) {
      while (this.pending.size) await Promise.all([...this.pending]);
      const next = [...this.sessions].find(([id]) => !queried.has(id));
      if (!next) break;
      if (queried.size >= 128) throw new Refusal("frame_limit");
      const [id, session] = next;
      queried.add(id);
      if (this.failures.has(id)) continue;
      try {
        const tree = (await this.send(session, "Page.getFrameTree")).frameTree;
        if (tree?.frame) trees.set(tree.frame.id, { tree, owner: id });
      } catch {
        // A child target can detach before Page.getFrameTree replies. Ignore
        // that session, but still verify tab eligibility before continuing.
        await this.guard();
      }
    }
    const owners = new Map();
    function expand(node, owner = "root", depth = 0) {
      if (!node?.frame || depth > 64) throw new Refusal("frame_stale");
      const replacement = trees.get(node.frame.id);
      if (replacement && owner !== replacement.owner) return expand({ ...replacement.tree, frame: { ...replacement.tree.frame, ...(node.frame.parentId ? { parentId: node.frame.parentId } : {}) } }, replacement.owner, depth + 1);
      owners.set(node.frame.id, owner);
      return { ...node, frame: { ...node.frame, url: frameUrl(node.frame) }, childFrames: (node.childFrames ?? []).map(child => expand(child, owner, depth + 1)) };
    }
    // Expand only nodes in the claimed tab's tree. A session whose root has
    // no tree position is ignored rather than supplying unrelated content.
    const firstTree = expand(root.frameTree);
    const latestRoot = await this.send({ tabId: this.state.tabId }, "Page.getFrameTree");
    const tree = expand(latestRoot.frameTree);
    const after = await this.navigation();
    const signature = frames => JSON.stringify(frames?.map(({ frameId, parentFrameId, documentId, url }) => ({ frameId, parentFrameId, documentId, url })).sort((a, b) => a.frameId - b.frameId));
    const flatten = node => [node.frame, ...(node.childFrames ?? []).flatMap(flatten)];
    const treeSignature = node => JSON.stringify(flatten(node).map(({ id, parentId, loaderId, url }) => ({ id, parentId, loaderId, url })).sort((a, b) => a.id.localeCompare(b.id)));
    const treeChanged = treeSignature(firstTree) !== treeSignature(tree);
    if ((treeChanged || signature(before) !== signature(after)) && attempt === 0) return this.read(1);
    const mappings = mapFrames(tree, after ?? [], owners);
    if (treeChanged || signature(before) !== signature(after)) {
      const previous = mapFrames(tree, before ?? [], owners);
      for (const frame of mappings) {
        const old = previous.find(old => old.frame_id === frame.frame_id);
        if (!old || old.web_navigation_frame_id !== frame.web_navigation_frame_id || old.document_id !== frame.document_id || old.unreadable_reason !== frame.unreadable_reason) frame.unreadable_reason = "stale";
        const priorFrame = flatten(firstTree).find(old => old.id === frame.frame_id);
        if (!priorFrame || priorFrame.loaderId !== frame.loader_id || frameUrl(priorFrame) !== frame.url) frame.unreadable_reason = "stale";
        const parent = mappings.find(parent => parent.frame_id === frame.parent_id);
        if (parent?.unreadable_reason) frame.unreadable_reason = parent.unreadable_reason;
      }
    }
    return { tree, mappings };
  }

  async resolve(command, rootRead = false) {
    const { mappings } = await this.read();
    const frame = mappings.find(frame => frame.frame_id === command.frame_id);
    if (frame?.unreadable_reason && !(rootRead && !frame.parent_id)) throw new Refusal(`frame_${frame.unreadable_reason}`, "read again");
    if (!frame || frame.loader_id !== command.loader_id || frame.session_id !== command.session_id) throw new Refusal("frame_stale", "read again");
    return { frame, target: frame.session_id === "root" ? { tabId: this.state.tabId } : this.sessions.get(frame.session_id) };
  }
}
