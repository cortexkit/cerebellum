import { Refusal } from "./errors.mjs";

// This declaration is internal, never caller supplied. Use an isolated world so
// page scripts cannot replace computed-style getters used for frame dimensions.
const DIMENSIONS = "function(){const s=getComputedStyle(this);let w=parseFloat(s.width),h=parseFloat(s.height);if(s.boxSizing==='border-box'){w-=parseFloat(s.borderLeftWidth)+parseFloat(s.borderRightWidth)+parseFloat(s.paddingLeft)+parseFloat(s.paddingRight);h-=parseFloat(s.borderTopWidth)+parseFloat(s.borderBottomWidth)+parseFloat(s.paddingTop)+parseFloat(s.paddingBottom);}return {width:w,height:h};}";

export function transformPoint(point, geometry, inverse = false) {
  const { quad: q, width, height } = geometry;
  if (!Array.isArray(q) || q.length !== 8 || ![...q, width, height, point.x, point.y].every(Number.isFinite) || width <= 0 || height <= 0
    || Math.abs(q[4] - (q[2] + q[6] - q[0])) > 0.05 || Math.abs(q[5] - (q[3] + q[7] - q[1])) > 0.05) throw new Refusal("frame_geometry_unavailable");
  const [ux, uy, vx, vy] = [q[2] - q[0], q[3] - q[1], q[6] - q[0], q[7] - q[1]];
  const determinant = ux * vy - uy * vx;
  if (Math.abs(determinant) < 1e-9) throw new Refusal("frame_geometry_unavailable");
  const u = inverse ? ((point.x - q[0]) * vy - (point.y - q[1]) * vx) / determinant : point.x / width;
  const v = inverse ? (ux * (point.y - q[1]) - uy * (point.x - q[0])) / determinant : point.y / height;
  if (u < 0 || u > 1 || v < 0 || v > 1) throw new Refusal("point_outside_frame");
  return inverse ? { x: u * width, y: v * height } : { x: q[0] + ux * u + vx * v, y: q[1] + uy * u + vy * v };
}

export class FrameGeometry {
  constructor(frames, mappings) { this.frames = frames; this.mappings = mappings; }
  target(frame) { return frame.session_id === "root" ? { tabId: this.frames.state.tabId } : this.frames.sessions.get(frame.session_id); }
  send(frame, method, params) { return this.frames.send(this.target(frame), method, params); }
  parent(frame) { return this.mappings.find(candidate => candidate.frame_id === frame.parent_id); }

  async owner(parent, child) {
    return (await this.send(parent, "DOM.getFrameOwner", { frameId: child.frame_id })).backendNodeId;
  }

  async geometry(parent, backendNodeId) {
    if (!Number.isSafeInteger(backendNodeId)) throw new Refusal("frame_geometry_unavailable");
    const box = await this.send(parent, "DOM.getBoxModel", { backendNodeId });
    const world = await this.send(parent, "Page.createIsolatedWorld", { frameId: parent.frame_id, worldName: "cortexkit-frame-geometry" });
    const object = await this.send(parent, "DOM.resolveNode", { backendNodeId, executionContextId: world.executionContextId });
    if (!object.object?.objectId || !Number.isSafeInteger(world.executionContextId)) throw new Refusal("frame_geometry_unavailable");
    const dimensions = await this.send(parent, "Runtime.callFunctionOn", { objectId: object.object.objectId, functionDeclaration: DIMENSIONS, returnByValue: true });
    // Remote objects die with this action's attachment; no object id crosses a plan.
    return { quad: box.model?.content, width: dimensions.result?.value?.width, height: dimensions.result?.value?.height };
  }

  async globalPoint(frame, point) {
    let seen = 0;
    while (frame.parent_id) {
      if (++seen > 64) throw new Refusal("frame_limit");
      const parent = this.parent(frame);
      if (!parent) throw new Refusal("frame_stale");
      if (parent.session_id !== frame.session_id) point = transformPoint(point, await this.geometry(parent, await this.owner(parent, frame)));
      frame = parent;
    }
    return point;
  }

  async hit(point, scope, params) {
    const root = this.mappings.find(frame => !frame.parent_id);
    if (!root) throw new Refusal("frame_stale");
    if (scope) point = await this.globalPoint(scope, point);
    const viewport = (await this.send(root, "Page.getLayoutMetrics", {})).cssVisualViewport;
    if (!viewport || ![viewport.offsetX, viewport.offsetY, viewport.clientWidth, viewport.clientHeight].every(Number.isFinite) || point.x < viewport.offsetX || point.y < viewport.offsetY || point.x >= viewport.offsetX + viewport.clientWidth || point.y >= viewport.offsetY + viewport.clientHeight) throw new Refusal("point_outside_viewport");
    let session = root;
    for (let depth = 0; depth < 64; depth++) {
      const visual = session === root ? viewport : (await this.send(session, "Page.getLayoutMetrics", {})).cssVisualViewport;
      if (!visual || ![visual.pageX, visual.pageY, visual.offsetX, visual.offsetY].every(Number.isFinite)) throw new Refusal("frame_geometry_unavailable");
      // Mouse input is viewport-relative; DOM hit testing is document-relative.
      // Each renderer has its own scroll offset, including nested child pages.
      const hit = await this.send(session, "DOM.getNodeForLocation", { ...params, x: Math.round(point.x + visual.pageX - visual.offsetX), y: Math.round(point.y + visual.pageY - visual.offsetY) });
      const parent = this.mappings.find(frame => frame.frame_id === hit.frameId && frame.session_id === session.session_id);
      if (!parent) throw new Refusal("frame_stale");
      let next;
      for (const child of this.mappings.filter(frame => frame.parent_id === parent.frame_id && frame.session_id !== parent.session_id)) {
        if (await this.owner(parent, child) === hit.backendNodeId) { next = child; break; }
      }
      if (!next) return { ...hit, frame_point: point };
      point = transformPoint(point, await this.geometry(parent, hit.backendNodeId), true);
      session = next;
    }
    throw new Refusal("frame_limit");
  }
}
