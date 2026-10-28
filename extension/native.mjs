import { bounded, DEADLINES, Refusal } from "./errors.mjs";
import { EXTENSION_REVISION } from "./revision.mjs";

export const NATIVE_HOST = "com.cortexkit.cerebellum";
export const MAX_MESSAGE_BYTES = 1024 * 1024;
export const MAX_RESULT_BYTES = 16 * 1024 * 1024;
export const CHUNK_BYTES = 128 * 1024;
const encoder = new TextEncoder();
export const byteLength = value => encoder.encode(typeof value === "string" ? value : JSON.stringify(value)).length;
const nextTurn = () => new Promise(resolve => setTimeout(resolve, 0));

// Cut at Unicode scalar boundaries so UTF-8 byte counts survive native JSON
// serialization; surrogate halves must never be split between ReplyChunks.
export function* chunks(text) {
  let start = 0, bytes = 0;
  for (let i = 0; i < text.length;) {
    const code = text.codePointAt(i);
    const width = code > 0xffff ? 2 : 1;
    const count = code <= 0x7f ? 1 : code <= 0x7ff ? 2 : code <= 0xffff ? 3 : 4;
    if (bytes + count > CHUNK_BYTES) { yield text.slice(start, i); start = i; bytes = 0; }
    bytes += count;
    i += width;
  }
  if (start < text.length) yield text.slice(start);
}

export class NativeBridge {
  constructor(chrome, agent) {
    this.chrome = chrome;
    this.agent = agent;
    this.port = null;
    this.epoch = null;
    this.entries = new Map();
    this.highestId = 0;
  }

  connect() {
    if (this.port) return;
    if (this.disconnecting) {
      void this.disconnecting.then(() => this.connect());
      return;
    }
    const port = this.chrome.runtime.connectNative(NATIVE_HOST);
    this.port = port;
    const helloTimer = setTimeout(() => { if (this.port === port && this.epoch === null) this.drop(port); }, DEADLINES.hello);
    port.onMessage.addListener(frame => {
      if (this.port !== port) return;
      try {
        if (byteLength(frame) > MAX_MESSAGE_BYTES) throw new Refusal("message_too_large");
        if (frame.type === "host_accepted") {
          if (this.epoch !== null || frame.protocol !== 1 || !Number.isSafeInteger(frame.epoch) || frame.epoch <= 0) throw new Refusal("invalid_handshake");
          clearTimeout(helloTimer);
          this.epoch = frame.epoch;
          this.highestId = 0;
          this.agent.connect(frame.epoch);
        } else if (frame.type === "host_refused") {
          this.drop(port);
        } else if (frame.type === "relay" && this.epoch !== null) {
          this.receive(frame.message);
        } else throw new Refusal("invalid_frame");
      } catch { this.drop(port); }
    });
    port.onDisconnect.addListener(() => {
      // Chrome reports an unchecked error unless lastError is read in this callback.
      void this.chrome.runtime.lastError;
      clearTimeout(helloTimer);
      this.drop(port, false);
    });
  }

  drop(port = this.port, disconnect = true) {
    if (this.port !== port) return;
    this.port = null;
    this.epoch = null;
    for (const entry of this.entries.values()) {
      entry.cancelled = true;
      if (entry.state) entry.state.cancelled = true;
      clearTimeout(entry.timer);
    }
    this.entries.clear();
    this.disconnecting = this.agent.disconnect().catch(() => {}).finally(() => { this.disconnecting = null; });
    if (disconnect) port?.disconnect();
    // Alarms survive worker suspension; reconnecting creates a new server epoch,
    // never a retry of any old invocation or transfer.
    void this.chrome.alarms.create("agent-reconnect", { delayInMinutes: 0.5 });
  }

  post(entry, body) {
    if (!this.port || this.epoch !== entry.epoch || entry.ended) return false;
    const frame = { type: "relay", message: { id: entry.id, epoch: entry.epoch, body } };
    if (byteLength(frame) > MAX_MESSAGE_BYTES) throw new Refusal("message_too_large");
    this.port.postMessage(frame);
    return true;
  }

  receive(message) {
    if (!message || message.epoch !== this.epoch || !Number.isSafeInteger(message.id) || message.id < 0 || Object.keys(message).some(key => !["id", "epoch", "body"].includes(key))) return;
    const body = message.body;
    if (!body || typeof body !== "object") throw new Refusal("invalid_message");
    if (body.type === "goodbye") {
      for (const entry of this.entries.values()) {
        if (entry.route.channel === body.route?.channel && entry.route.epoch === body.route?.epoch) void this.cancel(entry);
      }
      void this.agent.goodbye(body.route).catch(() => this.drop());
      return;
    }
    if (message.id === 0) return;
    if (body.type === "attach") {
      if (message.id <= this.highestId) return;
      this.highestId = message.id;
      const entry = { id: message.id, epoch: message.epoch, route: body.route, cancelled: false, ended: false, phase: "attaching" };
      this.entries.set(entry.id, entry);
      // The bridge owns queue order. Refuse overlapping actions rather than
      // creating a second extension queue whose deadlines could hide a hang.
      if (this.entries.size !== 1) { void this.refuse(entry, new Refusal("action_busy")); return; }
      if (!body.route || !Number.isInteger(body.route.channel) || body.route.channel < 0 || body.route.channel > 65535 || !Number.isInteger(body.route.epoch) || body.route.epoch < 0 || body.route.epoch > 0xffffffff) { void this.refuse(entry, new Refusal("invalid_route")); return; }
      entry.preparing = this.agent.prepare(body.route, body.command, message.epoch);
      void entry.preparing.then(async state => {
        entry.state = state;
        if (entry.cancelled || this.epoch !== entry.epoch) { await this.cancel(entry); return; }
        entry.phase = "attached";
        this.post(entry, { type: "attached" });
        entry.timer = setTimeout(() => { void this.refuse(entry, new Refusal("dispatch_deadline")); }, DEADLINES.dispatch);
      }).catch(error => { void this.refuse(entry, error); });
      return;
    }
    const entry = this.entries.get(message.id);
    if (!entry || entry.ended) return;
    if (body.type === "cancel") { void this.cancel(entry); return; }
    if (body.type !== "dispatch" || entry.phase !== "attached" || entry.cancelled) return;
    clearTimeout(entry.timer);
    entry.phase = "dispatched";
    this.post(entry, { type: "dispatched", input_dispatched: false });
    void bounded(this.agent.execute(entry.state).then(result => this.complete(entry, result)), "reply").catch(error => this.refuse(entry, error));
  }

  end(entry) {
    entry.ended = true;
    clearTimeout(entry.timer);
    if (this.entries.get(entry.id) === entry) this.entries.delete(entry.id);
  }

  async cleanup(entry) {
    if (entry.state) await this.agent.finish(entry.state);
  }

  async refuse(entry, error) {
    if (entry.ended || entry.cancelled) return;
    entry.cancelled = true;
    if (entry.state) entry.state.cancelled = true;
    try {
      await this.cleanup(entry);
      // Every refusal carries the contract revision, so cerebellum can tell a
      // refusal from a mismatched extension apart from an ordinary one.
      this.post(entry, { type: "refused", reason: JSON.stringify({ reason: error.reason ?? "extension_error", ...(error.detail ?? { remedy: "read again" }), extension_revision: EXTENSION_REVISION }), input_dispatched: entry.state?.input ?? false, detached: error.detached !== false });
      this.end(entry);
      if (error.detached === false && this.epoch === entry.epoch) this.drop();
    } catch { if (this.epoch === entry.epoch) this.drop(); }
  }

  async cancel(entry) {
    if (entry.ended) return;
    if (entry.cancelling) return entry.cancelling;
    entry.cancelled = true;
    clearTimeout(entry.timer);
    entry.cancelling = (async () => {
      try {
        if (!entry.state && entry.preparing) entry.state = await bounded(entry.preparing, "cancel");
        if (entry.state) await this.agent.cancel(entry.state);
        await this.cleanup(entry);
        this.post(entry, { type: "cancelled", input_dispatched: entry.state?.input ?? false, detached: true });
        this.end(entry);
      } catch { if (this.epoch === entry.epoch) this.drop(); }
    })();
    return entry.cancelling;
  }

  async complete(entry, result) {
    if (entry.cancelled || entry.ended || this.epoch !== entry.epoch) return;
    await this.cleanup(entry);
    // Every completed result carries the contract revision; cerebellum checks
    // it before decoding anything else in the reply.
    result = { ...result, extension_revision: EXTENSION_REVISION };
    const metadata = { input_dispatched: entry.state?.input ?? false, detached: true };
    const body = { type: "completed", result, ...metadata };
    // Check the whole escaped JSON envelope, not just the unescaped payload.
    const frame = { type: "relay", message: { id: entry.id, epoch: entry.epoch, body } };
    if (byteLength(frame) <= MAX_MESSAGE_BYTES) {
      if (entry.state?.tabId !== undefined) await this.agent.guard(entry.state);
      this.post(entry, body);
    } else {
      const text = JSON.stringify(result);
      const bytes = byteLength(text);
      if (bytes > MAX_RESULT_BYTES) throw new Refusal("reply_too_large", "request a smaller snapshot or screenshot");
      this.post(entry, { type: "reply_start", bytes, input_dispatched: metadata.input_dispatched });
      let sequence = 0;
      for (const data of chunks(text)) {
        await bounded(nextTurn(), "chunk");
        if (entry.cancelled || entry.ended || this.epoch !== entry.epoch) return;
        if (entry.state?.tabId !== undefined) await this.agent.guard(entry.state);
        this.post(entry, { type: "reply_chunk", sequence: sequence++, data });
      }
      if (entry.cancelled || entry.ended || this.epoch !== entry.epoch) return;
      if (entry.state?.tabId !== undefined) await this.agent.guard(entry.state);
      this.post(entry, { type: "reply_end", ...metadata });
    }
    this.end(entry);
  }
}
