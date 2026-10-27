import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeBridge, byteLength, chunks, CHUNK_BYTES, MAX_MESSAGE_BYTES } from "../native.mjs";
import { EXTENSION_REVISION } from "../revision.mjs";
import { setup, route, read, release, turn } from "./harness.mjs";
import { deferred } from "./fake-chrome.mjs";
import { readFileSync } from "node:fs";

// Frames the native host's Rust tests also check, so both ends of the native
// port are held to the same bytes rather than to their own idea of them.
const hostWire = JSON.parse(readFileSync(new URL("./native-host-wire.json", import.meta.url), "utf8"));

function waitBody(port, type, id) {
  const matches = frame => frame.message?.body.type === type && (id === undefined || frame.message.id === id);
  const existing = port.sent.find(matches);
  if (existing) return Promise.resolve(existing.message.body);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { port.onPost.removeListener(listener); reject(new Error(`missing ${type}`)); }, 2000);
    const listener = frame => { if (matches(frame)) { clearTimeout(timer); port.onPost.removeListener(listener); resolve(frame.message.body); } };
    port.onPost.addListener(listener);
  });
}

async function native(t) {
  const f = await setup();
  const bridge = new NativeBridge(f.chrome, f.agent);
  bridge.connect();
  const port = f.chrome.ports.at(-1);
  port.onMessage.emit({ type: "host_accepted", protocol: 1, epoch: 50 });
  await f.run({ version: 2, action: "claim_tab", tab: f.record.handle });
  t.after(async () => { bridge.drop(); await bridge.disconnecting; });
  const send = (id, body, epoch = 50, to = port) => to.onMessage.emit({ type: "relay", message: { id, epoch, body } });
  const attach = (id, command) => send(id, { type: "attach", route, command });
  const invoke = async (id, command) => { attach(id, command); await waitBody(port, "attached", id); send(id, { type: "dispatch" }); return waitBody(port, "completed", id); };
  return { ...f, bridge, port, send, attach, invoke };
}

test("native bridge observes Attach Dispatch and detached terminal completion", async t => {
  const f = await native(t);
  f.chrome.calls.length = 0;
  f.attach(1, f.cdp([read]));
  await waitBody(f.port, "attached", 1);
  assert.equal(f.chrome.calls.some(call => call[0] === "cdp"), false);
  f.send(1, { type: "dispatch" });
  const reply = await waitBody(f.port, "completed", 1);
  assert.equal(reply.detached, true);
  assert.equal(reply.input_dispatched, false);
  assert.deepEqual(reply.result.results, [{ result: { method: read.method } }]);
  assert.deepEqual(f.port.sent.map(frame => frame.message.body.type), ["attached", "dispatched", "completed"]);
  assert.equal(f.chrome.calls.filter(call => call[0] === "detach").length, 1);
});

test("native plan-level method refusals use the refusal path before attach", async t => {
  const f = await native(t);
  f.chrome.calls.length = 0;
  f.attach(1, f.cdp([{ method: "Target.createTarget", params: {} }]));
  const refusal = await waitBody(f.port, "refused", 1);
  assert.equal(JSON.parse(refusal.reason).reason, "unsupported_cdp_method");
  assert.equal(refusal.detached, true);
  assert.equal(f.chrome.calls.some(call => call[0] === "attach"), false);
});

test("native cancellation during attach waits for detachment and dispatches nothing", async t => {
  const f = await native(t);
  const pause = deferred();
  f.chrome.debugger.attach = () => pause.promise;
  f.attach(1, f.cdp([read]));
  await turn();
  f.send(1, { type: "cancel" });
  pause.resolve();
  const cancelled = await waitBody(f.port, "cancelled", 1);
  assert.equal(cancelled.detached, true);
  assert.equal(cancelled.input_dispatched, false);
  assert.equal(f.chrome.calls.some(call => call[0] === "cdp"), false);
  assert.equal(f.chrome.calls.filter(call => call[0] === "detach").length, 1);
});

test("native replies chunk escaped Unicode and stop on cancellation", async t => {
  const f = await native(t);
  f.chrome.debugger.sendCommand = async () => ({ data: ('"\\😀').repeat(180000) });
  f.attach(1, f.cdp([read]));
  await waitBody(f.port, "attached", 1);
  f.send(1, { type: "dispatch" });
  await waitBody(f.port, "reply_chunk", 1);
  f.send(1, { type: "cancel" });
  const cancelled = await waitBody(f.port, "cancelled", 1);
  assert.equal(cancelled.detached, true);
  await turn();
  assert.equal(f.port.sent.some(frame => frame.message.body.type === "reply_end"), false);
  const count = f.port.sent.length;
  await turn();
  assert.equal(f.port.sent.length, count);
  assert.ok(f.port.sent.every(frame => byteLength(frame) <= MAX_MESSAGE_BYTES));
});

test("native complete chunk stream reconstructs exact serialized result", async t => {
  const f = await native(t);
  const data = "雪😀\\\"".repeat(150000);
  f.chrome.debugger.sendCommand = async () => ({ data });
  f.attach(1, f.cdp([read]));
  await waitBody(f.port, "attached", 1);
  f.send(1, { type: "dispatch" });
  const end = await waitBody(f.port, "reply_end", 1);
  assert.equal(end.detached, true);
  const bodies = f.port.sent.map(frame => frame.message.body);
  const start = bodies.find(body => body.type === "reply_start");
  const received = bodies.filter(body => body.type === "reply_chunk");
  assert.deepEqual(received.map(chunk => chunk.sequence), received.map((_, i) => i));
  const text = received.map(chunk => chunk.data).join("");
  assert.equal(byteLength(text), start.bytes);
  assert.equal(JSON.parse(text).results[0].result.data, data);
  assert.ok(received.every(chunk => byteLength(chunk.data) <= CHUNK_BYTES));
  assert.ok(f.port.sent.every(frame => byteLength(frame) <= MAX_MESSAGE_BYTES));
});

test("native withdrawal during chunks yields no ReplyEnd or further content", async t => {
  const f = await native(t);
  f.chrome.debugger.sendCommand = async () => ({ data: "x".repeat(1100000) });
  f.attach(1, f.cdp([read]));
  await waitBody(f.port, "attached", 1);
  f.send(1, { type: "dispatch" });
  await waitBody(f.port, "reply_chunk", 1);
  f.chrome.tabData.get(2).groupId = -1;
  const refused = await waitBody(f.port, "refused", 1);
  assert.equal(refused.detached, true);
  assert.equal(f.port.sent.some(frame => frame.message.body.type === "reply_end"), false);
});

test("native reconnect is a new epoch and never replays an old dispatch", async t => {
  const f = await native(t);
  const fresh = await f.fresh();
  const pause = deferred();
  const sendCommand = f.chrome.debugger.sendCommand;
  let dispatches = 0;
  const cleanup = [];
  f.chrome.debugger.sendCommand = async (...args) => {
    if (args[2].type === "mouseReleased") {
      cleanup.push(args[2]);
      return sendCommand(...args);
    }
    dispatches += 1;
    await pause.promise;
    return sendCommand(...args);
  };
  f.attach(1, f.input(fresh.interaction_epoch));
  await waitBody(f.port, "attached", 1);
  f.send(1, { type: "dispatch" });
  await turn();
  assert.equal(dispatches, 1);
  f.port.onDisconnect.emit();
  await f.bridge.disconnecting;
  f.bridge.connect();
  const next = f.chrome.ports.at(-1);
  next.onMessage.emit({ type: "host_accepted", protocol: 1, epoch: 51 });
  f.send(1, { type: "dispatch" }, 50, next);
  f.send(2, { type: "attach", route, command: f.cdp([read]) }, 50, next);
  pause.resolve();
  await turn();
  assert.equal(dispatches, 1);
  assert.deepEqual(cleanup, [release.params]);
  assert.equal(next.sent.length, 0);
  assert.equal(f.agent.connectionEpoch, 51);
  assert.equal(f.agent.baselines.size, 0);
});

test("duplicate invocation and duplicate Dispatch are never executed twice", async t => {
  const f = await native(t);
  await f.invoke(1, f.cdp([read]));
  const before = f.chrome.calls.filter(call => call[0] === "cdp").length;
  f.attach(1, f.cdp([read]));
  f.send(1, { type: "dispatch" });
  await turn();
  assert.equal(f.chrome.calls.filter(call => call[0] === "cdp").length, before);
});

test("Goodbye releases handed claims and keeps the tab grouped", async t => {
  const f = await native(t);
  const handle = f.record.handle;
  f.send(0, { type: "goodbye", route });
  await turn();
  assert.equal(f.chrome.tabData.has(1), true);
  assert.equal(f.chrome.tabData.has(2), true);
  assert.equal(f.chrome.tabData.get(2).groupId, f.tabs.group.id);
  assert.equal(f.tabs.tabs.get(2)?.handle, handle);
  assert.equal(f.agent.claims.size, 0);
});

test("chunk splitter never splits astral Unicode or exceeds the UTF-8 cap", () => {
  const text = "a".repeat(CHUNK_BYTES - 1) + "😀雪";
  const parts = [...chunks(text)];
  assert.equal(parts.join(""), text);
  assert.ok(parts.every(part => byteLength(part) <= CHUNK_BYTES));
  assert.equal(parts[1], "😀雪");
});


test("native attach deadline reports unresolved detachment and drops the port", async t => {
  const f = await native(t);
  const pause = deferred();
  f.chrome.debugger.attach = () => pause.promise;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  f.attach(1, f.cdp([read]));
  await turn();
  t.mock.timers.tick(5001);
  await turn();
  const refusal = f.port.sent.find(frame => frame.message.body.type === "refused").message.body;
  assert.equal(JSON.parse(refusal.reason).reason, "attach_deadline");
  assert.equal(refusal.detached, false);
  assert.equal(f.bridge.port, null);
  pause.resolve();
  await turn();
  assert.ok(f.chrome.calls.some(call => call[0] === "detach"));
  assert.equal(f.chrome.calls.some(call => call[0] === "cdp"), false);
});

test("native dispatch deadline detaches without sending any command", async t => {
  const f = await native(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  f.attach(1, f.cdp([read]));
  await turn();
  t.mock.timers.tick(5001);
  await turn();
  const refusal = f.port.sent.find(frame => frame.message.body.type === "refused").message.body;
  assert.equal(JSON.parse(refusal.reason).reason, "dispatch_deadline");
  assert.equal(refusal.detached, true);
  assert.equal(f.chrome.calls.some(call => call[0] === "cdp"), false);
});

test("native reply deadline cancels a stalled press and sends only its cleanup release", async t => {
  const f = await native(t);
  const fresh = await f.fresh();
  const pause = deferred();
  let calls = 0;
  const cleanup = [];
  const sendCommand = f.chrome.debugger.sendCommand;
  f.chrome.debugger.sendCommand = async (...args) => {
    if (args[2].type === "mouseReleased") {
      cleanup.push(args[2]);
      return sendCommand(...args);
    }
    calls += 1;
    return pause.promise;
  };
  t.mock.timers.enable({ apis: ["setTimeout"] });
  f.attach(1, f.input(fresh.interaction_epoch));
  await turn();
  f.send(1, { type: "dispatch" });
  await turn();
  assert.equal(calls, 1);
  t.mock.timers.tick(30001);
  await turn();
  const refusal = f.port.sent.find(frame => frame.message.body.type === "refused").message.body;
  assert.equal(JSON.parse(refusal.reason).reason, "reply_deadline");
  assert.equal(refusal.detached, true);
  assert.equal(refusal.input_dispatched, true);
  pause.resolve({});
  await turn();
  assert.equal(calls, 1);
  assert.deepEqual(cleanup, [release.params]);
});

test("native bridge answers the native host's own frames for a first open_tab without closing the port", async t => {
  const f = await setup();
  const bridge = new NativeBridge(f.chrome, f.agent);
  bridge.connect();
  const port = f.chrome.ports.at(-1);
  t.after(async () => { bridge.drop(); await bridge.disconnecting; });
  let disconnected = false;
  port.onDisconnect.addListener(() => { disconnected = true; });
  const [accepted, attach, dispatch] = hostWire.host_to_extension;
  port.onMessage.emit(accepted);
  port.onMessage.emit(attach);
  await waitBody(port, "attached", 1);
  port.onMessage.emit(dispatch);
  const completed = await waitBody(port, "completed", 1);
  assert.equal(disconnected, false);
  assert.deepEqual(port.sent.slice(0, 2), hostWire.extension_to_host);
  assert.equal(completed.detached, true);
  assert.equal(typeof completed.result.tab, "string");
  assert.equal(completed.result.connection_epoch, hostWire.epoch);
});

// Cerebellum refuses any reply whose contract revision is missing or differs
// from its own, so every terminal reply shape must carry it.
test("completed, chunked and refused replies all carry the contract revision", async t => {
  const f = await native(t);
  assert.ok(Number.isSafeInteger(EXTENSION_REVISION) && EXTENSION_REVISION > 0);
  const completed = await f.invoke(1, f.cdp([read]));
  assert.equal(completed.result.extension_revision, EXTENSION_REVISION);
  assert.deepEqual(completed.result.results, [{ result: { method: read.method } }]);

  f.attach(2, f.cdp([{ method: "Target.createTarget", params: {} }]));
  const refusal = JSON.parse((await waitBody(f.port, "refused", 2)).reason);
  assert.equal(refusal.reason, "unsupported_cdp_method");
  assert.equal(refusal.extension_revision, EXTENSION_REVISION);

  f.chrome.debugger.sendCommand = async () => ({ data: "x".repeat(1100000) });
  f.attach(3, f.cdp([read]));
  await waitBody(f.port, "attached", 3);
  f.send(3, { type: "dispatch" });
  await waitBody(f.port, "reply_end", 3);
  const text = f.port.sent.filter(frame => frame.message.id === 3 && frame.message.body.type === "reply_chunk").map(frame => frame.message.body.data).join("");
  assert.equal(JSON.parse(text).extension_revision, EXTENSION_REVISION);
});

test("the extension's contract revision matches the one cerebellum requires", async () => {
  const rust = readFileSync(new URL("../../crates/cerebellum/src/user_browser.rs", import.meta.url), "utf8");
  const required = rust.match(/^pub\(crate\) const EXTENSION_REVISION: u64 = (\d+);$/m);
  assert.ok(required, "cerebellum must declare EXTENSION_REVISION");
  assert.equal(Number(required[1]), EXTENSION_REVISION);
});
