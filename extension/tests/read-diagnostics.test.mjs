import assert from "node:assert/strict";
import { test } from "node:test";
import { diagnosticReason, probeReadDiagnostic } from "../read-diagnostics.mjs";
import { setup } from "./harness.mjs";

const prefix = "Agent probe read: ";
function capture(t, enabled) {
  const previous = globalThis.__ckProbeReadDiagnostics;
  if (enabled) globalThis.__ckProbeReadDiagnostics = true;
  else delete globalThis.__ckProbeReadDiagnostics;
  t.after(() => {
    if (previous === undefined) delete globalThis.__ckProbeReadDiagnostics;
    else globalThis.__ckProbeReadDiagnostics = previous;
  });
  const lines = [];
  t.mock.method(console, "info", line => lines.push(line));
  return { lines, rows: () => lines.filter(line => line.startsWith(prefix)).map(line => JSON.parse(line.slice(prefix.length))) };
}

test("read diagnostics are disabled without the probe opt-in", t => {
  const { lines } = capture(t, false);
  probeReadDiagnostic("sample_failed", { tabId: 2, stage: "pre_read", reason: "interaction_continuity_lost" });
  globalThis.__ckProbeReadDiagnostics = "true";
  probeReadDiagnostic("sample_failed", { tabId: 2, stage: "post_plan", reason: "no_receiver" });
  assert.deepEqual(lines, []);
});

test("probe read diagnostics allow only fixed metadata and normalize exceptions", t => {
  const { lines, rows } = capture(t, true);
  const error = new Error('Cannot access contents of url "https://private.invalid/SECRET"');
  probeReadDiagnostic("sample_failed", {
    tabId: 2, stage: "pre_read", step: "frame_message", frameId: 7,
    reason: diagnosticReason(error), enabled: false, sequence: "SECRET",
    url: "https://private.invalid/SECRET", title: "SECRET", documentId: "SECRET", error,
  });
  probeReadDiagnostic("SECRET", { tabId: 2 });
  assert.deepEqual(rows(), [{ event: "sample_failed", tabId: 2, stage: "pre_read", step: "frame_message", frameId: 7, reason: "access_denied", enabled: false }]);
  assert.ok(lines.every(line => !line.includes("SECRET") && !line.includes("private.invalid")));
  assert.equal(diagnosticReason(new Error("arbitrary SECRET")), "other_error");
});

test("probe diagnostics explain unavailable observation without blaming person", async t => {
  const { rows } = capture(t, true);
  const f = await setup();
  f.chrome.tabs.sendMessage = async () => { throw new Error("Could not establish connection. Receiving end does not exist."); };
  const read = await f.fresh();
  assert.equal(read.results.length, 1);
  assert.equal(f.agent.baselines.has(2), false);
  await assert.rejects(f.run(f.input(0)), { reason: "observer_unavailable" });
  assert.ok(rows().some(row => row.event === "sample_failed" && row.stage === "pre_read" && row.step === "frame_message" && row.reason === "no_receiver" && row.frameId === 0));
  assert.ok(rows().some(row => row.event === "sample_failed" && row.stage === "post_plan" && row.reason === "observer_unavailable"));
  assert.ok(rows().some(row => row.event === "baseline_deleted" && row.covered === false && row.readObserved === false));
  assert.ok(rows().some(row => row.event === "input_baseline_refused" && row.reason === "baseline_missing" && row.baselinePresent === false && row.planEpoch === 0));
  assert.equal(f.chrome.calls.some(call => call[0] === "cdp" && call[2].startsWith("Input.")), false);
});

test("probe diagnostics distinguish epoch mismatch and post-only baseline loss", async t => {
  const { lines, rows } = capture(t, true);
  const f = await setup();
  const read = await f.fresh();
  assert.ok(rows().some(row => row.event === "baseline_set" && row.tabId === 2 && row.epoch === read.interaction_epoch));
  await assert.rejects(f.run(f.input(read.interaction_epoch + 1)), { reason: "fresh_read_required" });
  assert.ok(rows().some(row => row.event === "input_baseline_refused" && row.reason === "epoch_mismatch" && row.baselineEpoch === read.interaction_epoch && row.planEpoch === read.interaction_epoch + 1));
  lines.length = 0;
  const send = f.chrome.tabs.sendMessage;
  let samples = 0;
  f.chrome.tabs.sendMessage = async (...args) => {
    if (++samples === 2) throw new Error("The message port closed before a response was received.");
    return send(...args);
  };
  await f.fresh();
  assert.equal(f.agent.baselines.has(2), false);
  assert.ok(rows().some(row => row.event === "sample_failed" && row.stage === "post_plan" && row.step === "frame_message" && row.reason === "port_closed"));
  assert.ok(rows().some(row => row.event === "baseline_deleted" && row.covered === false && row.readObserved === true));
});


test("probe observer-install diagnostics redact Chrome exception text and preserve continuity", async t => {
  const { lines, rows } = capture(t, true);
  const f = await setup();
  const previous = f.epochs.record(2).continuity;
  f.chrome.scripting.executeScript = async () => { throw new Error('Cannot access contents of url "https://private.invalid/SECRET"'); };
  await f.epochs.install(2, 0, "blocked-document");
  assert.equal(f.epochs.record(2).continuity, previous + 1);
  assert.ok(rows().some(row => row.event === "observer_install_failed" && row.tabId === 2 && row.reason === "access_denied"));
  assert.ok(lines.every(line => !line.includes("SECRET") && !line.includes("private.invalid")));
});
