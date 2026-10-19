// Only the signed, feature-enabled CfT probe enables this flag in its own
// extension worker. Normal browser_use plans cannot turn diagnostics on.
const events = new Set(["plan_baseline", "sample_failed", "baseline_set", "baseline_deleted", "baseline_cleared", "observer_install_failed", "observer_commit", "observer_access", "debugger_timing", "input_baseline_refused"]);
const values = {
  stage: new Set(["pre_read", "post_plan", "input_check", "sample"]),
  step: new Set(["membership", "frame_list", "frame_message", "observation", "observer_install"]),
  documentKind: new Set(["http", "blank", "other"]),
  phase: new Set(["attach_start", "attach_done", "detach_start", "detach_done"]),
  reason: new Set(["baseline_missing", "plan_epoch_missing", "epoch_mismatch", "interaction_continuity_lost", "interaction_epoch_changed", "observer_unavailable", "host_permission_missing", "frame_removed", "tab_not_in_agent_group", "tab_not_claimed", "dispatch_deadline", "cancelled", "no_receiver", "port_closed", "access_denied", "no_frames", "other_error", "connected", "disconnected", "withdrawn", "released"]),
};
const numbers = new Set(["tabId", "frameId", "baselineEpoch", "planEpoch", "planContinuity", "baselineContinuity", "epoch", "continuity", "sequence", "previousSequence", "historyLength", "frameCount", "commandCount", "baselineCount", "attempt"]);
const booleans = new Set(["baselinePresent", "hasInput", "hasRead", "covered", "readObserved", "enabled", "sameDocument", "invalidated", "allowed"]);
export function diagnosticErrorMessage(error) {
  const message = typeof error === "string" ? error : typeof error?.message === "string" ? error.message : "Unrecognized observer error";
  // This message comes only from Chrome's injection API or the fixed isolated
  // observer script, never page evaluation. Preserve its explanation for the
  // probe, but strip URLs, document ids and quoted values before logging it.
  return message.replace(/(?:[a-z][a-z0-9+.-]*:\/\/|about:)[^\s"'<>]+/gi, "<url>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<document>")
    .replace(/"[^"\n]*"|'[^'\n]*'/g, "<quoted>")
    .replace(/[\r\n\t\x00-\x1f]/g, " ").slice(0, 240);
}

export function diagnosticReason(error) {
  if (values.reason.has(error?.reason)) return error.reason;
  // Classify failures for control flow without copying exception text into a
  // public refusal; the probe's install diagnostics use a separate redactor.
  const message = typeof error === "string" ? error : error?.message;
  if (typeof message === "string" && message.startsWith("Cannot access contents of the page. Extension manifest must request permission")) return "host_permission_missing";
  if (message === "The frame was removed." || typeof message === "string" && /^Frame with ID \d+ was removed\.$/.test(message)) return "frame_removed";
  if (message === "Could not establish connection. Receiving end does not exist.") return "no_receiver";
  if (message === "The message port closed before a response was received.") return "port_closed";
  if (typeof message === "string" && message.startsWith("Cannot access contents of url")) return "access_denied";
  return "other_error";
}

export function probeReadDiagnostic(event, fields = {}) {
  if (globalThis.__ckProbeReadDiagnostics !== true || !events.has(event)) return;
  const row = { event, at: Date.now() };
  for (const [key, value] of Object.entries(fields)) {
    if (values[key] instanceof Set && values[key].has(value) || numbers.has(key) && Number.isSafeInteger(value) || booleans.has(key) && typeof value === "boolean" || key === "errorMessage" && event === "observer_install_failed" && typeof value === "string" && diagnosticErrorMessage({ message: value }) === value) row[key] = value;
  }
  console.info(`Agent probe read: ${JSON.stringify(row)}`);
}
