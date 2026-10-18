// Only the signed, feature-enabled CfT probe enables this flag in its own
// extension worker. Normal browser_use plans cannot turn diagnostics on.
const events = new Set(["plan_baseline", "sample_failed", "baseline_set", "baseline_deleted", "baseline_cleared", "observer_install_failed", "input_baseline_refused"]);
const values = {
  stage: new Set(["pre_read", "post_plan", "input_check", "sample"]),
  step: new Set(["membership", "frame_list", "frame_message", "observation", "observer_install"]),
  reason: new Set(["baseline_missing", "plan_epoch_missing", "epoch_mismatch", "interaction_continuity_lost", "interaction_epoch_changed", "tab_not_in_agent_group", "tab_not_claimed", "dispatch_deadline", "cancelled", "no_receiver", "port_closed", "access_denied", "no_frames", "other_error", "connected", "disconnected", "withdrawn", "released"]),
};
const numbers = new Set(["tabId", "frameId", "baselineEpoch", "planEpoch", "epoch", "continuity", "sequence", "previousSequence", "historyLength", "frameCount", "commandCount", "baselineCount"]);
const booleans = new Set(["baselinePresent", "hasInput", "hasRead", "covered", "readObserved", "enabled", "sameDocument"]);

export function diagnosticReason(error) {
  if (values.reason.has(error?.reason)) return error.reason;
  // Classify known Chrome failures without printing arbitrary exception text,
  // which can contain the tab's URL or other page-controlled strings.
  const message = error?.message;
  if (message === "Could not establish connection. Receiving end does not exist.") return "no_receiver";
  if (message === "The message port closed before a response was received.") return "port_closed";
  if (typeof message === "string" && message.startsWith("Cannot access contents of url")) return "access_denied";
  return "other_error";
}

export function probeReadDiagnostic(event, fields = {}) {
  if (globalThis.__ckProbeReadDiagnostics !== true || !events.has(event)) return;
  const row = { event };
  for (const [key, value] of Object.entries(fields)) {
    if (values[key] instanceof Set && values[key].has(value) || numbers.has(key) && Number.isSafeInteger(value) || booleans.has(key) && typeof value === "boolean") row[key] = value;
  }
  console.info(`Agent probe read: ${JSON.stringify(row)}`);
}
