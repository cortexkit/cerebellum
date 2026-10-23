import { DEADLINES, Refusal } from "./errors.mjs";

const chromeMessage = error => String(error?.message ?? error ?? "unknown error").replace(/[\u0000-\u001f\u007f]/g, " ");

export function attachFailureKind(error) {
  const message = chromeMessage(error);
  if (/^another debugger is already attached to the tab with id:\s*\d+\.?$/i.test(message)) return "another_debugger";
  if (/^no tab with (?:given )?id[:\s]+\d+\.?$/i.test(message)) return "tab_gone";
  if (/^(?:cannot access a chrome:\/\/ URL|cannot access a chrome-extension:\/\/ URL of different extension|the extensions gallery cannot be scripted|cannot access a Chrome Web Store page)\.?$/i.test(message)) return "restricted_page";
  return "unknown";
}

export function attachRefusal(error, kind = attachFailureKind(error)) {
  const detail = { attach_failure: "rejection", attach_reason: kind };
  const remedies = {
    another_debugger: "Chrome rejected the debugger attach: DevTools or another extension is debugging this tab. Close it, then read again.",
    active_plan: "Chrome rejected the debugger attach while one of our plans is attached to this tab. Wait for that plan to finish, then read again.",
    tab_gone: "Chrome rejected the debugger attach because the tab no longer exists. Read status and claim the tab again.",
    restricted_page: "Chrome rejected the debugger attach because this page cannot be automated. Use a regular web page instead.",
  };
  if (error instanceof Refusal && error.reason === "attach_deadline") {
    return new Refusal("attach_deadline", `Chrome did not answer the debugger attach within ${DEADLINES.attach / 1000} seconds (the attach deadline). Read again.`, { attach_failure: "deadline", attach_reason: "timeout" });
  }
  if (remedies[kind]) return new Refusal("debugger_busy", remedies[kind], detail);
  // Attach errors describe Chrome's target or debugger state, not page content.
  // Bound only the quoted message so the cause and next action remain complete.
  const message = Array.from(chromeMessage(error)).slice(0, 200).join("");
  return new Refusal("debugger_busy", `Chrome rejected the debugger attach: ${JSON.stringify(message)}. Read again.`, { ...detail, chrome_message: message });
}
