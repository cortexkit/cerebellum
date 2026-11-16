import { Refusal } from "./errors.mjs";
import { RUNTIME_FUNCTION_SHA256 } from "./runtime-functions.mjs";

// Keep this a method allowlist, not a domain allowlist: Page.bringToFront,
// Runtime.runIfWaitingForDebugger and browser-wide target commands have very
// different authority from a read of a claimed tab's document.
const READ_METHODS = new Set([
  "Page.getNavigationHistory", "Page.getFrameTree", "Page.captureScreenshot", "Page.getLayoutMetrics",
  "Accessibility.enable", "Accessibility.getFullAXTree",
  "DOM.enable", "DOM.getFlattenedDocument", "DOM.getOuterHTML", "DOM.getContentQuads", "DOM.getNodeForLocation", "DOM.resolveNode", "DOM.getFrameOwner",
  "Runtime.enable",
]);
// Rust uses terminal-read-only-methods.json to decide whether a request may
// have changed the page, including when it times out or loses its reply.
// Debugger enables configure only this action's debugger; frame-owner, HTML,
// quad and hit-test queries only observe the page, so they are listed there.
// Unlisted methods count as mutations. Runtime.callFunctionOn is exempt only
// for the exact native focus-check function documented as HAS_FOCUS in PROTOCOL.md.
// CHOOSE_OPTION remains input: like a mouse click, changing selected and firing
// events requires the interaction epoch recorded by the last page read.
const INPUT_METHODS = new Set(["Input.dispatchMouseEvent", "Input.dispatchKeyEvent", "Input.insertText", "DOM.focus", "DOM.scrollIntoViewIfNeeded"]);

export function classifyCommand(command) {
  if (!command || typeof command.method !== "string" || !command.params || typeof command.params !== "object" || Array.isArray(command.params)) throw new Refusal("invalid_command", "update cerebellum and the extension together");
  if (command.method === "Extension.wait") {
    if (Object.keys(command.params).length !== 1 || !Number.isSafeInteger(command.params.ms) || command.params.ms < 0 || command.params.ms > 2000) throw new Refusal("invalid_command", "provide integer ms from 0 to 2000");
    return "wait";
  }
  const objectId = command.params.objectId;
  const validObjectId = typeof objectId === "string" && objectId.length > 0 || objectId && typeof objectId === "object" && Number.isInteger(objectId.$result) && objectId.$result >= 0 && Array.isArray(objectId.path) && Object.keys(objectId).every(key => ["$result", "path"].includes(key));
  if (command.method === "Runtime.callFunctionOn" && validObjectId && typeof command.params.functionDeclaration === "string" && command.params.returnByValue === true && Object.keys(command.params).every(key => ["objectId", "functionDeclaration", "returnByValue"].includes(key))) return "input";
  if (command.method === "Emulation.setFocusEmulationEnabled" && command.params.enabled === true && Object.keys(command.params).length === 1) return "input";
  if (INPUT_METHODS.has(command.method)) return "input";
  if (READ_METHODS.has(command.method)) return "read";
  if (command.method === "Page.navigate") {
    let url;
    try { url = new URL(command.params.url); } catch { throw new Refusal("invalid_navigation", "navigate to an HTTP(S) site"); }
    if (!["http:", "https:"].includes(url.protocol)) throw new Refusal("invalid_navigation", "navigate to an HTTP(S) site");
    return "navigate";
  }
  // Evaluation is intentionally not an arbitrary command escape hatch. The
  // browser adapter must provide a separately reviewed projection vocabulary.
  throw new Refusal("unsupported_cdp_method", "update the user-browser command adapter", { method: command.method });
}

export async function runtimeDigest(declaration) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(declaration));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

export async function verifyRuntime(command, pins = RUNTIME_FUNCTION_SHA256) {
  if (command.method !== "Runtime.callFunctionOn") return;
  classifyCommand(command);
  const digest = await runtimeDigest(command.params.functionDeclaration);
  if (!pins.includes(digest)) throw new Refusal("unsupported_cdp_method", "install the reviewed browser-adapter function pins", { method: command.method });
}

export function resolveParams(value, results, depth = 0) {
  if (depth > 64) throw new Refusal("invalid_result_reference");
  if (value && typeof value === "object" && !Array.isArray(value) && "$result" in value) {
    if (Object.keys(value).some(key => !["$result", "path"].includes(key)) || !Number.isInteger(value.$result) || value.$result < 0 || value.$result >= results.length || !Array.isArray(value.path) || value.path.length > 64) throw new Refusal("invalid_result_reference");
    let resolved = results[value.$result].result;
    for (const key of value.path) {
      if ((typeof key !== "string" && !Number.isInteger(key)) || ["__proto__", "constructor", "prototype"].includes(key) || resolved === null || typeof resolved !== "object" || !Object.hasOwn(resolved, key)) throw new Refusal("invalid_result_reference");
      resolved = resolved[key];
    }
    return structuredClone(resolved);
  }
  if (Array.isArray(value)) return value.map(item => resolveParams(item, results, depth + 1));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, resolveParams(item, results, depth + 1)]));
  return value;
}
