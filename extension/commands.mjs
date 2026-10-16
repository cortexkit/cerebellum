import { Refusal } from "./errors.mjs";
import { RUNTIME_FUNCTION_SHA256 } from "./runtime-functions.mjs";

// Keep this a method allowlist, not a domain allowlist: Page.bringToFront,
// Runtime.runIfWaitingForDebugger and browser-wide target commands have very
// different authority from a read of a claimed tab's document.
const READ_METHODS = new Set([
  "Page.getNavigationHistory", "Page.getFrameTree", "Page.captureScreenshot", "Page.getLayoutMetrics",
  "Accessibility.enable", "Accessibility.getFullAXTree",
  "DOM.enable", "DOM.getFlattenedDocument", "DOM.getOuterHTML", "DOM.getContentQuads", "DOM.getNodeForLocation", "DOM.resolveNode",
  "Runtime.enable",
]);
// Terminal accounting uses the narrower fixed set in
// terminal-read-only-methods.json, embedded by the Rust bridge. Methods absent
// from that set count as mutations, even if admitted above without input guards.
// Runtime.callFunctionOn is read-only only for the pinned HAS_FOCUS declaration.
const INPUT_METHODS = new Set(["Input.dispatchMouseEvent", "Input.dispatchKeyEvent", "Input.insertText", "DOM.focus"]);

export function classifyCommand(command) {
  if (!command || typeof command.method !== "string" || !command.params || typeof command.params !== "object" || Array.isArray(command.params)) throw new Refusal("invalid_command", "update cerebellum and the extension together");
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
