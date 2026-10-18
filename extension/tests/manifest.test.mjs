import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { classifyCommand, resolveParams, runtimeDigest, verifyRuntime } from "../commands.mjs";
import { RUNTIME_FUNCTION_SHA256 } from "../runtime-functions.mjs";
import { bounded } from "../errors.mjs";

const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));

test("MV3 module manifest pins the native host's independently derived extension id", () => {
  const hex = createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex").slice(0, 32);
  const id = [...hex].map(nibble => String.fromCharCode("a".charCodeAt(0) + parseInt(nibble, 16))).join("");
  assert.equal(id, "bfmlflnlaflnibiellpjjifdbcifciei");
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.type, "module");
  for (const permission of ["debugger", "tabGroups", "nativeMessaging"]) assert.ok(manifest.permissions.includes(permission));
  assert.equal(manifest.content_scripts, undefined);
});

test("runtime function pins fail closed and use independently computed SHA-256", async () => {
  const declaration = "function() { return true; }";
  const digest = createHash("sha256").update(declaration).digest("hex");
  assert.equal(await runtimeDigest(declaration), digest);
  const command = { method: "Runtime.callFunctionOn", params: { objectId: "object", functionDeclaration: declaration, returnByValue: true } };
  await assert.rejects(verifyRuntime(command), { reason: "unsupported_cdp_method" });
  await verifyRuntime(command, [digest]);
  await assert.rejects(verifyRuntime({ ...command, params: { ...command.params, functionDeclaration: declaration + " " } }, [digest]), { reason: "unsupported_cdp_method" });
  for (const params of [
    { expression: "window.focus()", returnByValue: true },
    { expression: "window.devicePixelRatio", returnByValue: true },
  ]) assert.throws(() => classifyCommand({ method: "Runtime.evaluate", params }), { reason: "unsupported_cdp_method" });
  assert.throws(() => classifyCommand({ ...command, params: { ...command.params, arguments: [] } }), { reason: "unsupported_cdp_method" });
});

test("result references cannot traverse prototypes or refer to absent results", () => {
  for (const value of [{ $result: 0, path: [] }, { $result: -1, path: [] }, { $result: 0, path: ["__proto__"] }, { $result: 0, path: ["constructor"] }]) {
    assert.throws(() => resolveParams(value, value.$result === 0 && value.path.length ? [{ result: {} }] : []), { reason: "invalid_result_reference" });
  }
});

test("named phase deadlines reject a stuck operation", async () => {
  await assert.rejects(bounded(new Promise(() => {}), "attach", 1), { reason: "attach_deadline" });
});


test("documented Runtime pins match the executable list", async () => {
  const protocol = await readFile(new URL("../PROTOCOL.md", import.meta.url), "utf8");
  const block = protocol.match(/<!-- runtime-function-sha256 -->\s*```json\s*([\s\S]*?)\s*```\s*<!-- \/runtime-function-sha256 -->/);
  assert.ok(block, "named Runtime pin list must be documented");
  assert.deepEqual(JSON.parse(block[1]), [...RUNTIME_FUNCTION_SHA256]);
  assert.ok(RUNTIME_FUNCTION_SHA256.every(pin => /^[a-f0-9]{64}$/.test(pin)));
});

test("the exact admitted CDP subset excludes broader driver commands", () => {
  for (const method of ["Page.getNavigationHistory", "Page.getFrameTree", "Page.getLayoutMetrics", "Page.captureScreenshot", "Accessibility.enable", "Accessibility.getFullAXTree", "DOM.enable", "DOM.getFlattenedDocument", "DOM.getOuterHTML", "DOM.getContentQuads", "DOM.getNodeForLocation", "DOM.resolveNode", "Runtime.enable", "Input.dispatchMouseEvent", "Input.dispatchKeyEvent", "Input.insertText", "DOM.focus"]) {
    assert.ok(["read", "input"].includes(classifyCommand({ method, params: {} })));
  }
  assert.equal(classifyCommand({ method: "Page.navigate", params: { url: "http://localhost/" } }), "navigate");
  assert.equal(classifyCommand({ method: "Emulation.setFocusEmulationEnabled", params: { enabled: true } }), "input");
  assert.equal(classifyCommand({ method: "DOM.scrollIntoViewIfNeeded", params: { backendNodeId: 9 } }), "input");
  for (const method of ["Runtime.resolveNode", "Runtime.evaluate", "Page.enable", "Page.createIsolatedWorld", "DOM.getDocument", "Accessibility.getRootAXNode", "Input.dispatchTouchEvent", "Target.setAutoAttach", "Network.enable"]) {
    assert.throws(() => classifyCommand({ method, params: {} }), { reason: "unsupported_cdp_method" });
  }
});


test("browser-adapter declarations match all three pins and a one-byte change refuses", async () => {
  const { DECLARATIONS } = await import("./functions-fixture.mjs");
  const protocol = await readFile(new URL("../PROTOCOL.md", import.meta.url), "utf8");
  const names = ["SELECT", "APPEND_CARET", "HAS_FOCUS"];
  assert.equal(RUNTIME_FUNCTION_SHA256.length, names.length);
  for (const [index, name] of names.entries()) {
    const declaration = DECLARATIONS[name];
    const documented = protocol.match(new RegExp(`const ${name} = ("[^"\\n]*");`));
    assert.ok(documented, `missing documented ${name} declaration`);
    assert.equal(JSON.parse(documented[1]), declaration);
    assert.equal(createHash("sha256").update(declaration, "utf8").digest("hex"), RUNTIME_FUNCTION_SHA256[index]);
    const command = { method: "Runtime.callFunctionOn", params: { objectId: "object", functionDeclaration: declaration, returnByValue: true } };
    await verifyRuntime(command);
    for (const params of [
      { ...command.params, objectId: null },
      { ...command.params, objectId: "" },
      { ...command.params, returnByValue: false },
      { ...command.params, arguments: [] },
    ]) await assert.rejects(verifyRuntime({ ...command, params }), { reason: "unsupported_cdp_method" });
    await assert.rejects(verifyRuntime({ ...command, params: { ...command.params, functionDeclaration: declaration + " " } }), { reason: "unsupported_cdp_method" });
  }
});

test("terminal read accounting covers frame queries without admitting target mutations", async () => {
  const readOnly = JSON.parse(await readFile(new URL("../terminal-read-only-methods.json", import.meta.url), "utf8"));
  for (const method of ["Accessibility.enable", "DOM.enable", "Runtime.enable", "DOM.getFrameOwner", "DOM.getOuterHTML", "DOM.getContentQuads", "DOM.getNodeForLocation"]) {
    assert.ok(readOnly.includes(method), `${method} must not mark a child read dispatched`);
    assert.equal(classifyCommand({ method, params: {} }), "read");
  }
  for (const method of ["Input.dispatchMouseEvent", "Input.insertText", "DOM.focus", "DOM.scrollIntoViewIfNeeded", "Runtime.callFunctionOn", "Target.setAutoAttach", "Page.createIsolatedWorld", "DOM.newReadMethod"]) {
    assert.ok(!readOnly.includes(method), `${method} must not become unconditionally read-only`);
  }
});
