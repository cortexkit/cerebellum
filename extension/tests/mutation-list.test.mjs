import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const names = pattern => {
  const env = { ...process.env };
  // Run the listing as a standalone tool, not as a nested Node test worker.
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["extension/list-test-names.mjs", "extension/tests/attach.test.mjs", pattern], { cwd: root, encoding: "utf8", env });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
};

test("mutation name discovery finds the executable own-session regression", () => {
  assert.deepEqual(names("^another holder is never retried when the own-session detach probe rejects$"), ["another holder is never retried when the own-session detach probe rejects"]);
});

test("mutation name discovery returns no invented test names", () => {
  assert.deepEqual(names("^this attach test does not exist$"), []);
});
