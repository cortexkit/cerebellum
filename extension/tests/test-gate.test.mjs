import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const gate = fileURLToPath(new URL("../test-gate.mjs", import.meta.url));
async function runFixture(t, source) {
  const directory = await mkdtemp(join(tmpdir(), "ck-extension-gate-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  if (source) await writeFile(join(directory, "fixture.test.mjs"), source, { mode: 0o600 });
  // Start an independent CLI runner, not another worker inside this test run.
  // Node's inherited worker marker otherwise suppresses the child's discovery.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return spawnSync(process.execPath, [gate, directory], { encoding: "utf8", timeout: 10000, env });
}

const header = 'import assert from "node:assert/strict"; import { test } from "node:test";\n';

test("extension gate passes only after a nonempty passing test run", async t => {
  const result = await runFixture(t, header + 'test("fixture passes", () => assert.equal(2 + 2, 4));\n');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /EXTENSION TEST GATE PASSED: 1 tests ran/);
});

test("extension gate propagates a named test failure", async t => {
  const result = await runFixture(t, header + 'test("fixture fails", () => assert.equal(1, 2));\n');
  assert.equal(result.status, 1);
  assert.match(result.stdout, /not ok 1 - fixture fails/);
  assert.match(result.stderr, /EXTENSION TEST GATE FAILED: test runner exited 1/);
  assert.doesNotMatch(result.stdout, /EXTENSION TEST GATE PASSED/);
});

test("extension gate refuses a successful runner with zero tests", async t => {
  const result = await runFixture(t);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /# tests 0/);
  assert.match(result.stderr, /EXTENSION TEST GATE FAILED: no tests ran \(count=0\)/);
  assert.doesNotMatch(result.stdout, /EXTENSION TEST GATE PASSED/);
});
