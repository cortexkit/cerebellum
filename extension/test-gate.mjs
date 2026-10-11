import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const directory = process.argv[2] ?? fileURLToPath(new URL("./tests/", import.meta.url));
console.log(`Extension test gate: Node ${process.version}`);

// TAP has a stable final test-count line across Node's human reporter changes.
// Stream the output unchanged while checking that success actually ran tests.
const runner = spawn(process.execPath, ["--test", "--test-reporter=tap"], {
  cwd: directory,
  stdio: ["ignore", "pipe", "inherit"],
});
let pending = "";
let count = null;
const readLine = line => {
  const match = /^# tests (\d+)\r?$/.exec(line);
  if (match) count = Number(match[1]);
};
runner.stdout.setEncoding("utf8");
runner.stdout.on("data", data => {
  process.stdout.write(data);
  pending += data;
  const lines = pending.split("\n");
  pending = lines.pop();
  for (const line of lines) readLine(line);
});
runner.on("error", error => {
  console.error(`EXTENSION TEST GATE FAILED: cannot run Node (${error.code ?? "unknown"})`);
  process.exitCode = 1;
});
runner.on("close", (code, signal) => {
  readLine(pending);
  if (code !== 0 || signal) {
    console.error(`EXTENSION TEST GATE FAILED: test runner exited ${code ?? signal}`);
    process.exitCode = 1;
  } else if (!Number.isSafeInteger(count) || count <= 0) {
    console.error(`EXTENSION TEST GATE FAILED: no tests ran (count=${count ?? "missing"})`);
    process.exitCode = 1;
  } else {
    console.log(`EXTENSION TEST GATE PASSED: ${count} tests ran`);
  }
});
