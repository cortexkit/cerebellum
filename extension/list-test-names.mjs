import { run } from "node:test";

// The mutation runner needs real Node test names, not text found in comments or
// strings. Use Node's test runner to discover names by running selected tests.
// Listing runs the selected isolated tests; either pass or fail discovers a
// name. The mutation runner separately executes and grades each named test.
const [file, pattern] = process.argv.slice(2);
if (!file || !pattern) throw new Error("usage: node extension/list-test-names.mjs FILE PATTERN");
const matches = new RegExp(pattern);
const names = new Set();
const tests = run({ files: [file], testNamePatterns: [matches] });
const record = data => {
  if (!data.skip && matches.test(data.name)) names.add(data.name);
};
tests.on("test:pass", record);
tests.on("test:fail", record);
tests.on("error", error => { console.error(error); process.exitCode = 1; });
tests.on("end", () => console.log(JSON.stringify([...names])));
tests.resume();
