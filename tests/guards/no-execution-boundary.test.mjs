import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { collectSourceFiles, findBoundaryViolations } from "../../scripts/check-no-execution-boundary.mjs";

test("no-execution guard accepts the current application source", async () => {
  const files = await collectSourceFiles(fileURLToPath(new URL("../../src", import.meta.url)));

  assert.ok(files.length > 0);
  assert.deepEqual(findBoundaryViolations(files), []);
});

test("no-execution guard rejects process APIs and repository execution commands", () => {
  const violations = findBoundaryViolations([
    { path: "dangerous.cs", content: "Process.Start(\"git\", \"clone https://example.invalid/repository\"); git clone https://example.invalid/repository" },
    { path: "dangerous.mjs", content: "import { exec } from 'node:child_process'; exec('npm install');" }
  ]);

  assert.deepEqual(
    violations.map((violation) => violation.patternId),
    ["PROCESS_API", "REPOSITORY_EXECUTION_COMMAND", "JAVASCRIPT_PROCESS_API", "REPOSITORY_EXECUTION_COMMAND"]);
});
