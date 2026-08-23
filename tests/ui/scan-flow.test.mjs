import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import {
  createInitialScanState,
  errorMessage,
  severityEntries,
  transitionScanState,
  validateRepositoryUrl
} from "../../src/McpSecurityScanner.Api/wwwroot/ui-state.mjs";

test("scan flow validates, loads, and exposes a redacted report model", () => {
  let state = createInitialScanState();
  assert.equal(validateRepositoryUrl("https://127.0.0.1/openai/example-mcp"), "Enter a public GitHub repository URL in the form https://github.com/owner/repository.");
  assert.equal(validateRepositoryUrl("https://github.com/openai/example-mcp"), null);

  state = transitionScanState(state, { type: "scan_started" });
  assert.equal(state.status, "loading");

  const response = {
    repository: { owner: "openai", name: "example-mcp" },
    mcp: { classification: "mcp_related", evidence: [{ signalId: "MCP-CONFIG-001" }] },
    report: {
      summary: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
      findings: [{ ruleId: "MCP-SEC-001", evidence: "apiKey: [REDACTED]" }]
    }
  };
  state = transitionScanState(state, { type: "scan_succeeded", response });

  assert.equal(state.status, "success");
  assert.deepEqual(severityEntries(state.response.report.summary), [["critical", 0], ["high", 1], ["medium", 0], ["low", 0], ["informational", 0]]);
  assert.equal(state.response.report.findings[0].evidence, "apiKey: [REDACTED]");
});

test("scan flow renders a clear rate-limit error state", () => {
  const message = errorMessage({ code: "GITHUB_RATE_LIMITED", retryAfterSeconds: 30 });
  const state = transitionScanState(createInitialScanState(), { type: "scan_failed", message });

  assert.equal(state.status, "error");
  assert.match(state.error, /30 seconds/);
});

test("UI has no security-score or certification component", async () => {
  const html = await readFile(new URL("../../src/McpSecurityScanner.Api/wwwroot/index.html", import.meta.url), "utf8");

  assert.doesNotMatch(html, /security certified/i);
  assert.doesNotMatch(html, /id="(?:security-score|certification)"/i);
  assert.match(html, /static evidence, not a security score, certification/i);
});
