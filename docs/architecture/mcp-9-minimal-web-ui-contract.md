# MCP-9: Minimal Scan and Report Web UI

**Status:** Accepted for MVP implementation
**Scope:** MCP-9.1 through MCP-9.5

The root route serves a dependency-free static interface backed only by `POST /api/scans`. It stores no scan history, account, credential, or report data after the browser session renders a response.

## User flow

1. The user enters a canonical public GitHub URL.
2. The browser validates the expected form and submits one scan request.
3. While the request is active, the form exposes a clear loading state and prevents duplicate submission.
4. Safe API errors are translated into clear invalid-URL, rate-limit, unavailable, timeout, resource-limit, or generic scan-failure messages.
5. A successful response displays repository identity, MCP classification/evidence, severity counts, and every finding's rule ID, location, evidence, why-it-matters, remediation, confidence, and reference.

## UI safety boundary

The interface uses DOM `textContent` and element creation for all response-derived strings, including repository file paths and evidence. It does not insert repository content as HTML. The browser receives only API-redacted finding evidence; the UI does not attempt to unmask, score, certify, or infer runtime behavior.

## Test boundary

`npm run test:ui` uses Node's built-in test runner without third-party frontend dependencies. It tests the form validation → loading → success/error state flow, redacted evidence model, rate-limit message, and absence of security-score/certification claims. The .NET test host separately verifies that `/` serves the static UI and MCP-8 verifies the mock GitHub API contract.
