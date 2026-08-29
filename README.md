# MCP Security Scanner

An explainable, deterministic static scanner for public GitHub repositories that contain Model Context Protocol (MCP) configuration or servers.

> This is not a security certification, a comprehensive pentest, a runtime sandbox, or proof that a repository is safe. It reports bounded static evidence from the currently implemented rules.

## What it does

1. Accepts exactly one canonical public URL: `https://github.com/{owner}/{repository}`.
2. Reads bounded public GitHub metadata, tree entries, and eligible text files using GitHub's REST API.
3. Classifies the repository as `mcp_related`, `not_mcp`, or `inconclusive` and returns explicit detection evidence.
4. Runs deterministic security rules and returns severity counts plus redacted, location-specific findings.

The browser UI is available at `/`; the API endpoint is `POST /api/scans`.

## Non-negotiable safety boundary

MSS **never executes analyzed repository code**. It does not clone, check out, build, install dependencies for, start, shell into, run Docker for, or dynamically test the submitted repository. The scanner uses a fixed `https://api.github.com/` client with redirects disabled and never derives arbitrary request destinations from submitted input.

## Architecture

```text
Browser UI / API client
          |
          v
POST /api/scans
          |
          v
Canonical URL validation
          |
          v
Fixed-host GitHub metadata/tree/content reader
          |
          +--> MCP detector --> classification + evidence
          |
          +--> deterministic rule engine --> redacted findings + summary
          |
          v
In-memory JSON response (no account, database, or scan history)
```

The Core scan orchestration calls only the bounded ingestion service, MCP detector, and static rule engine. API output is derived from typed safe contracts; error messages exclude GitHub response bodies and rule evidence passes through secret redaction before serialization.

## Threat model and limits

The principal scanner risks are SSRF, arbitrary code execution, resource exhaustion, parser abuse, and accidental secret disclosure. The MVP mitigates them with a canonical URL gate, fixed GitHub API base address, redirect denial, read-only Base64 content fetches, strict UTF-8/binary handling, resource caps, controlled errors, and evidence redaction.

| Bound | MVP value |
|---|---:|
| Tree entries | 1,000 |
| Candidate files | 200 |
| Single file | 512 KiB |
| Total decoded input | 5 MiB |
| Analysis deadline | 20 seconds |

Binary files and symbolic links are skipped. Private, deleted, unavailable, rate-limited, oversized, or timed-out repositories return safe error responses rather than partial execution or raw upstream content.

## MCP detection

Positive MCP classification requires deterministic evidence from at least one implemented source:

- JSON `mcpServers` configuration structure (`MCP-CONFIG-001`)
- MCP SDK dependency in a supported manifest (`MCP-SDK-001`)
- Supported source-level MCP server declaration (`MCP-SERVER-001`)

`not_mcp` only means no implemented signal was found in processable text. It is never a “clean” or certified security result.

## Rule catalogue

| Rule ID | Severity | Static evidence |
|---|---:|---|
| `MCP-CMD-001` | High | `sudo` privileged execution token |
| `MCP-CMD-002` | High | `rm` with recursive+force flags; `curl`/`wget` pipe-to-shell |
| `MCP-FS-001` | Medium | SSH/AWS credentials, system, process-environment, or Docker control paths |
| `MCP-NET-001` | Medium | Non-loopback remote `http://` endpoint |
| `MCP-SEC-001` | High | Literal hardcoded credential assignment |
| `MCP-AUTH-001` | Medium | Explicit broad or wildcard OAuth scope |
| `MCP-AUTH-002` | High | `javascript:`, `file:`, or `data:` authorization/redirect URL |

Credential-like evidence is masked as `[REDACTED]`. Loopback, `localhost`, `*.localhost`, and `0.0.0.0` development bind addresses are not reported by `MCP-NET-001`. Rule findings are static indicators, not exploitability claims.

## MCP reference baseline and rule limits

The implemented MCP-specific rules cite official **MCP 2026-07-28** [Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) and [Authorization Specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) guidance. This is a reference baseline for the rule catalogue, not a claim that MSS implements the MCP protocol, validates MCP conformance, or covers every vulnerability type in that specification.

Rules are deliberately bounded static pattern checks. They can produce false positives, and they can miss risky behavior (false negatives); a finding needs human review, while no finding is not proof that a repository is safe. See the [MCP specification reference policy](docs/architecture/mcp-specification-reference-policy.md).

## Example scan

```bash
curl --request POST http://127.0.0.1:8080/api/scans \
  --header 'Content-Type: application/json' \
  --data '{"repositoryUrl":"https://github.com/owner/repository"}'
```

Illustrative redacted response shape:

```json
{
  "repository": { "owner": "owner", "name": "repository" },
  "mcp": {
    "classification": "mcp_related",
    "evidence": [{ "signalId": "MCP-CONFIG-001", "filePath": "mcp.json", "line": 2 }]
  },
  "report": {
    "ruleSetVersion": "1.0.0",
    "summary": { "critical": 0, "high": 1, "medium": 1, "low": 0, "informational": 0 },
    "findings": [{
      "ruleId": "MCP-SEC-001",
      "filePath": "mcp.json",
      "line": 5,
      "evidence": "\"apiKey\": [REDACTED]",
      "remediation": "Remove the literal credential and load it from an approved secret manager."
    }]
  }
}
```

## Run locally

Prerequisites: .NET SDK 10 and Node.js 24 (Node is used only for UI-flow tests).

```bash
dotnet restore McpSecurityScanner.slnx
dotnet run --project src/McpSecurityScanner.Api/McpSecurityScanner.Api.csproj --urls http://127.0.0.1:8080
```

Open `http://127.0.0.1:8080` in a browser. The local server does not persist scan results.

## Test and quality gates

```bash
# .NET unit, integration, ingestion, detector, and rule-engine tests
dotnet test McpSecurityScanner.slnx --configuration Release --no-restore

# Browser-state UI flow tests (no third-party frontend packages)
npm run test:ui

# No-execution boundary guard and its self-tests (application source only)
node scripts/check-no-execution-boundary.mjs src
npm run test:boundary

# Cobertura coverage report and MCP-10 line-coverage gate
dotnet test McpSecurityScanner.slnx --configuration Release --no-restore --collect:'XPlat Code Coverage' --results-directory TestResults
npm run check:coverage

# Release build
dotnet build McpSecurityScanner.slnx --configuration Release --no-restore
```

The initial MVP quality gate is **at least 75% total line coverage**. The measured baseline when this gate was introduced was 78.23%. GitHub Actions runs restore, .NET tests with coverage, the coverage gate, UI tests, release build, and a Docker image build on pushes and pull requests.

The no-execution guard reads only MSS application source under `src/`. It rejects process-launch APIs, Git libraries, and explicit clone/install/build/run command patterns; it does not inspect, download, or execute a submitted repository. The CI/Docker image build packages MSS itself and is deliberately outside this guard's source scope.

## Run with Docker

```bash
docker build --tag mcp-security-scanner:local .
docker run --rm --publish 8080:8080 mcp-security-scanner:local
```

Then open `http://127.0.0.1:8080`. The runtime image exposes port 8080 and runs as the base image's non-root application user.

## Limitations and non-goals

- Public canonical GitHub repositories only; private repositories and arbitrary URLs are rejected.
- No runtime execution, exploit generation, dynamic testing, LLM analysis, full vulnerability coverage, SBOM, SARIF, or CI-action integration for scanned repositories.
- No authentication, organization support, billing, database, scan history, or report persistence.
- Rule coverage is intentionally narrow and deterministic. A missing finding is not proof of absence of risk.

## Further reading

- [MCP-1 security and architecture contract](docs/architecture/mcp-1-foundation-security-contract.md)
- [MCP-5 rule-engine contract](docs/architecture/mcp-5-rule-engine-contract.md)
- [MCP-8 scan API contract](docs/architecture/mcp-8-scan-api-contract.md)
- [MCP-9 web UI contract](docs/architecture/mcp-9-minimal-web-ui-contract.md)
- [MCP specification reference policy](docs/architecture/mcp-specification-reference-policy.md)
- [No-execution CI guard contract](docs/architecture/mss-12-no-execution-ci-guard.md)
