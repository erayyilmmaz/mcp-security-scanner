# MCP Security Scanner

An explainable, deterministic, specification-backed security scanner for public GitHub repositories containing Model Context Protocol (MCP) servers or configuration.

The scanner reads and analyzes repository content; it **never executes analyzed repository code**.

## Project status

MCP-1 security contract, MCP-2 canonical GitHub URL validation, MCP-3 safe public-repository ingestion, MCP-4 deterministic MCP detection, and MCP-5 rule-engine/finding contracts are implemented. Concrete security rules have not started yet.

## Architecture and security contract

See [MCP-1 Foundation & Security Contract](docs/architecture/mcp-1-foundation-security-contract.md) for the threat model, processing limits, API/error contract, and rule/report model.

## MVP boundaries

- Public canonical GitHub repository URLs only.
- Deterministic static checks with evidence, remediation, confidence, and references.
- No repository code execution, database, accounts, private repositories, LLM analysis, or dynamic testing.

## Current API surface

`POST /api/repositories/validate` accepts only this request shape:

```json
{ "repositoryUrl": "https://github.com/owner/repository" }
```

It returns the parsed owner/repository for a canonical URL or a safe `400 INVALID_REPOSITORY_URL` response for unsupported input. The endpoint does not make a GitHub request, so a syntactically accepted URL is not evidence that its repository exists or is public; that check belongs to the next ingestion ticket.

## Safe ingestion boundary

The ingestion service uses a fixed `https://api.github.com/` REST base address with redirects disabled. It reads metadata, a recursive tree, and selected Base64 file content only; it never clones, checks out, builds, installs, or runs repository code.

The initial limits are 1,000 tree entries, 200 candidate files, 512 KiB per file, 5 MiB total source bytes, and a 20-second deadline. Binary files and symbolic links are skipped; limit and timeout failures return controlled error contracts without logging raw repository content.

## MCP detection

The detector classifies bounded repository content as `mcp_related`, `not_mcp`, or `inconclusive`. Positive classifications require deterministic evidence from an MCP configuration structure, SDK dependency, or server declaration; `not_mcp` is never presented as a security certification or “clean” result. See [MCP-4 detection signals](docs/architecture/mcp-4-detection-signals.md).

## Rule engine

The rule engine runs independently implemented deterministic rules against the bounded content set. It produces versioned, severity-sorted findings with file/location evidence, explanation, remediation, confidence, and reference metadata. Evidence is redacted before it can enter a report. See [MCP-5 rule engine contract](docs/architecture/mcp-5-rule-engine-contract.md).
