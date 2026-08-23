# MCP Security Scanner

An explainable, deterministic, specification-backed security scanner for public GitHub repositories containing Model Context Protocol (MCP) servers or configuration.

The scanner reads and analyzes repository content; it **never executes analyzed repository code**.

## Project status

MCP-1 security contract and MCP-2 canonical GitHub URL validation are implemented. Repository ingestion has not started yet.

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

It returns the parsed owner/repository for a canonical URL or a safe `400 INVALID_REPOSITORY_URL` response for unsupported input. The endpoint does not make a GitHub request; repository access belongs to the next ingestion ticket.
