# MCP Security Scanner

An explainable, deterministic, specification-backed security scanner for public GitHub repositories containing Model Context Protocol (MCP) servers or configuration.

The scanner reads and analyzes repository content; it **never executes analyzed repository code**.

## Project status

MVP foundation contract is defined. Implementation begins with safe public GitHub URL validation and read-only repository ingestion.

## Architecture and security contract

See [MCP-1 Foundation & Security Contract](docs/architecture/mcp-1-foundation-security-contract.md) for the threat model, processing limits, API/error contract, and rule/report model.

## MVP boundaries

- Public canonical GitHub repository URLs only.
- Deterministic static checks with evidence, remediation, confidence, and references.
- No repository code execution, database, accounts, private repositories, LLM analysis, or dynamic testing.
