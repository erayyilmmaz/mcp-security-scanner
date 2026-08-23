# MCP-4: Deterministic MCP Detection Signals

**Status:** Accepted for MVP implementation
**Scope:** MCP-4.1 through MCP-4.4

The MCP detector consumes the bounded, read-only `RepositoryContentSet` from MCP-3. It performs no network access and never executes repository content.

## Classification contract

| Classification | Meaning |
|---|---|
| `mcp_related` | At least one high-confidence deterministic signal was found. |
| `not_mcp` | At least one text file was examined and no implemented signal was found. This is not a security verdict or a “clean” result. |
| `inconclusive` | No processable text file was available after safe ingestion, so classification cannot be made. |

## Signal catalogue and precedence

Signals are sorted by numeric priority, then repository-relative file path, line, and evidence token. The same content set therefore produces the same classification and evidence order.

| Priority | Signal ID | Trigger | Evidence returned | Confidence |
|---:|---|---|---|---|
| 10 | `MCP-CONFIG-001` | A JSON file contains the `mcpServers` property. | The fixed token `"mcpServers":` and location. | High |
| 20 | `MCP-SDK-001` | A known manifest contains `@modelcontextprotocol/sdk`, `modelcontextprotocol`, or `ModelContextProtocol`. | The matching package token and location. | High |
| 30 | `MCP-SERVER-001` | Source contains a specific Node, Python, FastMCP, or .NET MCP import/declaration/tool attribute. | The matching declaration token and location. | High |

Recognized manifest filenames: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pyproject.toml`, `requirements.txt`, `poetry.lock`, `Pipfile`, `Pipfile.lock`, and `*.csproj`.

## Evidence safety

The detector reports only the matching token, not the surrounding line or config value. This avoids putting commands, tokens, or other configuration values into detection evidence. Rule findings will apply their own evidence-redaction policy in MCP-5.

## Explicit non-signals

- A filename by itself, including `mcp.json`, is not enough to classify a repository as MCP-related.
- README prose mentioning “MCP” is not a signal.
- No LLM inference, dynamic connection, server startup, package installation, or command execution is used.
