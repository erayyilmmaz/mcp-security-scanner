# MCP-7: Transport, Credential, and Authorization Rules

**Status:** Accepted for MVP implementation
**Scope:** MCP-7.1 through MCP-7.5

MCP-7 adds four independent static rules to the MCP-5 engine. They consume only the bounded repository text set and never make network requests, start processes, execute commands, or otherwise run analyzed repository code.

## Rule catalogue

| Rule ID | Severity | Detection | Precision boundary |
|---|---:|---|---|
| `MCP-NET-001` | Medium | Non-loopback `http://` endpoint | Excludes `localhost`, `*.localhost`, IPv4/IPv6 loopback, and `0.0.0.0` development bind addresses. |
| `MCP-SEC-001` | High | Literal API key, token, secret, password, or client secret assignment | Ignores runtime environment references and common explicit placeholders. |
| `MCP-AUTH-001` | Medium | Scope value contains `*`, `all`, `admin`, `full_access`, or `read:*`/`write:*` | Requires a `scope` or `scopes` field. |
| `MCP-AUTH-002` | High | Authorization/authentication/redirect URL field uses `javascript:`, `file:`, or `data:` | Does not scan unrelated ordinary data strings. |

## Evidence, credentials, and references

Each match supplies file and one-based line/column evidence, explanation, remediation, high confidence, and an official MCP reference. The engine redacts literal credential values before findings are returned; the tests confirm that the raw API-key fixture value never appears in report evidence.

`MCP-NET-001` and `MCP-SEC-001` cite [MCP Security Best Practices (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices). The authorization rules cite the [MCP Authorization Specification (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), which covers authorization-server endpoint HTTPS requirements and least-privilege scope selection. See the [MCP specification reference policy](mcp-specification-reference-policy.md) for version ownership.

These rules identify explicit static configuration/source patterns. They do not assert runtime exploitability, credential validity, or an overall security certification.
