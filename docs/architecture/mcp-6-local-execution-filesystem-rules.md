# MCP-6: Local Execution and Sensitive Filesystem Rules

**Status:** Accepted for MVP implementation
**Scope:** MCP-6.1 through MCP-6.4

MCP-6 contributes three independent `ISecurityRule` implementations to the MCP-5 engine. Each reads the already bounded repository content only; it performs no network action, shell invocation, clone, build, or execution.

## Rule catalogue

| Rule ID | Severity | Detection | Precision boundary |
|---|---:|---|---|
| `MCP-CMD-001` | High | `sudo` command token | Supported configuration or executable source formats only. |
| `MCP-CMD-002` | High | `rm` with both recursive and force flags; `curl`/`wget` piped to `sh`, `bash`, or `zsh` | Does not flag download-only or non-force/non-recursive removal. |
| `MCP-FS-001` | Medium | `~/.ssh`, `~/.aws`, `$HOME` equivalents, `/etc/passwd`, `/etc/shadow`, `/etc/ssh`, Docker socket, process environment, and Windows System32 paths | Supported configuration or executable source formats only. |

README and plain-text documentation are intentionally outside the eligible formats. Mentioning a dangerous pattern in explanatory prose is not evidence that a server configuration or executable source will use it.

## Evidence and remediation

Each rule returns the full relevant source line plus a one-based source location. The MCP-5 engine applies secret evidence redaction before the finding can leave the analyzer. Every rule supplies a least-privilege remediation and the official [MCP Security Best Practices (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) reference. See the [MCP specification reference policy](mcp-specification-reference-policy.md) for version ownership.

These findings identify explicit static patterns; they do not claim runtime exploitability, repository compromise, or an overall security certification.
