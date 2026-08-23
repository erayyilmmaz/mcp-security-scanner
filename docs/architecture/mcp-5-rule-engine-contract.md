# MCP-5: Rule Engine and Finding Contract

**Status:** Accepted for MVP implementation
**Scope:** MCP-5.1 through MCP-5.5

The rule engine consumes the bounded `RepositoryContentSet` from MCP-3. It is deterministic, has no network dependency, and must never execute repository code.

## Rule contract

Each `ISecurityRule` supplies immutable `SecurityRuleDefinition` metadata and an independent `Evaluate(RepositoryContentSet)` method that returns one or more `RuleMatch` instances. Adding a rule requires implementing the interface and registering it with the engine; engine orchestration is not changed.

| Definition field | Purpose |
|---|---|
| ID, category, severity, title, description | Stable classification and display metadata. |
| Why it matters, remediation | Security impact and actionable safer alternative. |
| Confidence | Strength of the static evidence. |
| Reference | Authoritative title and URL for the rule basis. |

## Finding and report contract

Each `SecurityFinding` contains every definition field plus redacted evidence, repository-relative file path, optional line/column, and the reference. `SecurityReport` contains the rule-set version, deterministically ordered findings, and severity counts for critical, high, medium, low, and informational results.

Ordering is: severity (critical first), rule ID, file path, line, column, evidence. Duplicate rule IDs are rejected during engine construction.

## Evidence redaction

Raw rule evidence never reaches a report directly. Before serializing a finding, the engine masks labelled API keys/tokens/secrets/passwords/client secrets, Authorization Bearer values, and recognizable standalone GitHub/OpenAI-style tokens as `[REDACTED]`.

Redaction is defense in depth, not a substitute for narrow evidence. Rules should return the smallest location-specific evidence they need.

## Current status

MCP-5 delivers the engine only. It intentionally does not include concrete security rules; MCP-6 and MCP-7 add those as independent `ISecurityRule` implementations.
