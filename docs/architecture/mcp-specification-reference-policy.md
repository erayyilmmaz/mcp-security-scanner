# MCP Specification Reference Policy

## Baseline

MSS bases its MCP-specific finding references on the official **2026-07-28** MCP release:

- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

`McpSpecificationReferences` is the sole code-level owner of this baseline version and the two canonical URLs. Rule definitions use its guidance objects so every returned finding is updated together when the baseline changes.

## Scope boundary

MSS is a static repository scanner. It does not implement an MCP client or server, negotiate a protocol version, validate protocol conformance, or claim complete coverage of the 2026-07-28 specification. The reference baseline only identifies the official guidance used for the implemented deterministic rules.

The scanner accepts false positives and false negatives as an inherent limitation of bounded static pattern detection. A finding is evidence for human review, and no finding is proof that a repository is safe.

## Update procedure

When a later MCP specification becomes normative and materially affects a current rule reference:

1. Verify the official replacement pages and the rule's continued applicability.
2. Update `McpSpecificationReferences`, affected rule titles, architecture documentation, README, and exact reference assertions together.
3. Do not add a new rule solely because it appears on a roadmap or in a future-looking proposal.
