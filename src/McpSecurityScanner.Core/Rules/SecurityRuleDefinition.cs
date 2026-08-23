namespace McpSecurityScanner.Core.Rules;

public sealed record SecurityRuleDefinition(
    string Id,
    string Category,
    FindingSeverity Severity,
    string Title,
    string Description,
    string WhyItMatters,
    string Remediation,
    FindingConfidence Confidence,
    SecurityReference Reference);
