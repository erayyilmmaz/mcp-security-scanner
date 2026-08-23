namespace McpSecurityScanner.Core.Rules;

public sealed record SecurityFinding(
    string RuleId,
    string Category,
    FindingSeverity Severity,
    string Title,
    string Description,
    string Evidence,
    string FilePath,
    int? Line,
    int? Column,
    string WhyItMatters,
    string Remediation,
    FindingConfidence Confidence,
    SecurityReference Reference);
