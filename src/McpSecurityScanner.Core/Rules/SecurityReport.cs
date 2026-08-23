namespace McpSecurityScanner.Core.Rules;

public sealed record SecurityReport(
    string RuleSetVersion,
    IReadOnlyList<SecurityFinding> Findings,
    ReportSummary Summary);
