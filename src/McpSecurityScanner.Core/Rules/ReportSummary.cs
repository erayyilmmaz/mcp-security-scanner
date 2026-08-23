namespace McpSecurityScanner.Core.Rules;

public sealed record ReportSummary(
    int Critical,
    int High,
    int Medium,
    int Low,
    int Informational)
{
    public static ReportSummary FromFindings(IEnumerable<SecurityFinding> findings) =>
        new(
            findings.Count(finding => finding.Severity == FindingSeverity.Critical),
            findings.Count(finding => finding.Severity == FindingSeverity.High),
            findings.Count(finding => finding.Severity == FindingSeverity.Medium),
            findings.Count(finding => finding.Severity == FindingSeverity.Low),
            findings.Count(finding => finding.Severity == FindingSeverity.Informational));
}
