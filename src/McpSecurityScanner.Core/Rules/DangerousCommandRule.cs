using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class DangerousCommandRule : ISecurityRule
{
    public SecurityRuleDefinition Definition { get; } = new(
        "MCP-CMD-002",
        "Local Execution",
        FindingSeverity.High,
        "Destructive or download-and-execute command",
        "A repository configuration or executable source line contains an explicit destructive deletion or download-and-shell execution pattern.",
        "These patterns can destroy local data or execute remote content when an MCP server is installed or started.",
        "Remove the destructive or pipe-to-shell command. Pin, verify, and review downloaded artifacts before executing them with a least-privileged process.",
        FindingConfidence.High,
        McpSecurityGuidance.Reference);

    public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet)
    {
        foreach (var line in RuleContentLineReader.ReadEligibleLines(contentSet))
        {
            var match = RecursiveForceRemove().Match(line.Content);
            if (!match.Success)
            {
                match = DownloadPipeToShell().Match(line.Content);
            }

            if (match.Success)
            {
                yield return line.ToMatch(match.Index + 1);
            }
        }
    }

    [GeneratedRegex(
        @"\brm\s+-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+\s+\S+|\brm\s+--force\s+--recursive\s+\S+|\brm\s+--recursive\s+--force\s+\S+",
        RegexOptions.CultureInvariant)]
    private static partial Regex RecursiveForceRemove();

    [GeneratedRegex(
        @"\b(?:curl|wget)\b[^|\r\n]*\|\s*(?:(?:/usr/bin/env\s+)?(?:/bin/)?(?:sh|bash|zsh))\b",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex DownloadPipeToShell();
}
