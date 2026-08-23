using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class SensitiveFilesystemRule : ISecurityRule
{
    public SecurityRuleDefinition Definition { get; } = new(
        "MCP-FS-001",
        "Sensitive Filesystem Access",
        FindingSeverity.Medium,
        "Sensitive filesystem path reference",
        "A repository configuration or executable source line references a credential, SSH, operating-system, or container-control path.",
        "An MCP server with access to these paths can expose credentials, modify host configuration, or control local container workloads.",
        "Do not expose host credential or system paths to the server. Use a narrowly scoped application directory and inject only the minimum required capability.",
        FindingConfidence.High,
        McpSecurityGuidance.Reference);

    public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet)
    {
        foreach (var line in RuleContentLineReader.ReadEligibleLines(contentSet))
        {
            var match = SensitivePath().Match(line.Content);
            if (match.Success)
            {
                yield return line.ToMatch(match.Index + 1);
            }
        }
    }

    [GeneratedRegex(
        """(?:~|\$HOME|\$\{HOME\})/(?:\.ssh|\.aws)(?:/[^\s\"'`]+)?|/home/[^/\s]+/(?:\.ssh|\.aws)(?:/[^\s\"'`]+)?|/(?:etc/(?:passwd|shadow)|etc/ssh(?:/[^\s\"'`]+)?|var/run/docker\.sock|proc/self/environ)|[A-Za-z]:\\Windows\\System32(?:\\[^\s\"'`]+)?""",
        RegexOptions.CultureInvariant)]
    private static partial Regex SensitivePath();
}
