using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class PrivilegedExecutionRule : ISecurityRule
{
    public SecurityRuleDefinition Definition { get; } = new(
        "MCP-CMD-001",
        "Local Execution",
        FindingSeverity.High,
        "Privileged execution command",
        "A repository configuration or executable source line invokes sudo.",
        "Running an MCP server or its setup command with elevated privileges expands the impact of a compromised server or dependency.",
        "Remove sudo from the server command. Run the service with the least-privileged dedicated account and grant only the required filesystem permissions.",
        FindingConfidence.High,
        McpSecurityGuidance.Reference);

    public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet)
    {
        foreach (var line in RuleContentLineReader.ReadEligibleLines(contentSet))
        {
            var match = SudoCommand().Match(line.Content);
            if (match.Success)
            {
                yield return line.ToMatch(match.Index + 1);
            }
        }
    }

    [GeneratedRegex(@"(?<![\w.-])sudo\b", RegexOptions.CultureInvariant)]
    private static partial Regex SudoCommand();
}
