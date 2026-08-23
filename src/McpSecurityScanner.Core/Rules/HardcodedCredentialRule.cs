using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class HardcodedCredentialRule : ISecurityRule
{
    public SecurityRuleDefinition Definition { get; } = new(
        "MCP-SEC-001",
        "Credential Handling",
        FindingSeverity.High,
        "Hardcoded credential",
        "A configuration or executable source line assigns a literal value to a credential-like field.",
        "Hardcoded credentials can be copied, logged, committed, or exposed to users of the MCP server.",
        "Remove the literal credential, rotate it if it was real, and load it from an approved secret manager or runtime environment variable.",
        FindingConfidence.High,
        McpSecurityGuidance.Reference);

    public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet)
    {
        foreach (var line in RuleContentLineReader.ReadEligibleLines(contentSet))
        {
            foreach (Match match in CredentialAssignment().Matches(line.Content))
            {
                if (IsRuntimeReferenceOrPlaceholder(match.Groups["value"].Value))
                {
                    continue;
                }

                yield return line.ToMatch(match.Index + 1);
                break;
            }
        }
    }

    private static bool IsRuntimeReferenceOrPlaceholder(string rawValue)
    {
        var value = rawValue.Trim().Trim('"', '\'');
        return string.IsNullOrWhiteSpace(value)
            || value.StartsWith('$')
            || value.StartsWith("process.env.", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("env.", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("${{", StringComparison.Ordinal)
            || value.Contains("replace", StringComparison.OrdinalIgnoreCase)
            || value.Contains("example", StringComparison.OrdinalIgnoreCase)
            || value.Contains("your-", StringComparison.OrdinalIgnoreCase)
            || value.Contains("changeme", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(
        """(?<label>["']?(?:api[_-]?key|token|secret|password|client[_-]?secret)["']?\s*[:=]\s*)(?<value>"[^"]+"|'[^']+'|[^\s,;]+)""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CredentialAssignment();
}
