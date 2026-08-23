using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class BroadOAuthScopeRule : ISecurityRule
{
    public SecurityRuleDefinition Definition { get; } = new(
        "MCP-AUTH-001",
        "Authorization",
        FindingSeverity.Medium,
        "Broad or wildcard OAuth scope",
        "An OAuth scope field includes a broad administrative, all-access, or wildcard scope.",
        "Broad scopes grant more access than an MCP server may need and increase the impact of token theft or misuse.",
        "Request the smallest resource-specific scopes required for the operation; use incremental authorization when elevated access is needed.",
        FindingConfidence.High,
        McpAuthorizationGuidance.Reference);

    public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet)
    {
        foreach (var line in RuleContentLineReader.ReadEligibleLines(contentSet))
        {
            var scopeField = ScopeField().Match(line.Content);
            if (scopeField.Success && BroadScope().IsMatch(scopeField.Groups["value"].Value))
            {
                yield return line.ToMatch(scopeField.Index + 1);
            }
        }
    }

    [GeneratedRegex(
        """(?<field>["']?scopes?["']?\s*[:=]\s*)(?<value>[^\r\n]+)""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScopeField();

    [GeneratedRegex(
        """(?<![\w:-])(?:\*|all|admin|full[_-]?access|(?:read|write):\*)(?![\w:-])""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BroadScope();
}
