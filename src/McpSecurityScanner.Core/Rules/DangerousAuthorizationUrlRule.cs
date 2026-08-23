using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class DangerousAuthorizationUrlRule : ISecurityRule
{
    public SecurityRuleDefinition Definition { get; } = new(
        "MCP-AUTH-002",
        "Authorization",
        FindingSeverity.High,
        "Dangerous authorization URL scheme",
        "An authorization, authentication, or redirect URL field uses a javascript:, file:, or data: scheme.",
        "These schemes can execute script, expose local files, or embed untrusted content instead of directing a user to a secure authorization endpoint.",
        "Use a registered HTTPS authorization or redirect URI. Do not use javascript:, file:, or data: values for authorization flows.",
        FindingConfidence.High,
        McpAuthorizationGuidance.Reference);

    public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet)
    {
        foreach (var line in RuleContentLineReader.ReadEligibleLines(contentSet))
        {
            var match = DangerousAuthorizationUrl().Match(line.Content);
            if (match.Success)
            {
                yield return line.ToMatch(match.Index + 1);
            }
        }
    }

    [GeneratedRegex(
        """(?<field>["']?(?:authorization|auth|redirect)[_-]?(?:url|uri|endpoint)["']?\s*[:=]\s*["']?)(?:javascript|file|data):""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DangerousAuthorizationUrl();
}
