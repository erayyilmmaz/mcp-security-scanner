using System.Net;
using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class InsecureRemoteTransportRule : ISecurityRule
{
    public SecurityRuleDefinition Definition { get; } = new(
        "MCP-NET-001",
        "Transport Security",
        FindingSeverity.Medium,
        "Insecure remote HTTP transport",
        "A configuration or executable source line uses HTTP for a non-loopback remote endpoint.",
        "Unencrypted remote transport can expose MCP requests, responses, and credentials to network interception or modification.",
        "Use an HTTPS endpoint with certificate validation. Keep HTTP limited to explicitly local development addresses only.",
        FindingConfidence.High,
        McpSecurityGuidance.Reference);

    public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet)
    {
        foreach (var line in RuleContentLineReader.ReadEligibleLines(contentSet))
        {
            foreach (Match match in HttpUrl().Matches(line.Content))
            {
                var url = match.Groups["url"].Value.TrimEnd('.', ',', ';', ')', ']', '}');
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || IsLocalDevelopmentHost(uri.Host))
                {
                    continue;
                }

                yield return new RuleMatch(
                    line.FilePath,
                    line.Number,
                    match.Index + 1,
                    $"http://{uri.Authority}");
            }
        }
    }

    private static bool IsLocalDevelopmentHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(host, out var address)
            && (IPAddress.IsLoopback(address)
                || address.Equals(IPAddress.Any)
                || address.Equals(IPAddress.IPv6Any));
    }

    [GeneratedRegex("""(?<url>\bhttp://[^\s"'<>]+)""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HttpUrl();
}
