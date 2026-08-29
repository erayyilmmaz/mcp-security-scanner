using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Core.Rules;

namespace McpSecurityScanner.Tests;

public sealed class TransportCredentialAuthorizationRuleTests
{
    private const string SecurityBestPracticesReference =
        "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices";
    private const string AuthorizationSpecificationReference =
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization";

    private static readonly GitHubRepositoryReference Repository = new("openai", "example-mcp");
    private readonly SecurityRuleEngine _engine = new(
        [
            new InsecureRemoteTransportRule(),
            new HardcodedCredentialRule(),
            new BroadOAuthScopeRule(),
            new DangerousAuthorizationUrlRule()
        ],
        "1.0.0");

    [Fact]
    public void Analyze_DetectsRemoteTransportCredentialBroadScopeAndDangerousAuthorizationUrls()
    {
        var report = _engine.Analyze(ContentSet(("mcp.json", LoadFixture("transport-and-auth-positive.json"))));

        Assert.Equal(5, report.Findings.Count);
        Assert.Equal(3, report.Summary.High);
        Assert.Equal(2, report.Summary.Medium);
        Assert.Equal(
            ["MCP-AUTH-002", "MCP-AUTH-002", "MCP-SEC-001", "MCP-AUTH-001", "MCP-NET-001"],
            report.Findings.Select(finding => finding.RuleId));

        var credentialFinding = Assert.Single(report.Findings, finding => finding.RuleId == "MCP-SEC-001");
        Assert.Equal("mcp.json", credentialFinding.FilePath);
        Assert.Equal(3, credentialFinding.Line);
        Assert.Equal("\"apiKey\": [REDACTED],", credentialFinding.Evidence.Trim());
        Assert.DoesNotContain("actual-super-secret-value", credentialFinding.Evidence, StringComparison.Ordinal);

        var transportFinding = Assert.Single(report.Findings, finding => finding.RuleId == "MCP-NET-001");
        Assert.Equal("http://api.example.com", transportFinding.Evidence);
        Assert.Equal("MCP Security Best Practices (2026-07-28)", transportFinding.Reference.Title);

        Assert.All(report.Findings, finding =>
        {
            Assert.NotEmpty(finding.Description);
            Assert.NotEmpty(finding.Remediation);
            Assert.Equal(FindingConfidence.High, finding.Confidence);
            var expectedReference = finding.RuleId is "MCP-NET-001" or "MCP-SEC-001"
                ? SecurityBestPracticesReference
                : AuthorizationSpecificationReference;
            Assert.Equal(expectedReference, finding.Reference.Url);
        });
    }

    [Fact]
    public void Analyze_DoesNotFlagLoopbackDevelopmentCredentialReferencesOrNarrowAuthorizationSettings()
    {
        var report = _engine.Analyze(ContentSet(("mcp.json", LoadFixture("transport-and-auth-negative.json"))));

        Assert.Empty(report.Findings);
        Assert.Equal(0, report.Summary.High + report.Summary.Medium);
    }

    [Theory]
    [InlineData("http://localhost:8080/mcp")]
    [InlineData("http://127.0.0.42:8080/mcp")]
    [InlineData("http://[::1]:8080/mcp")]
    [InlineData("http://0.0.0.0:8080/mcp")]
    public void InsecureRemoteTransportRule_ExcludesLoopbackAndDevelopmentBindAddresses(string endpoint)
    {
        var report = new SecurityRuleEngine([new InsecureRemoteTransportRule()], "1.0.0")
            .Analyze(ContentSet(("config.json", $"{{ \"endpoint\": \"{endpoint}\" }}")));

        Assert.Empty(report.Findings);
    }

    [Theory]
    [InlineData("{ \"authorizationUrl\": \"file:///etc/passwd\" }")]
    [InlineData("{ \"redirect_uri\": \"data:text/html,untrusted\" }")]
    public void DangerousAuthorizationUrlRule_DetectsConfiguredDangerousSchemes(string content)
    {
        var report = new SecurityRuleEngine([new DangerousAuthorizationUrlRule()], "1.0.0")
            .Analyze(ContentSet(("config.json", content)));

        Assert.Single(report.Findings);
        Assert.Equal("MCP-AUTH-002", report.Findings[0].RuleId);
    }

    private static RepositoryContentSet ContentSet(params (string Path, string Content)[] files) =>
        new(
            Repository,
            "main",
            files.Select(file => new RepositoryContentFile(file.Path, file.Content)).ToArray());

    private static string LoadFixture(string fixtureName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "SecurityRules", fixtureName));
}
