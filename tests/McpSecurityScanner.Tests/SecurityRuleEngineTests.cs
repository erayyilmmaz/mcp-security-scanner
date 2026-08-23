using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Core.Rules;

namespace McpSecurityScanner.Tests;

public sealed class SecurityRuleEngineTests
{
    private static readonly GitHubRepositoryReference Repository = new("openai", "example-mcp");

    [Fact]
    public void Analyze_ProducesCompleteFindingAndSeveritySummary()
    {
        var rule = new StaticRule(
            Definition("MCP-TEST-001", FindingSeverity.High),
            [new RuleMatch("examples/mcp.json", 14, 3, "sudo node server.js")]);
        var engine = new SecurityRuleEngine([rule], "1.0.0");

        var report = engine.Analyze(ContentSet());

        Assert.Equal("1.0.0", report.RuleSetVersion);
        var finding = Assert.Single(report.Findings);
        Assert.Equal("MCP-TEST-001", finding.RuleId);
        Assert.Equal("Local Execution", finding.Category);
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Equal("Potentially dangerous command", finding.Title);
        Assert.Equal("A deterministic test rule.", finding.Description);
        Assert.Equal("sudo node server.js", finding.Evidence);
        Assert.Equal("examples/mcp.json", finding.FilePath);
        Assert.Equal(14, finding.Line);
        Assert.Equal(3, finding.Column);
        Assert.Equal("The command could run with elevated privileges.", finding.WhyItMatters);
        Assert.Equal("Remove privileged execution.", finding.Remediation);
        Assert.Equal(FindingConfidence.High, finding.Confidence);
        Assert.Equal("MCP Security Best Practices", finding.Reference.Title);
        Assert.Equal("https://modelcontextprotocol.io/", finding.Reference.Url);
        Assert.Equal(1, report.Summary.High);
        Assert.Equal(0, report.Summary.Critical + report.Summary.Medium + report.Summary.Low + report.Summary.Informational);
    }

    [Theory]
    [InlineData("API_KEY=super-secret-value", "API_KEY=[REDACTED]")]
    [InlineData("Authorization: Bearer super-secret-token", "Authorization: Bearer [REDACTED]")]
    [InlineData("token: 'another-secret'", "token: [REDACTED]")]
    public void Analyze_RedactsSecretEvidence(string rawEvidence, string expectedEvidence)
    {
        var rule = new StaticRule(
            Definition("MCP-TEST-002", FindingSeverity.Medium),
            [new RuleMatch("config.json", 1, null, rawEvidence)]);
        var engine = new SecurityRuleEngine([rule], "1.0.0");

        var report = engine.Analyze(ContentSet());

        Assert.Equal(expectedEvidence, Assert.Single(report.Findings).Evidence);
        Assert.DoesNotContain("secret", Assert.Single(report.Findings).Evidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_IsDeterministicAndOrdersFindingsBySeverityRuleAndLocation()
    {
        var lowRule = new StaticRule(
            Definition("MCP-TEST-200", FindingSeverity.Low),
            [new RuleMatch("z.json", 3, null, "z"), new RuleMatch("a.json", 2, null, "a")]);
        var criticalRule = new StaticRule(
            Definition("MCP-TEST-100", FindingSeverity.Critical),
            [new RuleMatch("b.json", 1, null, "b")]);

        var firstEngine = new SecurityRuleEngine([lowRule, criticalRule], "1.0.0");
        var secondEngine = new SecurityRuleEngine([criticalRule, lowRule], "1.0.0");

        var firstReport = firstEngine.Analyze(ContentSet());
        var secondReport = secondEngine.Analyze(ContentSet());

        Assert.Equal(firstReport.Findings, secondReport.Findings);
        Assert.Equal(
            ["MCP-TEST-100:b.json", "MCP-TEST-200:a.json", "MCP-TEST-200:z.json"],
            firstReport.Findings.Select(finding => $"{finding.RuleId}:{finding.FilePath}"));
        Assert.Equal(1, firstReport.Summary.Critical);
        Assert.Equal(2, firstReport.Summary.Low);
    }

    [Fact]
    public void Constructor_RejectsDuplicateRuleIds()
    {
        var firstRule = new StaticRule(Definition("MCP-TEST-001", FindingSeverity.Low), []);
        var duplicateRule = new StaticRule(Definition("MCP-TEST-001", FindingSeverity.High), []);

        Assert.Throws<ArgumentException>(() => new SecurityRuleEngine([firstRule, duplicateRule], "1.0.0"));
    }

    private static RepositoryContentSet ContentSet() =>
        new(Repository, "main", [new RepositoryContentFile("config.json", "{}")]);

    private static SecurityRuleDefinition Definition(string id, FindingSeverity severity) =>
        new(
            id,
            "Local Execution",
            severity,
            "Potentially dangerous command",
            "A deterministic test rule.",
            "The command could run with elevated privileges.",
            "Remove privileged execution.",
            FindingConfidence.High,
            new SecurityReference("MCP Security Best Practices", "https://modelcontextprotocol.io/"));

    private sealed class StaticRule : ISecurityRule
    {
        private readonly IReadOnlyList<RuleMatch> _matches;

        public StaticRule(SecurityRuleDefinition definition, IReadOnlyList<RuleMatch> matches)
        {
            Definition = definition;
            _matches = matches;
        }

        public SecurityRuleDefinition Definition { get; }

        public IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet) => _matches;
    }
}
