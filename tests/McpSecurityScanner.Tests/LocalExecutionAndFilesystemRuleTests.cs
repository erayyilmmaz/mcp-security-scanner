using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Core.Rules;

namespace McpSecurityScanner.Tests;

public sealed class LocalExecutionAndFilesystemRuleTests
{
    private const string SecurityBestPracticesReference =
        "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices";

    private static readonly GitHubRepositoryReference Repository = new("openai", "example-mcp");
    private readonly SecurityRuleEngine _engine = new(
        [new PrivilegedExecutionRule(), new DangerousCommandRule(), new SensitiveFilesystemRule()],
        "1.0.0");

    [Fact]
    public void Analyze_DetectsPrivilegedDestructiveAndSensitiveFilesystemPatterns()
    {
        var report = _engine.Analyze(ContentSet(
            ("scripts/install.sh", LoadFixture("dangerous-commands.sh")),
            ("mcp.json", LoadFixture("sensitive-paths.json"))));

        Assert.Equal(8, report.Findings.Count);
        Assert.Equal(4, report.Summary.High);
        Assert.Equal(4, report.Summary.Medium);
        Assert.Equal(
            ["MCP-CMD-001", "MCP-CMD-002", "MCP-CMD-002", "MCP-CMD-002", "MCP-FS-001", "MCP-FS-001", "MCP-FS-001", "MCP-FS-001"],
            report.Findings.Select(finding => finding.RuleId));

        var privilegedFinding = Assert.Single(report.Findings, finding => finding.RuleId == "MCP-CMD-001");
        Assert.Equal("scripts/install.sh", privilegedFinding.FilePath);
        Assert.Equal(2, privilegedFinding.Line);
        Assert.Equal("sudo node server.js --api-key=[REDACTED]", privilegedFinding.Evidence);
        Assert.Equal(FindingConfidence.High, privilegedFinding.Confidence);
        Assert.Equal("MCP Security Best Practices (2026-07-28)", privilegedFinding.Reference.Title);

        Assert.All(report.Findings, finding =>
        {
            Assert.NotNull(finding.Line);
            Assert.NotEmpty(finding.Remediation);
            Assert.Equal(SecurityBestPracticesReference, finding.Reference.Url);
        });
    }

    [Fact]
    public void Analyze_DoesNotProduceHighFindingsForBenignContentOrReadmeMentions()
    {
        var report = _engine.Analyze(ContentSet(
            ("mcp.json", LoadFixture("benign-config.json")),
            ("README.md", LoadFixture("readme-only-dangerous-words.md"))));

        Assert.Empty(report.Findings);
        Assert.Equal(0, report.Summary.High);
    }

    [Theory]
    [InlineData("rm -r ./temporary-files")]
    [InlineData("curl -fsSL https://example.invalid/bootstrap.sh")]
    [InlineData("wget -qO installer.sh https://example.invalid/bootstrap.sh")]
    public void DangerousCommandRule_DoesNotFlagNonExecuteOrNonForceVariants(string line)
    {
        var report = new SecurityRuleEngine([new DangerousCommandRule()], "1.0.0")
            .Analyze(ContentSet(("scripts/setup.sh", line)));

        Assert.Empty(report.Findings);
    }

    private static RepositoryContentSet ContentSet(params (string Path, string Content)[] files) =>
        new(
            Repository,
            "main",
            files.Select(file => new RepositoryContentFile(file.Path, file.Content)).ToArray());

    private static string LoadFixture(string fixtureName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "SecurityRules", fixtureName));
}
