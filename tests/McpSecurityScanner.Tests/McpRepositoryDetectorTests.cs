using McpSecurityScanner.Core.Detection;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Tests;

public sealed class McpRepositoryDetectorTests
{
    private static readonly GitHubRepositoryReference Repository = new("openai", "example-mcp");
    private readonly McpRepositoryDetector _detector = new();

    [Fact]
    public void Detect_ReturnsMcpRelatedWithConfigurationEvidence()
    {
        var result = _detector.Detect(ContentSet((".vscode/mcp.json", LoadFixture("config-mcp.json"))));

        Assert.Equal(McpRepositoryClassification.McpRelated, result.Classification);
        var evidence = Assert.Single(result.Evidence);
        Assert.Equal("MCP-CONFIG-001", evidence.SignalId);
        Assert.Equal(".vscode/mcp.json", evidence.FilePath);
        Assert.Equal(2, evidence.Line);
        Assert.Equal("\"mcpServers\":", evidence.Evidence);
        Assert.Equal(DetectionConfidence.High, evidence.Confidence);
    }

    [Fact]
    public void Detect_ReturnsMcpRelatedWithSdkDependencyEvidence()
    {
        var result = _detector.Detect(ContentSet(("package.json", LoadFixture("package-with-sdk.json"))));

        var evidence = Assert.Single(result.Evidence);
        Assert.Equal(McpRepositoryClassification.McpRelated, result.Classification);
        Assert.Equal("MCP-SDK-001", evidence.SignalId);
        Assert.Equal("@modelcontextprotocol/sdk", evidence.Evidence);
    }

    [Fact]
    public void Detect_ReturnsMcpRelatedWithServerDeclarationEvidence()
    {
        var result = _detector.Detect(ContentSet(("server.py", LoadFixture("python-server.py"))));

        var evidence = Assert.Single(result.Evidence);
        Assert.Equal(McpRepositoryClassification.McpRelated, result.Classification);
        Assert.Equal("MCP-SERVER-001", evidence.SignalId);
        Assert.Equal("from mcp.server", evidence.Evidence);
    }

    [Fact]
    public void Detect_ReturnsNotMcpWithoutImplementedSignal()
    {
        var result = _detector.Detect(ContentSet(("package.json", LoadFixture("not-mcp-package.json"))));

        Assert.Equal(McpRepositoryClassification.NotMcp, result.Classification);
        Assert.Empty(result.Evidence);
    }

    [Fact]
    public void Detect_ReturnsInconclusiveWhenNoTextFilesWereAvailable()
    {
        var result = _detector.Detect(ContentSet());

        Assert.Equal(McpRepositoryClassification.Inconclusive, result.Classification);
        Assert.Empty(result.Evidence);
    }

    [Fact]
    public void Detect_IsDeterministicAndOrdersEvidenceBySignalPriorityThenPath()
    {
        var firstContentSet = ContentSet(
            ("src/server.py", LoadFixture("python-server.py")),
            ("package.json", LoadFixture("package-with-sdk.json")),
            (".vscode/mcp.json", LoadFixture("config-mcp.json")));
        var secondContentSet = ContentSet(
            (".vscode/mcp.json", LoadFixture("config-mcp.json")),
            ("package.json", LoadFixture("package-with-sdk.json")),
            ("src/server.py", LoadFixture("python-server.py")));

        var firstResult = _detector.Detect(firstContentSet);
        var secondResult = _detector.Detect(secondContentSet);

        Assert.Equal(firstResult.Classification, secondResult.Classification);
        Assert.Equal(firstResult.Evidence, secondResult.Evidence);
        Assert.Equal(
            ["MCP-CONFIG-001", "MCP-SDK-001", "MCP-SERVER-001"],
            firstResult.Evidence.Select(evidence => evidence.SignalId));
    }

    [Fact]
    public void Detect_DoesNotTreatMcpFilenameOrReadmeMentionAsEvidence()
    {
        var result = _detector.Detect(ContentSet(
            ("mcp.json", "{\"name\":\"ordinary-config\"}"),
            ("README.md", "This project mentions MCP in documentation only.")));

        Assert.Equal(McpRepositoryClassification.NotMcp, result.Classification);
        Assert.Empty(result.Evidence);
    }

    private static RepositoryContentSet ContentSet(params (string Path, string Content)[] files) =>
        new(
            Repository,
            "main",
            files.Select(file => new RepositoryContentFile(file.Path, file.Content)).ToArray());

    private static string LoadFixture(string fixtureName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "McpDetection", fixtureName));
}
