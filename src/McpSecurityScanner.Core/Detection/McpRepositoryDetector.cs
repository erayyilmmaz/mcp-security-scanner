using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Detection;

public sealed partial class McpRepositoryDetector
{
    private static readonly string[] ManifestFileNames =
    [
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pyproject.toml",
        "requirements.txt",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "*.csproj"
    ];

    private static readonly string[] SdkDependencyTokens =
    [
        "@modelcontextprotocol/sdk",
        "modelcontextprotocol",
        "ModelContextProtocol"
    ];

    private static readonly string[] ServerDeclarationTokens =
    [
        "@modelcontextprotocol/sdk/",
        "from mcp.server",
        "import mcp.server",
        "from fastmcp",
        "FastMCP(",
        "using ModelContextProtocol",
        "[McpServerTool]"
    ];

    private static readonly string[] SourceFileExtensions =
    [
        ".cs",
        ".cjs",
        ".js",
        ".jsx",
        ".mjs",
        ".py",
        ".ts",
        ".tsx"
    ];

    public McpDetectionResult Detect(RepositoryContentSet contentSet)
    {
        var evidence = new List<McpDetectionEvidence>();

        foreach (var file in contentSet.Files.OrderBy(file => file.Path, StringComparer.Ordinal))
        {
            AddConfigurationEvidence(file, evidence);
            AddSdkDependencyEvidence(file, evidence);
            AddServerDeclarationEvidence(file, evidence);
        }

        var orderedEvidence = evidence
            .OrderBy(item => GetPriority(item.SignalId))
            .ThenBy(item => item.FilePath, StringComparer.Ordinal)
            .ThenBy(item => item.Line ?? int.MaxValue)
            .ThenBy(item => item.Evidence, StringComparer.Ordinal)
            .ToArray();

        var classification = orderedEvidence.Length > 0
            ? McpRepositoryClassification.McpRelated
            : contentSet.Files.Count == 0
                ? McpRepositoryClassification.Inconclusive
                : McpRepositoryClassification.NotMcp;

        return new McpDetectionResult(classification, orderedEvidence);
    }

    private static void AddConfigurationEvidence(RepositoryContentFile file, ICollection<McpDetectionEvidence> evidence)
    {
        if (!file.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var match = McpServersProperty().Match(file.Content);
        if (!match.Success)
        {
            return;
        }

        evidence.Add(CreateEvidence(
            McpDetectionSignalCatalog.Configuration,
            file.Path,
            file.Content,
            match.Index,
            "\"mcpServers\":"));
    }

    private static void AddSdkDependencyEvidence(RepositoryContentFile file, ICollection<McpDetectionEvidence> evidence)
    {
        if (!IsManifest(file.Path))
        {
            return;
        }

        var token = SdkDependencyTokens.FirstOrDefault(token =>
            file.Content.Contains(token, StringComparison.Ordinal));
        if (token is null)
        {
            return;
        }

        evidence.Add(CreateEvidence(
            McpDetectionSignalCatalog.SdkDependency,
            file.Path,
            file.Content,
            file.Content.IndexOf(token, StringComparison.Ordinal),
            token));
    }

    private static void AddServerDeclarationEvidence(RepositoryContentFile file, ICollection<McpDetectionEvidence> evidence)
    {
        if (!IsSourceFile(file.Path))
        {
            return;
        }

        var token = ServerDeclarationTokens.FirstOrDefault(token =>
            file.Content.Contains(token, StringComparison.Ordinal));
        if (token is null)
        {
            return;
        }

        evidence.Add(CreateEvidence(
            McpDetectionSignalCatalog.ServerDeclaration,
            file.Path,
            file.Content,
            file.Content.IndexOf(token, StringComparison.Ordinal),
            token));
    }

    private static McpDetectionEvidence CreateEvidence(
        McpDetectionSignal signal,
        string path,
        string content,
        int index,
        string token) =>
        new(
            signal.Id,
            signal.Title,
            path,
            GetLineNumber(content, index),
            token,
            signal.Confidence);

    private static bool IsManifest(string path)
    {
        var fileName = Path.GetFileName(path);

        return ManifestFileNames.Any(pattern =>
            pattern.StartsWith("*.", StringComparison.Ordinal)
                ? fileName.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase)
                : string.Equals(fileName, pattern, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSourceFile(string path) =>
        SourceFileExtensions.Any(extension => path.EndsWith(extension, StringComparison.OrdinalIgnoreCase));

    private static int GetPriority(string signalId) =>
        McpDetectionSignalCatalog.All.First(signal => signal.Id == signalId).Priority;

    private static int GetLineNumber(string content, int index) =>
        index < 0 ? 1 : content.AsSpan(0, index).Count('\n') + 1;

    [GeneratedRegex("\"mcpServers\"\\s*:", RegexOptions.CultureInvariant)]
    private static partial Regex McpServersProperty();
}
