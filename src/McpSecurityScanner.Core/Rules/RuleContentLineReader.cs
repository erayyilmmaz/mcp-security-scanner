using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

internal sealed record RuleContentLine(string FilePath, int Number, string Content)
{
    public RuleMatch ToMatch(int column) => new(FilePath, Number, column, Content.Trim());
}

internal static class RuleContentLineReader
{
    private static readonly string[] EligibleExtensions =
    [
        ".bash", ".cjs", ".cs", ".cts", ".go", ".java", ".js", ".json", ".kt", ".mjs",
        ".mts", ".php", ".ps1", ".py", ".rb", ".rs", ".sh", ".toml", ".ts", ".tsx",
        ".yaml", ".yml", ".zsh"
    ];

    public static IEnumerable<RuleContentLine> ReadEligibleLines(RepositoryContentSet contentSet)
    {
        foreach (var file in contentSet.Files.OrderBy(file => file.Path, StringComparer.Ordinal))
        {
            if (!IsEligible(file.Path))
            {
                continue;
            }

            using var reader = new StringReader(file.Content);
            var lineNumber = 0;
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                lineNumber++;
                yield return new RuleContentLine(file.Path, lineNumber, line);
            }
        }
    }

    private static bool IsEligible(string path)
    {
        var fileName = Path.GetFileName(path);
        return string.Equals(fileName, "Dockerfile", StringComparison.OrdinalIgnoreCase)
            || EligibleExtensions.Any(extension => fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase));
    }
}
