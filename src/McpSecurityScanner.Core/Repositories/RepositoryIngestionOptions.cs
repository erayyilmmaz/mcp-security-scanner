namespace McpSecurityScanner.Core.Repositories;

public sealed record RepositoryIngestionOptions
{
    public const int DefaultMaximumTreeEntries = 1_000;
    public const int DefaultMaximumCandidateFiles = 200;
    public const int DefaultMaximumFileBytes = 512 * 1024;
    public const int DefaultMaximumTotalBytes = 5 * 1024 * 1024;

    public static RepositoryIngestionOptions Default { get; } = new();

    public int MaximumTreeEntries { get; init; } = DefaultMaximumTreeEntries;

    public int MaximumCandidateFiles { get; init; } = DefaultMaximumCandidateFiles;

    public int MaximumFileBytes { get; init; } = DefaultMaximumFileBytes;

    public int MaximumTotalBytes { get; init; } = DefaultMaximumTotalBytes;

    public TimeSpan AnalysisTimeout { get; init; } = TimeSpan.FromSeconds(20);
}
