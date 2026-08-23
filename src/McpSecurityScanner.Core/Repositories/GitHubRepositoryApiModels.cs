namespace McpSecurityScanner.Core.Repositories;

public sealed record GitHubRepositoryMetadata(string DefaultBranch);

public sealed record GitHubRepositoryTree(
    bool IsTruncated,
    IReadOnlyList<GitHubRepositoryTreeEntry> Entries);

public sealed record GitHubRepositoryTreeEntry(
    string Path,
    string Type,
    long? Size,
    string? Mode = null);

public sealed record GitHubRepositoryFileContent(byte[] Bytes);
