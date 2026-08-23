using McpSecurityScanner.Core.Contracts;

namespace McpSecurityScanner.Core.Repositories;

public sealed record RepositoryContentFile(string Path, string Content);

public sealed record RepositoryContentSet(
    GitHubRepositoryReference Repository,
    string Reference,
    IReadOnlyList<RepositoryContentFile> Files);

public sealed record RepositoryIngestionResult(
    RepositoryContentSet? ContentSet,
    ApiErrorResponse? Error)
{
    public bool IsSuccess => ContentSet is not null && Error is null;

    public static RepositoryIngestionResult Success(RepositoryContentSet contentSet) =>
        new(contentSet, null);

    public static RepositoryIngestionResult Failure(ApiErrorResponse error) =>
        new(null, error);
}
