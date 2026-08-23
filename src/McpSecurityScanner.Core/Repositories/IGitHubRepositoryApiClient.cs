namespace McpSecurityScanner.Core.Repositories;

public interface IGitHubRepositoryApiClient
{
    Task<GitHubApiResult<GitHubRepositoryMetadata>> GetMetadataAsync(
        GitHubRepositoryReference repository,
        CancellationToken cancellationToken);

    Task<GitHubApiResult<GitHubRepositoryTree>> GetTreeAsync(
        GitHubRepositoryReference repository,
        string reference,
        CancellationToken cancellationToken);

    Task<GitHubApiResult<GitHubRepositoryFileContent>> GetFileContentAsync(
        GitHubRepositoryReference repository,
        string path,
        string reference,
        int maximumFileBytes,
        CancellationToken cancellationToken);
}
