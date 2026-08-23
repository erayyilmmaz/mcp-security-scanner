using System.Text;
using McpSecurityScanner.Core.Contracts;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Tests;

public sealed class RepositoryIngestionServiceTests
{
    private static readonly GitHubRepositoryReference Repository = new("openai", "example-mcp");

    [Fact]
    public async Task ReadAsync_ReturnsOnlyUtf8TextFiles()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            TreeResult = SuccessTree(
                new GitHubRepositoryTreeEntry("config/mcp.json", "blob", 18),
                new GitHubRepositoryTreeEntry("assets/logo.bin", "blob", 4))
        };
        client.FileResults["config/mcp.json"] = SuccessContent("{\"name\":\"mcp\"}");
        client.FileResults["assets/logo.bin"] = GitHubApiResult<GitHubRepositoryFileContent>.Success(
            new GitHubRepositoryFileContent(new byte[] { 0, 1, 2, 3 }));

        var service = new RepositoryIngestionService(client);

        var result = await service.ReadAsync(Repository);

        Assert.True(result.IsSuccess);
        var file = Assert.Single(result.ContentSet!.Files);
        Assert.Equal("config/mcp.json", file.Path);
        Assert.Equal("{\"name\":\"mcp\"}", file.Content);
        Assert.Equal(2, client.FileContentRequestCount);
    }

    [Fact]
    public async Task ReadAsync_ReturnsLimitError_BeforeReadingTooManyCandidateFiles()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            TreeResult = SuccessTree(
                new GitHubRepositoryTreeEntry("first.json", "blob", 10),
                new GitHubRepositoryTreeEntry("second.json", "blob", 10))
        };
        var service = new RepositoryIngestionService(client, new RepositoryIngestionOptions
        {
            MaximumTreeEntries = 10,
            MaximumCandidateFiles = 1,
            MaximumFileBytes = 100,
            MaximumTotalBytes = 100,
            AnalysisTimeout = TimeSpan.FromSeconds(1)
        });

        var result = await service.ReadAsync(Repository);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApiErrorCodes.ResourceLimitExceeded, result.Error?.Code);
        Assert.Equal(0, client.FileContentRequestCount);
    }

    [Fact]
    public async Task ReadAsync_ReturnsLimitError_BeforeReadingOversizedFile()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            TreeResult = SuccessTree(new GitHubRepositoryTreeEntry("large.json", "blob", 101))
        };
        var service = new RepositoryIngestionService(client, new RepositoryIngestionOptions
        {
            MaximumTreeEntries = 10,
            MaximumCandidateFiles = 10,
            MaximumFileBytes = 100,
            MaximumTotalBytes = 200,
            AnalysisTimeout = TimeSpan.FromSeconds(1)
        });

        var result = await service.ReadAsync(Repository);

        Assert.Equal(ApiErrorCodes.ResourceLimitExceeded, result.Error?.Code);
        Assert.Equal(0, client.FileContentRequestCount);
    }

    [Fact]
    public async Task ReadAsync_ReturnsLimitError_BeforeReadingFilesAboveTotalLimit()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            TreeResult = SuccessTree(
                new GitHubRepositoryTreeEntry("first.json", "blob", 60),
                new GitHubRepositoryTreeEntry("second.json", "blob", 60))
        };
        var service = new RepositoryIngestionService(client, new RepositoryIngestionOptions
        {
            MaximumTreeEntries = 10,
            MaximumCandidateFiles = 10,
            MaximumFileBytes = 100,
            MaximumTotalBytes = 100,
            AnalysisTimeout = TimeSpan.FromSeconds(1)
        });

        var result = await service.ReadAsync(Repository);

        Assert.Equal(ApiErrorCodes.ResourceLimitExceeded, result.Error?.Code);
        Assert.Equal(0, client.FileContentRequestCount);
    }

    [Fact]
    public async Task ReadAsync_ReturnsLimitError_ForTruncatedTree()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            TreeResult = GitHubApiResult<GitHubRepositoryTree>.Success(
                new GitHubRepositoryTree(true, Array.Empty<GitHubRepositoryTreeEntry>()))
        };
        var service = new RepositoryIngestionService(client);

        var result = await service.ReadAsync(Repository);

        Assert.Equal(ApiErrorCodes.ResourceLimitExceeded, result.Error?.Code);
        Assert.Equal(0, client.FileContentRequestCount);
    }

    [Fact]
    public async Task ReadAsync_SkipsSymbolicLinksWithoutFetchingTheirTarget()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            TreeResult = SuccessTree(
                new GitHubRepositoryTreeEntry("config/mcp.json", "blob", 18),
                new GitHubRepositoryTreeEntry("linked-secret", "blob", 12, "120000"))
        };
        client.FileResults["config/mcp.json"] = SuccessContent("{\"name\":\"mcp\"}");
        var service = new RepositoryIngestionService(client);

        var result = await service.ReadAsync(Repository);

        Assert.True(result.IsSuccess);
        Assert.Single(result.ContentSet!.Files);
        Assert.Equal(1, client.FileContentRequestCount);
    }

    [Fact]
    public async Task ReadAsync_PreservesRateLimitErrorFromGitHubClient()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            MetadataResult = GitHubApiResult<GitHubRepositoryMetadata>.Failure(
                new ApiErrorResponse(ApiErrorCodes.GitHubRateLimited, "GitHub rate limit was reached.", 60))
        };
        var service = new RepositoryIngestionService(client);

        var result = await service.ReadAsync(Repository);

        Assert.Equal(ApiErrorCodes.GitHubRateLimited, result.Error?.Code);
        Assert.Equal(60, result.Error?.RetryAfterSeconds);
    }

    [Fact]
    public async Task ReadAsync_ReturnsTimeoutError_WhenGitHubClientExceedsDeadline()
    {
        var client = new FakeGitHubRepositoryApiClient
        {
            MetadataHandler = async cancellationToken =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return GitHubApiResult<GitHubRepositoryMetadata>.Success(new GitHubRepositoryMetadata("main"));
            }
        };
        var service = new RepositoryIngestionService(client, new RepositoryIngestionOptions
        {
            MaximumTreeEntries = 10,
            MaximumCandidateFiles = 10,
            MaximumFileBytes = 100,
            MaximumTotalBytes = 100,
            AnalysisTimeout = TimeSpan.FromMilliseconds(50)
        });

        var result = await service.ReadAsync(Repository);

        Assert.Equal(ApiErrorCodes.AnalysisTimeout, result.Error?.Code);
    }

    private static GitHubApiResult<GitHubRepositoryTree> SuccessTree(params GitHubRepositoryTreeEntry[] entries) =>
        GitHubApiResult<GitHubRepositoryTree>.Success(new GitHubRepositoryTree(false, entries));

    private static GitHubApiResult<GitHubRepositoryFileContent> SuccessContent(string content) =>
        GitHubApiResult<GitHubRepositoryFileContent>.Success(
            new GitHubRepositoryFileContent(Encoding.UTF8.GetBytes(content)));

    private sealed class FakeGitHubRepositoryApiClient : IGitHubRepositoryApiClient
    {
        public GitHubApiResult<GitHubRepositoryMetadata> MetadataResult { get; init; } =
            GitHubApiResult<GitHubRepositoryMetadata>.Success(new GitHubRepositoryMetadata("main"));

        public GitHubApiResult<GitHubRepositoryTree> TreeResult { get; init; } =
            GitHubApiResult<GitHubRepositoryTree>.Success(
                new GitHubRepositoryTree(false, Array.Empty<GitHubRepositoryTreeEntry>()));

        public Dictionary<string, GitHubApiResult<GitHubRepositoryFileContent>> FileResults { get; } = new(StringComparer.Ordinal);

        public Func<CancellationToken, Task<GitHubApiResult<GitHubRepositoryMetadata>>>? MetadataHandler { get; init; }

        public int FileContentRequestCount { get; private set; }

        public Task<GitHubApiResult<GitHubRepositoryMetadata>> GetMetadataAsync(
            GitHubRepositoryReference repository,
            CancellationToken cancellationToken) =>
            MetadataHandler is null ? Task.FromResult(MetadataResult) : MetadataHandler(cancellationToken);

        public Task<GitHubApiResult<GitHubRepositoryTree>> GetTreeAsync(
            GitHubRepositoryReference repository,
            string reference,
            CancellationToken cancellationToken) =>
            Task.FromResult(TreeResult);

        public Task<GitHubApiResult<GitHubRepositoryFileContent>> GetFileContentAsync(
            GitHubRepositoryReference repository,
            string path,
            string reference,
            int maximumFileBytes,
            CancellationToken cancellationToken)
        {
            FileContentRequestCount++;

            return Task.FromResult(FileResults.TryGetValue(path, out var result)
                ? result
                : GitHubApiResult<GitHubRepositoryFileContent>.Failure(RepositoryIngestionErrors.AnalysisFailed()));
        }
    }
}
