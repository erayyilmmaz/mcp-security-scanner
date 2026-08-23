using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using McpSecurityScanner.Api.Contracts;
using McpSecurityScanner.Core.Contracts;
using McpSecurityScanner.Core.Repositories;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace McpSecurityScanner.Tests;

public sealed class ScanApiIntegrationTests
{
    [Fact]
    public async Task Root_ServesMinimalScanUi()
    {
        using var factory = new ScanApiFactory(FakeGitHubRepositoryApiClient.WithFiles(new Dictionary<string, string>()));
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Scan a repository", html, StringComparison.Ordinal);
        Assert.Contains("/app.js", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_ReturnsMcpEvidenceSeverityCountsFindingsAndNoRawSecret()
    {
        var gitHubClient = FakeGitHubRepositoryApiClient.WithFiles(new Dictionary<string, string>
        {
            ["mcp.json"] = """
                {
                  "mcpServers": {},
                  "remoteEndpoint": "http://api.example.com/mcp",
                  "apiKey": "actual-super-secret-value",
                  "scope": "admin",
                  "authorizationUrl": "javascript:alert(1)"
                }
                """
        });
        using var factory = new ScanApiFactory(gitHubClient);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/scans",
            new ScanRequest("https://github.com/openai/example-mcp"));
        var payload = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(payload);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("actual-super-secret-value", payload, StringComparison.Ordinal);
        Assert.Equal("mcp_related", json.RootElement.GetProperty("mcp").GetProperty("classification").GetString());
        Assert.Equal("MCP-CONFIG-001", json.RootElement.GetProperty("mcp").GetProperty("evidence")[0].GetProperty("signalId").GetString());
        Assert.Equal(2, json.RootElement.GetProperty("report").GetProperty("summary").GetProperty("high").GetInt32());
        Assert.Equal(2, json.RootElement.GetProperty("report").GetProperty("summary").GetProperty("medium").GetInt32());
        Assert.Contains("MCP-SEC-001", payload, StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", payload, StringComparison.Ordinal);
        Assert.Equal(1, gitHubClient.MetadataRequestCount);
        Assert.Equal(1, gitHubClient.TreeRequestCount);
        Assert.Equal(1, gitHubClient.FileContentRequestCount);
    }

    [Fact]
    public async Task Scan_ReturnsValidationErrorWithoutCallingGitHub()
    {
        var gitHubClient = FakeGitHubRepositoryApiClient.WithFiles(new Dictionary<string, string>());
        using var factory = new ScanApiFactory(gitHubClient);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/scans",
            new ScanRequest("https://127.0.0.1/openai/example-mcp"));
        var error = await response.Content.ReadFromJsonAsync<ApiErrorResponse>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ApiErrorCodes.InvalidRepositoryUrl, error?.Code);
        Assert.Equal(0, gitHubClient.MetadataRequestCount);
    }

    [Fact]
    public async Task Scan_MapsGitHubRateLimitToSafeResponse()
    {
        var gitHubClient = FakeGitHubRepositoryApiClient.RateLimited();
        using var factory = new ScanApiFactory(gitHubClient);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/scans",
            new ScanRequest("https://github.com/openai/example-mcp"));
        var payload = await response.Content.ReadAsStringAsync();
        var error = JsonSerializer.Deserialize<ApiErrorResponse>(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal(ApiErrorCodes.GitHubRateLimited, error?.Code);
        Assert.Equal(60, error?.RetryAfterSeconds);
        Assert.DoesNotContain("upstream-secret", payload, StringComparison.Ordinal);
    }

    private sealed class ScanApiFactory(FakeGitHubRepositoryApiClient gitHubClient) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IGitHubRepositoryApiClient>();
                services.AddSingleton<IGitHubRepositoryApiClient>(gitHubClient);
            });
        }
    }

    private sealed class FakeGitHubRepositoryApiClient : IGitHubRepositoryApiClient
    {
        private readonly GitHubApiResult<GitHubRepositoryMetadata> _metadataResult;
        private readonly Dictionary<string, GitHubApiResult<GitHubRepositoryFileContent>> _files;

        private FakeGitHubRepositoryApiClient(
            GitHubApiResult<GitHubRepositoryMetadata> metadataResult,
            Dictionary<string, GitHubApiResult<GitHubRepositoryFileContent>> files)
        {
            _metadataResult = metadataResult;
            _files = files;
        }

        public int MetadataRequestCount { get; private set; }

        public int TreeRequestCount { get; private set; }

        public int FileContentRequestCount { get; private set; }

        public static FakeGitHubRepositoryApiClient WithFiles(IReadOnlyDictionary<string, string> files) =>
            new(
                GitHubApiResult<GitHubRepositoryMetadata>.Success(new GitHubRepositoryMetadata("main")),
                files.ToDictionary(
                    pair => pair.Key,
                    pair => GitHubApiResult<GitHubRepositoryFileContent>.Success(
                        new GitHubRepositoryFileContent(Encoding.UTF8.GetBytes(pair.Value))),
                    StringComparer.Ordinal));

        public static FakeGitHubRepositoryApiClient RateLimited() =>
            new(
                GitHubApiResult<GitHubRepositoryMetadata>.Failure(
                    new ApiErrorResponse(ApiErrorCodes.GitHubRateLimited, "GitHub rate limit was reached.", 60)),
                new(StringComparer.Ordinal));

        public Task<GitHubApiResult<GitHubRepositoryMetadata>> GetMetadataAsync(
            GitHubRepositoryReference repository,
            CancellationToken cancellationToken)
        {
            MetadataRequestCount++;
            return Task.FromResult(_metadataResult);
        }

        public Task<GitHubApiResult<GitHubRepositoryTree>> GetTreeAsync(
            GitHubRepositoryReference repository,
            string reference,
            CancellationToken cancellationToken)
        {
            TreeRequestCount++;
            var entries = _files
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new GitHubRepositoryTreeEntry(pair.Key, "blob", pair.Value.Value?.Bytes.Length ?? 0))
                .ToArray();
            return Task.FromResult(GitHubApiResult<GitHubRepositoryTree>.Success(new GitHubRepositoryTree(false, entries)));
        }

        public Task<GitHubApiResult<GitHubRepositoryFileContent>> GetFileContentAsync(
            GitHubRepositoryReference repository,
            string path,
            string reference,
            int maximumFileBytes,
            CancellationToken cancellationToken)
        {
            FileContentRequestCount++;
            return Task.FromResult(_files.TryGetValue(path, out var content)
                ? content
                : GitHubApiResult<GitHubRepositoryFileContent>.Failure(RepositoryIngestionErrors.AnalysisFailed()));
        }
    }
}
