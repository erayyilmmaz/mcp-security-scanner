using System.Net;
using System.Text;
using McpSecurityScanner.Core.Contracts;
using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Infrastructure.GitHub;

namespace McpSecurityScanner.Tests;

public sealed class GitHubRestApiClientTests
{
    private static readonly GitHubRepositoryReference Repository = new("openai", "example-mcp");

    [Fact]
    public void SecureHttpContract_UsesFixedGitHubApiBaseAddressAndDisablesRedirects()
    {
        Assert.Equal(new Uri("https://api.github.com/"), GitHubRestApiClient.GitHubApiBaseAddress);

        using var handler = GitHubRestApiClient.CreateSecureMessageHandler();

        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public async Task GetMetadataAsync_UsesFixedRepositoryRoute_AndReadsDefaultBranch()
    {
        HttpRequestMessage? capturedRequest = null;
        using var httpClient = CreateHttpClient(request =>
        {
            capturedRequest = request;
            return JsonResponse("{\"default_branch\":\"main\"}");
        });
        var client = new GitHubRestApiClient(httpClient);

        var result = await client.GetMetadataAsync(Repository, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("main", result.Value?.DefaultBranch);
        Assert.Equal("/repos/openai/example-mcp", capturedRequest?.RequestUri?.AbsolutePath);
        Assert.Contains(capturedRequest!.Headers.Accept, header => header.MediaType == "application/vnd.github+json");
        Assert.Contains(capturedRequest.Headers.UserAgent, header => header.Product?.Name == "McpSecurityScanner");
        Assert.Equal("2026-03-10", capturedRequest.Headers.GetValues("X-GitHub-Api-Version").Single());
    }

    [Fact]
    public async Task GetTreeAsync_MapsNotFoundToAmbiguousPublicAccessError()
    {
        using var httpClient = CreateHttpClient(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var client = new GitHubRestApiClient(httpClient);

        var result = await client.GetTreeAsync(Repository, "main", CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApiErrorCodes.RepositoryNotPublicOrNotFound, result.Error?.Code);
    }

    [Fact]
    public async Task GetFileContentAsync_MapsRateLimitHeadersAndDoesNotExposeBody()
    {
        using var httpClient = CreateHttpClient(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent("sensitive response body")
            };
            response.Headers.Add("X-RateLimit-Remaining", "0");
            response.Headers.Add("Retry-After", "30");
            return response;
        });
        var client = new GitHubRestApiClient(httpClient);

        var result = await client.GetFileContentAsync(Repository, "config/mcp.json", "main", 512, CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApiErrorCodes.GitHubRateLimited, result.Error?.Code);
        Assert.Equal(30, result.Error?.RetryAfterSeconds);
        Assert.DoesNotContain("sensitive", result.Error?.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetFileContentAsync_DecodesBase64ContentWithinLimit()
    {
        var encodedContent = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"server\":\"mcp\"}"));
        using var httpClient = CreateHttpClient(_ =>
            JsonResponse($"{{\"content\":\"{encodedContent}\",\"encoding\":\"base64\"}}"));
        var client = new GitHubRestApiClient(httpClient);

        var result = await client.GetFileContentAsync(Repository, "config/mcp.json", "main", 512, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("{\"server\":\"mcp\"}", Encoding.UTF8.GetString(result.Value!.Bytes));
    }

    [Fact]
    public void Constructor_RejectsAnyNonGitHubApiBaseAddress()
    {
        using var httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://example.com/")
        };

        Assert.Throws<ArgumentException>(() => new GitHubRestApiClient(httpClient));
    }

    private static HttpClient CreateHttpClient(Func<HttpRequestMessage, HttpResponseMessage> responder) =>
        new(new StubHttpMessageHandler(responder))
        {
            BaseAddress = GitHubRestApiClient.GitHubApiBaseAddress
        };

    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(_responder(request));
    }
}
