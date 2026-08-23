using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using McpSecurityScanner.Core.Contracts;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Infrastructure.GitHub;

public sealed class GitHubRestApiClient : IGitHubRepositoryApiClient
{
    private const string GitHubApiHost = "api.github.com";
    private const int MaximumMetadataResponseBytes = 128 * 1024;
    private const int MaximumTreeResponseBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;

    public GitHubRestApiClient(HttpClient httpClient)
    {
        if (httpClient.BaseAddress is null ||
            !string.Equals(httpClient.BaseAddress.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            !string.Equals(httpClient.BaseAddress.Host, GitHubApiHost, StringComparison.Ordinal) ||
            httpClient.BaseAddress.Port != 443 ||
            !string.Equals(httpClient.BaseAddress.AbsolutePath, "/", StringComparison.Ordinal))
        {
            throw new ArgumentException("GitHub REST client must use the fixed https://api.github.com/ base address.", nameof(httpClient));
        }

        _httpClient = httpClient;
        EnsureRequiredHeaders();
    }

    public async Task<GitHubApiResult<GitHubRepositoryMetadata>> GetMetadataAsync(
        GitHubRepositoryReference repository,
        CancellationToken cancellationToken)
    {
        var responseResult = await SendAsync($"repos/{Escape(repository.Owner)}/{Escape(repository.Name)}", cancellationToken);
        if (!responseResult.IsSuccess)
        {
            return GitHubApiResult<GitHubRepositoryMetadata>.Failure(responseResult.Error!);
        }

        using var response = responseResult.Value!;

        try
        {
            var metadata = await ReadJsonAsync<RepositoryMetadataResponse>(
                response.Content,
                MaximumMetadataResponseBytes,
                cancellationToken);

            return string.IsNullOrWhiteSpace(metadata?.DefaultBranch)
                ? GitHubApiResult<GitHubRepositoryMetadata>.Failure(RepositoryIngestionErrors.AnalysisFailed())
                : GitHubApiResult<GitHubRepositoryMetadata>.Success(new GitHubRepositoryMetadata(metadata.DefaultBranch));
        }
        catch (ResponseSizeLimitExceededException)
        {
            return GitHubApiResult<GitHubRepositoryMetadata>.Failure(RepositoryIngestionErrors.ResourceLimitExceeded());
        }
        catch (JsonException)
        {
            return GitHubApiResult<GitHubRepositoryMetadata>.Failure(RepositoryIngestionErrors.AnalysisFailed());
        }
    }

    public async Task<GitHubApiResult<GitHubRepositoryTree>> GetTreeAsync(
        GitHubRepositoryReference repository,
        string reference,
        CancellationToken cancellationToken)
    {
        var route = $"repos/{Escape(repository.Owner)}/{Escape(repository.Name)}/git/trees/{Escape(reference)}?recursive=1";
        var responseResult = await SendAsync(route, cancellationToken);
        if (!responseResult.IsSuccess)
        {
            return GitHubApiResult<GitHubRepositoryTree>.Failure(responseResult.Error!);
        }

        using var response = responseResult.Value!;

        try
        {
            var tree = await ReadJsonAsync<RepositoryTreeResponse>(
                response.Content,
                MaximumTreeResponseBytes,
                cancellationToken);
            if (tree?.Entries is null)
            {
                return GitHubApiResult<GitHubRepositoryTree>.Failure(RepositoryIngestionErrors.AnalysisFailed());
            }

            var entries = tree.Entries
                .Where(entry => !string.IsNullOrWhiteSpace(entry.Path) && !string.IsNullOrWhiteSpace(entry.Type))
                .Select(entry => new GitHubRepositoryTreeEntry(entry.Path!, entry.Type!, entry.Size, entry.Mode))
                .ToArray();

            return GitHubApiResult<GitHubRepositoryTree>.Success(new GitHubRepositoryTree(tree.Truncated, entries));
        }
        catch (ResponseSizeLimitExceededException)
        {
            return GitHubApiResult<GitHubRepositoryTree>.Failure(RepositoryIngestionErrors.ResourceLimitExceeded());
        }
        catch (JsonException)
        {
            return GitHubApiResult<GitHubRepositoryTree>.Failure(RepositoryIngestionErrors.AnalysisFailed());
        }
    }

    public async Task<GitHubApiResult<GitHubRepositoryFileContent>> GetFileContentAsync(
        GitHubRepositoryReference repository,
        string path,
        string reference,
        int maximumFileBytes,
        CancellationToken cancellationToken)
    {
        var escapedPath = string.Join('/', path.Split('/').Select(Escape));
        var route = $"repos/{Escape(repository.Owner)}/{Escape(repository.Name)}/contents/{escapedPath}?ref={Escape(reference)}";
        var responseResult = await SendAsync(route, cancellationToken);
        if (!responseResult.IsSuccess)
        {
            return GitHubApiResult<GitHubRepositoryFileContent>.Failure(responseResult.Error!);
        }

        using var response = responseResult.Value!;

        try
        {
            var content = await ReadJsonAsync<RepositoryContentResponse>(
                response.Content,
                GetMaximumContentResponseBytes(maximumFileBytes),
                cancellationToken);
            if (content is null ||
                !string.Equals(content.Encoding, "base64", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrEmpty(content.Content))
            {
                return GitHubApiResult<GitHubRepositoryFileContent>.Failure(RepositoryIngestionErrors.AnalysisFailed());
            }

            var bytes = Convert.FromBase64String(content.Content.Replace("\n", string.Empty, StringComparison.Ordinal));
            return bytes.Length > maximumFileBytes
                ? GitHubApiResult<GitHubRepositoryFileContent>.Failure(RepositoryIngestionErrors.ResourceLimitExceeded())
                : GitHubApiResult<GitHubRepositoryFileContent>.Success(new GitHubRepositoryFileContent(bytes));
        }
        catch (ResponseSizeLimitExceededException)
        {
            return GitHubApiResult<GitHubRepositoryFileContent>.Failure(RepositoryIngestionErrors.ResourceLimitExceeded());
        }
        catch (FormatException)
        {
            return GitHubApiResult<GitHubRepositoryFileContent>.Failure(RepositoryIngestionErrors.AnalysisFailed());
        }
        catch (JsonException)
        {
            return GitHubApiResult<GitHubRepositoryFileContent>.Failure(RepositoryIngestionErrors.AnalysisFailed());
        }
    }

    private async Task<GitHubApiResult<HttpResponseMessage>> SendAsync(string relativeRoute, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, relativeRoute);
            var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                return GitHubApiResult<HttpResponseMessage>.Success(response);
            }

            var error = MapError(response);
            response.Dispose();
            return GitHubApiResult<HttpResponseMessage>.Failure(error);
        }
        catch (HttpRequestException)
        {
            return GitHubApiResult<HttpResponseMessage>.Failure(
                new ApiErrorResponse(
                    ApiErrorCodes.GitHubUnavailable,
                    "GitHub could not be reached. Please retry the scan later."));
        }
    }

    private static ApiErrorResponse MapError(HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new ApiErrorResponse(
                ApiErrorCodes.RepositoryNotPublicOrNotFound,
                "The repository does not exist or is not publicly accessible.");
        }

        var retryAfterSeconds = GetRetryAfterSeconds(response.Headers);
        var rateLimitRemainingIsZero = response.Headers.TryGetValues("X-RateLimit-Remaining", out var remainingValues) &&
            remainingValues.Any(value => string.Equals(value, "0", StringComparison.Ordinal));

        if (response.StatusCode == HttpStatusCode.TooManyRequests ||
            (response.StatusCode == HttpStatusCode.Forbidden && (rateLimitRemainingIsZero || retryAfterSeconds.HasValue)))
        {
            return new ApiErrorResponse(
                ApiErrorCodes.GitHubRateLimited,
                "GitHub rate limit was reached. Please retry later.",
                retryAfterSeconds);
        }

        return new ApiErrorResponse(
            ApiErrorCodes.GitHubUnavailable,
            "GitHub could not complete the repository request. Please retry later.");
    }

    private static int? GetRetryAfterSeconds(HttpResponseHeaders headers)
    {
        if (headers.RetryAfter?.Delta is { } retryAfter && retryAfter > TimeSpan.Zero)
        {
            return (int)Math.Ceiling(retryAfter.TotalSeconds);
        }

        if (headers.TryGetValues("X-RateLimit-Reset", out var resetValues) &&
            long.TryParse(resetValues.FirstOrDefault(), out var resetUnixSeconds))
        {
            var resetDelay = DateTimeOffset.FromUnixTimeSeconds(resetUnixSeconds) - DateTimeOffset.UtcNow;
            return resetDelay > TimeSpan.Zero ? (int)Math.Ceiling(resetDelay.TotalSeconds) : 0;
        }

        return null;
    }

    private static async Task<T?> ReadJsonAsync<T>(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadBytesLimitedAsync(content, maximumBytes, cancellationToken);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions);
    }

    private static async Task<byte[]> ReadBytesLimitedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is { } contentLength && contentLength > maximumBytes)
        {
            throw new ResponseSizeLimitExceededException();
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        await using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        var totalBytes = 0;

        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0)
            {
                break;
            }

            totalBytes += read;
            if (totalBytes > maximumBytes)
            {
                throw new ResponseSizeLimitExceededException();
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }

        return buffer.ToArray();
    }

    private static int GetMaximumContentResponseBytes(int maximumFileBytes) =>
        checked(Math.Max(maximumFileBytes * 2, maximumFileBytes + 64 * 1024));

    private static string Escape(string value) => Uri.EscapeDataString(value);

    private void EnsureRequiredHeaders()
    {
        if (!_httpClient.DefaultRequestHeaders.Accept.Any(header =>
                string.Equals(header.MediaType, "application/vnd.github+json", StringComparison.OrdinalIgnoreCase)))
        {
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        }

        if (!_httpClient.DefaultRequestHeaders.UserAgent.Any())
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("McpSecurityScanner/1.0");
        }

        if (!_httpClient.DefaultRequestHeaders.Contains("X-GitHub-Api-Version"))
        {
            _httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2026-03-10");
        }
    }

    private sealed class ResponseSizeLimitExceededException : Exception
    {
    }

    private sealed record RepositoryMetadataResponse(
        [property: JsonPropertyName("default_branch")] string? DefaultBranch);

    private sealed record RepositoryTreeResponse(
        [property: JsonPropertyName("truncated")] bool Truncated,
        [property: JsonPropertyName("tree")] IReadOnlyList<RepositoryTreeEntryResponse>? Entries);

    private sealed record RepositoryTreeEntryResponse(
        [property: JsonPropertyName("path")] string? Path,
        [property: JsonPropertyName("type")] string? Type,
        [property: JsonPropertyName("size")] long? Size,
        [property: JsonPropertyName("mode")] string? Mode);

    private sealed record RepositoryContentResponse(
        [property: JsonPropertyName("content")] string? Content,
        [property: JsonPropertyName("encoding")] string? Encoding);
}
