namespace McpSecurityScanner.Core.Contracts;

public static class ApiErrorCodes
{
    public const string InvalidRepositoryUrl = "INVALID_REPOSITORY_URL";
    public const string RepositoryNotPublicOrNotFound = "REPOSITORY_NOT_PUBLIC_OR_NOT_FOUND";
    public const string GitHubRateLimited = "GITHUB_RATE_LIMITED";
    public const string GitHubUnavailable = "GITHUB_UNAVAILABLE";
    public const string ResourceLimitExceeded = "RESOURCE_LIMIT_EXCEEDED";
    public const string AnalysisTimeout = "ANALYSIS_TIMEOUT";
    public const string AnalysisFailed = "ANALYSIS_FAILED";
}
