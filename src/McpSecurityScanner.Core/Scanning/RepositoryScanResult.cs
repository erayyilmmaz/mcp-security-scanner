using McpSecurityScanner.Core.Contracts;
using McpSecurityScanner.Core.Detection;
using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Core.Rules;

namespace McpSecurityScanner.Core.Scanning;

public sealed record RepositoryScanResult(
    GitHubRepositoryReference? Repository,
    McpDetectionResult? Detection,
    SecurityReport? Report,
    ApiErrorResponse? Error)
{
    public bool IsSuccess => Repository is not null && Detection is not null && Report is not null && Error is null;

    public static RepositoryScanResult Success(
        GitHubRepositoryReference repository,
        McpDetectionResult detection,
        SecurityReport report) =>
        new(repository, detection, report, null);

    public static RepositoryScanResult Failure(ApiErrorResponse error) =>
        new(null, null, null, error);
}
