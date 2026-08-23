using McpSecurityScanner.Core.Contracts;

namespace McpSecurityScanner.Core.Repositories;

public sealed record RepositoryUrlValidationResult(
    GitHubRepositoryReference? Repository,
    ApiErrorResponse? Error)
{
    public bool IsValid => Repository is not null && Error is null;

    public static RepositoryUrlValidationResult Valid(GitHubRepositoryReference repository) =>
        new(repository, null);

    public static RepositoryUrlValidationResult Invalid(ApiErrorResponse error) =>
        new(null, error);
}
