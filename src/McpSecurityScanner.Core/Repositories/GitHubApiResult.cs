using McpSecurityScanner.Core.Contracts;

namespace McpSecurityScanner.Core.Repositories;

public sealed record GitHubApiResult<T>(T? Value, ApiErrorResponse? Error)
{
    public bool IsSuccess => Value is not null && Error is null;

    public static GitHubApiResult<T> Success(T value) => new(value, null);

    public static GitHubApiResult<T> Failure(ApiErrorResponse error) => new(default, error);
}
