namespace McpSecurityScanner.Core.Contracts;

public sealed record ApiErrorResponse(
    string Code,
    string Message,
    int? RetryAfterSeconds = null);
