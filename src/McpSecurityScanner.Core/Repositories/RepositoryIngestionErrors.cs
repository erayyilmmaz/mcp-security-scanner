using McpSecurityScanner.Core.Contracts;

namespace McpSecurityScanner.Core.Repositories;

public static class RepositoryIngestionErrors
{
    public static ApiErrorResponse ResourceLimitExceeded() =>
        new(
            ApiErrorCodes.ResourceLimitExceeded,
            "The repository exceeds the scanner's configured processing limits.");

    public static ApiErrorResponse AnalysisTimeout() =>
        new(
            ApiErrorCodes.AnalysisTimeout,
            "Repository analysis exceeded the configured time limit.");

    public static ApiErrorResponse AnalysisFailed() =>
        new(
            ApiErrorCodes.AnalysisFailed,
            "Repository analysis could not be completed safely.");
}
