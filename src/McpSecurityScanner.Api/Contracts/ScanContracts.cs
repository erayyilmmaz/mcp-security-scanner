using McpSecurityScanner.Core.Detection;
using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Core.Rules;

namespace McpSecurityScanner.Api.Contracts;

public sealed record ScanRequest(string? RepositoryUrl);

public sealed record ScanResponse(
    GitHubRepositoryReference Repository,
    McpDetectionResult Mcp,
    SecurityReport Report);
