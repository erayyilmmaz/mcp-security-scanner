namespace McpSecurityScanner.Core.Detection;

public sealed record McpDetectionResult(
    McpRepositoryClassification Classification,
    IReadOnlyList<McpDetectionEvidence> Evidence)
{
    public bool IsMcpRelated => Classification == McpRepositoryClassification.McpRelated;
}
