namespace McpSecurityScanner.Core.Detection;

public sealed record McpDetectionSignal(
    string Id,
    int Priority,
    string Title,
    DetectionConfidence Confidence,
    string Description);
