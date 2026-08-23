namespace McpSecurityScanner.Core.Detection;

public sealed record McpDetectionEvidence(
    string SignalId,
    string Title,
    string FilePath,
    int? Line,
    string Evidence,
    DetectionConfidence Confidence);
