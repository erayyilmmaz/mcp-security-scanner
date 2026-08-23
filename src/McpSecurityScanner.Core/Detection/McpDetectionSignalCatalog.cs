namespace McpSecurityScanner.Core.Detection;

public static class McpDetectionSignalCatalog
{
    public static McpDetectionSignal Configuration { get; } = new(
        "MCP-CONFIG-001",
        10,
        "MCP server configuration",
        DetectionConfidence.High,
        "A JSON configuration contains the mcpServers structure.");

    public static McpDetectionSignal SdkDependency { get; } = new(
        "MCP-SDK-001",
        20,
        "MCP SDK dependency",
        DetectionConfidence.High,
        "A supported package manifest names an MCP SDK dependency.");

    public static McpDetectionSignal ServerDeclaration { get; } = new(
        "MCP-SERVER-001",
        30,
        "MCP server declaration",
        DetectionConfidence.High,
        "Source code contains a specific MCP server import, declaration, or tool attribute.");

    public static IReadOnlyList<McpDetectionSignal> All { get; } =
        new[] { Configuration, SdkDependency, ServerDeclaration };
}
