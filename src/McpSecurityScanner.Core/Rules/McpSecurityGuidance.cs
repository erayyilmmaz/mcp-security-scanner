namespace McpSecurityScanner.Core.Rules;

internal static class McpSecurityGuidance
{
    public static readonly SecurityReference Reference = new(
        $"MCP Security Best Practices ({McpSpecificationReferences.Version})",
        McpSpecificationReferences.SecurityBestPracticesUrl);
}
