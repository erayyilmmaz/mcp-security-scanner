namespace McpSecurityScanner.Core.Rules;

internal static class McpAuthorizationGuidance
{
    public static readonly SecurityReference Reference = new(
        $"MCP Authorization Specification ({McpSpecificationReferences.Version})",
        McpSpecificationReferences.AuthorizationSpecificationUrl);
}
