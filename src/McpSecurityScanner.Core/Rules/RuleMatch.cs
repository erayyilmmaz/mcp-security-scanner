namespace McpSecurityScanner.Core.Rules;

public sealed record RuleMatch(
    string FilePath,
    int? Line,
    int? Column,
    string Evidence);
