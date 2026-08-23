using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public interface ISecurityRule
{
    SecurityRuleDefinition Definition { get; }

    IEnumerable<RuleMatch> Evaluate(RepositoryContentSet contentSet);
}
