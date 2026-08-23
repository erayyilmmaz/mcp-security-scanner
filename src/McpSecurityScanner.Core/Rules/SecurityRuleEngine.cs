using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Core.Rules;

public sealed class SecurityRuleEngine
{
    private readonly IReadOnlyList<ISecurityRule> _rules;
    private readonly EvidenceRedactor _redactor;

    public SecurityRuleEngine(
        IEnumerable<ISecurityRule> rules,
        string ruleSetVersion,
        EvidenceRedactor? redactor = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleSetVersion);

        var materializedRules = rules.ToArray();
        if (materializedRules.Any(rule => rule is null))
        {
            throw new ArgumentException("Rule collection cannot contain null entries.", nameof(rules));
        }

        var duplicateRuleId = materializedRules
            .GroupBy(rule => rule.Definition.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateRuleId is not null)
        {
            throw new ArgumentException($"Duplicate rule ID: {duplicateRuleId.Key}", nameof(rules));
        }

        _rules = materializedRules
            .OrderBy(rule => rule.Definition.Id, StringComparer.Ordinal)
            .ToArray();
        RuleSetVersion = ruleSetVersion;
        _redactor = redactor ?? new EvidenceRedactor();
    }

    public string RuleSetVersion { get; }

    public SecurityReport Analyze(RepositoryContentSet contentSet)
    {
        ArgumentNullException.ThrowIfNull(contentSet);

        var findings = new List<SecurityFinding>();

        foreach (var rule in _rules)
        {
            var definition = rule.Definition;
            ValidateDefinition(definition);

            var matches = (rule.Evaluate(contentSet) ?? Enumerable.Empty<RuleMatch>()).ToArray();
            foreach (var match in matches)
            {
                ValidateMatch(match, definition.Id);
            }

            foreach (var match in matches
                .OrderBy(match => match.FilePath, StringComparer.Ordinal)
                .ThenBy(match => match.Line ?? int.MaxValue)
                .ThenBy(match => match.Column ?? int.MaxValue)
                .ThenBy(match => match.Evidence, StringComparer.Ordinal))
            {
                findings.Add(new SecurityFinding(
                    definition.Id,
                    definition.Category,
                    definition.Severity,
                    definition.Title,
                    definition.Description,
                    _redactor.Redact(match.Evidence),
                    match.FilePath,
                    match.Line,
                    match.Column,
                    definition.WhyItMatters,
                    definition.Remediation,
                    definition.Confidence,
                    definition.Reference));
            }
        }

        var orderedFindings = findings
            .OrderBy(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId, StringComparer.Ordinal)
            .ThenBy(finding => finding.FilePath, StringComparer.Ordinal)
            .ThenBy(finding => finding.Line ?? int.MaxValue)
            .ThenBy(finding => finding.Column ?? int.MaxValue)
            .ThenBy(finding => finding.Evidence, StringComparer.Ordinal)
            .ToArray();

        return new SecurityReport(
            RuleSetVersion,
            orderedFindings,
            ReportSummary.FromFindings(orderedFindings));
    }

    private static void ValidateDefinition(SecurityRuleDefinition definition)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.Id);
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.Category);
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.Title);
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.Description);
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.WhyItMatters);
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.Remediation);
        ArgumentNullException.ThrowIfNull(definition.Reference);
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.Reference.Title);
        ArgumentException.ThrowIfNullOrWhiteSpace(definition.Reference.Url);
    }

    private static void ValidateMatch(RuleMatch match, string ruleId)
    {
        ArgumentNullException.ThrowIfNull(match);
        ArgumentException.ThrowIfNullOrWhiteSpace(match.FilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(match.Evidence);

        if (match.Line is <= 0 || match.Column is <= 0)
        {
            throw new ArgumentException($"Rule {ruleId} returned an invalid source location.", nameof(match));
        }
    }
}
