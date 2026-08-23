using System.Text.RegularExpressions;

namespace McpSecurityScanner.Core.Rules;

public sealed partial class EvidenceRedactor
{
    public string Redact(string evidence)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(evidence);

        var redacted = LabeledSecret().Replace(
            evidence,
            match => $"{match.Groups["label"].Value}[REDACTED]");
        redacted = BearerToken().Replace(
            redacted,
            match => $"{match.Groups["prefix"].Value}[REDACTED]");

        return StandaloneSecret().Replace(redacted, "[REDACTED]");
    }

    [GeneratedRegex(
        """(?<label>\b(?:api[_-]?key|token|secret|password|client[_-]?secret)\b\s*[:=]\s*)(?<value>"[^"]*"|'[^']*'|[^\s,;]+)""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LabeledSecret();

    [GeneratedRegex(
        @"(?<prefix>\bAuthorization\s*:\s*Bearer\s+)(?<value>[^\s,;]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BearerToken();

    [GeneratedRegex(
        @"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex StandaloneSecret();
}
