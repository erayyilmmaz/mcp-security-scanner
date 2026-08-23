using System.Text.RegularExpressions;
using McpSecurityScanner.Core.Contracts;

namespace McpSecurityScanner.Core.Repositories;

public sealed partial class GitHubRepositoryUrlValidator
{
    public const int MaximumUrlLength = 2048;

    private const string InvalidUrlMessage =
        "Enter a public GitHub repository URL in the form https://github.com/{owner}/{repository}.";

    public RepositoryUrlValidationResult Validate(string? repositoryUrl)
    {
        if (string.IsNullOrEmpty(repositoryUrl) ||
            repositoryUrl.Length > MaximumUrlLength ||
            repositoryUrl.Any(char.IsWhiteSpace) ||
            !repositoryUrl.StartsWith("https://github.com/", StringComparison.Ordinal) ||
            !Uri.TryCreate(repositoryUrl, UriKind.Absolute, out var uri))
        {
            return Invalid();
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            !string.Equals(uri.Host, "github.com", StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath.Contains("//", StringComparison.Ordinal))
        {
            return Invalid();
        }

        var path = uri.AbsolutePath.TrimEnd('/');
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length != 2)
        {
            return Invalid();
        }

        var owner = segments[0];
        var repository = segments[1];

        if (!OwnerName().IsMatch(owner) ||
            !RepositoryName().IsMatch(repository) ||
            repository.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
        {
            return Invalid();
        }

        return RepositoryUrlValidationResult.Valid(new GitHubRepositoryReference(owner, repository));
    }

    private static RepositoryUrlValidationResult Invalid() =>
        RepositoryUrlValidationResult.Invalid(
            new ApiErrorResponse(ApiErrorCodes.InvalidRepositoryUrl, InvalidUrlMessage));

    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$", RegexOptions.CultureInvariant)]
    private static partial Regex OwnerName();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", RegexOptions.CultureInvariant)]
    private static partial Regex RepositoryName();
}
