using McpSecurityScanner.Core.Contracts;
using McpSecurityScanner.Core.Repositories;

namespace McpSecurityScanner.Tests;

public sealed class GitHubRepositoryUrlValidatorTests
{
    private readonly GitHubRepositoryUrlValidator _validator = new();

    [Theory]
    [InlineData("https://github.com/openai/openai-dotnet", "openai", "openai-dotnet")]
    [InlineData("https://github.com/owner/repository/", "owner", "repository")]
    [InlineData("https://github.com/acme-org/repository_name.v2", "acme-org", "repository_name.v2")]
    public void Validate_ReturnsRepositoryReference_ForCanonicalUrl(
        string repositoryUrl,
        string expectedOwner,
        string expectedRepository)
    {
        var result = _validator.Validate(repositoryUrl);

        Assert.True(result.IsValid);
        Assert.NotNull(result.Repository);
        Assert.Equal(expectedOwner, result.Repository.Owner);
        Assert.Equal(expectedRepository, result.Repository.Name);
        Assert.Null(result.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" https://github.com/openai/openai-dotnet")]
    [InlineData("git@github.com:openai/openai-dotnet.git")]
    [InlineData("git://github.com/openai/openai-dotnet")]
    [InlineData("http://github.com/openai/openai-dotnet")]
    [InlineData("https://api.github.com/openai/openai-dotnet")]
    [InlineData("https://github.example.com/openai/openai-dotnet")]
    [InlineData("https://127.0.0.1/openai/openai-dotnet")]
    [InlineData("https://localhost/openai/openai-dotnet")]
    [InlineData("https://github.com:443/openai/openai-dotnet")]
    [InlineData("https://user@github.com/openai/openai-dotnet")]
    [InlineData("https://github.com/openai/openai-dotnet?ref=main")]
    [InlineData("https://github.com/openai/openai-dotnet#readme")]
    [InlineData("https://github.com/openai/openai-dotnet/tree/main")]
    [InlineData("https://github.com/openai/openai-dotnet.git")]
    [InlineData("https://github.com/openai")]
    [InlineData("https://github.com/openai//openai-dotnet")]
    public void Validate_ReturnsSafeApiError_ForUnsupportedInput(string? repositoryUrl)
    {
        var result = _validator.Validate(repositoryUrl);

        Assert.False(result.IsValid);
        Assert.Null(result.Repository);
        Assert.NotNull(result.Error);
        Assert.Equal(ApiErrorCodes.InvalidRepositoryUrl, result.Error.Code);
        Assert.Equal(
            "Enter a public GitHub repository URL in the form https://github.com/{owner}/{repository}.",
            result.Error.Message);
        Assert.Null(result.Error.RetryAfterSeconds);
    }

    [Fact]
    public void Validate_ReturnsSafeApiError_WhenUrlExceedsMaximumLength()
    {
        var repositoryUrl =
            "https://github.com/owner/" + new string('a', GitHubRepositoryUrlValidator.MaximumUrlLength);

        var result = _validator.Validate(repositoryUrl);

        Assert.False(result.IsValid);
        Assert.Equal(ApiErrorCodes.InvalidRepositoryUrl, result.Error?.Code);
    }
}
