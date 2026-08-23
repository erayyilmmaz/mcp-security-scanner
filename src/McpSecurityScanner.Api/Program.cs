using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Infrastructure.GitHub;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<GitHubRepositoryUrlValidator>();
builder.Services.AddSingleton(RepositoryIngestionOptions.Default);
builder.Services.AddHttpClient<IGitHubRepositoryApiClient, GitHubRestApiClient>(client =>
{
    client.BaseAddress = new Uri("https://api.github.com/");
    client.Timeout = Timeout.InfiniteTimeSpan;
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AllowAutoRedirect = false
});
builder.Services.AddSingleton<RepositoryIngestionService>();

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "MCP Security Scanner",
    status = "validation-only"
}));

app.MapPost("/api/repositories/validate", (
    RepositoryUrlValidationRequest request,
    GitHubRepositoryUrlValidator validator) =>
{
    var result = validator.Validate(request.RepositoryUrl);

    return result.IsValid
        ? Results.Ok(new RepositoryUrlValidationResponse(result.Repository!))
        : Results.BadRequest(result.Error!);
});

app.Run();

public sealed record RepositoryUrlValidationRequest(string? RepositoryUrl);

public sealed record RepositoryUrlValidationResponse(GitHubRepositoryReference Repository);
