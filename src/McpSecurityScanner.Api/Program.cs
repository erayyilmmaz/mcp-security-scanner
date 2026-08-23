using McpSecurityScanner.Core.Repositories;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<GitHubRepositoryUrlValidator>();

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
