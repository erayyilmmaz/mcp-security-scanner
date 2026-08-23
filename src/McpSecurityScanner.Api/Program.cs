using System.Text.Json;
using System.Text.Json.Serialization;
using McpSecurityScanner.Api.Contracts;
using McpSecurityScanner.Core.Contracts;
using McpSecurityScanner.Core.Detection;
using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Core.Rules;
using McpSecurityScanner.Core.Scanning;
using McpSecurityScanner.Infrastructure.GitHub;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(
        new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
});
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
builder.Services.AddSingleton<McpRepositoryDetector>();
builder.Services.AddSingleton(new SecurityRuleEngine(
    [
        new PrivilegedExecutionRule(),
        new DangerousCommandRule(),
        new SensitiveFilesystemRule(),
        new InsecureRemoteTransportRule(),
        new HardcodedCredentialRule(),
        new BroadOAuthScopeRule(),
        new DangerousAuthorizationUrlRule()
    ],
    "1.0.0"));
builder.Services.AddSingleton<RepositoryScanService>();

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "MCP Security Scanner",
    status = "scan-api-ready"
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

app.MapPost("/api/scans", async (
    ScanRequest request,
    RepositoryScanService scanService,
    CancellationToken cancellationToken) =>
{
    var result = await scanService.ScanAsync(request.RepositoryUrl, cancellationToken);

    return result.IsSuccess
        ? Results.Ok(new ScanResponse(result.Repository!, result.Detection!, result.Report!))
        : ToErrorResult(result.Error!);
});

app.Run();

static IResult ToErrorResult(ApiErrorResponse error) =>
    error.Code switch
    {
        ApiErrorCodes.InvalidRepositoryUrl => Results.BadRequest(error),
        ApiErrorCodes.RepositoryNotPublicOrNotFound => Results.NotFound(error),
        ApiErrorCodes.GitHubRateLimited => Results.Json(error, statusCode: StatusCodes.Status429TooManyRequests),
        ApiErrorCodes.ResourceLimitExceeded => Results.Json(error, statusCode: StatusCodes.Status422UnprocessableEntity),
        ApiErrorCodes.AnalysisTimeout => Results.Json(error, statusCode: StatusCodes.Status504GatewayTimeout),
        ApiErrorCodes.GitHubUnavailable => Results.Json(error, statusCode: StatusCodes.Status502BadGateway),
        _ => Results.Json(error, statusCode: StatusCodes.Status500InternalServerError)
    };

public sealed record RepositoryUrlValidationRequest(string? RepositoryUrl);

public sealed record RepositoryUrlValidationResponse(GitHubRepositoryReference Repository);

public partial class Program
{
}
