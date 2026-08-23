using McpSecurityScanner.Core.Detection;
using McpSecurityScanner.Core.Repositories;
using McpSecurityScanner.Core.Rules;

namespace McpSecurityScanner.Core.Scanning;

public sealed class RepositoryScanService
{
    private readonly GitHubRepositoryUrlValidator _urlValidator;
    private readonly RepositoryIngestionService _ingestionService;
    private readonly McpRepositoryDetector _detector;
    private readonly SecurityRuleEngine _ruleEngine;

    public RepositoryScanService(
        GitHubRepositoryUrlValidator urlValidator,
        RepositoryIngestionService ingestionService,
        McpRepositoryDetector detector,
        SecurityRuleEngine ruleEngine)
    {
        _urlValidator = urlValidator;
        _ingestionService = ingestionService;
        _detector = detector;
        _ruleEngine = ruleEngine;
    }

    public async Task<RepositoryScanResult> ScanAsync(
        string? repositoryUrl,
        CancellationToken cancellationToken = default)
    {
        var validation = _urlValidator.Validate(repositoryUrl);
        if (!validation.IsValid)
        {
            return RepositoryScanResult.Failure(validation.Error!);
        }

        var repository = validation.Repository!;
        var ingestion = await _ingestionService.ReadAsync(repository, cancellationToken);
        if (!ingestion.IsSuccess)
        {
            return RepositoryScanResult.Failure(ingestion.Error!);
        }

        var contentSet = ingestion.ContentSet!;
        var detection = _detector.Detect(contentSet);
        var report = _ruleEngine.Analyze(contentSet);

        return RepositoryScanResult.Success(repository, detection, report);
    }
}
