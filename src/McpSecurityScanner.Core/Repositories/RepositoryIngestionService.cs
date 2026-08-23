using System.Text;
using McpSecurityScanner.Core.Contracts;

namespace McpSecurityScanner.Core.Repositories;

public sealed class RepositoryIngestionService
{
    private readonly IGitHubRepositoryApiClient _gitHubClient;
    private readonly RepositoryIngestionOptions _options;
    private readonly UTF8Encoding _strictUtf8 = new(false, true);

    public RepositoryIngestionService(
        IGitHubRepositoryApiClient gitHubClient,
        RepositoryIngestionOptions? options = null)
    {
        _gitHubClient = gitHubClient;
        _options = options ?? RepositoryIngestionOptions.Default;
    }

    public async Task<RepositoryIngestionResult> ReadAsync(
        GitHubRepositoryReference repository,
        CancellationToken cancellationToken = default)
    {
        if (!HasValidLimits())
        {
            return RepositoryIngestionResult.Failure(RepositoryIngestionErrors.AnalysisFailed());
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(_options.AnalysisTimeout);

        try
        {
            var metadataResult = await _gitHubClient.GetMetadataAsync(repository, timeoutSource.Token);
            if (!metadataResult.IsSuccess)
            {
                return RepositoryIngestionResult.Failure(metadataResult.Error!);
            }

            var treeResult = await _gitHubClient.GetTreeAsync(
                repository,
                metadataResult.Value!.DefaultBranch,
                timeoutSource.Token);
            if (!treeResult.IsSuccess)
            {
                return RepositoryIngestionResult.Failure(treeResult.Error!);
            }

            if (treeResult.Value!.IsTruncated || treeResult.Value.Entries.Count > _options.MaximumTreeEntries)
            {
                return RepositoryIngestionResult.Failure(RepositoryIngestionErrors.ResourceLimitExceeded());
            }

            var candidateFiles = treeResult.Value.Entries
                .Where(entry => string.Equals(entry.Type, "blob", StringComparison.Ordinal) &&
                    !string.Equals(entry.Mode, "120000", StringComparison.Ordinal))
                .OrderBy(entry => entry.Path, StringComparer.Ordinal)
                .ToArray();

            if (candidateFiles.Length > _options.MaximumCandidateFiles ||
                candidateFiles.Any(entry => entry.Size is { } size && size > _options.MaximumFileBytes) ||
                SumKnownFileSizesExceedsLimit(candidateFiles))
            {
                return RepositoryIngestionResult.Failure(RepositoryIngestionErrors.ResourceLimitExceeded());
            }

            var files = new List<RepositoryContentFile>(candidateFiles.Length);
            var totalBytes = 0;

            foreach (var candidateFile in candidateFiles)
            {
                var contentResult = await _gitHubClient.GetFileContentAsync(
                    repository,
                    candidateFile.Path,
                    metadataResult.Value.DefaultBranch,
                    _options.MaximumFileBytes,
                    timeoutSource.Token);
                if (!contentResult.IsSuccess)
                {
                    return RepositoryIngestionResult.Failure(contentResult.Error!);
                }

                var bytes = contentResult.Value!.Bytes;
                if (bytes.Length > _options.MaximumFileBytes || totalBytes > _options.MaximumTotalBytes - bytes.Length)
                {
                    return RepositoryIngestionResult.Failure(RepositoryIngestionErrors.ResourceLimitExceeded());
                }

                totalBytes += bytes.Length;

                if (!TryDecodeText(bytes, out var content))
                {
                    continue;
                }

                files.Add(new RepositoryContentFile(candidateFile.Path, content));
            }

            return RepositoryIngestionResult.Success(
                new RepositoryContentSet(repository, metadataResult.Value.DefaultBranch, files));
        }
        catch (OperationCanceledException) when (timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return RepositoryIngestionResult.Failure(RepositoryIngestionErrors.AnalysisTimeout());
        }
    }

    private bool SumKnownFileSizesExceedsLimit(IEnumerable<GitHubRepositoryTreeEntry> candidateFiles)
    {
        long total = 0;

        foreach (var candidateFile in candidateFiles)
        {
            if (candidateFile.Size is not { } size)
            {
                continue;
            }

            total += size;
            if (total > _options.MaximumTotalBytes)
            {
                return true;
            }
        }

        return false;
    }

    private bool TryDecodeText(byte[] bytes, out string content)
    {
        content = string.Empty;

        if (bytes.AsSpan().IndexOf((byte)0) >= 0)
        {
            return false;
        }

        try
        {
            content = _strictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        var controlCharacterCount = content.Count(character =>
            char.IsControl(character) && character is not '\r' and not '\n' and not '\t');

        return controlCharacterCount <= content.Length / 3;
    }

    private bool HasValidLimits() =>
        _options.MaximumTreeEntries > 0 &&
        _options.MaximumCandidateFiles > 0 &&
        _options.MaximumFileBytes > 0 &&
        _options.MaximumTotalBytes >= _options.MaximumFileBytes &&
        _options.AnalysisTimeout > TimeSpan.Zero;
}
