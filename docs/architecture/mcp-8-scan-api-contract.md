# MCP-8: Scan and Report API Contract

**Status:** Accepted for MVP implementation
**Scope:** MCP-8.1 through MCP-8.4

`POST /api/scans` accepts:

```json
{ "repositoryUrl": "https://github.com/{owner}/{repository}" }
```

The endpoint performs one in-memory, bounded scan request in this order:

1. Validate the canonical public GitHub URL.
2. Read public metadata, tree metadata, and bounded text file content through MCP-3's fixed GitHub API client.
3. Produce MCP-4 classification/evidence.
4. Run all seven MVP rules through the MCP-5 rule engine.
5. Return repository identity, MCP result, severity summary, and redacted findings.

The API keeps no scan history, user account, database record, or repository checkout. It never invokes a process, shell, build, package installation, Docker operation, or analyzed repository code.

## Error mapping

| Error code | HTTP status |
|---|---:|
| `INVALID_REPOSITORY_URL` | 400 |
| `REPOSITORY_NOT_PUBLIC_OR_NOT_FOUND` | 404 |
| `GITHUB_RATE_LIMITED` | 429 |
| `RESOURCE_LIMIT_EXCEEDED` | 422 |
| `ANALYSIS_TIMEOUT` | 504 |
| `GITHUB_UNAVAILABLE` | 502 |
| Other safe analysis failure | 500 |

Error messages are inherited from the safe MCP-1/MCP-3 contract and do not expose GitHub response bodies or repository source. Findings pass through MCP-5 evidence redaction before serialization.
