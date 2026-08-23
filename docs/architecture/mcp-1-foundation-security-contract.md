# MCP-1: Foundation & Security Contract

**Status:** Accepted for MVP implementation
**Version:** 1.0
**Scope:** MCP-1.1 through MCP-1.4

This document is the implementation contract for the MCP Security Scanner MVP. Later tickets must comply with it unless this document is explicitly revised.

## 1. Product boundary

The scanner accepts one supported public GitHub repository URL, reads selected repository metadata and text content, determines whether the repository is MCP-related, runs deterministic rules, and returns an explainable report.

The MVP is not a security certification, a comprehensive vulnerability scanner, or a dynamic testing tool. A report with no findings means only that no implemented rule found evidence in the processed content.

## 2. Non-negotiable security invariant

> **Analyzed repository code must never be executed, directly or indirectly.**

The implementation may only perform this pipeline:

```text
validate URL → read GitHub metadata/content → parse → detect → evaluate rules → redact → report
```

The following are prohibited for analyzed content:

- `git clone`, package installation, process execution, shell invocation, application startup, or repository scripts.
- Docker builds/runs, CI commands, build commands, test commands, or generated commands derived from repository content.
- Fetching URLs found inside the analyzed repository.
- Rendering untrusted content in a context that executes scripts.

Repository text is data, never an instruction. The implementation must not construct a command line from repository fields.

## 3. Threat model

### Assets to protect

- The scanner host, filesystem, network identity, process credentials, and GitHub credentials.
- Service availability and bounded resource consumption.
- Detected secret values and user-facing report integrity.

### Trust boundaries and controls

| Boundary | Untrusted input | Main risk | Required control |
|---|---|---|---|
| Browser → API | Repository URL | SSRF and malformed input | Accept only the canonical GitHub URL contract. |
| API → GitHub | Owner/repository identifiers | Host redirection or arbitrary fetch | Use a fixed GitHub API client; never use the submitted URL as a fetch target. |
| GitHub → analyzer | File tree, names, bytes, metadata | Resource exhaustion, parser abuse, binary data | Enforce limits, timeouts, text/binary handling, and no execution. |
| Analyzer → report/logs | Evidence, possibly secrets | Secret disclosure | Redact secret values before logs and API output. |
| Rule metadata → report | Rule title/reference/remediation | Misleading or unstable reporting | Version rules and keep static reference metadata in source control. |

### Out of scope threats for this MVP

- Exploitability proof, command injection detection, runtime MCP connection testing, and penetration testing.
- Private repository authorization and GitHub App/OAuth flows.
- Full secret-scanning coverage or a claim that non-detection proves absence of a secret.

## 4. Supported repository URL contract

### Accepted input

```text
https://github.com/{owner}/{repository}
```

The URL must use HTTPS, host `github.com`, and contain exactly an owner and repository path segment. Owner and repository names must be non-empty GitHub-compatible identifiers. A single trailing slash may be normalized before validation.

### Rejected input

- Any non-HTTPS scheme, alternate host, IP address, localhost address, port, user-info component, query string, or fragment.
- SSH/`git@github.com:` forms, `.git` suffixes, branch/tree/blob paths, and arbitrary remote URLs.
- Empty, malformed, or input longer than 2,048 characters.

The submitted URL is an identifier only. It must be parsed into owner/repository values; downstream access uses an allowlisted GitHub API base URL.

## 5. Initial resource policy

The limits below are product controls, not claims about the GitHub repository’s total size. Hitting a limit produces a partial/failed scan response; it must not cause the service to fetch or process more data.

| Control | Initial MVP value | Enforcement point |
|---|---:|---|
| Repository tree entries considered | 1,000 | After tree metadata retrieval |
| Candidate text files processed | 200 | Before individual content retrieval |
| Single file size | 512 KiB | Before and during content decoding |
| Total source bytes read | 5 MiB | Cumulative across selected files |
| Scan wall-clock time | 20 seconds | End-to-end cancellation token/deadline |
| Evidence excerpt | 240 characters | Before report serialization |

### File selection and cleanup

- Treat files as binary and skip them when GitHub metadata or byte inspection identifies binary content.
- Do not write repository content to disk in the MVP. If temporary storage is introduced later, it must be task-scoped and cleaned in a `finally` path.
- Stop at the first applicable resource limit and return the documented limit error; do not silently continue with an incomplete report.

## 6. Architecture contract

```text
Web UI
  → Scan API
    → Scan Orchestrator
      → GitHub Repository Reader (fixed GitHub API only)
      → Repository Content Set
        ├→ MCP Detector
        └→ Deterministic Rule Engine
             → Findings + Detection Evidence
    → Report Builder / Evidence Redactor
  → Scan Report
```

### Component responsibilities

| Component | Owns | Must not own |
|---|---|---|
| Web UI | URL entry and report display | Repository access or rule decisions |
| Scan API | Request validation, response/error mapping | Direct GitHub parsing logic |
| Scan Orchestrator | Ordered workflow and deadline propagation | Rule-specific detection logic |
| GitHub Repository Reader | Fixed-host metadata/tree/content reads and resource enforcement | Clone, checkout, command execution, or arbitrary URL fetching |
| MCP Detector | Evidence-backed MCP classification | Security finding generation |
| Rule Engine | Deterministic rule evaluation and finding collection | Network I/O or code execution |
| Report Builder | Summary, stable ordering, redaction | Changing raw rule outcome |

Dependency direction is inward: UI/API and GitHub infrastructure depend on application/domain contracts; rules and detector do not depend on HTTP/UI implementations.

## 7. Scan API and response contract

### Request

```json
{
  "repositoryUrl": "https://github.com/owner/repository"
}
```

No user, credential, branch, path, arbitrary endpoint, or execution option is accepted in the MVP.

### Successful report

```json
{
  "scanStatus": "completed",
  "repository": { "owner": "owner", "name": "repository" },
  "mcpClassification": "mcp_related",
  "detectionEvidence": [],
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "informational": 0
  },
  "findings": [],
  "ruleSetVersion": "1.0"
}
```

`mcpClassification` is one of `mcp_related`, `not_mcp`, or `inconclusive`. A `not_mcp` result is successful scan output, not an error and not a security verdict.

### Error response

```json
{
  "code": "INVALID_REPOSITORY_URL",
  "message": "Enter a public GitHub repository URL in the form https://github.com/{owner}/{repository}.",
  "retryAfterSeconds": null
}
```

Error responses must not disclose server internals, access tokens, raw secret values, or unsupported repository content.

### Error catalogue

| Code | HTTP status | User-facing behaviour |
|---|---:|---|
| `INVALID_REPOSITORY_URL` | 400 | Explain the accepted canonical format. |
| `REPOSITORY_NOT_PUBLIC_OR_NOT_FOUND` | 404 | State that the repository does not exist or is not publicly accessible; do not distinguish private from missing. |
| `GITHUB_RATE_LIMITED` | 429 | Ask the user to retry later; include `retryAfterSeconds` only when known. |
| `GITHUB_UNAVAILABLE` | 503 | Explain that GitHub could not be reached and retry is appropriate. |
| `RESOURCE_LIMIT_EXCEEDED` | 422 | State the exceeded limit and that no partial security conclusion is returned. |
| `ANALYSIS_TIMEOUT` | 504 | State that the analysis deadline was reached; do not return a misleading partial result. |
| `ANALYSIS_FAILED` | 500 | Show a generic failure message and correlation identifier when logging exists. |

## 8. MCP detection contract

MCP detection is repository-level classification, separate from rule findings. The detector may use known configuration names, MCP SDK dependencies, server declarations, and tool/resource/prompt structures.

Every positive detection includes one or more `DetectionEvidence` items:

| Field | Meaning |
|---|---|
| `signalId` | Stable detector signal identifier, for example `MCP-CONFIG-001`. |
| `title` | Human-readable reason for the signal. |
| `filePath` | Repository-relative path. |
| `location` | Optional one-based line/column range when available. |
| `evidence` | Short redacted excerpt or structural description. |
| `confidence` | `high`, `medium`, or `low`. |

`inconclusive` is reserved for a scan that cannot establish a reliable classification without violating the resource or processing contract. It is not a substitute for an implementation error.

## 9. Rule, finding, and summary contract

### Rule identifier vocabulary

Rule identifiers use `MCP-{CATEGORY}-{NNN}` and are immutable after publication.

| Category | Meaning | Initial rule IDs |
|---|---|---|
| `CMD` | Local execution command patterns | `MCP-CMD-001`, `MCP-CMD-002` |
| `FS` | Sensitive filesystem access references | `MCP-FS-001` |
| `NET` | Remote transport configuration | `MCP-NET-001` |
| `SEC` | Credential exposure patterns | `MCP-SEC-001` |
| `AUTH` | OAuth scopes and authorization URL safety | `MCP-AUTH-001`, `MCP-AUTH-002` |

Every rule definition includes: `ruleId`, `category`, `defaultSeverity`, `title`, `description`, deterministic detection logic, `whyItMatters`, `remediation`, `confidence`, and `reference`.

### Severity vocabulary

| Severity | Meaning |
|---|---|
| `critical` | Reserved for an immediately severe, high-confidence posture issue; no MVP rule uses it until explicitly justified. |
| `high` | Clear static evidence of a pattern that can materially increase harm. |
| `medium` | Meaningful risk signal needing review or safer configuration. |
| `low` | Limited-impact security hygiene signal. |
| `informational` | Context that is useful but not itself a risk finding. |

Severity is rule metadata, not a runtime exploitability score.

### Confidence vocabulary

| Confidence | Meaning |
|---|---|
| `high` | The evidence directly satisfies the deterministic rule condition. |
| `medium` | The evidence is clear but contextual interpretation is required. |
| `low` | The evidence is a weak signal; avoid using this for high-severity MVP findings. |

### Finding schema

Each finding contains:

| Field | Requirement |
|---|---|
| `ruleId`, `category`, `severity`, `confidence`, `title` | Stable classification and display metadata. |
| `filePath`, `location` | Repository-relative evidence location; location is optional only when parsing cannot provide it. |
| `evidence` | Maximum 240-character excerpt or structural evidence, redacted before output. |
| `whyItMatters` | Concrete, non-speculative security impact explanation. |
| `remediation` | Actionable, rule-specific safer configuration guidance. |
| `reference` | Stable official MCP security/specification guidance reference where applicable. |

`ReportSummary` is derived solely from the final finding list and reports counts by the five severity values. It must not expose a security posture score in this MVP.

## 10. Acceptance mapping

| MCP-1 acceptance criterion | Contract section |
|---|---|
| No analyzed code execution is documented | 2, 3, 6 |
| Canonical public GitHub URL is defined | 4 |
| File/byte/time resource limits are defined | 5 |
| Unsupported URL, private/deleted repository, rate limit, and MCP non-detection behaviour are defined | 4, 7, 8 |
| Finding, detection evidence, summary, and rule contracts are designed | 8, 9 |

## 11. Implementation guardrails for next tickets

- MCP-2 implements only URL validation from section 4 and its matching error mapping.
- MCP-3 implements fixed-host read-only GitHub access and section 5 limits; it must preserve no-execution behaviour.
- MCP-4 implements detection evidence from section 8.
- MCP-5 implements domain models and rule engine behaviour from section 9.
- Any proposed increase to a resource limit, new accepted URL form, or behavior that executes repository content requires an explicit contract revision and threat-model review.
