const canonicalRepositoryPattern = /^https:\/\/github\.com\/[^/?#\s]+\/[^/?#\s]+\/?$/i;

export function validateRepositoryUrl(repositoryUrl) {
  if (typeof repositoryUrl !== "string" || !canonicalRepositoryPattern.test(repositoryUrl)) {
    return "Enter a public GitHub repository URL in the form https://github.com/owner/repository.";
  }

  try {
    const parsed = new URL(repositoryUrl);
    if (parsed.hostname.toLowerCase() !== "github.com" || parsed.search || parsed.hash || parsed.username || parsed.password) {
      return "Enter a public GitHub repository URL in the form https://github.com/owner/repository.";
    }
  } catch {
    return "Enter a public GitHub repository URL in the form https://github.com/owner/repository.";
  }

  return null;
}

export function createInitialScanState() {
  return { status: "idle", error: null, response: null };
}

export function transitionScanState(state, event) {
  switch (event.type) {
    case "validation_failed":
    case "scan_failed":
      return { status: "error", error: event.message, response: null };
    case "scan_started":
      return { status: "loading", error: null, response: null };
    case "scan_succeeded":
      return { status: "success", error: null, response: event.response };
    default:
      return state;
  }
}

export function errorMessage(error) {
  const retry = error?.retryAfterSeconds;
  switch (error?.code) {
    case "INVALID_REPOSITORY_URL":
      return "Enter a canonical public GitHub repository URL and try again.";
    case "REPOSITORY_NOT_PUBLIC_OR_NOT_FOUND":
      return "The repository is private, deleted, or could not be found publicly.";
    case "GITHUB_RATE_LIMITED":
      return retry ? `GitHub rate limit reached. Try again in about ${retry} seconds.` : "GitHub rate limit reached. Try again later.";
    case "RESOURCE_LIMIT_EXCEEDED":
      return "The repository exceeds this scanner's safe processing limits.";
    case "ANALYSIS_TIMEOUT":
      return "Repository analysis exceeded the safe time limit. Try again later.";
    case "GITHUB_UNAVAILABLE":
      return "GitHub is currently unavailable. Try again later.";
    default:
      return "The repository could not be scanned safely. Try again later.";
  }
}

export function severityEntries(summary) {
  return [
    ["critical", summary?.critical ?? 0],
    ["high", summary?.high ?? 0],
    ["medium", summary?.medium ?? 0],
    ["low", summary?.low ?? 0],
    ["informational", summary?.informational ?? 0]
  ];
}

export function classificationLabel(classification) {
  return {
    mcp_related: "MCP-related",
    not_mcp: "Not MCP-related",
    inconclusive: "Inconclusive"
  }[classification] ?? "Unknown";
}
