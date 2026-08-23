import {
  classificationLabel,
  createInitialScanState,
  errorMessage,
  severityEntries,
  transitionScanState,
  validateRepositoryUrl
} from "./ui-state.mjs";

const form = document.querySelector("#scan-form");
const input = document.querySelector("#repository-url");
const button = document.querySelector("#scan-button");
const loading = document.querySelector("#scan-loading");
const error = document.querySelector("#scan-error");
const results = document.querySelector("#results");
const repository = document.querySelector("#result-repository");
const classification = document.querySelector("#result-classification");
const severitySummary = document.querySelector("#severity-summary");
const evidenceList = document.querySelector("#mcp-evidence");
const evidenceEmpty = document.querySelector("#mcp-evidence-empty");
const findingsList = document.querySelector("#findings");
const findingsEmpty = document.querySelector("#findings-empty");

let state = createInitialScanState();

function setState(event) {
  state = transitionScanState(state, event);
  render();
}

function render() {
  const isLoading = state.status === "loading";
  button.disabled = isLoading;
  input.disabled = isLoading;
  button.textContent = isLoading ? "Scanning…" : "Scan repository";
  loading.hidden = !isLoading;
  error.hidden = state.status !== "error";
  error.textContent = state.error ?? "";
  results.hidden = state.status !== "success";

  if (state.status === "success") {
    renderResult(state.response);
  }
}

function renderResult(response) {
  repository.textContent = `${response.repository.owner}/${response.repository.name}`;
  classification.textContent = classificationLabel(response.mcp.classification);

  severitySummary.replaceChildren(...severityEntries(response.report.summary).map(([name, count]) => {
    const card = element("div", `severity-card severity-${name}`);
    card.append(element("span", "severity-count", String(count)), element("span", "severity-label", name));
    return card;
  }));

  const evidence = response.mcp.evidence ?? [];
  evidenceEmpty.hidden = evidence.length > 0;
  evidenceList.replaceChildren(...evidence.map(renderDetectionEvidence));

  const findings = response.report.findings ?? [];
  findingsEmpty.hidden = findings.length > 0;
  findingsList.replaceChildren(...findings.map(renderFinding));
}

function renderDetectionEvidence(item) {
  const card = element("article", "evidence-card");
  const heading = element("div", "card-heading");
  heading.append(element("h4", null, `${item.signalId} — ${item.title}`), element("span", "pill pill-informational", item.confidence));
  card.append(heading, location(item.filePath, item.line), evidence(item.evidence));
  return card;
}

function renderFinding(finding) {
  const card = element("article", "finding-card");
  const heading = element("div", "card-heading");
  heading.append(element("h4", null, `${finding.ruleId} — ${finding.title}`), element("span", `pill pill-${finding.severity}`, finding.severity));

  const details = element("div", "detail-grid");
  details.append(
    detail("Why it matters", finding.whyItMatters),
    detail("Remediation", finding.remediation),
    detail("Confidence", finding.confidence),
    reference(finding.reference)
  );
  card.append(heading, element("p", "muted", finding.category), location(finding.filePath, finding.line, finding.column), evidence(finding.evidence), details);
  return card;
}

function element(tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function location(filePath, line, column) {
  const suffix = line ? `:${line}${column ? `:${column}` : ""}` : "";
  return element("p", "location", `${filePath}${suffix}`);
}

function evidence(text) {
  return element("code", "evidence", text);
}

function detail(label, text) {
  const container = element("p");
  container.append(element("strong", null, label), document.createTextNode(text ?? "Not provided"));
  return container;
}

function reference(item) {
  const container = element("p");
  container.append(element("strong", null, "Reference"));
  const link = element("a", null, item?.title ?? "Not provided");
  if (item?.url) {
    link.href = item.url;
    link.target = "_blank";
    link.rel = "noreferrer";
  }
  container.append(link);
  return container;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const repositoryUrl = input.value.trim();
  const validationError = validateRepositoryUrl(repositoryUrl);
  if (validationError) {
    setState({ type: "validation_failed", message: validationError });
    input.focus();
    return;
  }

  setState({ type: "scan_started" });
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repositoryUrl })
    });
    const payload = await response.json();
    if (!response.ok) {
      setState({ type: "scan_failed", message: errorMessage(payload) });
      return;
    }

    setState({ type: "scan_succeeded", response: payload });
  } catch {
    setState({ type: "scan_failed", message: "The scan service could not be reached. Try again later." });
  }
});

render();
