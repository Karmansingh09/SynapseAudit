"use strict";

const fixtureSelect = document.getElementById("fixture-select");
const analyzeButton = document.getElementById("analyze-button");
const retryButton = document.getElementById("retry-button");
const errorBanner = document.getElementById("error-banner");
const errorMessage = document.getElementById("error-message");
const statRow = document.getElementById("stat-row");
const topbarState = document.querySelector(".topbar-state");
const navItems = Array.from(document.querySelectorAll(".nav-item"));
const composeFile = document.getElementById("compose-file");
const uploadButton = document.getElementById("upload-button");
const uploadFilename = document.getElementById("upload-filename");
const githubConnectButton = document.getElementById("github-connect-button");
const githubDisconnectButton = document.getElementById("github-disconnect-button");
const githubStatus = document.getElementById("github-status");
const githubConnectionCopy = document.getElementById("github-connection-copy");
const githubSelectionStatus = document.getElementById("github-selection-status");
const githubSelection = document.getElementById("github-selection");
const githubRepositorySelect = document.getElementById("github-repository-select");
const githubBranchSelect = document.getElementById("github-branch-select");
const startScanButton = document.getElementById("start-scan-button");
const MAX_UPLOAD_BYTES = 1024 * 1024;
let currentReport = null;
let reports = { vulnerable: null, remediated: null };
let selectedFindingIndex = 0;
let reportSource = "none";
let activeOperation = 0;
const animationFrames = new Set();
let githubCsrfToken = null;

function setText(id, value) { document.getElementById(id).textContent = String(value); }
function showError(message) { errorMessage.textContent = message; errorBanner.hidden = false; topbarState.classList.remove("is-busy"); topbarState.classList.add("is-error"); setText("topbar-status", "Analysis request failed"); setText("overview-status", "Request failed, retry available"); }
function clearError() { errorBanner.hidden = true; errorMessage.textContent = ""; topbarState.classList.remove("is-error"); }
function setLoading(loading) { analyzeButton.disabled = loading; analyzeButton.querySelector("span").textContent = loading ? "Analyzing..." : "Analyze"; topbarState.classList.toggle("is-busy", loading); if (loading) { statRow.classList.add("scanning"); setText("analysis-status", "Reading local analyzer"); setText("topbar-status", "Local analysis in progress"); } else { statRow.classList.remove("scanning"); } }

function cancelAnimations() { animationFrames.forEach((frame) => cancelAnimationFrame(frame)); animationFrames.clear(); }
function invalidateOperations() { activeOperation += 1; cancelAnimations(); return activeOperation; }
function isCurrentOperation(operation) { return operation === activeOperation; }

function emptyState(title, copy) {
  const empty = document.createElement("div"); empty.className = "empty-state";
  const strong = document.createElement("strong"); strong.textContent = title;
  empty.append(strong, document.createTextNode(copy));
  return empty;
}

function clearDisplayedReport({ invalidate = true, clearFixtures = true } = {}) {
  if (invalidate) invalidateOperations(); else cancelAnimations();
  currentReport = null;
  if (clearFixtures) reports = { vulnerable: null, remediated: null };
  reportSource = "none";
  selectedFindingIndex = 0;
  ["metric-total", "metric-high", "metric-medium", "metric-paths", "risk-high-count", "risk-medium-count", "risk-low-count"].forEach((id) => setText(id, "—"));
  ["risk-high-bar", "risk-medium-bar", "risk-low-bar"].forEach((id) => { document.getElementById(id).style.width = "0%"; });
  const findingsBody = document.getElementById("findings-table-body"); findingsBody.replaceChildren();
  const findingRow = document.createElement("tr"); const findingCell = document.createElement("td"); findingCell.className = "empty-row"; findingCell.colSpan = 4; findingCell.textContent = "Analyze a fixture or selected file to load findings."; findingRow.append(findingCell); findingsBody.append(findingRow);
  document.getElementById("finding-detail").replaceChildren(emptyState("No report loaded", "Select a fixture or analyze a file."));
  document.getElementById("attack-content").replaceChildren(emptyState("No report loaded", "Select a fixture or analyze a file."));
  setText("findings-count", "—");
  renderComparison();
}

async function fetchReport(fixture) {
  const response = await fetch(`/api/analyze?fixture=${encodeURIComponent(fixture)}`, { headers: { Accept: "application/json" } });
  let payload;
  try { payload = await response.json(); } catch (error) { throw new Error("The local API returned an invalid response."); }
  if (!response.ok) throw new Error(payload.error || "The local analysis request failed.");
  return payload;
}

async function fetchUploadReport(file) {
  const form = new FormData();
  form.append("compose_file", file, file.name);
  const response = await fetch("/api/analyze-upload", { method: "POST", body: form, headers: { Accept: "application/json" } });
  let payload;
  try { payload = await response.json(); } catch (error) { throw new Error("The local API returned an invalid response."); }
  if (!response.ok) throw new Error(payload.error || "The upload analysis request failed.");
  return payload;
}

async function fetchGitHubJson(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) },
  });
  let payload;
  try { payload = await response.json(); } catch (error) { throw new Error("The local GitHub integration returned an invalid response."); }
  if (!response.ok) {
    const error = new Error(payload.error || "The GitHub integration request failed.");
    error.status = response.status;
    throw error;
  }
  return payload;
}

function setGitHubCopy(status, copy) { githubStatus.textContent = status; githubConnectionCopy.textContent = copy; }

function resetGitHubSelection() {
  githubSelection.hidden = true;
  githubRepositorySelect.replaceChildren();
  githubRepositorySelect.append(new Option("Connect GitHub to list repositories", ""));
  githubRepositorySelect.disabled = true;
  githubBranchSelect.replaceChildren();
  githubBranchSelect.append(new Option("Select a repository first", ""));
  githubBranchSelect.disabled = true;
  startScanButton.disabled = true;
  githubSelectionStatus.textContent = "Not connected";
}

function showGitHubDisconnected(message = "GitHub App access is optional and read-only.") {
  githubCsrfToken = null;
  githubConnectButton.disabled = false;
  githubConnectButton.textContent = "Connect GitHub";
  githubDisconnectButton.hidden = true;
  setGitHubCopy("Not connected", message);
  resetGitHubSelection();
}

async function loadGitHubRepositories() {
  try {
    const payload = await fetchGitHubJson("/api/github/repositories");
    githubRepositorySelect.replaceChildren();
    const repositories = Array.isArray(payload.repositories) ? payload.repositories : [];
    if (repositories.length === 0) {
      githubRepositorySelect.append(new Option("No accessible repositories", ""));
      githubRepositorySelect.disabled = true;
      githubSelectionStatus.textContent = "No repositories";
      return;
    }
    repositories.forEach((repository) => {
      if (!repository || typeof repository.full_name !== "string") return;
      const option = new Option(repository.full_name, repository.full_name);
      githubRepositorySelect.append(option);
    });
    githubRepositorySelect.disabled = false;
    githubSelectionStatus.textContent = `${repositories.length} accessible ${repositories.length === 1 ? "repository" : "repositories"}`;
  } catch (error) {
    if (error && (error.status === 401 || error.status === 403)) {
      showGitHubDisconnected("GitHub authorization expired or was revoked.");
    } else {
      setGitHubCopy("Repository list unavailable", error instanceof Error ? error.message : "GitHub repository access failed.");
    }
  }
}

async function loadGitHubBranches() {
  const fullName = githubRepositorySelect.value;
  githubBranchSelect.replaceChildren(new Option("Loading branches...", ""));
  githubBranchSelect.disabled = true;
  startScanButton.disabled = true;
  if (!fullName) {
    githubBranchSelect.replaceChildren(new Option("Select a repository first", ""));
    return;
  }
  const [owner, repository] = fullName.split("/");
  if (!owner || !repository) {
    setGitHubCopy("Repository selection invalid", "The server rejected the repository identifier.");
    return;
  }
  try {
    const payload = await fetchGitHubJson(`/api/github/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/branches`);
    const branches = Array.isArray(payload.branches) ? payload.branches : [];
    githubBranchSelect.replaceChildren();
    if (branches.length === 0) {
      githubBranchSelect.append(new Option("No branches available", ""));
      return;
    }
    branches.forEach((branch) => {
      if (!branch || typeof branch.name !== "string") return;
      githubBranchSelect.append(new Option(branch.name, branch.name));
    });
    githubBranchSelect.disabled = false;
  } catch (error) {
    githubBranchSelect.replaceChildren(new Option("Branches unavailable", ""));
    if (error && (error.status === 401 || error.status === 403)) showGitHubDisconnected("GitHub authorization expired or was revoked.");
    else setGitHubCopy("Branch list unavailable", error instanceof Error ? error.message : "GitHub branch access failed.");
  }
}

async function loadGitHubStatus() {
  try {
    const payload = await fetchGitHubJson("/api/github/status");
    githubCsrfToken = typeof payload.csrf_token === "string" ? payload.csrf_token : null;
    if (!payload.configured) {
      githubConnectButton.disabled = true;
      githubConnectButton.textContent = "GitHub unavailable";
      githubDisconnectButton.hidden = true;
      setGitHubCopy("Local-only mode", payload.message || "Configure a GitHub App on the server to connect.");
      resetGitHubSelection();
      return;
    }
    if (!payload.connected) {
      showGitHubDisconnected("GitHub App access is optional and read-only.");
      return;
    }
    githubConnectButton.disabled = true;
    githubConnectButton.textContent = "GitHub connected";
    githubDisconnectButton.hidden = false;
    githubSelection.hidden = false;
    githubSelectionStatus.textContent = "Loading repositories";
    setGitHubCopy("Connected", "Repository metadata is read-only; repository contents are not fetched in Phase 1.");
    await loadGitHubRepositories();
  } catch (error) {
    githubConnectButton.disabled = true;
    setGitHubCopy("GitHub status unavailable", error instanceof Error ? error.message : "The GitHub integration is unavailable.");
    resetGitHubSelection();
  }
}

async function connectGitHub() {
  githubConnectButton.disabled = true;
  githubConnectButton.textContent = "Connecting...";
  try {
    const payload = await fetchGitHubJson("/api/github/connect");
    if (typeof payload.authorization_url !== "string") throw new Error("The server did not provide a GitHub authorization URL.");
    window.location.assign(payload.authorization_url);
  } catch (error) {
    githubConnectButton.disabled = false;
    githubConnectButton.textContent = "Connect GitHub";
    setGitHubCopy("Authorization failed", error instanceof Error ? error.message : "GitHub authorization failed.");
  }
}

async function disconnectGitHub() {
  if (!githubCsrfToken) { showGitHubDisconnected("GitHub session expired; connect again to continue."); return; }
  try {
    await fetchGitHubJson("/api/github/disconnect", { method: "POST", headers: { "X-CSRF-Token": githubCsrfToken } });
    showGitHubDisconnected("GitHub App access disconnected.");
  } catch (error) {
    setGitHubCopy("Disconnect failed", error instanceof Error ? error.message : "The GitHub disconnect request failed.");
  }
}

async function fetchFixtureReports() {
  const [vulnerable, remediated] = await Promise.all([fetchReport("vulnerable"), fetchReport("remediated")]);
  return { vulnerable, remediated };
}

function severityCounts(report) {
  const findings = Array.isArray(report && report.findings) ? report.findings : [];
  return { total: findings.length, high: findings.filter((finding) => finding.severity === "high").length, medium: findings.filter((finding) => finding.severity === "medium").length, low: findings.filter((finding) => finding.severity === "low").length, paths: Array.isArray(report && report.attack_paths) ? report.attack_paths.length : 0 };
}

function animateCount(id, target, duration = 460) {
  const element = document.getElementById(id);
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced || target === 0) { element.textContent = String(target); return; }
  const started = performance.now();
  function tick(now) { animationFrames.delete(frame); const progress = Math.min((now - started) / duration, 1); element.textContent = String(Math.round(target * progress)); if (progress < 1) { const nextFrame = requestAnimationFrame(tick); animationFrames.add(nextFrame); } }
  const frame = requestAnimationFrame(tick);
  animationFrames.add(frame);
}

function updateRiskRail(counts) {
  const total = counts.total || 0;
  [["high", counts.high], ["medium", counts.medium], ["low", counts.low]].forEach(([level, count]) => {
    setText(`risk-${level}-count`, count);
    document.getElementById(`risk-${level}-bar`).style.width = total ? `${(count / total) * 100}%` : "0%";
  });
}

function renderMetrics(report, animate = false) {
  cancelAnimations();
  const counts = severityCounts(report);
  updateRiskRail(counts);
  statRow.classList.remove("revealed");
  if (animate) { animateCount("metric-total", counts.total); animateCount("metric-high", counts.high, 340); animateCount("metric-medium", counts.medium, 420); animateCount("metric-paths", counts.paths, 500); } else { setText("metric-total", counts.total); setText("metric-high", counts.high); setText("metric-medium", counts.medium); setText("metric-paths", counts.paths); }
  const frame = requestAnimationFrame(() => { animationFrames.delete(frame); statRow.classList.add("revealed"); });
  animationFrames.add(frame);
}

function detailBlock(label, value, className = "detail-copy", tagName = "p") {
  const block = document.createElement("div");
  const heading = document.createElement("div");
  heading.className = "detail-label";
  heading.textContent = label;
  const copy = document.createElement(tagName);
  copy.className = className;
  copy.textContent = String(value || "Not provided by the analyzer.");
  block.append(heading, copy);
  return block;
}

function renderFindingDetail(finding) {
  const detail = document.getElementById("finding-detail");
  detail.replaceChildren();
  if (!finding) { const empty = document.createElement("div"); empty.className = "empty-state"; const strong = document.createElement("strong"); const noFindings = !currentReport || !Array.isArray(currentReport.findings) || currentReport.findings.length === 0; const subject = reportSource === "upload" ? "uploaded file" : "selected fixture"; strong.textContent = noFindings ? "No active findings" : "Select a finding"; empty.append(strong, document.createTextNode(noFindings ? `The current deterministic rules found no issues in this ${subject}.` : "Select a row to inspect its evidence and remediation.")); detail.append(empty); return; }
  const content = document.createElement("div"); content.className = "evidence-content";
  const topline = document.createElement("div"); topline.className = "evidence-topline";
  const severity = document.createElement("span"); severity.className = `severity-badge ${finding.severity}`; severity.textContent = finding.severity;
  const rule = document.createElement("div"); rule.className = "evidence-rule"; rule.textContent = finding.id;
  topline.append(severity, rule);
  const title = document.createElement("h3"); title.className = "evidence-title"; title.textContent = finding.title;
  const service = document.createElement("div"); service.className = "evidence-service"; service.textContent = `service:${finding.service}`;
  const remediation = detailBlock("Remediation", finding.remediation, "remediation-copy"); remediation.className = "remediation-callout";
  const limitations = detailBlock("Limitations & assumptions", finding.limitations, "detail-copy"); limitations.className = "limitations-callout";
  content.append(
    topline,
    title,
    service,
    detailBlock("What the configuration does", finding.explanation),
    detailBlock("Potential impact", finding.impact),
    detailBlock("Evidence", finding.evidence, "evidence-copy", "pre"),
    remediation,
    limitations,
  ); detail.append(content);
}

function renderFindings(report) {
  const findings = Array.isArray(report && report.findings) ? report.findings : [];
  const body = document.getElementById("findings-table-body"); body.replaceChildren();
  setText("findings-count", `${findings.length} result${findings.length === 1 ? "" : "s"}`);
  selectedFindingIndex = Math.min(selectedFindingIndex, Math.max(findings.length - 1, 0));
  if (findings.length === 0) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.className = "empty-row"; cell.colSpan = 4; cell.textContent = reportSource === "upload" ? "No findings detected in this uploaded file." : "No findings detected in this fixture."; row.append(cell); body.append(row); renderFindingDetail(null); return; }
  findings.forEach((finding, index) => {
    const row = document.createElement("tr"); row.className = `finding-row${index === selectedFindingIndex ? " selected" : ""}`; row.tabIndex = 0; row.setAttribute("aria-selected", index === selectedFindingIndex ? "true" : "false");
    const severityCell = document.createElement("td"); severityCell.className = "severity-cell"; const badge = document.createElement("span"); badge.className = `severity-badge ${finding.severity}`; badge.textContent = finding.severity; severityCell.append(badge);
    const rule = document.createElement("td"); rule.className = "rule-id"; rule.textContent = finding.id;
    const service = document.createElement("td"); service.className = "service-id"; service.textContent = finding.service;
    const title = document.createElement("td"); title.className = "finding-title"; title.textContent = finding.title;
    row.append(severityCell, rule, service, title);
    const renderedReport = currentReport;
    const selectRow = () => { if (currentReport !== renderedReport) return; selectedFindingIndex = index; renderFindings(renderedReport); };
    row.addEventListener("click", selectRow); row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectRow(); } }); body.append(row);
  });
  renderFindingDetail(findings[selectedFindingIndex]);
}

function renderAttackPaths(report) {
  const container = document.getElementById("attack-content"); const paths = Array.isArray(report && report.attack_paths) ? report.attack_paths : []; container.replaceChildren();
  if (paths.length === 0) { const empty = document.createElement("div"); empty.className = "empty-state"; const strong = document.createElement("strong"); strong.textContent = "No correlated attack paths"; const subject = reportSource === "upload" ? "uploaded file" : "selected fixture"; empty.append(strong, document.createTextNode(`The ${subject} does not trigger the current deterministic correlation.`)); container.append(empty); return; }
  paths.forEach((path) => {
    const card = document.createElement("article"); card.className = "path-card";
    const header = document.createElement("div"); header.className = "path-header";
    const id = document.createElement("div"); id.className = "correlation-id"; id.textContent = `Deterministic correlation: ${path.id}`;
    const classification = document.createElement("div"); classification.className = "correlation-id"; classification.textContent = `Classification: ${path.classification || "deterministic_hypothetical_correlation"}`;
    header.append(id, classification);
    const title = document.createElement("h3"); title.className = "path-title"; title.textContent = path.title;
    const service = document.createElement("div"); service.className = "path-service"; service.textContent = `service:${path.service}`;
    const steps = document.createElement("ol"); steps.className = "path-steps";
    (Array.isArray(path.steps) ? path.steps : []).forEach((step, index) => { const item = document.createElement("li"); item.className = "path-step"; const number = document.createElement("span"); number.className = "path-step-number"; number.textContent = String(index + 1).padStart(2, "0"); const copy = document.createElement("span"); copy.className = "path-step-copy"; copy.textContent = step; item.append(number, copy); steps.append(item); });
    const foot = document.createElement("div"); foot.className = "path-foot";
    const impactWrap = document.createElement("div"); const impactLabel = document.createElement("div"); impactLabel.className = "detail-label"; impactLabel.textContent = "Impact framing"; const impact = document.createElement("p"); impact.textContent = path.impact; impactWrap.append(impactLabel, impact);
    const remediationWrap = document.createElement("div"); const remediationLabel = document.createElement("div"); remediationLabel.className = "detail-label"; remediationLabel.textContent = "Remediation"; const remediation = document.createElement("p"); remediation.textContent = path.remediation; remediationWrap.append(remediationLabel, remediation);
    const limitationsWrap = document.createElement("div"); const limitationsLabel = document.createElement("div"); limitationsLabel.className = "detail-label"; limitationsLabel.textContent = "Limitations"; const limitations = document.createElement("p"); limitations.textContent = path.limitations || "This is a bounded static correlation, not proof of exploitation."; limitationsWrap.append(limitationsLabel, limitations);
    foot.append(impactWrap, remediationWrap, limitationsWrap); card.append(header, title, service, steps, foot); container.append(card);
  });
}

function createComparisonRow(label, vulnerable, remediated) {
  const row = document.createElement("tr"); const labelCell = document.createElement("td"); labelCell.textContent = label; const vulnerableCell = document.createElement("td"); vulnerableCell.className = "comparison-value"; vulnerableCell.textContent = String(vulnerable); const remediatedCell = document.createElement("td"); remediatedCell.className = "comparison-value"; remediatedCell.textContent = String(remediated); const deltaCell = document.createElement("td"); const delta = remediated - vulnerable; deltaCell.className = `comparison-delta ${delta < 0 ? "reduction" : delta > 0 ? "increase" : "stable"}`; deltaCell.textContent = delta === 0 ? "No change" : `${delta > 0 ? "+" : ""}${delta}`; row.append(labelCell, vulnerableCell, remediatedCell, deltaCell); return row;
}

function renderComparison() {
  const body = document.getElementById("comparison-table-body"); body.replaceChildren();
  if (!reports.vulnerable || !reports.remediated) { setText("comparison-result", reportSource === "upload" ? "Fixture baseline unavailable" : "Awaiting fixture pair"); setText("comparison-result-detail", reportSource === "upload" ? "Uploaded results are shown separately; both built-in fixtures are required for this baseline." : "Both built-in fixture reports are required."); const row = document.createElement("tr"); const cell = document.createElement("td"); cell.className = "empty-row"; cell.colSpan = 4; cell.textContent = "No fixture comparison available yet. Uploaded results are never used as a fabricated baseline."; row.append(cell); body.append(row); return; }
  const vulnerableCounts = severityCounts(reports.vulnerable); const remediatedCounts = severityCounts(reports.remediated); const findingDelta = remediatedCounts.total - vulnerableCounts.total;
  const comparisonPrefix = reportSource === "upload" ? "Built-in fixtures: " : "";
  setText("comparison-result", `${comparisonPrefix}${findingDelta < 0 ? `${Math.abs(findingDelta)} findings resolved` : findingDelta > 0 ? `${findingDelta} findings added` : "No finding change"}`); setText("comparison-result-detail", `Vulnerable fixture ${vulnerableCounts.total} → Remediated fixture ${remediatedCounts.total} findings · ${vulnerableCounts.paths} → ${remediatedCounts.paths} paths`);
  body.append(createComparisonRow("Total findings", vulnerableCounts.total, remediatedCounts.total), createComparisonRow("High severity", vulnerableCounts.high, remediatedCounts.high), createComparisonRow("Medium severity", vulnerableCounts.medium, remediatedCounts.medium), createComparisonRow("Attack paths", vulnerableCounts.paths, remediatedCounts.paths));
}

function updateFixtureContext(fixture) { setText("current-fixture-label", fixture === "vulnerable" ? "Vulnerable fixture" : "Remediated fixture"); setText("source-file", `fixtures/compose.${fixture}.yml`); setText("summary-copy", "Local static analysis of the selected Compose fixture."); }
function updateUploadContext(file, state = "Uploaded YAML") { setText("current-fixture-label", state); setText("source-file", file.name); setText("summary-copy", "Local static analysis of an uploaded Compose YAML file."); }

async function loadReports() {
  clearError(); clearDisplayedReport(); const operation = activeOperation; setLoading(true); const selected = fixtureSelect.value; updateFixtureContext(selected);
  try {
    const fixtureReports = await fetchFixtureReports();
    if (!isCurrentOperation(operation)) return;
    reports = fixtureReports; currentReport = reports[selected]; reportSource = "fixture"; selectedFindingIndex = 0;
    renderMetrics(currentReport, true); renderFindings(currentReport); renderAttackPaths(currentReport); renderComparison();
    setText("analysis-status", `${selected} fixture analyzed locally`); setText("overview-status", "Report loaded, rules evaluated deterministically"); setText("topbar-status", "Local analysis complete");
  } catch (error) {
    if (!isCurrentOperation(operation)) return;
    currentReport = null; reports = { vulnerable: null, remediated: null }; reportSource = "none"; showError(error instanceof Error ? error.message : "The local analysis request failed."); clearDisplayedReport({ invalidate: false });
  }
  finally { if (isCurrentOperation(operation)) setLoading(false); }
}

async function loadUploadedReport() {
  const file = composeFile.files[0];
  if (!file) { showError("Choose a .yml or .yaml file first."); return; }
  if (file.size > MAX_UPLOAD_BYTES) { showError("Selected file exceeds the 1 MiB limit."); return; }
  clearError(); clearDisplayedReport({ clearFixtures: false }); const operation = activeOperation; setLoading(true); fixtureSelect.disabled = true; composeFile.disabled = true; uploadButton.disabled = true; uploadButton.textContent = "Uploading...";
  try {
    const report = await fetchUploadReport(file);
    if (!isCurrentOperation(operation)) return;
    if (!reports.vulnerable || !reports.remediated) reports = await fetchFixtureReports();
    if (!isCurrentOperation(operation)) return;
    currentReport = report; reportSource = "upload"; selectedFindingIndex = 0;
    renderMetrics(currentReport, true); renderFindings(currentReport); renderAttackPaths(currentReport); renderComparison();
    updateUploadContext(file); setText("analysis-status", "Uploaded file analyzed locally"); setText("overview-status", "Uploaded report is separate from the built-in fixture baseline"); setText("topbar-status", "Uploaded analysis complete");
  } catch (error) {
    if (!isCurrentOperation(operation)) return;
    currentReport = null; reportSource = "none"; showError(error instanceof Error ? error.message : "The upload analysis request failed."); clearDisplayedReport({ invalidate: false, clearFixtures: false }); updateUploadContext(file, "Upload failed"); setText("summary-copy", "The uploaded Compose YAML was not analyzed."); setText("analysis-status", "Upload rejected"); setText("overview-status", "No uploaded report is displayed");
  } finally {
    if (isCurrentOperation(operation)) { setLoading(false); fixtureSelect.disabled = false; composeFile.disabled = false; uploadButton.textContent = "Analyze file"; uploadButton.disabled = !composeFile.files[0]; }
  }
}

function handleFileSelection() {
  const file = composeFile.files[0];
  if (!file) { uploadFilename.textContent = "No file selected"; uploadButton.disabled = true; clearError(); clearDisplayedReport({ clearFixtures: false }); setText("current-fixture-label", "No uploaded file"); setText("source-file", "No file selected"); setText("summary-copy", "Select a Compose YAML file or use a built-in fixture."); setText("analysis-status", "Waiting for analysis"); setText("overview-status", "No uploaded report is displayed"); return; }
  uploadFilename.textContent = file.name;
  uploadButton.disabled = false;
  clearError(); clearDisplayedReport({ clearFixtures: false });
  setText("current-fixture-label", "File selected"); setText("source-file", file.name); setText("summary-copy", "Ready to analyze the selected Compose YAML file."); setText("analysis-status", "Ready to analyze"); setText("overview-status", "Analyze file to load an uploaded report"); setText("topbar-status", "File selected");
}

function activateSection(section) { navItems.forEach((item) => item.classList.toggle("active", item.dataset.section === section)); }
navItems.forEach((item) => item.addEventListener("click", () => { const target = document.getElementById(`section-${item.dataset.section}`); if (target) { activateSection(item.dataset.section); target.scrollIntoView({ behavior: "smooth", block: "start" }); } }));
fixtureSelect.addEventListener("change", loadReports); analyzeButton.addEventListener("click", loadReports); retryButton.addEventListener("click", loadReports); composeFile.addEventListener("change", handleFileSelection); uploadButton.addEventListener("click", loadUploadedReport); githubConnectButton.addEventListener("click", connectGitHub); githubDisconnectButton.addEventListener("click", disconnectGitHub); githubRepositorySelect.addEventListener("change", loadGitHubBranches); loadReports(); loadGitHubStatus();
