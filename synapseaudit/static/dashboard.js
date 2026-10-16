"use strict";

const fixtureSelect = document.getElementById("fixture-select");
const analyzeButton = document.getElementById("analyze-button");
const retryButton = document.getElementById("retry-button");
const errorBanner = document.getElementById("error-banner");
const errorMessage = document.getElementById("error-message");
const statRow = document.getElementById("stat-row");
const topbarState = document.querySelector(".topbar-state");
const navItems = Array.from(document.querySelectorAll(".nav-item"));
let currentReport = null;
let reports = { vulnerable: null, remediated: null };
let selectedFindingIndex = 0;

function setText(id, value) { document.getElementById(id).textContent = String(value); }
function showError(message) { errorMessage.textContent = message; errorBanner.hidden = false; topbarState.classList.remove("is-busy"); topbarState.classList.add("is-error"); setText("topbar-status", "Analysis request failed"); setText("overview-status", "Request failed, retry available"); }
function clearError() { errorBanner.hidden = true; errorMessage.textContent = ""; topbarState.classList.remove("is-error"); }
function setLoading(loading) { analyzeButton.disabled = loading; analyzeButton.querySelector("span").textContent = loading ? "Analyzing..." : "Analyze"; topbarState.classList.toggle("is-busy", loading); if (loading) { statRow.classList.add("scanning"); setText("analysis-status", "Reading local analyzer"); setText("topbar-status", "Local analysis in progress"); } else { statRow.classList.remove("scanning"); } }

async function fetchReport(fixture) {
  const response = await fetch(`/api/analyze?fixture=${encodeURIComponent(fixture)}`, { headers: { Accept: "application/json" } });
  let payload;
  try { payload = await response.json(); } catch (error) { throw new Error("The local API returned an invalid response."); }
  if (!response.ok) throw new Error(payload.error || "The local analysis request failed.");
  return payload;
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
  function tick(now) { const progress = Math.min((now - started) / duration, 1); element.textContent = String(Math.round(target * progress)); if (progress < 1) requestAnimationFrame(tick); }
  requestAnimationFrame(tick);
}

function updateRiskRail(counts) {
  const total = counts.total || 0;
  [["high", counts.high], ["medium", counts.medium], ["low", counts.low]].forEach(([level, count]) => {
    setText(`risk-${level}-count`, count);
    document.getElementById(`risk-${level}-bar`).style.width = total ? `${(count / total) * 100}%` : "0%";
  });
}

function renderMetrics(report, animate = false) {
  const counts = severityCounts(report);
  updateRiskRail(counts);
  statRow.classList.remove("revealed");
  if (animate) { animateCount("metric-total", counts.total); animateCount("metric-high", counts.high, 340); animateCount("metric-medium", counts.medium, 420); animateCount("metric-paths", counts.paths, 500); } else { setText("metric-total", counts.total); setText("metric-high", counts.high); setText("metric-medium", counts.medium); setText("metric-paths", counts.paths); }
  requestAnimationFrame(() => statRow.classList.add("revealed"));
}

function renderFindingDetail(finding) {
  const detail = document.getElementById("finding-detail");
  detail.replaceChildren();
  if (!finding) { const empty = document.createElement("div"); empty.className = "empty-state"; const strong = document.createElement("strong"); const noFindings = !currentReport || !Array.isArray(currentReport.findings) || currentReport.findings.length === 0; strong.textContent = noFindings ? "No active findings" : "Select a finding"; empty.append(strong, document.createTextNode(noFindings ? "The current deterministic rules found no issues in this fixture." : "Select a row to inspect its evidence and remediation.")); detail.append(empty); return; }
  const content = document.createElement("div"); content.className = "evidence-content";
  const topline = document.createElement("div"); topline.className = "evidence-topline";
  const severity = document.createElement("span"); severity.className = `severity-badge ${finding.severity}`; severity.textContent = finding.severity;
  const rule = document.createElement("div"); rule.className = "evidence-rule"; rule.textContent = finding.id;
  topline.append(severity, rule);
  const title = document.createElement("h3"); title.className = "evidence-title"; title.textContent = finding.title;
  const service = document.createElement("div"); service.className = "evidence-service"; service.textContent = `service:${finding.service}`;
  const evidenceLabel = document.createElement("div"); evidenceLabel.className = "detail-label"; evidenceLabel.textContent = "Evidence";
  const evidence = document.createElement("pre"); evidence.className = "evidence-copy"; evidence.textContent = finding.evidence;
  const remediation = document.createElement("p"); remediation.className = "remediation-copy"; remediation.textContent = finding.remediation;
  const remediationLabel = document.createElement("div"); remediationLabel.className = "detail-label"; remediationLabel.textContent = "Remediation";
  const remediationCallout = document.createElement("div"); remediationCallout.className = "remediation-callout"; remediationCallout.append(remediationLabel, remediation);
  content.append(topline, title, service, evidenceLabel, evidence, remediationCallout); detail.append(content);
}

function renderFindings(report) {
  const findings = Array.isArray(report && report.findings) ? report.findings : [];
  const body = document.getElementById("findings-table-body"); body.replaceChildren();
  setText("findings-count", `${findings.length} result${findings.length === 1 ? "" : "s"}`);
  selectedFindingIndex = Math.min(selectedFindingIndex, Math.max(findings.length - 1, 0));
  if (findings.length === 0) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.className = "empty-row"; cell.colSpan = 4; cell.textContent = "No findings detected in this fixture."; row.append(cell); body.append(row); renderFindingDetail(null); return; }
  findings.forEach((finding, index) => {
    const row = document.createElement("tr"); row.className = `finding-row${index === selectedFindingIndex ? " selected" : ""}`; row.tabIndex = 0; row.setAttribute("aria-selected", index === selectedFindingIndex ? "true" : "false");
    const severityCell = document.createElement("td"); severityCell.className = "severity-cell"; const badge = document.createElement("span"); badge.className = `severity-badge ${finding.severity}`; badge.textContent = finding.severity; severityCell.append(badge);
    const rule = document.createElement("td"); rule.className = "rule-id"; rule.textContent = finding.id;
    const service = document.createElement("td"); service.className = "service-id"; service.textContent = finding.service;
    const title = document.createElement("td"); title.className = "finding-title"; title.textContent = finding.title;
    row.append(severityCell, rule, service, title);
    const selectRow = () => { selectedFindingIndex = index; renderFindings(currentReport); };
    row.addEventListener("click", selectRow); row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectRow(); } }); body.append(row);
  });
  renderFindingDetail(findings[selectedFindingIndex]);
}

function renderAttackPaths(report) {
  const container = document.getElementById("attack-content"); const paths = Array.isArray(report && report.attack_paths) ? report.attack_paths : []; container.replaceChildren();
  if (paths.length === 0) { const empty = document.createElement("div"); empty.className = "empty-state"; const strong = document.createElement("strong"); strong.textContent = "No correlated attack paths"; empty.append(strong, document.createTextNode("The selected fixture does not trigger the current deterministic correlation.")); container.append(empty); return; }
  paths.forEach((path) => {
    const card = document.createElement("article"); card.className = "path-card";
    const header = document.createElement("div"); header.className = "path-header";
    const id = document.createElement("div"); id.className = "correlation-id"; id.textContent = `Deterministic correlation: ${path.id}`;
    header.append(id);
    const title = document.createElement("h3"); title.className = "path-title"; title.textContent = path.title;
    const service = document.createElement("div"); service.className = "path-service"; service.textContent = `service:${path.service}`;
    const steps = document.createElement("ol"); steps.className = "path-steps";
    (Array.isArray(path.steps) ? path.steps : []).forEach((step, index) => { const item = document.createElement("li"); item.className = "path-step"; const number = document.createElement("span"); number.className = "path-step-number"; number.textContent = String(index + 1).padStart(2, "0"); const copy = document.createElement("span"); copy.className = "path-step-copy"; copy.textContent = step; item.append(number, copy); steps.append(item); });
    const foot = document.createElement("div"); foot.className = "path-foot";
    const impactWrap = document.createElement("div"); const impactLabel = document.createElement("div"); impactLabel.className = "detail-label"; impactLabel.textContent = "Impact framing"; const impact = document.createElement("p"); impact.textContent = path.impact; impactWrap.append(impactLabel, impact);
    const remediationWrap = document.createElement("div"); const remediationLabel = document.createElement("div"); remediationLabel.className = "detail-label"; remediationLabel.textContent = "Remediation"; const remediation = document.createElement("p"); remediation.textContent = path.remediation; remediationWrap.append(remediationLabel, remediation);
    foot.append(impactWrap, remediationWrap); card.append(header, title, service, steps, foot); container.append(card);
  });
}

function createComparisonRow(label, vulnerable, remediated) {
  const row = document.createElement("tr"); const labelCell = document.createElement("td"); labelCell.textContent = label; const vulnerableCell = document.createElement("td"); vulnerableCell.className = "comparison-value"; vulnerableCell.textContent = String(vulnerable); const remediatedCell = document.createElement("td"); remediatedCell.className = "comparison-value"; remediatedCell.textContent = String(remediated); const deltaCell = document.createElement("td"); const delta = remediated - vulnerable; deltaCell.className = `comparison-delta ${delta < 0 ? "reduction" : delta > 0 ? "increase" : "stable"}`; deltaCell.textContent = delta === 0 ? "No change" : `${delta > 0 ? "+" : ""}${delta}`; row.append(labelCell, vulnerableCell, remediatedCell, deltaCell); return row;
}

function renderComparison() {
  const body = document.getElementById("comparison-table-body"); body.replaceChildren();
  if (!reports.vulnerable || !reports.remediated) { setText("comparison-result", "Awaiting fixture pair"); setText("comparison-result-detail", "Both reports are required."); const row = document.createElement("tr"); const cell = document.createElement("td"); cell.className = "empty-row"; cell.colSpan = 4; cell.textContent = "Comparison unavailable until both reports load."; row.append(cell); body.append(row); return; }
  const vulnerableCounts = severityCounts(reports.vulnerable); const remediatedCounts = severityCounts(reports.remediated); const findingDelta = remediatedCounts.total - vulnerableCounts.total;
  setText("comparison-result", findingDelta < 0 ? `${Math.abs(findingDelta)} findings resolved` : findingDelta > 0 ? `${findingDelta} findings added` : "No finding change"); setText("comparison-result-detail", `${vulnerableCounts.total} → ${remediatedCounts.total} findings · ${vulnerableCounts.paths} → ${remediatedCounts.paths} paths`);
  body.append(createComparisonRow("Total findings", vulnerableCounts.total, remediatedCounts.total), createComparisonRow("High severity", vulnerableCounts.high, remediatedCounts.high), createComparisonRow("Medium severity", vulnerableCounts.medium, remediatedCounts.medium), createComparisonRow("Attack paths", vulnerableCounts.paths, remediatedCounts.paths));
}

function updateContext(fixture) { setText("current-fixture-label", fixture === "vulnerable" ? "Vulnerable fixture" : "Remediated fixture"); setText("source-file", `fixtures/compose.${fixture}.yml`); }

async function loadReports() {
  clearError(); setLoading(true); const selected = fixtureSelect.value; updateContext(selected);
  try {
    const [vulnerableReport, remediatedReport] = await Promise.all([fetchReport("vulnerable"), fetchReport("remediated")]);
    reports = { vulnerable: vulnerableReport, remediated: remediatedReport }; currentReport = reports[selected]; selectedFindingIndex = 0;
    renderMetrics(currentReport, true); renderFindings(currentReport); renderAttackPaths(currentReport); renderComparison();
    setText("analysis-status", `${selected} fixture analyzed locally`); setText("overview-status", "Report loaded, rules evaluated deterministically"); setText("topbar-status", "Local analysis complete");
  } catch (error) { currentReport = null; reports = { vulnerable: null, remediated: null }; showError(error instanceof Error ? error.message : "The local analysis request failed."); renderFindings(null); renderAttackPaths(null); renderComparison(); }
  finally { setLoading(false); }
}

function activateSection(section) { navItems.forEach((item) => item.classList.toggle("active", item.dataset.section === section)); }
navItems.forEach((item) => item.addEventListener("click", () => { const target = document.getElementById(`section-${item.dataset.section}`); if (target) { activateSection(item.dataset.section); target.scrollIntoView({ behavior: "smooth", block: "start" }); } }));
fixtureSelect.addEventListener("change", loadReports); analyzeButton.addEventListener("click", loadReports); retryButton.addEventListener("click", loadReports); loadReports();
