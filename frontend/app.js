const scanForm = document.querySelector("#scanForm");
const startBtn = document.querySelector("#startBtn");
const livePanel = document.querySelector("#livePanel");
const reportPanel = document.querySelector("#reportPanel");
const pdfBtn = document.querySelector("#pdfBtn");
const DEFAULT_BACKEND_URL = "http://localhost:8000";

let pollTimer = null;
let activeScanId = null;
let activeBackendUrl = DEFAULT_BACKEND_URL;
let stepSequence = [];
let latestReport = null;

const processNotes = {
  Queued: "The scan request is waiting to start.",
  "Starting scan": "The scan session is being prepared and the target configuration is being validated.",
  "Launching browser": "A controlled browser session is starting so the scan can observe the site like a real visitor would.",
  "Loading target page": "The target website is being loaded and the first server response is being inspected.",
  "Checking security headers": "The scanner is checking browser security controls like CSP, HSTS, clickjacking protection, and referrer policy.",
  "Analyzing cookies": "Cookies are being reviewed to understand whether they are safely configured.",
  "Discovering page elements": "Pages, forms, buttons, links, and inputs are being mapped as attack surface evidence.",
  "Testing open redirects": "The scanner is checking redirect-style parameters and safe redirect flows to see whether users can be sent to attacker-controlled domains.",
  "Open redirect testing complete": "Open redirect validation for this page is complete.",
  "Testing DOM-based XSS": "The scanner is testing client-side handling of attacker-controlled URL fragments to see whether browser scripts inject them into the page.",
  "DOM-based XSS testing complete": "Initial DOM-based XSS validation for this page is complete.",
  "Testing reflected XSS": "The scanner is testing query parameters and low-risk form flows to see whether HTML is reflected back unsafely.",
  "Reflected XSS testing complete": "Initial reflected XSS validation for this page is complete.",
  "Testing stored XSS": "The scanner is testing low-risk forms to see whether attacker-controlled HTML persists after submission and reload.",
  "Stored XSS testing complete": "Initial stored XSS validation for this page is complete.",
  "Testing SQL injection": "The scanner is looking for database error leakage and strong response anomalies from low-risk input payloads.",
  "SQL injection testing complete": "Initial SQL injection validation for this page is complete.",
  "Interacting with target page": "The scanner is safely interacting with non-destructive controls to reveal hidden workflows and network calls.",
  "Validating SSL certificate": "The TLS certificate is being checked for validity and expiry.",
  "Probing sensitive paths": "Common sensitive paths are being checked for accidental exposure.",
  "Analyzing CORS security": "Cross-origin browser trust behavior is being tested.",
  "Scanning JavaScript for secrets": "First-party JavaScript files and inline scripts are being checked for exposed keys, tokens, and credentials.",
  "JavaScript secret scan complete": "JavaScript secret exposure analysis is complete.",
  "Scan complete": "The scan is complete and the report is being prepared."
};

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearReport();

  const targetUrl = document.querySelector("#targetUrl").value.trim();
  activeBackendUrl = DEFAULT_BACKEND_URL;
  const maxPages = Number(document.querySelector("#maxPages").value || 20);
  const maxDepth = Number(document.querySelector("#maxDepth").value || 2);

  startBtn.disabled = true;
  startBtn.textContent = "Starting scan...";
  livePanel.classList.remove("hidden");
  updateLiveStatus({
    status: "Queued",
    current_step: "Queued",
    live_metrics: {},
    events_log: { recent: [] }
  });

  try {
    const response = await fetch(`${activeBackendUrl}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: targetUrl,
        headless: true,
        max_pages: maxPages,
        max_depth: maxDepth
      })
    });

    if (!response.ok) {
      throw new Error(await response.text());
    }

    const job = await response.json();
    activeScanId = job.scan_id;
    pollTimer = window.setInterval(pollScanStatus, 1800);
    await pollScanStatus();
  } catch (error) {
    showFatalError(error);
  }
});

pdfBtn.addEventListener("click", () => {
  printCleanReport();
});

async function pollScanStatus() {
  if (!activeScanId) return;

  try {
    const response = await fetch(`${activeBackendUrl}/scan/status/${activeScanId}?readable=true`);
    if (!response.ok) {
      throw new Error(await response.text());
    }

    const payload = await response.json();
    if (payload.scan_metadata && payload.executive_summary) {
      window.clearInterval(pollTimer);
      pollTimer = null;
      startBtn.disabled = false;
      startBtn.textContent = "Start Security Scan";
      renderReport(payload);
      return;
    }

    updateLiveStatus(payload);
  } catch (error) {
    window.clearInterval(pollTimer);
    pollTimer = null;
    showFatalError(error);
  }
}

function updateLiveStatus(payload) {
  const rawStep = payload.current_step || "Queued";
  const status = String(payload.status || "Queued").replace(/^[^A-Za-z]*/, "").trim() || "Queued";
  const metrics = payload.live_metrics || {};

  document.querySelector("#liveTitle").textContent = rawStep;
  document.querySelector("#scanStatus").textContent = status;
  document.querySelector("#pagesMetric").textContent = metrics.pages_crawled || 0;
  document.querySelector("#formsMetric").textContent = metrics.forms_found || 0;
  document.querySelector("#inputsMetric").textContent = metrics.inputs_discovered || 0;
  document.querySelector("#apiMetric").textContent = metrics.api_calls_captured || 0;
  document.querySelector("#findingsMetric").textContent = metrics.findings_so_far || 0;
  document.querySelector("#plainProgress").textContent = processNotes[rawStep] || payload.progress_note || "The scanner is processing the target and collecting evidence.";

  rememberStep(rawStep, processNotes[rawStep] || payload.progress_note || "Security scan step completed.");
  const recent = payload.events_log?.recent || [];
  recent.slice(-4).forEach((event) => {
    const entry = describeEvent(event);
    if (entry) {
      rememberStep(entry.title, entry.detail);
    }
  });

  renderSteps();
  setProgress(rawStep, metrics);
}

function rememberStep(title, detail) {
  const cleanTitle = String(title || "Scan activity").replace(/^[^A-Za-z]*/, "").trim();
  const cleanDetail = String(detail || "").replace(/^[^A-Za-z]*/, "").trim();
  const key = `${cleanTitle}:${cleanDetail}`;

  if (stepSequence.some((item) => item.key === key)) return;
  stepSequence.push({ key, title: cleanTitle, detail: cleanDetail });
  if (stepSequence.length > 14) {
    stepSequence = stepSequence.slice(stepSequence.length - 14);
  }
}

function renderSteps() {
  const list = document.querySelector("#stepList");
  list.innerHTML = "";
  stepSequence.forEach((step, index) => {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="step-dot">${index + 1}</div>
      <div>
        <strong>${escapeHtml(step.title)}</strong>
        <span>${escapeHtml(step.detail)}</span>
      </div>
    `;
    list.appendChild(li);
  });
}

function setProgress(step, metrics) {
  const knownSteps = Object.keys(processNotes);
  const index = Math.max(0, knownSteps.indexOf(step));
  const pageFactor = Math.min(25, Number(metrics.pages_crawled || 0));
  const stepFactor = index >= 0 ? ((index + 1) / knownSteps.length) * 75 : 10;
  const progress = Math.min(96, Math.max(8, stepFactor + pageFactor));
  document.querySelector("#progressBar").style.width = `${progress}%`;
}

function renderReport(report) {
  latestReport = report;
  reportPanel.classList.remove("hidden");
  document.querySelector("#progressBar").style.width = "100%";

  const meta = report.scan_metadata || {};
  const summary = report.executive_summary || {};
  const risk = summary.risk_rating || "Informational";
  const scope = summary.scope || {};

  document.querySelector("#reportTarget").textContent = meta.target || "Security Assessment";
  document.querySelector("#reportDate").textContent = `Completed at ${meta.scan_completed_at || new Date().toLocaleString()}`;
  const riskBadge = document.querySelector("#riskBadge");
  riskBadge.textContent = `Risk: ${risk}`;
  riskBadge.dataset.risk = risk;
  document.querySelector("#summaryText").textContent = summary.summary || "Security scan completed. Review the findings and recommended actions below.";

  renderScope(scope, summary.finding_counts || {});
  renderTopRisks(summary.top_risks || []);
  renderAttackSurface(report.attack_surface_analysis || {});
  renderControls(report.security_analysis || {});
  renderFindings(report.findings || []);

  reportPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderScope(scope, counts) {
  const grid = document.querySelector("#scopeGrid");
  const cards = [
    ["Pages crawled", scope.pages_crawled || 0],
    ["Forms found", scope.forms_discovered || 0],
    ["Inputs found", scope.input_fields_found || 0],
    ["Network requests", scope.network_requests_captured || 0],
    ["Medium+ findings", (counts.Critical || 0) + (counts.High || 0) + (counts.Medium || 0)]
  ];
  grid.innerHTML = cards.map(([label, value]) => `
    <div><strong>${value}</strong><span>${label}</span></div>
  `).join("");
}

function renderTopRisks(risks) {
  const root = document.querySelector("#topRisks");
  if (!risks.length) {
    root.innerHTML = `<div class="finding-card"><h4>No high-priority findings</h4><p>No urgent automated findings were detected in this scan.</p></div>`;
    return;
  }
  root.innerHTML = risks.map((risk) => `
    <div class="finding-card" data-severity="${escapeHtml(risk.severity || "Info")}">
      <h4>${escapeHtml(risk.title || "Security finding")}</h4>
      <div class="finding-meta">
        <span class="${severityClass(risk.severity)}">${escapeHtml(risk.severity || "Info")}</span>
        <span>${escapeHtml(risk.priority || "Review")}</span>
      </div>
      <p><strong>Why it matters:</strong> ${escapeHtml(risk.impact || "This issue should be reviewed in application context.")}</p>
    </div>
  `).join("");
}

function renderAttackSurface(surface) {
  const pages = surface.pages || {};
  const inputs = surface.inputs || {};
  const network = surface.network || {};
  const counts = network.counts || {};
  document.querySelector("#attackSurface").innerHTML = `
    <div class="evidence-card">
      <h4>Application Surface</h4>
      <p>${pages.count || 0} unique pages were crawled. ${inputs.total || 0} input fields were discovered, including ${inputs.file_inputs || 0} file input(s) and ${inputs.hidden_inputs || 0} hidden input(s).</p>
      <p>The report summarizes attack surface by evidence type so stakeholders can understand exposure without getting buried in raw crawl output.</p>
    </div>
    <div class="evidence-card">
      <h4>Network Evidence</h4>
      <p>Captured requests were separated so tracking, static assets, and possible application endpoints do not get mixed together.</p>
      <code>First-party API-like: ${counts.first_party_api || 0}
First-party pages: ${counts.first_party_pages || 0}
Static assets: ${counts.first_party_static || 0}
Tracking/analytics: ${counts.tracking_or_analytics || 0}
Third-party services: ${counts.third_party_service || 0}</code>
    </div>
  `;
}

function renderControls(analysis) {
  const headers = analysis.headers || {};
  const ssl = analysis.ssl || {};
  const cookies = analysis.cookies || {};
  const javascriptSecrets = analysis.javascript_secrets || {};
  const domXss = analysis.dom_xss || {};
  const openRedirect = analysis.open_redirect || {};
  const reflectedXss = analysis.reflected_xss || {};
  const storedXss = analysis.stored_xss || {};
  const sqlInjection = analysis.sql_injection || {};
  const sensitive = analysis.sensitive_paths || {};
  const cors = analysis.cors || {};
  const missingHeaders = headers.missing || [];
  const notableCookies = cookies.notable_cookies || [];
  const secretDetections = javascriptSecrets.top_detections || [];
  const domXssVectors = domXss.vectors || [];
  const redirectVectors = openRedirect.vectors || [];
  const xssVectors = reflectedXss.vectors || [];
  const storedXssVectors = storedXss.vectors || [];
  const sqliVectors = sqlInjection.vectors || [];
  const exposedPaths = sensitive.exposed_paths || [];
  const blockedPaths = sensitive.blocked_paths || [];

  document.querySelector("#controlAnalysis").innerHTML = `
    <div class="finding-card" data-severity="Medium">
      <h4>Security Headers</h4>
      <p><strong>Status:</strong> ${escapeHtml(headers.status || "Not available")}</p>
      <p><strong>Impact:</strong> Missing browser protections can increase exposure to XSS impact, clickjacking, MIME sniffing, referrer leakage, and HTTPS downgrade risk.</p>
      <code>${escapeHtml(missingHeaders.map((item) => `${item.header}: ${item.impact}`).join("\n") || "No missing required headers reported")}</code>
    </div>
    <div class="finding-card" data-severity="Low">
      <h4>SSL And Cookies</h4>
      <p><strong>SSL:</strong> ${escapeHtml(ssl.status || "Not available")} - ${escapeHtml(ssl.note || "")}</p>
      <p><strong>Cookies:</strong> ${escapeHtml(cookies.status || "Not available")}</p>
      <code>${escapeHtml(notableCookies.map((item) => `${item.name} [${item.category}]: ${item.issue_summary}`).join("\n") || "No notable cookie issues reported")}</code>
    </div>
    <div class="finding-card" data-severity="${secretDetections.length ? "High" : "Low"}">
      <h4>JavaScript Secret Exposure</h4>
      <p><strong>Status:</strong> ${escapeHtml(javascriptSecrets.status || "Not available")}</p>
      <p><strong>Coverage:</strong> ${javascriptSecrets.scanned_files || 0} JavaScript file(s) and ${javascriptSecrets.scanned_inline_pages || 0} page(s) with inline scripts reviewed.</p>
      <code>${escapeHtml(secretDetections.map((item) => `${item.type} - ${item.source} - ${item.value_preview}`).join("\n") || "No JavaScript secret exposure detected")}</code>
    </div>
    <div class="finding-card" data-severity="${domXssVectors.length ? "High" : "Low"}">
      <h4>DOM-Based XSS Validation</h4>
      <p><strong>Status:</strong> ${escapeHtml(domXss.status || "Not available")}</p>
      <p><strong>Impact:</strong> DOM-based XSS happens in browser-side code and can execute without the server reflecting the payload.</p>
      <code>${escapeHtml(domXssVectors.map((item) => `${item.vector} - ${item.tested_url}`).join("\n") || "No DOM-based XSS detected in the tested fragment flows")}</code>
    </div>
    <div class="finding-card" data-severity="${redirectVectors.length ? "High" : "Low"}">
      <h4>Open Redirect Validation</h4>
      <p><strong>Status:</strong> ${escapeHtml(openRedirect.status || "Not available")}</p>
      <p><strong>Impact:</strong> Redirect abuse can turn a trusted domain into a phishing or token-forwarding step in an attack chain.</p>
      <code>${escapeHtml(redirectVectors.map((item) => `${item.vector} - ${item.tested_url} -> ${item.redirect_target}`).join("\n") || "No open redirect detected in the tested flows")}</code>
    </div>
    <div class="finding-card" data-severity="${xssVectors.length ? "High" : "Low"}">
      <h4>Reflected XSS Validation</h4>
      <p><strong>Status:</strong> ${escapeHtml(reflectedXss.status || "Not available")}</p>
      <p><strong>Impact:</strong> Unsanitized reflection can enable browser-side script execution, phishing overlays, and session compromise.</p>
      <code>${escapeHtml(xssVectors.map((item) => `${item.vector} - ${item.tested_url}`).join("\n") || "No reflected XSS detected in the tested parameters and forms")}</code>
    </div>
    <div class="finding-card" data-severity="${storedXssVectors.length ? "High" : "Low"}">
      <h4>Stored XSS Validation</h4>
      <p><strong>Status:</strong> ${escapeHtml(storedXss.status || "Not available")}</p>
      <p><strong>Impact:</strong> Stored XSS can affect every user who later views the injected record or page.</p>
      <code>${escapeHtml(storedXssVectors.map((item) => `${item.vector} - ${item.tested_url}`).join("\n") || "No stored XSS detected in the tested low-risk forms")}</code>
    </div>
    <div class="finding-card" data-severity="${sqliVectors.length ? "High" : "Low"}">
      <h4>SQL Injection Validation</h4>
      <p><strong>Status:</strong> ${escapeHtml(sqlInjection.status || "Not available")}</p>
      <p><strong>Impact:</strong> SQL injection can expose database content, modify records, or support authentication bypass and wider compromise.</p>
      <code>${escapeHtml(sqliVectors.map((item) => `${item.vector} - ${item.tested_url} - ${item.evidence}`).join("\n") || "No SQL injection evidence detected in the tested low-risk flows")}</code>
    </div>
    <div class="finding-card" data-severity="${exposedPaths.length ? "Medium" : "Low"}">
      <h4>Sensitive Paths</h4>
      <p>${exposedPaths.length} readable path(s), ${blockedPaths.length} blocked/detected path(s).</p>
      <p><strong>Important:</strong> HTTP 403 means blocked, not confirmed exposure. Readable paths require faster action.</p>
      <code>${escapeHtml(exposedPaths.concat(blockedPaths).slice(0, 10).map((item) => `${item.path} - HTTP ${item.http_status} - ${item.severity}`).join("\n") || "No sensitive path evidence reported")}</code>
    </div>
    <div class="finding-card" data-severity="${(cors.status || "").includes("High") ? "High" : (cors.status || "").includes("Medium") ? "Medium" : "Low"}">
      <h4>CORS</h4>
      <p><strong>Status:</strong> ${escapeHtml(cors.status || "Not available")}</p>
      <p>${escapeHtml(cors.engineer_summary || "No CORS summary available.")}</p>
    </div>
  `;
}

function renderFindings(findings) {
  const root = document.querySelector("#findingDetails");
  if (!findings.length) {
    root.innerHTML = `<div class="finding-card"><h4>No actionable findings</h4><p>The scan did not identify actionable findings. Authenticated and active validation testing is still recommended for enterprise assurance.</p></div>`;
    return;
  }

  root.innerHTML = findings.map((finding) => `
    <div class="finding-card" data-severity="${escapeHtml(finding.severity || "Info")}">
      <h4>${escapeHtml(finding.title || "Security finding")}</h4>
      <div class="finding-meta">
        <span class="${severityClass(finding.severity)}">${escapeHtml(finding.severity || "Info")}</span>
        <span>${escapeHtml(finding.priority || "Review")}</span>
        <span>Confidence: ${escapeHtml(finding.confidence || "Medium")}</span>
      </div>
      <p><strong>Impact:</strong> ${escapeHtml(finding.impact || "Review this finding in application context.")}</p>
      <p><strong>Evidence:</strong></p>
      <code>${escapeHtml(finding.evidence_summary || "Evidence not available")}</code>
      <p><strong>Actionable fix:</strong> ${escapeHtml(finding.remediation || "Validate and remediate according to security standards.")}</p>
    </div>
  `).join("");
}

function clearReport() {
  reportPanel.classList.add("hidden");
  stepSequence = [];
}

function showFatalError(error) {
  startBtn.disabled = false;
  startBtn.textContent = "Start Security Scan";
  livePanel.classList.remove("hidden");
  document.querySelector("#liveTitle").textContent = "Scan could not continue";
  document.querySelector("#scanStatus").textContent = "Failed";
  document.querySelector("#plainProgress").textContent = "The scan could not reach the local backend service. Confirm uvicorn is running on port 8000 and then try again.";
  rememberStep("Error", error.message || String(error));
  renderSteps();
}

function describeEvent(event) {
  const phase = String(event.phase || "").toLowerCase();
  const detail = event.detail || {};
  const message = cleanEventMessage(event.message || "Evidence collected during scan.");

  if (phase === "discovery") {
    if (message === "Form discovered") {
      return {
        title: "Form discovered",
        detail: `${safeMethod(detail.method)} form on ${compactUrl(detail.url || detail.action || detail.source_url)}`
      };
    }
    if (message === "Input discovered") {
      return {
        title: "Input discovered",
        detail: `${detail.input_type || "text"} field${detail.required ? " (required)" : ""} on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Textarea discovered") {
      return {
        title: "Textarea discovered",
        detail: `Free-text input on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Button discovered") {
      return {
        title: "Button discovered",
        detail: `${detail.button || "Unnamed button"} on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Internal link discovered") {
      return {
        title: "Page queued for crawl",
        detail: compactUrl(detail.discovered_url || detail.url)
      };
    }
  }

  if (phase === "network") {
    return {
      title: "Network request observed",
      detail: `${detail.method || "GET"} ${friendlyResourceType(detail.resource_type)} ${compactUrl(detail.url)}`
    };
  }

  if (phase === "interaction") {
    if (message === "Input filled") {
      return {
        title: "Input exercised",
        detail: `${detail.input_type || "field"} field populated on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Textarea filled") {
      return {
        title: "Textarea exercised",
        detail: `Text area populated on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Checkbox clicked") {
      return {
        title: "Checkbox tested",
        detail: `Checkbox interaction completed on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Radio selected") {
      return {
        title: "Option selected",
        detail: `Radio option selected on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Select option chosen") {
      return {
        title: "Dropdown exercised",
        detail: `Selected value ${detail.value || "test option"} on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Button clicked" || message === "Clicking button") {
      return {
        title: "Button interaction",
        detail: `${detail.button || "Action button"} on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Skipping destructive button") {
      return {
        title: "Safety control applied",
        detail: `Skipped potentially destructive button: ${detail.button || "unknown"}`
      };
    }
    if (message === "API request discovered after button click") {
      return {
        title: "Application endpoint observed",
        detail: compactUrl(detail.url)
      };
    }
  }

  if (phase === "xss") {
    if (message === "Testing reflected XSS via query parameter") {
      return {
        title: "XSS parameter test",
        detail: `${detail.parameter || "query"} tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Testing reflected XSS via safe form") {
      return {
        title: "XSS form test",
        detail: `${detail.form_method || "GET"} form tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Potential reflected XSS detected") {
      return {
        title: "Potential reflected XSS detected",
        detail: `${detail.parameter || detail.form_action || "reflected input"} on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Potential reflected XSS detected after form submission") {
      return {
        title: "Potential reflected XSS detected",
        detail: `Form response reflected HTML on ${compactUrl(detail.url)}`
      };
    }
    if (message === "XSS query-parameter test skipped" || message === "XSS form test skipped") {
      return {
        title: "XSS test skipped",
        detail: `${detail.error || "Scanner moved on to keep the assessment safe."}`
      };
    }
  }

  if (phase === "redirect") {
    if (message === "Testing open redirect parameter") {
      return {
        title: "Open redirect test",
        detail: `${detail.parameter || "redirect"} tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Testing open redirect form") {
      return {
        title: "Open redirect form test",
        detail: `${detail.form_method || "GET"} redirect flow tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Potential open redirect detected") {
      return {
        title: "Potential open redirect detected",
        detail: `${compactUrl(detail.url)} redirects to ${compactUrl(detail.redirect_target)}`
      };
    }
    if (message === "Open redirect test skipped" || message === "Open redirect form test skipped") {
      return {
        title: "Open redirect test skipped",
        detail: `${detail.error || "Scanner moved on to keep the assessment safe."}`
      };
    }
  }

  if (phase === "dom_xss") {
    if (message === "Testing DOM-based XSS via URL fragment") {
      return {
        title: "DOM XSS test",
        detail: `Fragment payload tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Potential DOM-based XSS detected") {
      return {
        title: "Potential DOM-based XSS detected",
        detail: `${compactUrl(detail.url)} rendered fragment input into the DOM`
      };
    }
    if (message === "DOM-based XSS test skipped") {
      return {
        title: "DOM XSS test skipped",
        detail: `${detail.error || "Scanner moved on to keep the assessment safe."}`
      };
    }
  }

  if (phase === "stored_xss") {
    if (message === "Testing stored XSS via low-risk form") {
      return {
        title: "Stored XSS test",
        detail: `Low-risk form tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Potential stored XSS detected") {
      return {
        title: "Potential stored XSS detected",
        detail: `${compactUrl(detail.url)} showed payload persistence after reload`
      };
    }
    if (message === "Stored XSS test skipped") {
      return {
        title: "Stored XSS test skipped",
        detail: `${detail.error || "Scanner moved on to keep the assessment safe."}`
      };
    }
  }

  if (phase === "sqli") {
    if (message === "Testing SQL injection parameter") {
      return {
        title: "SQL injection test",
        detail: `${detail.parameter || "parameter"} tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Testing SQL injection via safe form") {
      return {
        title: "SQL injection form test",
        detail: `${detail.form_method || "GET"} form tested on ${compactUrl(detail.url)}`
      };
    }
    if (message === "Potential SQL injection detected") {
      return {
        title: "Potential SQL injection detected",
        detail: `${compactUrl(detail.url)} returned a database-style anomaly`
      };
    }
    if (message === "SQL injection form test skipped") {
      return {
        title: "SQL injection test skipped",
        detail: `${detail.error || "Scanner moved on to keep the assessment safe."}`
      };
    }
  }

  if (phase === "scan") {
    return {
      title: message,
      detail: buildScanDetail(message, detail)
    };
  }

  return {
    title: sentenceCase(phase || "Evidence"),
    detail: buildGenericDetail(message, detail)
  };
}

function cleanEventMessage(value) {
  return String(value || "")
    .replace(/^[^A-Za-z]+/, "")
    .trim();
}

function buildScanDetail(message, detail) {
  if (message === "Visiting page") {
    return `Depth ${detail.current_depth ?? "?"} page ${compactUrl(detail.current_url)}`;
  }
  if (message === "Page elements discovered") {
    return `Mapped forms, inputs, buttons, and links on ${compactUrl(detail.current_url)}`;
  }
  if (message === "Page interaction complete") {
    return `Completed safe interaction testing on ${compactUrl(detail.current_url)}`;
  }
  if (message === "Sensitive path probing complete") {
    return `${detail.sensitive_paths_found || 0} sensitive path signal(s) identified`;
  }
  if (message === "CORS analysis complete") {
    return `${detail.cors_issues_found || 0} CORS issue(s) flagged`;
  }
  if (message === "Cookies analyzed") {
    return `${detail.cookies_found || 0} cookies reviewed for security flags`;
  }
  return processNotes[message] || "Progress updated.";
}

function buildGenericDetail(message, detail) {
  const values = [];
  Object.entries(detail).forEach(([key, value]) => {
    if (value === null || value === undefined || value === "") return;
    if (key.toLowerCase().includes("url") || key === "action") {
      values.push(compactUrl(value));
      return;
    }
    values.push(`${sentenceCase(key.replaceAll("_", " "))}: ${value}`);
  });
  return values.length ? values.join(" | ") : message;
}

function compactUrl(value) {
  if (!value) return "the current page";
  try {
    const url = new URL(String(value));
    return `${url.hostname}${url.pathname || "/"}`;
  } catch {
    return String(value).replace(/^https?:\/\//, "");
  }
}

function safeMethod(value) {
  return String(value || "GET").toUpperCase();
}

function friendlyResourceType(value) {
  const type = String(value || "request").toLowerCase();
  const labels = {
    document: "document",
    fetch: "fetch",
    xhr: "XHR",
    script: "script",
    stylesheet: "stylesheet",
    image: "image",
    font: "font"
  };
  return labels[type] || type;
}

function sentenceCase(value) {
  const text = String(value || "").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Evidence";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function severityClass(severity) {
  return `sev-${String(severity || "info").toLowerCase()}`;
}

function printCleanReport() {
  const report = document.querySelector("#report");
  const styles = document.querySelector('link[rel="stylesheet"]');
  const stylesheetHref = styles ? new URL(styles.getAttribute("href"), window.location.href).href : "";
  const logoUrl = new URL("./assets/hit.png", window.location.href).href;
  const filename = buildPdfFilename();
  const printWindow = window.open("", "hit_secure_scan_report", "width=1100,height=900");

  if (!printWindow) {
    window.print();
    return;
  }

  const reportHtml = report.outerHTML.replaceAll("./assets/hit.png", logoUrl);
  printWindow.document.open();
  printWindow.document.write(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(filename)}</title>
  ${stylesheetHref ? `<link rel="stylesheet" href="${stylesheetHref}">` : ""}
</head>
<body class="print-body">
  <main class="print-shell">
    ${reportHtml}
  </main>
  <script>
    window.addEventListener("load", () => {
      setTimeout(() => {
        window.print();
      }, 250);
    });
  <\/script>
</body>
</html>`);
  printWindow.document.close();
}

function buildPdfFilename() {
  const target = latestReport?.scan_metadata?.target || document.querySelector("#targetUrl").value.trim() || "security-scan";
  const completedAt = latestReport?.scan_metadata?.scan_completed_at || new Date().toISOString();
  const stamp = formatTimestampForFilename(completedAt);
  return `${safeFilename(target)}_${stamp}`;
}

function formatTimestampForFilename(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "report";
  }

  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  return `${year}${month}${day}_${hours}${minutes}${seconds}`;
}

function safeFilename(value) {
  return String(value)
    .replace(/^https?:\/\//, "")
    .replace(/\/+$/, "")
    .replace(/[^a-z0-9.-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase() || "security-scan";
}
