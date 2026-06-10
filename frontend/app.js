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
  "Detecting authentication surface": "The scanner is checking whether login, signup, password reset, or other authentication entry points exist in the public scope.",
  "Authentication surface detection complete": "The first auth-surface classification pass is complete.",
  "Refreshing authentication surface classification": "The auth-surface classification is being refreshed using the full set of discovered pages, forms, buttons, and API routes.",
  "Authentication coverage classification complete": "The scan has classified whether this looks like a public-only website or an application with auth features beyond the public surface.",
  "Scan workload estimated": "The scanner has finished counting pages and discovered workload, and the ETA is now locked from that full queue.",
  "Scanning discovered page": "The scanner is now working through the counted pages and running the active validation checks against that fixed scope.",
  "Checking HTTP methods": "The scanner is reviewing allowed HTTP methods and checking whether risky methods like TRACE are enabled.",
  "Checking server headers": "The scanner is reviewing whether the response leaks server, framework, or proxy banner details.",
  "Checking header regression": "The scanner is comparing the current header set against the last saved baseline to detect regressions.",
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
  "Validating SSL certificate": "The TLS certificate is being checked for validity, expiry, and transport hardening.",
  "Checking SSL expiry monitor": "The scanner is checking whether the certificate is nearing the configured renewal threshold.",
  "Checking domain posture": "The scanner is reviewing public domain posture signals such as parking indicators and recent registration age.",
  "Checking certificate transparency": "The scanner is pulling public certificate transparency records to inventory known subdomains.",
  "Checking new subdomains": "The scanner is comparing current certificate transparency records against the saved baseline to spot new subdomains.",
  "Checking subdomain takeover": "The scanner is checking discovered subdomains for dangling third-party hosting fingerprints.",
  "Checking DNSSEC": "The scanner is checking whether the public domain appears to publish DNSSEC records.",
  "Checking open ports": "The scanner is trying a short list of common public TCP ports to see whether extra services are exposed.",
  "Checking passive host intelligence": "The scanner is collecting passive public host intelligence to understand externally observed exposure.",
  "Checking domain credential leaks": "The scanner is checking public breach catalogs for domain-related exposure history.",
  "Probing sensitive paths": "Common sensitive paths are being checked for accidental exposure.",
  "Analyzing CORS security": "Cross-origin browser trust behavior is being tested.",
  "Analyzing CSRF risk": "The scanner is reviewing discovered forms for likely anti-CSRF protections and risky state-changing patterns.",
  "CSRF risk analysis complete": "Initial CSRF risk review is complete.",
  "Testing error handling": "The scanner is checking whether error responses leak stack traces, SQL errors, or debug details.",
  "Error handling analysis complete": "Error handling review is complete.",
  "Fingerprinting technology": "The scanner is identifying likely frameworks, CMS markers, server technologies, and API patterns.",
  "Technology fingerprinting complete": "Technology fingerprinting is complete.",
  "Checking GraphQL introspection": "The scanner is checking whether GraphQL schema metadata is exposed publicly.",
  "GraphQL introspection check complete": "GraphQL exposure review is complete.",
  "Scanning JavaScript for secrets": "First-party JavaScript files and inline scripts are being checked for exposed keys, tokens, and credentials.",
  "JavaScript secret scan complete": "JavaScript secret exposure analysis is complete.",
  "Checking source maps": "The scanner is checking whether JavaScript source maps are publicly accessible.",
  "Source map check complete": "Source map exposure review is complete.",
  "Checking API versions": "The scanner is probing whether sibling API versions are reachable and may need parity review.",
  "Testing path traversal": "The scanner is testing file-style parameters with safe traversal payloads to look for direct file-read evidence.",
  "Testing HTTP response splitting": "The scanner is checking whether CRLF input can inject unexpected response headers.",
  "Checking exposed asset drift": "The scanner is comparing current public pages and API routes against the last saved baseline to spot drift.",
  "Checking directory listing": "The scanner is checking whether directories can be browsed directly through the web server.",
  "Directory listing check complete": "Directory listing review is complete.",
  "Checking forced browsing": "The scanner is probing common unlinked paths to see whether internal routes are directly reachable.",
  "Forced browsing check complete": "Forced browsing review is complete.",
  "Testing API rate limiting": "The scanner is checking whether exposed API endpoints show signs of throttling or abuse protection.",
  "API rate limiting test complete": "API throttling review is complete.",
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
  downloadPdfReport();
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
  const timing = payload.timing || {};
  const progress = payload.progress || {};
  const error = payload.error || "";

  document.querySelector("#liveTitle").textContent = rawStep;
  document.querySelector("#scanStatus").textContent = status;
  document.querySelector("#pagesMetric").textContent = metrics.pages_crawled || 0;
  document.querySelector("#pagesKnownMetric").textContent = metrics.pages_total || metrics.pages_known || metrics.pages_crawled || 0;
  document.querySelector("#formsMetric").textContent = metrics.forms_found || 0;
  document.querySelector("#inputsMetric").textContent = metrics.inputs_discovered || 0;
  document.querySelector("#apiMetric").textContent = metrics.api_calls_captured || 0;
  document.querySelector("#findingsMetric").textContent = metrics.findings_so_far || 0;
  renderTimingState(timing, status);
  const progressText = processNotes[rawStep] || payload.progress_note || "The scanner is processing the target and collecting evidence.";
  const detailText = status === "FAILED" && error
    ? `${progressText} ${error}`
    : timing.eta_note
      ? `${progressText} ${timing.eta_note}`
      : progressText;
  document.querySelector("#plainProgress").textContent = detailText;

  rememberStep(rawStep, processNotes[rawStep] || payload.progress_note || "Security scan step completed.");
  const recent = payload.events_log?.recent || [];
  recent.slice(-3).forEach((event) => {
    const entry = describeEvent(event);
    if (entry) {
      rememberStep(entry.title, entry.detail);
    }
  });

  renderSteps();
  setProgress(rawStep, metrics, progress);
}

function rememberStep(title, detail) {
  const cleanTitle = String(title || "Scan activity").replace(/^[^A-Za-z]*/, "").trim();
  const cleanDetail = String(detail || "").replace(/^[^A-Za-z]*/, "").trim();
  const key = `${cleanTitle}:${cleanDetail}`;

  if (stepSequence.some((item) => item.key === key)) return;
  stepSequence.push({ key, title: cleanTitle, detail: cleanDetail });
  if (stepSequence.length > 10) {
    stepSequence = stepSequence.slice(stepSequence.length - 10);
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

function setProgress(step, metrics, progress) {
  if (typeof progress.percent === "number") {
    document.querySelector("#progressBar").style.width = `${Math.max(3, Math.min(100, progress.percent))}%`;
    return;
  }
  const knownSteps = Object.keys(processNotes);
  const index = Math.max(0, knownSteps.indexOf(step));
  const pageFactor = Math.min(25, Number(metrics.pages_crawled || 0));
  const stepFactor = index >= 0 ? ((index + 1) / knownSteps.length) * 75 : 10;
  const fallbackPercent = Math.min(96, Math.max(8, stepFactor + pageFactor));
  document.querySelector("#progressBar").style.width = `${fallbackPercent}%`;
}

function renderReport(report) {
  latestReport = report;
  reportPanel.classList.remove("hidden");
  document.querySelector("#progressBar").style.width = "100%";
  document.querySelector("#scanStatus").textContent = "Completed";
  document.querySelector("#liveTitle").textContent = "Scan complete";

  const meta = report.scan_metadata || {};
  const summary = report.executive_summary || {};
  const risk = summary.risk_rating || "Informational";
  const scope = summary.scope || {};
  const elapsedText = formatDuration(meta.elapsed_seconds);

  showEtaValue(elapsedText, "Scan completed in");
  document.querySelector("#plainProgress").textContent = `Scan complete. Total time: ${elapsedText}.`;

  document.querySelector("#reportTarget").textContent = meta.target || "Security Assessment";
  document.querySelector("#reportDate").textContent = buildReportDate(meta);
  const riskBadge = document.querySelector("#riskBadge");
  riskBadge.textContent = `Risk: ${risk}`;
  riskBadge.dataset.risk = risk;
  document.querySelector("#summaryText").textContent = summary.summary || "Security scan completed. Review the findings and recommended actions below.";

  renderScope(summary);
  renderAttackSurface(report.attack_surface_analysis || {});
  renderAssessment(report);

  reportPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderScope(summary) {
  const scope = summary.scope || {};
  const counts = summary.finding_counts || {};
  const checks = summary.checks_performed || {};
  const grid = document.querySelector("#scopeGrid");
  const cards = [
    ["Pages crawled", scope.pages_crawled || 0],
    ["Forms found", scope.forms_discovered || 0],
    ["Inputs found", scope.input_fields_found || 0],
    ["Network requests", scope.network_requests_captured || 0],
    ["Checks performed", checks.implemented_public_checks || 0],
    ["Findings detected", checks.findings_detected ?? ((counts.Critical || 0) + (counts.High || 0) + (counts.Medium || 0) + (counts.Low || 0))]
  ];
  grid.innerHTML = cards.map(([label, value]) => `
    <div><strong>${value}</strong><span>${label}</span></div>
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

function renderAssessment(report) {
  const root = document.querySelector("#assessmentList");
  const items = Array.isArray(report.assessment_items) && report.assessment_items.length
    ? report.assessment_items
    : buildAssessmentItems(report);

  if (!items.length) {
    root.innerHTML = `<div class="finding-card"><h4>No actionable findings</h4><p>The scan did not identify actionable findings in the tested scope.</p></div>`;
    return;
  }

  root.innerHTML = items.map((item, index) => `
    <div class="finding-card" data-severity="${escapeHtml(item.severity || "Info")}">
      <div class="assessment-head">
        <div class="assessment-number">${index + 1}</div>
        <div class="assessment-title-wrap">
          <h4>${escapeHtml(item.title || "Security finding")}</h4>
          <div class="finding-meta">
            <span class="${severityClass(item.severity)}">${escapeHtml(item.severity || "Info")}</span>
            ${item.priority ? `<span>${escapeHtml(item.priority)}</span>` : ""}
            ${item.confidence ? `<span>Confidence: ${escapeHtml(item.confidence)}</span>` : ""}
          </div>
        </div>
      </div>
      <p><strong>Status:</strong> ${escapeHtml(item.status || "Review required")}</p>
      <p><strong>Analysis:</strong> ${escapeHtml(item.analysis || "Review this issue in application context.")}</p>
      <p><strong>Evidence:</strong></p>
      <code>${escapeHtml(item.evidence || "Evidence not available")}</code>
      <p><strong>Actionable fix:</strong> ${escapeHtml(item.fix || "Validate and remediate according to security standards.")}</p>
    </div>
  `).join("");
}

function buildAssessmentItems(report) {
  const analysis = report.security_analysis || {};
  const headers = analysis.headers || {};
  const ssl = analysis.ssl || {};
  const sslExpiryMonitor = analysis.ssl_expiry_monitor || {};
  const cookies = analysis.cookies || {};
  const certificateTransparency = analysis.certificate_transparency || {};
  const newSubdomainAlert = analysis.new_subdomain_alert || {};
  const subdomainTakeover = analysis.subdomain_takeover || {};
  const headerRegression = analysis.header_regression || {};
  const assetDrift = analysis.asset_drift || {};
  const passiveHostIntelligence = analysis.passive_host_intelligence || {};
  const domainCredentialLeaks = analysis.domain_credential_leaks || {};
  const httpMethods = analysis.http_methods || {};
  const serverHeader = analysis.server_header_disclosure || {};
  const javascriptSecrets = analysis.javascript_secrets || {};
  const htmlSecrets = analysis.html_secrets || {};
  const authSurface = analysis.auth_surface || {};
  const technology = analysis.technology || {};
  const domainPosture = analysis.domain_posture || {};
  const dnssec = analysis.dnssec || {};
  const openPorts = analysis.open_ports || {};
  const graphql = analysis.graphql || {};
  const apiVersioning = analysis.api_versioning || {};
  const apiRateLimiting = analysis.api_rate_limiting || {};
  const csrf = analysis.csrf || {};
  const sourceMaps = analysis.source_maps || {};
  const pathTraversal = analysis.path_traversal || {};
  const responseSplitting = analysis.http_response_splitting || {};
  const directoryListing = analysis.directory_listing || {};
  const forcedBrowsing = analysis.forced_browsing || {};
  const verboseErrors = analysis.verbose_errors || {};
  const domXss = analysis.dom_xss || {};
  const openRedirect = analysis.open_redirect || {};
  const reflectedXss = analysis.reflected_xss || {};
  const storedXss = analysis.stored_xss || {};
  const sqlInjection = analysis.sql_injection || {};
  const sensitive = analysis.sensitive_paths || {};
  const cors = analysis.cors || {};
  const findings = report.findings || [];
  const missingHeaders = headers.missing || [];
  const notableCookies = cookies.notable_cookies || [];
  const secretDetections = javascriptSecrets.top_detections || [];
  const authSignals = authSurface.signals || [];
  const domXssVectors = domXss.vectors || [];
  const redirectVectors = openRedirect.vectors || [];
  const xssVectors = reflectedXss.vectors || [];
  const storedXssVectors = storedXss.vectors || [];
  const sqliVectors = sqlInjection.vectors || [];
  const exposedPaths = sensitive.exposed_paths || [];
  const blockedPaths = sensitive.blocked_paths || [];
  const items = [];
  const coveredVulnerabilities = new Set([
    "Missing Security Headers",
    "Weak Cookie Flags",
    "SSL Certificate Issue",
    "SSL Certificate Expiring Soon",
    "Weak TLS Protocol Supported",
    "Weak Cipher Suites Accepted",
    "HTTP Methods Enabled",
    "HTTP TRACE Enabled",
    "Verbose Error Messages",
    "Server Header Disclosure",
    "GraphQL Introspection",
    "JavaScript Source Maps",
    "Directory Listing Enabled",
    "Forced Browsing",
    "CSRF",
    "API Rate Limiting Absent",
    "JavaScript Secrets Exposed",
    "Hardcoded Secrets in HTML",
    "Technology Fingerprinting",
    "Domain Age & Parking Detection",
    "Missing DNSSEC",
    "Open Port Scanning",
    "Subdomain Takeover",
    "New Subdomain Alert",
    "SSL Certificate Expiry Monitor",
    "Security Header Regression Alert",
    "Exposed Asset Drift Detection",
    "Shodan / Censys Passive Recon",
    "IP Reputation Check",
    "Domain Credential Leak Check",
    "Shodan Exposure Score",
    "API Version Abuse",
    "Path Traversal",
    "HTTP Response Splitting",
    "DOM-Based XSS",
    "Open Redirect",
    "Reflected XSS",
    "Stored XSS",
    "SQL Injection",
    "Sensitive Path Detected",
  ]);

  const pushItem = (item) => items.push(item);

  pushItem({
    title: "Security Headers",
    severity: missingHeaders.length ? "Medium" : "Low",
    status: headers.status || "Not available",
    analysis: "Missing browser protections can increase exposure to XSS impact, clickjacking, MIME sniffing, referrer leakage, and HTTPS downgrade risk.",
    evidence: missingHeaders.map((item) => `${item.header}: ${item.impact}`).join("\n") || "No missing required headers reported",
    fix: missingHeaders.map((item) => item.remediation).join(" ") || "No immediate remediation needed.",
  });

  pushItem({
    title: "SSL Certificate",
    severity: (ssl.status || "").includes("Critical") || (ssl.status || "").includes("Warning") ? "Medium" : "Low",
    status: ssl.status || "Not available",
    analysis: ssl.note || "TLS certificate review not available.",
    evidence: [
      `Expires on: ${ssl.expires_on || "Unknown"}`,
      `Days remaining: ${ssl.days_remaining ?? "Unknown"}`,
      `Negotiated protocol: ${ssl.negotiated_protocol || "Unknown"}`,
      `Negotiated cipher: ${(ssl.negotiated_cipher || {}).name || "Unknown"}`
    ].join("\n"),
    fix: "Renew the certificate before expiry if needed and keep modern TLS protocol and cipher settings enabled.",
  });

  pushItem({
    title: "SSL Expiry Monitor",
    severity: (sslExpiryMonitor.status || "").includes("threshold") ? "Medium" : "Low",
    status: sslExpiryMonitor.status || "Not available",
    analysis: `Threshold: ${sslExpiryMonitor.threshold_days ?? "Unknown"} day(s).`,
    evidence: [
      `Days remaining: ${sslExpiryMonitor.days_remaining ?? "Unknown"}`,
      `Previous expiry: ${sslExpiryMonitor.previous_expiry || "None"}`,
      `Current expiry: ${sslExpiryMonitor.current_expiry || "Unknown"}`
    ].join("\n"),
    fix: "Renew the public certificate before the monitored threshold is reached and verify deployment everywhere HTTPS terminates.",
  });

  pushItem({
    title: "Cookies",
    severity: notableCookies.length ? "Low" : "Info",
    status: cookies.status || "Not available",
    analysis: cookies.note || "Cookie analysis not available.",
    evidence: notableCookies.map((item) => `${item.name} [${item.category}]: ${item.issue_summary}`).join("\n") || "No notable cookie issues reported",
    fix: "Harden real session cookies with Secure, HttpOnly, and SameSite after separating them from marketing cookies.",
  });

  pushItem({
    title: "HTTP Methods",
    severity: httpMethods.trace_enabled || (httpMethods.dangerous_methods || []).length ? "Medium" : "Low",
    status: httpMethods.status || "Not available",
    analysis: "Unnecessary HTTP methods can increase attack surface or suggest weak request hardening.",
    evidence: [
      `Allowed methods: ${(httpMethods.allow_methods || []).join(", ") || "Not observed"}`,
      `Dangerous methods: ${(httpMethods.dangerous_methods || []).join(", ") || "None"}`,
      `TRACE enabled: ${httpMethods.trace_enabled ? "Yes" : "No"}`
    ].join("\n"),
    fix: "Restrict allowed methods to only what the application needs and disable TRACE unless there is a specific operational requirement.",
  });

  pushItem({
    title: "Server Header Disclosure",
    severity: (serverHeader.headers || []).length ? "Low" : "Info",
    status: serverHeader.status || "Not available",
    analysis: serverHeader.note || "Server header disclosure review not available.",
    evidence: (serverHeader.headers || []).map((item) => `${item.header}: ${item.value}`).join("\n") || "No notable disclosure headers detected",
    fix: "Remove or generalize unnecessary server-identifying headers at the origin, reverse proxy, CDN, or framework layer.",
  });

  pushItem({
    title: "Security Header Regression Alert",
    severity: (headerRegression.regressed_headers || []).length ? "Medium" : "Low",
    status: headerRegression.status || "Not available",
    analysis: "Compares the current header posture with the previous saved baseline.",
    evidence: (headerRegression.regressed_headers || []).join("\n") || "No regressed headers detected or no previous baseline available",
    fix: "Restore any previously present security headers that disappeared unintentionally and keep them under baseline monitoring.",
  });

  pushItem({
    title: "Verbose Error Messages",
    severity: (verboseErrors.count || 0) ? "Medium" : "Low",
    status: verboseErrors.status || "Not available",
    analysis: "Stack traces, SQL errors, or framework exceptions can help attackers fingerprint the application and refine payloads.",
    evidence: `Verbose error evidence count: ${verboseErrors.count || 0}`,
    fix: "Return generic production error responses and keep detailed exceptions only in internal logs.",
  });

  pushItem({
    title: "Technology Fingerprinting",
    severity: "Low",
    status: technology.status || "Not available",
    analysis: technology.note || "Technology fingerprinting was not available.",
    evidence: [
      `Frameworks: ${(technology.frameworks || []).join(", ") || "None observed"}`,
      `Servers: ${(technology.server_markers || []).join(", ") || "None observed"}`,
      `CMS markers: ${(technology.cms_markers || []).join(", ") || "None observed"}`
    ].join("\n"),
    fix: "Review externally visible stack identifiers and remove avoidable banner or metadata leakage where practical.",
  });

  pushItem({
    title: "Certificate Transparency Monitoring",
    severity: "Low",
    status: certificateTransparency.status || "Not available",
    analysis: certificateTransparency.note || "CT monitoring was not available.",
    evidence: [
      `Domain: ${certificateTransparency.domain || "Unknown"}`,
      `Certificates observed: ${certificateTransparency.certificates_observed ?? "Unknown"}`,
      `Subdomains discovered: ${(certificateTransparency.subdomains || []).slice(0, 10).join(", ") || "None"}`
    ].join("\n"),
    fix: "Review CT-discovered subdomains regularly so new public assets do not bypass normal hardening and ownership checks.",
  });

  pushItem({
    title: "New Subdomain Alert",
    severity: (newSubdomainAlert.new_subdomains || []).length ? "Medium" : "Low",
    status: newSubdomainAlert.status || "Not available",
    analysis: "Compares the current CT-backed subdomain set against the previous saved baseline.",
    evidence: (newSubdomainAlert.new_subdomains || []).join("\n") || "No new subdomains detected or no previous baseline available",
    fix: "Review newly observed subdomains, confirm ownership and purpose, and apply the same security baseline as the main property.",
  });

  pushItem({
    title: "Subdomain Takeover",
    severity: (subdomainTakeover.suspected_takeovers || []).length ? "High" : "Low",
    status: subdomainTakeover.status || "Not available",
    analysis: "Checks discovered subdomains for dangling third-party hosting fingerprints.",
    evidence: (subdomainTakeover.suspected_takeovers || []).map((item) => `${item.subdomain} - ${item.provider} - ${item.cname || "no cname"}`).join("\n") || "No takeover fingerprint detected",
    fix: "Remove unused DNS records, reclaim abandoned third-party service bindings, and eliminate dangling CNAMEs.",
  });

  pushItem({
    title: "DNSSEC",
    severity: dnssec.dnssec_enabled === false ? "Low" : "Info",
    status: dnssec.status || "Not available",
    analysis: dnssec.note || "DNSSEC improves trust in DNS responses by adding authenticity signals at the zone level.",
    evidence: [
      `Domain: ${dnssec.domain || "Unknown"}`,
      `DNSSEC enabled: ${dnssec.dnssec_enabled === true ? "Yes" : dnssec.dnssec_enabled === false ? "No" : "Unknown"}`,
      `Error: ${dnssec.error || "None"}`
    ].join("\n"),
    fix: "Enable DNSSEC signing for the public zone and verify DS and DNSKEY records are published correctly.",
  });

  pushItem({
    title: "Open Port Scanning",
    severity: (openPorts.open_ports || []).some((item) => item.port !== 80 && item.port !== 443) ? "Medium" : "Low",
    status: openPorts.status || "Not available",
    analysis: openPorts.note || "This is a lightweight connect scan against a short common-port list.",
    evidence: (openPorts.open_ports || []).map((item) => `${item.port} (${item.service})`).join("\n") || "No additional common open ports detected",
    fix: "Close unnecessary public ports at the firewall, security group, load balancer, or host level.",
  });

  pushItem({
    title: "Passive Host Intelligence",
    severity: (passiveHostIntelligence.ports || []).length || (passiveHostIntelligence.vulns || []).length ? "Low" : "Info",
    status: passiveHostIntelligence.status || "Not available",
    analysis: passiveHostIntelligence.note || "Passive public exposure data is enrichment, not definitive proof of a live issue.",
    evidence: [
      `IP: ${passiveHostIntelligence.ip || "Unknown"}`,
      `Ports: ${(passiveHostIntelligence.ports || []).join(", ") || "None"}`,
      `Tags: ${(passiveHostIntelligence.tags || []).join(", ") || "None"}`,
      `Vulns: ${(passiveHostIntelligence.vulns || []).join(", ") || "None"}`
    ].join("\n"),
    fix: "Compare passive host data with the intended public footprint and investigate any exposed services or vulnerability hints.",
  });

  pushItem({
    title: "IP Reputation Check",
    severity: (passiveHostIntelligence.risky_ports || []).length || (passiveHostIntelligence.risky_tags || []).length || (passiveHostIntelligence.vulns || []).length ? "Medium" : "Low",
    status: (passiveHostIntelligence.risky_ports || []).length || (passiveHostIntelligence.risky_tags || []).length || (passiveHostIntelligence.vulns || []).length ? "Passive risk signals detected" : "No passive risk signal detected",
    analysis: "Builds a reputation-style signal from passively observed risky ports, tags, and vulnerability hints.",
    evidence: [
      `Risky ports: ${(passiveHostIntelligence.risky_ports || []).join(", ") || "None"}`,
      `Risky tags: ${(passiveHostIntelligence.risky_tags || []).join(", ") || "None"}`,
      `Vulns: ${(passiveHostIntelligence.vulns || []).join(", ") || "None"}`
    ].join("\n"),
    fix: "Investigate passively observed risky services and verify the host is not exposing unnecessary or vulnerable software to the internet.",
  });

  pushItem({
    title: "Shodan Exposure Score",
    severity: (passiveHostIntelligence.exposure_score || 0) >= 40 ? "Medium" : "Low",
    status: passiveHostIntelligence.status || "Not available",
    analysis: "Summarizes the passively observed public footprint into a simple exposure score.",
    evidence: `Exposure score: ${passiveHostIntelligence.exposure_score ?? "Unknown"}/100`,
    fix: "Reduce the externally visible footprint by closing unnecessary ports and addressing passively observed exposure signals.",
  });

  pushItem({
    title: "Domain Credential Leak Check",
    severity: (domainCredentialLeaks.breaches || []).length ? "Medium" : "Low",
    status: domainCredentialLeaks.status || "Not available",
    analysis: domainCredentialLeaks.note || "Checks public breach records tied to the scanned domain.",
    evidence: (domainCredentialLeaks.breaches || []).map((item) => `${item.domain} - ${item.breach}`).join("\n") || "No public breach catalog match found for the domain",
    fix: "Review breach history linked to the domain and strengthen credential hygiene with MFA, password resets, and credential-stuffing protections where applicable.",
  });

  pushItem({
    title: "Authentication Coverage",
    severity: authSurface.auth_detected ? "Medium" : "Low",
    status: authSurface.status || "Not available",
    analysis: "If login, signup, or password reset functionality exists, a public-only scan cannot be treated as full application assurance.",
    evidence: [
      `Classification: ${authSurface.classification || "unknown"}`,
      `Assessment note: ${authSurface.note || "Not available"}`,
      `Signals: ${authSignals.map((item) => `${item.type}: ${item.value}`).join(" | ") || "No auth-related signals detected"}`
    ].join("\n"),
    fix: "Run an authenticated scan or manual review before treating the application as fully assessed.",
  });

  pushItem({
    title: "Sensitive Paths",
    severity: exposedPaths.length ? "Medium" : blockedPaths.length ? "Low" : "Info",
    status: sensitive.status || "Not available",
    analysis: "HTTP 403 means blocked, not confirmed exposure. Readable paths need faster action.",
    evidence: exposedPaths.concat(blockedPaths).slice(0, 10).map((item) => `${item.path} - HTTP ${item.http_status} - ${item.severity}`).join("\n") || "No sensitive path evidence reported",
    fix: "Remove or restrict readable sensitive files and review blocked hits as route-existence signals rather than confirmed exposure.",
  });

  pushItem({
    title: "CORS",
    severity: (cors.status || "").includes("High") ? "High" : (cors.status || "").includes("Medium") ? "Medium" : "Low",
    status: cors.status || "Not available",
    analysis: cors.engineer_summary || "No CORS summary available.",
    evidence: (cors.issues || []).map((item) => `${item.issue_type}: ${item.description}`).join("\n") || "No CORS issues reported",
    fix: "Use an explicit allowlist of trusted origins and avoid credentials with wildcard or reflected origins.",
  });

  pushItem({
    title: "CSRF",
    severity: (csrf.count || 0) ? "Medium" : "Low",
    status: csrf.status || "Not available",
    analysis: "Browser-authenticated actions need request-forgery protections.",
    evidence: `POST forms without token signals: ${csrf.count || 0}`,
    fix: "Use anti-CSRF tokens, validate Origin or Referer where appropriate, and pair them with stricter SameSite cookie protections.",
  });

  pushItem({
    title: "API Rate Limiting",
    severity: (apiRateLimiting.status || "").includes("No throttling") ? "Medium" : "Low",
    status: apiRateLimiting.status || "Not available",
    analysis: "Weak or absent throttling can make brute force, scraping, or automated abuse easier on public APIs.",
    evidence: [
      `Tested endpoint: ${apiRateLimiting.tested_endpoint || "None"}`,
      `Probe statuses: ${(apiRateLimiting.statuses || []).join(", ") || "Not tested"}`,
      `Throttled: ${apiRateLimiting.throttled ? "Yes" : "No"}`
    ].join("\n"),
    fix: "Apply rate limits, anomaly detection, and challenge controls on sensitive or high-value API endpoints.",
  });

  pushItem({
    title: "GraphQL Introspection",
    severity: (graphql.count || 0) ? "Medium" : "Low",
    status: graphql.status || "Not available",
    analysis: "Public GraphQL schema metadata can accelerate attacker reconnaissance.",
    evidence: `GraphQL findings: ${graphql.count || 0}`,
    fix: "Disable GraphQL introspection in production where possible or restrict it to trusted users and environments.",
  });

  pushItem({
    title: "JavaScript Secret Exposure",
    severity: secretDetections.length ? "High" : "Low",
    status: javascriptSecrets.status || "Not available",
    analysis: `Coverage: ${javascriptSecrets.scanned_files || 0} JavaScript file(s) and ${javascriptSecrets.scanned_inline_pages || 0} inline-script page(s) reviewed.`,
    evidence: secretDetections.map((item) => `${item.type} - ${item.source} - ${item.value_preview}`).join("\n") || "No JavaScript secret exposure detected",
    fix: "Rotate exposed keys or tokens immediately and move privileged secrets out of frontend-delivered code.",
  });

  pushItem({
    title: "HTML Secret Exposure",
    severity: (htmlSecrets.detections || []).length ? "High" : "Low",
    status: htmlSecrets.status || "Not available",
    analysis: htmlSecrets.note || "Checks rendered HTML, inline config, and page source for secret-looking values.",
    evidence: (htmlSecrets.detections || []).map((item) => `${item.type} - ${item.source} - ${item.value_preview}`).join("\n") || "No HTML secret exposure detected",
    fix: "Remove secrets from rendered HTML, inline config, and hydration data, then rotate any exposed live credentials.",
  });

  pushItem({
    title: "Source Maps",
    severity: (sourceMaps.count || 0) ? "Medium" : "Low",
    status: sourceMaps.status || "Not available",
    analysis: "Source maps can reveal original code, comments, and internal implementation details.",
    evidence: `Source map findings: ${sourceMaps.count || 0}`,
    fix: "Remove public source maps in production or restrict them to trusted users and debugging environments.",
  });

  pushItem({
    title: "Directory Listing",
    severity: (directoryListing.count || 0) ? "Medium" : "Low",
    status: directoryListing.status || "Not available",
    analysis: "Directory indexes can expose internal file structure, backups, or forgotten assets.",
    evidence: `Directory listing findings: ${directoryListing.count || 0}`,
    fix: "Disable auto-indexing on the web server and serve explicit index files or deny directory browsing.",
  });

  pushItem({
    title: "Forced Browsing",
    severity: (forcedBrowsing.count || 0) ? "Medium" : "Low",
    status: forcedBrowsing.status || "Not available",
    analysis: "Directly reachable but unlinked routes can expose internal or admin-style functionality.",
    evidence: `Forced browsing findings: ${forcedBrowsing.count || 0}`,
    fix: "Review unlinked but reachable routes and enforce authentication, authorization, or removal where appropriate.",
  });

  pushItem({
    title: "API Version Exposure",
    severity: (apiVersioning.reachable_versions || []).length ? "Medium" : "Low",
    status: apiVersioning.status || "Not available",
    analysis: apiVersioning.note || "Versioned public APIs can drift from newer security controls over time.",
    evidence: (apiVersioning.reachable_versions || []).map((item) => `${item.candidate_url} - HTTP ${item.status}`).join("\n") || "No sibling API versions confirmed",
    fix: "Inventory every reachable API version, retire obsolete versions, and confirm security controls are consistent across them.",
  });

  pushItem({
    title: "Path Traversal",
    severity: (pathTraversal.issues || []).length ? "High" : "Low",
    status: pathTraversal.status || "Not available",
    analysis: "File-style parameters are a common place for unsafe path joining and normalization mistakes.",
    evidence: (pathTraversal.issues || []).map((item) => `${item.parameter} - ${item.tested_url} - ${item.evidence}`).join("\n") || "No path traversal signal detected",
    fix: "Never use raw user input in filesystem paths, apply strict allowlists, normalize paths safely, and enforce a fixed document root or storage boundary.",
  });

  pushItem({
    title: "HTTP Response Splitting",
    severity: (responseSplitting.issues || []).length ? "High" : "Low",
    status: responseSplitting.status || "Not available",
    analysis: "CRLF header injection can affect browsers, proxies, caches, and downstream security controls.",
    evidence: (responseSplitting.issues || []).map((item) => `${item.parameter} - ${item.tested_url}`).join("\n") || "No response splitting signal detected",
    fix: "Reject CRLF characters in header-influencing input and avoid copying raw user input into response headers.",
  });

  pushItem({
    title: "DOM-Based XSS",
    severity: domXssVectors.length ? "High" : "Low",
    status: domXss.status || "Not available",
    analysis: "DOM-based XSS happens in browser-side code and can execute without server-side reflection.",
    evidence: domXssVectors.map((item) => `${item.vector} - ${item.tested_url}`).join("\n") || "No DOM-based XSS detected in the tested fragment flows",
    fix: "Avoid unsafe DOM sinks such as innerHTML for untrusted data and sanitize fragment or URL-derived input before rendering.",
  });

  pushItem({
    title: "Open Redirect",
    severity: redirectVectors.length ? "High" : "Low",
    status: openRedirect.status || "Not available",
    analysis: "Redirect abuse can turn a trusted domain into a phishing or token-forwarding step in an attack chain.",
    evidence: redirectVectors.map((item) => `${item.vector} - ${item.tested_url} -> ${item.redirect_target}`).join("\n") || "No open redirect detected in the tested flows",
    fix: "Restrict redirect destinations to approved internal paths or allowlisted hosts and reject attacker-controlled absolute URLs.",
  });

  pushItem({
    title: "Reflected XSS",
    severity: xssVectors.length ? "High" : "Low",
    status: reflectedXss.status || "Not available",
    analysis: "Unsanitized reflection can enable browser-side script execution, phishing overlays, and session compromise.",
    evidence: xssVectors.map((item) => `${item.vector} - ${item.tested_url}`).join("\n") || "No reflected XSS detected in the tested parameters and forms",
    fix: "Apply context-aware output encoding, sanitize reflected input, and use framework-safe templating rather than unsafe rendering.",
  });

  pushItem({
    title: "Stored XSS",
    severity: storedXssVectors.length ? "High" : "Low",
    status: storedXss.status || "Not available",
    analysis: "Stored XSS can affect every user who later views the injected record or page.",
    evidence: storedXssVectors.map((item) => `${item.vector} - ${item.tested_url}`).join("\n") || "No stored XSS detected in the tested low-risk forms",
    fix: "Apply context-aware output encoding for stored content, sanitize rich text safely, and review any workflow that persists user-supplied HTML.",
  });

  pushItem({
    title: "SQL Injection",
    severity: sqliVectors.length ? "High" : "Low",
    status: sqlInjection.status || "Not available",
    analysis: "SQL injection can expose database content, modify records, or support authentication bypass and wider compromise.",
    evidence: sqliVectors.map((item) => `${item.vector} - ${item.tested_url} - ${item.evidence}`).join("\n") || "No SQL injection evidence detected in the tested low-risk flows",
    fix: "Use parameterized queries, strict server-side validation, ORM-safe bindings, and suppress database error leakage to users.",
  });

  pushItem({
    title: "Domain Age And Parking Detection",
    severity: domainPosture.parking_detected || ((domainPosture.age_days || 999999) <= 30) ? "Low" : "Info",
    status: domainPosture.status || "Not available",
    analysis: domainPosture.note || "Registration age and parking signals are best-effort passive trust context.",
    evidence: [
      `Domain: ${domainPosture.domain || "Unknown"}`,
      `Age (days): ${domainPosture.age_days ?? "Unknown"}`,
      `Parking detected: ${domainPosture.parking_detected ? "Yes" : "No"}`
    ].join("\n"),
    fix: "Review whether the domain is intentionally live, newly registered, or parked before treating it as a stable production property.",
  });

  pushItem({
    title: "Exposed Asset Drift Detection",
    severity: (assetDrift.new_pages || []).length || (assetDrift.new_api_calls || []).length ? "Medium" : "Low",
    status: assetDrift.status || "Not available",
    analysis: "Compares public pages and API calls against the previous saved baseline.",
    evidence: [
      `New pages: ${(assetDrift.new_pages || []).join(", ") || "None"}`,
      `New API calls: ${(assetDrift.new_api_calls || []).join(", ") || "None"}`,
      `Removed pages: ${(assetDrift.removed_pages || []).join(", ") || "None"}`,
      `Removed API calls: ${(assetDrift.removed_api_calls || []).join(", ") || "None"}`
    ].join("\n"),
    fix: "Review newly exposed or removed assets since the last baseline so unexpected surface changes do not slip through unnoticed.",
  });

  findings.forEach((finding) => {
    const raw = finding.raw || {};
    if (coveredVulnerabilities.has(raw.vulnerability)) {
      return;
    }
    items.push({
      title: finding.title || "Security finding",
      severity: finding.severity || "Info",
      priority: finding.priority || "Review",
      confidence: finding.confidence || "Medium",
      status: finding.title || "Finding detected",
      analysis: finding.impact || "Review this finding in application context.",
      evidence: finding.evidence_summary || "Evidence not available",
      fix: finding.remediation || "Validate and remediate according to security standards.",
    });
  });

  return items;
}

function clearReport() {
  reportPanel.classList.add("hidden");
  stepSequence = [];
  document.querySelector("#progressBar").style.width = "8%";
  showEtaLoading();
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
    const host = compactUrl(detail.url);
    const lowerHost = host.toLowerCase();
    if (
      lowerHost.includes("googleads") ||
      lowerHost.includes("doubleclick") ||
      lowerHost.includes("google-analytics") ||
      lowerHost.includes("googletagmanager") ||
      lowerHost.includes("facebook") ||
      lowerHost.includes("hotjar") ||
      lowerHost.includes("clarity")
    ) {
      return null;
    }
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

function formatDuration(totalSeconds) {
  const seconds = Number(totalSeconds);
  if (!Number.isFinite(seconds) || seconds < 1) return "0s";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const leftoverMinutes = minutes % 60;
  return leftoverMinutes ? `${hours}h ${leftoverMinutes}m` : `${hours}h`;
}

function formatEta(totalSeconds, finalized) {
  const seconds = Number(totalSeconds);
  if (!Number.isFinite(seconds) || seconds < 0) {
    return "Estimating...";
  }
  if (seconds === 0) {
    return finalized ? "Almost done" : "0s";
  }
  const prefix = finalized ? "" : "~";
  return `${prefix}${formatDuration(seconds)}`;
}

function renderTimingState(timing, status) {
  if (status === "FAILED") {
    showEtaValue("Unavailable", "Estimated remaining");
    return;
  }

  const remaining = timing.estimated_remaining_seconds;
  if (remaining === null || remaining === undefined || Number.isNaN(Number(remaining))) {
    showEtaLoading();
    return;
  }

  showEtaValue(formatEta(remaining, timing.eta_finalized), "Estimated remaining");
}

function showEtaLoading() {
  document.querySelector("#etaLoading").classList.remove("hidden");
  document.querySelector("#etaMetric").classList.add("hidden");
  document.querySelector("#timeLabel").textContent = "Estimated remaining";
}

function showEtaValue(value, label) {
  const loading = document.querySelector("#etaLoading");
  const metric = document.querySelector("#etaMetric");
  loading.classList.add("hidden");
  metric.classList.remove("hidden");
  metric.textContent = value;
  document.querySelector("#timeLabel").textContent = label;
}

function buildReportDate(meta) {
  const completed = meta.scan_completed_at || new Date().toLocaleString();
  const started = meta.scan_started_at;
  const elapsed = formatDuration(meta.elapsed_seconds);
  if (started) {
    return `Started at ${started} | Completed at ${completed} | Duration ${elapsed}`;
  }
  return `Completed at ${completed} | Duration ${elapsed}`;
}

async function downloadPdfReport() {
  if (!activeScanId) {
    showFatalError(new Error("No completed scan is available for PDF download yet."));
    return;
  }

  const originalText = pdfBtn.textContent;
  pdfBtn.disabled = true;
  pdfBtn.textContent = "Preparing PDF...";

  try {
    const response = await fetch(`${activeBackendUrl}/scan/status/${activeScanId}?pdf=true`);
    if (!response.ok) {
      throw new Error(await response.text());
    }

    const blob = await response.blob();
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.download = getDownloadFilename(response.headers.get("Content-Disposition"));
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(downloadUrl);
  } catch (error) {
    showFatalError(error);
  } finally {
    pdfBtn.disabled = false;
    pdfBtn.textContent = originalText;
  }
}

function getDownloadFilename(contentDisposition) {
  const match = /filename=([^;]+)/i.exec(String(contentDisposition || ""));
  if (!match) {
    return "security-report.pdf";
  }
  return match[1].trim().replace(/^"+|"+$/g, "");
}
