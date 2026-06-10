"""
Server-side PDF report rendering.

Uses Playwright to render a styled HTML report and export it as a PDF so the
frontend can download a stable backend-generated file.
"""

import asyncio
from html import escape

from playwright.async_api import async_playwright

from core.reporter import generate_readable_json


def build_pdf_filename(target_url: str, scan_time: str) -> str:
    safe_target = (
        str(target_url or "security-scan")
        .replace("https://", "")
        .replace("http://", "")
        .strip("/")
    )
    safe_target = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in safe_target).strip("-").lower()
    stamp = (
        str(scan_time or "")
        .replace("-", "")
        .replace(":", "")
        .replace(" ", "_")
    ) or "report"
    return f"{safe_target or 'security-scan'}_{stamp}.pdf"


def render_pdf_report_sync(data: dict, scan_time: str) -> bytes:
    return asyncio.run(render_pdf_report(data, scan_time))


async def render_pdf_report(data: dict, scan_time: str) -> bytes:
    readable = generate_readable_json(data, scan_time)
    html = _build_report_html(readable)

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.set_content(html, wait_until="networkidle")
        pdf = await page.pdf(
            format="A4",
            print_background=True,
            margin={"top": "16mm", "right": "12mm", "bottom": "16mm", "left": "12mm"},
        )
        await browser.close()
    return pdf


def _build_report_html(report: dict) -> str:
    meta = report.get("scan_metadata", {})
    summary = report.get("executive_summary", {})
    scope = summary.get("scope", {})
    counts = summary.get("finding_counts", {})
    checks = summary.get("checks_performed", {})
    security = report.get("security_analysis", {})
    attack_surface = report.get("attack_surface_analysis", {})

    risk = escape(summary.get("risk_rating", "Informational"))
    target = escape(meta.get("target", "Security Assessment"))
    completed = escape(meta.get("scan_completed_at", ""))
    summary_text = escape(summary.get("summary", ""))

    surface_pages = attack_surface.get("pages", {})
    surface_inputs = attack_surface.get("inputs", {})
    surface_network = attack_surface.get("network", {}).get("counts", {})

    headers = security.get("headers", {})
    cookies = security.get("cookies", {})
    auth_surface = security.get("auth_surface", {})
    http_methods = security.get("http_methods", {})
    server_header = security.get("server_header_disclosure", {})
    technology = security.get("technology", {})
    graphql = security.get("graphql", {})
    api_rate_limiting = security.get("api_rate_limiting", {})
    csrf = security.get("csrf", {})
    source_maps = security.get("source_maps", {})
    directory_listing = security.get("directory_listing", {})
    forced_browsing = security.get("forced_browsing", {})
    verbose_errors = security.get("verbose_errors", {})
    javascript_secrets = security.get("javascript_secrets", {})
    dom_xss = security.get("dom_xss", {})
    open_redirect = security.get("open_redirect", {})
    reflected_xss = security.get("reflected_xss", {})
    stored_xss = security.get("stored_xss", {})
    sql_injection = security.get("sql_injection", {})
    sensitive_paths = security.get("sensitive_paths", {})
    cors = security.get("cors", {})
    ssl = security.get("ssl", {})
    newline = "\n"

    assessment_cards = _build_assessment_cards(
        report,
        headers=headers,
        ssl=ssl,
        cookies=cookies,
        http_methods=http_methods,
        server_header=server_header,
        verbose_errors=verbose_errors,
        technology=technology,
        graphql=graphql,
        source_maps=source_maps,
        directory_listing=directory_listing,
        forced_browsing=forced_browsing,
        auth_surface=auth_surface,
        csrf=csrf,
        api_rate_limiting=api_rate_limiting,
        javascript_secrets=javascript_secrets,
        dom_xss=dom_xss,
        open_redirect=open_redirect,
        reflected_xss=reflected_xss,
        stored_xss=stored_xss,
        sql_injection=sql_injection,
        sensitive_paths=sensitive_paths,
        cors=cors,
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{target}</title>
  <style>
    :root {{
      --ink: #17202a;
      --muted: #667085;
      --line: #d8dee8;
      --blue: #155eef;
      --green: #087443;
      --amber: #b54708;
      --red: #b42318;
      --soft-blue: #eef4ff;
      --soft-green: #ecfdf3;
      --soft-amber: #fffaeb;
      --soft-red: #fef3f2;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: Arial, Helvetica, sans-serif;
      background: #ffffff;
      font-size: 12px;
      line-height: 1.5;
    }}
    .report {{
      border: 1px solid var(--line);
    }}
    .cover {{
      color: #fff;
      padding: 28px;
      background: linear-gradient(135deg, #111827 0%, #1849a9 64%, #087443 100%);
    }}
    .cover-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
    }}
    .brand-small {{
      font-size: 11px;
      letter-spacing: 1.3px;
      text-transform: uppercase;
      opacity: 0.9;
    }}
    .cover h1 {{
      margin: 14px 0 8px;
      font-size: 30px;
      line-height: 1.2;
      word-break: break-word;
    }}
    .cover p {{ margin: 0; color: rgba(255,255,255,0.84); }}
    .risk-badge {{
      display: inline-block;
      margin-top: 14px;
      padding: 8px 12px;
      border-radius: 999px;
      font-weight: 700;
      background: { _risk_background(summary.get("risk_rating", "Informational")) };
      color: { _risk_color(summary.get("risk_rating", "Informational")) };
    }}
    .section {{
      padding: 22px 24px;
      border-top: 1px solid var(--line);
    }}
    .section h2 {{
      margin: 0 0 12px;
      font-size: 20px;
    }}
    .summary-grid {{
      font-size: 0;
      margin-top: 14px;
    }}
    .metric, .card {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
    }}
    .metric {{
      display: inline-block;
      width: calc(20% - 8px);
      margin: 0 10px 10px 0;
      vertical-align: top;
      font-size: 12px;
      border-left: 4px solid var(--blue);
      background: #fbfcff;
    }}
    .metric strong {{
      display: block;
      font-size: 22px;
      margin-bottom: 4px;
    }}
    .metric span, .subtle {{
      color: var(--muted);
    }}
    .grid-2 {{
      font-size: 0;
    }}
    .list {{
      display: block;
    }}
    .card h4 {{
      margin: 0 0 8px;
      font-size: 16px;
    }}
    .finding-meta {{
      margin: 8px 0;
    }}
    .assessment-head {{
      display: table;
      width: 100%;
      margin-bottom: 6px;
    }}
    .assessment-head > div {{
      display: table-cell;
      vertical-align: top;
    }}
    .assessment-number {{
      width: 34px;
      height: 34px;
      text-align: center;
      border-radius: 999px;
      background: #f2f4f7;
      color: var(--ink);
      font-size: 14px;
      font-weight: 800;
      line-height: 34px;
      margin-right: 12px;
    }}
    .pill {{
      display: inline-block;
      margin-right: 6px;
      margin-bottom: 6px;
      padding: 4px 8px;
      border-radius: 999px;
      background: #f2f4f7;
      font-size: 11px;
      font-weight: 700;
    }}
    .sev-critical, .sev-high {{
      background: var(--soft-red);
      color: var(--red);
    }}
    .sev-medium {{
      background: var(--soft-amber);
      color: var(--amber);
    }}
    .sev-low, .sev-informational, .sev-info {{
      background: var(--soft-green);
      color: var(--green);
    }}
    .evidence {{
      white-space: pre-wrap;
      padding: 10px;
      border-radius: 6px;
      background: #f2f4f7;
      color: #344054;
      font-size: 11px;
    }}
    .split {{
      font-size: 0;
    }}
    .list .card {{
      margin-bottom: 12px;
    }}
    .grid-2 .card,
    .split > div {{
      display: inline-block;
      width: calc(50% - 6px);
      margin: 0 12px 12px 0;
      vertical-align: top;
      font-size: 12px;
    }}
    .grid-2 .card:nth-child(2n),
    .split > div:nth-child(2n),
    .summary-grid .metric:nth-child(5n) {{
      margin-right: 0;
    }}
    .summary-grid .metric:last-child,
    .list .card:last-child,
    .grid-2 .card:last-child,
    .split > div:last-child {{
      margin-bottom: 0;
    }}
    ul {{
      margin: 10px 0 0 18px;
      padding: 0;
    }}
    li {{
      margin-bottom: 6px;
    }}
    .cta {{
      background: linear-gradient(135deg, #eef4ff, #ffffff 58%, #ecfdf3);
      border: 1px solid #b9c7ff;
    }}
    .disclaimer {{
      background: #f8fafc;
      border: 1px solid #d6dbe6;
    }}
  </style>
</head>
<body>
  <div class="report">
    <section class="cover">
      <div class="cover-top">
        <div>
          <div class="brand-small">HIT SecureScan</div>
          <h1>{target}</h1>
          <p>Security Engineer Report</p>
          <p>Completed at {completed}</p>
          <div class="risk-badge">Risk: {risk}</div>
        </div>
        <div style="text-align:right">
          <div class="brand-small">Prepared By</div>
          <div style="font-size:22px;font-weight:700">Hands In Technology</div>
        </div>
      </div>
    </section>

    <section class="section">
      <h2>Executive Summary</h2>
      <p>{summary_text}</p>
      <div class="summary-grid">
        <div class="metric"><strong>{scope.get("pages_crawled", 0)}</strong><span>Pages crawled</span></div>
        <div class="metric"><strong>{scope.get("forms_discovered", 0)}</strong><span>Forms found</span></div>
        <div class="metric"><strong>{scope.get("input_fields_found", 0)}</strong><span>Inputs found</span></div>
        <div class="metric"><strong>{scope.get("network_requests_captured", 0)}</strong><span>Network requests</span></div>
        <div class="metric"><strong>{checks.get("implemented_public_checks", 0)}</strong><span>Checks performed</span></div>
        <div class="metric"><strong>{checks.get("findings_detected", counts.get("Critical", 0) + counts.get("High", 0) + counts.get("Medium", 0) + counts.get("Low", 0))}</strong><span>Findings detected</span></div>
      </div>
    </section>

    <section class="section">
      <h2>Evidence And Attack Surface</h2>
      <div class="grid-2">
        <div class="card">
          <h4>Application Surface</h4>
          <p>{surface_pages.get("count", 0)} unique pages were crawled. {surface_inputs.get("total", 0)} input fields were discovered, including {surface_inputs.get("file_inputs", 0)} file input(s) and {surface_inputs.get("hidden_inputs", 0)} hidden input(s).</p>
          <p class="subtle">The report summarizes evidence categories rather than dumping raw page lists.</p>
        </div>
        <div class="card">
          <h4>Network Evidence</h4>
          <div class="evidence">First-party API-like: {surface_network.get("first_party_api", 0)}
First-party pages: {surface_network.get("first_party_pages", 0)}
Static assets: {surface_network.get("first_party_static", 0)}
Tracking/analytics: {surface_network.get("tracking_or_analytics", 0)}
Third-party services: {surface_network.get("third_party_service", 0)}</div>
        </div>
      </div>
    </section>

    <section class="section">
      <h2>Findings</h2>
      <div class="list">{assessment_cards}</div>
    </section>

    <section class="section">
      <div class="card cta">
        <h4>Need Help Fixing This?</h4>
        <p>Hands In Technology can help validate findings, harden your website, secure APIs, fix input handling issues, review secrets exposure, and turn this report into a practical remediation roadmap.</p>
        <div class="split">
          <div>
            <strong>Email</strong><br>
            info@handsintechnology.com
          </div>
          <div>
            <strong>Phone</strong><br>
            +91 7977747037
          </div>
        </div>
        <p style="margin-top:12px"><strong>Address</strong><br>412, Ghanshyam Enclave Near Lalji Pada Police Station, New Link Rd, Kandivali West, Mumbai, Maharashtra 400067</p>
        <p><strong>Website</strong><br>handsintechnology.com</p>
      </div>
    </section>

    <section class="section">
      <div class="card disclaimer">
        <h4>Assessment Disclaimer</h4>
        <p>This report is an automated security assessment based on the tested scope and current scan logic. Findings can identify real weaknesses and meaningful risk signals, but critical issues should still be manually validated. A clean report does not guarantee that the application is secure or fully free from vulnerabilities.</p>
      </div>
    </section>
  </div>
</body>
</html>"""


def _build_assessment_cards(report: dict, **analysis: dict) -> str:
    items = report.get("assessment_items", []) or _build_assessment_items(report, analysis)
    if not items:
        return "<div class='card'><h4>No actionable findings</h4><p>The scan did not identify actionable findings in the tested scope.</p></div>"
    return "".join(_assessment_card_html(item, index + 1) for index, item in enumerate(items))


def _build_assessment_items(report: dict, analysis: dict) -> list[dict]:
    headers = analysis.get("headers", {})
    ssl = analysis.get("ssl", {})
    cookies = analysis.get("cookies", {})
    http_methods = analysis.get("http_methods", {})
    server_header = analysis.get("server_header", {})
    verbose_errors = analysis.get("verbose_errors", {})
    technology = analysis.get("technology", {})
    graphql = analysis.get("graphql", {})
    source_maps = analysis.get("source_maps", {})
    directory_listing = analysis.get("directory_listing", {})
    forced_browsing = analysis.get("forced_browsing", {})
    auth_surface = analysis.get("auth_surface", {})
    csrf = analysis.get("csrf", {})
    api_rate_limiting = analysis.get("api_rate_limiting", {})
    findings = report.get("findings", [])

    items = []
    missing_headers = headers.get("missing", [])
    notable_cookies = cookies.get("notable_cookies", [])

    if headers.get("status"):
        items.append({
            "title": "Security Headers",
            "severity": "Medium" if missing_headers else "Low",
            "status": headers.get("status", "Not available"),
            "analysis": "Missing browser protections can increase exposure to XSS impact, clickjacking, MIME sniffing, referrer leakage, and HTTPS downgrade risk.",
            "evidence": "\n".join(f"{item.get('header')}: {item.get('impact')}" for item in missing_headers) or "No missing required headers reported",
            "fix": "Configure the missing headers at the web server, CDN, or application layer and keep them in the baseline going forward.",
        })

    if ssl.get("status") or cookies.get("status"):
        items.append({
            "title": "SSL And Cookies",
            "severity": "Low" if notable_cookies else "Info",
            "status": f"{ssl.get('status', 'Not available')} - {ssl.get('note', '')}".strip(" -"),
            "analysis": cookies.get("status", "Cookie analysis not available."),
            "evidence": "\n".join(
                f"{item.get('name')} [{item.get('category')}]: {item.get('issue_summary')}"
                for item in notable_cookies
            ) or "No notable cookie issues reported",
            "fix": "Renew the certificate before expiry if needed, and harden real session cookies with Secure, HttpOnly, and SameSite after separating them from marketing cookies.",
        })

    if http_methods.get("status") or verbose_errors.get("status") or server_header.get("status"):
        items.append({
            "title": "HTTP Methods And Server Behavior",
            "severity": "Medium" if http_methods.get("trace_enabled") or http_methods.get("dangerous_methods") or verbose_errors.get("count", 0) else "Low",
            "status": http_methods.get("status", "Server behavior reviewed"),
            "analysis": f"{verbose_errors.get('status', 'Verbose error review not available.')} {server_header.get('status', '')}".strip(),
            "evidence": "\n".join([
                f"Allowed methods: {', '.join(http_methods.get('allow_methods', [])) or 'Not observed'}",
                f"TRACE enabled: {'Yes' if http_methods.get('trace_enabled') else 'No'}",
                f"Verbose error evidence: {verbose_errors.get('count', 0)}",
                "Server disclosure headers: " + (" | ".join(f"{item.get('header')}: {item.get('value')}" for item in server_header.get("headers", [])) or "Not observed"),
            ]),
            "fix": "Restrict unnecessary HTTP methods, disable TRACE, remove avoidable server banners, and return generic production-safe error responses.",
        })

    if (graphql.get("count", 0) or source_maps.get("count", 0) or directory_listing.get("count", 0) or forced_browsing.get("count", 0) or technology.get("status")):
        items.append({
            "title": "Exposure And Discovery Checks",
            "severity": "Medium" if (graphql.get("count", 0) or source_maps.get("count", 0) or directory_listing.get("count", 0) or forced_browsing.get("count", 0)) else "Low",
            "status": technology.get("status", "Discovery checks completed"),
            "analysis": graphql.get("status", "GraphQL exposure not observed."),
            "evidence": "\n".join([
                f"Source maps: {source_maps.get('status', 'Not available')}",
                f"Directory listing: {directory_listing.get('status', 'Not available')}",
                f"Forced browsing: {forced_browsing.get('status', 'Not available')}",
            ]),
            "fix": "Remove public debugging artifacts, review directly reachable internal-style paths, and expose only the routes and metadata that are intentionally public.",
        })

    if auth_surface.get("auth_detected"):
        items.append({
            "title": "Authentication Coverage",
            "severity": "Medium",
            "status": auth_surface.get("status", "Authentication surface detected"),
            "analysis": "If login, signup, or password reset functionality exists, a public-only scan cannot be treated as full application assurance.",
            "evidence": "\n".join([
                f"Classification: {auth_surface.get('classification', 'unknown')}",
                f"Assessment note: {auth_surface.get('note', 'Not available')}",
                "Signals: " + (" | ".join(f"{item.get('type')}: {item.get('value')}" for item in auth_surface.get("signals", [])) or "No auth-related signals detected"),
            ]),
            "fix": "Run an authenticated scan or manual review before treating the application as fully assessed.",
        })

    if csrf.get("count", 0) or "No throttling" in str(api_rate_limiting.get("status", "")):
        items.append({
            "title": "Application Defense Checks",
            "severity": "Medium",
            "status": csrf.get("status", "Application defense checks completed"),
            "analysis": api_rate_limiting.get("status", "API rate-limiting check not available."),
            "evidence": "\n".join([
                f"POST forms without token signals: {csrf.get('count', 0)}",
                f"Rate-limit probe statuses: {', '.join(str(x) for x in api_rate_limiting.get('statuses', [])) or 'Not tested'}",
            ]),
            "fix": "Add anti-CSRF protections on state-changing forms and apply throttling or abuse controls to exposed API endpoints.",
        })

    covered = {
        "Missing Security Headers", "Weak Cookie Flags", "SSL Certificate Issue", "SSL Certificate Expiring Soon",
        "Weak TLS Protocol Supported", "Weak Cipher Suites Accepted", "HTTP Methods Enabled", "HTTP TRACE Enabled",
        "Verbose Error Messages", "Server Header Disclosure", "GraphQL Introspection", "JavaScript Source Maps",
        "Directory Listing Enabled", "Forced Browsing", "CSRF", "API Rate Limiting Absent", "JavaScript Secrets Exposed",
        "DOM-Based XSS", "Open Redirect", "Reflected XSS", "Stored XSS", "SQL Injection", "Sensitive Path Detected",
    }
    for finding in findings:
        raw = finding.get("raw", {})
        if raw.get("vulnerability") in covered:
            continue
        items.append({
            "title": finding.get("title", "Security finding"),
            "severity": finding.get("severity", "Info"),
            "priority": finding.get("priority", "Review"),
            "confidence": finding.get("confidence", "Medium"),
            "status": finding.get("title", "Finding detected"),
            "analysis": finding.get("impact", "Review this finding in application context."),
            "evidence": finding.get("evidence_summary", "Evidence not available"),
            "fix": finding.get("remediation", "Validate and remediate according to security standards."),
        })
    return items


def _assessment_card_html(item: dict, number: int) -> str:
    severity = escape(str(item.get("severity", "Info")))
    title = escape(str(item.get("title", "Security finding")))
    status = escape(str(item.get("status", "Review required")))
    analysis = escape(str(item.get("analysis", "Review this issue in application context.")))
    evidence = escape(str(item.get("evidence", "Evidence not available")))
    fix = escape(str(item.get("fix", "Validate and remediate according to security standards.")))
    priority = str(item.get("priority", "")).strip()
    confidence = str(item.get("confidence", "")).strip()
    meta = [f"<span class='pill sev-{severity.lower()}'>{severity}</span>"]
    if priority:
        meta.append(f"<span class='pill'>{escape(priority)}</span>")
    if confidence:
        meta.append(f"<span class='pill'>Confidence: {escape(confidence)}</span>")
    return (
        f"<div class='card'>"
        f"<div class='assessment-head'><div class='assessment-number'>{number}</div><div>"
        f"<h4>{title}</h4><div class='finding-meta'>{''.join(meta)}</div></div></div>"
        f"<p><strong>Status:</strong> {status}</p>"
        f"<p><strong>Analysis:</strong> {analysis}</p>"
        f"<p><strong>Evidence:</strong></p><div class='evidence'>{evidence}</div>"
        f"<p><strong>Actionable fix:</strong> {fix}</p>"
        f"</div>"
    )


def _risk_background(risk: str) -> str:
    risk = str(risk)
    if risk in {"Critical", "High"}:
        return "#fef3f2"
    if risk == "Medium":
        return "#fffaeb"
    return "#ecfdf3"


def _risk_color(risk: str) -> str:
    risk = str(risk)
    if risk in {"Critical", "High"}:
        return "#b42318"
    if risk == "Medium":
        return "#b54708"
    return "#087443"
