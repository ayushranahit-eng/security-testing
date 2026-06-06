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
    security = report.get("security_analysis", {})
    findings = report.get("findings", [])
    top_risks = summary.get("top_risks", [])
    actions = report.get("recommended_actions", {}).get("priority_order", [])
    attack_surface = report.get("attack_surface_analysis", {})

    risk = escape(summary.get("risk_rating", "Informational"))
    target = escape(meta.get("target", "Security Assessment"))
    completed = escape(meta.get("scan_completed_at", ""))
    summary_text = escape(summary.get("summary", ""))

    top_risk_cards = "".join(
        _finding_card_html(item, compact=True) for item in top_risks
    ) or '<div class="card"><h4>No high-priority findings</h4><p>No urgent automated findings were detected in this scan.</p></div>'

    detailed_cards = "".join(
        _finding_card_html(item, compact=False) for item in findings
    ) or '<div class="card"><h4>No actionable findings</h4><p>The scan did not identify actionable findings in the tested scope.</p></div>'

    action_items = "".join(
        f"<li>{escape(step)}</li>" for step in actions
    ) or "<li>Re-run the assessment after any remediation changes.</li>"

    surface_pages = attack_surface.get("pages", {})
    surface_inputs = attack_surface.get("inputs", {})
    surface_network = attack_surface.get("network", {}).get("counts", {})

    headers = security.get("headers", {})
    cookies = security.get("cookies", {})
    auth_surface = security.get("auth_surface", {})
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

    header_evidence = newline.join(
        f"{item.get('header')}: {item.get('impact')}" for item in headers.get("missing", [])
    ) or "No missing required headers reported"
    cookie_evidence = newline.join(
        f"{item.get('name')} [{item.get('category')}]: {item.get('issue_summary')}"
        for item in cookies.get("notable_cookies", [])
    ) or "No notable cookie issues reported"
    auth_surface_evidence = newline.join(
        f"{item.get('type')}: {item.get('value')}"
        for item in auth_surface.get("signals", [])[:10]
    ) or "No auth-related public-surface signals detected"
    js_secret_evidence = newline.join(
        f"{item.get('type')} - {item.get('source')} - {item.get('value_preview')}"
        for item in javascript_secrets.get("top_detections", [])[:10]
    ) or "No JavaScript secret exposure detected"
    dom_xss_evidence = newline.join(
        f"{item.get('vector')} - {item.get('tested_url')}"
        for item in dom_xss.get("vectors", [])[:10]
    ) or "No DOM-based XSS detected in the tested fragment flows"
    open_redirect_evidence = newline.join(
        f"{item.get('vector')} - {item.get('tested_url')} -> {item.get('redirect_target')}"
        for item in open_redirect.get("vectors", [])[:10]
    ) or "No open redirect detected in the tested flows"
    reflected_xss_evidence = newline.join(
        f"{item.get('vector')} - {item.get('tested_url')}"
        for item in reflected_xss.get("vectors", [])[:10]
    ) or "No reflected XSS detected in the tested parameters and forms"
    stored_xss_evidence = newline.join(
        f"{item.get('vector')} - {item.get('tested_url')}"
        for item in stored_xss.get("vectors", [])[:10]
    ) or "No stored XSS detected in the tested low-risk forms"
    sqli_evidence = newline.join(
        f"{item.get('vector')} - {item.get('tested_url')} - {item.get('evidence')}"
        for item in sql_injection.get("vectors", [])[:10]
    ) or "No SQL injection evidence detected in the tested low-risk flows"
    sensitive_path_evidence = newline.join(
        f"{item.get('path')} - HTTP {item.get('http_status')} - {item.get('severity')}"
        for item in (sensitive_paths.get("exposed_paths", []) + sensitive_paths.get("blocked_paths", []))[:10]
    ) or "No sensitive path evidence reported"
    cors_evidence = newline.join(
        f"{item.get('issue_type')}: {item.get('description')}"
        for item in cors.get("issues", [])[:10]
    ) or "No CORS issues reported"

    header_card = _control_card(
        "Security Headers",
        headers.get("status", "Not available"),
        "Missing browser protections can increase exposure to XSS impact, clickjacking, MIME sniffing, referrer leakage, and HTTPS downgrade risk.",
        header_evidence,
        "Medium",
    )
    cookie_card = _control_card(
        "SSL And Cookies",
        f"{ssl.get('status', 'Not available')} - {ssl.get('note', '')}",
        cookies.get("status", "Not available"),
        cookie_evidence,
        "Low",
    )
    auth_surface_card = _control_card(
        "Authentication Coverage",
        auth_surface.get("status", "Not available"),
        auth_surface.get(
            "note",
            "Authentication surface classification was not available.",
        ),
        auth_surface_evidence,
        "Medium" if auth_surface.get("auth_detected") else "Low",
    )
    js_secret_card = _control_card(
        "JavaScript Secret Exposure",
        javascript_secrets.get("status", "Not available"),
        f"{javascript_secrets.get('scanned_files', 0)} JavaScript file(s) and {javascript_secrets.get('scanned_inline_pages', 0)} inline-script page(s) reviewed.",
        js_secret_evidence,
        "High" if javascript_secrets.get("count", 0) else "Low",
    )
    dom_xss_card = _control_card(
        "DOM-Based XSS Validation",
        dom_xss.get("status", "Not available"),
        "DOM-based XSS happens in browser-side code and can execute without server-side reflection.",
        dom_xss_evidence,
        "High" if dom_xss.get("count", 0) else "Low",
    )
    open_redirect_card = _control_card(
        "Open Redirect Validation",
        open_redirect.get("status", "Not available"),
        "Redirect abuse can turn a trusted domain into a phishing or token-forwarding step in an attack chain.",
        open_redirect_evidence,
        "High" if open_redirect.get("count", 0) else "Low",
    )
    reflected_xss_card = _control_card(
        "Reflected XSS Validation",
        reflected_xss.get("status", "Not available"),
        "Unsanitized reflection can enable browser-side script execution, phishing overlays, and session compromise.",
        reflected_xss_evidence,
        "High" if reflected_xss.get("count", 0) else "Low",
    )
    stored_xss_card = _control_card(
        "Stored XSS Validation",
        stored_xss.get("status", "Not available"),
        "Stored XSS can affect every user who later views the injected record or page.",
        stored_xss_evidence,
        "High" if stored_xss.get("count", 0) else "Low",
    )
    sqli_card = _control_card(
        "SQL Injection Validation",
        sql_injection.get("status", "Not available"),
        "SQL injection can expose database content, modify records, or support authentication bypass and wider compromise.",
        sqli_evidence,
        "High" if sql_injection.get("count", 0) else "Low",
    )
    sensitive_paths_card = _control_card(
        "Sensitive Paths",
        sensitive_paths.get("status", "Not available"),
        f"{len(sensitive_paths.get('exposed_paths', []))} readable path(s), {len(sensitive_paths.get('blocked_paths', []))} blocked/detected path(s). HTTP 403 means blocked, not confirmed exposure.",
        sensitive_path_evidence,
        "Medium" if sensitive_paths.get("exposed_paths") else "Low",
    )
    cors_card = _control_card(
        "CORS",
        cors.get("status", "Not available"),
        cors.get("engineer_summary", "No CORS summary available."),
        cors_evidence,
        "High" if "High" in cors.get("status", "") else "Medium" if "Medium" in cors.get("status", "") else "Low",
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
        <div class="metric"><strong>{counts.get("Critical", 0) + counts.get("High", 0) + counts.get("Medium", 0)}</strong><span>Medium+ findings</span></div>
      </div>
    </section>

    <section class="section">
      <h2>Top Security Priorities</h2>
      <div class="list">{top_risk_cards}</div>
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
      <h2>Security Control Analysis</h2>
      <div class="list">
        {header_card}
        {cookie_card}
        {auth_surface_card}
        {js_secret_card}
        {dom_xss_card}
        {open_redirect_card}
        {reflected_xss_card}
        {stored_xss_card}
        {sqli_card}
        {sensitive_paths_card}
        {cors_card}
      </div>
    </section>

    <section class="section">
      <h2>Detailed Findings</h2>
      <div class="list">{detailed_cards}</div>
    </section>

    <section class="section">
      <h2>Recommended Next Steps</h2>
      <ul>{action_items}</ul>
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


def _finding_card_html(item: dict, compact: bool) -> str:
    severity = str(item.get("severity", "Info"))
    priority = escape(str(item.get("priority", "Review")))
    confidence = escape(str(item.get("confidence", "Medium")))
    title = escape(str(item.get("title", "Security finding")))
    impact = escape(str(item.get("impact", "Review this finding in application context.")))
    evidence = escape(str(item.get("evidence_summary", "Evidence not available")))
    remediation = escape(str(item.get("remediation", "Validate and remediate according to security standards.")))
    classes = f"pill sev-{severity.lower()}"
    extra = "" if compact else f"<p><strong>Evidence:</strong></p><div class='evidence'>{evidence}</div><p><strong>Actionable fix:</strong> {remediation}</p>"
    return (
        f"<div class='card'>"
        f"<h4>{title}</h4>"
        f"<div class='finding-meta'><span class='{classes}'>{escape(severity)}</span><span class='pill'>{priority}</span>"
        + ("" if compact else f"<span class='pill'>Confidence: {confidence}</span>")
        + f"</div><p><strong>Impact:</strong> {impact}</p>{extra}</div>"
    )


def _control_card(title: str, status: str, impact: str, evidence: str, severity: str) -> str:
    return (
        f"<div class='card'>"
        f"<h4>{escape(title)}</h4>"
        f"<div class='finding-meta'><span class='pill sev-{escape(severity.lower())}'>{escape(severity)}</span></div>"
        f"<p><strong>Status:</strong> {escape(status)}</p>"
        f"<p><strong>Analysis:</strong> {escape(impact)}</p>"
        f"<div class='evidence'>{escape(evidence)}</div>"
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
