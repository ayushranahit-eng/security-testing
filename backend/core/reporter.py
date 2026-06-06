"""
Report generator.

The scanner collects a lot of raw evidence. This module turns that evidence
into a tighter engineer-readable report: priority, impact, confidence,
evidence, and concrete remediation.
"""

from html import unescape
from urllib.parse import urlparse


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
STATIC_EXTENSIONS = {
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".webm", ".pdf", ".txt", ".xml",
}
PAGE_EXTENSIONS = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}
TRACKING_HOST_KEYWORDS = {
    "google-analytics", "googletagmanager", "googleadservices", "doubleclick",
    "facebook", "hotjar", "clarity", "segment", "mixpanel", "gstatic",
    "googleapis", "cloudflareinsights",
}
THIRD_PARTY_SERVICE_KEYWORDS = {"tawk", "recaptcha", "captcha", "stripe", "paypal"}
TRACKING_COOKIE_PREFIXES = (
    "_ga", "_gid", "_gcl", "_fbp", "_gat", "test_cookie",
    "twk_", "tawk", "Tawk",
)


def generate_readable_json(data: dict, scan_time: str) -> dict:
    target_url = data.get("target", "")
    findings = data.get("findings", [])
    api_analysis = _classify_network_calls(target_url, data.get("api_calls", []))
    auth_surface_analysis = _analyze_auth_surface(data.get("auth_surface", {}))
    sensitive_analysis = _analyze_sensitive_paths(data.get("sensitive_paths", []))
    cookie_analysis = _analyze_cookies(data.get("cookies", []))
    http_method_analysis = _analyze_http_methods(data.get("http_methods", {}))
    js_secret_analysis = _analyze_javascript_secrets(data.get("javascript_secrets", {}))
    technology_analysis = _analyze_technology(data.get("technology_fingerprint", {}))
    graphql_analysis = _analyze_graphql(data.get("graphql", {}))
    api_rate_limit_analysis = _analyze_rate_limits(data.get("api_rate_limiting", {}))
    csrf_analysis = _analyze_csrf(data.get("csrf", {}))
    source_map_analysis = _analyze_source_maps(data.get("source_maps", {}))
    directory_listing_analysis = _analyze_directory_listing(data.get("directory_listing", {}))
    forced_browsing_analysis = _analyze_forced_browsing(data.get("forced_browsing", {}))
    verbose_error_analysis = _analyze_verbose_errors(data.get("verbose_errors", {}))
    dom_xss_analysis = _analyze_dom_xss(data.get("dom_xss", []))
    open_redirect_analysis = _analyze_open_redirect(data.get("open_redirect", []))
    reflected_xss_analysis = _analyze_reflected_xss(data.get("reflected_xss", []))
    stored_xss_analysis = _analyze_stored_xss(data.get("stored_xss", []))
    sql_injection_analysis = _analyze_sql_injection(data.get("sql_injection", []))
    finding_analysis = _analyze_findings(findings)
    counts = _severity_counts(finding_analysis["findings"])

    return {
        "scan_metadata": {
            "target": target_url,
            "scan_completed_at": scan_time,
            "status": "completed",
            "coverage": {
                "scan_mode": "unauthenticated_public",
                "auth_surface_detected": auth_surface_analysis["auth_detected"],
                "classification": auth_surface_analysis["classification"],
                "note": auth_surface_analysis["note"],
            },
        },
        "executive_summary": {
            "risk_rating": _overall_risk(counts, sensitive_analysis),
            "scope": {
                "pages_crawled": len(_unique_clean(data.get("pages", []))),
                "forms_discovered": len(data.get("forms", [])),
                "input_fields_found": len(data.get("inputs", [])),
                "buttons_observed": len(data.get("buttons", [])),
                "network_requests_captured": len(data.get("api_calls", [])),
                "cookies_analyzed": len(data.get("cookies", [])),
            },
            "finding_counts": counts,
            "top_risks": finding_analysis["top_risks"],
            "summary": _executive_summary_text(
                counts,
                auth_surface_analysis,
                sensitive_analysis,
                cookie_analysis,
                http_method_analysis,
                js_secret_analysis,
                technology_analysis,
                graphql_analysis,
                api_rate_limit_analysis,
                csrf_analysis,
                source_map_analysis,
                directory_listing_analysis,
                forced_browsing_analysis,
                verbose_error_analysis,
                dom_xss_analysis,
                open_redirect_analysis,
                reflected_xss_analysis,
                stored_xss_analysis,
                sql_injection_analysis,
            ),
        },
        "attack_surface_analysis": {
            "pages": {
                "count": len(_unique_clean(data.get("pages", []))),
                "note": "Page URLs are counted but not listed in the business report to avoid noisy file-path dumps.",
            },
            "inputs": _summarize_inputs(data.get("inputs", [])),
            "network": api_analysis,
        },
        "security_analysis": {
            "auth_surface": auth_surface_analysis,
            "headers": _analyze_headers(data.get("security_headers", {})),
            "ssl": _analyze_ssl(data.get("ssl", {})),
            "cookies": cookie_analysis,
            "http_methods": http_method_analysis,
            "javascript_secrets": js_secret_analysis,
            "technology": technology_analysis,
            "graphql": graphql_analysis,
            "api_rate_limiting": api_rate_limit_analysis,
            "csrf": csrf_analysis,
            "source_maps": source_map_analysis,
            "directory_listing": directory_listing_analysis,
            "forced_browsing": forced_browsing_analysis,
            "verbose_errors": verbose_error_analysis,
            "dom_xss": dom_xss_analysis,
            "open_redirect": open_redirect_analysis,
            "reflected_xss": reflected_xss_analysis,
            "stored_xss": stored_xss_analysis,
            "sql_injection": sql_injection_analysis,
            "sensitive_paths": sensitive_analysis,
            "cors": _analyze_cors_for_readable_report(data.get("cors_analysis", {})),
        },
        "findings": finding_analysis["findings"],
        "recommended_actions": _generate_next_steps(findings, data, api_analysis, sensitive_analysis),
        "raw_data": {
            "note": "Raw scanner output is included for automation and deep review.",
            "complete_scan_results": data,
        },
    }


def generate_text_report(data: dict, scan_time: str) -> str:
    target_url = data.get("target", "")
    findings = data.get("findings", [])
    api_analysis = _classify_network_calls(target_url, data.get("api_calls", []))
    auth_surface_analysis = _analyze_auth_surface(data.get("auth_surface", {}))
    sensitive_analysis = _analyze_sensitive_paths(data.get("sensitive_paths", []))
    cookie_analysis = _analyze_cookies(data.get("cookies", []))
    http_method_analysis = _analyze_http_methods(data.get("http_methods", {}))
    js_secret_analysis = _analyze_javascript_secrets(data.get("javascript_secrets", {}))
    technology_analysis = _analyze_technology(data.get("technology_fingerprint", {}))
    graphql_analysis = _analyze_graphql(data.get("graphql", {}))
    api_rate_limit_analysis = _analyze_rate_limits(data.get("api_rate_limiting", {}))
    csrf_analysis = _analyze_csrf(data.get("csrf", {}))
    source_map_analysis = _analyze_source_maps(data.get("source_maps", {}))
    directory_listing_analysis = _analyze_directory_listing(data.get("directory_listing", {}))
    forced_browsing_analysis = _analyze_forced_browsing(data.get("forced_browsing", {}))
    verbose_error_analysis = _analyze_verbose_errors(data.get("verbose_errors", {}))
    dom_xss_analysis = _analyze_dom_xss(data.get("dom_xss", []))
    open_redirect_analysis = _analyze_open_redirect(data.get("open_redirect", []))
    reflected_xss_analysis = _analyze_reflected_xss(data.get("reflected_xss", []))
    stored_xss_analysis = _analyze_stored_xss(data.get("stored_xss", []))
    sql_injection_analysis = _analyze_sql_injection(data.get("sql_injection", []))
    input_summary = _summarize_inputs(data.get("inputs", []))
    analyzed_findings = _analyze_findings(findings)["findings"]
    counts = _severity_counts(analyzed_findings)

    sep = "=" * 72
    sep2 = "-" * 72
    lines = []
    add = lines.append

    add(sep)
    add("SECURITY SCAN REPORT")
    add(sep)
    add(f"Target    : {target_url}")
    add(f"Scan Date : {scan_time}")
    add("")

    add("EXECUTIVE SUMMARY")
    add(sep2)
    add(f"Overall Risk : {_overall_risk(counts, sensitive_analysis)}")
    add(f"Findings     : {len(analyzed_findings)} total "
        f"({counts['Critical']} Critical, {counts['High']} High, "
        f"{counts['Medium']} Medium, {counts['Low']} Low)")
    add(f"Scope        : {len(_unique_clean(data.get('pages', [])))} pages, "
        f"{len(data.get('forms', []))} forms, {len(data.get('inputs', []))} inputs, "
        f"{len(data.get('api_calls', []))} network requests")
    add("")
    for line in _wrap(
        _executive_summary_text(
            counts,
            auth_surface_analysis,
            sensitive_analysis,
            cookie_analysis,
            http_method_analysis,
            js_secret_analysis,
            technology_analysis,
            graphql_analysis,
            api_rate_limit_analysis,
            csrf_analysis,
            source_map_analysis,
            directory_listing_analysis,
            forced_browsing_analysis,
            verbose_error_analysis,
            dom_xss_analysis,
            open_redirect_analysis,
            reflected_xss_analysis,
            stored_xss_analysis,
            sql_injection_analysis,
        ),
        70,
    ):
        add(line)
    add("")

    add("TOP PRIORITIES")
    add(sep2)
    if not analyzed_findings:
        add("No actionable findings were detected.")
    else:
        for idx, finding in enumerate(analyzed_findings[:5], 1):
            add(f"{idx}. [{finding['severity']}] {finding['title']}")
            add(f"   Priority   : {finding['priority']}")
            add(f"   Confidence : {finding['confidence']}")
            add(f"   Impact     : {finding['impact']}")
            add(f"   Fix        : {finding['remediation']}")
            add("")

    add("ATTACK SURFACE")
    add(sep2)
    add(f"Pages crawled        : {len(_unique_clean(data.get('pages', [])))}")
    add(f"Forms discovered     : {len(data.get('forms', []))}")
    add(f"Input fields         : {input_summary['total']} total")
    add(f"Required inputs      : {input_summary['required_inputs']}")
    add(f"File inputs          : {input_summary['file_inputs']}")
    add(f"Hidden inputs        : {input_summary['hidden_inputs']}")
    add("")
    add("Input types:")
    for input_type, count in input_summary["by_type"].items():
        add(f"  - {input_type}: {count}")
    add("")

    add("NETWORK REQUEST ANALYSIS")
    add(sep2)
    add(f"Captured requests    : {api_analysis['total']}")
    add(f"First-party pages    : {api_analysis['counts']['first_party_pages']}")
    add(f"First-party API-like : {api_analysis['counts']['first_party_api']}")
    add(f"First-party static   : {api_analysis['counts']['first_party_static']}")
    add(f"Third-party services : {api_analysis['counts']['third_party_service']}")
    add(f"Tracking/analytics   : {api_analysis['counts']['tracking_or_analytics']}")
    add(f"Other third-party    : {api_analysis['counts']['other_third_party']}")
    add("")
    add("AUTHENTICATION COVERAGE")
    add(sep2)
    add(f"Status      : {auth_surface_analysis['status']}")
    add(f"Scan mode   : Unauthenticated public scan")
    add(f"Assessment  : {auth_surface_analysis['note']}")
    if auth_surface_analysis["signals"]:
        add("Auth-related signals:")
        for signal in auth_surface_analysis["signals"][:8]:
            add(f"  - {signal['type']}: {signal['value']}")
    add("")
    if api_analysis["first_party_api"]:
        add("First-party API-like samples:")
        for call in api_analysis["first_party_api"][:10]:
            add(f"  - {call}")
    else:
        add("No clear first-party API endpoints were separated from static/third-party traffic.")
    add("")

    add("SECURITY CONTROLS")
    add(sep2)
    headers = _analyze_headers(data.get("security_headers", {}))
    add(f"Headers : {headers['status']}")
    for item in headers["missing"]:
        add(f"  - Missing {item['header']}: {item['impact']}")
    ssl = _analyze_ssl(data.get("ssl", {}))
    add(f"SSL     : {ssl['status']} ({ssl['note']})")
    add(f"Cookies : {cookie_analysis['status']}")
    for item in cookie_analysis["notable_cookies"][:8]:
        add(f"  - {item['name']} [{item['category']}]: {item['risk']} - {item['issue_summary']}")
    add(f"HTTP methods : {http_method_analysis['status']}")
    add(f"Technology   : {technology_analysis['status']}")
    add(f"Auth surface : {auth_surface_analysis['status']}")
    add("")

    add("ACTIVE VALIDATION")
    add(sep2)
    add(f"JavaScript secret scan : {js_secret_analysis['status']}")
    add(f"JS files scanned       : {js_secret_analysis['scanned_files']}")
    for item in js_secret_analysis["top_detections"][:8]:
        add(f"  - [{item['severity']}] {item['type']} in {item['source']}: {item['value_preview']}")
    add(f"GraphQL introspection  : {graphql_analysis['status']}")
    add(f"API rate limiting      : {api_rate_limit_analysis['status']}")
    add(f"CSRF risk              : {csrf_analysis['status']}")
    add(f"Source map exposure    : {source_map_analysis['status']}")
    add(f"Directory listing      : {directory_listing_analysis['status']}")
    add(f"Forced browsing        : {forced_browsing_analysis['status']}")
    add(f"Verbose errors         : {verbose_error_analysis['status']}")
    add(f"DOM-based XSS testing  : {dom_xss_analysis['status']}")
    add(f"DOM XSS vectors found  : {dom_xss_analysis['count']}")
    for item in dom_xss_analysis["vectors"][:8]:
        add(f"  - [{item['severity']}] {item['vector']} on {item['tested_url']}")
    add(f"Open redirect testing  : {open_redirect_analysis['status']}")
    add(f"Redirect vectors found : {open_redirect_analysis['count']}")
    for item in open_redirect_analysis["vectors"][:8]:
        add(f"  - [{item['severity']}] {item['vector']} on {item['tested_url']} -> {item['redirect_target']}")
    add(f"Reflected XSS testing  : {reflected_xss_analysis['status']}")
    add(f"XSS vectors detected   : {reflected_xss_analysis['count']}")
    for item in reflected_xss_analysis["vectors"][:8]:
        add(f"  - [{item['severity']}] {item['vector']} on {item['tested_url']}")
    add(f"Stored XSS testing     : {stored_xss_analysis['status']}")
    add(f"Stored XSS vectors     : {stored_xss_analysis['count']}")
    for item in stored_xss_analysis["vectors"][:8]:
        add(f"  - [{item['severity']}] {item['vector']} on {item['tested_url']}")
    add(f"SQL injection testing  : {sql_injection_analysis['status']}")
    add(f"SQLi vectors detected  : {sql_injection_analysis['count']}")
    for item in sql_injection_analysis["vectors"][:8]:
        add(f"  - [{item['severity']}] {item['vector']} on {item['tested_url']}")
    add("")

    add("SENSITIVE PATH ANALYSIS")
    add(sep2)
    add(f"Paths probed         : {sensitive_analysis['paths_probed']}")
    add(f"Exposed/readable     : {len(sensitive_analysis['exposed_paths'])}")
    add(f"Blocked/detected     : {len(sensitive_analysis['blocked_paths'])}")
    add("")
    if sensitive_analysis["exposed_paths"]:
        add("Readable paths needing review:")
        for path in sensitive_analysis["exposed_paths"][:10]:
            add(f"  - [{path['severity']}] {path['path']} "
                f"(HTTP {path['http_status']}, {path['content_type']}, {path['response_size_bytes']}B)")
    if sensitive_analysis["blocked_paths"]:
        add("Blocked paths detected, not confirmed exposed:")
        for path in sensitive_analysis["blocked_paths"][:10]:
            add(f"  - [{path['severity']}] {path['path']} (HTTP {path['http_status']})")
    if not sensitive_analysis["exposed_paths"] and not sensitive_analysis["blocked_paths"]:
        add("No sensitive paths were exposed or detected.")
    add("")

    add("CORS ANALYSIS")
    add(sep2)
    cors = _analyze_cors_for_readable_report(data.get("cors_analysis", {}))
    add(f"Status : {cors['status']}")
    add(f"Note   : {cors['engineer_summary']}")
    for issue in cors.get("issues", []):
        add(f"  - [{issue['severity']}] {issue['issue_type']}: {issue['description']}")
    add("")

    add("FINDINGS DETAIL")
    add(sep2)
    if not analyzed_findings:
        add("No actionable findings were detected.")
    else:
        for idx, finding in enumerate(analyzed_findings, 1):
            add(f"{idx}. [{finding['severity']}] {finding['title']}")
            add(f"   Confidence : {finding['confidence']}")
            add(f"   Impact     : {finding['impact']}")
            add(f"   Evidence   : {finding['evidence_summary']}")
            add(f"   Remediate  : {finding['remediation']}")
            add("")

    add("RECOMMENDED NEXT STEPS")
    add(sep2)
    steps = _generate_next_steps(findings, data, api_analysis, sensitive_analysis)
    for step in steps["priority_order"]:
        add(f"- {step}")
    add("")
    add(sep)
    add("END OF REPORT")
    add(sep)

    return "\n".join(lines)


def _severity_counts(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in findings:
        severity = finding.get("severity", "Info")
        counts[severity if severity in counts else "Info"] += 1
    return counts


def _overall_risk(counts: dict, sensitive_analysis: dict) -> str:
    if counts["Critical"] or sensitive_analysis.get("critical_exposure_count", 0):
        return "Critical"
    if counts["High"] or sensitive_analysis.get("high_exposure_count", 0):
        return "High"
    if counts["Medium"]:
        return "Medium"
    if counts["Low"]:
        return "Low"
    return "Informational"


def _executive_summary_text(
    counts: dict,
    auth_surface_analysis: dict,
    sensitive_analysis: dict,
    cookie_analysis: dict,
    http_method_analysis: dict,
    js_secret_analysis: dict,
    technology_analysis: dict,
    graphql_analysis: dict,
    api_rate_limit_analysis: dict,
    csrf_analysis: dict,
    source_map_analysis: dict,
    directory_listing_analysis: dict,
    forced_browsing_analysis: dict,
    verbose_error_analysis: dict,
    dom_xss_analysis: dict,
    open_redirect_analysis: dict,
    reflected_xss_analysis: dict,
    stored_xss_analysis: dict,
    sql_injection_analysis: dict,
) -> str:
    exposed = len(sensitive_analysis.get("exposed_paths", []))
    blocked = len(sensitive_analysis.get("blocked_paths", []))
    cookie_issues = len(cookie_analysis.get("notable_cookies", []))

    parts = []
    if auth_surface_analysis.get("auth_detected"):
        parts.append(
            "Authentication-related functionality was detected, but this assessment was performed without valid credentials. Public attack surface and auth-boundary checks were reviewed, while internal authenticated workflows were not tested."
        )
    else:
        parts.append(
            "No obvious authentication surface was detected in the scanned public scope, so this assessment primarily reflects public-facing exposure."
        )
    if exposed:
        parts.append(
            f"{exposed} sensitive path(s) returned readable content. These should be reviewed first because they may expose configuration, dependency, or application metadata."
        )
    if blocked:
        parts.append(
            f"{blocked} sensitive path(s) returned blocked responses. Treat these as detection signals, not confirmed exposure."
        )
    if http_method_analysis.get("trace_enabled"):
        parts.append("HTTP TRACE appears enabled. Review unnecessary HTTP methods and restrict anything not required.")
    if js_secret_analysis.get("count", 0):
        parts.append(
            f"{js_secret_analysis['count']} JavaScript secret exposure(s) were detected. Treat any live key or token in frontend code as immediately actionable."
        )
    if graphql_analysis.get("count", 0):
        parts.append("GraphQL introspection is exposed on at least one endpoint. Review whether schema visibility is intentional for this environment.")
    if api_rate_limit_analysis.get("status") == "No throttling observed":
        parts.append("No clear API throttling was observed on the tested endpoint. Review brute-force and scraping defenses.")
    if csrf_analysis.get("count", 0):
        parts.append("POST forms without obvious CSRF tokens were detected. Validate anti-CSRF controls in authenticated workflows.")
    if source_map_analysis.get("count", 0):
        parts.append("JavaScript source maps were publicly accessible. These can expose original source and implementation detail.")
    if directory_listing_analysis.get("count", 0):
        parts.append("Directory listing was detected on at least one path, which can disclose internal file structure.")
    if forced_browsing_analysis.get("count", 0):
        parts.append("Unlinked or sensitive-looking paths were reachable directly. Review access control and route exposure.")
    if verbose_error_analysis.get("count", 0):
        parts.append("Verbose error handling was observed. Stack traces or exception details can help attackers fingerprint the application.")
    if dom_xss_analysis.get("count", 0):
        parts.append(
            f"{dom_xss_analysis['count']} DOM-based XSS path(s) were detected from client-side rendering of attacker-controlled fragment input."
        )
    if open_redirect_analysis.get("count", 0):
        parts.append(
            f"{open_redirect_analysis['count']} open redirect path(s) were validated. These can be abused for phishing and trust-hijacking from the target domain."
        )
    if reflected_xss_analysis.get("count", 0):
        parts.append(
            f"{reflected_xss_analysis['count']} reflected XSS validation path(s) returned unsanitized HTML reflection and should be reviewed with priority."
        )
    if stored_xss_analysis.get("count", 0):
        parts.append(
            f"{stored_xss_analysis['count']} stored XSS path(s) showed payload persistence after submission and reload, which can indicate multi-user browser compromise risk."
        )
    if sql_injection_analysis.get("count", 0):
        parts.append(
            f"{sql_injection_analysis['count']} SQL injection signal(s) were detected from active input testing. Database error leakage or strong response anomalies should be triaged quickly."
        )
    if counts["Medium"] or counts["High"] or counts["Critical"]:
        parts.append(
            "The scanner found issues that should be remediated, but exploitability depends on application context and manual validation."
        )
    if cookie_issues:
        parts.append(
            "Cookie issues were detected; third-party marketing cookies should be separated from true authentication/session cookies during triage."
        )
    if not parts:
        parts.append("No major automated findings were detected in the current unauthenticated scan.")
    return " ".join(parts)


def _unique_clean(values: list) -> list:
    cleaned = []
    seen = set()
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    return cleaned


def _classify_network_calls(target_url: str, calls: list) -> dict:
    target_host = urlparse(target_url).netloc.lower()
    buckets = {
        "first_party_pages": [],
        "first_party_api": [],
        "first_party_static": [],
        "third_party_service": [],
        "tracking_or_analytics": [],
        "other_third_party": [],
    }

    for raw_call in _unique_clean([unescape(str(c)) for c in calls]):
        parsed = urlparse(raw_call)
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        ext = _extension(path)
        is_first_party = host == target_host or host.endswith("." + target_host)

        if any(keyword in host for keyword in TRACKING_HOST_KEYWORDS):
            buckets["tracking_or_analytics"].append(raw_call)
        elif any(keyword in host for keyword in THIRD_PARTY_SERVICE_KEYWORDS):
            buckets["third_party_service"].append(raw_call)
        elif is_first_party and (ext in STATIC_EXTENSIONS or "/assets/" in path or "/static/" in path):
            buckets["first_party_static"].append(raw_call)
        elif is_first_party and (ext in PAGE_EXTENSIONS or ext == ""):
            buckets["first_party_pages"].append(raw_call)
        elif is_first_party:
            buckets["first_party_api"].append(raw_call)
        else:
            buckets["other_third_party"].append(raw_call)

    return {
        "total": sum(len(v) for v in buckets.values()),
        "counts": {key: len(value) for key, value in buckets.items()},
        **buckets,
        "note": "Classification is URL-based. Confirm true API endpoints manually before testing authorization or rate limits.",
    }


def _extension(path: str) -> str:
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _summarize_inputs(inputs: list) -> dict:
    by_type = {}
    unique_fields = set()
    required = 0
    for inp in inputs:
        input_type = (inp.get("type") or "unknown").lower()
        by_type[input_type] = by_type.get(input_type, 0) + 1
        if inp.get("required"):
            required += 1
        unique_fields.add((inp.get("page"), inp.get("id"), inp.get("name"), input_type))

    return {
        "total": len(inputs),
        "unique_field_signatures": len(unique_fields),
        "required_inputs": required,
        "file_inputs": by_type.get("file", 0),
        "hidden_inputs": by_type.get("hidden", 0),
        "by_type": dict(sorted(by_type.items(), key=lambda item: item[0])),
        "risk_note": "Inputs are mapped as attack surface. This scanner now performs limited reflected XSS validation, but deeper authenticated and server-side injection testing still requires manual review.",
    }


def _analyze_headers(headers: dict) -> dict:
    missing = headers.get("missing", [])
    present = headers.get("present", [])
    impact_map = {
        "content-security-policy": "reduces XSS impact and limits untrusted script execution",
        "x-frame-options": "reduces clickjacking risk",
        "strict-transport-security": "enforces HTTPS after first trusted visit",
        "x-content-type-options": "reduces MIME-sniffing risk",
        "referrer-policy": "limits URL/referrer leakage to third parties",
    }
    return {
        "status": "Missing headers detected" if missing else "All required headers present",
        "present": present,
        "missing": [
            {
                "header": header,
                "impact": impact_map.get(header, "improves browser-side security posture"),
                "remediation": f"Configure the {header} response header at the web server or application layer.",
            }
            for header in missing
        ],
    }


def _analyze_ssl(ssl_info: dict) -> dict:
    if ssl_info.get("valid"):
        days = ssl_info.get("days_remaining", "?")
        if isinstance(days, int) and days < 7:
            status = "Critical - certificate expires very soon"
            note = f"Expires in {days} day(s). Renew immediately."
        elif isinstance(days, int) and days < 30:
            status = "Warning - certificate expires soon"
            note = f"Expires in {days} day(s). Schedule renewal."
        else:
            status = "Valid"
            note = f"Certificate is valid with {days} day(s) remaining."
        return {
            "status": status,
            "valid": True,
            "expires_on": ssl_info.get("expires", "Unknown"),
            "days_remaining": days,
            "note": note,
        }

    return {
        "status": "Invalid",
        "valid": False,
        "error": ssl_info.get("error", "Unknown error"),
        "note": "SSL validation failed. Verify certificate chain, hostname, and expiry.",
    }


def _analyze_cookies(cookies: list) -> dict:
    if not cookies:
        return {
            "status": "No cookies detected",
            "count": 0,
            "notable_cookies": [],
            "note": "Run an authenticated scan if the application uses session cookies after login.",
        }

    notable = []
    for cookie in cookies:
        issues = []
        if not cookie.get("secure"):
            issues.append("missing Secure")
        if not cookie.get("httpOnly"):
            issues.append("missing HttpOnly")
        if not cookie.get("sameSite") or str(cookie.get("sameSite")).lower() == "none":
            issues.append("weak or missing SameSite")

        if not issues:
            continue

        name = cookie.get("name") or "unnamed"
        category = _cookie_category(name)
        risk = "Medium" if category == "possible_session_or_app_cookie" else "Low"
        notable.append({
            "name": name,
            "category": category,
            "risk": risk,
            "secure": bool(cookie.get("secure")),
            "httpOnly": bool(cookie.get("httpOnly")),
            "sameSite": cookie.get("sameSite") or "Not Set",
            "issue_summary": ", ".join(issues),
            "triage_note": (
                "Prioritize if this stores authentication or user session state."
                if risk == "Medium"
                else "Likely third-party or marketing cookie; verify before treating as session risk."
            ),
        })

    return {
        "status": f"{len(notable)} cookie(s) need review" if notable else "Cookies appear properly configured",
        "count": len(cookies),
        "notable_cookies": notable,
        "note": "Cookie risk depends on whether the cookie carries authentication/session state.",
    }


def _cookie_category(name: str) -> str:
    if name.startswith(TRACKING_COOKIE_PREFIXES):
        return "tracking_or_third_party_cookie"
    return "possible_session_or_app_cookie"


def _analyze_sensitive_paths(probe_results: list) -> dict:
    exposed = []
    blocked = []

    for probe in probe_results:
        severity = probe.get("severity")
        status = probe.get("status")
        if severity not in ("Critical", "High", "Medium", "Low"):
            continue

        item = {
            "path": probe.get("path"),
            "full_url": probe.get("url"),
            "http_status": status,
            "content_type": probe.get("content_type") or "unknown",
            "response_size_bytes": probe.get("size"),
            "severity": severity,
            "confidence": "High" if status and status < 400 else "Medium",
            "engineer_note": _get_sensitive_path_note(probe.get("path", ""), status == 403),
        }
        if status and status < 400:
            exposed.append(item)
        elif status == 403:
            blocked.append(item)

    return {
        "status": "Sensitive path exposure found" if exposed else "No readable sensitive path exposure confirmed",
        "paths_probed": len(probe_results),
        "exposed_paths": exposed,
        "blocked_paths": blocked,
        "critical_exposure_count": len([p for p in exposed if p["severity"] == "Critical"]),
        "high_exposure_count": len([p for p in exposed if p["severity"] == "High"]),
        "note": "HTTP 403 is not confirmed exposure; it is a signal that the route exists or is being blocked by the server/CDN.",
    }


def _analyze_javascript_secrets(scan_result: dict) -> dict:
    detections = scan_result.get("detections", [])
    return {
        "status": scan_result.get("status", "Not run"),
        "count": len(detections),
        "scanned_files": scan_result.get("scanned_javascript_files", 0),
        "scanned_inline_pages": scan_result.get("scanned_inline_script_pages", 0),
        "top_detections": detections,
        "note": scan_result.get("note", "JavaScript secret scanning was not available."),
    }


def _analyze_http_methods(result: dict) -> dict:
    return {
        "status": result.get("status", "Not run"),
        "allow_methods": result.get("allow_methods", []),
        "dangerous_methods": result.get("dangerous_methods", []),
        "trace_enabled": bool(result.get("trace_enabled")),
        "trace_status": result.get("trace_status"),
    }


def _analyze_auth_surface(result: dict) -> dict:
    signals = result.get("signals", [])
    return {
        "status": result.get("status", "Not run"),
        "auth_detected": bool(result.get("auth_detected")),
        "classification": result.get("classification", "unknown"),
        "count": len(signals),
        "signals": signals,
        "note": result.get(
            "note",
            "Authentication surface classification was not available.",
        ),
    }


def _analyze_technology(result: dict) -> dict:
    detected = result.get("detected", [])
    return {
        "status": result.get("status", "Not run"),
        "count": len(detected),
        "detected": detected,
        "note": result.get("note", "Technology fingerprinting was not available."),
    }


def _analyze_graphql(result: dict) -> dict:
    exposed = result.get("exposed_endpoints", [])
    return {
        "status": result.get("status", "Not run"),
        "count": len(exposed),
        "exposed_endpoints": exposed,
    }


def _analyze_rate_limits(result: dict) -> dict:
    return {
        "status": result.get("status", "Not run"),
        "tested_endpoint": result.get("tested_endpoint"),
        "statuses": result.get("statuses", []),
        "throttled": bool(result.get("throttled")),
    }


def _analyze_csrf(result: dict) -> dict:
    forms = result.get("post_forms_without_token", [])
    return {
        "status": result.get("status", "Not run"),
        "count": len(forms),
        "forms": forms,
        "cookies_observed": result.get("cookies_observed", 0),
        "note": result.get("note", "CSRF analysis was not available."),
    }


def _analyze_source_maps(result: dict) -> dict:
    maps = result.get("exposed_maps", [])
    return {
        "status": result.get("status", "Not run"),
        "count": len(maps),
        "maps": maps,
    }


def _analyze_directory_listing(result: dict) -> dict:
    items = result.get("exposed_directories", [])
    return {
        "status": result.get("status", "Not run"),
        "count": len(items),
        "directories": items,
    }


def _analyze_forced_browsing(result: dict) -> dict:
    hits = result.get("hits", [])
    return {
        "status": result.get("status", "Not run"),
        "count": len(hits),
        "hits": hits,
    }


def _analyze_verbose_errors(result: dict) -> dict:
    evidence = result.get("evidence", [])
    return {
        "status": result.get("status", "Not run"),
        "count": len(evidence),
        "evidence": evidence,
    }


def _analyze_reflected_xss(vectors: list) -> dict:
    return {
        "status": "Potential reflected XSS detected" if vectors else "No reflected XSS detected in the tested flows",
        "count": len(vectors),
        "vectors": vectors,
        "note": "The scanner tests URL parameters and low-risk form flows. Full authenticated XSS coverage still requires manual validation.",
    }


def _analyze_dom_xss(vectors: list) -> dict:
    return {
        "status": "Potential DOM-based XSS detected" if vectors else "No DOM-based XSS detected in the tested fragment flows",
        "count": len(vectors),
        "vectors": vectors,
        "note": "Current DOM-XSS testing focuses on URL fragment handling because fragments never reach the server and are ideal for client-side sink checks.",
    }


def _analyze_open_redirect(vectors: list) -> dict:
    return {
        "status": "Potential open redirect detected" if vectors else "No open redirect detected in the tested redirect flows",
        "count": len(vectors),
        "vectors": vectors,
        "note": "Testing is focused on redirect-style parameters and GET-based redirect flows to keep the scan safe.",
    }


def _analyze_sql_injection(vectors: list) -> dict:
    return {
        "status": "Potential SQL injection detected" if vectors else "No SQL injection evidence detected in the tested low-risk flows",
        "count": len(vectors),
        "vectors": vectors,
        "note": "Current SQLi testing is heuristic and conservative. Confirm findings manually, especially where only response anomalies were observed.",
    }


def _analyze_stored_xss(vectors: list) -> dict:
    return {
        "status": "Potential stored XSS detected" if vectors else "No stored XSS detected in the tested low-risk forms",
        "count": len(vectors),
        "vectors": vectors,
        "note": "Stored-XSS testing is conservative and focuses on low-risk text forms. Broader authenticated workflow coverage still requires manual validation.",
    }


def _get_sensitive_path_note(path: str, blocked: bool) -> str:
    path_lower = path.lower()
    if blocked:
        return "The server denied access. Review whether this route should exist publicly, but do not treat it as readable exposure."
    if ".env" in path_lower:
        return "Environment files often contain credentials and API keys."
    if ".git" in path_lower:
        return "Git metadata can expose source history and committed secrets."
    if "composer.json" in path_lower or "package.json" in path_lower:
        return "Dependency metadata can help attackers fingerprint frameworks and vulnerable libraries."
    if "swagger" in path_lower or "openapi" in path_lower:
        return "API documentation can expose endpoints and request shapes."
    if any(token in path_lower for token in ["backup", ".sql", "dump"]):
        return "Backup or database files may contain sensitive application data."
    if "wp-config" in path_lower:
        return "WordPress config files can contain database credentials."
    return "Review the content and restrict access if it exposes internal information."


def _analyze_cors_for_readable_report(cors_analysis: dict) -> dict:
    issues = cors_analysis.get("issues", [])
    if not issues:
        return {
            "status": "No CORS issues detected",
            "tested_url": cors_analysis.get("tested_url"),
            "issues": [],
            "engineer_summary": "No unsafe cross-origin behavior was detected by the automated checks.",
        }

    def _issue_rank(issue):
        return SEVERITY_ORDER.get(issue.get("severity", "Low"), 3)

    worst = min(issues, key=_issue_rank)
    return {
        "status": f"{worst.get('severity', 'Low')} CORS observation",
        "tested_url": cors_analysis.get("tested_url"),
        "issues": [
            {
                "issue_type": issue.get("issue_type"),
                "severity": issue.get("severity"),
                "description": issue.get("description"),
                "evidence": issue.get("evidence", {}),
                "remediation": issue.get("remediation"),
            }
            for issue in issues
        ],
        "engineer_summary": _get_cors_engineer_summary(issues),
    }


def _get_cors_engineer_summary(issues: list) -> str:
    issue_types = {issue.get("issue_type") for issue in issues}
    if "no_cors_policy_defined" in issue_types and len(issues) == 1:
        return (
            "No CORS headers were detected. This is usually safe for browser access because "
            "same-origin restrictions apply, but it should be documented if intentional."
        )
    if any(issue.get("severity") in ("Critical", "High") for issue in issues):
        return "High-risk CORS behavior was detected. Restrict origins to a strict allowlist."
    return "Lower-severity CORS observations were detected. Review policy intent and document allowed origins."


def _analyze_findings(findings: list) -> dict:
    analyzed = [_enrich_finding(finding) for finding in findings]
    analyzed.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 4), f["priority"]))
    return {
        "top_risks": [
            {
                "title": finding["title"],
                "severity": finding["severity"],
                "priority": finding["priority"],
                "impact": finding["impact"],
            }
            for finding in analyzed[:3]
        ],
        "findings": analyzed,
    }


def _enrich_finding(finding: dict) -> dict:
    vuln = finding.get("vulnerability", "Unknown")
    severity = finding.get("severity", "Info")
    details = finding.get("details", [])
    if not isinstance(details, list):
        details = [details] if details else []

    if vuln == "Missing Security Headers":
        adjusted_severity = (
            "Medium"
            if len(details) >= 3 and (
                "content-security-policy" in details
                or "strict-transport-security" in details
            )
            else severity
        )
        return {
            "title": "Missing browser security headers",
            "severity": adjusted_severity,
            "priority": "P2",
            "confidence": "High",
            "impact": "Browsers have fewer built-in protections against XSS impact, clickjacking, MIME sniffing, referrer leakage, and HTTPS downgrade scenarios.",
            "evidence_summary": ", ".join(details) if details else "Required headers were absent from the initial response.",
            "remediation": "Add CSP, X-Frame-Options or frame-ancestors, HSTS, X-Content-Type-Options, and Referrer-Policy at the edge or app server.",
            "raw": finding,
        }

    if "Cookie" in vuln:
        cookie_name = finding.get("cookie", "unknown")
        category = _cookie_category(cookie_name)
        likely_tracking = category == "tracking_or_third_party_cookie"
        return {
            "title": f"Cookie security flags need review: {cookie_name}",
            "severity": "Low" if likely_tracking else severity,
            "priority": "P3" if likely_tracking else "P2",
            "confidence": "Medium",
            "impact": (
                "Likely third-party or marketing cookie. Confirm usage before treating it as session risk."
                if likely_tracking
                else "If this cookie stores session or authentication state, missing flags can increase session theft or CSRF risk."
            ),
            "evidence_summary": ", ".join(details),
            "remediation": "Set Secure, HttpOnly, and an explicit SameSite value for application/session cookies. Triage third-party cookies separately.",
            "raw": finding,
        }

    if "Sensitive Path" in vuln:
        path_entries = finding.get("paths", [])
        exposed = [p for p in path_entries if not p.get("blocked")]
        blocked = [p for p in path_entries if p.get("blocked")]
        return {
            "title": "Sensitive path detected",
            "severity": severity if exposed else "Low",
            "priority": "P1" if exposed and severity in ("Critical", "High") else "P3",
            "confidence": "High" if exposed else "Medium",
            "impact": (
                "Readable sensitive paths can expose credentials, dependency metadata, source control traces, or internal configuration."
                if exposed
                else "Detected paths returned blocked responses. This is not confirmed exposure, but it reveals routes worth reviewing."
            ),
            "evidence_summary": f"{len(exposed)} readable, {len(blocked)} blocked. " + "; ".join(details[:5]),
            "remediation": "Remove public access to sensitive files. For blocked routes, confirm they are intentionally blocked and cannot be bypassed.",
            "raw": finding,
        }

    if vuln == "JavaScript Secrets Exposed":
        secrets = finding.get("secrets", [])
        highest = secrets[0] if secrets else {}
        return {
            "title": "Secrets exposed in frontend JavaScript",
            "severity": severity,
            "priority": "P1",
            "confidence": "High",
            "impact": "Live API keys, access tokens, or cloud credentials in client-side code can allow unauthorized API use, data access, or broader cloud compromise.",
            "evidence_summary": "; ".join(
                f"{item['type']} in {item['source']} ({item['value_preview']})"
                for item in secrets[:5]
            ) or "; ".join(details),
            "remediation": "Remove exposed secrets from client-side code, rotate compromised credentials, move privileged calls server-side, and enforce least-privilege scopes.",
            "raw": finding,
            "source_hint": highest.get("source"),
        }

    if vuln == "Reflected XSS":
        vectors = finding.get("xss_vectors", [])
        return {
            "title": "Reflected XSS behavior detected",
            "severity": severity,
            "priority": "P1",
            "confidence": "High" if vectors else "Medium",
            "impact": "Reflected XSS can let attackers execute script in a victim browser, enabling session theft, phishing overlays, malicious redirects, or account takeover chains.",
            "evidence_summary": "; ".join(
                f"{item['vector']} on {item['tested_url']}"
                for item in vectors[:5]
            ) or "; ".join(details),
            "remediation": "Apply context-aware output encoding, sanitize reflected input, add framework-safe templating, and use CSP as a secondary control rather than the primary fix.",
            "raw": finding,
        }

    if vuln == "Open Redirect":
        vectors = finding.get("redirect_vectors", [])
        return {
            "title": "Open redirect behavior detected",
            "severity": severity,
            "priority": "P1",
            "confidence": "High" if vectors else "Medium",
            "impact": "Open redirects let attackers abuse a trusted domain in phishing campaigns, token leakage chains, or auth-flow manipulation.",
            "evidence_summary": "; ".join(
                f"{item['vector']} on {item['tested_url']} -> {item['redirect_target']}"
                for item in vectors[:5]
            ) or "; ".join(details),
            "remediation": "Restrict redirect destinations to approved internal paths or allowlisted hosts, and reject attacker-controlled absolute URLs.",
            "raw": finding,
        }

    if vuln == "DOM-Based XSS":
        vectors = finding.get("dom_xss_vectors", [])
        return {
            "title": "DOM-based XSS behavior detected",
            "severity": severity,
            "priority": "P1",
            "confidence": "High" if vectors else "Medium",
            "impact": "DOM-based XSS lets client-side code turn attacker-controlled input into live DOM content, enabling browser-side code execution without server reflection.",
            "evidence_summary": "; ".join(
                f"{item['vector']} on {item['tested_url']}"
                for item in vectors[:5]
            ) or "; ".join(details),
            "remediation": "Avoid unsafe sinks such as innerHTML for untrusted input, sanitize fragment and URL-derived values, and use safe DOM APIs or framework escaping.",
            "raw": finding,
        }

    if vuln == "HTTP Methods Enabled":
        methods = finding.get("methods", [])
        return {
            "title": "Risky HTTP methods advertised",
            "severity": severity,
            "priority": "P3",
            "confidence": "High",
            "impact": "Unnecessary HTTP methods can increase attack surface or suggest weak request handling on the origin.",
            "evidence_summary": ", ".join(methods) if methods else "; ".join(details),
            "remediation": "Restrict allowed methods to only what the application requires and deny TRACE, PUT, DELETE, and PATCH where they are not needed.",
            "raw": finding,
        }

    if vuln == "HTTP TRACE Enabled":
        return {
            "title": "HTTP TRACE appears enabled",
            "severity": severity,
            "priority": "P3",
            "confidence": "High",
            "impact": "TRACE can support legacy cross-site tracing abuse and is usually unnecessary on public applications.",
            "evidence_summary": "; ".join(details),
            "remediation": "Disable TRACE at the web server, proxy, or CDN layer unless there is a specific operational requirement.",
            "raw": finding,
        }

    if vuln == "SQL Injection":
        vectors = finding.get("sqli_vectors", [])
        return {
            "title": "SQL injection signal detected",
            "severity": severity,
            "priority": "P1",
            "confidence": "Medium" if vectors else "Low",
            "impact": "Successful SQL injection can expose, modify, or destroy database content and may lead to authentication bypass or broader system compromise.",
            "evidence_summary": "; ".join(
                f"{item['vector']} on {item['tested_url']}: {item['evidence']}"
                for item in vectors[:5]
            ) or "; ".join(details),
            "remediation": "Use parameterized queries, strict server-side validation, ORM-safe bindings, and suppress database error leakage to users.",
            "raw": finding,
        }

    if vuln == "Stored XSS":
        vectors = finding.get("stored_xss_vectors", [])
        return {
            "title": "Stored XSS behavior detected",
            "severity": severity,
            "priority": "P1",
            "confidence": "Medium" if vectors else "Low",
            "impact": "Stored XSS can impact every user who views the injected content, leading to persistent session theft, phishing, or account takeover chains.",
            "evidence_summary": "; ".join(
                f"{item['vector']} on {item['tested_url']}: {item['evidence']}"
                for item in vectors[:5]
            ) or "; ".join(details),
            "remediation": "Apply context-aware output encoding for stored content, sanitize rich text safely, validate input server-side, and review any workflow that persists user-supplied HTML.",
            "raw": finding,
        }

    if vuln == "Verbose Error Messages":
        return {
            "title": "Verbose error handling observed",
            "severity": severity,
            "priority": "P3",
            "confidence": "Medium",
            "impact": "Stack traces, filesystem paths, SQL errors, or framework exceptions can help attackers fingerprint the application and refine exploit attempts.",
            "evidence_summary": "; ".join(details),
            "remediation": "Return generic production error pages, suppress stack traces in responses, and route detailed exceptions only to internal logs.",
            "raw": finding,
        }

    if vuln == "GraphQL Introspection":
        return {
            "title": "GraphQL introspection exposed",
            "severity": severity,
            "priority": "P4",
            "confidence": "High",
            "impact": "Exposed schema metadata can reveal object types, operations, and internal API structure that helps attackers map the application faster.",
            "evidence_summary": "; ".join(details),
            "remediation": "Disable GraphQL introspection in production where possible or restrict access to trusted users and environments.",
            "raw": finding,
        }

    if vuln == "API Rate Limiting Absent":
        return {
            "title": "No clear API throttling observed",
            "severity": severity,
            "priority": "P3",
            "confidence": "Low",
            "impact": "Weak or absent rate limiting can make brute force, scraping, or automated abuse easier on public APIs.",
            "evidence_summary": "; ".join(details),
            "remediation": "Apply rate limits, anomaly detection, and challenge controls on sensitive or high-value API endpoints.",
            "raw": finding,
        }

    if vuln == "CSRF":
        return {
            "title": "Potential CSRF risk detected",
            "severity": severity,
            "priority": "P2",
            "confidence": "Medium",
            "impact": "Authenticated users may be tricked into submitting unintended state-changing requests if anti-CSRF controls are weak or missing.",
            "evidence_summary": "; ".join(details),
            "remediation": "Use anti-CSRF tokens, verify Origin or Referer where appropriate, and combine with SameSite protections for session cookies.",
            "raw": finding,
        }

    if vuln == "JavaScript Source Maps":
        return {
            "title": "JavaScript source maps exposed",
            "severity": severity,
            "priority": "P4",
            "confidence": "High",
            "impact": "Source maps can reveal original client-side code, internal comments, variable names, and implementation details that aid attackers.",
            "evidence_summary": "; ".join(details),
            "remediation": "Remove public source maps in production or restrict access to trusted users and debugging environments.",
            "raw": finding,
        }

    if vuln == "Directory Listing Enabled":
        return {
            "title": "Directory listing enabled",
            "severity": severity,
            "priority": "P4",
            "confidence": "High",
            "impact": "Directory indexes can expose internal file structure, backups, assets, and forgotten files that were not meant for public browsing.",
            "evidence_summary": "; ".join(details),
            "remediation": "Disable auto-indexing on the web server and serve explicit index files or deny directory browsing.",
            "raw": finding,
        }

    if vuln == "Forced Browsing":
        return {
            "title": "Unlinked path accessible directly",
            "severity": severity,
            "priority": "P4",
            "confidence": "Medium",
            "impact": "Directly reachable but unlinked routes can expose administrative, debug, or internal functionality that normal navigation does not reveal.",
            "evidence_summary": "; ".join(details),
            "remediation": "Review each exposed route, remove unused paths, and enforce authentication or authorization where required.",
            "raw": finding,
        }

    if "CORS" in vuln:
        return {
            "title": "CORS policy observation",
            "severity": severity,
            "priority": "P1" if severity in ("Critical", "High") else "P4",
            "confidence": "High",
            "impact": "Unsafe CORS can allow malicious websites to read browser-authenticated API responses. Missing CORS alone is usually safe but should be intentional.",
            "evidence_summary": "; ".join(details),
            "remediation": "Use an explicit allowlist of trusted origins and avoid credentials with wildcard or reflected origins.",
            "raw": finding,
        }

    return {
        "title": vuln,
        "severity": severity,
        "priority": "P3",
        "confidence": "Medium",
        "impact": "Review this issue in application context.",
        "evidence_summary": "; ".join(details),
        "remediation": "Validate the evidence and remediate according to internal security standards.",
        "raw": finding,
    }


def _generate_next_steps(findings: list, data: dict, api_analysis: dict, sensitive_analysis: dict) -> dict:
    steps = []
    auth_surface = _analyze_auth_surface(data.get("auth_surface", {}))
    if auth_surface.get("auth_detected"):
        steps.append("Run an authenticated scan with test credentials before treating this application as fully assessed; public-only testing stops at the login boundary.")
    if sensitive_analysis.get("exposed_paths"):
        steps.append("Review readable sensitive paths first; remove or restrict anything exposing dependency, config, or source metadata.")
    if any(f.get("vulnerability") == "Missing Security Headers" for f in findings):
        steps.append("Implement missing security headers at the web server, CDN, or application middleware layer.")
    if any("Cookie" in f.get("vulnerability", "") for f in findings):
        steps.append("Separate third-party cookies from real auth/session cookies, then harden session cookies with Secure, HttpOnly, and SameSite.")
    if any(f.get("vulnerability") == "HTTP TRACE Enabled" for f in findings):
        steps.append("Disable HTTP TRACE and review unnecessary advertised methods on the public origin.")
    if any(f.get("vulnerability") == "JavaScript Secrets Exposed" for f in findings):
        steps.append("Rotate any exposed API keys or tokens immediately and move privileged secrets out of frontend JavaScript.")
    if any(f.get("vulnerability") == "GraphQL Introspection" for f in findings):
        steps.append("Review GraphQL production exposure and disable introspection where it is not intentionally required.")
    if any(f.get("vulnerability") == "API Rate Limiting Absent" for f in findings):
        steps.append("Apply throttling and abuse controls to exposed API endpoints, especially authentication and enumeration-sensitive routes.")
    if any(f.get("vulnerability") == "CSRF" for f in findings):
        steps.append("Review state-changing forms for anti-CSRF tokens and pair them with stricter SameSite and origin validation controls.")
    if any(f.get("vulnerability") == "JavaScript Source Maps" for f in findings):
        steps.append("Remove production source maps or restrict them to internal debugging access only.")
    if any(f.get("vulnerability") == "Directory Listing Enabled" for f in findings):
        steps.append("Disable web-server directory indexing and verify no sensitive files are browsable directly.")
    if any(f.get("vulnerability") == "Forced Browsing" for f in findings):
        steps.append("Review unlinked but reachable routes and enforce authentication or route removal where appropriate.")
    if any(f.get("vulnerability") == "Verbose Error Messages" for f in findings):
        steps.append("Replace verbose error responses with generic production-safe messages and keep detail in internal logs only.")
    if any(f.get("vulnerability") == "DOM-Based XSS" for f in findings):
        steps.append("Patch DOM-based XSS by removing unsafe client-side sinks and sanitizing fragment or URL-derived input before rendering.")
    if any(f.get("vulnerability") == "Open Redirect" for f in findings):
        steps.append("Patch open redirects by enforcing allowlisted destinations and removing attacker-controlled external redirect targets.")
    if any(f.get("vulnerability") == "Reflected XSS" for f in findings):
        steps.append("Patch reflected XSS using context-aware output encoding and retest the exact reflected parameters and forms.")
    if any(f.get("vulnerability") == "Stored XSS" for f in findings):
        steps.append("Investigate stored XSS persistence paths, sanitize saved content, and review who can create or view the affected records.")
    if any(f.get("vulnerability") == "SQL Injection" for f in findings):
        steps.append("Investigate SQLi evidence immediately, verify query construction on the affected parameters, and convert unsafe queries to parameterized statements.")
    if api_analysis["counts"]["first_party_api"]:
        steps.append("Manually test first-party API-like endpoints for authentication, authorization, validation, and rate limiting.")
    if data.get("inputs"):
        steps.append("Extend input validation testing beyond the automated checks: authenticated reflected/stored XSS, SQL injection, file upload abuse, and server-side validation bypass.")
    steps.append("Re-run the scan after fixes and compare the findings count plus exposed path list.")
    return {"priority_order": steps}


def _wrap(text: str, width: int) -> list:
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            if current:
                lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
